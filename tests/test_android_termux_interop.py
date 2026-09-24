#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Android bridge against an engine configured the way the Termux XMPP
client configures it.

WHAT DIFFERS BETWEEN THE TWO PLATFORMS
======================================
The engine is the same file and the same Rust crate on both. What differs is
configuration and the path around it:

  * Android: `OTRConfig()` -- identity and trust in memory, a new identity
    each launch (decision B1) -- driven through `OtrApp`.
  * Termux XMPP: `_xmpp_otr_config()` -- `persist_identity=True` (sealed in
    Rust under a device DEK), `persist_trust=True` -- driven directly through
    `handle_incoming_message` / `handle_outgoing_message`, the calls
    `otrv4plus_xmpp` makes.

Both sides fragment at `otrv4plus_fragment.MAX_FRAGMENT` and reassemble with
the same module, so frames here travel fragmented in both directions, as
they do on a network.

WHAT THIS IS NOT: two devices, an XMPP server, or I2P. It proves the two
configurations interoperate at the protocol layer; the handset run in
`ANDROID_CALL_AND_FILE_DEVICE_TEST.md` is still what proves the network does.
"""

import os
import tempfile
import uuid

import pytest

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

import otrv4plus_fragment as frag                                     # noqa: E402
from android_bridge.app import OtrApp, Transport                      # noqa: E402
from android_bridge.events import MessageReceived                     # noqa: E402
from android_bridge.app import SecurityState, SmpState                # noqa: E402

SECRET = "the passphrase we agreed on the train"


def _termux_config(directory):
    """`otrv4plus_xmpp._xmpp_otr_config()`, pointed at a temporary directory.

    Restated rather than called because the original resolves its paths
    under the real HOME. The flags are the ones that matter and they are the
    same; `test_the_config_matches_the_terminal_clients` holds that.
    """
    p = lambda name: os.path.join(directory, name)                   # noqa: E731
    return otr.OTRConfig(
        test_mode=True, persist_identity=True, persist_trust=True,
        trust_db_path=p("trust.json"), smp_secrets_path=p("smp_secrets.json"),
        identity_path=p("identity.sealed"), identity_dek_path=p(".identity_dek"),
        key_storage_path=p("keys"))


def _android_manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class TermuxPeer:
    """What `otrv4plus_xmpp` does with an inbound body and an outbound line."""

    def __init__(self, directory, jid):
        self.jid = jid
        self.mgr = otr.EnhancedSessionManager(config=_termux_config(directory))
        self.mgr.smp_guided_prompt = True      # as otrv4plus_xmpp sets it
        self.reassembler = frag.Reassembler()
        self.seq = 0
        self.android = None          # (OtrApp, android_jid, reassembler)
        self.received = []

    def _send(self, payload):
        app, android_jid, reassembler = self.android
        parts, self.seq = frag.fragment(payload, self.seq)
        for part in parts:
            whole = reassembler.feed(self.jid, part) if frag.is_fragment(part) else part
            if whole is not None:
                app.receive_message(self.jid, whole)

    def deliver(self, peer, body):
        if frag.is_fragment(body):
            body = self.reassembler.feed(peer, body)
            if body is None:
                return
        out = self.mgr.handle_incoming_message(peer, body)
        if not out:
            return
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        if text.startswith("?OTRv4"):
            self._send(text)
        else:
            self.received.append(text)

    def say(self, peer, text):
        frame, should_send = self.mgr.handle_outgoing_message(peer, text)
        if should_send and frame:
            self._send(frame if isinstance(frame, str) else frame.decode())


class AndroidWire(Transport):
    def __init__(self, termux, android_jid):
        self.termux, self.android_jid, self.seq = termux, android_jid, 0

    def send(self, peer, payload):
        parts, self.seq = frag.fragment(payload, self.seq)
        for part in parts:
            self.termux.deliver(self.android_jid, part)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


@pytest.fixture
def world():
    otr._dake1_rate_limiter._attempts.clear()
    tag = uuid.uuid4().hex[:8]
    android_jid, termux_jid = "droid-%s@example.test" % tag, "termux-%s@example.test" % tag
    termux_dir = tempfile.mkdtemp()
    termux = TermuxPeer(termux_dir, termux_jid)
    sink = Sink()
    app = OtrApp(_android_manager(), AndroidWire(termux, android_jid), sink)
    termux.android = (app, android_jid, frag.Reassembler())
    w = type("World", (), {})()
    w.app, w.sink, w.termux, w.dir = app, sink, termux, termux_dir
    w.android_jid, w.termux_jid = android_jid, termux_jid
    yield w
    app.shutdown()


def _texts(sink):
    return [e.body for e in sink.events if isinstance(e, MessageReceived)]


class TestTheTwoConfigurationsInteroperate:

    def test_the_config_matches_the_terminal_clients(self):
        import otrv4plus_xmpp as X
        src = open(X.__file__, encoding="utf-8").read()
        body = src[src.index("def _xmpp_otr_config"):src.index("OTR_MODULE =")]
        for flag in ("persist_identity=True", "persist_trust=True", "test_mode=True"):
            assert flag in body, "the terminal client's config changed: %s" % flag

    def test_android_initiates_and_both_directions_carry_text(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        assert w.app.security_state(w.termux_jid) is not SecurityState.PLAINTEXT
        assert w.termux.mgr.has_session(w.android_jid)

        w.app.send_message(w.termux_jid, "hello from the phone")
        assert w.termux.received[-1] == "hello from the phone"

        w.termux.say(w.android_jid, "hello from termux " + "x" * 9000)   # fragmented
        assert _texts(w.sink)[-1] == "hello from termux " + "x" * 9000

    def test_termux_initiates(self, world):
        w = world
        w.termux.say(w.android_jid, "")          # what /otr start sends
        assert w.app.security_state(w.termux_jid) is not SecurityState.PLAINTEXT
        w.termux.say(w.android_jid, "they started it")
        assert _texts(w.sink)[-1] == "they started it"

    def test_smp_verifies_across_the_two(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        # The terminal's auto-respond: its user set the passphrase in advance.
        w.termux.mgr.set_smp_secret(w.android_jid, SECRET)
        w.app.smp_start(w.termux_jid, SECRET)
        assert w.app.smp_state(w.termux_jid) is SmpState.VERIFIED
        assert w.termux.mgr.get_smp_status(w.android_jid)["verified"]

    def test_a_wrong_passphrase_fails_across_the_two(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        w.termux.mgr.set_smp_secret(w.android_jid, "not the same passphrase")
        w.app.smp_start(w.termux_jid, SECRET)
        assert w.app.smp_state(w.termux_jid) is not SmpState.VERIFIED
        assert not w.termux.mgr.get_smp_status(w.android_jid)["verified"]

    def test_the_termux_identity_persists_and_the_android_one_does_not(self, world):
        w = world
        again = otr.EnhancedSessionManager(config=_termux_config(w.dir))
        assert again.get_fingerprint() == w.termux.mgr.get_fingerprint()
        assert _android_manager().get_fingerprint() != w.app._engine.get_fingerprint()


# ---------------------------------------------------------------------------
# Termux <-> Termux, the ratchet over many messages, reconnects, and the gate
# ---------------------------------------------------------------------------

import otrv4plus_voice as _V                                          # noqa: E402


def _fp(s):
    return (s or "").replace(" ", "").upper()


def _gate(mgr, peer):
    """The call/file gate: exactly what VoiceCallManager._smp_verified reads."""
    return _V._smp_query_default(mgr, peer)[0]


class TermuxToTermux(TermuxPeer):
    """A Termux-configured engine whose other end is another one."""

    other = None

    def _send(self, payload):
        parts, self.seq = frag.fragment(payload, self.seq)
        for part in parts:
            self.other.deliver(self.jid, part)


@pytest.fixture
def termux_pair():
    otr._dake1_rate_limiter._attempts.clear()
    tag = uuid.uuid4().hex[:8]
    a = TermuxToTermux(tempfile.mkdtemp(), "ta-%s@example.test" % tag)
    b = TermuxToTermux(tempfile.mkdtemp(), "tb-%s@example.test" % tag)
    a.other, b.other = b, a
    return a, b


class TestTermuxToTermux:

    def test_dake_text_and_fragmentation(self, termux_pair):
        a, b = termux_pair
        a.say(b.jid, "")
        assert a.mgr.has_session(b.jid) and b.mgr.has_session(a.jid)
        a.say(b.jid, "hello " + "y" * 9000)
        assert b.received[-1] == "hello " + "y" * 9000
        b.say(a.jid, "back")
        assert a.received[-1] == "back"

    def test_fingerprints_agree_across_the_two(self, termux_pair):
        a, b = termux_pair
        a.say(b.jid, "")
        assert _fp(a.mgr.get_peer_fingerprint(b.jid)) == _fp(b.mgr.get_fingerprint())
        assert _fp(b.mgr.get_peer_fingerprint(a.jid)) == _fp(a.mgr.get_fingerprint())

    def test_auto_respond_smp_through_the_rust_store(self, termux_pair):
        """Both sides store the passphrase (the Termux auto-respond feature);
        the responder answers from the Rust store without a prompt."""
        a, b = termux_pair
        a.say(b.jid, "")
        b.mgr.set_smp_secret(a.jid, SECRET)            # stored for auto-respond
        a.mgr.set_smp_secret(b.jid, SECRET)
        smp1 = a.mgr.start_smp_with_stored_secret(b.jid)
        assert smp1
        a._send(smp1)
        assert a.mgr.get_smp_status(b.jid)["verified"]
        assert b.mgr.get_smp_status(a.jid)["verified"]
        assert _gate(a.mgr, b.jid) and _gate(b.mgr, a.jid)


class TestTheRatchetAcrossPlatforms:

    def test_sixty_alternating_messages(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        for i in range(30):
            w.app.send_message(w.termux_jid, "d%d" % i)
            assert w.termux.received[-1] == "d%d" % i
            w.termux.say(w.android_jid, "t%d" % i)
            assert _texts(w.sink)[-1] == "t%d" % i

    def test_bursts_in_one_direction_then_the_other(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        for i in range(12):
            w.app.send_message(w.termux_jid, "burst%d" % i)
        assert w.termux.received[-12:] == ["burst%d" % i for i in range(12)]
        for i in range(12):
            w.termux.say(w.android_jid, "reply%d" % i)
        assert _texts(w.sink)[-12:] == ["reply%d" % i for i in range(12)]

    def test_fingerprints_agree_across_the_two(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        assert _fp(w.termux.mgr.get_peer_fingerprint(w.android_jid)) == _fp(w.app._engine.get_fingerprint())
        assert _fp(w.app._engine.get_peer_fingerprint(w.termux_jid)) == _fp(w.termux.mgr.get_fingerprint())


class TestTheGateAcrossPlatforms:
    """Calls and files are gated by the backend predicate on BOTH platforms."""

    def _verify(self, w):
        w.app.start_session(w.termux_jid)
        w.termux.mgr.set_smp_secret(w.android_jid, SECRET)
        w.app.smp_start(w.termux_jid, SECRET)
        assert _gate(w.app._engine, w.termux_jid) and _gate(w.termux.mgr, w.android_jid)

    def test_unverified_is_denied(self, world):
        world.app.start_session(world.termux_jid)
        assert not _gate(world.app._engine, world.termux_jid)
        assert not _gate(world.termux.mgr, world.android_jid)

    def test_a_reconnect_needs_verifying_again(self, world):
        w = world
        self._verify(w)
        w.app._engine.sessions.pop(w.termux_jid, None)
        w.termux.mgr.sessions.pop(w.android_jid, None)
        otr._dake1_rate_limiter._attempts.clear()
        w.app.start_session(w.termux_jid)
        w.app.send_message(w.termux_jid, "after reconnect")
        assert w.termux.received[-1] == "after reconnect"
        assert not _gate(w.app._engine, w.termux_jid)
        assert not _gate(w.termux.mgr, w.android_jid)

    def test_an_aborted_smp_is_denied(self, world):
        w = world
        w.app.start_session(w.termux_jid)
        # Nothing stored on the Termux side: its SMP1 is parked and we abort.
        w.app.smp_start(w.termux_jid, SECRET)
        assert w.termux.mgr.smp_secret_required(w.android_jid)
        w.app.smp_abort(w.termux_jid)
        assert not _gate(w.app._engine, w.termux_jid)
        assert not _gate(w.termux.mgr, w.android_jid)
        # The peer was told: its parked request is gone, not left waiting.
        assert not w.termux.mgr.smp_secret_required(w.android_jid)

    def test_a_changed_key_is_not_verified(self, world):
        """The Termux side comes back with a different identity (a new state
        directory). Android's pin no longer matches; nothing carries the old
        verification over."""
        w = world
        self._verify(w)
        new = TermuxPeer(tempfile.mkdtemp(), w.termux_jid)
        new.android = w.termux.android
        w.app._transport.termux = new
        w.app._engine.sessions.pop(w.termux_jid, None)
        otr._dake1_rate_limiter._attempts.clear()
        try:
            w.app.start_session(w.termux_jid)
        except Exception:
            pass
        assert new.mgr.get_fingerprint() != w.termux.mgr.get_fingerprint()
        assert not _gate(w.app._engine, w.termux_jid)
        assert w.app.security_state(w.termux_jid) is not SecurityState.SMP_VERIFIED


class TestTheCallGateAndroidRenders:
    """`OtrApp.call_gate`: the one answer the Android call control shows.

    The handset report was "the call button did not appear". The screen read
    security from the roster poll, and this harness's roster is EMPTY -- the
    same as a peer who is not on the account's roster -- so every assertion
    below would have been PLAINTEXT to the old screen.
    """

    def _voice_ok(self, monkeypatch, w):
        monkeypatch.setattr(type(w.app), "voice_unavailable_reason", lambda self: "")

    def test_the_gate_walks_the_states_in_order(self, world, monkeypatch):
        w = world
        self._voice_ok(monkeypatch, w)
        assert w.app.call_gate(w.termux_jid)["gate"] == "no_session"
        w.app.start_session(w.termux_jid)
        assert w.app.call_gate(w.termux_jid)["gate"] == "not_verified"
        w.termux.mgr.set_smp_secret(w.android_jid, SECRET)
        w.app.smp_start(w.termux_jid, SECRET)
        assert w.app.call_gate(w.termux_jid) == {"gate": "available", "reason": ""}
        # Case and resource do not change the answer.
        assert w.app.call_gate(w.termux_jid.upper() + "/phone")["gate"] == "available"

    def test_a_wrong_passphrase_keeps_it_closed(self, world, monkeypatch):
        w = world
        self._voice_ok(monkeypatch, w)
        w.app.start_session(w.termux_jid)
        w.termux.mgr.set_smp_secret(w.android_jid, "something else")
        w.app.smp_start(w.termux_jid, SECRET)
        assert w.app.call_gate(w.termux_jid)["gate"] == "not_verified"

    def test_a_new_session_closes_it_again(self, world, monkeypatch):
        w = world
        self._voice_ok(monkeypatch, w)
        TestTheGateAcrossPlatforms()._verify(w)
        assert w.app.call_gate(w.termux_jid)["gate"] == "available"
        w.app._engine.sessions.pop(w.termux_jid, None)
        w.termux.mgr.sessions.pop(w.android_jid, None)
        assert w.app.call_gate(w.termux_jid)["gate"] == "no_session"
        otr._dake1_rate_limiter._attempts.clear()
        w.app.start_session(w.termux_jid)
        assert w.app.call_gate(w.termux_jid)["gate"] == "not_verified"

    def test_voice_that_cannot_run_is_said_after_verification(self, world, monkeypatch):
        w = world
        monkeypatch.setattr(type(w.app), "voice_unavailable_reason",
                            lambda self: "no audio backend")
        TestTheGateAcrossPlatforms()._verify(w)
        assert w.app.call_gate(w.termux_jid) == {"gate": "voice_unavailable",
                                                 "reason": "no audio backend"}

    def test_rooms_and_a_wiped_app_are_never_available(self, world):
        w = world
        w.app.note_room_joined("lobby@rooms.example.test")
        assert w.app.call_gate("lobby@rooms.example.test")["gate"] == "room"
        w.app.wipe()
        assert w.app.call_gate(w.termux_jid)["gate"] == "wiped"

    def test_every_answer_is_a_known_code(self, world):
        w = world
        assert w.app.call_gate(w.termux_jid)["gate"] in OtrApp.CALL_GATES

    def test_the_events_android_consumes_arrive_in_a_safe_order(self, world):
        """Kotlin drops a VERIFIED when a later SessionStateChanged says the
        session is no longer SMP_VERIFIED. That is only right if the engine
        reports SMP_VERIFIED no later than the SmpResult -- checked here."""
        from android_bridge.events import SessionStateChanged, SmpResult
        w = world
        w.app.start_session(w.termux_jid)
        w.termux.mgr.set_smp_secret(w.android_jid, SECRET)
        w.app.smp_start(w.termux_jid, SECRET)
        seq = [e for e in w.sink.events if isinstance(e, (SessionStateChanged, SmpResult))]
        verified_at = next(i for i, e in enumerate(seq)
                           if isinstance(e, SmpResult) and e.state is SmpState.VERIFIED)
        after = [e for e in seq[verified_at:] if isinstance(e, SessionStateChanged)]
        assert all(e.security is SecurityState.SMP_VERIFIED for e in after), (
            "a level below SMP_VERIFIED was reported after the verification")
        assert any(isinstance(e, SessionStateChanged) and
                   e.security is SecurityState.SMP_VERIFIED for e in seq)
