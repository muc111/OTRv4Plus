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
