#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""SMP driven through TWO Android bridges against the REAL Rust core.

WHY THIS FILE EXISTS
====================
The Android SMP work was covered by unit tests that all passed while the
responder path was completely dead. Three separate things hid it:

  1. `smp_respond` stored the passphrase and never sent SMP2. A fake engine
     records the call and reports success, so the test agreed.
  2. An arriving SMP1 emitted no event at all, because the bridge only
     announced a change in the SECURITY LEVEL and SMP does not change it.
  3. `EnhancedSessionManager.smp_guided_prompt` defaults to False and the
     bridge never set it, so the core ABORTED an SMP1 with no stored secret
     instead of parking it -- making SECRET_REQUIRED unreachable on Android
     and every remedy above it unreachable too.

Each was invisible for the same reason: the fake engine answered questions
from flags the test had set, so it encoded the same assumptions as the code
it stood in for. That is the fourth occurrence in this project, after
`connect(address=...)`, the SSL context and `RosterItem.get`.

WHAT THIS IS, AND WHAT IT IS NOT
================================
It is a REAL protocol run. Two `EnhancedSessionManager` instances with a real
DAKE, a real `otrv4_core.RustSMP` on each side, real SMP1/2/3/4 frames, driven
through two real `OtrApp` facades and delivered between them by a transport
that does nothing but carry bytes. Nothing about SMP is stubbed.

IT IS NOT ANDROID-TO-TERMUX NETWORK INTEROPERABILITY. There is no XMPP server,
no I2P tunnel, no handset and no second process here. What this proves is that
the Android bridge drives the protocol correctly end to end; what it cannot
prove is that two real clients on a real network do. Those are different
claims and this file makes only the first.

WHY NOT test_smp_end_to_end.py
==============================
That file already runs SMP through two real managers and is the reason the
data-frame classifier regression cannot come back. But it calls
`bob_mgr.set_smp_secret(alice, SECRET)` BEFORE the run -- so the responder
always has the passphrase already, never parks an SMP1, never reaches
SECRET_REQUIRED and never calls `resume_held_smp1`. The exact path that was
broken is the one it does not take. It also never touches `OtrApp`.
"""

import collections
import itertools
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")

from android_bridge.app import BridgeError, OtrApp, Transport   # noqa: E402
from android_bridge.events import (                             # noqa: E402
    SecurityState, SmpProgress, SmpResult, SmpState,
)

SECRET = "correct horse battery staple"
WRONG = "not the same passphrase at all"

#: A FRESH PAIR OF JIDS PER TEST, and a rate-limiter reset with them.
#:
#: `otrv4_._dake1_rate_limiter` is a module-level `DAKE1RateLimiter` -- the M-4
#: fix -- allowing 5 inbound DAKE1s per bucket per 60 seconds and dropping the
#: rest SILENTLY, deliberately, so an attacker gets no oracle.
#:
#: UNIQUE JIDS ARE NOT ENOUGH, AND WHY IS A FINDING IN ITS OWN RIGHT. The class
#: is documented "Per-peer sliding-window rate limiter" and takes a `peer_key`,
#: but BOTH call sites -- otrv4_.py:8332 and :9108 -- call
#: `process_dake1(dake1_msg)` without it, so every peer in the process shares
#: the default bucket `"unknown"`. Measured, six distinct peer pairs:
#:
#:     pair 0..4  responder replied = True
#:     pair 5     responder replied = False
#:     limiter buckets: {'unknown': 5}
#:
#: So the limit is process-wide rather than per-peer. That is reported, not
#: fixed here: it is pre-existing engine behaviour, unrelated to SMP or to
#: Android, and changing a DoS control is not this file's business.
#:
#: `reset()` exists for exactly this and `tests/test_otrv4_integration.py:48`
#: already uses it. Resetting per test keeps these tests measuring SMP rather
#: than measuring the quota.
_counter = itertools.count()


def _jids():
    n = next(_counter)
    return "alice%d@example.test" % n, "bob%d@example.test" % n


Pair = collections.namedtuple(
    "Pair", "alice bob alice_wire bob_wire alice_jid bob_jid")


# ── the wire ─────────────────────────────────────────────────────────────────

class Wire(Transport):
    """A transport that carries bytes and decides nothing.

    Deliberately inert. Every routing, classification and protocol decision
    has to come from `OtrApp` and the engine, because those are what is under
    test -- a transport that understood OTR frames would be a second opinion
    about what they mean, in a place with no way to be right.
    """

    def __init__(self):
        self.sent = []
        self.peer_app = None
        self.peer_id = None
        self.deliver = True

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        self.sent.append((peer, text))
        if self.deliver and self.peer_app is not None:
            self.peer_app.receive_message(self.peer_id, text)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class Sink:
    def __init__(self): self.events = []
    def on_event(self, event): self.events.append(event)
    def of(self, cls): return [e for e in self.events if isinstance(e, cls)]
    def smp_states(self):
        return [e.state for e in self.events
                if isinstance(e, (SmpProgress, SmpResult))]


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def pair():
    """Two Android bridges with a completed DAKE between them.

    The DAKE is driven through `OtrApp.start_session` and
    `OtrApp.receive_message` -- the same two methods the handset calls -- so
    the session these tests verify over is one the bridge established, not one
    assembled behind its back.
    """
    alice_jid, bob_jid = _jids()
    # See the note on `_counter`: the bucket is shared process-wide, so
    # without this the sixth test in the file loses its DAKE1 in silence.
    otr._dake1_rate_limiter.reset("unknown")
    alice_wire, bob_wire = Wire(), Wire()
    alice = OtrApp(_manager(), alice_wire, Sink())
    bob = OtrApp(_manager(), bob_wire, Sink())
    alice_wire.peer_app, alice_wire.peer_id = bob, alice_jid
    bob_wire.peer_app, bob_wire.peer_id = alice, bob_jid

    alice.start_session(bob_jid)

    assert alice.security_state(bob_jid) is not SecurityState.PLAINTEXT, \
        "the initiator never reached an encrypted session"
    assert bob.security_state(alice_jid) is not SecurityState.PLAINTEXT, \
        "the responder never reached an encrypted session"

    # THE BASELINE. The DAKE put frames on both wires, and a test asking
    # "did the responder send SMP2" must not count DAKE2 as the answer --
    # that is how `test_the_responder_actually_produced_smp2` first passed
    # against a responder that sent nothing.
    alice_wire.sent.clear()
    bob_wire.sent.clear()
    alice._sink.events.clear()
    bob._sink.events.clear()
    return Pair(alice, bob, alice_wire, bob_wire, alice_jid, bob_jid)


# ── the session the verification runs over ───────────────────────────────────

class TestTheSessionIsRealBeforeAnythingIsVerified:

    def test_the_dake_completes_through_the_bridge(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        assert alice.security_state(BOB) is not SecurityState.PLAINTEXT
        assert bob.security_state(ALICE) is not SecurityState.PLAINTEXT

    def test_encrypted_is_not_verified(self, pair):
        """The distinction the whole feature exists for. A completed DAKE
        means encrypted TO SOMEBODY; nobody has checked who."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        assert alice.smp_state(BOB) is SmpState.NOT_VERIFIED
        assert bob.smp_state(ALICE) is SmpState.NOT_VERIFIED
        assert alice.security_state(BOB) is not SecurityState.SMP_VERIFIED
        assert bob.security_state(ALICE) is not SecurityState.SMP_VERIFIED

    def test_fingerprints_are_pinned_on_both_sides(self, pair):
        """The existing TOFU behaviour, which SMP adds to and never replaces."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        assert alice.security_details(BOB).peer_fingerprint
        assert bob.security_details(ALICE).peer_fingerprint

    def test_ordinary_encrypted_messaging_works_first(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        assert alice.send_user_text(BOB, "before verifying") == \
            OtrApp.SEND_ENCRYPTED
        received = [e.body for e in bob._sink.of(
            __import__("android_bridge.events", fromlist=["MessageReceived"])
            .MessageReceived)]
        assert "before verifying" in received


# ── the responder path that was dead ─────────────────────────────────────────

class TestTheGuidedResponderPathIsReachable:
    """THE FIFTH DEFECT, and the one that made everything else moot.

    `smp_guided_prompt` defaults to False. Both terminal clients set it True;
    `android_bridge` never did. With it False the core ABORTS an SMP1 that
    arrives with no stored secret rather than parking it, so SECRET_REQUIRED
    was unreachable on Android and no prompt could ever open.
    """

    def test_the_bridge_declares_it_can_ask(self, pair):
        alice = pair.alice
        assert alice._engine.smp_guided_prompt is True, (
            "the bridge did not enable the guided flow, so an arriving SMP1 "
            "will be aborted instead of parked and no prompt can open")

    def test_the_default_really_is_the_broken_one(self):
        """Guards the premise. If the engine's default changed, the fix above
        becomes a no-op and this test should be the thing that says so."""
        manager = _manager()
        # ABSENT, not False. The session-level default at otrv4_.py:6550 is
        # False; the MANAGER carries no such attribute until a front end sets
        # one, and `session.smp_guided_prompt = getattr(self,
        # "smp_guided_prompt", False)` is what turns "absent" into "this front
        # end cannot ask". Either way the guided path is off, which is the
        # premise this guards -- so assert the effective value, not the
        # spelling.
        assert getattr(manager, "smp_guided_prompt", False) is False, (
            "the engine now enables the guided flow by default; the bridge's "
            "own _enable_guided_smp has become a no-op and this test is the "
            "only thing that would say so")

    def test_an_arriving_smp1_is_parked_rather_than_aborted(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert bob.smp_secret_required(ALICE) is True, (
            "the responder did not park the SMP1")
        assert bob.smp_state(ALICE) is SmpState.SECRET_REQUIRED
        assert bob_wire.sent == [], (
            "the responder answered before being given a passphrase; that is "
            "the abort branch, not the parked one")

    def test_the_responder_is_told_without_pressing_anything(self, pair):
        """THE RECEIVING REQUIREMENT. Bob's UI learns a request is waiting
        from an event, with no button pressed and no poll."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert SmpState.SECRET_REQUIRED in bob._sink.smp_states(), (
            "nothing was emitted, so the responder's screen cannot know a "
            "verification request arrived")


# ── the complete exchange ────────────────────────────────────────────────────

class TestTheCompleteExchange:
    """SMP1 -> SMP2 -> SMP3 -> SMP4, through two bridges, ending VERIFIED.

    The test the previous round of work did not have. Every assertion here is
    about a frame that actually moved or a state the Rust core actually
    reports; none of it is an API-shape check.
    """

    def test_both_sides_reach_verified(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)

        assert alice.smp_state(BOB) is SmpState.VERIFIED, \
            "the initiator did not reach VERIFIED"
        assert bob.smp_state(ALICE) is SmpState.VERIFIED, \
            "the responder did not reach VERIFIED"

    def test_the_engine_itself_says_verified(self, pair):
        """Read off the engine rather than the facade's mapping, so a mapping
        that lied could not make this pass."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        assert alice._engine.get_smp_status(BOB)["verified"] is True
        assert bob._engine.get_smp_status(ALICE)["verified"] is True

    def test_the_responder_actually_produced_smp2(self, pair):
        """NOT that `smp_respond` was called -- that a frame left the device.

        The defect was precisely that the passphrase was stored and nothing
        was sent, which every unit test read as success.
        """
        alice, bob = pair.alice, pair.bob
        _aw, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert bob_wire.sent == [], "the responder sent something too early"

        bob.smp_respond(ALICE, SECRET)
        assert bob_wire.sent, (
            "the responder stored the passphrase and sent nothing; SMP2 never "
            "left the device and the initiator would wait forever")
        peer, frame = bob_wire.sent[0]
        assert peer == ALICE
        assert frame.startswith("?OTRv4"), "what was sent is not an OTR frame"

    def test_four_frames_crossed_the_wire(self, pair):
        """SMP is a four-message protocol. Counting them is how a run that
        completed is told from one that stalled after the first reply."""
        alice, bob = pair.alice, pair.bob
        alice_wire, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        before_a = len(alice_wire.sent)
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)

        alice_frames = len(alice_wire.sent) - before_a
        bob_frames = len(bob_wire.sent)
        assert alice_frames >= 2, (
            "the initiator sent %d frames; SMP1 and SMP3 are both hers"
            % alice_frames)
        assert bob_frames >= 2, (
            "the responder sent %d frames; SMP2 and SMP4 are both his"
            % bob_frames)

    def test_the_held_message_is_consumed_rather_than_restarted(self, pair):
        """The point of parking. Once answered, nothing is waiting -- a run
        that restarted instead would cost a second I2P round trip."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert bob.smp_secret_required(ALICE) is True
        bob.smp_respond(ALICE, SECRET)
        assert bob.smp_secret_required(ALICE) is False

    def test_ordinary_messaging_continues_afterwards(self, pair):
        """Verification must not disturb the session it verified."""
        from android_bridge.events import MessageReceived
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)

        assert alice.send_user_text(BOB, "after verifying") == \
            OtrApp.SEND_ENCRYPTED
        assert "after verifying" in [
            e.body for e in bob._sink.of(MessageReceived)]
        assert bob.send_user_text(ALICE, "and back") == OtrApp.SEND_ENCRYPTED
        assert "and back" in [e.body for e in alice._sink.of(MessageReceived)]

    def test_the_security_level_rises_to_smp_verified(self, pair):
        """The level is what gates voice. It must move on its own, from the
        engine, and not because the UI decided the run looked successful."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        assert alice.security_state(BOB) is SecurityState.SMP_VERIFIED
        assert bob.security_state(ALICE) is SecurityState.SMP_VERIFIED

    def test_both_uis_are_told_it_finished(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        assert SmpState.VERIFIED in alice._sink.smp_states()
        assert SmpState.VERIFIED in bob._sink.smp_states()


# ── the other direction ──────────────────────────────────────────────────────

class TestEitherPartyMayInitiate:
    """Both directions, because the roles are not symmetric in the engine --
    the initiator generates SMP1 and SMP3, the responder SMP2 and SMP4 -- and
    a bridge correct in one direction can be broken in the other. That
    asymmetry is exactly what produced the original responder defect.
    """

    def test_bob_can_initiate_and_both_verify(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        bob.smp_start(ALICE, SECRET)
        assert alice.smp_secret_required(BOB) is True
        alice.smp_respond(BOB, SECRET)
        assert alice.smp_state(BOB) is SmpState.VERIFIED
        assert bob.smp_state(ALICE) is SmpState.VERIFIED

    def test_alices_smp2_actually_left_her_device(self, pair):
        alice, bob = pair.alice, pair.bob
        alice_wire, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        bob.smp_start(ALICE, SECRET)
        before = len(alice_wire.sent)
        alice.smp_respond(BOB, SECRET)
        assert len(alice_wire.sent) > before, (
            "the responder role is broken in this direction")


# ── the wrong secret ─────────────────────────────────────────────────────────

class TestAWrongPassphraseFails:
    """The property SMP exists for. A run that completed and a run that proved
    something must never be the same outcome."""

    def test_a_wrong_passphrase_does_not_verify(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)

        assert alice.smp_state(BOB) is not SmpState.VERIFIED, (
            "the initiator reported VERIFIED against a peer who did not know "
            "the passphrase -- SMP is not proving anything")
        assert bob.smp_state(ALICE) is not SmpState.VERIFIED

    def test_a_wrong_passphrase_is_reported_as_failure(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)
        assert alice.smp_state(BOB) is SmpState.FAILED, (
            "a mismatched passphrase must be FAILED -- on this protocol that "
            "is what an impersonation looks like and the user must see it")

    def test_the_engine_itself_says_not_verified(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)
        assert alice._engine.get_smp_status(BOB)["verified"] is False
        assert bob._engine.get_smp_status(ALICE)["verified"] is False

    def test_the_security_level_does_not_rise(self, pair):
        """The voice gate. A failed run must leave a call unavailable."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)
        assert alice.security_state(BOB) is not SecurityState.SMP_VERIFIED
        assert bob.security_state(ALICE) is not SecurityState.SMP_VERIFIED

    def test_the_run_still_exchanged_frames(self, pair):
        """A failure must be a FAILED PROOF, not a stall. If nothing crossed
        the wire, this test would be passing for the wrong reason."""
        alice, bob = pair.alice, pair.bob
        _aw, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)
        assert bob_wire.sent, (
            "no frame left the responder, so the wrong-secret case proves "
            "nothing about the proof -- it only shows nothing happened")

    def test_the_conversation_survives_a_failed_verification(self, pair):
        """A failed identity check is not a broken session. The user has to be
        able to try again, and to keep talking meanwhile."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, WRONG)
        assert alice.security_state(BOB) is not SecurityState.PLAINTEXT
        assert alice.send_user_text(BOB, "still here") == OtrApp.SEND_ENCRYPTED


# ── the passphrase itself ────────────────────────────────────────────────────

class TestThePassphraseNeverTravels:
    """SMP's entire design is that both sides prove they know the secret
    WITHOUT transmitting it. A frame containing it would defeat the protocol,
    and this checks the real frames rather than a fake's recorded arguments.
    """

    def test_no_frame_contains_the_passphrase(self, pair):
        alice, bob = pair.alice, pair.bob
        alice_wire, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        assert alice_wire.sent and bob_wire.sent, "nothing was sent"
        for _peer, frame in alice_wire.sent + bob_wire.sent:
            assert SECRET not in frame
            for word in SECRET.split():
                assert word not in frame

    def test_no_event_contains_the_passphrase(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        for sink in (alice._sink, bob._sink):
            for event in sink.events:
                assert SECRET not in repr(event)

    def test_the_facade_retains_nothing(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        for app in (alice, bob):
            for value in vars(app).values():
                assert SECRET not in repr(value)

    def test_nothing_is_logged(self, pair, caplog):
        import logging
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        with caplog.at_level(logging.DEBUG):
            alice.smp_start(BOB, SECRET)
            bob.smp_respond(ALICE, SECRET)
        joined = "\n".join(record.getMessage() for record in caplog.records)
        assert SECRET not in joined

    def test_the_diagnostic_trace_carries_neither_secret_nor_frame(self, pair):
        from android_bridge.trace import TRACE
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        TRACE.clear()
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        rendered = TRACE.render()
        assert SECRET not in rendered
        assert "?OTRv4" not in rendered


# ── refusals, against the real engine ────────────────────────────────────────

class TestRefusalsHoldAgainstTheRealEngine:

    def test_smp_cannot_start_without_an_encrypted_session(self):
        """No DAKE has run. A proof here would prove nothing about anybody."""
        _alice_jid, bob_jid = _jids()
        otr._dake1_rate_limiter.reset("unknown")
        wire = Wire()
        app = OtrApp(_manager(), wire, Sink())
        with pytest.raises(BridgeError) as caught:
            app.smp_start(bob_jid, SECRET)
        assert caught.value.code == "smp_not_encrypted"
        assert wire.sent == []

    def test_answering_when_nothing_is_held_is_refused(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, bob_wire = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        assert bob.smp_secret_required(ALICE) is False
        with pytest.raises(BridgeError) as caught:
            bob.smp_respond(ALICE, SECRET)
        assert caught.value.code == "smp_not_requested"
        assert bob_wire.sent == []

    def test_a_short_passphrase_is_refused_by_the_engine(self, pair):
        """The 8-character minimum is the engine's rule, not the UI's. The
        dialog disables its button below it; this is what happens if anything
        gets past that."""
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        with pytest.raises(BridgeError):
            alice.smp_start(BOB, "short")
        assert alice.smp_state(BOB) is not SmpState.VERIFIED


# ── what the Rust core reports, unmapped ─────────────────────────────────────

class TestThePhasesAreTheCoresOwn:
    """`_SMP_PHASE_MAP` silently collapsed SECRET_REQUIRED to IDLE for two
    releases. These read the phase strings off a live run rather than a table,
    so a mapping that drifts from the core fails here.
    """

    def test_secret_required_is_what_the_core_reports(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert bob._engine.get_smp_status(ALICE)["state"] == "SECRET_REQUIRED"
        assert bob.smp_state(ALICE) is SmpState.SECRET_REQUIRED, (
            "the core reports SECRET_REQUIRED and the bridge does not; the "
            "state that means 'somebody is waiting on you' is being lost")

    def test_the_initiator_waits_in_a_phase_the_bridge_understands(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        assert alice._engine.get_smp_status(BOB)["state"] == "AWAITING_MSG2"
        assert alice.smp_state(BOB) is SmpState.IN_PROGRESS

    def test_verified_is_what_the_core_reports(self, pair):
        alice, bob = pair.alice, pair.bob
        _aw, _bw = pair.alice_wire, pair.bob_wire
        ALICE, BOB = pair.alice_jid, pair.bob_jid
        alice.smp_start(BOB, SECRET)
        bob.smp_respond(ALICE, SECRET)
        assert alice._engine.get_smp_status(BOB)["state"] == "VERIFIED"
        assert bob._engine.get_smp_status(ALICE)["state"] == "VERIFIED"
