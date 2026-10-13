# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Handshake and SMP scenarios the recovery and SMP suites did not yet pin.

Complements tests/test_dake_recovery.py (lost DAKE1/2/3, peer restart,
glare, rate-limited recovery, verification not carried over) and
tests/test_smp_after_messages.py (SMP after chat, wrong secret, already
verified, cooldown, retry). The three-failure lock is reached for real in
Rust: smp::tests::three_real_wrong_answers_lock_the_run_for_good.

Engine level, two real bridges in one process. What a handset adds (radio,
I2P latency, process death) is in the physical test plan, not here.
"""
import pytest

pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import BridgeError                      # noqa: E402
from android_bridge.events import (MessageReceived, SecurityState,  # noqa: E402
                                   SmpState)
from tests.test_wipe_and_exit import (SECRET, Wire, _pair,       # noqa: E402,F401
                                      isolated_home)


class Recording(Wire):
    def __init__(self):
        super().__init__()
        self.log = []

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        self.log.append(text)
        super().send(peer, payload)


def _received(sink):
    return [e.body for e in sink.events if isinstance(e, MessageReceived)]


@pytest.fixture
def recorded():
    wire = Recording()
    p = _pair(alice_wire=wire)
    p.alice.start_session(p.bob_jid)
    p.handshake = list(wire.log)          # everything Alice sent to set it up
    assert p.handshake, "no handshake traffic recorded"
    yield p
    for app in (p.alice, p.bob):
        try:
            app.shutdown()
        except Exception:
            pass


def _verify(p):
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED


def test_a_replayed_handshake_leaves_the_verified_session_working(recorded):
    """An attacker replays Alice's whole handshake into Bob. They hold none
    of Alice's keys, so it cannot complete: the live session keeps working
    in both directions and its verification is untouched."""
    p = recorded
    _verify(p)
    level = p.bob.security_state(p.alice_jid)
    for frame in p.handshake:
        p.bob.receive_message(p.alice_jid, frame)
    p.alice.send_user_text(p.bob_jid, "after the replay")
    p.bob.send_user_text(p.alice_jid, "still here")
    assert _received(p.bob_sink)[-1] == "after the replay"
    assert _received(p.alice_sink)[-1] == "still here"
    assert p.bob.security_state(p.alice_jid) == level
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)


def test_a_replayed_handshake_never_yields_plaintext(recorded):
    p = recorded
    for frame in p.handshake:
        p.bob.receive_message(p.alice_jid, frame)
    assert p.bob.security_state(p.alice_jid) is not SecurityState.PLAINTEXT
    for body in _received(p.bob_sink):
        assert not body.startswith("?OTR"), "protocol text reached the chat"


def test_simultaneous_smp_start_resolves_to_one_run(recorded):
    """Both press Verify. The second is told a run is under way; answering
    the one in progress verifies both sides; nothing reaches the chat."""
    p = recorded
    p.alice.smp_start(p.bob_jid, SECRET)
    with pytest.raises(BridgeError) as e:
        p.bob.smp_start(p.alice_jid, SECRET)
    assert e.value.code == "smp_in_progress"
    assert p.bob.smp_secret_required(p.alice_jid)
    p.bob.smp_respond(p.alice_jid, SECRET)
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)


def test_a_late_abort_does_not_undo_a_verification(recorded):
    """An abort cancels a run in progress. Arriving after the run verified,
    it must not turn verified keys into unverified ones on either side."""
    p = recorded
    _verify(p)
    p.alice.smp_abort(p.bob_jid)
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED


def test_an_abort_mid_run_leaves_neither_side_verified(recorded):
    p = recorded
    p.bob_wire.cut = True                  # Bob's SMP2 never arrives
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    p.bob_wire.cut = False
    p.alice.smp_abort(p.bob_jid)
    assert p.alice.smp_state(p.bob_jid) is not SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is not SmpState.VERIFIED
    # The session itself is untouched by an SMP abort.
    p.alice.send_user_text(p.bob_jid, "carry on")
    assert _received(p.bob_sink)[-1] == "carry on"
