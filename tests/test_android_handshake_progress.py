# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4+ handshake reports where it is, from the engine and the wire.

Reported from two handsets: starting OTR between two Android apps looked like
it did nothing -- it worked, but took minutes over I2P with no sign anything
was happening. `OtrApp.handshake_status` reports the step from the engine's
own DAKE state and, while a frame is arriving in parts, how many parts have
come. Driven here by two REAL engines with the frames held and released one
at a time, so each intermediate state is observed rather than assumed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

import otrv4plus_fragment as fragment                           # noqa: E402
from android_bridge.app import OtrApp                           # noqa: E402
from tests.test_smp_android_interop import (Sink, Wire, _jids,  # noqa: E402
                                            _manager)


class HeldWire(Wire):
    """Carries frames only when told to, so the steps can be looked at."""

    def __init__(self):
        super().__init__()
        self.deliver = False
        self.parts = None           # what inbound_progress reports

    def release(self):
        frames, self.sent = list(self.sent), []
        for _peer, text in frames:
            self.peer_app.receive_message(self.peer_id, text)
        return len(frames)

    def inbound_progress(self, peer):
        return self.parts


@pytest.fixture
def pair():
    a_jid, b_jid = _jids()
    otr._dake1_rate_limiter._attempts.clear()
    aw, bw = HeldWire(), HeldWire()
    alice = OtrApp(_manager(), aw, Sink())
    bob = OtrApp(_manager(), bw, Sink())
    aw.peer_app, aw.peer_id = bob, a_jid
    bw.peer_app, bw.peer_id = alice, b_jid
    return alice, bob, aw, bw, a_jid, b_jid


def stage(app, peer):
    return app.handshake_status(peer)["stage"]


class TestEveryStepIsReported:

    def test_the_whole_handshake_step_by_step(self, pair):
        alice, bob, aw, bw, A, B = pair
        assert stage(alice, B) == OtrApp.HS_IDLE

        alice.start_session(B)                 # DAKE1 out
        s = alice.handshake_status(B)
        assert s["stage"] == OtrApp.HS_WAITING_REPLY and s["step"] == 1
        assert s["steps"] == 3

        aw.release()                           # Bob gets DAKE1, sends DAKE2
        assert stage(bob, A) == OtrApp.HS_WAITING_CONFIRM
        assert bob.handshake_status(A)["step"] == 2

        bw.release()                           # Alice gets DAKE2, sends DAKE3
        assert stage(alice, B) == OtrApp.HS_ESTABLISHED
        assert alice.handshake_status(B)["step"] == 3

        aw.release()                           # Bob gets DAKE3
        assert stage(bob, A) == OtrApp.HS_ESTABLISHED

    def test_parts_arriving_are_counted(self, pair):
        alice, bob, aw, bw, A, B = pair
        alice.start_session(B)
        aw.parts = (1, 2)                      # DAKE2 half here
        s = alice.handshake_status(B)
        assert s["stage"] == OtrApp.HS_RECEIVING_REPLY
        assert (s["have"], s["of"], s["step"]) == (1, 2, 2)

    def test_the_responder_sees_the_request_arriving(self, pair):
        alice, bob, aw, bw, A, B = pair
        bw.parts = (1, 3)
        s = bob.handshake_status(A)
        assert s["stage"] == OtrApp.HS_RECEIVING_REQUEST and s["step"] == 1

    def test_elapsed_counts_from_the_start_and_resets_after(self, pair):
        alice, bob, aw, bw, A, B = pair
        alice.start_session(B)
        first = alice.handshake_status(B)
        assert first["elapsed"] >= 0
        aw.release(); bw.release(); aw.release()
        assert alice.handshake_status(B)["elapsed"] == 0

    def test_it_carries_no_key_material(self, pair):
        alice, bob, aw, bw, A, B = pair
        alice.start_session(B)
        s = alice.handshake_status(B)
        assert set(s) == {"stage", "step", "steps", "have", "of", "elapsed"}
        assert all(isinstance(v, (int, str)) for v in s.values())


class TestTheReassemblerCountsParts:

    def test_progress_of_a_partial_set(self):
        r = fragment.Reassembler()
        parts, _ = fragment.fragment("x" * (fragment.MAX_FRAGMENT * 2 + 5), 0)
        assert len(parts) == 3
        assert r.progress("bob@x") is None
        r.feed("bob@x", parts[0])
        assert r.progress("bob@x") == (1, 3)
        r.feed("bob@x", parts[2])
        assert r.progress("bob@x") == (2, 3)
        assert r.progress("carol@x") is None
        assert r.feed("bob@x", parts[1]) is not None
        assert r.progress("bob@x") is None
