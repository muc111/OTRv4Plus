# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Owner's rules (2026-10-04): no plaintext to an OTRv4+ contact; lines typed
before the conversation is ready wait and are SENT when it is; a contact whose
app lacks OTRv4+ is written to in the clear, labelled.

Also the defect found while doing this: the engine's own queue was cleared,
not sent, when the handshake completed -- a line typed during a DAKE was
reported "queued" and never arrived. Two REAL engines here, frames held and
released one at a time.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp                           # noqa: E402
from android_bridge.events import MessageReceived, QueuedSent   # noqa: E402
from tests.test_android_handshake_progress import HeldWire       # noqa: E402
from tests.test_smp_android_interop import Sink, _jids, _manager  # noqa: E402


class CapWire(HeldWire):
    """A wire that also reports a capability, like the real transport."""

    def __init__(self):
        super().__init__()
        self.cap = "checking"
        self._profile = None

    def otr_capability(self, peer):
        return self.cap


def _pair():
    a_jid, b_jid = _jids()
    otr._dake1_rate_limiter._attempts.clear()
    aw, bw = CapWire(), CapWire()
    sa, sb = Sink(), Sink()
    alice = OtrApp(_manager(), aw, sa)
    bob = OtrApp(_manager(), bw, sb)
    aw.peer_app, aw.peer_id = bob, a_jid
    bw.peer_app, bw.peer_id = alice, b_jid
    return alice, bob, aw, bw, a_jid, b_jid, sa, sb


def _run(aw, bw, rounds=6):
    for _ in range(rounds):
        if not (aw.release() + bw.release()):
            break


def _events(sink, kind):
    return [e for e in getattr(sink, "events", []) if isinstance(e, kind)]


def test_nothing_leaves_while_capability_is_unknown():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    assert alice.send_user_text(B, "secret plans") == OtrApp.SEND_QUEUED
    assert aw.sent == []                              # not a byte on the wire
    assert alice.outbox_count(B) == 1


def test_an_otrv4_contact_gets_the_waiting_lines_encrypted():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    aw.cap = bw.cap = "available"
    assert alice.send_user_text(B, "first") == OtrApp.SEND_QUEUED
    assert alice.send_user_text(B, "second") == OtrApp.SEND_QUEUED
    # Nothing in the clear: every frame that left is OTRv4+.
    assert all(t.startswith("?OTRv4") for _p, t in aw.sent)
    _run(aw, bw)
    got = [e.body for e in _events(sb, MessageReceived)]
    assert got == ["first", "second"], got
    sent = _events(sa, QueuedSent)
    assert sent and sent[-1].count == 2 and sent[-1].encrypted
    assert alice.outbox_count(B) == 0
    # After that, straight through.
    assert alice.send_user_text(B, "third") == OtrApp.SEND_ENCRYPTED


def test_a_line_typed_during_the_handshake_is_not_lost():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    aw.cap = bw.cap = "available"
    alice.start_session(B)
    aw.release()                                      # DAKE1 -> Bob
    assert alice.send_user_text(B, "typed mid-handshake") == OtrApp.SEND_QUEUED
    _run(aw, bw)
    assert [e.body for e in _events(sb, MessageReceived)] == ["typed mid-handshake"]


def test_a_contact_without_otrv4_gets_plaintext_labelled():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    alice.send_user_text(B, "hi")                     # capability unknown: held
    aw.cap = "unavailable"
    alice.note_capability(B)
    assert aw.sent == [(B, "hi")]
    sent = _events(sa, QueuedSent)
    assert sent and not sent[-1].encrypted
    assert alice.send_user_text(B, "next") == OtrApp.SEND_PLAINTEXT


def test_a_capable_contact_coming_online_starts_otr_on_one_side_only():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    aw.cap = bw.cap = "available"
    # Alice's JID sorts first in _jids? Decide by comparison.
    first, second = (alice, bob) if A < B else (bob, alice)
    first_w, second_w = (aw, bw) if first is alice else (bw, aw)
    first_peer = B if first is alice else A
    second_peer = A if first is alice else B
    first._transport._profile = type("P", (), {"jid": A if first is alice else B})()
    second._transport._profile = type("P", (), {"jid": B if first is alice else A})()
    second.note_capability(second_peer)
    assert second_w.sent == []                        # the higher JID waits
    first.note_capability(first_peer)
    assert first_w.sent and first_w.sent[0][1].startswith("?OTRv4")


def test_the_eta_comes_from_past_handshakes():
    alice, bob, aw, bw, A, B, sa, sb = _pair()
    assert alice.handshake_eta(B, 0) == OtrApp.HANDSHAKE_TYPICAL_SECONDS
    alice._hs_history[B] = [30.0, 40.0, 50.0]
    assert alice.handshake_eta(B, 10) == 30
    assert alice.handshake_eta(B, 100) == 5


def test_sign_out_lets_go_of_the_groups_so_sign_in_can_open_them(monkeypatch, tmp_path_factory):
    """Device test (2026-10-05): after Sign out the account could not sign in
    again. The app's shutdown never closed its secure groups, so their state
    lock stayed held and the next sign-in's groups found it "in use"."""
    import tempfile
    d = tempfile.mkdtemp()
    monkeypatch.setattr(OtrApp, "GROUP_STATE_DIR", d)
    alice, *_rest = _pair()
    a_jid = _rest[3]
    assert alice.open_groups(a_jid)
    alice.shutdown()                               # Sign out
    again, *_ = _pair()                            # a new engine, same phone
    assert again.open_groups(a_jid), "the groups were still held by the old app"
    again.shutdown()
