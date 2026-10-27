# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""P2 (docs/SECURITY_ISSUES.md): a forced DH step the peer cannot follow.

Found by the audit of 2026-10-26, writing a residual test for SPEC §5.1.
The engine forced a send-side DH step at every rekey boundary (100 messages
in one direction, or 24 hours) toward the peer's current key, even when it
had already stepped toward that key, by an earlier forced step or by the
receive step that answers the peer's new key. The peer's receive step for
the second one uses the key it made after the first, so every later message
failed to decrypt, silently: `handle_incoming_message` returned None and
the session stayed up. Two everyday ways in: the 101st message from one
side after a DH round trip (measured; up to the 200th with no DH step yet),
or a chat open for two days.

The fix (`RustBackedDoubleRatchet._forced_toward`): at most one send step
toward each remote key. The next step comes from the peer's reply, as in
the double ratchet. Rust: `pq_ratchet::p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed`.
"""
from __future__ import annotations

import random

import pytest

import test_smp_end_to_end as E

otr = E.otr
pytest.importorskip("otrv4_core")
A, B = "alice@example.test", "bob@example.test"


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


def _pair(monkeypatch, rekey=None):
    if rekey is not None:
        monkeypatch.setattr(otr.OTRConstants, "REKEY_INTERVAL", rekey)
    a, b = E._manager(), E._manager()
    first, _ = a.handle_outgoing_message(B, "")
    E._relay(first, a, b, A, B)
    assert a.has_encrypted_session(B) and b.has_encrypted_session(A)
    return a, b


def _say(sender, receiver, peer, frm, text):
    wire, _ = sender.handle_outgoing_message(peer, text)
    return receiver.handle_incoming_message(frm, wire) == text.encode()


def test_bursts_both_ways_across_many_boundaries_all_decrypt(monkeypatch):
    """Rekey every 3 messages, bursts of 1-8 each way, 30 rounds: before the
    fix 235 of these messages failed (the first in round 1)."""
    a, b = _pair(monkeypatch, rekey=3)
    rnd = random.Random(7)
    failed = []
    for r in range(30):
        for who in ("a", "b"):
            for i in range(rnd.randint(1, 8)):
                text = "%s%d-%d" % (who, r, i)
                ok = (_say(a, b, B, A, text) if who == "a" else _say(b, a, A, B, text))
                if not ok:
                    failed.append(text)
    assert failed == []
    assert a.get_session(B).ratchet._dh_epoch > 10, "the ratchet did step"


def test_one_way_past_two_boundaries_after_a_round_trip(monkeypatch):
    a, b = _pair(monkeypatch, rekey=3)
    assert _say(a, b, B, A, "hello") and _say(b, a, A, B, "hi")
    assert all(_say(a, b, B, A, "a%d" % i) for i in range(10))
    assert _say(b, a, A, B, "reply")
    assert all(_say(a, b, B, A, "c%d" % i) for i in range(10))


def test_a_chat_open_for_two_days(monkeypatch):
    """The production interval; the clock moved a day, twice. Before the
    fix both directions failed from day three."""
    a, b = _pair(monkeypatch)
    ratchet = a.get_session(B).ratchet
    for text in ("a1", "b1", "a2", "b2"):
        assert _say(a, b, B, A, text) if text[0] == "a" else _say(b, a, A, B, text)
    for day in (2, 3):
        ratchet.last_rekey_time -= 25 * 3600
        assert _say(a, b, B, A, "a on day %d" % day)
        assert _say(b, a, A, B, "b on day %d" % day)
        assert _say(a, b, B, A, "a again on day %d" % day)


def test_one_forced_step_per_remote_key():
    src = open(otr.__file__, encoding="utf-8").read()
    enc = src[src.index("    def encrypt_message(self, plaintext):"):]
    enc = enc[:enc.index("\n    def ", 10)]
    assert '_rekey_target != getattr(self, "_forced_toward", None)' in enc
    new_dh = src[src.index("    def _decrypt_new_dh("):]
    new_dh = new_dh[:new_dh.index("\n    def ", 10)]
    assert "self._forced_toward = dh_pub" in new_dh


def test_the_boundary_is_the_101st_message_after_a_dh_round_trip(monkeypatch):
    """Measured at the production interval (2026-10-27). After a DH round
    trip -- a timer step, then the peer's reply with a new key -- the
    engine before the fix broke at the 101st message from one side with no
    reply: `message_counter_send` reaches REKEY_INTERVAL (100) there, and
    the forced step went toward the key the receive step had already gone
    toward. The fix does not take that step (nor any other in the run): it
    is skipped, not moved, and the rekey waits for the peer's reply."""
    a, b = _pair(monkeypatch)
    ratchet = a.get_session(B).ratchet
    assert _say(a, b, B, A, "hello") and _say(b, a, A, B, "reply")
    ratchet.last_rekey_time -= 25 * 3600                  # a timer step ...
    assert _say(a, b, B, A, "stepped") and _say(b, a, A, B, "new key")   # ... answered
    steps, orig = [], type(ratchet)._ratchet

    def spy(self, remote):
        steps.append(self.message_counter_send)
        return orig(self, remote)

    monkeypatch.setattr(type(ratchet), "_ratchet", spy)
    at_101 = None
    for n in range(1, 202):
        if n == 101:
            at_101 = ratchet.message_counter_send
        assert _say(a, b, B, A, "m%d" % n), n
    assert at_101 == otr.OTRConstants.REKEY_INTERVAL, "the boundary is the 101st message"
    assert steps == [], "no step the peer could not follow"
    assert _say(b, a, A, B, "back")
