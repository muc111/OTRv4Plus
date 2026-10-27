# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Make Chat Deniable, audited from the wire: what an outsider can do.

The mechanism is meant for a transcript someone ELSE holds: the peer's
copy, or a recording of the traffic. No deniability property is claimed for
it (docs/SECURITY_ISSUES.md L1, RESOLVED-CODE); this shows what the wire
carries. So this test is that someone. It holds every frame two real apps put
on the wire -- nothing else, no key from either app -- and checks, after
Make Chat Deniable, what the property needs:

  * every DATA message that carried a line has its MAC key on the wire, in a
    `revealed_mac_keys` field read without any secret -- so its MAC is no
    longer evidence: anyone with the transcript can re-MAC it, or MAC a
    changed one;
  * that holds for messages lost on the way and delivered out of order, and
    in both directions;
  * a revealed key appears only AFTER the message it authenticated was
    delivered (a key published early would let a forger race the message);
  * nothing is revealed that authenticates the new session.
"""
from __future__ import annotations

import collections
import os
import tempfile
import types

import pytest

pytest.importorskip("otrv4_core")

import test_smp_end_to_end as E                                  # noqa: E402
from android_bridge.app import OtrApp, Transport                 # noqa: E402
from android_bridge.events import SecurityState                  # noqa: E402

otr = E.otr
core = pytest.importorskip("otrv4_core")
ALICE, BOB = "alice@example.test", "bob@example.test"


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


class Wire:
    """Everything either app sends, in order, as an eavesdropper sees it.
    [hold] / [lose] decide per frame: held frames are delivered later, lost
    ones never (but were on the wire)."""

    def __init__(self):
        self.apps, self.frames, self.q, self.busy = {}, [], collections.deque(), False
        self.lose = lambda frm, to, body: False
        self.lost = set()
        self.held = []
        self.hold = lambda frm, to, body: False

    def push(self, frm, to, body):
        self.frames.append((frm, to, body))
        if self.lose(frm, to, body):
            self.lost.add(len(self.frames) - 1)   # on the sender's link only
            return
        if self.hold(frm, to, body):
            self.held.append((frm, to, body))
            return
        self.q.append((frm, to, body))
        self._pump()

    def release_held(self):
        held, self.held = self.held, []
        self.q.extend(held)
        self._pump()

    def _pump(self):
        if self.busy:
            return
        self.busy = True
        try:
            while self.q:
                frm, to, body = self.q.popleft()
                self.delivered.append(len(self.frames))
                self.apps[to].receive_message(frm, body)
        finally:
            self.busy = False

    delivered: list = []


class Link(Transport):
    def __init__(self, wire, jid):
        self.wire, self.jid = wire, jid
        self._profile = types.SimpleNamespace(jid=jid + "/phone")
        self.is_connected = True

    def send(self, peer, payload):
        self.wire.push(self.jid, peer.split("/")[0], payload)

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return []


def _pair():
    wire = Wire()
    wire.delivered = []
    apps = {}
    for jid in (ALICE, BOB):
        a = OtrApp(E._manager(), Link(wire, jid))
        a.otr_capability = lambda peer: "available"
        a.GROUP_STATE_DIR = os.path.join(tempfile.mkdtemp(), "groups")
        apps[jid] = wire.apps[jid] = a
    apps[ALICE].ensure_otr(BOB)
    assert apps[ALICE].security_state(BOB) is not SecurityState.PLAINTEXT
    return wire, apps[ALICE], apps[BOB]


def _data(body):
    """The DATA message in a frame, decoded with no key at all; or None."""
    if not body.startswith("?OTRv4 "):
        return None
    try:
        raw = otr._safe_b64decode(body[len("?OTRv4 "):].strip())
        if not otr.OTRv4DataMessage.looks_like_data_frame(raw):
            return None
        return otr.OTRv4DataMessage.decode(raw)
    except Exception:
        return None


def _revealed_on_the_wire(frames):
    keys = []
    for _frm, _to, body in frames:
        msg = _data(body)
        if msg is not None:
            keys.extend(bytes(k) for k in msg.revealed_mac_keys)
    return keys


def _key_for(msg, keys):
    """The revealed key, if any, that re-MACs [msg] -- what a forger needs."""
    region = msg.auth_region()
    for k in keys:
        if core.MessageMacKey.from_revealed(k).verify(region, msg.mac):
            return k
    return None


def _talk(wire, alice, bob, script):
    """Send the lines; returns the indexes (in wire.frames) of their DATA frames."""
    lines = []
    for who, text in script:
        sender, peer = (alice, BOB) if who == "a" else (bob, ALICE)
        before = len(wire.frames)
        sender.send_user_text(peer, text)
        lines.extend(i for i in range(before, len(wire.frames))
                     if _data(wire.frames[i][2]) is not None)
    return lines


SCRIPT = [("a", "one"), ("a", "two"), ("b", "three"), ("a", "four"),
          ("b", "five"), ("b", "six"), ("a", "seven"), ("b", "eight")]


def _audit(wire, lines, arrived_only=False):
    """[arrived_only]: the transcript as the server and the peer hold it --
    a frame lost on the way is not in it. Otherwise everything the sender's
    link carried, lost frames included."""
    frames = ([f for i, f in enumerate(wire.frames) if i not in wire.lost]
              if arrived_only else wire.frames)
    keys = _revealed_on_the_wire(frames)
    missing = [i for i in lines if _key_for(_data(wire.frames[i][2]), keys) is None]
    return keys, missing


def test_every_line_in_both_directions_has_its_mac_key_on_the_wire():
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT)
    assert len(lines) == len(SCRIPT)
    assert alice.make_chat_deniable(BOB, restart=False).startswith("made_deniable")
    keys, missing = _audit(wire, lines)
    assert keys, "nothing was revealed"
    assert missing == [], "lines whose MAC is still evidence: %r" % missing


def test_every_line_is_covered_across_dh_steps(monkeypatch):
    """The scripts above stay on the handshake's chains (the first DH step
    comes after 100 messages). Here a step every 3 messages, bursts both
    ways: the first message of every new DH chain is covered as well.
    Audit 2026-10-26: without this, removing R1 for that message (the
    receive step's retirement) failed no test."""
    monkeypatch.setattr(otr.OTRConstants, "REKEY_INTERVAL", 3)
    wire, alice, bob = _pair()
    script = [(who, "%s%d" % (who, i)) for i, who in enumerate("aaaabbbbbaabbbaaaaab")]
    lines = _talk(wire, alice, bob, script)
    assert len(lines) == len(script)
    steps = alice._engine.get_session(BOB).ratchet._dh_epoch
    assert steps >= 3, "DH steps happened (%d)" % steps
    assert alice.make_chat_deniable(BOB, restart=False).startswith("made_deniable")
    _keys, missing = _audit(wire, lines)
    assert missing == [], "lines still provable across DH steps: %r" % missing


def test_a_lost_and_an_out_of_order_line_are_covered_too():
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT[:3])
    state = {"lost": False, "held": False}

    def lose(frm, to, body):
        if frm == ALICE and _data(body) is not None and not state["lost"]:
            state["lost"] = True
            return True
        return False

    def hold(frm, to, body):
        if frm == BOB and _data(body) is not None and not state["held"]:
            state["held"] = True
            return True
        return False

    wire.lose, wire.hold = lose, hold
    lines += _talk(wire, alice, bob, [("a", "lost on the way"), ("a", "after it"),
                                      ("b", "late"), ("b", "on time")])
    wire.lose, wire.hold = (lambda *a: False), (lambda *a: False)
    wire.release_held()                      # the late one arrives after its successor
    assert state["lost"] and state["held"]
    assert alice.make_chat_deniable(BOB, restart=False).startswith("made_deniable")
    _keys, missing = _audit(wire, lines)
    assert missing == [], "lost or reordered lines still provable: %r" % missing


def test_a_key_is_never_on_the_wire_before_its_message_was_delivered():
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT)
    alice.make_chat_deniable(BOB, restart=False)
    first_seen = {}
    for idx, (_f, _t, body) in enumerate(wire.frames):
        msg = _data(body)
        for k in (msg.revealed_mac_keys if msg is not None else []):
            first_seen.setdefault(bytes(k), idx)
    for i in lines:
        k = _key_for(_data(wire.frames[i][2]), list(first_seen))
        assert first_seen[k] > i, "frame %d's key was out before it" % i


def test_the_new_session_is_not_authenticated_by_anything_revealed():
    wire, alice, bob = _pair()
    _talk(wire, alice, bob, SCRIPT[:4])
    alice.make_chat_deniable(BOB)                     # and a new session starts
    assert alice.security_state(BOB) is not SecurityState.PLAINTEXT
    old_keys = _revealed_on_the_wire(wire.frames)
    after = _talk(wire, alice, bob, [("a", "new session"), ("b", "reply")])
    assert after, "the new session carried the lines"
    for i in after:
        assert _key_for(_data(wire.frames[i][2]), old_keys) is None


def test_the_peer_ending_it_publishes_what_the_peer_received():
    """Bob presses it: Alice's lines (which Bob received) are covered by
    Bob's closing message, and Bob's lines by Alice's answer to it."""
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT)
    assert bob.make_chat_deniable(ALICE, restart=False).startswith("made_deniable")
    _keys, missing = _audit(wire, lines)
    assert missing == []


def test_residual_a_peer_that_never_closes_leaves_our_lines_provable():
    """SECURITY_ISSUES.md L1, "The second closing": each side publishes the
    keys of what it RECEIVED. Alice presses it; Bob's app never reads her
    closing message, so it never closes. Bob's lines are covered by Alice's
    closing message. Alice's last line, which Bob received after he last
    sent anything, keeps its MAC key in Bob's ratchet, unpublished: exactly
    that line stays provable."""
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT + [("a", "nine")])
    last = lines[-1]
    wire.hold = lambda frm, to, body: frm == ALICE   # on the wire, never read
    alice.make_chat_deniable(BOB, restart=False)
    assert wire.held, "Alice's closing messages are on the wire, unread"
    _keys, missing = _audit(wire, lines)
    assert missing == [last], "only the line after Bob's last message: %r" % missing


def test_the_audit_sees_it_when_the_closing_messages_are_lost():
    """Negative control: drop every frame from the press on. The lines stay
    provable -- which is why Make Chat Deniable now asks the server to
    confirm the closing messages, and re-sends the unconfirmed ones."""
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT)
    n = len(wire.frames)
    wire.lose = lambda *a: True
    alice.make_chat_deniable(BOB, restart=False)
    assert wire.frames[n:], "the closing messages were sent, and lost"
    # Only what the wire carried BEFORE the press is out: the reveals during
    # the conversation (R1) cover some lines, never the last ones.
    keys_before = _revealed_on_the_wire(wire.frames[:n])
    still = [i for i in lines if _key_for(_data(wire.frames[i][2]), keys_before) is None]
    assert still, "without the closing messages some lines stay provable"


def test_sign_out_publishes_every_line_too():
    """Sign-out closes every session the same way (SPEC §5.8, Close)."""
    wire, alice, bob = _pair()
    lines = _talk(wire, alice, bob, SCRIPT)
    alice.shutdown()
    _keys, missing = _audit(wire, lines)
    assert missing == []


# ── a close over the per-message bound: several closing messages ─────────────

class TestMultiPartClose:
    """More retired keys than one closing message may carry (REVEAL_FIELD_MAX,
    2000) means several closing messages, each publishing its own range,
    oldest first. Alice sends 2150 lines, Bob sends nothing, Alice presses:
    Bob's close publishes the 2150 keys in two parts."""

    N = 2150
    BOUND = 2000

    def _run(self, lose_part=None):
        wire, alice, bob = _pair()
        lines = []
        for i in range(self.N):
            before = len(wire.frames)
            alice.send_user_text(BOB, "line %d" % i)
            lines.extend(j for j in range(before, len(wire.frames))
                         if _data(wire.frames[j][2]) is not None)
        assert len(lines) == self.N
        n = len(wire.frames)
        state = {"bob_parts": 0}

        def lose(frm, to, body):
            if frm == BOB and _data(body) is not None:
                state["bob_parts"] += 1
                return state["bob_parts"] == lose_part
            return False

        wire.lose = lose
        alice.make_chat_deniable(BOB, restart=False)
        bob_parts = [_data(b) for f, _t, b in wire.frames[n:] if f == BOB and _data(b)]
        return wire, lines, bob_parts

    def test_bobs_close_is_two_parts_each_with_its_own_range(self):
        wire, lines, parts = self._run()
        # Part 2 also carries the keys of what Bob received at the press:
        # Alice's "keys published" message (app_deniable, 2026-10-27) and her
        # closing message.
        assert [len(p.revealed_mac_keys) for p in parts] == [self.BOUND, self.N - self.BOUND + 2]
        first = {bytes(k) for k in parts[0].revealed_mac_keys}
        second = {bytes(k) for k in parts[1].revealed_mac_keys}
        assert not first & second, "no key in two parts"
        _keys, missing = _audit(wire, lines)
        assert missing == [], "both parts out: every line deniable"
        covered_by_first = [i for i in lines if _key_for(_data(wire.frames[i][2]), list(first))]
        assert covered_by_first == lines[:self.BOUND], "part 1: exactly the oldest 2000"

    def test_a_lost_second_part_leaves_exactly_its_range_provable(self):
        """The audit refuses the transcript: the deniability claim does not
        hold for it. Part 1's range is deniable, part 2's is not."""
        wire, lines, parts = self._run(lose_part=2)
        _keys, missing = _audit(wire, lines, arrived_only=True)
        assert missing == lines[self.BOUND:], "the last 150 lines stay provable"
        assert missing, "the audit rejects this transcript"
        # The client keeps the lost part until the server confirms it, and
        # sends it again (app_deniable.py): that is what closes the gap.
        bob = wire.apps[BOB]
        assert len([e for e in bob._closings() if e[2]]) == 2, "both parts kept unconfirmed"
        bob._resend_closings_now()
        _keys, missing = _audit(wire, lines, arrived_only=True)
        assert missing == [], "re-sent: the gap closes"
