# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A handshake that loses a frame, or a peer that restarts, recovers.

Device report: after a VPN switch or a reconnect, OTR sat on "starting"
and tapping Start again did nothing. Measured through two real bridges
before the fix, every one of these stayed stuck:

    DAKE1 lost          -> retry:            PLAINTEXT / PLAINTEXT
    DAKE2 lost          -> retry either side: PLAINTEXT / PLAINTEXT
    DAKE3 lost          -> retry either side: ENCRYPTED / PLAINTEXT
    peer restarted      -> either side:       ENCRYPTED / PLAINTEXT

The engine answered a DAKE1 only from PLAINTEXT, and an explicit Start
on Android sent a bare query the peer ignores.
"""
import collections

import pytest

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp                         # noqa: E402
from android_bridge.events import (MessageReceived,           # noqa: E402
                                   SecurityState, SmpState)
from tests.test_wipe_and_exit import (SECRET, Sink, Wire,      # noqa: E402,F401
                                      _manager, _pair, isolated_home)


def _state(p):
    return (p.alice.security_state(p.bob_jid), p.bob.security_state(p.alice_jid))


ENC = (SecurityState.ENCRYPTED, SecurityState.ENCRYPTED)


def _talks(p, tag="x"):
    """Both directions decrypt; returns what each side received."""
    p.alice.send_user_text(p.bob_jid, "a->b " + tag)
    p.bob.send_user_text(p.alice_jid, "b->a " + tag)
    got_b = [e.body for e in p.bob_sink.events if isinstance(e, MessageReceived)]
    got_a = [e.body for e in p.alice_sink.events if isinstance(e, MessageReceived)]
    return got_a[-1:] == ["b->a " + tag] and got_b[-1:] == ["a->b " + tag]


class Recorder(Wire):
    """A wire that can drop the Nth frame and records what crossed it."""

    def __init__(self, drop=()):
        super().__init__()
        self.drop = set(drop)
        self.count = 0
        self.frames = []

    def send(self, peer, payload):
        self.count += 1
        text = payload if isinstance(payload, str) else payload.decode()
        self.frames.append(text)
        if self.count in self.drop:
            return
        super().send(peer, payload)


def _recorded_pair():
    p = _pair(alice_wire=Recorder())
    p.bob_wire = Recorder()
    p.bob = OtrApp(_manager(), p.bob_wire, p.bob_sink)
    p.alice_wire.peer_app = p.bob
    p.bob_wire.peer_app, p.bob_wire.peer_id = p.alice, p.bob_jid
    return p


def _never_plaintext(p):
    for wire in (p.alice_wire, p.bob_wire):
        for frame in wire.frames:
            assert frame.startswith("?OTRv4"), "a frame left in the clear: %r" % frame[:40]


# ---------------------------------------------------------------------------
# Lost frames
# ---------------------------------------------------------------------------

def test_lost_dake1_recovers_on_retry():
    p = _recorded_pair()
    p.alice_wire.drop = {1}
    p.alice.start_session(p.bob_jid)
    assert _state(p) != ENC
    p.alice.start_session(p.bob_jid)
    assert _state(p) == ENC and _talks(p)
    _never_plaintext(p)


@pytest.mark.parametrize("retrier", ["alice", "bob"])
def test_lost_dake2_recovers_on_retry_from_either_side(retrier):
    p = _recorded_pair()
    p.bob_wire.drop = {1}                          # bob's DAKE2
    p.alice.start_session(p.bob_jid)
    assert _state(p) != ENC
    if retrier == "alice":
        p.alice.start_session(p.bob_jid)
    else:
        p.bob.start_session(p.alice_jid)
    assert _state(p) == ENC and _talks(p)
    _never_plaintext(p)


@pytest.mark.parametrize("retrier", ["alice", "bob"])
def test_lost_dake3_recovers_on_retry_from_either_side(retrier):
    p = _recorded_pair()
    p.alice_wire.drop = {2}                        # alice's DAKE3
    p.alice.start_session(p.bob_jid)
    assert _state(p) == (SecurityState.ENCRYPTED, SecurityState.PLAINTEXT)
    if retrier == "alice":
        # Alice is ENCRYPTED; her request goes out as an encrypted frame
        # bob cannot read, and bob's side answers that with a handshake.
        p.alice.start_session(p.bob_jid)
    else:
        p.bob.start_session(p.alice_jid)
    assert _state(p) == ENC and _talks(p)
    _never_plaintext(p)


def test_a_message_sent_into_a_lost_dake3_recovers_the_session():
    p = _recorded_pair()
    p.alice_wire.drop = {2}
    p.alice.start_session(p.bob_jid)
    p.alice.send_user_text(p.bob_jid, "into the void")
    assert _state(p) == ENC
    assert _talks(p, "after")
    _never_plaintext(p)


# ---------------------------------------------------------------------------
# Peer restart
# ---------------------------------------------------------------------------

def _restart_bob(p):
    otr._dake1_rate_limiter._attempts.clear()
    p.bob_sink = Sink()
    p.bob = OtrApp(_manager(), p.bob_wire, p.bob_sink)
    p.alice_wire.peer_app = p.bob


@pytest.mark.parametrize("who", ["restarted", "survivor"])
def test_a_restarted_peer_recovers_from_either_side(who):
    p = _recorded_pair()
    p.alice.start_session(p.bob_jid)
    assert _state(p) == ENC
    _restart_bob(p)
    assert _state(p) == (SecurityState.ENCRYPTED, SecurityState.PLAINTEXT)
    if who == "restarted":
        p.bob.start_session(p.alice_jid)
    else:
        p.alice.start_session(p.bob_jid)
    assert _state(p) == ENC and _talks(p)
    _never_plaintext(p)


def test_the_replacement_is_a_new_session_and_verification_does_not_carry_over():
    p = _recorded_pair()
    p.alice.start_session(p.bob_jid)
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    old = p.alice._engine.sessions[p.bob_jid]
    _restart_bob(p)
    p.bob.start_session(p.alice_jid)
    new = p.alice._engine.sessions[p.bob_jid]
    assert new is not old
    assert p.alice.smp_state(p.bob_jid) is not SmpState.VERIFIED, (
        "a verification carried over to keys it never checked")
    assert old.ratchet is None or old.session_state.name != "ENCRYPTED"


# ---------------------------------------------------------------------------
# The live session is not disturbed by a handshake that goes nowhere
# ---------------------------------------------------------------------------

def test_a_dake1_that_goes_nowhere_leaves_the_live_session_working():
    p = _recorded_pair()
    p.alice.start_session(p.bob_jid)
    live = p.alice._engine.sessions[p.bob_jid]
    # A stranger's engine (a restarted peer, or an injected frame) makes a
    # DAKE1 addressed as bob; alice answers into the void.
    stranger = _manager()
    d1, _ = stranger.handle_outgoing_message(p.alice_jid, "")
    reply = p.alice._engine.handle_incoming_message(p.bob_jid, d1)
    assert reply and reply.startswith(b"?OTRv4 ")          # a DAKE2
    assert p.alice._engine.sessions[p.bob_jid] is live
    assert p.bob_jid in p.alice._engine._pending_sessions
    assert _talks(p, "still"), "the live session stopped working"


def test_wipe_destroys_a_pending_session():
    p = _recorded_pair()
    p.alice.start_session(p.bob_jid)
    stranger = _manager()
    d1, _ = stranger.handle_outgoing_message(p.alice_jid, "")
    p.alice._engine.handle_incoming_message(p.bob_jid, d1)
    pending = p.alice._engine._pending_sessions[p.bob_jid]
    p.alice._engine.wipe()
    assert not p.alice._engine._pending_sessions
    assert pending.session_state.name in ("FINISHED", "FAILED", "PLAINTEXT")


# ---------------------------------------------------------------------------
# Glare: both sides start at once
# ---------------------------------------------------------------------------

class Held(Wire):
    """Queues frames until pumped: both sides can send before either hears."""

    def __init__(self):
        super().__init__()
        self.queue = collections.deque()
        self.frames = []

    def send(self, peer, payload):
        text = payload if isinstance(payload, str) else payload.decode()
        self.frames.append(text)
        self.queue.append(text)


def _pump(p, limit=40):
    for _ in range(limit):
        moved = False
        for wire in (p.alice_wire, p.bob_wire):
            if wire.queue:
                wire.peer_app.receive_message(wire.peer_id, wire.queue.popleft())
                moved = True
        if not moved:
            return
    raise AssertionError("frames kept flowing: the two sides are ping-ponging")


@pytest.mark.parametrize("run", range(6))
def test_glare_settles_on_exactly_one_initiator(run):
    p = _pair(alice_wire=Held())
    p.bob_wire = Held()
    p.bob = OtrApp(_manager(), p.bob_wire, p.bob_sink)
    p.alice_wire.peer_app = p.bob
    p.bob_wire.peer_app, p.bob_wire.peer_id = p.alice, p.bob_jid
    p.alice.start_session(p.bob_jid)
    p.bob.start_session(p.alice_jid)
    _pump(p)
    assert _state(p) == ENC
    p.alice.send_user_text(p.bob_jid, "hello")
    _pump(p)
    assert [e.body for e in p.bob_sink.events if isinstance(e, MessageReceived)] == ["hello"]
    _never_plaintext(p)


# ---------------------------------------------------------------------------
# Automatic recovery is bounded
# ---------------------------------------------------------------------------

def test_orphan_recovery_is_rate_limited():
    p = _recorded_pair()
    p.alice.start_session(p.bob_jid)
    _restart_bob(p)
    now = [1000.0]
    p.bob._clock = lambda: now[0]
    p.bob_wire.cut = True                 # bob's handshakes go nowhere
    mark = len(p.bob_wire.frames)

    def handshakes():
        return [f for f in p.bob_wire.frames[mark:] if f.startswith("?OTRv4 ")]

    for i in range(5):
        p.alice.send_user_text(p.bob_jid, "m%d" % i)
    assert len(handshakes()) == 1, "a stream of frames made bob send %d handshakes" % len(handshakes())
    now[0] += OtrApp.RECOVERY_INTERVAL + 1
    p.alice.send_user_text(p.bob_jid, "later")
    assert len(handshakes()) == 2
