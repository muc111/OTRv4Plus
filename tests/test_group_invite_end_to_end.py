# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Secure-group invitations, end to end between two real apps.

Owner (2026-10-26): "Mls group invite is not working both methods invite
name or list online and invite isn't working other client didn't receive."

Two `OtrApp`s with real engines and real MLS state, joined by an in-memory
network for 1:1 frames and one shared room. What these found: the automatic
OTRv4+ start that an invitation waits on (`ensure_otr`, `_auto_start`, a
queued send) declined whenever ANY session object existed for the peer --
one that had ended, or a handshake whose DAKE message was lost (over I2P, or
refused by the peer's DAKE1 rate limit after a quick Make Chat Deniable). The
invitation then waited for a handshake nobody was running, until the app
restarted. Now a stalled handshake is started again (`_handshake_running`,
`retry_stalled_handshakes` on the UI's event tick).
"""
from __future__ import annotations

import collections
import os
import tempfile
import time
import types

import pytest

pytest.importorskip("otrv4_core")

import test_smp_end_to_end as E                                    # noqa: E402
from android_bridge.app import OtrApp, Transport                   # noqa: E402
from android_bridge.events import GroupInvite, SecurityState       # noqa: E402

otr = E.otr
ROOM = "team@conference.example.test"
ALICE, BOB, CAROL, DAVE = ("alice@example.test", "bob@example.test",
                           "carol@example.test", "dave@example.test")


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


@pytest.fixture
def clock(monkeypatch):
    """time.monotonic, moved by the test (the DAKE timeout and the retry)."""
    now = [time.monotonic()]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    return now


class Net:
    """1:1 frames and one room, delivered in order. [drop] decides, per
    frame, whether the network loses it."""

    def __init__(self):
        self.apps, self.q, self.log, self.busy = {}, collections.deque(), [], False
        self.drop = lambda kind, frm, to, body: False

    def push(self, item):
        if self.drop(*item):
            self.log.append(("lost",) + item[1:3])
            return
        self.q.append(item)
        if self.busy:
            return
        self.busy = True
        try:
            while self.q:
                kind, frm, to, body = self.q.popleft()
                self.log.append((kind, frm, to))
                if kind == "chat":
                    self.apps[to].receive_message(frm, body)
                else:
                    for jid, app in list(self.apps.items()):
                        if ROOM in app._rooms:
                            app.receive_room_message(ROOM, frm.split("@")[0], body,
                                                     own=(jid == frm))
        finally:
            self.busy = False


class Wire(Transport):
    def __init__(self, net, jid):
        self.net, self.jid = net, jid
        self._profile = types.SimpleNamespace(jid=jid + "/phone")
        self.is_connected = True

    def send(self, peer, payload):
        self.net.push(("chat", self.jid, peer.split("/")[0], payload))

    def send_room_message(self, room, body, volatile=False):
        self.net.push(("room", self.jid, room, body))

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return [{"jid": j, "subscription": "both"} for j in self.net.apps if j != self.jid]


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


def _app(net, jid, monkeypatch, stored_identity=False):
    home = tempfile.mkdtemp()
    a = OtrApp(E._manager(), Wire(net, jid), Sink())
    a.GROUP_STATE_DIR = os.path.join(home, "groups")
    a.otr_capability = lambda peer: "available"
    if stored_identity:                      # F3, as the apps run it
        monkeypatch.setenv("HOME", home)
        from android_bridge.account_identity import for_desktop
        a.use_identity_store(for_desktop())
        a.bind_identity_account(jid)
        a.note_signed_in(jid)
    net.apps[jid] = a
    a.open_groups(jid)
    return a


def _invited(app, room=ROOM):
    return [e for e in app._sink.events if isinstance(e, GroupInvite) and e.room == room]


def _group(net, creator):
    creator.note_room_joined(ROOM)
    creator.groups.create(ROOM)


# ── the two ways to invite ──────────────────────────────────────────────────

@pytest.mark.parametrize("stored_identity", [False, True])
def test_invite_by_name_with_no_session_yet(monkeypatch, stored_identity):
    net = Net()
    alice = _app(net, ALICE, monkeypatch, stored_identity)
    bob = _app(net, BOB, monkeypatch, stored_identity)
    _group(net, alice)
    assert alice.invite_when_ready(ROOM, BOB) == "waiting_for_otr"
    assert _invited(bob), "the invitation went once OTRv4+ was up"


def test_invite_with_the_chat_already_open(monkeypatch):
    net = Net()
    alice, bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    alice.ensure_otr(BOB)
    _group(net, alice)
    assert alice.invite_when_ready(ROOM, BOB) == "sent"
    assert _invited(bob)


def test_everyone_picked_from_the_online_list_is_invited(monkeypatch):
    net = Net()
    alice = _app(net, ALICE, monkeypatch)
    others = [_app(net, j, monkeypatch) for j in (BOB, CAROL, DAVE)]
    alice.ensure_otr(CAROL)                  # one already talking, two not
    _group(net, alice)
    for jid in (BOB, CAROL, DAVE):
        alice.invite_when_ready(ROOM, jid)
    for other in others:
        assert _invited(other), other._own_bare()


@pytest.mark.parametrize("who_made_it_deniable", ["inviter", "invitee"])
def test_invite_after_make_chat_deniable(monkeypatch, who_made_it_deniable):
    net = Net()
    alice, bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    alice.ensure_otr(BOB)
    if who_made_it_deniable == "inviter":
        alice.make_chat_deniable(BOB)
    else:
        bob.make_chat_deniable(ALICE)
    _group(net, alice)
    alice.invite_when_ready(ROOM, BOB)
    assert _invited(bob)


# ── the defect: a lost handshake message left the invitation waiting ────────

def _lose_first(kind_prefix):
    """Drop the first 1:1 frame whose base64 starts like [kind_prefix]."""
    state = {"done": False}

    def drop(kind, frm, to, body):
        if kind == "chat" and not state["done"] and body.startswith(kind_prefix):
            state["done"] = True
            return True
        return False
    return drop


@pytest.mark.parametrize("lost", ["?OTRv4 N"])        # a DAKE message
def test_a_lost_handshake_message_is_recovered_and_the_invite_arrives(monkeypatch, clock, lost):
    net = Net()
    alice, bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    _group(net, alice)
    net.drop = _lose_first(lost)
    alice.invite_when_ready(ROOM, BOB)
    assert any(entry[0] == "lost" for entry in net.log)
    assert not _invited(bob)
    assert alice.security_state(BOB) is SecurityState.PLAINTEXT
    # Young: left alone. Nothing restarts a handshake that may still finish.
    clock[0] += 30
    alice.retry_stalled_handshakes()
    assert not _invited(bob)
    # Past the DAKE timeout: started again, and the invitation goes.
    clock[0] += OtrApp.HANDSHAKE_STALL_SECONDS
    assert alice.retry_stalled_handshakes() == 1
    assert _invited(bob)


def test_a_session_object_with_no_handshake_never_blocks_a_start(monkeypatch):
    """A session object that is not handshaking (ended, or never started)
    used to read as 'a handshake is in progress', so nothing started one."""
    net = Net()
    alice, bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    alice._engine.get_or_create_session(BOB)
    assert alice._engine.has_session(BOB)
    assert not alice._handshake_running(BOB)
    _group(net, alice)
    alice.invite_when_ready(ROOM, BOB)
    assert _invited(bob)


def test_the_retry_is_bounded(monkeypatch, clock):
    net = Net()
    alice, bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    _group(net, alice)
    net.drop = lambda kind, frm, to, body: kind == "chat"      # nothing gets through
    alice.invite_when_ready(ROOM, BOB)
    clock[0] += OtrApp.HANDSHAKE_STALL_SECONDS + 1
    assert alice.retry_stalled_handshakes() == 1
    clock[0] += OtrApp.RETRY_LOOK_SECONDS + 1
    assert alice.retry_stalled_handshakes() == 0, "the new handshake is young"
    clock[0] += 1
    assert alice.retry_stalled_handshakes() == 0, "not more often than it looks"
    clock[0] += OtrApp.HANDSHAKE_STALL_SECONDS + OtrApp.RETRY_LOOK_SECONDS
    assert alice.retry_stalled_handshakes() == 1, "once per stall period"


def test_nothing_waiting_nothing_started(monkeypatch, clock):
    net = Net()
    alice, _bob = _app(net, ALICE, monkeypatch), _app(net, BOB, monkeypatch)
    clock[0] += 1000
    assert alice.retry_stalled_handshakes() == 0
    assert net.log == []


def test_the_ui_tick_runs_the_retry():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "android_bridge", "connection.py"), encoding="utf-8").read()
    fn = src[src.index("    def drain_events("):src.index("    def add_contact(")]
    assert "self._app.retry_stalled_handshakes()" in fn
    assert fn.index("retry_stalled_handshakes") < fn.index("return self._events.drain(limit)")


def test_no_automatic_start_asks_has_session_any_more():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "android_bridge", "app.py"), encoding="utf-8").read()
    for name in ("    def ensure_otr(", "    def _auto_start(", "    def send_message("):
        if name not in src:
            continue
        body = src[src.index(name):]
        body = body[:body.index("\n    def ", 10)]
        assert "has_session(" not in body, name
