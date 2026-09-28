# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Secure groups through real OtrApp bridges.

Two bridges with a real OTRv4+ session (DAKE + SMP) set a group up over it;
a simulated MUC carries the MLS frames and reflects them to the sender, as
XEP-0045 does. What is checked is the wiring: that the setup really rides the
encrypted session, that room text is MLS in both directions, and that a
secure room never shows or sends plaintext.
"""
import pytest

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

from android_bridge.app import OtrApp                            # noqa: E402
from android_bridge.events import (GroupChanged, GroupInvite,    # noqa: E402
                                   MessageReceived, RoomMessageReceived)
from tests.test_wipe_and_exit import (SECRET, Sink, Wire,         # noqa: E402,F401
                                      _manager, isolated_home)

ROOM = "sealed@conference.example.test"


class Muc:
    def __init__(self):
        self.members = {}         # nick -> app
        self.bodies = []

    def post(self, nick, body):
        self.bodies.append(body)
        for other, app in list(self.members.items()):
            if other == nick:
                app.receive_room_message(ROOM, nick, body, 0.0, own=True)
            else:
                app.receive_room_message(ROOM, nick, body, 0.0)


class RoomWire(Wire):
    def __init__(self, muc, nick):
        super().__init__()
        self.muc, self.nick = muc, nick
        self.private = []

    def send(self, peer, payload):
        text = payload if isinstance(payload, str) else payload.decode()
        self.private.append(text)
        super().send(peer, text)

    def send_room_message(self, room, body):
        self.muc.post(self.nick, body)


@pytest.fixture
def pair():
    muc = Muc()
    a_jid, b_jid = "alice@example.test", "bob@example.test"
    otr._dake1_rate_limiter._attempts.clear()
    aw, bw = RoomWire(muc, "alice"), RoomWire(muc, "bob")
    asink, bsink = Sink(), Sink()
    a, b = OtrApp(_manager(), aw, asink), OtrApp(_manager(), bw, bsink)
    aw.peer_app, aw.peer_id = b, a_jid
    bw.peer_app, bw.peer_id = a, b_jid
    a.open_groups(a_jid)
    b.open_groups(b_jid)
    a.start_session(b_jid)
    a.smp_start(b_jid, SECRET)
    b.smp_respond(a_jid, SECRET)
    yield muc, (a, aw, asink, a_jid), (b, bw, bsink, b_jid)
    for app in (a, b):
        try:
            app.shutdown()
        except Exception:
            pass


def _setup(muc, A, B):
    a, aw, asink, a_jid = A
    b, bw, bsink, b_jid = B
    a.note_room_joined(ROOM)
    muc.members["alice"] = a
    a.groups.create(ROOM)
    a.groups.invite(ROOM, b_jid)
    assert any(isinstance(e, GroupInvite) and e.room == ROOM and e.verified
               for e in bsink.events), "bob never saw the invitation"
    b.note_room_joined(ROOM)
    muc.members["bob"] = b
    b.groups.accept(ROOM)
    assert b.groups.is_secure(ROOM), [e for e in bsink.events if isinstance(e, GroupChanged)]


def test_setup_rides_the_encrypted_session_and_the_room_carries_only_mls(pair):
    muc, A, B = pair
    _setup(muc, A, B)
    a, aw, asink, a_jid = A
    b, bw, bsink, b_jid = B
    # Every setup message left as an OTRv4+ protocol frame (encrypted).
    for frame in aw.private + bw.private:
        assert frame.startswith(("?OTRv4 ", "?OTRv4F|")), frame[:40]
        assert "?OTRv4-MLS:" not in frame
    # Room text, both ways, as MLS.
    assert a.send_user_text(ROOM, "hello bob, secretly") == OtrApp.SEND_ENCRYPTED
    got = [e for e in bsink.events if isinstance(e, RoomMessageReceived)]
    assert got[-1].body == "hello bob, secretly"
    assert got[-1].encrypted and got[-1].verified
    assert got[-1].sender_identity == a_jid
    assert b.send_user_text(ROOM, "and back") == OtrApp.SEND_ENCRYPTED
    got = [e for e in asink.events if isinstance(e, RoomMessageReceived)]
    assert got[-1].body == "and back" and got[-1].encrypted
    for body in muc.bodies:
        assert body.startswith(("?OTRv4MLS1:", "?OTRv4F|")), body[:30]
        assert "secretly" not in body and "and back" not in body
    # The group setup never surfaced as a chat message.
    assert not [e for e in bsink.events
                if isinstance(e, MessageReceived) and "OTRv4-MLS" in e.body]


def test_a_secure_room_shows_no_plaintext_and_sends_none(pair):
    muc, A, B = pair
    _setup(muc, A, B)
    a, aw, asink, a_jid = A
    b, bw, bsink, b_jid = B
    before = len([e for e in bsink.events if isinstance(e, RoomMessageReceived)])
    b.receive_room_message(ROOM, "mallory", "plain text in a secure room", 0.0)
    after = [e for e in bsink.events if isinstance(e, RoomMessageReceived)]
    assert len(after) == before
    # A commit lost in transit leaves Alice's group waiting: sending fails
    # rather than posting text.
    muc.members.pop("alice")
    muc.members.pop("bob")
    a.groups.rekey(ROOM)
    n = len(muc.bodies)
    assert a.send_user_text(ROOM, "must not leak") == OtrApp.SEND_FAILED
    assert all("must not leak" not in body for body in muc.bodies[n:])


def test_a_plain_room_is_unchanged(pair):
    muc, A, B = pair
    a, aw, asink, a_jid = A
    b, bw, bsink, b_jid = B
    plain = "lobby@conference.example.test"
    b.note_room_joined(plain)
    b.receive_room_message(plain, "carol", "hi all", 0.0)
    got = [e for e in bsink.events if isinstance(e, RoomMessageReceived)]
    assert got[-1].body == "hi all" and not got[-1].encrypted
    # Our own reflection in a plain room is still not shown twice.
    b.receive_room_message(plain, "bob", "?OTRv4F|x|1|2|y", 0.0, own=True)
    assert len([e for e in bsink.events if isinstance(e, RoomMessageReceived)]) == len(got)


def test_wipe_destroys_the_group_state(pair):
    muc, A, B = pair
    _setup(muc, A, B)
    a = A[0]
    a.wipe_crypto()
    assert a.groups.wiped
    assert not a.groups.is_secure(ROOM)
