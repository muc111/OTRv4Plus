# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OTRv4Plus secure groups: MLS over a room, set up over OTRv4+.

A simulated MUC relays every body to every occupant in one order, the sender
included (XEP-0045 reflection), and can drop, duplicate, replay or tamper. A
simulated OTRv4+ side channel stands in for an encrypted 1:1 session, with
its SMP state per pair. The MLS is the real Rust core.
"""
import base64
import os
import tempfile

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

from android_bridge.events import (ErrorOccurred, GroupChanged,      # noqa: E402
                                   GroupInvite, RoomMessageReceived,
                                   SecurityState)
from android_bridge.groups import (ROOM_PREFIX, SIGNAL_PREFIX,       # noqa: E402
                                   GroupError, SecureGroups)

ROOM = "secret@conference.example.i2p"


class Room:
    def __init__(self):
        self.occupants = {}          # jid -> Member
        self.log = []                # every body posted, in order
        self.drop_next = 0
        self.tamper_next = False

    def post(self, sender_jid, body):
        if self.drop_next:
            self.drop_next -= 1
            return
        if self.tamper_next and body.startswith((ROOM_PREFIX, "?OTRv4F|")):
            # One base64 character in the middle of the payload, changed to
            # another valid one: a different ciphertext byte, same length.
            self.tamper_next = False
            i = len(body) - 40
            body = body[:i] + ("A" if body[i] != "A" else "B") + body[i + 1:]
        self.log.append((sender_jid, body))
        nick = sender_jid.split("@")[0]
        for jid, m in list(self.occupants.items()):
            m.groups.on_room_body(ROOM, nick, body, 0.0, own=(jid == sender_jid))

    def replay(self, index):
        sender_jid, body = self.log[index]
        nick = sender_jid.split("@")[0]
        for jid, m in list(self.occupants.items()):
            m.groups.on_room_body(ROOM, nick, body, 0.0, own=(jid == sender_jid))


class World:
    def __init__(self, state_root=None):
        self.room = Room()
        self.members = {}
        self.otr = {}                # frozenset({a, b}) -> SecurityState
        self.cut_private = False
        self.state_root = state_root

    def add(self, jid, state_dir=None):
        m = Member(self, jid, state_dir)
        self.members[jid] = m
        return m

    def pair(self, a, b, level=SecurityState.SMP_VERIFIED):
        self.otr[frozenset((a, b))] = level

    def private(self, frm, to, body):
        if self.cut_private:
            return
        self.members[to].groups.on_signal(frm, body)


class Member:
    def __init__(self, world, jid, state_dir=None):
        self.world, self.jid = world, jid
        self.events = []
        self.groups = SecureGroups(
            send_room=lambda room, body: world.room.post(jid, body),
            send_private=lambda peer, body: world.private(jid, peer, body),
            emit=self.events.append,
            peer_security=lambda peer: world.otr.get(frozenset((jid, peer)),
                                                     SecurityState.PLAINTEXT),
            state_dir=state_dir)
        self.groups.open(jid)

    def texts(self):
        return [(e.sender_identity, e.body, e.verified) for e in self.events
                if isinstance(e, RoomMessageReceived)]

    def changes(self):
        return [e.change for e in self.events if isinstance(e, GroupChanged)]

    def errors(self):
        return [e.code for e in self.events if isinstance(e, ErrorOccurred)]

    def join_room(self):
        self.world.room.occupants[self.jid] = self


def _invite(world, inviter, invitee):
    a, b = world.members[inviter], world.members[invitee]
    b.join_room()
    a.groups.invite(ROOM, invitee)
    assert any(isinstance(e, GroupInvite) and e.room == ROOM for e in b.events)
    b.groups.accept(ROOM)


def _group(n=3, levels=None):
    w = World()
    names = ["alice@x.i2p", "bob@x.i2p", "carol@x.i2p", "dave@x.i2p"][:n]
    for name in names:
        w.add(name)
    a = w.members[names[0]]
    a.join_room()
    a.groups.create(ROOM)
    for other in names[1:]:
        w.pair(names[0], other, (levels or {}).get(other, SecurityState.SMP_VERIFIED))
        _invite(w, names[0], other)
    return w, [w.members[x] for x in names]


def test_three_members_join_and_talk_with_only_ciphertext_in_the_room():
    w, (a, b, c) = _group(3)
    for m in (a, b, c):
        assert m.groups.is_secure(ROOM)
        assert len(m.groups.members(ROOM)) == 3
    a.groups.send(ROOM, "hello secure room")
    assert ("alice@x.i2p", "hello secure room", True) in b.texts()
    assert ("alice@x.i2p", "hello secure room", True) in c.texts()
    assert a.texts() == [], "the sender's own reflection was shown twice"
    for _sender, body in w.room.log:
        assert body.startswith((ROOM_PREFIX, "?OTRv4F|")), body[:30]
        assert "hello secure room" not in body


def test_verification_comes_from_the_otr_session_not_membership():
    w, (a, b, c) = _group(3, levels={"carol@x.i2p": SecurityState.ENCRYPTED})
    a.groups.send(ROOM, "x")
    # Alice bound Bob over an SMP-verified session, Carol over an unverified one.
    by_jid = {m["jid"]: m for m in a.groups.members(ROOM)}
    assert by_jid["bob@x.i2p"]["verified"] is True
    assert by_jid["carol@x.i2p"]["verified"] is False
    assert by_jid["carol@x.i2p"]["bound"] is True
    # Bob never had an OTR session with Carol: he sees her, unverified.
    b_view = {m["jid"]: m for m in b.groups.members(ROOM)}
    assert b_view["carol@x.i2p"]["verified"] is False
    assert b_view["alice@x.i2p"]["verified"] is True
    c.groups.send(ROOM, "from carol")
    assert ("carol@x.i2p", "from carol", False) in b.texts()


def test_setup_requires_an_encrypted_otr_session():
    w = World()
    a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
    a.join_room()
    a.groups.create(ROOM)
    with pytest.raises(GroupError) as e:
        a.groups.invite(ROOM, "bob@x.i2p")
    assert e.value.code == "otr_required"
    # A signal arriving without an encrypted session is refused.
    b.groups.on_signal("alice@x.i2p", SIGNAL_PREFIX + "INVITE:%s|%s" % (ROOM, "0" * 96))
    assert "group_signal_unencrypted" in b.errors()
    assert not b.groups.pending_invites()


def test_a_key_package_nobody_asked_for_adds_nobody():
    w = World()
    a, m = w.add("alice@x.i2p"), w.add("mallory@x.i2p")
    w.pair("alice@x.i2p", "mallory@x.i2p", SecurityState.ENCRYPTED)
    a.join_room()
    a.groups.create(ROOM)
    kp = base64.b64encode(bytes(m.groups._need().key_package())).decode()
    a.groups.on_signal("mallory@x.i2p", SIGNAL_PREFIX + "KP:%s|%s" % (ROOM, kp))
    assert len(a.groups.members(ROOM)) == 1
    assert "refused" in a.changes()


def test_an_unsolicited_or_forged_welcome_is_refused():
    w, (a, b) = _group(2)
    # Mallory builds her own group under the same room name and "welcomes" Carol.
    mallory, carol = w.add("mallory@x.i2p"), w.add("carol@x.i2p")
    w.pair("mallory@x.i2p", "carol@x.i2p", SecurityState.ENCRYPTED)
    mc = core.RustMlsClient(b"mallory@x.i2p")
    mc.create_group(ROOM.encode())
    com = mc.add_members(ROOM.encode(), [bytes(carol.groups._need().key_package())])
    welcome = bytes(mc.process(ROOM.encode(), bytes(com))["welcome"])
    carol.groups.on_signal("mallory@x.i2p", SIGNAL_PREFIX + "WELCOME:%s|%s"
                           % (ROOM, base64.b64encode(welcome).decode()))
    assert not carol.groups.is_secure(ROOM)
    assert "refused" in carol.changes()


def test_a_welcome_whose_inviter_key_does_not_match_the_invite_is_refused():
    """The inviter's fingerprint came over OTRv4+; the group must hold it."""
    w = World()
    a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
    w.pair("alice@x.i2p", "bob@x.i2p")
    b.join_room()
    # An invite claiming a fingerprint that is not Alice's key in the group.
    b.groups.on_signal("alice@x.i2p", SIGNAL_PREFIX + "INVITE:%s|%s" % (ROOM, "ab" * 48))
    b.groups.accept(ROOM)
    # Alice (who never sent that invite) nonetheless has a group and adds Bob.
    a.join_room()
    a.groups.create(ROOM)
    a.groups._outgoing[(ROOM, "bob@x.i2p")] = type(
        "O", (), {"room": ROOM, "at": 1e18})()
    kp = base64.b64encode(bytes(b.groups._need().key_package())).decode()
    a.groups.on_signal("bob@x.i2p", SIGNAL_PREFIX + "KP:%s|%s" % (ROOM, kp))
    assert not b.groups.is_secure(ROOM)
    assert any(isinstance(e, GroupChanged) and e.detail == "inviter_fingerprint_mismatch"
               for e in b.events)


def test_removed_member_cannot_read_what_follows():
    w, (a, b, c) = _group(3)
    a.groups.remove(ROOM, "carol@x.i2p")
    assert "removed_us" in c.changes()
    assert not c.groups.is_secure(ROOM)
    before = len(c.texts())
    a.groups.send(ROOM, "after carol")
    assert len(c.texts()) == before
    assert ("alice@x.i2p", "after carol", True) in b.texts()


def test_plaintext_in_a_secure_room_is_never_shown():
    w, (a, b, c) = _group(3)
    w.room.post("dave@x.i2p", "hello, I am plaintext")
    for m in (a, b, c):
        assert all(t[1] != "hello, I am plaintext" for t in m.texts())
        assert "room_plaintext_refused" in m.errors()


def test_tampered_replayed_and_stale_frames_are_dropped():
    w, (a, b, c) = _group(3)
    a.groups.send(ROOM, "once")
    assert b.texts()[-1][1] == "once"
    n = len(b.texts())
    w.room.replay(len(w.room.log) - 1)
    assert len(b.texts()) == n, "a replay was shown"
    w.room.tamper_next = True
    a.groups.send(ROOM, "tampered")
    assert all(t[1] != "tampered" for t in b.texts())
    # Stale: a message made in an epoch that a later commit closes.
    stale_body = None
    orig = w.room.post
    held = []
    w.room.post = lambda s, body: held.append((s, body))
    a.groups.send(ROOM, "old epoch")
    w.room.post = orig
    c.groups.rekey(ROOM)
    for s, body in held:
        orig(s, body)
    assert all(t[1] != "old epoch" for t in b.texts())
    assert b.groups.stats.undecryptable >= 2


def test_concurrent_membership_changes_resolve_by_room_order():
    w, (a, b, c) = _group(3)
    orig = w.room.post
    held = []
    w.room.post = lambda s, body: held.append((s, body))
    a.groups.rekey(ROOM)
    b.groups.rekey(ROOM)
    w.room.post = orig
    for s, body in held:
        orig(s, body)
    assert "commit_lost" in b.changes()
    assert len({m.groups.epoch(ROOM) for m in (a, b, c)}) == 1
    b.groups.send(ROOM, "still together")
    # Carol never had an OTRv4+ session with Bob: readable, not verified.
    assert ("bob@x.i2p", "still together", False) in c.texts()
    # A rekey keeps the signing key, so Alice's binding of Bob survives it.
    assert ("bob@x.i2p", "still together", True) in a.texts()


def test_sending_never_falls_back_to_plaintext():
    w, (a, b) = _group(2)
    orig = w.room.post
    w.room.post = lambda s, body: None          # our commit is lost in transit
    a.groups.rekey(ROOM)
    w.room.post = orig
    with pytest.raises(GroupError) as e:
        a.groups.send(ROOM, "must not leak")
    assert e.value.code == "commit_pending"
    assert all("must not leak" not in body for _, body in w.room.log)
    with pytest.raises(GroupError):
        a.groups.send("not-a-group@conference.x.i2p", "plain")


def test_transport_failure_on_the_side_channel_leaves_no_half_member():
    w = World()
    a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
    w.pair("alice@x.i2p", "bob@x.i2p")
    a.join_room()
    a.groups.create(ROOM)
    b.join_room()
    a.groups.invite(ROOM, "bob@x.i2p")
    w.cut_private = True                        # Bob's KeyPackage never arrives
    b.groups.accept(ROOM)
    assert len(a.groups.members(ROOM)) == 1
    assert not b.groups.is_secure(ROOM)


def test_large_frames_are_fragmented_and_reassembled():
    w, (a, b, c, d) = _group(4)
    assert any(body.startswith("?OTRv4F|") for _, body in w.room.log), \
        "add-commits are large enough that they must fragment"
    assert all(len(body) <= 6100 for _, body in w.room.log)
    a.groups.send(ROOM, "x" * 20000)
    assert b.texts()[-1][1] == "x" * 20000


def test_state_survives_a_restart_sealed_and_bound_to_the_account():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    b = w.add("bob@x.i2p", os.path.join(root, "b"))
    w.pair("alice@x.i2p", "bob@x.i2p")
    a.join_room()
    a.groups.create(ROOM)
    _invite(w, "alice@x.i2p", "bob@x.i2p")
    blob = open(os.path.join(root, "b", SecureGroups.STATE_NAME), "rb").read()
    assert b"bob@x.i2p" not in blob and ROOM.encode() not in blob
    # Bob restarts.
    b2 = Member(w, "bob@x.i2p", os.path.join(root, "b"))
    w.members["bob@x.i2p"] = b2
    b2.join_room()
    assert b2.groups.is_secure(ROOM)
    a.groups.send(ROOM, "after bob restarted")
    assert b2.texts()[-1][1] == "after bob restarted"
    b2.groups.send(ROOM, "back")
    assert a.texts()[-1][1] == "back"
    # The same files opened as another account refuse, and are kept aside.
    m = SecureGroups(send_room=lambda *a: None, send_private=lambda *a: None,
                     emit=lambda e: None, peer_security=lambda p: SecurityState.PLAINTEXT,
                     state_dir=os.path.join(root, "b"))
    m.open("mallory@x.i2p")
    assert not m.is_secure(ROOM)
    assert os.path.exists(os.path.join(root, "b", SecureGroups.STATE_NAME + ".unopened"))


def test_wipe_destroys_the_groups_and_their_files():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    a.join_room()
    a.groups.create(ROOM)
    a.groups.wipe()
    assert os.listdir(os.path.join(root, "a")) == []
    assert not a.groups.is_secure(ROOM)
    with pytest.raises(GroupError):
        a.groups.send(ROOM, "after wipe")
    with pytest.raises(GroupError):
        a.groups.open("alice@x.i2p")


def test_invitations_are_bounded_and_expire():
    w = World()
    a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
    w.pair("alice@x.i2p", "bob@x.i2p")
    for i in range(40):
        b.groups.on_signal("alice@x.i2p", SIGNAL_PREFIX + "INVITE:r%d@conference.x.i2p|%s"
                           % (i, "0" * 96))
    assert len(b.groups.pending_invites()) == 32
    b.groups._clock = lambda: 1e12
    assert b.groups.pending_invites() == []


def test_malformed_signals_do_nothing():
    w = World()
    a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
    w.pair("alice@x.i2p", "bob@x.i2p")
    for body in ["INVITE:", "INVITE:no-at-sign|" + "0" * 96, "INVITE:%s|short" % ROOM,
                 "KP:%s|!!!notbase64" % ROOM, "WELCOME:%s|" % ROOM, "BOGUS:x",
                 "INVITE:a|b|c@x.i2p|" + "0" * 96]:
        b.groups.on_signal("alice@x.i2p", SIGNAL_PREFIX + body)
    assert b.groups.pending_invites() == []
    assert b.groups.rooms() == []



class TestRoomPacer:
    """Room fragments under mod_muc_limits' rate: a burst, then spaced, in
    order, never overtaking (unit, with a manual clock and scheduler)."""

    def _pacer(self, burst=3, interval=2.0):
        from android_bridge.groups import RoomPacer
        now = [0.0]
        timers = []
        sent = []
        p = RoomPacer(lambda room, part: sent.append(part), burst=burst,
                      interval=interval, on_error=lambda room: None,
                      clock=lambda: now[0],
                      schedule=lambda delay, fn: timers.append((delay, fn)))
        return p, now, timers, sent

    def test_burst_then_one_per_interval_in_order(self):
        p, now, timers, sent = self._pacer()
        p.post("r", ["a1", "a2", "a3", "a4", "a5"])
        p.post("r", ["b1"])
        assert sent == ["a1", "a2", "a3"]
        for expected in (["a4"], ["a5"], ["b1"]):
            now[0] += 2.0
            _delay, fn = timers.pop(0)
            fn()
            assert sent[-1:] == expected
        assert p.pending("r") == 0

    def test_zero_interval_sends_at_once(self):
        p, now, timers, sent = self._pacer(interval=0)
        p.post("r", ["1", "2", "3", "4", "5"])
        assert sent == ["1", "2", "3", "4", "5"] and timers == []

    def test_a_failed_send_drops_the_rest_of_that_set(self):
        from android_bridge.groups import RoomPacer
        errors = []

        def boom(room, part):
            raise OSError("gone")
        p = RoomPacer(boom, burst=3, interval=1.0, on_error=errors.append,
                      clock=lambda: 0.0, schedule=lambda d, f: None)
        p.post("r", ["1", "2"])
        assert errors == ["r"] and p.pending("r") == 0

    def test_close_stops_everything(self):
        p, now, timers, sent = self._pacer()
        p.post("r", ["1", "2", "3", "4"])
        p.close()
        now[0] += 10
        timers[0][1]()
        assert sent == ["1", "2", "3"]
