# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OTRv4Plus secure groups: MLS over a room, set up over OTRv4+.

A simulated MUC relays every body to every occupant in one order, the sender
included (XEP-0045 reflection), and can drop, duplicate, replay or tamper. A
simulated OTRv4+ side channel stands in for an encrypted 1:1 session, with
its SMP state per pair. The MLS is the real Rust core.
"""
import base64
import collections
import os
import tempfile

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

from android_bridge.events import (QueuedSent, ErrorOccurred, GroupChanged,      # noqa: E402
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
        self._deliver(sender_jid, body)

    def _deliver(self, sender_jid, body):
        # Like a real room: one order for everyone. A message posted while
        # another is being delivered (a member answering a commit at once)
        # goes out after it, never in the middle.
        self._queue = getattr(self, "_queue", collections.deque())
        self._queue.append((sender_jid, body))
        if getattr(self, "_busy", False):
            return
        self._busy = True
        try:
            while self._queue:
                frm, item = self._queue.popleft()
                nick = frm.split("@")[0]
                for jid, m in list(self.occupants.items()):
                    m.groups.on_room_body(ROOM, nick, item, 0.0, own=(jid == frm))
        finally:
            self._busy = False

    def replay(self, index):
        sender_jid, body = self.log[index]
        self._deliver(sender_jid, body)



@pytest.fixture(autouse=True)
def _rooms_settle_at_once(monkeypatch):
    """The simulated room delivers history synchronously: no settling time
    (TestSyncAfterRejoin sets one where it is the subject)."""
    from android_bridge.groups import SecureGroups as _SG
    monkeypatch.setattr(_SG, "SYNC_SETTLE_SECONDS", 0.0)

from android_bridge.groups import SIGNAL_PREFIX as T_SIGNAL  # noqa: E402

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
    # An older inviter's Welcome carries no fingerprint: the invite's is used.
    real = w.private
    w.private = lambda frm, to, body: real(
        frm, to, body.rsplit("|", 1)[0] if "WELCOME:" in body else body)
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
    # Our change has not landed: the line waits (rc.42), never goes plain.
    assert a.groups.send(ROOM, "must not leak") == "held"
    assert "held_change" in a.changes()
    assert all("must not leak" not in body for _, body in w.room.log)
    # The change goes out again and lands; the line follows, encrypted.
    a.groups.on_room_rejoined(ROOM)
    assert any(body == "must not leak" for _s, body, _v in b.texts())
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


def _state_file(directory, account):
    import hashlib
    return os.path.join(directory, "groups-%s.sealed"
                        % hashlib.sha256(account.encode()).hexdigest()[:20])


def test_state_survives_a_restart_sealed_and_bound_to_the_account():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    b = w.add("bob@x.i2p", os.path.join(root, "b"))
    w.pair("alice@x.i2p", "bob@x.i2p")
    a.join_room()
    a.groups.create(ROOM)
    _invite(w, "alice@x.i2p", "bob@x.i2p")
    path = _state_file(os.path.join(root, "b"), "bob@x.i2p")
    blob = open(path, "rb").read()
    assert b"bob@x.i2p" not in blob and ROOM.encode() not in blob
    assert "bob" not in os.path.basename(path)       # no address in a file name
    # Bob restarts (the old process is gone).
    b.groups.close()
    b2 = Member(w, "bob@x.i2p", os.path.join(root, "b"))
    w.members["bob@x.i2p"] = b2
    b2.join_room()
    assert b2.groups.is_secure(ROOM)
    b2.groups.on_room_rejoined(ROOM)
    a.groups.send(ROOM, "after bob restarted")
    assert b2.texts()[-1][1] == "after bob restarted"
    b2.groups.send(ROOM, "back")
    assert a.texts()[-1][1] == "back"
    # ANOTHER ACCOUNT on the same device (the app signed in as someone else,
    # Termux run as another user) has its own state and leaves Bob's alone.
    b2.groups.close()
    m = SecureGroups(send_room=lambda *a: None, send_private=lambda *a: None,
                     emit=lambda e: None, peer_security=lambda p: SecurityState.PLAINTEXT,
                     state_dir=os.path.join(root, "b"))
    m.open("mallory@x.i2p")
    assert not m.is_secure(ROOM)
    m.create("other@conference.example.i2p")
    m.close()
    assert open(path, "rb").read()                    # Bob's file untouched
    b3 = Member(w, "bob@x.i2p", os.path.join(root, "b"))
    assert b3.groups.is_secure(ROOM)


def test_a_second_client_for_the_same_account_is_refused():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    with pytest.raises(GroupError) as e:
        Member(w, "alice@x.i2p", os.path.join(root, "a"))
    assert e.value.code == "state_in_use"
    a.groups.close()
    Member(w, "alice@x.i2p", os.path.join(root, "a"))


def test_the_old_one_file_per_device_state_is_adopted_by_its_account():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    a.join_room()
    a.groups.create(ROOM)
    a.groups.close()
    d = os.path.join(root, "a")
    # As an earlier version left it: one shared file, set aside once.
    os.replace(_state_file(d, "alice@x.i2p"), os.path.join(d, SecureGroups.STATE_NAME + ".unopened"))
    os.remove(_state_file(d, "alice@x.i2p") + ".prev") if os.path.exists(
        _state_file(d, "alice@x.i2p") + ".prev") else None
    events = []
    other = SecureGroups(send_room=lambda *a: None, send_private=lambda *a: None,
                         emit=events.append, peer_security=lambda p: SecurityState.PLAINTEXT,
                         state_dir=d)
    other.open("carol@x.i2p")                         # not hers: left alone
    assert not other.is_secure(ROOM)
    other.close()
    assert os.path.exists(os.path.join(d, SecureGroups.STATE_NAME + ".unopened"))
    a2 = Member(w, "alice@x.i2p", d)                   # hers: adopted
    assert a2.groups.is_secure(ROOM)
    assert os.path.exists(_state_file(d, "alice@x.i2p"))


def test_a_damaged_state_falls_back_to_the_last_good_copy():
    root = tempfile.mkdtemp()
    w = World()
    a = w.add("alice@x.i2p", os.path.join(root, "a"))
    a.join_room()
    a.groups.create(ROOM)
    a.groups.save()                                   # a .prev now exists
    a.groups.close()
    path = _state_file(os.path.join(root, "a"), "alice@x.i2p")
    with open(path, "r+b") as f:
        f.seek(40)
        f.write(b"\xff\xff")
    a2 = Member(w, "alice@x.i2p", os.path.join(root, "a"))
    assert a2.groups.is_secure(ROOM)


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



class _Clock:
    """A manual clock and scheduler for RoomPacer."""

    def __init__(self):
        self.now = 0.0
        self.timers = []

    def schedule(self, delay, fn):
        self.timers.append((self.now + delay, len(self.timers), fn))

    def advance(self, seconds):
        end = self.now + seconds
        while True:
            due = sorted(t for t in self.timers if t[0] <= end)
            if not due:
                break
            first = due[0]
            self.timers.remove(first)
            self.now = max(self.now, first[0])
            first[2]()
        self.now = end


class TestRoomPacer:
    """Room fragments: fast until the server bounces one, then slow; every
    piece held until the room echoes it, and sent again if it never does
    (unit, with a manual clock and scheduler)."""

    def _pacer(self, burst=3, interval=2.0, send=None, **kw):
        from android_bridge.groups import RoomPacer
        clock = _Clock()
        sent = []
        errors = []
        p = RoomPacer(send or (lambda room, part: sent.append(part)),
                      burst=burst, interval=interval, on_error=errors.append,
                      clock=lambda: clock.now, schedule=clock.schedule, **kw)
        return p, clock, sent, errors

    def test_burst_then_one_per_interval_in_order(self):
        p, clock, sent, _e = self._pacer()
        p.post("r", ["a1", "a2", "a3", "a4", "a5"])
        p.post("r", ["b1"])
        assert sent == ["a1", "a2", "a3"]
        for expected in (["a4"], ["a5"], ["b1"]):
            clock.advance(2.0)
            assert sent[-1:] == expected
        assert p.pending("r") == 0

    def test_fast_by_default(self):
        p, clock, sent, _e = self._pacer(burst=10, interval=0.25)
        parts = ["p%d" % i for i in range(11)]       # an add-member commit
        p.post("r", parts)
        assert len(sent) == 10
        clock.advance(0.25)
        assert sent == parts and not p.is_slow("r")

    def test_zero_interval_sends_at_once(self):
        p, clock, sent, _e = self._pacer(interval=0)
        p.post("r", ["1", "2", "3", "4", "5"])
        assert sent == ["1", "2", "3", "4", "5"] and clock.timers == []
        assert p.in_flight("r") == 0

    def test_a_failed_send_drops_the_rest_of_that_set(self):
        def boom(room, part):
            raise OSError("gone")
        p, clock, _sent, errors = self._pacer(send=boom, interval=1.0)
        p.post("r", ["1", "2"])
        assert errors == ["r"] and p.pending("r") == 0 and p.in_flight("r") == 0

    def test_close_stops_everything(self):
        p, clock, sent, _e = self._pacer()
        p.post("r", ["1", "2", "3", "4"])
        p.close()
        clock.advance(100)
        assert sent == ["1", "2", "3"]

    def test_an_echo_confirms_a_piece(self):
        p, clock, sent, _e = self._pacer(echo_timeout=20)
        p.post("r", ["1", "2"])
        assert p.in_flight("r") == 2
        assert p.confirm("r", "1") and not p.confirm("r", "1")
        assert not p.confirm("other", "2")
        p.confirm("r", "2")
        clock.advance(60)
        assert sent == ["1", "2"]                # nothing sent again

    def test_a_rejection_slows_the_room_and_resends_what_was_not_echoed(self):
        p, clock, sent, _e = self._pacer(burst=10, interval=0.25, slow_burst=3,
                                         slow_interval=2.0, slow_for=300)
        p.post("r", ["1", "2", "3", "4", "5"])
        p.confirm("r", "1")
        p.confirm("r", "2")
        p.rejected("r")
        assert p.is_slow("r")
        assert sent == ["1", "2", "3", "4", "5"]  # waits for the server
        assert p.pending("r") == 3
        # More bounces for the same burst only keep it slow.
        p.rejected("r")
        assert p.pending("r") == 3
        clock.advance(2.0)
        assert sent[5:] == ["3"]
        clock.advance(4.0)
        assert sent[5:] == ["3", "4", "5"]       # in order, one per 2 s

    def test_slow_ends_after_the_quiet_period_and_doubles_per_strike(self):
        p, clock, sent, _e = self._pacer(burst=10, interval=0.25, slow_burst=1,
                                         slow_interval=2.0, slow_for=300,
                                         max_slow_for=1000)
        p.rejected("r")
        clock.advance(299)
        assert p.is_slow("r")
        clock.advance(2)
        assert not p.is_slow("r")
        p.rejected("r")
        clock.advance(599)
        assert p.is_slow("r")
        clock.advance(2)
        assert not p.is_slow("r")
        for _ in range(5):
            clock.advance(10)
            p.rejected("r")
        clock.advance(999)
        assert p.is_slow("r")                    # capped, not 300 * 2**6
        clock.advance(2)
        assert not p.is_slow("r")

    def test_a_piece_never_echoed_goes_again_then_is_given_up(self):
        p, clock, sent, errors = self._pacer(burst=5, interval=0.5,
                                             echo_timeout=20, max_attempts=3)
        p.post("r", ["a", "b"])
        p.confirm("r", "b")
        clock.advance(20)
        assert sent == ["a", "b", "a"]
        clock.advance(20)
        assert sent == ["a", "b", "a", "a"]
        clock.advance(20)
        assert sent.count("a") == 3 and errors == ["r"]
        assert p.in_flight("r") == 0
        clock.advance(100)
        assert sent.count("a") == 3


class TestAdaptivePacingEndToEnd:
    """A group on a server that rate-limits the room (mod_muc_limits left at
    its defaults): the first burst is partly bounced, the sender slows
    down and sends the bounced pieces again, and every message arrives."""

    def test_every_message_arrives_through_a_rate_limited_room(self):
        from android_bridge.groups import RoomPacer
        w, (a, b, c) = _group(3)
        clock = _Clock()
        for m in (a, b, c):
            m.groups._pacer = RoomPacer(
                m.groups._send_room, burst=10, interval=0.25, slow_burst=3,
                slow_interval=2.2, slow_for=300, echo_timeout=20,
                on_error=lambda room: None,
                clock=lambda: clock.now, schedule=clock.schedule)

        # The server: 3 events at once, then one per 2 s per occupant; the
        # rest bounced, the notice arriving half a second later.
        bucket = {}
        bounced = []
        post = w.room.post

        def limited(sender_jid, body):
            tokens, at = bucket.get(sender_jid, (3.0, clock.now))
            tokens = min(3.0, tokens + (clock.now - at) / 2.0)
            if tokens < 1.0:
                bucket[sender_jid] = (tokens, clock.now)
                bounced.append(sender_jid)
                clock.schedule(0.5, lambda: w.members[sender_jid]
                               .groups.on_room_rejected(ROOM))
                return
            bucket[sender_jid] = (tokens - 1.0, clock.now)
            post(sender_jid, body)
        w.room.post = limited

        a.groups.rekey(ROOM)                  # ~8 pieces: most bounce
        clock.advance(120)
        assert bounced, "the server never limited anything"
        assert a.groups._pacer.is_slow(ROOM)
        for line in ("one", "two", "three"):
            a.groups.send(ROOM, line)
        clock.advance(120)
        for m in (b, c):
            got = [body for who, body, _v in m.texts() if who == "alice@x.i2p"]
            assert got == ["one", "two", "three"], got
            assert m.groups.epoch(ROOM) == a.groups.epoch(ROOM)
        assert a.groups._pacer.in_flight(ROOM) == 0
        assert a.groups._pacer.pending(ROOM) == 0


class TestRekeyKnobs:
    """MLS_SECURITY_HARDENING.md §4: defaults 50 messages / 30 min, set by
    environment, clamped, never an import error."""

    def test_defaults_and_clamping(self, monkeypatch):
        from android_bridge import groups as G
        assert G.SecureGroups.AUTO_REKEY_MESSAGES == 50
        assert G.SecureGroups.AUTO_REKEY_SECONDS == 30 * 60
        monkeypatch.setenv("X_KNOB", "7")
        assert G._env_int("X_KNOB", 50, 1, 100) == 7
        monkeypatch.setenv("X_KNOB", "0")
        assert G._env_int("X_KNOB", 50, 1, 100) == 1
        monkeypatch.setenv("X_KNOB", "lots")
        assert G._env_int("X_KNOB", 50, 1, 100) == 50


# ── M2: signing keys per group, rotated; bookkeeping survives a restart ──────

def _verified(member, jid):
    return {m["jid"]: m["verified"] for m in member.groups.members(ROOM)}[jid]


class TestSigningKeysRotate:
    """MLS_SECURITY_HARDENING.md §1 / M2: one signing key per group, a new
    one at every rekey, and an SMP verification that follows the person
    across the rotation -- but never across a new leaf under an old name."""

    def test_each_group_has_its_own_fingerprint(self):
        w, (a, b) = _group(2)
        other = "other@conference.example.i2p"
        a.groups.create(other)
        assert a.groups.own_fingerprint(ROOM) != a.groups.own_fingerprint(other)

    def test_a_rekey_rotates_the_key_and_verification_follows_it(self):
        w, (a, b, c) = _group(3)
        before = a.groups.own_fingerprint(ROOM)
        assert _verified(b, "alice@x.i2p") is True
        a.groups.rekey(ROOM)
        after = a.groups.own_fingerprint(ROOM)
        assert after != before
        assert {m["jid"]: m["fingerprint"] for m in b.groups.members(ROOM)}[
            "alice@x.i2p"] == after
        assert _verified(b, "alice@x.i2p") is True
        a.groups.send(ROOM, "signed with my new key")
        assert ("alice@x.i2p", "signed with my new key", True) in b.texts()
        # Bob's own rotation is followed by Alice.
        b.groups.rekey(ROOM)
        assert _verified(a, "bob@x.i2p") is True

    def test_a_new_member_under_an_old_name_is_not_verified(self):
        w, (a, b, c) = _group(3)
        assert _verified(a, "carol@x.i2p") is True
        a.groups.remove(ROOM, "carol@x.i2p")
        # Someone else now joins as "carol" with another key.
        imp = w.add("carol@x.i2p")
        w.pair("bob@x.i2p", "carol@x.i2p", SecurityState.ENCRYPTED)
        _invite(w, "bob@x.i2p", "carol@x.i2p")
        assert _verified(a, "carol@x.i2p") is False

    def test_a_rekey_between_invite_and_welcome_still_lets_them_in(self):
        w, (a, b) = _group(2)
        c = w.add("carol@x.i2p")
        w.pair("alice@x.i2p", "carol@x.i2p")
        c.join_room()
        a.groups.invite(ROOM, "carol@x.i2p")        # Carol holds our old key
        a.groups.rekey(ROOM)                        # ... which now rotates
        c.groups.accept(ROOM)
        assert c.groups.is_secure(ROOM), c.changes()
        assert _verified(c, "alice@x.i2p") is True
        a.groups.send(ROOM, "welcome carol")
        assert ("alice@x.i2p", "welcome carol", True) in c.texts()

    def test_a_welcome_naming_another_key_is_refused(self):
        w = World()
        a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
        w.pair("alice@x.i2p", "bob@x.i2p")
        a.join_room()
        a.groups.create(ROOM)
        b.join_room()
        a.groups.invite(ROOM, "bob@x.i2p")
        # The Welcome is relayed with a fingerprint that is not Alice's.
        real = w.private

        def swap(frm, to, body):
            if "WELCOME:" in body:
                body = body.rsplit("|", 1)[0] + "|" + "cd" * 48
            real(frm, to, body)
        w.private = swap
        b.groups.accept(ROOM)
        assert not b.groups.is_secure(ROOM)
        assert any(isinstance(e, GroupChanged) and e.detail == "inviter_fingerprint_mismatch"
                   for e in b.events)

    def test_a_key_package_during_our_pending_commit_is_added_after_it(self):
        w, (a, b) = _group(2)
        c = w.add("carol@x.i2p")
        w.pair("alice@x.i2p", "carol@x.i2p")
        c.join_room()
        a.groups.invite(ROOM, "carol@x.i2p")
        w.room.drop_next = 100                      # the room holds Alice's rekey
        a.groups.rekey(ROOM)
        c.groups.accept(ROOM)                       # KP arrives while pending
        assert not c.groups.is_secure(ROOM)
        w.room.drop_next = 0
        a.groups.resend_pending_commit(ROOM)        # the rekey lands
        assert c.groups.is_secure(ROOM), (a.changes(), c.changes())
        assert len(b.groups.members(ROOM)) == 3

    def test_verification_and_a_pending_commit_survive_a_restart(self):
        root = tempfile.mkdtemp()
        w = World()
        a = w.add("alice@x.i2p", os.path.join(root, "a"))
        b = w.add("bob@x.i2p", os.path.join(root, "b"))
        w.pair("alice@x.i2p", "bob@x.i2p")
        a.join_room()
        a.groups.create(ROOM)
        _invite(w, "alice@x.i2p", "bob@x.i2p")
        assert _verified(a, "bob@x.i2p") is True
        w.room.drop_next = 100
        a.groups.rekey(ROOM)                        # lost with the old stream
        a.groups.close()                            # the process exits
        a2 = Member(w, "alice@x.i2p", os.path.join(root, "a"))
        w.members["alice@x.i2p"] = a2
        a2.join_room()
        assert _verified(a2, "bob@x.i2p") is True
        w.room.drop_next = 0
        a2.groups.on_room_rejoined(ROOM)            # re-sent from sealed state
        assert "commit_resent" in a2.changes()
        a2.groups.send(ROOM, "after restart and rekey")
        assert ("alice@x.i2p", "after restart and rekey", True) in b.texts()


# ── M3: timed rekey and idle members (72 h) ──────────────────────────────────

class TestMaintenance:

    def _clocked(self, n=3):
        w, members = _group(n)
        now = [1_000_000.0]
        for m in members:
            m.groups._clock = lambda: now[0]
            m.groups._settled_from = now[0]
            for room in m.groups._activity:
                for ident in m.groups._activity[room]:
                    m.groups._activity[room][ident] = now[0]
            for room in m.groups._since_rekey:
                m.groups._since_rekey[room][1] = now[0]
        return w, members, now

    def test_a_quiet_member_still_rekeys_on_time(self):
        w, (a, b, c), now = self._clocked()
        assert a.groups.maintain() == []
        now[0] += SecureGroups.AUTO_REKEY_SECONDS + 1
        before = a.groups.own_fingerprint(ROOM)
        assert a.groups.maintain() == ["rekey:" + ROOM]
        assert a.groups.own_fingerprint(ROOM) != before

    def test_a_member_away_for_72_hours_is_removed(self):
        w, (a, b, c), now = self._clocked()
        del w.room.occupants["carol@x.i2p"]          # Carol's phone is off
        for _ in range(int(73 * 3600 // SecureGroups.AUTO_REKEY_SECONDS) + 1):
            now[0] += SecureGroups.AUTO_REKEY_SECONDS + 1
            a.groups.maintain()
            b.groups.maintain()
        assert sorted(m["jid"] for m in a.groups.members(ROOM)) == [
            "alice@x.i2p", "bob@x.i2p"]
        assert sorted(m["jid"] for m in b.groups.members(ROOM)) == [
            "alice@x.i2p", "bob@x.i2p"]
        assert "idle_removed" in a.changes() + b.changes()
        # Those who stayed keep talking.
        a.groups.send(ROOM, "still here")
        assert ("alice@x.i2p", "still here", True) in b.texts()

    def test_nobody_is_judged_idle_straight_after_a_reconnect(self):
        w, (a, b, c), now = self._clocked()
        now[0] += SecureGroups.IDLE_REMOVE_SECONDS + 10
        a.groups._since_rekey[ROOM][1] = now[0]       # no rekey due
        a.groups.on_room_rejoined(ROOM)
        assert a.groups.maintain() == []
        now[0] += SecureGroups.IDLE_GRACE_SECONDS + 1
        a.groups._since_rekey[ROOM][1] = now[0]
        assert a.groups.maintain() == ["removed:" + ROOM]

    def test_idle_removal_can_be_turned_off(self):
        w, (a, b, c), now = self._clocked()
        a.groups.IDLE_REMOVE_SECONDS = 0
        now[0] += 10 * 86400
        a.groups._since_rekey[ROOM][1] = now[0]
        assert a.groups.maintain() == []

    def test_the_knob_is_read_in_hours(self, monkeypatch):
        import importlib
        from android_bridge import groups as G
        assert G.SecureGroups.IDLE_REMOVE_SECONDS == 72 * 3600
        monkeypatch.setenv("OTRV4PLUS_MLS_IDLE_REMOVE_HOURS", "24")
        assert G._env_int("OTRV4PLUS_MLS_IDLE_REMOVE_HOURS", 72, 0, 8760) == 24
        del importlib


# ── M4: the hybrid ciphersuite ───────────────────────────────────────────────

class TestHybridSuite:
    """MLS_SECURITY_HARDENING.md §2 / M4: every new group is
    X448+ML-KEM-1024 / Ed448+ML-DSA-87 (0xF0A1); a group of the earlier
    PQ-only suite keeps working but takes no new members."""

    def test_every_new_group_is_hybrid_for_every_member(self):
        w, members = _group(3)
        for m in members:
            assert m.groups.suite(ROOM) == "hybrid"
            assert int(m.groups._need().ciphersuite(ROOM.encode())) == 0xF0A1

    def test_a_pq_only_group_takes_no_new_members(self, monkeypatch):
        w, (a, b) = _group(2)
        monkeypatch.setattr(a.groups, "suite", lambda room: "pq-only")
        c = w.add("carol@x.i2p")
        w.pair("alice@x.i2p", "carol@x.i2p")
        with pytest.raises(GroupError) as e:
            a.groups.invite(ROOM, "carol@x.i2p")
        assert e.value.code == "legacy_group"
        # ... and still carries messages.
        a.groups.send(ROOM, "still here")
        assert ("alice@x.i2p", "still here", True) in b.texts()

    def test_hybrid_messages_still_fit_the_room_pieces(self):
        w, (a, b) = _group(2)
        a.groups.send(ROOM, "x" * 2000)
        assert all(len(body) <= 5664 for _s, body in w.room.log)


# ── A Welcome is kept until the invitee confirms (rc.28 device report) ───────

class TestWelcomeDelivery:

    def _invite_with_lost_welcome(self):
        w = World()
        a, b = w.add("alice@x.i2p"), w.add("bob@x.i2p")
        w.pair("alice@x.i2p", "bob@x.i2p")
        a.join_room()
        a.groups.create(ROOM)
        b.join_room()
        real = w.private
        lost = []

        def lose_welcomes(frm, to, body):
            if "WELCOME:" in body and not lost:
                lost.append(body)            # the connection dropped
                raise OSError("timed out")
            real(frm, to, body)
        w.private = lose_welcomes
        a.groups.invite(ROOM, "bob@x.i2p")
        b.groups.accept(ROOM)
        return w, a, b, lost

    def test_a_lost_welcome_is_sent_again_on_reconnect(self):
        w, a, b, lost = self._invite_with_lost_welcome()
        assert lost and not b.groups.is_secure(ROOM)
        assert ("secret@conference.example.i2p", "bob@x.i2p") in a.groups._welcome_out
        a.groups.on_room_rejoined(ROOM)
        assert b.groups.is_secure(ROOM)
        # Bob said JOINED: nothing is pending any more.
        assert a.groups._welcome_out == {}
        a.groups.send(ROOM, "made it")
        assert ("alice@x.i2p", "made it", True) in b.texts()

    def test_maintenance_resends_after_a_while(self):
        w, a, b, lost = self._invite_with_lost_welcome()
        now = [a.groups._clock()]
        a.groups._clock = lambda: now[0]
        a.groups.maintain()
        assert not b.groups.is_secure(ROOM)          # not yet due
        now[0] += 300
        a.groups.maintain()
        assert b.groups.is_secure(ROOM)

    def test_a_repeated_welcome_is_acknowledged_not_refused(self):
        w, (a, b) = _group(2)
        body = "%sWELCOME:%s|%s|%s" % (SIGNAL_PREFIX, ROOM, "AAAA", "ab" * 48)
        a.groups._welcome_out[(ROOM, "bob@x.i2p")] = [body, 0.0, 1]
        b.groups.on_signal("alice@x.i2p", body)
        assert "refused" not in b.changes()
        assert a.groups._welcome_out == {}


def test_a_member_who_wiped_is_invited_back_with_one_leaf():
    """Device report (2026-10-05): Alice wiped the app; Bob invites her
    again. Her old leaf is replaced in the same commit, never kept beside the
    new one."""
    w, (a, b, c) = _group(3)
    a.groups.wipe()
    del w.room.occupants[a.jid]
    a2 = w.add(a.jid)                       # the same account, fresh device
    w.pair(b.jid, a.jid)
    _invite(w, b.jid, a.jid)
    for m in (a2, b, c):
        assert m.groups.is_secure(ROOM)
        jids = [x["jid"] for x in m.groups.members(ROOM)]
        assert sorted(jids) == sorted([a.jid, b.jid, c.jid])
    a2.groups.send(ROOM, "back after the wipe")
    # A new device is a new key: Carol verified the old one, not this one,
    # so Alice reads as unverified to her until they verify again.
    assert (a.jid, "back after the wipe", False) in c.texts()
    assert (a.jid, "back after the wipe", True) not in c.texts()
    c.groups.send(ROOM, "welcome back")
    assert any(body == "welcome back" for _s, body, _v in a2.texts())


class TestSyncAfterRejoin:
    """Device test (2026-10-05): signed in again, the first message to the
    group was "sent, encrypted" and nobody got it -- it went out on an epoch
    the others had left while we were away. Until the room is joined again
    and its history applied, what is typed waits."""

    def _restarted_bob(self, settle=5.0):
        root = tempfile.mkdtemp()
        w = World()
        a = w.add("alice@x.i2p", os.path.join(root, "a"))
        b = w.add("bob@x.i2p", os.path.join(root, "b"))
        w.pair("alice@x.i2p", "bob@x.i2p")
        a.join_room()
        a.groups.create(ROOM)
        _invite(w, "alice@x.i2p", "bob@x.i2p")
        b.groups.close()
        del w.room.occupants["bob@x.i2p"]
        w.away_from = len(w.room.log)
        a.groups.rekey(ROOM)                    # while Bob is away
        b2 = Member(w, "bob@x.i2p", os.path.join(root, "b"))
        w.members["bob@x.i2p"] = b2
        now = [1000.0]
        b2.groups._clock = lambda: now[0]
        b2.groups.SYNC_SETTLE_SECONDS = settle
        return w, a, b2, now

    def test_typed_before_the_room_is_back_waits_and_then_goes(self):
        w, a, b2, now = self._restarted_bob()
        assert b2.groups.is_syncing(ROOM)
        # Said at once, so the app shows a restored group as an encrypted
        # group catching up -- never "Not encrypted".
        assert b2.changes() == ["syncing"]
        assert b2.groups.send(ROOM, "typed too early") == "held"
        assert b2.changes() == ["syncing", "held"]
        assert not any(body == "typed too early" for _s, body, _v in a.texts())
        # Back in the room; its history brings Alice's rekey.
        b2.join_room()
        for i in range(w.away_from, len(w.room.log)):   # the history replay
            w.room.replay(i)
        b2.groups.on_room_rejoined(ROOM)
        assert b2.groups.send(ROOM, "still settling") == "held"
        now[0] += 6
        b2.groups.maintain()                    # or the settle timer
        got = [body for _s, body, _v in a.texts()]
        assert got[-2:] == ["typed too early", "still settling"]
        assert any(isinstance(e, QueuedSent) and e.count == 2 for e in b2.events)
        assert b2.groups.send(ROOM, "now direct") == "sent"

    def test_no_commit_while_out_of_sync(self):
        w, a, b2, now = self._restarted_bob()
        b2.groups.AUTO_REKEY_SECONDS = 1
        now[0] += 10_000
        assert b2.groups.maintain() == []


def test_the_app_holds_group_messages_until_each_room_is_back(monkeypatch):
    """The Android controller marks its groups out of sync before it
    rejoins their rooms, and tells each group when its room is back."""
    import threading as _threading
    from android_bridge.connection import ConnectionController

    calls = []

    class Groups:
        def rooms(self):
            return [ROOM]

        def mark_syncing(self, room=None):
            calls.append(("mark", room))

        def on_room_rejoined(self, room):
            calls.append(("rejoined", room))

    ctl = ConnectionController.__new__(ConnectionController)
    ctl._app = type("App", (), {"groups": Groups()})()
    ctl._profile = type("P", (), {"jid": "dave@x.i2p"})()
    ctl.join_room = lambda room, nick: (calls.append(("join", room)) or {"ok": True})
    ctl._transport = None

    class Inline:
        def __init__(self, target=None, **_kw):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(_threading, "Thread", Inline)
    ctl._rejoin_secure_rooms()
    assert calls == [("mark", None), ("join", ROOM), ("rejoined", ROOM)]


def test_a_member_whose_copy_fell_behind_is_invited_back():
    """Device test (2026-10-05): inviting B, who still held the group but
    could no longer read it, did nothing -- B's client dropped the invitation
    because it was "already a member", and the inviter waited."""
    w, (a, b, c) = _group(3)
    # Bob misses a change (offline beyond the room's history): he is behind.
    del w.room.occupants[b.jid]
    a.groups.rekey(ROOM)
    b.join_room()
    a.groups.send(ROOM, "bob cannot read this")
    assert not any(body == "bob cannot read this" for _s, body, _v in b.texts())
    # Alice invites him back. He is told, and nothing changes until he accepts.
    b.events.clear()
    a.groups.invite(ROOM, b.jid)
    assert "reinvited" in b.changes()
    assert any(isinstance(e, GroupInvite) and e.room == ROOM for e in b.events)
    b.groups.accept(ROOM)                    # KeyPackage -> Welcome -> joined
    assert "joined" in b.changes()
    for m in (a, b, c):
        assert sorted(x["jid"] for x in m.groups.members(ROOM)) == sorted(
            [a.jid, b.jid, c.jid])
    c.groups.send(ROOM, "bob is back")
    assert any(body == "bob is back" for _s, body, _v in b.texts())
    b.groups.send(ROOM, "and reading")
    assert any(body == "and reading" for _s, body, _v in a.texts())



def test_a_deleted_group_ends_for_every_member():
    w, (a, b, c) = _group(3)
    assert b.groups.on_room_destroyed(ROOM) is True
    assert not b.groups.is_secure(ROOM) and "deleted" in b.changes()
    assert b.groups.on_room_destroyed(ROOM) is False      # once
    assert b.groups.on_room_destroyed("other@conference.x.i2p") is False


def test_the_app_ends_a_group_whose_room_was_gone_on_rejoin(monkeypatch):
    import threading as _threading
    from android_bridge.connection import ConnectionController

    calls = []

    class Groups:
        def rooms(self):
            return [ROOM]

        def mark_syncing(self, room=None):
            pass

        def on_room_rejoined(self, room):
            calls.append(("rejoined", room))

        def on_room_destroyed(self, room):
            calls.append(("destroyed", room))

    class Transport:
        def take_recreated(self, room):
            return True

    ctl = ConnectionController.__new__(ConnectionController)
    ctl._app = type("App", (), {"groups": Groups()})()
    ctl._profile = type("P", (), {"jid": "dave@x.i2p"})()
    ctl._transport = Transport()
    ctl.join_room = lambda room, nick: {"ok": True}
    ctl.destroy_room = lambda room, reason="": calls.append(("destroy", room)) or {"ok": True}

    class Inline:
        def __init__(self, target=None, **_kw):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(_threading, "Thread", Inline)
    ctl._rejoin_secure_rooms()
    assert calls == [("destroy", ROOM), ("destroyed", ROOM)]


def test_deleting_says_who_may_and_cleans_up_a_room_already_gone():
    from android_bridge.connection import ConnectionController
    ended = []
    ctl = ConnectionController.__new__(ConnectionController)
    ctl._on_room_destroyed = ended.append
    ctl.destroy_room = lambda room, reason="": {
        "ok": False, "code": "forbidden", "detail": "You are banned from this room.",
        "value": None}
    out = ctl.delete_secure_group(ROOM)
    assert not out["ok"] and "creator" in out["detail"] and "banned" not in out["detail"]
    assert ended == []
    ctl.destroy_room = lambda room, reason="": {
        "ok": False, "code": "item_not_found", "detail": "", "value": None}
    assert ctl.delete_secure_group(ROOM)["ok"] and ended == [ROOM]


class TestVerifyingMembersForCalls:
    """Owner question (2026-10-10): group calls need verified members; how?
    SMP between two members, at any time, now verifies them in every group
    they share -- not only inviter and invitee at invitation time."""

    def _verified(self, m, jid):
        return {x["jid"]: x["verified"] for x in m.groups.members(ROOM)}[jid]

    def test_smp_between_two_members_verifies_them_in_the_group(self):
        w, (a, b, c) = _group(3)
        assert not self._verified(b, c.jid) and not self._verified(c, b.jid)
        # They have an OTRv4+ session but have not run SMP yet.
        w.pair(b.jid, c.jid, SecurityState.ENCRYPTED)
        assert b.groups.verify_members(ROOM)[c.jid] == "sent"
        assert "member_bound" in c.changes()
        assert not self._verified(c, b.jid)
        # SMP succeeds (both sides hear it): verified both ways.
        w.pair(b.jid, c.jid, SecurityState.SMP_VERIFIED)
        b.groups.on_peer_verified(c.jid)
        c.groups.on_peer_verified(b.jid)
        assert self._verified(b, c.jid) and self._verified(c, b.jid)
        assert "member_verified" in b.changes() and "member_verified" in c.changes()

    def test_without_an_encrypted_session_nothing_is_bound(self):
        # (The real clients refuse to send without a session; the simulated
        # side channel delivers anyway, so the receiving side's own check is
        # what this shows.)
        w, (a, b, c) = _group(3)
        b.groups.verify_members(ROOM)
        assert "group_signal_unencrypted" in c.errors()
        assert not self._verified(c, b.jid)
        assert "member_bound" not in c.changes()

    def test_a_key_the_group_does_not_hold_is_refused(self):
        w, (a, b, c) = _group(3)
        w.pair(b.jid, c.jid, SecurityState.SMP_VERIFIED)
        c.groups.on_signal(b.jid, "%sFP:%s|%s" % (T_SIGNAL, ROOM, "ab" * 48))
        assert not self._verified(c, b.jid)
        assert "refused" in c.changes()


def test_the_app_says_who_still_needs_smp():
    from android_bridge.connection import ConnectionController
    ctl = ConnectionController.__new__(ConnectionController)
    status = {"b@x": "sent", "c@x": "no_session", "d@x": "verified"}
    ctl._app = type("App", (), {"groups": type("G", (), {
        "verify_members": staticmethod(lambda room: status)})()})()
    out = ctl.verify_group_members(ROOM)
    assert out["ok"] and "b@x" in out["detail"] and "c@x" in out["detail"]
    assert "SMP" in out["detail"] and "d@x" not in out["detail"]


class TestGroupVerification:
    """Owner design (2026-10-10): the creator sets a group passphrase; a
    verification runs SMP between every pair of members with it; whoever
    typed it wrong stays out of group calls."""

    def _verifiers(self, members):
        from android_bridge.group_verify import GroupVerify
        return [GroupVerify(m.groups, emit=m.events.append) for m in members]

    def _verified(self, m, jid):
        return {x["jid"]: x["verified"] for x in m.groups.members(ROOM)}[jid]

    def test_everyone_with_the_passphrase_is_verified_with_everyone(self):
        w, (a, b, c) = _group(3)
        va, vb, vc = self._verifiers([a, b, c])
        va.set_passphrase(ROOM, bytearray(b"correct horse battery"))
        va.start(ROOM)                                   # the creator starts
        assert "verify_started" in b.changes()
        assert vb.pending(ROOM) is not None
        vb.start(ROOM, bytearray(b"correct horse battery"))
        vc.start(ROOM, bytearray(b"correct horse battery"))
        for m, others in ((a, (b, c)), (b, (a, c)), (c, (a, b))):
            for o in others:
                assert self._verified(m, o.jid), (m.jid, o.jid)
        assert "group_verified" in a.changes()
        assert va.all_verified(ROOM)
        # Nothing of it was shown as chat, and the passphrase never travelled.
        for m in (a, b, c):
            assert not m.texts()
        assert all("correct horse" not in body for _s, body in w.room.log)

    def test_a_wrong_passphrase_fails_and_stays_out(self):
        # Nobody verified anybody when inviting: only the run can.
        w, (a, b, c) = _group(3, levels={"bob@x.i2p": SecurityState.ENCRYPTED,
                                         "carol@x.i2p": SecurityState.ENCRYPTED})
        assert not self._verified(a, c.jid)
        va, vb, vc = self._verifiers([a, b, c])
        va.start(ROOM, bytearray(b"correct horse battery"))
        vb.start(ROOM, bytearray(b"correct horse battery"))
        vc.start(ROOM, bytearray(b"wrong horse battery!"))
        assert self._verified(a, b.jid) and self._verified(b, a.jid)
        assert not self._verified(a, c.jid) and not self._verified(c, a.jid)
        assert not self._verified(b, c.jid)
        assert "member_verify_failed" in a.changes()
        assert va.status(ROOM)[c.jid] == "failed"
        assert not va.all_verified(ROOM)

    def test_a_short_passphrase_is_refused(self):
        w, (a, b) = _group(2)
        (va, _vb) = self._verifiers([a, b])
        with pytest.raises(ValueError):
            va.start(ROOM, bytearray(b"short"))
        with pytest.raises(ValueError):
            va.start(ROOM)                               # none set at creation
