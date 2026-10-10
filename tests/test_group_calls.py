# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group voice calls in a secure group (MLS_SECURITY_HARDENING.md §5, M5).

Members are in-process; the room and the I2P datagram network are
simulated. What is checked: keys come from the group's epoch and follow
every commit; only SMP-verified members are in a call; an outsider or a
removed member cannot read a frame; control messages are never shown as
chat; the starter forces a rekey every 120 s.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustGroupVoice"):
    pytest.skip("this core has no group voice", allow_module_level=True)

from android_bridge.events import GroupChanged, RoomMessageReceived, SecurityState  # noqa: E402
from android_bridge.group_call import CALL_PREFIX, GroupCalls, mix  # noqa: E402

import test_secure_groups as T  # noqa: E402

ROOM = T.ROOM


class Net:
    """The I2P datagram mesh: destination -> member."""

    def __init__(self):
        self.calls = {}
        self.sent = []
        self.drop = set()

    def send(self, frm, dest, packet):
        self.sent.append((frm, dest, len(packet)))
        if dest in self.drop:
            return
        target = self.calls.get(dest)
        if target is not None:
            target.on_datagram(packet)


def _calling(n=3, levels=None):
    w, members = T._group(n, levels=levels)
    net = Net()
    now = [1000.0]
    heard = {m.jid: [] for m in members}
    for m in members:
        dest = "dest-" + m.jid
        m.calls = GroupCalls(
            m.groups,
            send_datagram=lambda d, p, frm=m.jid: net.send(frm, d, p),
            local_destination=lambda dest=dest: dest,
            on_audio=lambda room, who, frame, jid=m.jid: heard[jid].append((who, frame)),
            emit=m.events.append, clock=lambda: now[0])
        net.calls[dest] = m.calls
    return w, members, net, now, heard


def _pair_all(w, members, level=SecurityState.SMP_VERIFIED):
    """Bindings between every pair (as if each had verified the others)."""
    for a in members:
        for b in members:
            if a is not b:
                fp = b.groups.own_fingerprint(ROOM)
                a.groups._bound.setdefault(ROOM, {})[b.jid] = (
                    fp, level == SecurityState.SMP_VERIFIED)


class TestACall:

    def test_three_verified_members_hear_each_other(self):
        w, (a, b, c), net, now, heard = _calling(3)
        _pair_all(w, [a, b, c])
        call_id = a.calls.start(ROOM)
        assert any(r["call"] == call_id for r in b.calls.ringing())
        b.calls.join(ROOM)
        c.calls.join(ROOM)
        assert sorted(a.calls.participants(ROOM)) == ["bob@x.i2p", "carol@x.i2p"]
        assert sorted(b.calls.participants(ROOM)) == ["alice@x.i2p", "carol@x.i2p"]
        assert a.calls.send_audio(b"\x01\x00" * 4) == 2
        c.calls.send_audio(b"\x02\x00" * 4)
        assert heard["bob@x.i2p"] == [("alice@x.i2p", b"\x01\x00" * 4),
                                      ("carol@x.i2p", b"\x02\x00" * 4)]
        assert ("alice@x.i2p", b"\x01\x00" * 4) in heard["carol@x.i2p"]

    def test_control_messages_are_never_shown_as_chat(self):
        w, (a, b, c), net, now, heard = _calling(3)
        _pair_all(w, [a, b, c])
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        for m in (a, b, c):
            assert not any(isinstance(e, RoomMessageReceived) and CALL_PREFIX in e.body
                           for e in m.events)
            assert not any(isinstance(e, RoomMessageReceived) for e in m.events)
        # ... and travelled as MLS ciphertext, not as text in the room.
        assert not any("ring" in body for _s, body in w.room.log)

    def test_an_unverified_member_is_not_in_the_call(self):
        w, (a, b, c), net, now, heard = _calling(3)
        _pair_all(w, [a, b])
        for m in (a, b):                       # nobody verified Carol
            m.groups._bound[ROOM]["carol@x.i2p"] = ("00" * 48, False)
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        c.calls.join(ROOM)
        assert a.calls.participants(ROOM) == ["bob@x.i2p"]
        assert "call_refused_unverified" in [e.change for e in a.events
                                             if isinstance(e, GroupChanged)]
        a.calls.send_audio(b"\x05\x00")
        assert heard["carol@x.i2p"] == []
        assert not any(d == "dest-carol@x.i2p" for f, d, n in net.sent if f == "alice@x.i2p")
        # Carol's frames, sent to Alice anyway, are dropped.
        c.calls._calls[ROOM].peers["alice@x.i2p"] = "dest-alice@x.i2p"
        c.calls.send_audio(b"\x07\x00")
        assert all(who != "carol@x.i2p" for who, _f in heard["alice@x.i2p"])

    def test_nobody_verified_means_no_call(self):
        w, (a, b), net, now, heard = _calling(2)
        a.groups._bound[ROOM]["bob@x.i2p"] = (b.groups.own_fingerprint(ROOM), False)
        with pytest.raises(ValueError):
            a.calls.start(ROOM)


class TestKeysFollowTheGroup:

    def test_a_commit_moves_the_call_to_new_keys(self):
        w, (a, b, c), net, now, heard = _calling(3)
        _pair_all(w, [a, b, c])
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        epoch = a.calls._calls[ROOM].voice.epoch
        b.groups.rekey(ROOM)                    # any commit
        _pair_all(w, [a, b, c])
        assert a.calls._calls[ROOM].voice.epoch == epoch + 1
        assert b.calls._calls[ROOM].voice.epoch == epoch + 1
        a.calls.send_audio(b"\x09\x00")
        assert heard["bob@x.i2p"][-1] == ("alice@x.i2p", b"\x09\x00")
        # The previous epoch goes after the grace period.
        assert a.calls._calls[ROOM].voice.has_previous
        now[0] += GroupCalls.GRACE_SECONDS + 1
        a.calls.tick()
        assert not a.calls._calls[ROOM].voice.has_previous

    def test_the_starter_rekeys_every_120_seconds(self):
        w, (a, b), net, now, heard = _calling(2)
        _pair_all(w, [a, b])
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        epoch = a.groups.epoch(ROOM)
        now[0] += 60
        a.calls.tick()
        b.calls.tick()
        assert a.groups.epoch(ROOM) == epoch
        now[0] += 61
        b.calls.tick()                          # not the starter
        assert a.groups.epoch(ROOM) == epoch
        a.calls.tick()
        assert a.groups.epoch(ROOM) == epoch + 1 == b.groups.epoch(ROOM)
        assert b.calls._calls[ROOM].voice.epoch == epoch + 1

    def test_a_removed_member_cannot_hear_after_the_commit(self):
        w, (a, b, c), net, now, heard = _calling(3)
        _pair_all(w, [a, b, c])
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        c.calls.join(ROOM)
        a.groups.remove(ROOM, "carol@x.i2p")
        assert "carol@x.i2p" not in a.calls.participants(ROOM)
        # Even if a frame reaches Carol, her keys are the old epoch's.
        packet = bytes(a.calls._calls[ROOM].voice.seal(b"\x0a\x00"))
        assert c.calls.on_datagram(packet) is False

    def test_an_outsider_with_the_call_id_hears_nothing(self):
        w, (a, b), net, now, heard = _calling(2)
        _pair_all(w, [a, b])
        call_id = a.calls.start(ROOM)
        packet = bytes(a.calls._calls[ROOM].voice.seal(b"\x0b\x00"))
        mallory = core.RustMlsClient(b"mallory@x.i2p")
        mallory.create_group(ROOM.encode())
        v = mallory.group_voice(ROOM.encode(), bytes.fromhex(call_id))
        with pytest.raises(ValueError):
            v.open(packet)


class TestHangUp:

    def test_hangup_destroys_the_keys_and_tells_the_others(self):
        w, (a, b), net, now, heard = _calling(2)
        _pair_all(w, [a, b])
        a.calls.start(ROOM)
        b.calls.join(ROOM)
        voice = b.calls._calls[ROOM].voice
        b.calls.hangup(ROOM)
        assert voice.zeroized
        assert "bob@x.i2p" not in a.calls.participants(ROOM)
        assert a.calls.send_audio(b"\x00\x00") == 0

    def test_mixing_clips(self):
        loud = (30000).to_bytes(2, "little", signed=True)
        assert mix([loud, loud]) == (32767).to_bytes(2, "little", signed=True)
        assert mix([b"\x01\x00", b"\x01\x00\x02\x00"]) == b"\x02\x00\x02\x00"
        assert mix([]) == b""


class TestTermuxMedia:
    """The terminal client's media side, without a router or a microphone."""

    def test_playout_mixes_one_frame_per_sender_and_bounds_queues(self):
        import otrv4plus_groupcall as gc
        p = gc.Playout(4)
        assert p.next_frame() == b"\x00" * 4             # silence when idle
        for i in range(gc.PER_SENDER_QUEUE + 3):
            p.push("bob", b"\x01\x00\x01\x00")
        p.push("carol", b"\x02\x00\x02\x00")
        assert p.next_frame() == b"\x03\x00\x03\x00"
        frames = 1
        while p.next_frame() != b"\x00" * 4:
            frames += 1
        assert frames == gc.PER_SENDER_QUEUE              # oldest were dropped

    def test_datagrams_go_through_the_sam_udp_header(self):
        import otrv4plus_groupcall as gc
        import otrv4plus_voice as voice
        media = gc.GroupCallMedia(loop=None, sam_host="127.0.0.1", sam_port=7656)
        sent = []
        media._transport = type("T", (), {"sendto": lambda self, d, a: sent.append((d, a))})()
        media._session_id = "sid"
        media.send_datagram("DEST", b"packet")
        assert sent == [(b"3.0 sid DEST\npacket", ("127.0.0.1", voice.sam_udp_port()))]
        # Inbound: the header is split off, the payload goes to GroupCalls.
        got = []
        media._calls = type("C", (), {"on_datagram": lambda self, p: got.append(p) or True})()
        media._on_datagram(b"A" * 516 + b"\npayload")
        assert got == [b"payload"] and media.stats["rx"] == 1


def test_pause_stops_our_audio_but_keeps_us_in_the_call():
    w, (a, b), net, now, heard = _calling(2)
    _pair_all(w, [a, b])
    a.calls.start(ROOM)
    b.calls.join(ROOM)
    assert a.calls.pause() is True
    assert a.calls.send_audio(b"\x01\x00") == 0
    b.calls.send_audio(b"\x02\x00")                 # we still hear them
    assert heard["alice@x.i2p"][-1] == ("bob@x.i2p", b"\x02\x00")
    assert a.calls.pause() is False
    assert a.calls.send_audio(b"\x03\x00") == 1
    assert "call_paused" in [e.change for e in a.events if isinstance(e, GroupChanged)]


def test_the_app_joins_a_verified_ring_only_with_the_microphone_allowed():
    """Owner design (2026-10-10): verified members join a group call by
    themselves. In the app that opens the microphone, so only when the user
    has granted it (`auto_join`, set from the permission)."""
    import threading as _threading
    from android_bridge.group_call_bridge import GroupCallBridge
    w, (a, b) = T._group(2)
    _pair_all(w, [a, b])
    joined = []
    bridges = {}
    for m in (a, b):
        app = type("App", (), {"groups": m.groups})()
        br = GroupCallBridge(app, sam=lambda: ("127.0.0.1", 7656),
                             emit=m.events.append)
        br.join = lambda room, jid=m.jid: joined.append((jid, room))
        bridges[m.jid] = br

    class Inline:
        def __init__(self, target=None, args=(), **_kw):
            self.target, self.args = target, args

        def start(self):
            self.target(*self.args)

    import android_bridge.group_call_bridge as gcb
    orig = gcb.threading.Thread
    gcb.threading.Thread = Inline
    try:
        ring = GroupChanged(peer=ROOM, change="call_ringing", detail=a.jid)
        bridges[b.jid]._emit(ring)                       # microphone not allowed
        assert joined == []
        bridges[b.jid].auto_join = True
        bridges[b.jid]._emit(ring)
        assert joined == [(b.jid, ROOM)]
        # Not from someone we have not verified.
        b.groups._bound[ROOM][a.jid] = ("00" * 48, False)
        bridges[b.jid]._emit(ring)
        assert joined == [(b.jid, ROOM)]
    finally:
        gcb.threading.Thread = orig
    assert any(isinstance(e, GroupChanged) and e.change == "call_ringing"
               for e in b.events)                       # still shown
