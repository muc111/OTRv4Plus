# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every verified member of a group is in its call (device test, 2026-11-06).

Three devices, all reported verified; the call held two. The device's report
showed peers=1 and one decoded sender for the whole call, so the third member
never entered the peer set: media was fine, admission was not.

How members come to trust each other: they do not run SMP with each other.
The group's coordinator (its creator) runs one SMP with each member and then
VOUCHES for everyone verified so far; each member marks them verified on the
coordinator's word (group_verify.py, _on_vouch). A call admits a remote only
if this device holds a verified binding for them at the moment their
join/here arrives (group_call.py, _on_control).

Real Rust MLS, real SMP, the simulated room of test_secure_groups.
"""
from __future__ import annotations

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient") or not hasattr(core, "RustGroupVoice"):
    pytest.skip("this core has no mls / group voice", allow_module_level=True)

from android_bridge.events import GroupChanged, SecurityState          # noqa: E402
from android_bridge.group_call import GroupCalls                       # noqa: E402
from android_bridge.group_verify import GroupVerify                    # noqa: E402
from test_secure_groups import ROOM, _group                            # noqa: E402

RIGHT = b"correct horse battery"


class _Net:
    def __init__(self):
        self.calls = {}

    def send(self, dest, packet):
        target = self.calls.get(dest)
        if target is not None:
            target.on_datagram(packet)


NAMES = ["alice@x.i2p", "bob@x.i2p", "carol@x.i2p", "dave@x.i2p", "erin@x.i2p"]


def _members(n):
    """n members in one secure group, created by the first; no member holds
    a verified binding for another yet (their 1:1 sessions are encrypted,
    not SMP-verified), so trust can only come from group verification."""
    import test_secure_groups as T
    w = T.World()
    names = NAMES[:n]
    for name in names:
        w.add(name)
    w.members[names[0]].join_room()
    w.members[names[0]].groups.create(ROOM)
    for other in names[1:]:
        w.pair(names[0], other, SecurityState.ENCRYPTED)
        T._invite(w, names[0], other)
    return [w.members[x] for x in names]


def _verified_group(n, *, lose_run_before=None):
    """n members verified the way devices do it: the creator runs SMP with
    each, then vouches. `lose_run_before=k`: member 1's app restarts (its
    in-memory verification run is gone) before member k is verified."""
    members = _members(n)
    ver = [GroupVerify(m.groups, emit=m.events.append) for m in members]
    ver[0].start(ROOM, bytearray(RIGHT))
    for i in range(1, n):
        if lose_run_before == i:
            ver[1] = GroupVerify(members[1].groups, emit=members[1].events.append)
        ver[i].start(ROOM, bytearray(RIGHT))
    return members, ver


def _with_calls(members):
    net = _Net()
    for m in members:
        dest = "dest-" + m.jid
        m.calls = GroupCalls(
            m.groups, send_datagram=lambda d, p: net.send(d, p),
            local_destination=lambda dest=dest: dest,
            on_audio=lambda *a: None, emit=m.events.append, clock=lambda: 1000.0)
        net.calls[dest] = m.calls
    return members


def _call(members):
    members[0].calls.start(ROOM)
    for m in members[1:]:
        m.calls.join(ROOM)


def _refused(m):
    return sum(1 for e in m.events
               if isinstance(e, GroupChanged) and e.change == "call_refused_unverified")


def test_reproduce_three_devices_when_a_member_missed_the_vouch():
    """The device report, reproduced: member 1's verification run is gone
    (app restarted) when the creator verifies member 2. The creator's vouch
    for member 2 reaches member 1 with no run to receive it."""
    members, _ver = _verified_group(3, lose_run_before=2)
    a, b, c = _with_calls(members)
    _call((a, b, c))
    print("refused: creator=%d b=%d c=%d" % (_refused(a), _refused(b), _refused(c)))
    print("peers:   creator=%d b=%d c=%d" % tuple(
        len(m.calls.participants(ROOM)) for m in (a, b, c)))
    assert len(b.calls.participants(ROOM)) == 2, "b sees only one remote"
    assert len(c.calls.participants(ROOM)) == 2, "c sees only one remote"


def test_reproduce_join_that_beats_the_creators_vouch():
    """The race behind "the third device wasn't connected even though it
    verified". The third member's SMP with the creator succeeds on ITS side
    first, and it joins the running call at once; the creator's vouch for it
    (sent when the creator's side finishes, then paced through the room)
    reaches the second member AFTER the join. The second member refused the
    join as unverified -- and never looked again."""
    members = _members(3)
    a, b, c = members
    ver = [GroupVerify(m.groups, emit=m.events.append) for m in members]
    ver[0].start(ROOM, bytearray(RIGHT))
    ver[1].start(ROOM, bytearray(RIGHT))            # b verified, vouched
    held = []
    real = ver[0]._send
    ver[0]._send = lambda room, msg: (held.append((room, dict(msg)))
                                      if msg.get("t") == "vouch" else real(room, msg))
    ver[2].start(ROOM, bytearray(RIGHT))            # c verified; its vouch held
    _with_calls(members)
    a.calls.start(ROOM)
    b.calls.join(ROOM)
    c.calls.join(ROOM)                               # beats the vouch to b
    assert _refused(b) >= 1, "precondition: b refused c's join"
    ver[0]._send = real
    for room, msg in held:                           # the vouch lands now
        real(room, msg)
    assert {x["jid"]: x["verified"] for x in b.groups.members(ROOM)}[c.jid]
    for m in members:
        m.calls.tick()
    print("peers after the vouch: creator=%d b=%d c=%d" % tuple(
        len(m.calls.participants(ROOM)) for m in members))
    assert sorted(b.calls.participants(ROOM)) == sorted([a.jid, c.jid]), (
        "b verified c but never admitted it: the join was refused for good")
    assert sorted(c.calls.participants(ROOM)) == sorted([a.jid, b.jid])


def _remote(m):
    return sorted(m.calls.participants(ROOM))


def _others(members, m):
    return sorted(x.jid for x in members if x is not m)


def test_three_verified_members_max_five_each_admits_two_remotes():
    members, _ = _verified_group(3)
    _with_calls(members)
    _call(members)
    for m in members:
        m.calls.tick()
        assert _remote(m) == _others(members, m), (m.jid, _remote(m))


def test_five_verified_members_max_five_each_admits_four_remotes():
    members, _ = _verified_group(5)
    _with_calls(members)
    _call(members)
    for m in members:
        m.calls.tick()
        assert len(_remote(m)) == 4 and _remote(m) == _others(members, m), (
            m.jid, _remote(m))


def test_third_member_verified_after_the_call_started_is_added():
    """The call is up between the creator and one member; the third member
    verifies afterwards and joins: it is added on every side, not ignored."""
    members = _members(3)
    a, b, c = members
    ver = [GroupVerify(m.groups, emit=m.events.append) for m in members]
    ver[0].start(ROOM, bytearray(RIGHT))
    ver[1].start(ROOM, bytearray(RIGHT))
    _with_calls(members)
    a.calls.start(ROOM)
    b.calls.join(ROOM)
    assert _remote(a) == [b.jid] and _remote(b) == [a.jid]
    ver[2].start(ROOM, bytearray(RIGHT))            # verifies mid-call
    c.calls.join(ROOM)
    for m in members:
        m.calls.tick()
    for m in members:
        assert _remote(m) == _others(members, m), (m.jid, _remote(m))


def test_a_member_who_never_verifies_stays_out_of_the_call():
    """The safety half of the fix: a pending joiner is admitted only once
    this device holds a verified binding for it. One that failed its
    verification is never admitted, however long the call runs."""
    members = _members(3)
    a, b, c = members
    ver = [GroupVerify(m.groups, emit=m.events.append) for m in members]
    ver[0].start(ROOM, bytearray(RIGHT))
    ver[1].start(ROOM, bytearray(RIGHT))
    ver[2].start(ROOM, bytearray(b"wrong horse battery!"))   # c fails
    _with_calls(members)
    _call(members)
    for _ in range(5):
        for m in members:
            m.calls.tick()
    assert c.jid not in _remote(a) and c.jid not in _remote(b)
    assert a.calls.send_audio(b"\x01\x00" * 4) == 1, "audio went to an unverified member"


def test_every_admission_decision_reaches_the_report():
    """The device report could not say whether the third member's join was
    refused or never arrived: neither was recorded. Both are now, with the
    member as a label, never the address."""
    from android_bridge.trace import TRACE
    TRACE.clear()
    test_reproduce_join_that_beats_the_creators_vouch()
    events = [(e["event"], e["fields"].get("via", ""))
              for e in TRACE.events() if e["component"] == "group_call"]
    assert ("join_refused_unverified", "") in events
    assert ("participant_added", "verified_later") in events
    assert "@x.i2p" not in TRACE.render()
    TRACE.clear()
