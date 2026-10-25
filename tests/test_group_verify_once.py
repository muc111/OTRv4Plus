# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One verification attempt per member; the creator removes who failed.

Owner (2026-10-25): "Verify must only be once SMP passphrase pass anyone who
got it wrong can be excluded and kicked from group by creator". A failure is
recorded against the member's group key, survives a restart, is never tried
again, and the creator -- only the creator -- removes everyone who failed in
one commit. Real Rust MLS and SMP; the simulated room of test_secure_groups.
"""
from __future__ import annotations

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

from android_bridge.events import SecurityState                        # noqa: E402
from android_bridge.group_verify import GroupVerify                    # noqa: E402
from android_bridge.groups import GroupError                           # noqa: E402
from test_secure_groups import ROOM, _group                           # noqa: E402

RIGHT = b"correct horse battery"
WRONG = b"wrong horse battery!"
UNVERIFIED = {"bob@x.i2p": SecurityState.ENCRYPTED, "carol@x.i2p": SecurityState.ENCRYPTED}


def _run_with_carol_wrong():
    w, (a, b, c) = _group(3, levels=UNVERIFIED)
    va, vb, vc = [GroupVerify(m.groups, emit=m.events.append) for m in (a, b, c)]
    sent = []
    real = va._send
    va._send = lambda room, msg: (sent.append(dict(msg)), real(room, msg))
    va.start(ROOM, bytearray(RIGHT))
    vb.start(ROOM, bytearray(RIGHT))
    vc.start(ROOM, bytearray(WRONG))
    return (a, b, c), (va, vb, vc), sent


def _member(m, jid):
    return {x["jid"]: x for x in m.groups.members(ROOM)}[jid]


def test_a_wrong_passphrase_is_recorded_against_the_key():
    (a, b, c), (va, vb, vc), _ = _run_with_carol_wrong()
    assert _member(a, c.jid)["failed"] and not _member(a, c.jid)["verified"]
    assert va.status(ROOM)[c.jid] == "failed"
    assert va.failed(ROOM) == [c.jid]
    # The creator said so, with her key: bob knows too.
    assert _member(b, c.jid)["failed"]


def test_there_is_no_second_attempt():
    (a, b, c), (va, vb, vc), sent = _run_with_carol_wrong()
    to_carol = sum(1 for m in sent if m.get("t") == "smp" and m.get("to") == c.jid)
    # She retypes it right: there is nothing left for her to join.
    assert vc.start(ROOM, bytearray(RIGHT)) == ""
    assert _member(c, a.jid)["failed"], "her side records it too"
    assert sum(1 for m in sent if m.get("t") == "smp" and m.get("to") == c.jid) == to_carol
    # Nor in a new run the creator starts later.
    va.cancel(ROOM)
    va.start(ROOM, bytearray(RIGHT))
    vc.start(ROOM, bytearray(RIGHT))
    assert sum(1 for m in sent if m.get("t") == "smp" and m.get("to") == c.jid) == to_carol
    assert not _member(a, c.jid)["verified"] and _member(a, c.jid)["failed"]


def test_the_run_ends_once_everyone_is_settled():
    (a, b, c), (va, vb, vc), _ = _run_with_carol_wrong()
    assert va.settled(ROOM)
    assert ROOM not in va._runs, "nothing left to try: the passphrase is zeroed"
    # A member asked to join now is told there is nothing left.
    assert vb.start(ROOM, bytearray(RIGHT)) == ""


def test_the_failure_survives_a_restart():
    (a, b, c), _, _ = _run_with_carol_wrong()
    a.groups._store_app_state()
    a.groups._failed.clear()
    a.groups._load_app_state()
    assert _member(a, c.jid)["failed"]


def test_the_creator_removes_everyone_who_failed_in_one_commit():
    (a, b, c), (va, vb, vc), _ = _run_with_carol_wrong()
    assert a.groups.remove_failed(ROOM) == [c.jid]
    left = {m["jid"] for m in a.groups.members(ROOM)}
    assert c.jid not in left and b.jid in left
    assert c.jid not in {m["jid"] for m in b.groups.members(ROOM)}
    assert "removed_us" in c.changes()
    assert a.groups._failed.get(ROOM, {}) == {}


def test_nobody_but_the_creator_removes():
    (a, b, c), _, _ = _run_with_carol_wrong()
    with pytest.raises(GroupError) as exc:
        b.groups.remove(ROOM, c.jid)
    assert exc.value.code == "only_the_creator_removes"
    with pytest.raises(GroupError):
        b.groups.remove_failed(ROOM)
    assert c.jid in {m["jid"] for m in a.groups.members(ROOM)}


def test_a_failure_said_by_anyone_else_or_for_another_key_counts_for_nothing():
    w, (a, b, c) = _group(3, levels=UNVERIFIED)
    va, vb, vc = [GroupVerify(m.groups, emit=m.events.append) for m in (a, b, c)]
    va.start(ROOM, bytearray(RIGHT))
    run = vb._runs[ROOM]
    carol_fp = b.groups.member_fingerprint(ROOM, c.jid)
    vb._on_vouch(ROOM, c.jid, run, {"ok": [], "failed": [[c.jid, carol_fp]]})
    assert not _member(b, c.jid)["failed"], "carol is not the creator"
    vb._on_vouch(ROOM, a.jid, run, {"ok": [], "failed": [[c.jid, "00" * 32]]})
    assert not _member(b, c.jid)["failed"], "not the key the group holds"
    vb._on_vouch(ROOM, a.jid, run, {"ok": [], "failed": [[c.jid, carol_fp]]})
    assert _member(b, c.jid)["failed"]


def test_a_later_success_on_the_same_key_clears_it():
    (a, b, c), _, _ = _run_with_carol_wrong()
    a.groups.mark_member_verified(ROOM, c.jid)
    assert not _member(a, c.jid)["failed"] and _member(a, c.jid)["verified"]
