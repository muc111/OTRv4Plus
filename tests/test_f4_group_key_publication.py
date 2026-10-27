# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""F4 -- secure groups publish the signing keys they retire (epochal signatures).

Owner (2026-10-26): add chat deniability to the MLS groups -- "instead of
releasing MAC keys, you publish a secret signing key after a time delay,
allowing forgery of past signatures but not future ones". Each rekey already
replaced a member's signing key; the old one was wiped, so everything it
signed stayed verifiable for ever. Now Rust keeps it and, after
REVEAL_DELAY_SECONDS (at once for "Make Group Deniable"), publishes it to the
group. The keys never reach Python: Rust builds the publication and, on
receipt, checks it and reports fingerprints only. Real MLS clients
(test_secure_groups.World); the cryptographic claims are proven in Rust
(`retired_key_tests`).
"""
from __future__ import annotations

import pytest

core = pytest.importorskip("otrv4_core")

from android_bridge.groups import GroupError                        # noqa: E402
from test_secure_groups import ROOM, _group                         # noqa: E402
from test_secure_groups import _rooms_settle_at_once                 # noqa: E402,F401


def _clocked(members, start=1_000_000.0):
    now = [start]
    for m in members:
        m.groups._clock = lambda: now[0]
    return now


def _published_to(m):
    return [e.detail for e in m.events if getattr(e, "change", "") == "keys_published"]


def _retired(m):
    return m.groups._client.retired_count(ROOM.encode())


def test_a_rekey_retires_the_old_key_and_maintain_publishes_it_after_the_delay():
    w, (a, b, c) = _group(3)
    now = _clocked([a, b, c])
    a.groups.rekey(ROOM)
    assert _retired(a) == 1, "kept, not wiped"
    a.groups.maintain()
    assert _retired(a) == 1 and not _published_to(b), "not before the delay"
    now[0] += a.groups.REVEAL_DELAY_SECONDS + 1
    assert "published:" + ROOM in a.groups.maintain()
    assert _retired(a) == 0
    assert _published_to(b) == [a.jid] and _published_to(c) == [a.jid]


def test_make_group_deniable_publishes_as_soon_as_the_rotation_lands():
    w, (a, b) = _group(2)
    old = a.groups._client.own_fingerprint(ROOM.encode())
    assert a.groups.make_deniable(ROOM) == "rotating"
    assert a.groups._client.own_fingerprint(ROOM.encode()) != old, "rotated"
    assert _retired(a) == 0, "and published at once"
    assert _published_to(b) == [a.jid]
    assert "keys_published_ours" in a.changes()


def test_the_group_carries_on_after_a_publication():
    w, (a, b, c) = _group(3)
    a.groups.make_deniable(ROOM)
    a.groups.send(ROOM, "after")
    b.groups.send(ROOM, "and back")
    assert ("alice@x.i2p", "after", True) in b.texts()
    assert ("bob@x.i2p", "and back", True) in a.texts()


def test_a_publication_is_never_shown_as_text():
    w, (a, b) = _group(2)
    a.groups.make_deniable(ROOM)
    assert b.texts() == [] and a.texts() == []


def test_only_fingerprints_come_out_of_rust():
    w, (a, b) = _group(2)
    seen = []
    real = b.groups._client

    class Spy:
        def __getattr__(self, name):
            return getattr(real, name)

        def process(self, group, msg):
            ev = real.process(group, msg)
            seen.append(dict(ev))
            return ev

    b.groups._client = Spy()
    a.groups.make_deniable(ROOM)
    [ev] = [e for e in seen if e.get("kind") == "keys_revealed"]
    assert set(ev) == {"kind", "sender", "fingerprints"}
    assert all(len(bytes(f)) == 48 for f in ev["fingerprints"]), "SHA-384 fingerprints"


def test_refused_while_a_change_of_ours_is_on_its_way():
    w, (a, b) = _group(2)
    w.room.drop_next = 1                       # the rekey does not come back
    a.groups.rekey(ROOM)
    with pytest.raises(GroupError) as err:
        a.groups.make_deniable(ROOM)
    assert err.value.code == "commit_pending"


def test_a_client_from_before_hides_it():
    """Behind the group verification control prefix, whose handler drops
    anything that is not its JSON: an older client shows nothing."""
    from android_bridge.group_verify import GroupVerify
    import inspect
    src = inspect.getsource(GroupVerify._on_control)
    assert "json.loads(payload)" in src and "except ValueError" in src
    import os
    rust = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "Rust", "mls", "src", "client.rs"), encoding="utf-8").read()
    assert 'REVEAL_MAGIC: &[u8] = b"\\x00OTRv4GV1:' in rust


def test_leaving_or_wipe_drops_unpublished_keys():
    w, (a, b) = _group(2)
    a.groups.rekey(ROOM)
    assert _retired(a) == 1
    a.groups.on_room_destroyed(ROOM)
    assert ROOM not in a.groups._retired_at


# ── the apps offer it ───────────────────────────────────────────────────────

def _src(*parts):
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_the_controller_and_the_desktop_host_offer_it():
    import types
    from android_bridge.connection import ConnectionController
    from desktop_bridge.host import CONTROLLER_OPS
    calls = []
    ctl = ConnectionController.__new__(ConnectionController)
    ctl._app = types.SimpleNamespace(groups=types.SimpleNamespace(
        make_deniable=lambda room: calls.append(room) or "rotating"))
    out = ctl.make_group_deniable(ROOM)
    assert out["ok"] and calls == [ROOM]
    assert CONTROLLER_OPS["make_group_deniable"] == ("room",)


def test_both_apps_ask_first_and_clear_the_history_after():
    android_core = "android/app/src/main/java/org/otrv4plus/android/bridge/ChaquopyOtrCore.kt"
    desktop_core = "desktop/src/main/kotlin/org/otrv4plus/desktop/engine/DesktopCore.kt"
    for core_path in (android_core, desktop_core):
        assert '"make_group_deniable"' in _src(*core_path.split("/"))
    for ui in ("android/app/src/main/java/org/otrv4plus/android/ui/ConversationGroupUi.kt",
               "desktop/src/main/kotlin/org/otrv4plus/desktop/ui/GroupPane.kt"):
        src = _src(*ui.split("/"))
        assert "GroupDeniable.ACTION" in src and "text.BODY" in src and "text.CONFIRM" in src
    for model in ("android/app/src/main/java/org/otrv4plus/android/chat/ChatViewModel.kt",
                  "desktop/src/main/kotlin/org/otrv4plus/desktop/AppModel.kt"):
        assert "GroupDeniable.apply(" in _src(*model.split("/"))


# ── publication waits for every member (F4 containment, option A) ──────────
#
# A member that has not processed the rotation is still in the old epoch and
# would accept a message signed with the old key (Rust:
# `residual_a_member_that_has_not_processed_the_rotation_accepts_the_retired
# _key_until_it_does`). So the keys go only once every other member has
# acknowledged the rotation (`publication_waits_until_every_member_has_
# acknowledged_the_rotation`). These drive that through the app's group
# manager, with a member offline.

def _offline(w, m):
    del w.room.occupants[m.jid]
    return len(w.room.log)


def _back(w, m, since):
    """[m] comes back and gets what the room relayed while it was away."""
    m.join_room()
    for frm, body in list(w.room.log[since:]):
        m.groups.on_room_body(ROOM, frm.split("@")[0], body, 0.0, own=(frm == m.jid))


def _published_traced():
    from android_bridge.trace import TRACE
    return [ev for ev in TRACE.events() if ev["event"] == "keys_published_ours"]


def test_publish_group_keys_waits_for_a_member_who_is_offline():
    w, (a, b, c) = _group(3)
    since = _offline(w, c)
    traced = len(_published_traced())
    assert a.groups.make_deniable(ROOM) == "rotating"
    assert _retired(a) == 1, "kept: Carol has not seen the new key"
    assert not _published_to(b)
    assert a.groups.keys_waiting(ROOM) == [c.jid]
    assert len(_published_traced()) == traced, "nothing traced as published yet"
    _back(w, c, since)                     # she processes it and acknowledges
    assert _retired(a) == 0
    assert len(_published_traced()) == traced + 1, "the device test reads this"
    assert _published_to(b) == [a.jid] and _published_to(c) == [a.jid]
    assert a.groups.keys_waiting(ROOM) == []


def test_the_delay_does_not_publish_past_a_member_who_is_offline():
    w, (a, b, c) = _group(3)
    now = _clocked([a, b, c])
    since = _offline(w, c)
    a.groups.rekey(ROOM)
    now[0] += a.groups.REVEAL_DELAY_SECONDS + 1
    assert "published:" + ROOM not in a.groups.maintain()
    assert _retired(a) == 1 and not _published_to(b)
    _back(w, c, since)
    assert _retired(a) == 0, "her acknowledgement lets the due keys go"
    assert _published_to(b) == [a.jid]


def test_each_member_acknowledges_another_members_rotation_and_shows_nothing():
    w, (a, b, c) = _group(3)
    before = len(w.room.log)
    a.groups.rekey(ROOM)
    # One message each. It goes as two room pieces: every MLS message
    # carries a composite Ed448 + ML-DSA-87 signature (about 4.7 KB).
    messages = {(frm, body.split("|")[1]) for frm, body in w.room.log[before:]}
    senders = [frm for frm, _ in messages]
    assert senders.count(b.jid) == 1 and senders.count(c.jid) == 1, senders
    assert b.texts() == [] and c.texts() == [] and a.texts() == []
    assert a.groups.keys_waiting(ROOM) == []


def test_the_apps_show_who_the_keys_wait_for():
    import types
    from android_bridge.connection import ConnectionController
    from desktop_bridge.host import CONTROLLER_OPS
    ctl = ConnectionController.__new__(ConnectionController)
    ctl._app = types.SimpleNamespace(groups=types.SimpleNamespace(
        keys_waiting=lambda room: ["carol@x.i2p"]))
    assert ctl.group_publication_waiting(ROOM)["value"] == ["carol@x.i2p"]
    assert CONTROLLER_OPS["group_publication_waiting"] == ("room",)
    for core_path in ("android/app/src/main/java/org/otrv4plus/android/bridge/ChaquopyOtrCore.kt",
                      "desktop/src/main/kotlin/org/otrv4plus/desktop/engine/DesktopCore.kt"):
        assert '"group_publication_waiting"' in _src(*core_path.split("/"))
    for ui in ("android/app/src/main/java/org/otrv4plus/android/ui/ConversationGroupUi.kt",
               "desktop/src/main/kotlin/org/otrv4plus/desktop/ui/GroupPane.kt"):
        src = _src(*ui.split("/"))
        assert "enabled = groupKeys.canPublish(waitingFor)" in src
        assert "groupKeys.waitingLine(waitingFor)" in src


def test_an_acknowledgement_that_could_not_go_is_sent_by_maintain():
    """An acknowledgement refused when it was due (a commit of ours pending
    at that moment, as after re-adding a queued member) stays owed, and
    `maintain` sends it; otherwise the publisher's keys would wait for
    Bob's next message. The owed state is set directly: the moment it is
    refused has passed by the time anything can observe it."""
    w, (a, b, c) = _group(3)
    b.groups._ack_owed.add(ROOM)
    before = len(w.room.log)
    b.groups.maintain()
    assert [frm for frm, _ in w.room.log[before:]].count(b.jid) >= 1, "it went"
    assert ROOM not in b.groups._ack_owed
