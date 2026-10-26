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
