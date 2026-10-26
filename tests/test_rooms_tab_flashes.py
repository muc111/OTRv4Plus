# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Desktop: the Rooms tab flashes while a group invitation is unseen.

Owner (2026-10-26): an invitation was missed -- it was on the Rooms tab,
marked by a small dot, while Chats was open. The decision is
`InviteAttention` (InviteAttentionTest); this pins that the rail uses it.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESK = os.path.join(ROOT, "desktop/src/main/kotlin/org/otrv4plus/desktop")


def _read(rel):
    with open(os.path.join(DESK, rel), encoding="utf-8") as fh:
        return fh.read()


def test_the_rooms_rail_item_flashes_for_unseen_invitations():
    src = _read("ui/MainScreen.kt")
    rooms = src[src.index("AppModel.Tab.ROOMS, Icons.Filled.Groups"):]
    rooms = rooms[:rooms.index(")\n")]
    assert "flashing = model.unseenInvites()" in rooms


def test_the_rail_pulses_and_counts():
    src = _read("ui/MainScreen.kt")
    item = src[src.index("private fun RailItem("):src.index("private fun LinkBanner(")]
    assert "rememberInfiniteTransition" in item and "RepeatMode.Reverse" in item
    assert 'Text("$flashing"' in item, "the count is shown, not only a dot"


def test_seeing_rooms_is_what_stops_it():
    src = _read("AppModel.kt")
    fn = src[src.index("fun unseenInvites()"):]
    fn = fn[:fn.index("\n\n")]
    assert "chat.pendingGroupInvites" in fn and "tab == Tab.ROOMS" in fn
    assert os.path.exists(os.path.join(ROOT, "desktop/src/test/kotlin/org/otrv4plus/"
                                             "desktop/InviteAttentionTest.kt"))
