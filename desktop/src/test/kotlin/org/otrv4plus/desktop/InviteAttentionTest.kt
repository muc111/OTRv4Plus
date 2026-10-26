// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import kotlin.test.Test
import kotlin.test.assertEquals

/** The Rooms tab flashes until an invitation has been on screen. */
class InviteAttentionTest {

    @Test
    fun `an invitation that arrives while Chats is open flashes Rooms`() {
        val a = InviteAttention()
        assertEquals(0, a.unseen(emptyList(), onRooms = false))
        assertEquals(1, a.unseen(listOf("team@conference.example"), onRooms = false))
        assertEquals(1, a.unseen(listOf("team@conference.example"), onRooms = false),
            "it keeps flashing until seen")
    }

    @Test
    fun `opening Rooms counts as seeing it`() {
        val a = InviteAttention()
        a.unseen(listOf("team@conference.example"), onRooms = false)
        assertEquals(0, a.unseen(listOf("team@conference.example"), onRooms = true))
        assertEquals(0, a.unseen(listOf("team@conference.example"), onRooms = false),
            "back on Chats, an invitation already seen does not flash again")
    }

    @Test
    fun `a later invitation flashes again and is counted alone`() {
        val a = InviteAttention()
        a.unseen(listOf("one@conference.example"), onRooms = true)
        assertEquals(1, a.unseen(listOf("one@conference.example", "two@conference.example"),
                                 onRooms = false))
    }

    @Test
    fun `an invitation that arrives while Rooms is open is seen at once`() {
        val a = InviteAttention()
        assertEquals(0, a.unseen(listOf("team@conference.example"), onRooms = true))
    }

    @Test
    fun `answered invitations are forgotten, so the same room can flash again`() {
        val a = InviteAttention()
        a.unseen(listOf("team@conference.example"), onRooms = true)
        a.unseen(emptyList(), onRooms = false)                    // accepted or declined
        assertEquals(1, a.unseen(listOf("team@conference.example"), onRooms = false),
            "invited again later: a new invitation")
    }
}
