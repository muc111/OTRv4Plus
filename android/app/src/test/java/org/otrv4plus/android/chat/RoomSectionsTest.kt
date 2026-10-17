// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomSummary
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RoomSectionsTest {

    private val ours = RoomSummary("team@muc.x", "", secure = true)
    private val theirs = RoomSummary("club@muc.x", "", claimsSecure = true)
    private val plain = RoomSummary("welcome@muc.x", "")
    private val locked = RoomSummary("quiet@muc.x", "", password = true)

    @Test
    fun `our groups are not listed twice and plain rooms stand apart`() {
        val split = RoomSections.split(listOf(ours, theirs, plain, locked), listOf("TEAM@muc.x"))
        assertEquals(listOf(theirs), split.encrypted)
        assertEquals(listOf(plain, locked), split.plain)
    }

    @Test
    fun `asking is limited to once per ten minutes`() {
        assertTrue(RoomSections.mayAsk(null, 1_000))
        assertFalse(RoomSections.mayAsk(0, RoomSections.ASK_EVERY_MS - 1))
        assertTrue(RoomSections.mayAsk(0, RoomSections.ASK_EVERY_MS))
        // A clock set back does not lock the button for good.
        assertTrue(RoomSections.mayAsk(5_000, 1_000))
        assertEquals("You asked recently. You can ask again in 10 min.",
                     RoomSections.askAgainIn(0, 0))
    }

    @Test
    fun `the plain section says it is not encrypted`() {
        assertTrue(RoomSections.PLAIN_TITLE.contains("not encrypted"))
        assertTrue(RoomSections.PLAIN_NOTE.contains("NOT end-to-end encrypted"))
    }
}
