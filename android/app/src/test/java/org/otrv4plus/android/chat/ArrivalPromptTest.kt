// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Whom the app asks about after a notification tap, and in what order. */
class ArrivalPromptTest {

    @Test
    fun `nothing arrived means nothing to ask`() {
        assertNull(ArrivalPrompt().next())
    }

    @Test
    fun `the most recent sender is asked about first`() {
        val p = ArrivalPrompt()
        p.arrived("alice@example.i2p")
        p.arrived("bob@example.i2p")
        assertEquals("bob@example.i2p", p.next())
    }

    @Test
    fun `a sender who writes again moves to the front, once`() {
        val p = ArrivalPrompt()
        p.arrived("alice@example.i2p")
        p.arrived("bob@example.i2p")
        p.arrived("alice@example.i2p")
        assertEquals("alice@example.i2p", p.next())
        assertEquals(listOf("bob@example.i2p", "alice@example.i2p"), p.pending())
    }

    @Test
    fun `not now moves on to the next sender, then to nobody`() {
        val p = ArrivalPrompt()
        p.arrived("alice@example.i2p")
        p.arrived("bob@example.i2p")
        p.answered("bob@example.i2p")
        assertEquals("alice@example.i2p", p.next())
        p.answered("alice@example.i2p")
        assertNull(p.next())
    }

    @Test
    fun `opening a conversation some other way drops it from the queue`() {
        val p = ArrivalPrompt()
        p.arrived("alice@example.i2p")
        p.answered("alice@example.i2p")
        p.answered("never-arrived@example.i2p")
        assertNull(p.next())
    }

    @Test
    fun `a blank sender is ignored`() {
        val p = ArrivalPrompt()
        p.arrived("")
        p.arrived("   ")
        assertNull(p.next())
    }

    @Test
    fun `sign out forgets everyone`() {
        val p = ArrivalPrompt()
        p.arrived("alice@example.i2p")
        p.arrived("room@conference.example.i2p")
        p.clear()
        assertEquals(emptyList(), p.pending())
    }
}
