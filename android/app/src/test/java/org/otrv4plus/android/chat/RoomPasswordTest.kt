// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The prompt opens only when the service asks for a password. */
class RoomPasswordTest {

    private val room = "club@muc.fixture.i2p"
    private fun out(ok: Boolean, code: String) = RoomOutcome(ok, code, "")

    @Test
    fun `a not-authorized join asks for the password`() {
        val p = RoomPassword.afterJoin(room, "me", out(false, "not_authorized"), false)
        assertNotNull(p)
        assertEquals(room, p.room)
        assertEquals("me", p.nick)
        assertFalse(p.retry)
    }

    @Test
    fun `a refused password asks again and says so`() {
        val p = RoomPassword.afterJoin(room, "me", out(false, "not_authorized"), true)
        assertNotNull(p)
        assertTrue(p.retry)
        assertTrue("not accepted" in p.message)
    }

    @Test
    fun `nothing else opens the prompt`() {
        assertNull(RoomPassword.afterJoin(room, "me", out(true, "ok"), true))
        for (code in listOf("forbidden", "conflict", "registration_required",
                            "item_not_found", "timeout", "network")) {
            assertNull(RoomPassword.afterJoin(room, "me", out(false, code), false), code)
        }
    }

    @Test
    fun `a room password must be something`() {
        assertNotNull(RoomPassword.problem(""))
        assertNotNull(RoomPassword.problem("   "))
        assertNotNull(RoomPassword.problem("a".repeat(RoomPassword.MAX_LENGTH + 1)))
        assertNotNull(RoomPassword.problem("pa\u0000ss"))
        assertNull(RoomPassword.problem("correct horse battery"))
    }

    @Test
    fun `it never claims to be encryption`() {
        assertTrue("not end-to-end encrypted" in RoomPassword.NOT_ENCRYPTION)
    }

    @Test
    fun `a room the list marks as protected is asked about before joining`() {
        val p = RoomPassword.beforeJoin("club@conference.otrv4plus.i2p", "alice", needsPassword = true)
        assertNotNull(p)
        assertFalse(p!!.retry)
        assertNull(RoomPassword.beforeJoin("open@conference.otrv4plus.i2p", "alice", needsPassword = false))
    }

    @Test
    fun `asking to join an encrypted group says who will see it`() {
        assertTrue(RoomPassword.NEEDS_INVITE.contains("can invite you"))
        assertTrue(RoomPassword.NEEDS_INVITE.contains("can see that you asked"))
    }
}
