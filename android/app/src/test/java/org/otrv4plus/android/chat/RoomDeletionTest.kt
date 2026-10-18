// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.chat.RoomDeletion.Action
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Delete for the owner and the server admin; Leave only for everyone else. */
class RoomDeletionTest {

    @Test
    fun `the owner and a server admin are offered Delete`() {
        assertEquals(setOf(Action.LEAVE, Action.DELETE), RoomDeletion.actions("owner", false))
        assertEquals(setOf(Action.LEAVE, Action.DELETE), RoomDeletion.actions("none", true))
        assertEquals(setOf(Action.LEAVE, Action.DELETE), RoomDeletion.actions("member", true))
    }

    @Test
    fun `members and strangers are offered Leave only`() {
        for (aff in listOf("member", "none", "", "outcast", "something-new")) {
            assertEquals(setOf(Action.LEAVE), RoomDeletion.actions(aff, false), aff)
        }
    }

    @Test
    fun `a room admin is not an owner (XEP-0045 10 point 9)`() {
        assertEquals(setOf(Action.LEAVE), RoomDeletion.actions("admin", false))
    }

    @Test
    fun `the chat list and the group screen use the same rule`() {
        val s = ChatState()
        s.bindAccount(AccountScope.of("me@otrv4plus.i2p"))
        val room = "team@conference.otrv4plus.i2p"
        assertFalse(s.canDeleteRoom(room))
        s.noteOwnedRooms(listOf(room))
        assertTrue(s.canDeleteRoom(room))
        s.noteOwnedRooms(emptyList())
        s.noteServerAdmin(true)
        assertTrue(s.canDeleteRoom("anyone-elses@conference.otrv4plus.i2p"))
    }

    @Test
    fun `a delete pressed while something runs says so`() {
        assertEquals("Wait for \"Looking for a rooms service\" to finish, then try again.",
                     RoomDeletion.waitFor("Looking for a rooms service..."))
    }
}
