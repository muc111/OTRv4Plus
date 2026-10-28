// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ServerRoomsTest {

    @Test
    fun `an admin is told hidden rooms are listed and that a group still cannot be read`() {
        val note = ServerRooms.note(admin = true)
        assertTrue("Hidden rooms are listed" in note)
        assertTrue("delete any room or group" in note)
        assertTrue("cannot read an encrypted group" in note)
        assertTrue("you are its admin" in ServerRooms.title(admin = true))
    }

    @Test
    fun `anyone else is not promised hidden rooms or deleting`() {
        val note = ServerRooms.note(admin = false)
        assertFalse("delete" in note.lowercase())
        assertTrue("can be hidden" in note)
        assertFalse("admin" in ServerRooms.title(admin = false))
    }

    @Test
    fun `asking to join says the members decide, even for an admin`() {
        assertTrue("members decide" in ServerRooms.ASK_TEXT)
        assertTrue("even as the server's admin" in ServerRooms.ASK_TEXT)
    }

    @Test
    fun `deleting says what happens to a held group and to anyone else's`() {
        assertTrue("Every member is removed" in ServerRooms.deleteText("g@c", held = true))
        val other = ServerRooms.deleteText("g@c", held = false)
        assertTrue("deleted from the server for everyone" in other)
        assertTrue("their app ends its copy" in other)
    }
}
