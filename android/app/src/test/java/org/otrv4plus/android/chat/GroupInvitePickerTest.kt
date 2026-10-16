// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals

/** Owner (2026-10-16): tick the online people, invite them all at once. */
class GroupInvitePickerTest {

    private fun e(jid: String, r: OnlineUsers.Relation) =
        OnlineUsers.Entry(jid, jid.substringBefore('@'), r, encrypted = false, verified = false)

    @Test
    fun `only online people outside the group, contacts first`() {
        val dir = listOf(
            e("zed@x.i2p", OnlineUsers.Relation.ONLINE_ADD),
            e("bob@x.i2p", OnlineUsers.Relation.ADDED_ONLINE),
            e("carol@x.i2p", OnlineUsers.Relation.ADDED_OFFLINE),
            e("dave@x.i2p", OnlineUsers.Relation.ADDED_ONLINE),
            e("alice@x.i2p", OnlineUsers.Relation.ADDED_ONLINE),
            e("eve@x.i2p", OnlineUsers.Relation.PENDING),
        )
        val got = GroupInvitePicker.candidates(dir, members = listOf("Dave@x.i2p/phone"),
                                               me = "alice@x.i2p")
        assertEquals(listOf("bob@x.i2p", "zed@x.i2p"), got.map { it.jid })
        assertEquals(listOf(true, false), got.map { it.contact })
    }

    @Test
    fun `the button says how many`() {
        assertEquals("Invite", GroupInvitePicker.button(0))
        assertEquals("Invite 1 person", GroupInvitePicker.button(1))
        assertEquals("Invite 3 people", GroupInvitePicker.button(3))
    }
}
