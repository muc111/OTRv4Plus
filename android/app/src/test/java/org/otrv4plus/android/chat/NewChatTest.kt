// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NewChatTest {

    private fun e(jid: String, r: OnlineUsers.Relation, name: String = jid.substringBefore('@'),
                  verified: Boolean = false) =
        OnlineUsers.Entry(jid, name, r, encrypted = false, verified = verified)

    private val people = listOf(
        e("zoe@x.i2p", OnlineUsers.Relation.ONLINE_ADD),
        e("bob@x.i2p", OnlineUsers.Relation.ADDED_ONLINE),
        e("amy@x.i2p", OnlineUsers.Relation.ONLINE_ADD),
        e("carl@x.i2p", OnlineUsers.Relation.ADDED_OFFLINE),
        e("dan@x.i2p", OnlineUsers.Relation.PENDING),
        e("eve@x.i2p", OnlineUsers.Relation.ACCEPT),
        e("fay@x.i2p", OnlineUsers.Relation.ADDED_UNKNOWN),
    )

    @Test fun `only people online are listed, contacts first`() {
        assertEquals(listOf("bob@x.i2p", "amy@x.i2p", "zoe@x.i2p"), NewChat.online(people).map { it.jid })
    }

    @Test fun `typing narrows the list`() {
        assertEquals(listOf("zoe@x.i2p"), NewChat.online(people, "ZO").map { it.jid })
        assertEquals(emptyList(), NewChat.online(people, "carl"))
    }

    @Test fun `a typed name or address becomes the address to chat with`() {
        assertEquals("bob@x.i2p", NewChat.address(" Bob@X.i2p ", "me@x.i2p"))
        assertEquals("ann@x.i2p", NewChat.address("ann", "me@x.i2p/phone"))
        assertNull(NewChat.address("me", "me@x.i2p"), "never ourselves")
        assertNull(NewChat.address("a b", "me@x.i2p"))
        assertNull(NewChat.address("bob@", "me@x.i2p"))
        assertNull(NewChat.address("@x.i2p", "me@x.i2p"))
        assertNull(NewChat.address("a@b@c.i2p", "me@x.i2p"))
        assertNull(NewChat.address("", "me@x.i2p"))
    }

    @Test fun `rows say whether they are a contact yet`() {
        assertEquals("Online · contact · SMP verified",
                     NewChat.subtitle(e("bob@x.i2p", OnlineUsers.Relation.ADDED_ONLINE, verified = true)))
        assertTrue("not a contact" in NewChat.subtitle(people[0]))
    }
}
