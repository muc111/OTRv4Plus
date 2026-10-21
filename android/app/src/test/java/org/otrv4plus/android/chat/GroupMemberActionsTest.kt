// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.security.InMemoryVault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Add to contacts" and "Message privately" on a secure-group message
 * (owner, 2026-10-20). Offered for the member MLS authenticated -- never for
 * a nickname, our own message, or an ordinary room's line.
 */
class GroupMemberActionsTest {

    private val me = "owner@x.i2p"
    private val room = "team@conference.x.i2p"

    private fun chat(): ChatState {
        val vault = InMemoryVault()
        return ChatState(PersistentMessageStore(vault)).apply {
            bindVault(vault)
            bindAccount(AccountScope.of(me))
        }
    }

    private fun line(author: String, sender: String = "carol", outgoing: Boolean = false,
                     security: SecurityLabel = SecurityLabel.ENCRYPTED) =
        Message(id = "r:$sender:$author", conversationId = room, body = "hi", outgoing = outgoing,
                at = 1L, sendState = SendState.NONE, security = security,
                sender = sender, wireId = "W", author = author)

    @Test
    fun `a group member is offered by the address MLS proved`() {
        val c = chat()
        assertEquals("carol@x.i2p", c.memberOf(line("Carol@X.i2p")))
        assertFalse(c.isContact("carol@x.i2p"))
        c.applyRoster(listOf(Contact("carol@x.i2p", "Carol", PeerPresence.ONLINE,
                                     SecurityState.PLAINTEXT, SmpState.NOT_VERIFIED, false)))
        assertTrue(c.isContact("Carol@x.i2p"), "already a contact: only Message privately")
    }

    @Test
    fun `nothing is offered without an authenticated author`() {
        val c = chat()
        // An ordinary room's line: only a nickname, which the room assigns.
        assertNull(c.memberOf(line(author = "", sender = "carol", security = SecurityLabel.PLAINTEXT)))
        assertNull(c.memberOf(line(author = "carol")))               // not an address
        assertNull(c.memberOf(line("carol@x.i2p", outgoing = true)))
        assertNull(c.memberOf(line(me)))                              // ourselves
        assertNull(c.memberOf(line("carol@x.i2p", security = SecurityLabel.SYSTEM)))
    }
}
