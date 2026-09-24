// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** "Online users" from real presence, with four facts kept apart. */
class OnlineUsersTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    private fun contact(jid: String, presence: PeerPresence,
                        security: SecurityState = SecurityState.PLAINTEXT) =
        Contact(jid, jid.substringBefore('@').replaceFirstChar { it.uppercase() },
                presence, security, SmpState.NOT_VERIFIED, false)

    private fun state(vararg roster: Contact) = ChatState().apply {
        applyConnection(ConnectionStatus(stage = "connected", connected = true))
        applyRoster(roster.toList())
    }

    private fun online(s: ChatState) = OnlineUsers.rows(s.conversations())

    @Test
    fun `only people the server says are online are listed, and it updates live`() {
        val s = state(contact(alice, PeerPresence.ONLINE), contact(bob, PeerPresence.OFFLINE))
        assertEquals(listOf(alice), online(s).map { it.jid })
        s.applyRoster(listOf(contact(alice, PeerPresence.OFFLINE), contact(bob, PeerPresence.ONLINE)))
        assertEquals(listOf(bob), online(s).map { it.jid })
        s.applyRoster(listOf(contact(alice, PeerPresence.UNKNOWN), contact(bob, PeerPresence.OFFLINE)))
        assertEquals(emptyList(), online(s), "unknown presence was shown as online")
    }

    @Test
    fun `nobody is online while our own stream is down`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        s.applyConnection(ConnectionStatus(stage = "failed", connected = false))
        assertEquals(emptyList(), online(s), "a stale online outlived our connection")
    }

    @Test
    fun `online, encrypted, verified and call are four separate facts`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        var row = online(s).single()
        assertTrue(row.online)
        assertFalse(row.encrypted || row.verified || row.callReady,
                    "being online was taken as more than being online")
        assertTrue("not encrypted" in row.facts)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.ENCRYPTED))
        row = online(s).single()
        assertTrue(row.encrypted); assertFalse(row.verified || row.callReady)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.SMP_VERIFIED))
        s.handle(OtrEvent.SmpFinished(alice, SmpState.VERIFIED))
        row = online(s).single()
        assertTrue(row.encrypted && row.verified && row.callReady)
        assertEquals(listOf("online", "OTR encrypted", "SMP verified", "call available"), row.facts)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.PLAINTEXT))
        row = online(s).single()
        assertFalse(row.encrypted || row.verified || row.callReady, "a stale verified survived")
    }

    @Test
    fun `tapping reuses the one conversation, whatever the spelling`() {
        val s = state(contact("Alice@XMPP-Elite.i2p/phone", PeerPresence.ONLINE))
        s.receive(OtrEvent.MessageReceived(alice, "hi", 1.0))
        val row = online(s).single()
        assertEquals(alice, row.jid)
        s.open(row.jid)
        assertEquals(1, s.conversations().count { it.jid == alice }, "a duplicate conversation")
        assertEquals(listOf("hi"), s.messages(row.jid).map { it.body })
    }

    @Test
    fun `the title carries the count`() {
        assertEquals("ONLINE USERS (2)", OnlineUsers.title(2))
    }
}
