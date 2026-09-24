// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Somebody messaged us who was never added.
 *
 * An ordinary thing to happen, and the conversation works: a message from a
 * stranger is still a message, and it already got a row from the union of the
 * roster and the store.
 *
 * What was missing is the EXPLANATION. The server does not send us the
 * presence of somebody we have not subscribed to, so their availability reads
 * "presence unknown" — permanently, not slowly. Waiting does not fix it and
 * nothing on screen said so, which leaves the user with the same conclusion
 * every unexplained unknown leaves them with: the app is broken.
 *
 * Saving them is what subscribes. That makes `saved` a fact with a remedy
 * attached rather than a filing detail.
 */
class UnsavedSenderTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val stranger = "carol@elsewhere.i2p"

    private fun state(vararg roster: Contact): ChatState {
        val s = ChatState()
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        if (roster.isNotEmpty()) s.applyRoster(roster.toList())
        return s
    }

    private fun contact(jid: String) = Contact(
        jid = jid, displayName = jid.substringBefore('@'),
        presence = PeerPresence.ONLINE,
        security = SecurityState.PLAINTEXT, smp = SmpState.NOT_VERIFIED,
        callAvailable = false)

    private fun find(s: ChatState, jid: String) =
        s.conversations().first { it.jid == jid }

    // ── the conversation exists either way ──────────────────────────────────

    @Test
    fun `a message from a stranger still gets a conversation`() {
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived(stranger, "hello", 1.0))
        assertTrue(s.conversations().any { it.jid == stranger },
            "a message from somebody not on the roster was dropped")
    }

    @Test
    fun `and it is marked as not saved`() {
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived(stranger, "hello", 1.0))
        assertFalse(find(s, stranger).saved)
    }

    @Test
    fun `a roster contact is saved`() {
        val s = state(contact(alice))
        assertTrue(find(s, alice).saved)
    }

    @Test
    fun `saving is offered for a stranger`() {
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived(stranger, "hello", 1.0))
        assertTrue(find(s, stranger).canBeSaved)
    }

    @Test
    fun `and not for somebody already on the roster`() {
        val s = state(contact(alice))
        assertFalse(find(s, alice).canBeSaved,
            "offering to save a contact who is already saved")
    }

    // ── why it matters ──────────────────────────────────────────────────────

    @Test
    fun `an unsaved sender's presence is unknown`() {
        // Not a defect being papered over. The server sends us nothing about
        // somebody we have not subscribed to, so this is the correct answer —
        // and it is permanent, which is the part the UI has to explain.
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived(stranger, "hello", 1.0))
        assertEquals(Presence.UNKNOWN, find(s, stranger).presence)
    }

    @Test
    fun `saving them changes the answer once the roster comes back`() {
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived(stranger, "hello", 1.0))
        assertFalse(find(s, stranger).saved)

        // What the server pushes after the subscription is accepted.
        s.applyRoster(listOf(contact(alice), contact(stranger)))

        assertTrue(find(s, stranger).saved)
        assertFalse(find(s, stranger).canBeSaved)
        assertEquals(Presence.ONLINE, find(s, stranger).presence)
    }

    // ── it must not put a Save button in front of the wrong person ──────────

    @Test
    fun `a conversation looked up before the roster loads is not called unsaved`() {
        // `conversation(jid)` falls back when the union has no row. Claiming
        // `saved = false` there would offer Save for somebody who may already
        // be a contact the roster has simply not delivered yet.
        val s = ChatState()
        assertTrue(s.conversation(alice).saved)
        assertFalse(s.conversation(alice).canBeSaved)
    }

    @Test
    fun `a jid that is not an address cannot be saved`() {
        val s = state(contact(alice))
        s.receive(OtrEvent.MessageReceived("notajid", "hello", 1.0))
        assertFalse(find(s, "notajid").canBeSaved,
            "offering to add something that is not an address")
    }

    @Test
    fun `losing the roster does not turn every contact into a stranger`() {
        // A roster read that fails must not produce a screen full of Save
        // buttons for people who are already contacts.
        val s = state(contact(alice))
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        assertTrue(find(s, alice).saved)
    }
}
