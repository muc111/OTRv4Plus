// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OnlineDiscovery
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription
import org.otrv4plus.android.bridge.SubscriptionPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The one list of people: roster + requests + who the server says is online,
 * one row each, with Add / Pending / Accept / Added states. Nothing guessed.
 */
class PeopleDirectoryTest {

    private val me = "me@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"
    private val carol = "carol@xmpp-elite.i2p"
    private val dave = "dave@xmpp-elite.i2p"
    private val erin = "erin@xmpp-elite.i2p"

    private fun contact(jid: String, presence: PeerPresence,
                        subscription: Subscription = Subscription.BOTH) =
        Contact(jid, jid.substringBefore('@'), presence, SecurityState.PLAINTEXT,
                SmpState.NOT_VERIFIED, false, subscription)

    private fun state(vararg roster: Contact) = ChatState().apply {
        bindAccount(AccountScope.of(me))
        applyConnection(ConnectionStatus(stage = "connected", connected = true))
        applyRoster(roster.toList())
    }

    private fun relations(s: ChatState) =
        s.directory().associate { it.jid to it.relation }

    @Test
    fun `every relation, one row per person, in decision-first order`() {
        val s = state(
            contact(alice, PeerPresence.ONLINE),
            contact(bob, PeerPresence.OFFLINE),
            contact(carol, PeerPresence.UNKNOWN, Subscription.PENDING),
            contact(erin, PeerPresence.UNKNOWN, Subscription.FROM),
        )
        s.noteSubscription(OtrEvent.SubscriptionRequested(dave, SubscriptionPolicy.ASK))
        s.applyDiscovery(OnlineDiscovery(OnlineDiscovery.XEP_0133,
                                         listOf("$alice/phone", "frank@xmpp-elite.i2p", me)))
        val rows = s.directory()
        assertEquals(
            listOf(dave to OnlineUsers.Relation.ACCEPT,
                   alice to OnlineUsers.Relation.ADDED_ONLINE,
                   "frank@xmpp-elite.i2p" to OnlineUsers.Relation.ONLINE_ADD,
                   carol to OnlineUsers.Relation.PENDING,
                   bob to OnlineUsers.Relation.ADDED_OFFLINE,
                   erin to OnlineUsers.Relation.ADDED_UNKNOWN),
            rows.map { it.jid to it.relation })
        assertEquals(rows.size, rows.map { it.jid }.toSet().size, "a person listed twice")
        assertFalse(rows.any { it.jid == me }, "our own account was listed")
        assertEquals("Add", OnlineUsers.Relation.ONLINE_ADD.action)
        assertEquals("Accept", OnlineUsers.Relation.ACCEPT.action)
        assertNull(OnlineUsers.Relation.PENDING.action)
    }

    @Test
    fun `without server discovery only roster and requests are shown`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        s.applyDiscovery(OnlineDiscovery(OnlineDiscovery.NONE, emptyList()))
        assertEquals(mapOf(alice to OnlineUsers.Relation.ADDED_ONLINE), relations(s))
        val note = OnlineUsers.discoveryNote(s.discovery, s.canSend())
        assertNotNull(note)
        assertTrue("XEP-0133" in note, "the reason was not stated")
    }

    @Test
    fun `server-listed users vanish with our connection and with the account`() {
        val s = state()
        s.applyDiscovery(OnlineDiscovery(OnlineDiscovery.XEP_0133, listOf(bob)))
        assertEquals(mapOf(bob to OnlineUsers.Relation.ONLINE_ADD), relations(s))
        s.applyConnection(ConnectionStatus(stage = "failed", connected = false))
        assertTrue(s.directory().isEmpty(), "a stale online outlived our connection")
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        s.bindAccount(AccountScope.of("other@xmpp-elite.i2p"))
        assertNull(s.discovery, "one account's server answer carried to another")
    }

    @Test
    fun `a request answered automatically is not a question`() {
        val s = state()
        s.noteSubscription(OtrEvent.SubscriptionRequested(dave, SubscriptionPolicy.ACCEPT))
        assertFalse(relations(s).containsKey(dave))
    }

    @Test
    fun `accepting clears the row's question`() {
        val s = state()
        s.noteSubscription(OtrEvent.SubscriptionRequested(dave, SubscriptionPolicy.ASK))
        assertEquals(OnlineUsers.Relation.ACCEPT, relations(s)[dave])
        s.clearSubscription(dave)
        assertFalse(relations(s).containsKey(dave))
    }

    @Test
    fun `online is not encrypted, and the facts say so separately`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        var row = s.directory().single()
        assertEquals(listOf("Online — Added", "not encrypted"), row.facts)
        s.handle(OtrEvent.SessionChanged(alice, SecurityState.SMP_VERIFIED))
        s.handle(OtrEvent.SmpFinished(alice, SmpState.VERIFIED))
        row = s.directory().single()
        assertEquals(listOf("Online — Added", "OTR encrypted", "SMP verified"), row.facts)
    }

    @Test
    fun `the title counts people and who is online`() {
        val s = state(contact(alice, PeerPresence.ONLINE), contact(bob, PeerPresence.OFFLINE))
        assertEquals("PEOPLE (2 · 1 online)", OnlineUsers.directoryTitle(s.directory()))
    }
}
