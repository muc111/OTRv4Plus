// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription
import org.otrv4plus.android.bridge.SubscriptionPolicy
import org.otrv4plus.android.bridge.WelcomeView
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.OtrAvailability
import org.otrv4plus.android.crypto.TransferUi
import java.io.File
import org.otrv4plus.android.chat.OnlineUsers.Relation as R
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Welcome-room occupants in the one People list. Roster state wins; one row
 * per person; discovery grants nothing -- not trust, SMP, calls or files.
 */
class WelcomeDiscoveryTest {

    private val me = "me@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"
    private val carol = "carol@xmpp-elite.i2p"
    private val dave = "dave@xmpp-elite.i2p"

    private fun contact(jid: String, presence: PeerPresence,
                        subscription: Subscription = Subscription.BOTH) =
        Contact(jid, jid.substringBefore('@'), presence, SecurityState.PLAINTEXT,
                SmpState.NOT_VERIFIED, false, subscription)

    private fun state(vararg roster: Contact) = ChatState().apply {
        bindAccount(AccountScope.of(me))
        applyConnection(ConnectionStatus(stage = "connected", connected = true))
        applyRoster(roster.toList())
    }

    private fun welcome(vararg people: String, hidden: Int = 0,
                        state: String = WelcomeView.JOINED) =
        WelcomeView(state, "lobby@muc.fixture.i2p", "non_anonymous",
                    people.toList(), hidden)

    private fun rel(s: ChatState) = s.directory().associate { it.jid to it.relation }

    @Test
    fun `a welcome occupant not in the roster is Online - Add`() {
        val s = state()
        s.applyWelcome(welcome(dave))
        assertEquals(mapOf(dave to R.ONLINE_ADD), rel(s))
        assertEquals("Add", R.ONLINE_ADD.action)
    }

    @Test
    fun `a roster contact in the room stays one Online - Added row`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        s.applyWelcome(welcome(alice, "ALICE@xmpp-elite.i2p"))
        val rows = s.directory()
        assertEquals(1, rows.size)
        assertEquals(R.ADDED_ONLINE, rows.single().relation)
    }

    @Test
    fun `roster state wins - offline, pending and accept are kept`() {
        val s = state(contact(bob, PeerPresence.OFFLINE),
                      contact(carol, PeerPresence.UNKNOWN, Subscription.PENDING))
        s.noteSubscription(OtrEvent.SubscriptionRequested(dave, SubscriptionPolicy.ASK))
        s.applyWelcome(welcome(bob, carol, dave))
        assertEquals(R.ADDED_OFFLINE, rel(s)[bob])
        assertEquals(R.PENDING, rel(s)[carol])
        assertEquals(R.ACCEPT, rel(s)[dave])
        assertEquals(3, s.directory().size, "a person was listed twice")
    }

    @Test
    fun `leaving the room, losing the stream, or another account clears it`() {
        val s = state()
        s.applyWelcome(welcome(dave))
        assertTrue(rel(s).containsKey(dave))
        s.applyWelcome(welcome(state = WelcomeView.LEFT))
        assertTrue(s.directory().isEmpty())
        s.applyWelcome(welcome(dave))
        assertTrue(rel(s).containsKey(dave), "rejoining did not bring them back")
        s.applyConnection(ConnectionStatus(stage = "failed", connected = false))
        assertTrue(s.directory().isEmpty(), "a stale occupant outlived our stream")
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        s.bindAccount(AccountScope.of("other@xmpp-elite.i2p"))
        assertEquals(WelcomeView.NONE, s.welcome)
    }

    @Test
    fun `occupants are only listed while joined`() {
        val s = state()
        for (st in listOf(WelcomeView.JOINING, WelcomeView.SEARCHING,
                          WelcomeView.FAILED, WelcomeView.NOT_FOUND)) {
            s.applyWelcome(welcome(dave, state = st))
            assertTrue(s.directory().isEmpty(), st)
        }
    }

    @Test
    fun `hidden occupants are counted, never given an address`() {
        val s = state()
        s.applyWelcome(welcome(hidden = 4))
        assertTrue(s.directory().isEmpty())
        val note = OnlineUsers.discoveryNote(s.welcome, s.discovery, s.canSend())
        assertNotNull(note)
        assertTrue("4" in note && "hidden" in note)
    }

    @Test
    fun `our own account is never a discoverable person`() {
        val s = state()
        s.applyWelcome(welcome(me, dave))
        assertEquals(setOf(dave), rel(s).keys)
    }

    @Test
    fun `discovery grants no trust, no verification, no call and no file`() {
        val s = state()
        s.applyWelcome(welcome(dave))
        val row = s.directory().single()
        assertFalse(row.encrypted || row.verified)
        val c = s.conversation(dave)
        assertEquals(SecurityState.PLAINTEXT, c.security)
        assertEquals(SmpState.NOT_VERIFIED, c.smp)
        // Being discoverable is not a capability either: no auto OTRv4+.
        assertFalse(OtrAvailability.mayStart(c.otrCapability))
        assertEquals(TransferUi.Offer.NeedsEncryption, TransferUi.offer(c.security))
        assertTrue(CallUi.localGate(true, false, c.security, "") != CallUi.Gate.AVAILABLE)
    }

    @Test
    fun `calls and files stay closed until SMP, even when encrypted`() {
        assertEquals(TransferUi.Offer.NeedsVerification,
                     TransferUi.offer(SecurityState.ENCRYPTED))
        assertEquals(CallUi.Gate.NOT_VERIFIED,
                     CallUi.localGate(true, false, SecurityState.ENCRYPTED, ""))
        assertEquals(TransferUi.Offer.Available,
                     TransferUi.offer(SecurityState.SMP_VERIFIED))
    }

    @Test
    fun `pending has no client-side expiry`() {
        // Pending comes only from the server's roster; nothing in the list
        // logic reads a clock.
        val rel = "java/org/otrv4plus/android/chat/OnlineUsers.kt"
        val file = listOf("src/main/$rel", "main/$rel", "app/src/main/$rel")
            .map(::File).firstOrNull { it.exists() }
        assertNotNull(file, "OnlineUsers.kt not found from ${File(".").absolutePath}")
        val src = file.readText()
        for (clock in listOf("currentTimeMillis", "Instant", "Duration",
                             "172800", "48 * 60", "2 * 24")) {
            assertFalse(clock in src, "OnlineUsers reads a clock ($clock)")
        }
    }

    @Test
    fun `the joined welcome room is listed in chats as a room`() {
        val s = state()
        assertFalse(s.conversations().any { it.displayName == "OTRv4Plus Welcome" })
        s.applyWelcome(welcome(dave))
        val row = s.conversations().single { it.jid == "lobby@muc.fixture.i2p" }
        assertEquals("OTRv4Plus Welcome", row.displayName)
        assertTrue(s.isRoom(row.jid), "the landing room was treated as a person")
    }

    @Test
    fun `creating it says what happened in words`() {
        assertTrue("ready" in OnlineUsers.welcomeCreated(true, "", emptyList()))
        val partial = OnlineUsers.welcomeCreated(true, "", listOf("kept when empty"))
        assertTrue("did not allow" in partial && "kept when empty" in partial)
        assertTrue("not created" in OnlineUsers.welcomeCreated(false, "refused", emptyList()))
        val w = OnlineUsers.WELCOME_CREATE_WARNING
        assertTrue("not end-to-end encrypted" in w && "address" in w)
    }
}
