// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.RosterResult
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The rules of the chat, driven directly.
 *
 * Each of the four bypasses the brief names -- skip persistence, skip the
 * presence update, route every message to the open conversation, send twice --
 * has at least one test here that goes red when it is planted. That is the
 * point of [ChatState] existing separately from the ViewModel: these are
 * executed, not read.
 */
class ChatStateTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    private fun state(vararg roster: Contact): ChatState {
        val s = ChatState()
        s.now = { FIXED_NOW }
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        if (roster.isNotEmpty()) s.applyRoster(roster.toList())
        return s
    }

    private fun contact(
        jid: String,
        online: Boolean = true,
        security: SecurityState = SecurityState.PLAINTEXT,
        displayName: String = jid,
    ) = Contact(
        jid = jid, displayName = displayName, online = online, security = security,
        smp = SmpState.IDLE, callAvailable = false,
    )

    private fun inbound(peer: String, body: String, at: Double = 1_700.0) =
        OtrEvent.MessageReceived(peer = peer, body = body, timestamp = at)

    // ── persistence ─────────────────────────────────────────────────────────
    // Bypass: "skip persistence" -- drop the store.append in receive or
    // beginSend.

    @Test
    fun `an inbound message is kept`() {
        val s = state(contact(alice))
        assertTrue(s.receive(inbound(alice, "hello")))
        assertEquals(listOf("hello"), s.messages(alice).map { it.body })
    }

    @Test
    fun `history survives the contact going offline and coming back`() {
        val s = state(contact(alice))
        s.receive(inbound(alice, "hello"))
        s.applyRoster(listOf(contact(alice, online = false)))
        s.applyRoster(listOf(contact(alice, online = true)))
        assertEquals(1, s.messages(alice).size)
    }

    @Test
    fun `history survives the contact leaving the roster entirely`() {
        // Unsubscribing is not a request to delete what was said.
        val s = state(contact(alice))
        s.receive(inbound(alice, "hello"))
        s.applyRoster(emptyList())
        assertEquals(listOf("hello"), s.messages(alice).map { it.body })
        // ...and the conversation is still listed, from the store alone.
        assertEquals(listOf(alice), s.conversations().map { it.jid })
    }

    @Test
    fun `an outgoing message is kept`() {
        val s = state(contact(alice))
        s.setDraft(alice, "hi")
        assertTrue(s.beginSend(alice) != null)
        assertEquals(listOf("hi"), s.messages(alice).map { it.body })
    }

    // ── presence ────────────────────────────────────────────────────────────
    // Bypass: "skip presence update" -- ignore applyRoster, or read a stale
    // contact.

    @Test
    fun `presence follows the roster`() {
        val s = state(contact(alice, online = false))
        assertEquals(Presence.OFFLINE, s.conversation(alice).presence)
        s.applyRoster(listOf(contact(alice, online = true)))
        assertEquals(Presence.ONLINE, s.conversation(alice).presence)
        s.applyRoster(listOf(contact(alice, online = false)))
        assertEquals(Presence.OFFLINE, s.conversation(alice).presence)
    }

    @Test
    fun `presence is unknown while disconnected, not offline`() {
        // The device report that started this work said "user is offline" when
        // the truth was that nothing had been asked. A stale "online" from
        // before the stream died would be worse.
        val s = state(contact(alice, online = true))
        assertEquals(Presence.ONLINE, s.conversation(alice).presence)
        s.applyConnection(ConnectionStatus(stage = "disconnected", connected = false))
        assertEquals(Presence.UNKNOWN, s.conversation(alice).presence)
    }

    @Test
    fun `a contact with no roster entry has unknown presence`() {
        val s = state()
        s.receive(inbound("stranger@xmpp-elite.i2p", "hello"))
        assertEquals(
            Presence.UNKNOWN,
            s.conversation("stranger@xmpp-elite.i2p").presence,
        )
    }

    @Test
    fun `a display name from the roster is used and a blank one is not`() {
        val s = state(contact(alice, displayName = "Alice"))
        assertEquals("Alice", s.conversation(alice).displayName)
        s.applyRoster(listOf(contact(alice, displayName = "   ")))
        assertEquals(alice, s.conversation(alice).displayName)
    }

    // ── routing ─────────────────────────────────────────────────────────────
    // Bypass: "route every message to the active conversation" -- use
    // openConversation instead of the sender's JID.

    @Test
    fun `a message goes to its sender, not to the open conversation`() {
        val s = state(contact(alice), contact(bob))
        s.open(bob)                                  // looking at bob
        s.receive(inbound(alice, "from alice"))      // alice writes
        assertEquals(listOf("from alice"), s.messages(alice).map { it.body })
        assertTrue(s.messages(bob).isEmpty())
    }

    @Test
    fun `a message from a stranger does not land in the open conversation`() {
        val s = state(contact(bob))
        s.open(bob)
        s.receive(inbound("mallory@xmpp-elite.i2p", "hello"))
        assertTrue(s.messages(bob).isEmpty())
        assertEquals(1, s.messages("mallory@xmpp-elite.i2p").size)
    }

    @Test
    fun `resources collapse onto one conversation`() {
        // alice@host/phone and alice@host/laptop are alice.
        val s = state(contact(alice))
        s.receive(inbound("$alice/phone", "from the phone"))
        s.receive(inbound("$alice/laptop", "from the laptop"))
        assertEquals(2, s.messages(alice).size)
        assertEquals(listOf(alice), s.conversations().map { it.jid })
    }

    @Test
    fun `an unread message from someone else does not get marked read`() {
        val s = state(contact(alice), contact(bob))
        s.open(bob)
        s.receive(inbound(alice, "unread"))
        assertEquals(1, s.conversation(alice).unread)
    }

    @Test
    fun `a message in the conversation on screen is read as it arrives`() {
        val s = state(contact(alice))
        s.open(alice)
        s.receive(inbound(alice, "seen"))
        assertEquals(0, s.conversation(alice).unread)
    }

    @Test
    fun `closing the conversation stops messages being read automatically`() {
        val s = state(contact(alice))
        s.open(alice)
        s.closeConversation()
        s.receive(inbound(alice, "unseen"))
        assertEquals(1, s.conversation(alice).unread)
    }

    // ── sending once ────────────────────────────────────────────────────────
    // Bypass: "send twice" -- append the result instead of updating, or clear
    // the draft after the call rather than before.

    @Test
    fun `a sent message appears exactly once through its whole lifecycle`() {
        val s = state(contact(alice))
        s.setDraft(alice, "only once")
        val message = s.beginSend(alice)!!
        s.completeSend(message, SendOutcome.ENCRYPTED)
        assertEquals(1, s.messages(alice).size)
        assertEquals(SendState.SENT, s.messages(alice).single().sendState)
    }

    @Test
    fun `the draft is cleared before the send completes`() {
        // So a second tap during the round trip has nothing to send. This is
        // the whole reason beginSend and completeSend are separate calls.
        val s = state(contact(alice))
        s.setDraft(alice, "hi")
        s.beginSend(alice)
        assertEquals("", s.draft(alice))
        assertNull(s.beginSend(alice))
        assertEquals(1, s.messages(alice).size)
    }

    @Test
    fun `a blank draft sends nothing`() {
        val s = state(contact(alice))
        s.setDraft(alice, "   \n ")
        assertNull(s.beginSend(alice))
        assertTrue(s.messages(alice).isEmpty())
    }

    @Test
    fun `the same text sent twice on purpose is two messages`() {
        val s = state(contact(alice))
        s.setDraft(alice, "ok")
        val first = s.beginSend(alice)!!
        s.setDraft(alice, "ok")
        val second = s.beginSend(alice)!!
        assertNotEquals(first.id, second.id)
        assertEquals(2, s.messages(alice).size)
    }

    @Test
    fun `drafts are per conversation`() {
        val s = state(contact(alice), contact(bob))
        s.setDraft(alice, "for alice")
        s.setDraft(bob, "for bob")
        assertEquals("for alice", s.draft(alice))
        assertEquals("for bob", s.draft(bob))
    }

    // ── send outcomes ───────────────────────────────────────────────────────

    @Test
    fun `queued is recorded as queued, not as a failure`() {
        // The engine is holding the text until a session exists. Reporting
        // that as "not sent" is what made this screen look broken during a
        // DAKE.
        val s = state(contact(alice))
        s.setDraft(alice, "hi")
        val message = s.beginSend(alice)!!
        s.completeSend(message, SendOutcome.QUEUED)
        assertEquals(SendState.QUEUED, s.messages(alice).single().sendState)
    }

    @Test
    fun `a failed send says so`() {
        val s = state(contact(alice))
        s.setDraft(alice, "hi")
        val message = s.beginSend(alice)!!
        s.completeSend(message, SendOutcome.FAILED)
        assertEquals(SendState.FAILED, s.messages(alice).single().sendState)
    }

    @Test
    fun `a plaintext send is recorded as sent and as not encrypted`() {
        // Both halves matter. It DID go -- calling it failed would be wrong --
        // and it went in the clear, which the user is entitled to be told.
        val s = state(contact(alice))
        s.setDraft(alice, "hello")
        val message = s.beginSend(alice)!!
        s.completeSend(message, SendOutcome.PLAINTEXT)
        val stored = s.messages(alice).single()
        assertEquals(SendState.SENT, stored.sendState)
        assertEquals(SecurityLabel.PLAINTEXT, stored.security)
    }

    @Test
    fun `only an encrypted outcome labels an outgoing message encrypted`() {
        for (outcome in listOf(SendOutcome.QUEUED, SendOutcome.FAILED,
                               SendOutcome.PLAINTEXT)) {
            val s = state(contact(alice))
            s.setDraft(alice, "hi")
            val message = s.beginSend(alice)!!
            s.completeSend(message, outcome)
            assertNotEquals(
                SecurityLabel.ENCRYPTED,
                s.messages(alice).single().security,
                outcome.name,
            )
        }
    }

    @Test
    fun `an outgoing message is not labelled encrypted before it is sent`() {
        val s = state(contact(alice))
        s.setDraft(alice, "hi")
        s.beginSend(alice)
        assertEquals(SecurityLabel.UNKNOWN, s.messages(alice).single().security)
    }

    // ── the security boundary ───────────────────────────────────────────────

    @Test
    fun `being connected does not make an inbound message encrypted`() {
        // The connection is up and the roster says PLAINTEXT. Connected is a
        // fact about the network, not about this conversation.
        val s = state(contact(alice, security = SecurityState.PLAINTEXT))
        s.receive(inbound(alice, "hello"))
        assertEquals(SecurityLabel.PLAINTEXT, s.messages(alice).single().security)
    }

    @Test
    fun `an inbound message takes the label the engine reported for that peer`() {
        val s = state(
            contact(alice, security = SecurityState.SMP_VERIFIED),
            contact(bob, security = SecurityState.PLAINTEXT),
        )
        s.receive(inbound(alice, "secret"))
        s.receive(inbound(bob, "not secret"))
        assertEquals(SecurityLabel.ENCRYPTED, s.messages(alice).single().security)
        assertEquals(SecurityLabel.PLAINTEXT, s.messages(bob).single().security)
    }

    @Test
    fun `a message keeps the label it had when it arrived`() {
        // A later DAKE does not retroactively encrypt what was already sent in
        // the clear.
        val s = state(contact(alice, security = SecurityState.PLAINTEXT))
        s.receive(inbound(alice, "early"))
        s.applyRoster(listOf(contact(alice, security = SecurityState.SMP_VERIFIED)))
        assertEquals(SecurityLabel.PLAINTEXT, s.messages(alice).single().security)
    }

    @Test
    fun `conversation security comes from the roster and defaults to plaintext`() {
        val s = state(contact(alice, security = SecurityState.SMP_VERIFIED))
        assertEquals(SecurityState.SMP_VERIFIED, s.conversation(alice).security)
        assertEquals(SecurityState.PLAINTEXT, s.conversation("nobody@x.i2p").security)
    }

    @Test
    fun `sending is refused while the transport says it is not connected`() {
        val s = state(contact(alice))
        assertTrue(s.canSend())
        s.applyConnection(ConnectionStatus(stage = "disconnected", connected = false))
        assertFalse(s.canSend())
    }

    // ── duplicates ──────────────────────────────────────────────────────────

    @Test
    fun `a replayed inbound event is stored once`() {
        val s = state(contact(alice))
        val event = inbound(alice, "hello")
        assertTrue(s.receive(event))
        assertFalse(s.receive(event))
        assertEquals(1, s.messages(alice).size)
    }

    @Test
    fun `a replayed event does not raise the unread count again`() {
        val s = state(contact(alice))
        val event = inbound(alice, "hello")
        s.receive(event)
        s.receive(event)
        assertEquals(1, s.conversation(alice).unread)
    }

    @Test
    fun `the same words sent twice by the peer are both kept`() {
        // Two genuine messages with the same body at different times.
        val s = state(contact(alice))
        assertTrue(s.receive(inbound(alice, "ok", at = 1_700.0)))
        assertTrue(s.receive(inbound(alice, "ok", at = 1_701.0)))
        assertEquals(2, s.messages(alice).size)
    }

    @Test
    fun `an event with no timestamp is stamped locally`() {
        val s = state(contact(alice))
        s.receive(inbound(alice, "hello", at = 0.0))
        assertEquals(FIXED_NOW, s.messages(alice).single().at)
    }

    @Test
    fun `a server timestamp is converted from seconds to milliseconds`() {
        val s = state(contact(alice))
        s.receive(inbound(alice, "hello", at = 1_700.5))
        assertEquals(1_700_500L, s.messages(alice).single().at)
    }

    // ── the conversation list ───────────────────────────────────────────────

    @Test
    fun `a roster contact with no history still gets a row`() {
        val s = state(contact(alice))
        assertEquals(listOf(alice), s.conversations().map { it.jid })
    }

    @Test
    fun `the most recent conversation is first`() {
        val s = state(contact(alice), contact(bob))
        s.receive(inbound(alice, "older", at = 1_000.0))
        s.receive(inbound(bob, "newer", at = 2_000.0))
        assertEquals(listOf(bob, alice), s.conversations().map { it.jid })
    }

    @Test
    fun `conversations with no history sort by name`() {
        val s = state(contact(bob, displayName = "Bob"),
                      contact(alice, displayName = "Alice"))
        assertEquals(listOf("Alice", "Bob"), s.conversations().map { it.displayName })
    }

    @Test
    fun `a conversation is listed once even when it is both roster and history`() {
        val s = state(contact(alice))
        s.receive(inbound(alice, "hello"))
        assertEquals(1, s.conversations().count { it.jid == alice })
    }

    // ── "we cannot read the bridge" is not "the stream is down" ─────────────
    //
    // The handset bug: one failing read discarded the connection status with
    // everything else, and the screen announced a disconnection it had never
    // observed. These pin the distinction.

    @Test
    fun `before anything is read the link is unknown, not disconnected`() {
        val s = ChatState()
        assertEquals(ChatState.Link.UNKNOWN, s.link)
        assertFalse(s.canSend())
    }

    @Test
    fun `a successful status read makes the link ok`() {
        val s = state(contact(alice))
        assertEquals(ChatState.Link.OK, s.link)
        assertTrue(s.canSend())
    }

    @Test
    fun `a failed status read does not overwrite the last known status`() {
        // Overwriting it would be inventing the answer we just failed to get,
        // and the direction it invents is the one that stops the user sending.
        val s = state(contact(alice))
        s.noteLinkFailure("status:PyException")
        assertEquals(ChatState.Link.FAILING, s.link)
        assertTrue(s.connection.connected, "the last known status was discarded")
    }

    @Test
    fun `a failing link refuses to send even though the last status said connected`() {
        val s = state(contact(alice))
        s.noteLinkFailure("status:PyException")
        assertFalse(s.canSend(), "sending on a connection state we cannot read")
    }

    @Test
    fun `a failing link makes presence unknown rather than stale`() {
        val s = state(contact(alice, online = true))
        assertEquals(Presence.ONLINE, s.conversation(alice).presence)
        s.noteLinkFailure("contacts:PyException")
        assertEquals(Presence.UNKNOWN, s.conversation(alice).presence)
    }

    @Test
    fun `recovering a read clears the failure`() {
        val s = state(contact(alice))
        s.noteLinkFailure("status:PyException")
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        assertEquals(ChatState.Link.OK, s.link)
        assertNull(s.linkFailure)
        assertTrue(s.canSend())
    }

    @Test
    fun `the failing read is remembered as a code for diagnosis`() {
        val s = state(contact(alice))
        s.noteReadFailure("contacts:PyException")
        assertEquals("contacts:PyException", s.readFailure)
        s.noteReadFailure(null)
        assertNull(s.readFailure)
    }

    @Test
    fun `a roster read that failed does not by itself claim a disconnection`() {
        // contacts() can fail while the stream is perfectly healthy -- that is
        // exactly what happened on the handset.
        val s = state(contact(alice))
        s.noteReadFailure("contacts:PyException")
        assertEquals(ChatState.Link.OK, s.link)
        assertTrue(s.canSend())
    }

    @Test
    fun `sending is refused while disconnected and the draft is kept`() {
        // The composer's button is disabled, but the keyboard's Send action is
        // a second route in and was not gated. Losing the typed text as well
        // would be the insult after the injury.
        val s = state(contact(alice))
        s.setDraft(alice, "hello")
        s.applyConnection(ConnectionStatus(stage = "disconnected", connected = false))
        assertNull(s.beginSend(alice))
        assertEquals("hello", s.draft(alice))
        assertTrue(s.messages(alice).isEmpty())
    }

    @Test
    fun `sending is refused while the link cannot be read`() {
        val s = state(contact(alice))
        s.setDraft(alice, "hello")
        s.noteLinkFailure("status:PyException")
        assertNull(s.beginSend(alice))
        assertEquals("hello", s.draft(alice))
    }

    // ── the answer to adding a contact ──────────────────────────────────────

    @Test
    fun `a notice is held until it is dismissed`() {
        val s = state()
        assertNull(s.notice)
        s.note("Connect before changing the contact list.")
        assertEquals("Connect before changing the contact list.", s.notice)
        s.dismissNotice()
        assertNull(s.notice)
    }

    @Test
    fun `a roster refusal carries a sentence, not just a code`() {
        assertEquals(
            "Connect before changing the contact list.",
            RosterResult(false, "not_connected", "").message(),
        )
    }

    @Test
    fun `a roster success says nothing`() {
        assertNull(RosterResult(true, "ok", "").message())
    }

    @Test
    fun `the controller's own detail is preferred when it wrote one`() {
        assertEquals(
            "Server said no.",
            RosterResult(false, "roster_failed", "Server said no.").message(),
        )
    }

    // ── alerts and misc ─────────────────────────────────────────────────────

    @Test
    fun `a fingerprint change is raised as a blocking alert`() {
        val s = state(contact(alice))
        assertNull(s.fingerprintAlert)
        s.handle(
            OtrEvent.FingerprintChanged(
                peer = alice, storedFingerprint = "AAAA", receivedFingerprint = "BBBB",
            )
        )
        assertEquals(alice, s.fingerprintAlert?.peer)
        s.dismissFingerprintAlert()
        assertNull(s.fingerprintAlert)
    }

    // `openConversation` outlives the UI now, because the service owns this
    // object. So "is it open" stopped being the same question as "is the user
    // looking at it", and the unread badge depends on the difference.

    @Test
    fun `a message to the open conversation is read only if the user is there`() {
        val s = state(contact(alice))
        s.setUiVisible(true)
        s.open(alice)
        s.handle(inbound(alice, "hello"))
        assertEquals(0, s.conversation(alice).unread)
    }

    @Test
    fun `a message arriving while the app is away stays unread`() {
        val s = state(contact(alice))
        s.setUiVisible(true)
        s.open(alice)
        s.setUiVisible(false)                 // pocket
        s.handle(inbound(alice, "hello"))
        assertEquals(1, s.conversation(alice).unread,
            "the badge was cleared before the user had a chance to look, so " +
            "nothing afterwards says the message was there")
    }

    @Test
    fun `coming back reads what landed in the conversation left open`() {
        val s = state(contact(alice))
        s.setUiVisible(true)
        s.open(alice)
        s.setUiVisible(false)
        s.handle(inbound(alice, "hello"))
        s.setUiVisible(true)                  // still on that screen
        assertEquals(0, s.conversation(alice).unread,
            "the badge sat there while the user read the messages it counted")
    }

    @Test
    fun `coming back does not read a conversation that is not open`() {
        val s = state(contact(alice), contact(bob))
        s.setUiVisible(true)
        s.open(alice)
        s.setUiVisible(false)
        s.handle(inbound(bob, "hello"))
        s.setUiVisible(true)
        assertEquals(1, s.conversation(bob).unread)
    }

    @Test
    fun `coming back to the list reads nothing`() {
        val s = state(contact(alice))
        s.setUiVisible(true)
        s.open(alice)
        s.closeConversation()
        s.setUiVisible(false)
        s.handle(inbound(alice, "hello"))
        s.setUiVisible(true)
        assertEquals(1, s.conversation(alice).unread)
    }

    @Test
    fun `opening a conversation counts as looking at it`() {
        // The service's visibility signal can lag the Activity's onStart by a
        // frame; a badge on the screen you are reading is its own small bug.
        val s = state(contact(alice))
        s.handle(inbound(alice, "hello"))
        s.open(alice)
        assertEquals(0, s.conversation(alice).unread)
        assertTrue(s.uiVisible)
    }

    @Test
    fun `nothing is visible until something says so`() {
        assertFalse(state().uiVisible)
    }

    // What `handle` RETURNS is what decides whether the phone buzzes. It is
    // not a detail of the return type: a `true` for a duplicate lets a peer
    // who resends the same message ring the phone as often as they like.

    @Test
    fun `handle reports that a new message arrived`() {
        val s = state(contact(alice))
        assertTrue(s.handle(inbound(alice, "hello")))
    }

    @Test
    fun `handle reports nothing for a message it already had`() {
        val s = state(contact(alice))
        s.handle(inbound(alice, "hello"))
        assertFalse(s.handle(inbound(alice, "hello")),
            "a resend would notify again, so a peer could buzz the phone at will")
    }

    @Test
    fun `handle reports nothing for an event that is not a message`() {
        val s = state(contact(alice))
        assertFalse(
            s.handle(
                OtrEvent.FingerprintChanged(
                    peer = alice, storedFingerprint = "AAAA", receivedFingerprint = "BBBB",
                )
            ),
            "a non-message event asked for a new-message notification",
        )
        assertFalse(s.handle(OtrEvent.SessionChanged(alice, SecurityState.ENCRYPTED)))
    }

    @Test
    fun `dropped events are reported`() {
        val s = state()
        s.applyDropped(7)
        assertEquals(7, s.droppedEvents)
    }

    @Test
    fun `an address without an at sign is not a contact`() {
        val s = state()
        assertFalse(s.validContact("alice"))
        assertFalse(s.validContact("   "))
        assertFalse(s.validContact("alice@"))
        assertFalse(s.validContact("@server.i2p"))
        assertTrue(s.validContact(alice))
        assertTrue(s.validContact("  $alice/phone  "))
    }

    @Test
    fun `bare strips the resource and leaves a bare jid alone`() {
        assertEquals(alice, ChatState.bare("$alice/phone"))
        assertEquals(alice, ChatState.bare(alice))
    }

    private companion object {
        const val FIXED_NOW = 1_600_000_000_000L
    }
}
