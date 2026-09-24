// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpProgress
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * ONE CONTACT, ONE KEY -- driven, not asserted about the source.
 *
 * XMPP says the localpart and domain are case-insensitive and the resource is
 * not part of an identity, so `Bob@Example.TEST/phone` and `bob@example.test`
 * are the same person. Three things here used to disagree about that:
 *
 *   * [ChatState.bare] split the resource off and left the CASE alone, so a
 *     JID the user typed and the same JID echoed by the server (slixmpp
 *     normalises) were two different keys;
 *   * [ChatState.applyRoster] keyed `contacts` on the RAW roster JID while
 *     the message store was keyed on the bared one;
 *   * [ChatState.conversations] unions those two with the saved list, which
 *     is where a disagreement between them becomes two rows for one person,
 *     each holding half the history.
 *
 * The consequence on the Python side was worse and is covered by
 * `tests/test_jid_canonicalisation.py`: a conversation that had asked for OTR
 * reported that plaintext was allowed under a different spelling of the same
 * JID. This file covers the half that decides what the user SEES.
 *
 * Folding is the safe direction. It can only merge two keys into one; it can
 * never split one into two, and it can never map two different people
 * together, because it only changes case and drops a resource.
 */
class JidCanonicalisationTest {

    private val bob = "bob@xmpp-elite.i2p"

    private fun state(): ChatState {
        val s = ChatState()
        s.now = { 1_600_000_000_000L }
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        return s
    }

    private fun contact(
        jid: String,
        displayName: String = jid,
        security: SecurityState = SecurityState.PLAINTEXT,
        smp: SmpState = SmpState.NOT_VERIFIED,
    ) = Contact(
        jid = jid, displayName = displayName, presence = PeerPresence.ONLINE,
        security = security, smp = smp, callAvailable = false,
        subscription = Subscription.BOTH,
    )

    // ── bare() itself ───────────────────────────────────────────────────────

    @Test
    fun `bare folds case as well as dropping the resource`() {
        assertEquals(bob, ChatState.bare("Bob@XMPP-Elite.i2p"))
        assertEquals(bob, ChatState.bare("BOB@XMPP-ELITE.I2P/Phone"))
        assertEquals(bob, ChatState.bare("  bob@xmpp-elite.i2p/laptop  "))
    }

    @Test
    fun `bare is idempotent`() {
        assertEquals(ChatState.bare(bob), ChatState.bare(ChatState.bare(bob)))
    }

    @Test
    fun `bare never merges two different people`() {
        assertTrue(ChatState.bare("bob@a.i2p") != ChatState.bare("bob@b.i2p"))
        assertTrue(ChatState.bare("bob@a.i2p") != ChatState.bare("rob@a.i2p"))
    }

    // ── one row, not two ────────────────────────────────────────────────────

    @Test
    fun `a roster entry and its own history are one conversation`() {
        // The server's spelling differs from the one the message arrived
        // under. Before the fix these were separate keys and the list showed
        // the same person twice, one row with the history and one without.
        val s = state()
        s.receive(OtrEvent.MessageReceived(peer = bob, body = "hi", timestamp = 1_700.0))
        s.applyRoster(listOf(contact("Bob@XMPP-Elite.i2p")))

        val rows = s.conversations().filter { ChatState.bare(it.jid) == bob }
        assertEquals(1, rows.size, "one person is showing as two conversations")
        assertEquals("hi", rows.single().lastMessage?.body,
            "the row that survived is the one WITHOUT the history")
    }

    @Test
    fun `a message from a resource lands in the bare conversation`() {
        val s = state()
        s.applyRoster(listOf(contact(bob)))
        s.receive(OtrEvent.MessageReceived(
            peer = "$bob/phone", body = "from my phone", timestamp = 1_700.0))
        s.receive(OtrEvent.MessageReceived(
            peer = "$bob/laptop", body = "and my laptop", timestamp = 1_701.0))

        assertEquals(listOf("from my phone", "and my laptop"),
            s.messages(bob).map { it.body },
            "one conversation forked per resource")
        assertEquals(1, s.conversations().count { ChatState.bare(it.jid) == bob })
    }

    @Test
    fun `the roster row keeps its display name under the folded key`() {
        val s = state()
        s.applyRoster(listOf(contact("Bob@XMPP-Elite.i2p", displayName = "Bob")))
        val row = s.conversations().single { ChatState.bare(it.jid) == bob }
        assertEquals("Bob", row.displayName,
            "folding the key lost the roster entry it belongs to")
        assertTrue(row.saved, "the row no longer reads as server-confirmed")
    }

    // ── what it means for security ──────────────────────────────────────────

    @Test
    fun `an inbound message is labelled with the security of that peer`() {
        // `receive` looks the contact up by the BARED jid. With `contacts`
        // keyed raw the lookup missed and every message from an encrypted
        // session was stored labelled as if it had arrived in the clear.
        val s = state()
        s.applyRoster(listOf(
            contact("Bob@XMPP-Elite.i2p", security = SecurityState.ENCRYPTED)))
        s.receive(OtrEvent.MessageReceived(peer = bob, body = "hi", timestamp = 1_700.0))

        val stored = s.messages(bob).single()
        assertTrue(stored.security != SecurityLabel.PLAINTEXT,
            "an encrypted message was recorded as plaintext because the " +
            "contact lookup missed on a spelling")
    }

    @Test
    fun `a verification event reaches the row it belongs to`() {
        val s = state()
        s.applyRoster(listOf(contact(bob)))
        s.handle(OtrEvent.SmpProgressed(
            peer = "Bob@XMPP-Elite.i2p/phone",
            progress = SmpProgress(
                step = 1, total = 4, state = SmpState.SECRET_REQUIRED)))

        val row = s.conversations().single { ChatState.bare(it.jid) == bob }
        assertEquals(SmpState.SECRET_REQUIRED, row.smp,
            "an incoming verification request was filed under a key the " +
            "screen never reads, so the prompt never appeared")
    }

    @Test
    fun `a failed verification is not hidden by a stale roster poll`() {
        // The fail-closed direction, and the reason the event is preferred
        // over `contact.smp`: if the event key missed, the row would go on
        // showing the better state from the last poll.
        val s = state()
        s.applyRoster(listOf(contact(bob, smp = SmpState.VERIFIED)))
        s.handle(OtrEvent.SmpFinished(
            peer = "BOB@XMPP-ELITE.I2P", state = SmpState.FAILED))

        val row = s.conversations().single { ChatState.bare(it.jid) == bob }
        assertEquals(SmpState.FAILED, row.smp,
            "a verification that FAILED is still being shown as verified")
    }

    @Test
    fun `verification state is still dropped with the account`() {
        // The fold must not outlive the boundary it sits inside.
        val s = state()
        s.applyRoster(listOf(contact(bob)))
        s.handle(OtrEvent.SmpFinished(peer = bob, state = SmpState.VERIFIED))
        s.bindAccount(AccountScope.of("dave@xmpp-elite.i2p"))
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        s.applyRoster(listOf(contact(bob)))

        val row = s.conversations().single { ChatState.bare(it.jid) == bob }
        assertEquals(SmpState.NOT_VERIFIED, row.smp,
            "one account's identity check is being shown as another's")
    }

    // ── the roster stays authoritative ──────────────────────────────────────

    @Test
    fun `an entry that leaves the roster still leaves it when folded`() {
        // A message so the row survives the roster and there is something to
        // assert about -- otherwise `none { it.saved }` passes on an empty
        // list and proves nothing.
        val s = state()
        s.receive(OtrEvent.MessageReceived(peer = bob, body = "hi", timestamp = 1_700.0))
        s.applyRoster(listOf(contact("Bob@XMPP-Elite.i2p")))
        assertTrue(s.conversations().single { ChatState.bare(it.jid) == bob }.saved)

        s.applyRoster(emptyList())
        val row = s.conversations().single { ChatState.bare(it.jid) == bob }
        assertEquals(false, row.saved,
            "a folded key survived the roster it came from, so somebody who " +
            "unsubscribed still reads as a confirmed contact")
        assertNotNull(row.lastMessage, "the history went with the roster entry")
    }
}
