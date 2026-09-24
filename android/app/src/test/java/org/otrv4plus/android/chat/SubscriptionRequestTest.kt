// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SubscriptionPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Somebody asking to see this account's presence.
 *
 * THE DEFECT THESE COVER. `answer_subscription` existed in the transport and
 * in the controller and had NO KOTLIN CALLER, and the controller's
 * subscription handler was a log line that deliberately queued nothing. So the
 * `ASK` policy could be set and then never answered: the asker waited forever,
 * and the user was never shown the question. Under the shipped `ACCEPT` policy
 * presence was granted to anyone who asked with no way to find out it had
 * happened.
 *
 * Presence is metadata. Approving tells that account when this device is
 * online, from which resource, and how idle it is, for as long as they keep it.
 */
class SubscriptionRequestTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"
    private val mallory = "mallory@elsewhere.i2p"

    private fun signedIn(jid: String = alice): ChatState {
        val s = ChatState()
        s.bindAccount(AccountScope.of(jid))
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        return s
    }

    private fun ask(jid: String) =
        OtrEvent.SubscriptionRequested(jid, SubscriptionPolicy.ASK)

    private fun accepted(jid: String) =
        OtrEvent.SubscriptionRequested(jid, SubscriptionPolicy.ACCEPT)

    // ── it arrives at all ────────────────────────────────────────────────────

    @Test
    fun `a request reaches the pending list`() {
        val s = signedIn()
        assertTrue(s.handle(ask(bob)) == false, "it must not buzz the phone")
        assertEquals(listOf(bob), s.pendingSubscriptions.map { it.peer })
    }

    @Test
    fun `a request is not a new message`() {
        // `handle` returns whether something arrived that deserves a
        // notification. A subscription request is worth a banner when the user
        // next looks, not an interruption.
        assertFalse(signedIn().handle(ask(bob)))
    }

    @Test
    fun `two different people both get asked about`() {
        val s = signedIn()
        s.handle(ask(bob))
        s.handle(ask(mallory))
        assertEquals(listOf(bob, mallory), s.pendingSubscriptions.map { it.peer })
    }

    @Test
    fun `the same person asking twice does not stack up`() {
        // `subscribe` presence is retransmitted by servers and resent by
        // clients. Without deduping, one persistent asker becomes a column of
        // identical banners to clear one at a time.
        val s = signedIn()
        s.handle(ask(bob))
        s.handle(ask(bob))
        s.handle(ask(bob))
        assertEquals(1, s.pendingSubscriptions.size)
    }

    @Test
    fun `a resource does not make it a different person`() {
        val s = signedIn()
        s.handle(ask("$bob/phone"))
        s.handle(ask("$bob/laptop"))
        assertEquals(1, s.pendingSubscriptions.size)
    }

    // ── answering it ─────────────────────────────────────────────────────────

    @Test
    fun `answering removes it`() {
        val s = signedIn()
        s.handle(ask(bob))
        s.clearSubscription(bob)
        assertTrue(s.pendingSubscriptions.isEmpty())
    }

    @Test
    fun `answering one leaves the other`() {
        val s = signedIn()
        s.handle(ask(bob))
        s.handle(ask(mallory))
        s.clearSubscription(bob)
        assertEquals(listOf(mallory), s.pendingSubscriptions.map { it.peer })
    }

    @Test
    fun `answering by full jid clears the bare entry`() {
        val s = signedIn()
        s.handle(ask(bob))
        s.clearSubscription("$bob/phone")
        assertTrue(s.pendingSubscriptions.isEmpty())
    }

    @Test
    fun `clearing somebody who never asked does nothing`() {
        val s = signedIn()
        s.handle(ask(bob))
        s.clearSubscription(mallory)
        assertEquals(1, s.pendingSubscriptions.size)
    }

    @Test
    fun `the same person can ask again after being answered`() {
        // The remedy for an answer that failed to leave the device is the
        // banner coming back, not one that never goes away.
        val s = signedIn()
        s.handle(ask(bob))
        s.clearSubscription(bob)
        s.handle(ask(bob))
        assertEquals(1, s.pendingSubscriptions.size)
    }

    // ── the policy decides what may be said ──────────────────────────────────

    @Test
    fun `under ask the user still has a decision`() {
        assertTrue(ask(bob).isQuestion)
    }

    @Test
    fun `under accept the decision was already made`() {
        // slixmpp answered before the event was raised. A prompt offering to
        // decline would be offering to undo something already done.
        assertFalse(accepted(bob).isQuestion)
    }

    @Test
    fun `an unrecognised policy is not treated as a question`() {
        assertFalse(
            OtrEvent.SubscriptionRequested(bob, SubscriptionPolicy.UNKNOWN)
                .isQuestion)
    }

    @Test
    fun `reject is not a question either`() {
        assertFalse(
            OtrEvent.SubscriptionRequested(bob, SubscriptionPolicy.REJECT)
                .isQuestion)
    }

    @Test
    fun `the policy survives the trip from python`() {
        assertEquals(SubscriptionPolicy.ACCEPT, SubscriptionPolicy.of("accept"))
        assertEquals(SubscriptionPolicy.ACCEPT_ONE_WAY,
                     SubscriptionPolicy.of("accept_one_way"))
        assertEquals(SubscriptionPolicy.ASK, SubscriptionPolicy.of("ask"))
        assertEquals(SubscriptionPolicy.REJECT, SubscriptionPolicy.of("reject"))
    }

    @Test
    fun `an unknown policy string does not become accept`() {
        // Python falls back to ACCEPT for a string it does not recognise. A
        // Kotlin enum doing the same would render "they can now see you" for a
        // state it had not understood -- a confident sentence about a privacy
        // grant, derived from a parse failure.
        assertEquals(SubscriptionPolicy.UNKNOWN, SubscriptionPolicy.of("banana"))
        assertEquals(SubscriptionPolicy.UNKNOWN, SubscriptionPolicy.of(""))
    }

    @Test
    fun `only ask defers to the user`() {
        assertTrue(SubscriptionPolicy.ASK.defersToUser)
        for (other in listOf(SubscriptionPolicy.ACCEPT,
                             SubscriptionPolicy.ACCEPT_ONE_WAY,
                             SubscriptionPolicy.REJECT,
                             SubscriptionPolicy.UNKNOWN)) {
            assertFalse(other.defersToUser, other.name)
        }
    }

    // ── it belongs to one account ────────────────────────────────────────────

    @Test
    fun `nothing is recorded before an account is established`() {
        // The window between the process starting and an identity being
        // established. A request arriving then belongs to no account.
        val s = ChatState()
        assertFalse(s.handle(ask(bob)))
        assertTrue(s.pendingSubscriptions.isEmpty())
    }

    @Test
    fun `signing in as somebody else drops the pending requests`() {
        // THE ACCOUNT-ISOLATION RULE. Who asked to watch alice is not bob's
        // business, and a banner left behind would name a stranger to the new
        // account and offer to grant them bob's presence.
        val s = signedIn(alice)
        s.handle(ask(mallory))
        assertEquals(1, s.pendingSubscriptions.size)

        s.bindAccount(AccountScope.of(bob))
        assertTrue(s.pendingSubscriptions.isEmpty(),
                   "a request for alice survived a sign-in as bob")
    }

    @Test
    fun `signing out drops them too`() {
        val s = signedIn(alice)
        s.handle(ask(mallory))
        s.bindAccount(AccountScope.NONE)
        assertTrue(s.pendingSubscriptions.isEmpty())
    }

    @Test
    fun `reconnecting as the same account keeps them`() {
        // Binding to the same account is a no-op, so a reconnect does not
        // throw away a question the user has not answered yet.
        val s = signedIn(alice)
        s.handle(ask(mallory))
        s.bindAccount(AccountScope.of(alice))
        assertEquals(1, s.pendingSubscriptions.size)
    }

    // ── it does not leak ─────────────────────────────────────────────────────

    @Test
    fun `an empty jid is refused`() {
        val s = signedIn()
        assertFalse(s.handle(ask("")))
        assertTrue(s.pendingSubscriptions.isEmpty())
    }

    @Test
    fun `the pending list is a copy`() {
        // This state is owned by the service and read from the UI thread;
        // handing out the live list would let a screen mutate it.
        val s = signedIn()
        s.handle(ask(bob))
        val first = s.pendingSubscriptions
        s.handle(ask(mallory))
        assertEquals(1, first.size, "the returned list changed underneath")
        assertEquals(2, s.pendingSubscriptions.size)
    }
}
