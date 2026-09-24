// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What actually reaches the core when a protocol is chosen.
 *
 * NOT "does the selector render". These drive the whole chain with a provider
 * that RECORDS what it was asked to establish, so the assertions are about the
 * value that arrived at the engine rather than about what a screen displayed.
 *
 * THE TRACE THAT PROMPTED THEM. Before [EncryptionLauncher] nothing outside
 * `crypto/` imported the package at all, and `ChatViewModel.startSession` had
 * no UI caller — so on Android no conversation could ever ask for OTR, and
 * `OtrApp.send_user_text` correctly kept sending plaintext to "a conversation
 * where nobody has asked". The screen said so truthfully and offered no remedy.
 */
class EncryptionLauncherTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"
    private val room = "general@rooms.xmpp-elite.i2p"

    private fun direct() =
        ConversationRef(account = alice, target = bob, isGroup = false)

    private fun group() =
        ConversationRef(account = alice, target = room, isGroup = true)

    /** Records every establish() it is given. That record is the assertion. */
    private class Recording(
        override val kind: EncryptionKind,
        private val available: Availability,
    ) : EncryptionProvider {
        val established = mutableListOf<ConversationRef>()

        override fun availability(conversation: ConversationRef) =
            if (!conversation.isValid) Availability.NOT_APPLICABLE
            else if (!kind.suits(conversation)) Availability.NOT_APPLICABLE
            else available

        override fun state(conversation: ConversationRef) =
            EncryptionState.INACTIVE

        override suspend fun establish(conversation: ConversationRef):
            EncryptionOutcome {
            established.add(conversation)
            return EncryptionOutcome.established(EncryptionState.ACTIVE)
        }

        override suspend fun encrypt(
            conversation: ConversationRef,
            body: String,
        ) = EncryptionOutcome.encrypted("ct", EncryptionState.ACTIVE)

        override suspend fun decrypt(
            conversation: ConversationRef,
            payload: String,
        ) = DecryptionOutcome.decrypted("pt")

        override fun forgetAccount() {}
    }

    /** The shipped shape: OTRv4+ usable, OMEMO and MLS not implemented. */
    private fun shipped(): Pair<EncryptionLauncher, Map<EncryptionKind, Recording>> {
        val otr = Recording(EncryptionKind.OTRV4_PLUS, Availability.AVAILABLE)
        val omemo = Recording(EncryptionKind.OMEMO_2, Availability.NOT_IMPLEMENTED)
        val mls = Recording(EncryptionKind.MLS, Availability.NOT_IMPLEMENTED)
        return EncryptionLauncher(listOf(otr, omemo, mls)) to
            mapOf(EncryptionKind.OTRV4_PLUS to otr,
                  EncryptionKind.OMEMO_2 to omemo,
                  EncryptionKind.MLS to mls)
    }

    // ── what the shipped build actually offers ───────────────────────────────

    @Test
    fun `a one to one conversation is offered exactly OTRv4 plus`() {
        val (launcher, _) = shipped()
        assertEquals(listOf(EncryptionKind.OTRV4_PLUS), launcher.offered(direct()))
    }

    @Test
    fun `a room is offered nothing in this build`() {
        // OTR is two-party, OMEMO is not implemented, MLS is not implemented.
        // The honest UI for this is a sentence, not an empty dropdown.
        val (launcher, _) = shipped()
        assertTrue(launcher.offered(group()).isEmpty())
        assertTrue(launcher.unavailableReason(group()).isNotEmpty())
    }

    @Test
    fun `there is currently no choice to make in a one to one`() {
        // Recorded as a fact rather than a limitation to hide. A picker
        // implying a decision the build cannot honour would be worse than a
        // single control that says what it will do.
        val (launcher, _) = shipped()
        assertEquals(1, launcher.offered(direct()).size)
    }

    // ── the value that reaches the core ──────────────────────────────────────

    @Test
    fun `starting the default reaches the OTR provider with this conversation`() {
        val (launcher, rec) = shipped()
        val outcome = runBlocking { launcher.startDefault(direct()) }
        assertTrue(outcome.ok)
        assertEquals(listOf(direct()),
                     rec[EncryptionKind.OTRV4_PLUS]!!.established)
    }

    @Test
    fun `the conversation that arrives is the one that was asked for`() {
        // Not merely "something was established" -- the account and target
        // that reached the provider are the ones from the screen.
        val (launcher, rec) = shipped()
        runBlocking { launcher.startDefault(direct()) }
        val got = rec[EncryptionKind.OTRV4_PLUS]!!.established.single()
        assertEquals(alice, got.account)
        assertEquals(bob, got.target)
        assertFalse(got.isGroup)
    }

    @Test
    fun `nothing reaches a provider the selector did not offer`() {
        val (launcher, rec) = shipped()
        runBlocking { launcher.startDefault(direct()) }
        assertTrue(rec[EncryptionKind.OMEMO_2]!!.established.isEmpty())
        assertTrue(rec[EncryptionKind.MLS]!!.established.isEmpty())
    }

    // ── the guard: an unoffered kind cannot be started ───────────────────────

    @Test
    fun `asking for an unimplemented protocol is refused, not attempted`() {
        val (launcher, rec) = shipped()
        val outcome = runBlocking {
            launcher.start(direct(), EncryptionKind.OMEMO_2)
        }
        assertFalse(outcome.ok)
        assertEquals(EncryptionError.UNAVAILABLE, outcome.error)
        assertTrue(rec[EncryptionKind.OMEMO_2]!!.established.isEmpty(),
                   "an unimplemented provider was asked to establish")
    }

    @Test
    fun `OTR cannot be started in a room`() {
        // THE RULE THAT MATTERS MOST. OTR in a MUC is not weaker, it is
        // meaningless: the service fans the message out to everybody present.
        // A stale screen must not be able to start one.
        val (launcher, rec) = shipped()
        val outcome = runBlocking {
            launcher.start(group(), EncryptionKind.OTRV4_PLUS)
        }
        assertFalse(outcome.ok)
        assertTrue(rec[EncryptionKind.OTRV4_PLUS]!!.established.isEmpty(),
                   "a two-party protocol was started for a room")
    }

    @Test
    fun `the offer is re-derived rather than trusted from the caller`() {
        // A screen is a cache of a decision taken earlier. If availability
        // changes underneath it, the tap that arrives afterwards must be
        // judged by the current answer, not the rendered one.
        val otr = Recording(EncryptionKind.OTRV4_PLUS,
                            Availability.UNSUPPORTED_HERE)
        val launcher = EncryptionLauncher(listOf(otr))
        val outcome = runBlocking {
            launcher.start(direct(), EncryptionKind.OTRV4_PLUS)
        }
        assertFalse(outcome.ok)
        assertTrue(otr.established.isEmpty())
    }

    @Test
    fun `plaintext is not something that can be established`() {
        val (launcher, _) = shipped()
        val outcome = runBlocking {
            launcher.start(direct(), EncryptionKind.NONE)
        }
        assertFalse(outcome.ok)
        assertEquals(EncryptionError.UNAVAILABLE, outcome.error)
    }

    @Test
    fun `a kind with no provider registered is refused`() {
        val launcher = EncryptionLauncher(emptyList())
        assertEquals(Availability.NOT_IMPLEMENTED,
                     launcher.availability(EncryptionKind.OTRV4_PLUS, direct()))
        val outcome = runBlocking {
            launcher.start(direct(), EncryptionKind.OTRV4_PLUS)
        }
        assertFalse(outcome.ok)
    }

    // ── refusing says why ────────────────────────────────────────────────────

    @Test
    fun `a refusal in a room carries the room sentence`() {
        val (launcher, _) = shipped()
        val outcome = runBlocking { launcher.startDefault(group()) }
        assertFalse(outcome.ok)
        assertEquals(EncryptionSelector.unavailableReason(group()),
                     outcome.detail)
    }

    @Test
    fun `startDefault refuses rather than doing nothing`() {
        // A control that silently does nothing is exactly what this trace
        // found: startSession existed and no screen called it.
        val (launcher, _) = shipped()
        val outcome = runBlocking { launcher.startDefault(group()) }
        assertFalse(outcome.ok)
        assertTrue(outcome.detail.isNotEmpty())
    }

    @Test
    fun `an invalid conversation is offered nothing`() {
        val (launcher, rec) = shipped()
        val bad = ConversationRef(account = "", target = "", isGroup = false)
        assertTrue(launcher.offered(bad).isEmpty())
        val outcome = runBlocking { launcher.startDefault(bad) }
        assertFalse(outcome.ok)
        assertTrue(rec[EncryptionKind.OTRV4_PLUS]!!.established.isEmpty())
    }
}
