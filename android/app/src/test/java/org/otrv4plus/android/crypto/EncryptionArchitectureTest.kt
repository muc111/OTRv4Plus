// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Three protocols behind one interface, and the rules that keep them apart.
 *
 * The two failures this file exists to prevent are both silent ones:
 *
 * **Offering a protocol that cannot work here.** OTRv4+ in a room, MLS in a
 * 1:1, OMEMO with no backend. Every one of them produces a menu entry that
 * fails minutes after it is chosen — over I2P, long enough for the user to
 * have moved on and concluded the app is unreliable.
 *
 * **Falling back to plaintext.** An app that quietly sends in the clear when
 * the ratchet fails has told its user something untrue about every message
 * before it.
 */
class EncryptionArchitectureTest {

    private val direct = ConversationRef(
        account = "alice@xmpp-elite.i2p",
        target = "bob@xmpp-elite.i2p",
        isGroup = false)

    private val group = ConversationRef(
        account = "alice@xmpp-elite.i2p",
        target = "general@rooms.xmpp-elite.i2p",
        isGroup = true)

    private fun all(kind: EncryptionKind) = Availability.AVAILABLE
    private fun none(kind: EncryptionKind) = Availability.NOT_IMPLEMENTED

    // ── shape decides what is even applicable ───────────────────────────────

    @Test
    fun `OTRv4+ is for one-to-one and says so`() {
        assertTrue(EncryptionKind.OTRV4_PLUS.suitsDirect)
        assertFalse(EncryptionKind.OTRV4_PLUS.suitsGroup,
            "OTR is a two-party protocol; a MUC message is fanned out by the " +
                "service, so OTR in a room is not weaker — it is meaningless")
    }

    @Test
    fun `MLS is a group protocol`() {
        assertTrue(EncryptionKind.MLS.suitsGroup)
        assertFalse(EncryptionKind.MLS.suitsDirect,
            "1:1 is already answered by OTRv4+, with SMP and a fingerprint")
    }

    @Test
    fun `OMEMO serves both`() {
        assertTrue(EncryptionKind.OMEMO_2.suitsDirect)
        assertTrue(EncryptionKind.OMEMO_2.suitsGroup)
    }

    @Test
    fun `a group conversation is never offered OTRv4+`() {
        assertFalse(EncryptionSelector.offered(group, ::all)
            .contains(EncryptionKind.OTRV4_PLUS))
    }

    @Test
    fun `a direct conversation is never offered MLS`() {
        assertFalse(EncryptionSelector.offered(direct, ::all)
            .contains(EncryptionKind.MLS))
    }

    // ── what is offered, and in what order ──────────────────────────────────

    @Test
    fun `one-to-one defaults to OTRv4+`() {
        assertEquals(EncryptionKind.OTRV4_PLUS,
            EncryptionSelector.defaultFor(direct, ::all))
    }

    @Test
    fun `a group defaults to OMEMO`() {
        assertEquals(EncryptionKind.OMEMO_2,
            EncryptionSelector.defaultFor(group, ::all))
    }

    @Test
    fun `the default is the first thing offered`() {
        // So the list does not need a separate notion of which is default,
        // and the two cannot disagree.
        for (conversation in listOf(direct, group)) {
            assertEquals(EncryptionSelector.offered(conversation, ::all).first(),
                EncryptionSelector.defaultFor(conversation, ::all))
        }
    }

    @Test
    fun `plaintext is never offered as a protocol`() {
        for (conversation in listOf(direct, group)) {
            assertFalse(EncryptionSelector.offered(conversation, ::all)
                .contains(EncryptionKind.NONE), conversation.target)
        }
    }

    @Test
    fun `an unavailable provider is left out rather than shown disabled`() {
        // A greyed-out MLS reads as "coming soon" where the honest statement
        // is that this build cannot do it.
        assertTrue(EncryptionSelector.offered(group, ::none).isEmpty())
    }

    @Test
    fun `nothing available gives null, not plaintext`() {
        // NULL. "We could not offer you encryption" and "you chose to send in
        // the clear" are different facts, and a default of NONE turns the
        // first silently into the second.
        assertNull(EncryptionSelector.defaultFor(group, ::none))
    }

    @Test
    fun `an invalid conversation is offered nothing`() {
        val empty = ConversationRef("", "", false)
        assertTrue(EncryptionSelector.offered(empty, ::all).isEmpty())
        assertNull(EncryptionSelector.defaultFor(empty, ::all))
    }

    @Test
    fun `an unavailable reason is a sentence, not an empty menu`() {
        // An empty dropdown is indistinguishable from a broken one.
        for (conversation in listOf(direct, group)) {
            val reason = EncryptionSelector.unavailableReason(conversation)
            assertTrue(reason.isNotBlank())
            assertFalse(reason.contains("@"), "the reason names a JID")
        }
    }

    // ── no silent downgrade, anywhere ───────────────────────────────────────

    @Test
    fun `nothing may fall back to anything`() {
        for (from in EncryptionKind.entries) {
            for (to in EncryptionKind.entries) {
                assertFalse(EncryptionSelector.mayFallBack(from, to),
                    "$from was allowed to become $to")
            }
        }
    }

    @Test
    fun `a failed encryption carries no ciphertext`() {
        val outcome = EncryptionOutcome.failed(
            EncryptionError.NO_SESSION, "no session")
        assertFalse(outcome.ok)
        assertNull(outcome.ciphertext,
            "a failure produced something a caller could send")
    }

    @Test
    fun `a failed decryption carries no plaintext`() {
        // Ciphertext rendered as a body reads as a corrupted message from the
        // sender rather than a protocol problem.
        val outcome = DecryptionOutcome.failed(
            EncryptionError.UNKNOWN, "could not decrypt")
        assertFalse(outcome.ok)
        assertNull(outcome.plaintext)
    }

    @Test
    fun `retrying is only suggested where it could work`() {
        assertTrue(EncryptionOutcome.failed(
            EncryptionError.TIMEOUT, "").worthRetrying)
        assertTrue(EncryptionOutcome.failed(
            EncryptionError.NETWORK, "").worthRetrying)
        assertFalse(EncryptionOutcome.failed(
            EncryptionError.UNAVAILABLE, "").worthRetrying,
            "a protocol that is not implemented will not become implemented " +
                "by pressing send again")
        assertFalse(EncryptionOutcome.failed(
            EncryptionError.REJECTED, "").worthRetrying)
    }

    // ── OTRv4+ ──────────────────────────────────────────────────────────────

    private fun otr(security: SecurityState) =
        OtrV4PlusProvider(securityOf = { security })

    @Test
    fun `OTR is available for a direct conversation`() {
        assertEquals(Availability.AVAILABLE,
            otr(SecurityState.PLAINTEXT).availability(direct))
    }

    @Test
    fun `OTR is not applicable to a room`() {
        assertEquals(Availability.NOT_APPLICABLE,
            otr(SecurityState.PLAINTEXT).availability(group))
    }

    @Test
    fun `the security ladder is not flattened`() {
        // ENCRYPTED means the DAKE ran and nobody checked who answered.
        // SMP_VERIFIED means somebody did. If these both read as "encrypted"
        // then SMP has no product meaning at all.
        assertEquals(EncryptionState.ACTIVE,
            otr(SecurityState.ENCRYPTED).state(direct))
        assertEquals(EncryptionState.VERIFIED,
            otr(SecurityState.SMP_VERIFIED).state(direct))
    }

    @Test
    fun `a fingerprint mismatch is a failure, not an encrypted session`() {
        // It IS encrypted, and that is not the point: something is wrong and
        // the user has to see it.
        assertEquals(EncryptionState.FAILED,
            otr(SecurityState.FINGERPRINT_MISMATCH).state(direct))
    }

    @Test
    fun `plaintext is inactive`() {
        assertEquals(EncryptionState.INACTIVE,
            otr(SecurityState.PLAINTEXT).state(direct))
    }

    @Test
    fun `OTR refuses to encrypt without a session`() = runBlocking {
        val outcome = otr(SecurityState.PLAINTEXT).encrypt(direct, "hello")
        assertFalse(outcome.ok)
        assertEquals(EncryptionError.NO_SESSION, outcome.error)
    }

    @Test
    fun `OTR permits a send once the session is up`() = runBlocking {
        assertTrue(otr(SecurityState.ENCRYPTED).encrypt(direct, "hello").ok)
    }

    @Test
    fun `OTR refuses a room outright`() = runBlocking {
        val outcome = otr(SecurityState.ENCRYPTED).encrypt(group, "hello")
        assertFalse(outcome.ok)
        assertEquals(EncryptionError.UNAVAILABLE, outcome.error)
    }

    @Test
    fun `establishing asks the engine and does not block`() = runBlocking {
        var asked: String? = null
        val provider = OtrV4PlusProvider(
            securityOf = { SecurityState.PLAINTEXT },
            startSession = { asked = it })
        val outcome = provider.establish(direct)
        assertEquals("bob@xmpp-elite.i2p", asked)
        assertEquals(EncryptionState.ESTABLISHING, outcome.state)
    }

    @Test
    fun `an engine that throws while starting is reported, not propagated`() =
        runBlocking {
            val provider = OtrV4PlusProvider(
                securityOf = { SecurityState.PLAINTEXT },
                startSession = { throw RuntimeException("boom") })
            assertFalse(provider.establish(direct).ok)
        }

    // ── OMEMO ───────────────────────────────────────────────────────────────

    @Test
    fun `OMEMO with no backend says not implemented`() {
        // Named rather than hidden: "not implemented in this build" is a
        // different statement from "this room cannot do it".
        assertEquals(Availability.NOT_IMPLEMENTED,
            Omemo2Provider().availability(direct))
    }

    @Test
    fun `OMEMO with no backend is not offered anywhere`() {
        val offered = EncryptionSelector.offered(group) {
            Omemo2Provider().availability(group)
        }
        assertTrue(offered.isEmpty())
    }

    @Test
    fun `OMEMO with no backend refuses to encrypt`() = runBlocking {
        val outcome = Omemo2Provider().encrypt(direct, "hello")
        assertFalse(outcome.ok)
        assertEquals(EncryptionError.UNAVAILABLE, outcome.error)
        assertNull(outcome.ciphertext)
    }

    @Test
    fun `OMEMO with no backend refuses to decrypt rather than showing bytes`() =
        runBlocking {
            val outcome = Omemo2Provider().decrypt(direct, "<ciphertext>")
            assertFalse(outcome.ok)
            assertNull(outcome.plaintext)
        }

    @Test
    fun `a backend that is not ready is unsupported here, not unimplemented`() {
        val provider = Omemo2Provider(FakeBackend(ready = false))
        assertEquals(Availability.UNSUPPORTED_HERE,
            provider.availability(direct))
    }

    @Test
    fun `a ready backend is available`() {
        assertEquals(Availability.AVAILABLE,
            Omemo2Provider(FakeBackend(ready = true)).availability(direct))
    }

    @Test
    fun `forgetting an account reaches the backend`() {
        val backend = FakeBackend(ready = true)
        Omemo2Provider(backend).forgetAccount()
        assertTrue(backend.forgotten)
    }

    // ── MLS ─────────────────────────────────────────────────────────────────

    @Test
    fun `MLS is not implemented and says so for a group`() {
        assertEquals(Availability.NOT_IMPLEMENTED,
            MlsProvider().availability(group))
    }

    @Test
    fun `MLS is not applicable to a one-to-one, which is a different no`() {
        // A permanent design decision, not a temporary gap. A single
        // "unavailable" would blur the two.
        assertEquals(Availability.NOT_APPLICABLE,
            MlsProvider().availability(direct))
    }

    @Test
    fun `MLS never claims to encrypt`() = runBlocking {
        val provider = MlsProvider()
        assertFalse(provider.establish(group).ok)
        assertFalse(provider.encrypt(group, "hello").ok)
        assertNull(provider.encrypt(group, "hello").ciphertext)
        assertFalse(provider.decrypt(group, "x").ok)
    }

    @Test
    fun `MLS does not promise a date`() = runBlocking {
        // "Coming soon" in a security control is a claim about a roadmap made
        // to somebody deciding whether to trust a message.
        val detail = MlsProvider().encrypt(group, "hello").detail
        for (promise in listOf("soon", "shortly", "next", "will be")) {
            assertFalse(detail.lowercase().contains(promise), promise)
        }
    }

    @Test
    fun `the MLS transport seam exists and defaults to unavailable`() {
        // A real object rather than a null, so there is no nullable path to
        // get wrong when an implementation lands.
        assertFalse(MlsTransport.Unavailable.isAvailable)
    }

    @Test
    fun `the unavailable transport fails rather than pretending`() = runBlocking {
        val outcome = MlsTransport.Unavailable.send("g", byteArrayOf(1))
        assertFalse(outcome.ok)
        assertFalse(outcome.retryable)
    }

    @Test
    fun `a transport outcome carries a code and not a message from below`() {
        // A SAM error text can contain an I2P destination, and this field is
        // rendered and exported.
        val outcome = MlsTransport.TransportOutcome.failed("no_transport")
        assertFalse(outcome.code.contains(" "),
            "the code looks like a sentence, which is how a destination " +
                "ends up in a diagnostic")
    }

    // ── the providers do not reach into each other ──────────────────────────

    @Test
    fun `each provider reports only its own kind`() {
        assertEquals(EncryptionKind.OTRV4_PLUS,
            otr(SecurityState.PLAINTEXT).kind)
        assertEquals(EncryptionKind.OMEMO_2, Omemo2Provider().kind)
        assertEquals(EncryptionKind.MLS, MlsProvider().kind)
    }

    @Test
    fun `forgetting one provider's account does not touch another's`() {
        val omemo = FakeBackend(ready = true)
        Omemo2Provider(omemo).forgetAccount()
        // OTR holds no state of its own here: it reads the engine's, and the
        // engine's teardown belongs with the connection. An account boundary
        // reaching into the OTR session store would be exactly the
        // cross-provider access the architecture forbids.
        otr(SecurityState.ENCRYPTED).forgetAccount()
        MlsProvider().forgetAccount()
        assertTrue(omemo.forgotten)
    }

    private class FakeBackend(
        private val ready: Boolean,
    ) : Omemo2Provider.Backend {
        var forgotten = false
        override val deviceId = 1234
        override fun isReady(account: String) = ready
        override suspend fun establish(conversation: ConversationRef) =
            EncryptionOutcome.established(EncryptionState.ACTIVE)
        override suspend fun encrypt(
            conversation: ConversationRef,
            plaintext: String,
        ) = EncryptionOutcome.encrypted("cipher", EncryptionState.ACTIVE)
        override suspend fun decrypt(
            conversation: ConversationRef,
            payload: String,
        ) = DecryptionOutcome.decrypted("plain")
        override fun forgetAccount() { forgotten = true }
    }
}
