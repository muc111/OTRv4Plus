// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * MLS, as a boundary rather than an implementation.
 *
 * WHAT THIS IS
 * ------------
 * The seam. RFC 9420 group messaging is intended to run over this project's
 * I2P datagram transport, and the point of writing this file now — before any
 * of that exists — is that the chat architecture should not need rewriting
 * when it does. The layering it has to fit into:
 *
 *     MLS group state
 *            ↓
 *     MLS protocol engine
 *            ↓
 *     MlsTransport            ← the seam, see MlsTransport.kt
 *            ↓
 *     I2P datagram transport
 *            ↓
 *     I2P
 *
 * WHAT THIS IS NOT
 * ----------------
 * It is not an MLS implementation, does not perform key schedule, group
 * operations or encryption, and is not interoperable with anything. It reports
 * [Availability.NOT_IMPLEMENTED] and every operation fails with
 * [EncryptionError.UNAVAILABLE].
 *
 * That is a deliberate choice over the alternative, which is to leave MLS out
 * of the type system until it works. A named provider that says "not
 * implemented" is checkable — `EncryptionSelector` filters it out of every
 * menu, and a test asserts that it never appears as usable. A missing provider
 * is not checkable, and the first thing anyone would do to add one is discover
 * whether the abstraction fits, which is the discovery this file exists to
 * make cheap.
 *
 * WHY IT IS GROUP-ONLY
 * --------------------
 * MLS is a group protocol. 1:1 is a group of two and MLS handles it, but this
 * project already has OTRv4+ for that — with SMP, a verified fingerprint and a
 * Rust core it has been built around. Offering MLS for 1:1 would be a second
 * answer to a question already answered.
 *
 * WHAT MUST STAY TRUE WHEN IT IS IMPLEMENTED
 * ------------------------------------------
 * The engine must not know about Android, and must not know about XMPP MUC.
 * It talks to [MlsTransport] and nothing else. Coupling it to either is what
 * would make "MLS over I2P datagrams" and "MLS over something else" a rewrite
 * rather than a different adapter.
 *
 * Its key material is its own. No OTRv4+ key, no OMEMO identity, no shared
 * ratchet — see the separation rule in `ANDROID_ENCRYPTION_ARCHITECTURE.md`.
 */
class MlsProvider(
    /**
     * Where MLS handshake and application messages would go.
     *
     * Held, unused, and deliberately part of the constructor: it is what makes
     * the transport boundary real now rather than a diagram. A version of this
     * class that took no transport would be free to grow a direct dependency
     * on XMPP or on Android the moment somebody implemented it.
     */
    @Suppress("unused")
    private val transport: MlsTransport = MlsTransport.Unavailable,
) : EncryptionProvider {

    override val kind = EncryptionKind.MLS

    /**
     * Never usable, and honest about which kind of "no" it is.
     *
     * NOT_APPLICABLE for a 1:1 conversation is a statement about the protocol
     * fit; NOT_IMPLEMENTED for a group is a statement about this build. A
     * single "unavailable" would blur a permanent design decision into a
     * temporary gap.
     */
    override fun availability(conversation: ConversationRef): Availability = when {
        !conversation.isValid -> Availability.NOT_APPLICABLE
        !conversation.isGroup -> Availability.NOT_APPLICABLE
        else -> Availability.NOT_IMPLEMENTED
    }

    override fun state(conversation: ConversationRef): EncryptionState =
        EncryptionState.INACTIVE

    override suspend fun establish(conversation: ConversationRef) = unavailable()

    override suspend fun encrypt(
        conversation: ConversationRef,
        plaintext: String,
    ) = unavailable()

    override suspend fun decrypt(
        conversation: ConversationRef,
        payload: String,
    ): DecryptionOutcome = DecryptionOutcome.failed(
        EncryptionError.UNAVAILABLE, NOT_YET)

    override fun forgetAccount() = Unit

    private fun unavailable() =
        EncryptionOutcome.failed(EncryptionError.UNAVAILABLE, NOT_YET)

    private companion object {
        /**
         * One sentence, and it does not promise a date.
         *
         * "Coming soon" in a security control is a claim about a roadmap made
         * to somebody deciding whether to trust a message.
         */
        const val NOT_YET = "MLS is not implemented in this build."
    }
}
