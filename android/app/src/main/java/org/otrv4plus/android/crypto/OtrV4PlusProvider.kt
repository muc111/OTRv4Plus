// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState

/**
 * OTRv4+ behind the provider interface. The project's native 1:1 protocol.
 *
 * WHAT THIS CLASS IS NOT
 * ----------------------
 * It is not a reimplementation and it does not touch cryptography. The DAKE,
 * the ratchet, SMP, X448, ML-KEM, ML-DSA and the Rust core are exactly where
 * they were; this is an adapter that lets the chat UI ask the same four
 * questions of OTRv4+ that it asks of OMEMO and MLS.
 *
 * That was the constraint: the provider abstraction must not cost the existing
 * protocol anything. Nothing in `otrv4plus_*` or in the Rust core changed to
 * make this fit, and if it had, the abstraction would have been the wrong
 * shape.
 *
 * WHY ENCRYPT AND DECRYPT DELEGATE RATHER THAN TRANSFORM
 * ------------------------------------------------------
 * OTRv4+ does not expose "encrypt this string and give me the ciphertext" as a
 * separate step — the engine owns the session and `sendUserText` both encrypts
 * and hands the frame to the transport, including fragmentation. Pulling those
 * apart to satisfy an interface would mean a second code path through the most
 * security-critical part of the application, which is a far worse trade than
 * an adapter that reports what the engine did.
 *
 * So [encrypt] here reports readiness rather than producing bytes, and the
 * send path continues to go through the engine. The interface accommodates
 * that because it never promised to hand ciphertext to the caller for every
 * provider — only that a provider which cannot protect a message says so
 * instead of letting it out in the clear.
 *
 * THE SECURITY LADDER IS NOT FLATTENED
 * ------------------------------------
 * `SecurityState` has four rungs and [EncryptionState] has five states, and
 * the mapping keeps the distinction SMP exists for: ENCRYPTED means the DAKE
 * ran and nobody checked who answered; SMP_VERIFIED means somebody did. They
 * must never both read as "encrypted", which is the whole point of having SMP
 * in the product.
 */
class OtrV4PlusProvider(
    /** Reads the engine's view. Injected so this class is testable. */
    private val securityOf: (String) -> SecurityState,
    /** Asks the engine to start a session. Slow: a DAKE over I2P. */
    private val startSession: (String) -> Unit = {},
) : EncryptionProvider {

    override val kind = EncryptionKind.OTRV4_PLUS

    override fun availability(conversation: ConversationRef): Availability = when {
        !conversation.isValid -> Availability.NOT_APPLICABLE
        // A MUC message is fanned out by the service to everybody present.
        // OTR in a room is not a weaker option, it is a meaningless one.
        conversation.isGroup -> Availability.NOT_APPLICABLE
        else -> Availability.AVAILABLE
    }

    override fun state(conversation: ConversationRef): EncryptionState {
        if (availability(conversation) != Availability.AVAILABLE) {
            return EncryptionState.INACTIVE
        }
        return stateOf(securityOf(conversation.target))
    }

    override suspend fun establish(
        conversation: ConversationRef,
    ): EncryptionOutcome {
        if (availability(conversation) != Availability.AVAILABLE) {
            return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                "OTRv4+ protects conversations between two people.")
        }
        // Asked for, not awaited. The DAKE completes through the engine's
        // event stream and the UI follows `state`; blocking here would hold a
        // coroutine open for the length of an I2P round trip and tell the user
        // nothing it is not already going to learn.
        runCatching { startSession(conversation.target) }
            .onFailure {
                return EncryptionOutcome.failed(
                    EncryptionError.UNKNOWN,
                    "The secure session could not be started.")
            }
        return EncryptionOutcome.established(EncryptionState.ESTABLISHING)
    }

    /**
     * Whether the engine will protect this message.
     *
     * No ciphertext: see the class docs. A success here means the caller may
     * hand the body to the engine, which encrypts it. A failure means it must
     * not, and the reason is shown rather than the message being sent anyway.
     */
    override suspend fun encrypt(
        conversation: ConversationRef,
        plaintext: String,
    ): EncryptionOutcome {
        if (availability(conversation) != Availability.AVAILABLE) {
            return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                "OTRv4+ protects conversations between two people.")
        }
        return when (val current = state(conversation)) {
            EncryptionState.ACTIVE, EncryptionState.VERIFIED ->
                EncryptionOutcome.established(current)

            EncryptionState.ESTABLISHING -> EncryptionOutcome.failed(
                EncryptionError.NO_SESSION,
                "The secure session is still being set up.")

            EncryptionState.FAILED -> EncryptionOutcome.failed(
                EncryptionError.REJECTED,
                "The contact's key does not match the one already trusted.")

            EncryptionState.INACTIVE -> EncryptionOutcome.failed(
                EncryptionError.NO_SESSION,
                "There is no secure session with this contact yet.")
        }
    }

    /**
     * Not this provider's job, and saying so explicitly.
     *
     * Inbound OTRv4+ frames are recognised, reassembled and decrypted by the
     * engine before anything reaches the chat layer — the transport hands
     * every body up and lets the engine decide, which is a rule this project
     * already enforces in `android_bridge.transport`. Routing decryption back
     * out through here would be a second opinion about what counts as an OTR
     * frame, in a place with no way to be right.
     */
    override suspend fun decrypt(
        conversation: ConversationRef,
        payload: String,
    ): DecryptionOutcome = DecryptionOutcome.failed(
        EncryptionError.UNAVAILABLE,
        "OTRv4+ messages are decrypted by the engine before they reach here.")

    /**
     * Nothing to forget HERE.
     *
     * This class holds no cryptographic state — it reads the engine's. The
     * engine's own teardown is the service's business and belongs with the
     * connection, not with an adapter; doing it here would mean an account
     * boundary could reach into the OTR session store, which is exactly the
     * cross-provider access the architecture forbids.
     */
    override fun forgetAccount() = Unit

    private fun stateOf(security: SecurityState): EncryptionState = when (security) {
        SecurityState.PLAINTEXT -> EncryptionState.INACTIVE
        // Encrypted to SOMEBODY. The DAKE ran; nobody checked who answered.
        SecurityState.ENCRYPTED -> EncryptionState.ACTIVE
        // A fingerprint has been seen, not confirmed by the human.
        SecurityState.FINGERPRINT -> EncryptionState.ACTIVE
        // SMP passed: this is the rung that means the peer proved who they are.
        SecurityState.SMP_VERIFIED -> EncryptionState.VERIFIED
        // The key changed. FAILED rather than ACTIVE: it is encrypted, and
        // that is not the point — something is wrong and the user must see it.
        SecurityState.FINGERPRINT_MISMATCH -> EncryptionState.FAILED
    }
}
