// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * OMEMO 2 (`urn:xmpp:omemo:2`, XEP-0384) behind the provider interface.
 *
 * WHAT IS PRESENT AND WHAT IS NOT
 * -------------------------------
 * The XMPP half is implemented and tested: `otrv4plus_omemo` derives the
 * recipient device set from room MEMBERSHIP rather than presence, decides
 * which bundles must be fetched, detects a room whose anonymity makes OMEMO
 * impossible, and classifies every failure into a code this class renders.
 *
 * The cryptographic half is NOT present, and this class does not pretend
 * otherwise: [availability] reports [Availability.NOT_IMPLEMENTED] whenever
 * [backend] is absent, so `EncryptionSelector` leaves OMEMO out of every menu
 * and no user is offered a protocol that would fail on use.
 *
 * WHY THE CRYPTOGRAPHY IS MISSING, PRECISELY
 * ------------------------------------------
 * Not for want of a design. OMEMO 2's key agreement and ratchet are
 * implemented by `python-omemo` / `twomemo`, which are the reference
 * implementations, and writing a second Double Ratchet for a security product
 * is the worst kind of wheel to reinvent. The blocker is the build:
 *
 *     twomemo ──► X3DH, DoubleRatchet ──► cryptography, pydantic
 *             └─► XEdDSA ──► libxeddsa (C)
 *
 * `xeddsa` binds to a C library and publishes no Android wheel; nor do
 * `cryptography` or `pydantic-core`. Each would have to be cross-compiled for
 * `arm64-v8a` and `x86_64` the way `otrv4_core` already is. That is tractable
 * -- CI has the NDK toolchain -- and it is a packaging problem rather than a
 * protocol one, which is the state this class is written to leave it in.
 *
 * `ANDROID_ENCRYPTION_ARCHITECTURE.md` records it with the evidence.
 *
 * NO SILENT DOWNGRADE
 * -------------------
 * Every failure path returns a failure. There is no branch in this file that
 * produces a sendable message when encryption did not happen, and
 * [EncryptionOutcome] cannot express one.
 */
class Omemo2Provider(
    /**
     * The cryptographic backend, or null when this build has none.
     *
     * Injected rather than constructed so that the day the wheels exist, this
     * class does not change -- and so the tests can drive both the present
     * and the absent case without either being hypothetical.
     */
    private val backend: Backend? = null,
) : EncryptionProvider {

    /**
     * What a cryptographic backend must provide.
     *
     * Deliberately small, and deliberately not leaking key material: sessions,
     * ratchets, device keys and bundles belong to the implementation. This is
     * the line that keeps OMEMO's state out of reach of OTRv4+ and MLS.
     */
    interface Backend {
        /** This device's own OMEMO id, once it has been generated. */
        val deviceId: Int

        /** Whether the server advertises OMEMO 2 and our state is usable. */
        fun isReady(account: String): Boolean

        suspend fun establish(conversation: ConversationRef): EncryptionOutcome
        suspend fun encrypt(
            conversation: ConversationRef,
            plaintext: String,
        ): EncryptionOutcome
        suspend fun decrypt(
            conversation: ConversationRef,
            payload: String,
        ): DecryptionOutcome

        /** Drop this account's device identity, sessions and cached lists. */
        fun forgetAccount()
    }

    override val kind = EncryptionKind.OMEMO_2

    override fun availability(conversation: ConversationRef): Availability = when {
        !conversation.isValid -> Availability.NOT_APPLICABLE
        // Named rather than hidden. "Not implemented in this build" is a
        // different statement from "this room cannot do it", and a user
        // deciding whether to trust a message is entitled to the difference.
        backend == null -> Availability.NOT_IMPLEMENTED
        !backend.isReady(conversation.account) -> Availability.UNSUPPORTED_HERE
        else -> Availability.AVAILABLE
    }

    override fun state(conversation: ConversationRef): EncryptionState =
        EncryptionState.INACTIVE

    override suspend fun establish(
        conversation: ConversationRef,
    ): EncryptionOutcome {
        val ready = backend ?: return noBackend()
        return ready.establish(conversation)
    }

    override suspend fun encrypt(
        conversation: ConversationRef,
        plaintext: String,
    ): EncryptionOutcome {
        val ready = backend ?: return noBackend()
        return ready.encrypt(conversation, plaintext)
    }

    override suspend fun decrypt(
        conversation: ConversationRef,
        payload: String,
    ): DecryptionOutcome {
        val ready = backend ?: return DecryptionOutcome.failed(
            EncryptionError.UNAVAILABLE, NO_BACKEND)
        return ready.decrypt(conversation, payload)
    }

    /**
     * Forget OMEMO's own state, and nothing else.
     *
     * The separation rule: this clears device identity, sessions and cached
     * device lists for the account that is leaving. It has no reach into
     * OTRv4+'s session store or MLS's group state and must never acquire one.
     */
    override fun forgetAccount() {
        backend?.forgetAccount()
    }

    private fun noBackend() =
        EncryptionOutcome.failed(EncryptionError.UNAVAILABLE, NO_BACKEND)

    private companion object {
        /**
         * One sentence, and it does not promise a date.
         *
         * The reason is a build problem, but saying "coming soon" in a
         * security control is a claim about a roadmap made to somebody
         * deciding whether to trust a message.
         */
        const val NO_BACKEND = "OMEMO is not available in this build."
    }
}
