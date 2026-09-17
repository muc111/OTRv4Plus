// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * The boundary between the chat UI and whichever protocol is encrypting.
 *
 * WHY THIS EXISTS
 * ---------------
 * Three protocols, with nothing in common below this line:
 *
 *     EncryptionProvider
 *       ├── OtrV4PlusProvider   1:1, the project's native protocol
 *       ├── Omemo2Provider      group/MUC, XMPP interoperability
 *       └── MlsProvider         group, prototype over I2P datagrams
 *
 * They are not one cryptographic system with three modes and must never become
 * one. OTRv4+ has a DAKE, a fingerprint, SMP and a Rust core; OMEMO has device
 * lists, bundles and a double ratchet per device; MLS has a group tree. The
 * value of this interface is precisely that the UI cannot tell.
 *
 * WHAT THIS INTERFACE IS AND IS NOT
 * ---------------------------------
 * It is a QUESTION SURFACE, not a crypto API. Nothing here takes or returns
 * key material, and no implementation may expose any: a provider owns its
 * state and the only things that cross this line are a conversation id, a
 * plaintext or ciphertext body, and a state.
 *
 * That constraint is what makes the MLS boundary cheap later. An interface
 * that leaked OTR's session handle or OMEMO's device id would have to grow a
 * third shape for MLS, which is the rewrite this design exists to avoid.
 *
 * NO SILENT DOWNGRADE
 * -------------------
 * There is deliberately no "encrypt, or send plaintext if you cannot". A
 * provider either produces ciphertext or reports why it could not, and the
 * decision to send anything anyway belongs to the user in front of a message
 * that says what happened. [EncryptionOutcome] has no success-with-plaintext
 * case and cannot be given one without changing this file.
 */
interface EncryptionProvider {

    /** Which protocol this is. Stable; the UI branches on it. */
    val kind: EncryptionKind

    /**
     * Whether this provider could work here at all.
     *
     * Asked before it is offered, so a selector never lists something that
     * would fail on use. It is about CAPABILITY -- is the protocol available
     * for this kind of conversation, on this server, in this build -- not
     * about whether a session happens to be established yet.
     */
    fun availability(conversation: ConversationRef): Availability

    /** What is true right now for this conversation. */
    fun state(conversation: ConversationRef): EncryptionState

    /**
     * Try to reach a state where [encrypt] can succeed.
     *
     * Separate from [encrypt] because on this transport it is slow -- a DAKE
     * or a bundle fetch is I2P round trips -- and the UI has to be able to
     * show that something is happening rather than appearing to hang on a
     * keypress.
     */
    suspend fun establish(conversation: ConversationRef): EncryptionOutcome

    /**
     * Encrypt [plaintext], or say why not.
     *
     * Never returns the plaintext. A provider that cannot encrypt returns a
     * failure and the caller does not send.
     */
    suspend fun encrypt(
        conversation: ConversationRef,
        plaintext: String,
    ): EncryptionOutcome

    /**
     * Decrypt an incoming payload, or say why not.
     *
     * A failure must NOT be rendered as message text. Ciphertext shown as a
     * body is worse than a gap: it looks like a corrupted message from the
     * person rather than a protocol problem, and on a shared screen it leaks
     * that something encrypted arrived.
     */
    suspend fun decrypt(
        conversation: ConversationRef,
        payload: String,
    ): DecryptionOutcome

    /**
     * Forget everything this provider holds for an account.
     *
     * Called at the account boundary. Each provider clears its OWN state and
     * never another's -- see the cryptographic separation rule in
     * `ANDROID_ENCRYPTION_ARCHITECTURE.md`.
     */
    fun forgetAccount()
}

/**
 * Which protocol, and what it is for.
 *
 * [suitsDirect] and [suitsGroup] are what stop a selector offering a
 * group-only protocol in a 1:1 conversation, or OTRv4+ in a room where it
 * cannot work -- OTR is a two-party protocol and a MUC message is fanned out
 * by the service.
 */
enum class EncryptionKind(
    val label: String,
    val suitsDirect: Boolean,
    val suitsGroup: Boolean,
) {
    /** The project's native 1:1 protocol. Default for direct conversations. */
    OTRV4_PLUS("OTRv4+", suitsDirect = true, suitsGroup = false),

    /** XEP-0384 `urn:xmpp:omemo:2`. Interoperable group and direct encryption. */
    OMEMO_2("OMEMO 2.0", suitsDirect = true, suitsGroup = true),

    /** Prototype, over I2P datagrams. Not production. */
    MLS("MLS", suitsDirect = false, suitsGroup = true),

    /**
     * No encryption.
     *
     * A real member rather than a null, so "this conversation is not
     * encrypted" is a state the UI renders deliberately instead of the
     * absence of one. It is never selected automatically in place of a
     * protocol that failed.
     */
    NONE("Not encrypted", suitsDirect = true, suitsGroup = true);

    /** Whether this protocol fits [conversation]'s shape. */
    fun suits(conversation: ConversationRef): Boolean =
        if (conversation.isGroup) suitsGroup else suitsDirect
}

/**
 * What a conversation is, as much as a provider needs to know.
 *
 * Carries the account because every provider's state is per-account -- the
 * same OMEMO device list means nothing to a different local account, and
 * mixing them would be the storage defect again in a cryptographic place.
 */
data class ConversationRef(
    /** The account this conversation belongs to, as `AccountScope.bareJid`. */
    val account: String,
    /** The peer's bare JID, or the room's JID for a group. */
    val target: String,
    /** True for a MUC. Decides which protocols are even applicable. */
    val isGroup: Boolean,
) {
    val isValid: Boolean
        get() = account.isNotBlank() && target.isNotBlank()
}

/** Whether a provider can be used here, and if not, why not. */
enum class Availability {
    /** Usable now. */
    AVAILABLE,

    /** The protocol does not apply to this kind of conversation. */
    NOT_APPLICABLE,

    /** The server or room does not support it. */
    UNSUPPORTED_HERE,

    /** Implemented, but switched off in this build. */
    DISABLED,

    /** Not implemented yet. Named rather than hidden, so a prototype is
     *  visible as a prototype instead of appearing to work. */
    NOT_IMPLEMENTED,
}

/**
 * What is true for a conversation right now.
 *
 * Deliberately NOT a boolean and not [SecurityState]. `SecurityState` is
 * OTRv4+'s ladder -- plaintext, encrypted, fingerprint, SMP-verified -- and
 * forcing OMEMO or MLS onto it would either invent a verification level they
 * do not have or flatten OTR's, which is the distinction SMP exists for.
 */
enum class EncryptionState {
    /** Nothing established, and nothing being attempted. */
    INACTIVE,

    /** A handshake or key fetch is in flight. Slow on this transport. */
    ESTABLISHING,

    /** Messages will be encrypted. Says nothing about WHO is at the far end. */
    ACTIVE,

    /** Established and the peer's identity has been checked. */
    VERIFIED,

    /** It was active and has broken. NOT the same as INACTIVE: something was
     *  expected to work and stopped, which the user has to be told. */
    FAILED,
}

/** Why an encryption operation did not work. Stable; the UI branches on it. */
enum class EncryptionError {
    NONE,

    /** No session, and one could not be built. */
    NO_SESSION,

    /** The peer published no usable device or key material. */
    NO_RECIPIENT_KEYS,

    /** A device or bundle we needed could not be fetched. */
    MISSING_BUNDLE,

    /** The far side or the server refused. */
    REJECTED,

    /** The round trip did not complete. Ordinary on I2P; worth retrying. */
    TIMEOUT,

    /** Could not reach the server at all. */
    NETWORK,

    /** The provider is not implemented or not enabled here. */
    UNAVAILABLE,

    /** Anything else. Never carries the underlying message -- see below. */
    UNKNOWN,
}

/**
 * The result of [EncryptionProvider.establish] or [EncryptionProvider.encrypt].
 *
 * `ciphertext` is non-null only on success, and there is no member that means
 * "here is your plaintext back". A provider that cannot encrypt cannot express
 * a partial success, so a caller cannot accidentally send one.
 *
 * `detail` is a sentence for a person, chosen by the provider from its own
 * fixed set. It is never an exception's text: a crypto library's message can
 * quote a key id, a JID or a stanza, and this string is rendered on screen.
 */
data class EncryptionOutcome(
    val ok: Boolean,
    val state: EncryptionState,
    val error: EncryptionError = EncryptionError.NONE,
    val detail: String = "",
    val ciphertext: String? = null,
) {
    /** Whether the same attempt could work later. */
    val worthRetrying: Boolean
        get() = error == EncryptionError.TIMEOUT ||
            error == EncryptionError.NETWORK ||
            error == EncryptionError.MISSING_BUNDLE

    companion object {
        fun encrypted(ciphertext: String, state: EncryptionState) =
            EncryptionOutcome(true, state, ciphertext = ciphertext)

        fun established(state: EncryptionState) = EncryptionOutcome(true, state)

        fun failed(error: EncryptionError, detail: String) =
            EncryptionOutcome(false, EncryptionState.FAILED, error, detail)
    }
}

/**
 * The result of a decryption.
 *
 * `plaintext` is non-null only on success. On failure the UI shows a
 * decryption-failure state and NOT the payload: ciphertext rendered as a body
 * reads as a corrupted message from the sender rather than a protocol problem.
 */
data class DecryptionOutcome(
    val ok: Boolean,
    val plaintext: String? = null,
    val error: EncryptionError = EncryptionError.NONE,
    val detail: String = "",
) {
    companion object {
        fun decrypted(plaintext: String) = DecryptionOutcome(true, plaintext)

        fun failed(error: EncryptionError, detail: String) =
            DecryptionOutcome(false, error = error, detail = detail)
    }
}
