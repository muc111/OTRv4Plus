// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * The step between "the user picked one" and "the core was told".
 *
 * WHY THIS EXISTS, AND WHAT THE TRACE FOUND
 * -----------------------------------------
 * [EncryptionSelector] decides what may be offered and [EncryptionProvider]
 * knows how to establish it, and until now NOTHING JOINED THEM TO THE APP.
 * Tracing the chain end to end found:
 *
 *   * no file outside `crypto/` imported `org.otrv4plus.android.crypto` at
 *     all — the selector, the providers and [ConversationRef] were reachable
 *     only from their own tests;
 *   * `ChatViewModel.startSession(jid)` existed, and `ChaquopyOtrCore` and
 *     `OtrCore` implemented it, but no screen called it.
 *
 * The consequence is the one worth writing down. `OtrApp.send_user_text`
 * deliberately sends an ordinary XMPP message "to a conversation where nobody
 * has asked for OTR", because opportunistically starting a DAKE would emit an
 * 11 KB handshake in place of "hello". That is correct — but on Android
 * nothing could ask. Every 1:1 conversation stayed in the nobody-has-asked
 * state permanently, so the app could only send plaintext unless the REMOTE
 * side started OTR. The conversation screen said "Not encrypted — anything
 * sent here is readable by the server", truthfully, and offered no way to
 * change it.
 *
 * THE RULE THIS CLASS ENFORCES
 * ----------------------------
 * **A kind the selector does not offer can never reach the core.** [start]
 * re-derives the offer rather than trusting its argument, so a stale screen, a
 * race between the availability changing and the tap landing, or a caller that
 * simply passes the wrong value cannot begin OTR in a room or begin a protocol
 * this build has not implemented.
 *
 * Plain Kotlin with no Android import, like [EncryptionSelector] and
 * [ChatState], so the rule is executed by a JVM test rather than reviewed.
 */
class EncryptionLauncher(
    private val providers: List<EncryptionProvider>,
) {

    private fun providerFor(kind: EncryptionKind): EncryptionProvider? =
        providers.firstOrNull { it.kind == kind }

    /**
     * Availability as the real providers report it.
     *
     * A kind with no provider registered is [Availability.NOT_IMPLEMENTED]
     * rather than absent, because "this build has no such provider" and "this
     * conversation cannot use it" are different sentences and the selector
     * filters both out anyway — but only one of them is a missing feature.
     */
    fun availability(kind: EncryptionKind, conversation: ConversationRef):
        Availability =
        providerFor(kind)?.availability(conversation)
            ?: Availability.NOT_IMPLEMENTED

    /** What to show, in order. Empty when nothing is usable. */
    fun offered(conversation: ConversationRef): List<EncryptionKind> =
        EncryptionSelector.offered(conversation) { availability(it, conversation) }

    /** What to start if the user just says "encrypt this", or null. */
    fun defaultFor(conversation: ConversationRef): EncryptionKind? =
        EncryptionSelector.defaultFor(conversation) { availability(it, conversation) }

    /** The sentence to show when [offered] is empty. */
    fun unavailableReason(conversation: ConversationRef): String =
        EncryptionSelector.unavailableReason(conversation)

    /**
     * Begin [kind] for [conversation], or refuse.
     *
     * THE GUARD IS NOT REDUNDANT with the screen only showing offered kinds.
     * A screen is a cache of a decision taken earlier; availability can change
     * underneath it (a room's configuration, a provider that was ready and is
     * not), and the tap arrives afterwards. Deriving the offer again here
     * means the last word on what reaches the core belongs to the same rule
     * that decided what to display, not to whatever the UI last rendered.
     *
     * Refusal is [EncryptionError.UNAVAILABLE] with the selector's own
     * sentence, so the user is told the same thing whichever way they got
     * here.
     */
    suspend fun start(
        conversation: ConversationRef,
        kind: EncryptionKind,
    ): EncryptionOutcome {
        if (kind == EncryptionKind.NONE) {
            return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                "Plaintext is not something to establish.")
        }
        if (kind !in offered(conversation)) {
            return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                unavailableReason(conversation))
        }
        val provider = providerFor(kind)
            ?: return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                unavailableReason(conversation))
        return provider.establish(conversation)
    }

    /**
     * Begin whatever [defaultFor] chooses, or refuse with a reason.
     *
     * What the conversation screen's one control calls. Returns a refusal
     * rather than doing nothing when there is no usable protocol, because a
     * control that silently does nothing is the thing this whole trace was
     * about.
     */
    suspend fun startDefault(conversation: ConversationRef): EncryptionOutcome {
        val kind = defaultFor(conversation)
            ?: return EncryptionOutcome.failed(
                EncryptionError.UNAVAILABLE,
                unavailableReason(conversation))
        return start(conversation, kind)
    }
}
