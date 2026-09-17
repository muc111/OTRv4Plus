// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * Which encryption a conversation may offer, and which it starts with.
 *
 * Separated from [EncryptionProvider] and from the UI because these are the
 * rules most likely to be got wrong quietly: offering a protocol that cannot
 * work here, or falling back to plaintext when one fails. Both produce a
 * screen that looks fine. So they live in plain Kotlin with no Android import
 * and are tested by being run.
 *
 * THE TWO RULES THAT MATTER
 * -------------------------
 * **Shape first.** OTRv4+ is a two-party protocol; a MUC message is fanned out
 * by the service to everybody present, so OTR in a room is not a weaker option
 * but a meaningless one. MLS is a group protocol. A selector that listed
 * everything and let the user find out would be inviting a failure minutes
 * later over I2P.
 *
 * **Never choose plaintext on behalf of the user.** [defaultFor] returns a
 * protocol or it returns nothing; it does not answer `NONE` because something
 * else was unavailable. A conversation that ends up unencrypted got there
 * because somebody chose it.
 */
object EncryptionSelector {

    /**
     * What to offer, in the order it should be shown.
     *
     * Only what is genuinely usable: a provider reporting anything other than
     * [Availability.AVAILABLE] is left out rather than shown disabled, because
     * a greyed-out `MLS` reads as "coming soon" in a place where the honest
     * statement is that this room cannot do it.
     *
     * Ordered by [preference], so the first entry is also [defaultFor]'s
     * answer and the list does not need a separate notion of which is default.
     */
    fun offered(
        conversation: ConversationRef,
        availability: (EncryptionKind) -> Availability,
    ): List<EncryptionKind> {
        if (!conversation.isValid) return emptyList()
        return EncryptionKind.entries
            .filter { it != EncryptionKind.NONE }
            .filter { it.suits(conversation) }
            .filter { availability(it) == Availability.AVAILABLE }
            .sortedBy { preference(it, conversation) }
    }

    /**
     * What a conversation starts with, or null when nothing is usable.
     *
     * NULL, not [EncryptionKind.NONE]. "We could not offer you encryption" and
     * "you chose to send in the clear" are different facts and the UI has to
     * say which one it is — a default of NONE would turn the first silently
     * into the second, which is the downgrade this whole design refuses.
     */
    fun defaultFor(
        conversation: ConversationRef,
        availability: (EncryptionKind) -> Availability,
    ): EncryptionKind? = offered(conversation, availability).firstOrNull()

    /**
     * Lower sorts first.
     *
     * 1:1 prefers OTRv4+: it is the project's native protocol, it is the one
     * with SMP and a verified fingerprint, and it is what the rest of the app
     * has been built around. OMEMO is offered second for interoperability.
     *
     * Group prefers OMEMO 2.0, because it is the one that actually works with
     * other XMPP clients. MLS sorts last while it is a prototype — see
     * `MlsProvider`, which reports [Availability.NOT_IMPLEMENTED] until it is
     * more than an interface, so in practice it is not in this list at all.
     */
    fun preference(kind: EncryptionKind, conversation: ConversationRef): Int =
        if (conversation.isGroup) {
            when (kind) {
                EncryptionKind.OMEMO_2 -> 0
                EncryptionKind.MLS -> 1
                else -> 9
            }
        } else {
            when (kind) {
                EncryptionKind.OTRV4_PLUS -> 0
                EncryptionKind.OMEMO_2 -> 1
                else -> 9
            }
        }

    /**
     * Whether a failed [selected] protocol may be replaced by [fallback].
     *
     * Always false, and it is a function rather than a missing feature so the
     * rule is somewhere a test can point at. If encryption was selected and
     * could not be established, the message is not sent: the user is told, and
     * chooses. An app that quietly sends in the clear when the ratchet fails
     * has told its user something untrue about every message before it.
     */
    fun mayFallBack(selected: EncryptionKind, fallback: EncryptionKind): Boolean =
        false

    /**
     * What to show when a room or peer supports nothing we can do.
     *
     * A sentence rather than an empty dropdown, because an empty dropdown is
     * indistinguishable from a broken one.
     */
    fun unavailableReason(conversation: ConversationRef): String =
        if (conversation.isGroup)
            "This room does not support any encryption this app can use."
        else
            "No encryption is available for this conversation."
}
