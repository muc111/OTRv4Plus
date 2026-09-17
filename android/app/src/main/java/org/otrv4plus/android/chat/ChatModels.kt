// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription

/**
 * What a message is, in this application.
 *
 * Messages used to be raw strings in a Composable. That is fine until the
 * first question anybody asks about one -- did it send? when? was it
 * encrypted? which conversation is it in? -- and every one of those is a field
 * this type has and a string does not.
 *
 * DESIGNED FOR THE OTR LAYER THAT IS NOT HERE YET.
 *
 * [security] is deliberately its own axis, separate from [sendState]. A
 * message can be delivered and unencrypted, or encrypted and failed. Folding
 * them into one status is how a UI ends up showing a padlock because a send
 * succeeded, which is the single claim this project cannot afford to get
 * wrong. When the DAKE lands, [SecurityLabel] gains states and nothing else
 * in the UI has to change.
 */
data class Message(
    /** Stable identity. See [MessageId]. */
    val id: String,
    /** The bare JID of the other party. Never our own. */
    val conversationId: String,
    val body: String,
    val outgoing: Boolean,
    /** Wall-clock milliseconds, for display only. Not a protocol ordering. */
    val at: Long,
    val sendState: SendState,
    val security: SecurityLabel,
)

/**
 * How far an outgoing message got.
 *
 * QUEUED is the one that matters and the one the first version of this app got
 * wrong. The engine does not discard text sent before a session exists -- it
 * holds it and flushes it after the DAKE, which the terminal client reports as
 * `[queued] will send once OTR is ready`. Calling that "failed" tells the user
 * to retype something that is already waiting; calling it "sent" claims
 * delivery of something still sitting in memory.
 */
enum class SendState {
    /** Shown immediately on send, before the engine has answered. */
    SENDING,

    /** The engine encrypted it and the transport took it. */
    SENT,

    /** No session yet. The engine holds it; nothing is on the wire. */
    QUEUED,

    /** It will not be sent, and nothing is retrying. */
    FAILED,

    /** Inbound messages have no send state. */
    NONE,
}

/**
 * What is actually known about this message's protection.
 *
 * NOT derived from whether XMPP is connected. Transport connectivity and OTR
 * security are different questions with different answers, and the whole point
 * of naming this separately is that no amount of connection success can
 * promote a message to ENCRYPTED.
 */
enum class SecurityLabel {
    /** Carried by XMPP with no OTR session. Readable by the server. */
    PLAINTEXT,

    /** Sent through the engine, which reported ciphertext. */
    ENCRYPTED,

    /** A local note: a state change, an error, a session event. Not traffic. */
    SYSTEM,

    /** We do not know. Never rendered as reassurance. */
    UNKNOWN,
    ;

    companion object {
        /**
         * The label for an INBOUND message, given the engine's session state.
         *
         * Asked of the engine rather than inferred from the payload's shape.
         * A body that merely looks like ciphertext is not evidence of
         * anything, and a peer can send one.
         */
        fun forInbound(state: SecurityState): SecurityLabel = when (state) {
            SecurityState.PLAINTEXT -> PLAINTEXT

            SecurityState.ENCRYPTED,
            SecurityState.FINGERPRINT,
            SecurityState.SMP_VERIFIED -> ENCRYPTED

            // A mismatch is NOT "encrypted". The engine is telling us the
            // peer's long-term key is not the one we pinned, which is either a
            // reinstall or somebody in the middle -- and we cannot tell which
            // from here. Labelling it ENCRYPTED would put the reassuring word
            // on the one message that least deserves it, so it falls to
            // UNKNOWN and the conversation's security line says so outright.
            SecurityState.FINGERPRINT_MISMATCH -> UNKNOWN
        }
    }
}

/**
 * One conversation, as the list needs it.
 *
 * Keyed by bare JID. A conversation survives the contact going offline, the
 * roster being refetched and the account reconnecting -- none of those are
 * reasons to forget what was said.
 */
data class Conversation(
    val jid: String,
    val displayName: String,
    val presence: Presence,
    val security: SecurityState,
    val lastMessage: Message?,
    val unread: Int,
    /**
     * Whether this person is on the roster.
     *
     * False means somebody messaged us who we have never added. That is an
     * ordinary thing to happen and the conversation exists either way — a
     * message from a stranger is still a message — but it is WHY their
     * presence will never be anything but unknown, and the UI has to be able
     * to say so and offer the remedy.
     */
    val saved: Boolean = true,
    /**
     * Identity verification, which [security] alone cannot express in flight.
     *
     * `SecurityState.SMP_VERIFIED` is the level AFTER a run completes.
     * SECRET_REQUIRED and IN_PROGRESS have no level of their own — the
     * session stays ENCRYPTED throughout, correctly — so without this field
     * "their request is waiting on you" and "nothing is happening" are the
     * same conversation.
     */
    val smp: SmpState = SmpState.NOT_VERIFIED,
) {
    /** What the list row shows under the name. Empty for a fresh contact. */
    val preview: String
        get() = lastMessage?.body?.replace('\n', ' ')?.take(120) ?: ""

    val lastAt: Long get() = lastMessage?.at ?: 0L

    /**
     * Whether offering "Save contact" would do anything.
     *
     * Saving is what subscribes to their presence, so this is not a filing
     * convenience: an unsaved sender's presence is unknowable, permanently,
     * and no amount of waiting changes it.
     */
    val canBeSaved: Boolean get() = !saved && jid.contains('@')
}

/**
 * Presence, with UNKNOWN as a first-class answer.
 *
 * Three states, not a Boolean. "We have not heard" is different from "they are
 * offline", and collapsing them means a freshly-added contact is rendered as
 * definitively absent before the server has said anything at all.
 */
enum class Presence {
    ONLINE,
    OFFLINE,
    UNKNOWN,

    /**
     * We have asked to see them and they have not answered yet.
     *
     * A distinct state from UNKNOWN, because it has a distinct CAUSE and a
     * distinct remedy: nothing is wrong, the other person has simply not
     * approved the request, and that can take days. Rendered as UNKNOWN it is
     * indistinguishable from a broken connection, and "the app is broken" is
     * the wrong conclusion to leave available to somebody waiting on a friend.
     */
    PENDING,
    ;

    companion object {
        /**
         * From the engine's view, which only distinguishes online/not.
         *
         * [known] is false before any presence has arrived for that JID, and
         * before the local account is connected -- a disconnected client
         * knows nothing about anyone, and continuing to show contacts as
         * online after our own stream dies is a stale claim.
         */
        fun of(online: Boolean, known: Boolean): Presence = when {
            !known -> UNKNOWN
            online -> ONLINE
            else -> OFFLINE
        }

        /**
         * As [of], but able to say WHY presence is unknown.
         *
         * A pending subscription outranks everything else: until they approve,
         * the server sends us nothing about them and no amount of being
         * connected changes that. Reporting it as a plain UNKNOWN blames the
         * connection for something the connection is not doing wrong.
         */
        fun of(online: Boolean, known: Boolean,
               subscription: Subscription): Presence = when {
            subscription == Subscription.PENDING -> PENDING
            !known -> UNKNOWN
            // The server does not send us their presence under these, so
            // "offline" would be a claim we have no basis for.
            !subscription.presenceIsKnowable &&
                subscription != Subscription.UNKNOWN -> UNKNOWN
            online -> ONLINE
            else -> OFFLINE
        }

        /**
         * From what the server actually said about THIS PEER.
         *
         * The overload above takes a Boolean, which cannot distinguish "the
         * server has not told us" from "they are offline" — so it inferred
         * OFFLINE for a peer nothing was known about, and the only thing
         * standing between that and a wrong label on screen was [linkKnown],
         * which is a fact about OUR connection rather than about them.
         *
         * Precedence, and each step is a different question:
         *
         *  1. a request they have not answered -> PENDING, whatever else is
         *     true: the server will not send their presence until they do;
         *  2. our own link is not readable -> UNKNOWN: a disconnected client
         *     knows nothing about anybody;
         *  3. a subscription that does not carry presence -> UNKNOWN, and
         *     permanently so — this is correct, not a failure;
         *  4. otherwise the peer's own state, including UNKNOWN when no
         *     stanza has arrived yet.
         */
        fun of(peer: PeerPresence, linkKnown: Boolean,
               subscription: Subscription): Presence = when {
            subscription == Subscription.PENDING -> PENDING
            !linkKnown -> UNKNOWN
            !subscription.presenceIsKnowable &&
                subscription != Subscription.UNKNOWN -> UNKNOWN
            peer == PeerPresence.ONLINE -> ONLINE
            peer == PeerPresence.OFFLINE -> OFFLINE
            // Nothing has arrived for them yet. Says so rather than guessing.
            else -> UNKNOWN
        }
    }
}

/**
 * Message identity, and why duplicates happen without it.
 *
 * Three distinct sources of the same message appearing twice:
 *
 *  1. **Optimistic echo.** An outgoing message is shown before it is sent. If
 *     the send path later appended again, it would appear twice.
 *  2. **Re-delivery.** A reconnect can replay, and the event queue is drained
 *     by a poll that a recomposition or a ViewModel restart can repeat.
 *  3. **Recomposition.** Compose re-runs a composable freely; anything that
 *     appends from inside one appends repeatedly.
 *
 * The answer is that appends are idempotent on [id], and ids are chosen so
 * that the same message produces the same id.
 *
 * NOT a protocol guarantee. XMPP's own message ids are per-sender and
 * optional, and nothing here promises exactly-once delivery -- that is not
 * something XMPP provides and pretending otherwise would be inventing a
 * guarantee. This is local de-duplication only.
 */
object MessageId {

    /**
     * For an outgoing message: ours to choose, so make it unique.
     *
     * Uses the local sequence rather than the body, because sending the same
     * word twice on purpose is ordinary and must produce two messages.
     */
    fun outgoing(conversationId: String, sequence: Long): String =
        "out:$conversationId:$sequence"

    /**
     * For an inbound message: derived from what the peer sent.
     *
     * The timestamp comes from the engine's event, so a replay of the same
     * event produces the same id and collapses. Two genuinely identical
     * messages a millisecond apart would also collapse, which is the price of
     * not having a reliable per-message id from the protocol -- and losing a
     * duplicate is a smaller fault than showing a message twice and making
     * the user wonder whether the peer sent it twice.
     */
    fun inbound(conversationId: String, at: Long, body: String): String =
        "in:$conversationId:$at:${body.hashCode()}"

    /** For a locally generated note about the session. */
    fun system(conversationId: String, at: Long, text: String): String =
        "sys:$conversationId:$at:${text.hashCode()}"
}
