// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SendOutcome

/**
 * What the chat DECIDES, separated from how Android is told about it.
 *
 * WHY THIS IS NOT THE VIEWMODEL
 * -----------------------------
 * Every interesting rule in the chat layer is a decision about data: which
 * conversation an inbound message belongs to, whether a contact's presence is
 * known or merely unreported, whether an outgoing message is appended once or
 * twice, what a send outcome means. None of it needs Compose, a Looper, a
 * coroutine or a device.
 *
 * But if it lives in a `ViewModel` it needs all four to run, because
 * `androidx.lifecycle` and `androidx.compose.runtime` are published only to
 * Google's Maven repository -- which this development environment cannot reach
 * (see `.github/workflows/android.yml`). Logic that cannot be compiled outside
 * an Android build is logic that gets checked by reading it, and reading is how
 * the routing bug in the first version of this screen survived review.
 *
 * So the rules live here, in plain Kotlin against plain data classes, where a
 * JVM test can drive them directly and a deliberately planted fault -- skip the
 * append, ignore the roster, route everything to whatever is on screen, send
 * twice -- makes a test go red rather than a reviewer go quiet.
 *
 * [ChatViewModel] owns one of these and does the Android half: polling, the
 * coroutine scope, and telling Compose when to look again.
 *
 * SECURITY BOUNDARY
 * -----------------
 * Nothing here decides whether a conversation is secure. Security comes from
 * the engine, via [Contact.security], and is recorded onto a message as it
 * arrives. There is no path from "we are connected" to "this is encrypted".
 */
class ChatState(
    private val store: MessageStore = InMemoryMessageStore(),
) {

    /** Roster entries as the engine reports them, keyed by bare JID. */
    private val contacts = LinkedHashMap<String, Contact>()

    private val drafts = HashMap<String, String>()

    private var outgoingSequence = 0L

    /** Which conversation is open, or null for the list. A JID, never an
     *  object: navigation state must not hold anything mutable or live. */
    var openConversation: String? = null
        private set

    /** The transport's own view. Drives every "can I send" decision. */
    var connection: ConnectionStatus = ConnectionStatus()
        private set

    /** How many events the bounded queue discarded. A gap is worth saying. */
    var droppedEvents: Int = 0
        private set

    /** A blocking warning the user must acknowledge, or null. */
    var fingerprintAlert: OtrEvent.FingerprintChanged? = null
        private set

    // -- what the poll loop feeds in -----------------------------------------

    fun applyConnection(status: ConnectionStatus) {
        connection = status
    }

    fun applyDropped(count: Int) {
        droppedEvents = count
    }

    /**
     * Replace the roster with what the engine just reported.
     *
     * Entries that vanished are dropped from the contact map but NOT from the
     * store: a conversation outlives the roster entry, and deleting history
     * because somebody unsubscribed would be destroying data the user did not
     * ask to lose.
     */
    fun applyRoster(roster: List<Contact>) {
        for (contact in roster) contacts[contact.jid] = contact
        val present = roster.map { it.jid }.toSet()
        contacts.keys.retainAll { it in present }
    }

    fun handle(event: OtrEvent) {
        when (event) {
            is OtrEvent.MessageReceived -> receive(event)
            is OtrEvent.FingerprintChanged -> fingerprintAlert = event
            else -> Unit
        }
    }

    /**
     * An inbound message, routed by the SENDER'S JID.
     *
     * Routed, not appended to whatever is open. A message from carol while
     * bob's conversation is on screen belongs to carol, and putting it in bob's
     * would be showing the user someone else's words under the wrong name --
     * and, worse, under bob's security label.
     *
     * Returns whether it was stored, which is false for a duplicate.
     */
    fun receive(event: OtrEvent.MessageReceived): Boolean {
        val jid = bare(event.peer)
        val at = if (event.timestamp > 0) (event.timestamp * 1000).toLong()
                 else now()
        val added = store.append(
            Message(
                id = MessageId.inbound(jid, at, event.body),
                conversationId = jid,
                body = event.body,
                outgoing = false,
                at = at,
                // What the ENGINE says about that peer, captured now. Not
                // inferred from the body's shape, which a peer controls.
                security = SecurityLabel.forInbound(securityOf(jid)),
                sendState = SendState.NONE,
            )
        )
        // Read as it arrives only if the user is actually looking at it.
        if (added && openConversation == jid) store.markRead(jid)
        return added
    }

    // -- what the UI reads ---------------------------------------------------

    /**
     * Every conversation, newest first, then unread, then alphabetical.
     *
     * Built from the union of the roster and the store: a roster entry with no
     * history still gets a row, because you have to be able to start a
     * conversation with somebody you have never spoken to; and history with no
     * roster entry still gets a row, because a message from a stranger is still
     * a message.
     */
    fun conversations(): List<Conversation> {
        val jids = contacts.keys + store.conversationIds()
        return jids.map { jid ->
            val contact = contacts[jid]
            Conversation(
                jid = jid,
                displayName = contact?.displayName?.takeIf { it.isNotBlank() } ?: jid,
                presence = Presence.of(
                    online = contact?.online == true,
                    // Nothing is known about anyone while we are disconnected.
                    // A stale "online" from before the stream died is a lie
                    // with a timestamp.
                    known = connection.connected && contact != null,
                ),
                security = contact?.security ?: SecurityState.PLAINTEXT,
                lastMessage = store.lastMessage(jid),
                unread = store.unread(jid),
            )
        }.sortedWith(
            compareByDescending<Conversation> { it.lastAt }
                .thenByDescending { it.unread }
                .thenBy { it.displayName.lowercase() }
        )
    }

    fun conversation(jid: String): Conversation =
        conversations().firstOrNull { it.jid == jid }
            ?: Conversation(
                jid = jid,
                displayName = jid,
                presence = Presence.UNKNOWN,
                security = SecurityState.PLAINTEXT,
                lastMessage = null,
                unread = 0,
            )

    fun messages(jid: String): List<Message> = store.messages(jid)

    fun draft(jid: String): String = drafts[jid] ?: ""

    fun setDraft(jid: String, text: String) {
        drafts[jid] = text
    }

    /**
     * Whether a message can be sent right now.
     *
     * The transport's own `connected`, not "did the user press Connect". The
     * keepalive clears that flag the moment a round trip stops being answered,
     * so this goes false when the stream actually dies rather than when the
     * user gives up.
     */
    fun canSend(): Boolean = connection.connected

    // -- actions -------------------------------------------------------------

    fun open(jid: String) {
        openConversation = jid
        store.markRead(jid)
    }

    fun closeConversation() {
        openConversation = null
    }

    fun dismissFingerprintAlert() {
        fingerprintAlert = null
    }

    /**
     * Begin sending the draft for [jid]: validate it, clear it, and record the
     * optimistic message.
     *
     * Returns the message that was stored, or null if there was nothing to
     * send. The caller performs the actual send and hands the result back to
     * [completeSend].
     *
     * Split in two because the send itself is a blocking call into Python and
     * must not happen on the main thread, while everything here must happen
     * before the user can tap again.
     *
     * The draft is cleared BEFORE the call, not after: if it were cleared when
     * the send returned, a second tap during the round trip would find the text
     * still there and send it twice.
     *
     * The message is appended ONCE, with a stable id, and [completeSend]
     * updates it in place. Appending the result as well is how an optimistic
     * echo and its own confirmation become two bubbles.
     */
    fun beginSend(jid: String): Message? {
        val body = draft(jid)
        if (body.isBlank()) return null
        drafts[jid] = ""
        val message = Message(
            id = MessageId.outgoing(jid, ++outgoingSequence),
            conversationId = jid,
            body = body,
            outgoing = true,
            at = now(),
            sendState = SendState.SENDING,
            // Not ENCRYPTED. We have not sent it yet, and only the engine's
            // answer can promote it.
            security = SecurityLabel.UNKNOWN,
        )
        store.append(message)
        return message
    }

    /**
     * Record what the engine did with [message].
     *
     * QUEUED is not a failure. The engine holds the text until a session
     * exists, exactly as the terminal client reports `[queued] will send once
     * OTR is ready`, and reporting that as "not sent" is what made the first
     * version of this screen look broken during a DAKE.
     */
    fun completeSend(message: Message, outcome: SendOutcome): Boolean =
        store.update(
            message.copy(
                sendState = when (outcome) {
                    SendOutcome.ENCRYPTED -> SendState.SENT
                    SendOutcome.QUEUED -> SendState.QUEUED
                    SendOutcome.FAILED -> SendState.FAILED
                },
                security = when (outcome) {
                    // The engine reported ciphertext. Nothing else here may
                    // set this label.
                    SendOutcome.ENCRYPTED -> SecurityLabel.ENCRYPTED
                    else -> SecurityLabel.UNKNOWN
                },
            )
        )

    /** Whether [jid] is worth sending to the engine as a contact. */
    fun validContact(jid: String): Boolean {
        val bare = bare(jid.trim())
        return bare.isNotBlank() && bare.contains('@') && !bare.startsWith("@") &&
            !bare.endsWith("@")
    }

    private fun securityOf(jid: String): SecurityState =
        contacts[jid]?.security ?: SecurityState.PLAINTEXT

    /** Overridable so tests are not at the mercy of the wall clock. */
    internal var now: () -> Long = { System.currentTimeMillis() }

    companion object {
        /**
         * The bare JID. Resources come and go with each reconnect and each
         * device, and a conversation keyed by a full JID would fork every time
         * the peer's client restarted -- one thread per resource, none of them
         * the whole conversation.
         */
        fun bare(jid: String): String = jid.substringBefore('/')
    }
}
