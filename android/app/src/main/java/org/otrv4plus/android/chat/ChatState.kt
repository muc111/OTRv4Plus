// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.Subscription
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

    /**
     * Whose conversation this is.
     *
     * The store enforces the boundary for anything that reaches a disk; this
     * field is what closes it for the state that never does — the roster, the
     * drafts, the open conversation, the unread badge. All of it is private
     * to an account and all of it used to survive a sign-in as somebody else,
     * because this object is a service singleton and nothing ever told it the
     * account had changed.
     */
    var account: AccountScope = AccountScope.NONE
        private set

    /**
     * Bind to an account, dropping everything belonging to the last one.
     *
     * ONE CALL, and everything goes in it: the store is rebound, the roster
     * is emptied, the drafts are dropped, the open conversation is closed and
     * the connection view is reset. A partial boundary is not a boundary —
     * leaving the roster behind would show Dave a list of Bob's contacts even
     * with Bob's messages correctly gone.
     *
     * Binding to the same account is a no-op, so a reconnect does not discard
     * a half-typed message.
     */
    fun bindAccount(next: AccountScope) {
        if (next == account) return
        account = next
        contacts.clear()
        drafts.clear()
        openConversation = null
        connection = ConnectionStatus()
        link = Link.UNKNOWN
        readFailure = null
        notice = null
        droppedEvents = 0
        outgoingSequence = 0L
        // Who asked to watch BOB is not Dave's business, and a banner left
        // behind here would name a stranger to the new account and offer to
        // grant them Dave's presence.
        subscriptionRequests.clear()
        postLogin.onSignedOut()
        savedContacts.bind(next)
        (store as? PersistentMessageStore)?.bind(next)
    }

    /**
     * Whether a message that arrived for [forAccount] may be accepted.
     *
     * The ingestion guard. A listener belonging to a session that has been
     * replaced can still deliver — the callback is held by the old client, not
     * by us — and without this its message lands in whoever is signed in now.
     */
    fun accepts(forAccount: AccountScope): Boolean =
        account.isAuthenticated && forAccount == account

    /** Which conversation is open, or null for the list. A JID, never an
     *  object: navigation state must not hold anything mutable or live. */
    var openConversation: String? = null
        private set

    /**
     * Whether the user can actually see the screen.
     *
     * Needed because [openConversation] now outlives the UI. This state is
     * owned by the service, so "alice's conversation is open" stays true after
     * the user puts the phone in their pocket -- and a message arriving then
     * was being marked READ, because the only question asked was whether that
     * conversation was open. The unread badge was gone before they ever
     * looked, which is worse than a missing notification: nothing afterwards
     * says a message was there.
     */
    var uiVisible: Boolean = false
        private set

    /** The transport's own view. Only meaningful when [link] is [Link.OK]. */
    var connection: ConnectionStatus = ConnectionStatus()
        private set

    /**
     * Whether we are managing to READ the bridge at all.
     *
     * This exists because the app got it badly wrong on a handset: the poll
     * gathered four things in one `runCatching`, so a single throw discarded
     * the connection status along with everything else, and the screen fell
     * back to a default `ConnectionStatus()` whose `connected` is false. The
     * UI then stated, in red, "Not connected. Messages cannot be sent or
     * received." about a stream that was up.
     *
     * That is a fabricated state, and the wrong kind: an app that says the
     * network is down when it has merely failed to ask is indistinguishable
     * from one that knows. So "we have not heard" is now its own answer, and
     * the only thing entitled to claim a disconnection is [Link.OK] plus a
     * transport that says so.
     */
    var link: Link = Link.UNKNOWN
        private set

    /**
     * A stable code for the last failed read, or null.
     *
     * A CODE, never exception text: a `PyException` crossing Chaquopy carries
     * the engine's own message, which can quote what it was handling. This is
     * for telling a developer which call is failing, and it must not become a
     * route for engine text to reach a screen.
     */
    var linkFailure: String? = null
        private set

    /** How many events the bounded queue discarded. A gap is worth saying. */
    var droppedEvents: Int = 0
        private set

    /** A blocking warning the user must acknowledge, or null. */
    var fingerprintAlert: OtrEvent.FingerprintChanged? = null
        private set

    /**
     * People who have asked to see this account's presence, oldest first.
     *
     * NOT blocking, unlike [fingerprintAlert]. A fingerprint change means the
     * person you are talking to may not be who you think; a subscription
     * request means somebody wants to know when you are online. Treating the
     * second like the first trains people to dismiss the first.
     *
     * A LIST rather than a single slot, because two requests arriving while
     * the screen is away is ordinary and the second must not silently replace
     * the first — that would leave one person waiting forever on a question
     * the user was never shown.
     */
    private val subscriptionRequests =
        ArrayList<OtrEvent.SubscriptionRequested>()

    /** The pending requests, for the screen to render. A copy, not the list:
     *  this object is owned by the service and read from the UI thread. */
    val pendingSubscriptions: List<OtrEvent.SubscriptionRequested>
        get() = subscriptionRequests.toList()

    /**
     * Record a request, unless the same peer already has one outstanding.
     *
     * DEDUPED BY PEER. A `subscribe` presence is retransmitted by servers and
     * resent by clients, and without this one persistent asker becomes a
     * column of identical banners the user has to clear one at a time.
     *
     * Not recorded at all when nothing is signed in: a request arriving in the
     * window between the process starting and an identity being established
     * belongs to no account, and the only safe thing to do with it is nothing.
     */
    fun noteSubscription(event: OtrEvent.SubscriptionRequested): Boolean {
        if (!account.isAuthenticated) return false
        val jid = bare(event.peer)
        if (jid.isEmpty()) return false
        if (subscriptionRequests.any { bare(it.peer) == jid }) return false
        subscriptionRequests.add(event)
        return true
    }

    /**
     * Drop a request once it has been answered or dismissed.
     *
     * Removed whatever the answer was, and whether or not the stanza left the
     * device. A request that stays on screen after the user has answered it
     * reads as the answer not having worked, and the remedy for a failed
     * answer is the banner coming back on the next request, not one that never
     * goes away.
     */
    fun clearSubscription(jid: String) {
        val wanted = bare(jid)
        subscriptionRequests.removeAll { bare(it.peer) == wanted }
    }

    // -- what the poll loop feeds in -----------------------------------------

    /** The transport answered: this is its view. */
    fun applyConnection(status: ConnectionStatus) {
        connection = status
        link = Link.OK
        linkFailure = null
    }

    /**
     * The status read itself failed, so we do not know the connection state.
     *
     * The last known [connection] is deliberately KEPT rather than reset to a
     * disconnected default. Overwriting it would be inventing the answer we
     * just failed to obtain, and the direction it invents -- "not connected"
     * -- is the one that stops the user sending.
     */
    fun noteLinkFailure(code: String) {
        link = Link.FAILING
        linkFailure = code
    }

    /**
     * The most recent failing read of ANY of the four, or null if all four
     * answered.
     *
     * Separate from [link] because a roster that will not load is worth
     * telling somebody about even while the connection reads fine -- that is
     * the exact combination that made the contact list look empty on a working
     * stream, and it was invisible because every failure was swallowed.
     */
    var readFailure: String? = null
        private set

    fun noteReadFailure(code: String?) {
        readFailure = code
    }

    /** A notice from the last roster change, or null. Cleared once shown. */
    var notice: String? = null
        private set

    fun note(message: String?) {
        notice = message
    }

    fun dismissNotice() {
        notice = null
    }

    fun applyDropped(count: Int) {
        droppedEvents = count
    }

    /**
     * What has finished since authentication. Observed, never gated on.
     *
     * Exists so an empty conversation list can say which empty it is: "the
     * server says you have no contacts" or "the roster has not arrived yet".
     * Without it the two render identically, which is what made a handset
     * report of "contacts do not appear" unanswerable without a log.
     */
    val postLogin = PostLogin()

    /**
     * People this device chose to remember. NOT the roster.
     *
     * The server owns subscription and presence; this owns one local fact,
     * "this account asked to keep this JID". Kept apart so a tap on this
     * phone can never be rendered as something the server confirmed.
     */
    var savedContacts = SavedContacts(null)
        private set

    /** Give the saved-contact store somewhere to persist. */
    fun bindVault(vault: org.otrv4plus.android.security.Vault?) {
        savedContacts = SavedContacts(vault)
        savedContacts.bind(account)
    }

    /**
     * Replace the roster with what the engine just reported.
     *
     * Entries that vanished are dropped from the contact map but NOT from the
     * store: a conversation outlives the roster entry, and deleting history
     * because somebody unsubscribed would be destroying data the user did not
     * ask to lose.
     *
     * The ROSTER REMAINS AUTHORITATIVE. Locally saved contacts are not merged
     * in here and do not survive being absent from it as roster entries --
     * they surface through [conversations] as rows with `saved = false`, so
     * somebody remembered on this device but not confirmed by the server is
     * visible and is not described as confirmed.
     */
    fun applyRoster(roster: List<Contact>) {
        for (contact in roster) contacts[contact.jid] = contact
        val present = roster.map { it.jid }.toSet()
        contacts.keys.retainAll { it in present }
        if (canSend()) {
            postLogin.onAuthenticated()
            postLogin.onRoster(roster.size)
        }
    }

    /**
     * Apply one event from the engine.
     *
     * Returns whether a NEW inbound message was stored, which is what decides
     * whether the user gets a notification. False for a duplicate the store
     * rejected: a peer who resends must not be able to buzz the phone again,
     * and false for every other kind of event, which the UI shows without
     * interrupting anybody.
     */
    fun handle(event: OtrEvent): Boolean {
        return when (event) {
            is OtrEvent.MessageReceived -> receive(event)
            is OtrEvent.FingerprintChanged -> {
                fingerprintAlert = event
                false
            }
            // Returns false: this is not a new message and must not buzz the
            // phone. Somebody asking to see your presence is worth a banner
            // when you next look, not a notification that interrupts you.
            is OtrEvent.SubscriptionRequested -> {
                noteSubscription(event)
                false
            }
            else -> false
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
        // Read as it arrives only if the user is actually looking at it --
        // BOTH that this conversation is the open one and that the screen is
        // in front of them. Either alone is not "they saw it".
        if (added && uiVisible && openConversation == jid) store.markRead(jid)
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
        // Locally saved people are included so somebody remembered on a
        // previous run has a row before the roster arrives -- but `saved`
        // below still comes from the ROSTER, so a local record can never
        // render as a server-confirmed contact.
        val jids = contacts.keys + store.conversationIds() +
            savedContacts.all().map { it.jid }
        return jids.map { jid ->
            val contact = contacts[jid]
            Conversation(
                jid = jid,
                displayName = contact?.displayName?.takeIf { it.isNotBlank() }
                    ?: savedContacts.all()
                        .firstOrNull { it.jid == jid }?.displayName
                        ?.takeIf { it.isNotBlank() }
                    ?: jid,
                presence = Presence.of(
                    // The PEER's own state, not a boolean derived from it.
                    // A boolean cannot say "no stanza has arrived for them
                    // yet", so it inferred OFFLINE -- and a just-added
                    // contact read as unknown forever.
                    peer = contact?.presence ?: PeerPresence.UNKNOWN,
                    // Nothing is known about anyone while we are disconnected,
                    // and nothing is known while we cannot read the bridge
                    // either. A stale "online" from before the stream died is
                    // a lie with a timestamp.
                    linkKnown = canSend() && contact != null,
                    // Says WHY it is unknown when it is. A contact who has
                    // not approved the request yet is not a broken app.
                    subscription = contact?.subscription
                        ?: Subscription.UNKNOWN,
                ),
                security = contact?.security ?: SecurityState.PLAINTEXT,
                lastMessage = store.lastMessage(jid),
                unread = store.unread(jid),
                // A conversation with no roster entry is somebody who
                // messaged us and was never added. Their presence is
                // unknowable until they are, which is a thing the screen can
                // say and act on rather than a silent permanent "unknown".
                saved = contact != null,
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
                // Nothing is known about this JID at all — it is in neither
                // the roster nor the store. `false` would put a Save button in
                // front of somebody who may already be a contact whose roster
                // entry has simply not arrived, so this branch declines to
                // offer the remedy rather than offering the wrong one.
                saved = true,
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
    fun canSend(): Boolean = link == Link.OK && connection.connected

    // -- actions -------------------------------------------------------------

    fun open(jid: String) {
        openConversation = jid
        // Opening a conversation is looking at it. The service's own signal
        // can lag a frame behind the Activity's onStart, and a badge that
        // lingers on the screen you are reading is its own small bug.
        uiVisible = true
        store.markRead(jid)
    }

    /**
     * The user can, or can no longer, see the screen.
     *
     * Coming back reads whatever landed in the conversation that was left
     * open: it is still on screen, so the composition will not call [open]
     * again, and without this the badge would sit there while the user reads
     * the very messages it counts.
     */
    fun setUiVisible(visible: Boolean) {
        uiVisible = visible
        if (visible) openConversation?.let { store.markRead(it) }
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
        // Refused here as well as disabled in the composer, because the button
        // is not the only route in: the keyboard's Send action is the other,
        // and a guard on only one of them is a guard on neither. The draft is
        // deliberately NOT cleared on this path -- the user's text stays in
        // the box rather than vanishing into a message that cannot go.
        if (!canSend()) return null
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
                    SendOutcome.PLAINTEXT -> SendState.SENT
                    SendOutcome.QUEUED -> SendState.QUEUED
                    SendOutcome.FAILED -> SendState.FAILED
                },
                security = when (outcome) {
                    // The engine reported ciphertext. Nothing else here may
                    // set this label.
                    SendOutcome.ENCRYPTED -> SecurityLabel.ENCRYPTED
                    // It went, and it went in the clear. Distinct from
                    // UNKNOWN: we know exactly what happened to this one, and
                    // the user is entitled to be told.
                    SendOutcome.PLAINTEXT -> SecurityLabel.PLAINTEXT
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

    /**
     * How well we can read the bridge, which is not the same question as
     * whether the stream is up.
     */
    enum class Link {
        /** Nothing has been read yet. Say so; do not guess. */
        UNKNOWN,

        /** The last read succeeded, so [connection] means what it says. */
        OK,

        /** The read itself is failing. The connection state is unknown. */
        FAILING,
    }

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
