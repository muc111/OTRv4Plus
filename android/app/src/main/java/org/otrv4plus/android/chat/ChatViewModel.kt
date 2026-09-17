// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.crypto.ConversationRef
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.EncryptionLauncher
import org.otrv4plus.android.crypto.MlsProvider
import org.otrv4plus.android.crypto.Omemo2Provider
import org.otrv4plus.android.crypto.OtrV4PlusProvider

/**
 * The UI's window onto the conversation. It owns none of it.
 *
 * WHAT CHANGED, AND WHY
 * ---------------------
 * This class used to hold the [ChatState] and drain the engine's event queue.
 * The queue is DESTRUCTIVE -- a drain removes what it returns -- so whoever
 * drains it is the only one who will ever see those events. A ViewModel does
 * not exist while the UI is gone, so a message arriving with the app
 * backgrounded was dropped or left unread, and no amount of persistence
 * further down would have helped: the message never reached the code that
 * would have written it.
 *
 * `OtrConnectionService` owns the state and the drain loop now. This class
 * holds a reference, re-reads it on a timer so Compose recomposes, and sends
 * what the user types. When it is cleared, nothing happens to the
 * conversation.
 *
 * SO WHAT IS LEFT HERE
 * --------------------
 * A redraw ticket and the outbound half of the composer. No routing, no
 * presence, no history, no rules -- those are in [ChatState], which is plain
 * Kotlin with real tests, and the structural suite fails if any of them
 * reappear above this line.
 */
class ChatViewModel : ViewModel() {

    private var core: ChaquopyOtrCore? = null
    private var state: ChatState? = null
    private var pollJob: Job? = null

    /**
     * Redraw ticket.
     *
     * [ChatState] is deliberately not a Compose-observable type -- it must work
     * without Compose, in a service, and be unit-testable -- so the ViewModel
     * tells Compose when to look again.
     */
    private var revision by mutableStateOf(0)

    private fun observe() {
        @Suppress("UNUSED_EXPRESSION") revision
    }

    /** Whether the service has handed its state over yet. */
    val attached: Boolean get() { observe(); return state != null }

    // -- what the UI reads ----------------------------------------------------

    val connection: ConnectionStatus
        get() { observe(); return state?.connection ?: ConnectionStatus() }

    val droppedEvents: Int get() { observe(); return state?.droppedEvents ?: 0 }

    val link: ChatState.Link
        get() { observe(); return state?.link ?: ChatState.Link.UNKNOWN }

    val readFailure: String? get() { observe(); return state?.readFailure }

    val notice: String? get() { observe(); return state?.notice }

    val openConversation: String? get() { observe(); return state?.openConversation }

    val fingerprintAlert: OtrEvent.FingerprintChanged?
        get() { observe(); return state?.fingerprintAlert }

    fun conversations(): List<Conversation> {
        observe()
        return state?.conversations() ?: emptyList()
    }

    fun conversation(jid: String): Conversation {
        observe()
        return state?.conversation(jid) ?: Conversation(
            jid = jid, displayName = jid, presence = Presence.UNKNOWN,
            security = org.otrv4plus.android.bridge.SecurityState.PLAINTEXT,
            lastMessage = null, unread = 0,
        )
    }

    fun messages(jid: String): List<Message> {
        observe()
        return state?.messages(jid) ?: emptyList()
    }

    fun draft(jid: String): String { observe(); return state?.draft(jid) ?: "" }

    fun canSend(): Boolean { observe(); return state?.canSend() == true }

    // -- wiring ---------------------------------------------------------------

    /**
     * Take the service's core and its conversation.
     *
     * Idempotent, and NOT a handover of ownership: the service keeps both. A
     * recomposition can call this and a recreated Activity will, so calling it
     * again with the same pair must do nothing beyond ensuring the redraw
     * timer is running.
     */
    fun attach(core: ChaquopyOtrCore, state: ChatState) {
        val same = this.core === core && this.state === state
        this.core = core
        this.state = state
        if (same && pollJob?.isActive == true) return
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (isActive) {
                // No work, just a redraw: the SERVICE reads Python. Doing it
                // here as well would be two drainers on one destructive queue.
                revision++
                delay(REDRAW_INTERVAL_MS)
            }
        }
    }

    // -- actions --------------------------------------------------------------

    fun setDraft(jid: String, text: String) {
        state?.setDraft(jid, text)
        revision++
    }

    fun open(jid: String) {
        state?.open(jid)
        revision++
    }

    fun closeConversation() {
        state?.closeConversation()
        revision++
    }

    fun dismissFingerprintAlert() {
        state?.dismissFingerprintAlert()
        revision++
    }

    fun dismissNotice() {
        state?.dismissNotice()
        revision++
    }

    /** People who have asked to see this account's presence. */
    val pendingSubscriptions: List<OtrEvent.SubscriptionRequested>
        get() { observe(); return state?.pendingSubscriptions ?: emptyList() }

    /**
     * Answer a pending subscription request.
     *
     * The request is cleared FIRST and unconditionally, before the blocking
     * call is even scheduled. Two reasons, and the second is the important
     * one: the answer is an I2P round trip and a banner that lingered for it
     * reads as the button not working; and a banner that stayed up on failure
     * would invite a second tap, which under ASK sends a second `subscribed`
     * stanza for a request that may already have been answered.
     *
     * Only sent when the policy actually left the decision open. Under ACCEPT
     * slixmpp answered before the event was raised, so the stanza would have
     * nothing to do — the screen offers revoking instead, via
     * [removeContact].
     */
    fun answerSubscription(jid: String, approve: Boolean) {
        val state = this.state ?: return
        val bare = ChatState.bare(jid.trim())
        val pending = state.pendingSubscriptions
            .firstOrNull { ChatState.bare(it.peer) == bare }
        state.clearSubscription(bare)
        revision++
        if (pending?.isQuestion != true) return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                core.answerSubscription(bare, approve)
            }
            state.note(result.message())
            revision++
        }
    }

    /**
     * Dismiss a request without answering it.
     *
     * Distinct from declining. Under ASK, saying nothing leaves the asker
     * pending on the server rather than telling them no, and that is a
     * legitimate thing to want — a decline is itself a signal that this
     * account exists and is being used.
     */
    fun dismissSubscription(jid: String) {
        state?.clearSubscription(ChatState.bare(jid.trim()))
        revision++
    }

    /**
     * Drop a contact and revoke both directions of subscription.
     *
     * The remedy the banner offers under ACCEPT, where presence was granted
     * before anybody was asked. Without it, automatic approval was a one-way
     * door from the handset.
     */
    fun removeContact(jid: String) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        val bare = ChatState.bare(jid.trim())
        state.clearSubscription(bare)
        revision++
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { core.removeContact(bare) }
            state.note(result.message())
            revision++
        }
    }

    /** Add a contact to the roster, and say what happened. */
    fun addContact(jid: String) {
        val state = this.state ?: return
        if (!state.validContact(jid)) {
            state.note("That does not look like an address (name@server).")
            revision++
            return
        }
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        val bare = ChatState.bare(jid.trim())
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { core.addContact(bare) }
            // SAVED ONLY AFTER THE CONTROLLER CONFIRMED IT.
            //
            // `RosterResult.ok` is the answer to the roster operation, not to
            // the tap. Writing on the tap would make the local list a record
            // of intentions, and the entire reason it is kept apart from the
            // roster is that it must never assert something the server has
            // not done.
            //
            // What this records is still only local: "this account asked to
            // keep this JID". Whether they accept the subscription, and
            // whether their presence ever becomes visible, stays the server's
            // to say and arrives through the roster poll.
            if (result.ok) {
                state.savedContacts.save(bare, at = System.currentTimeMillis())
            }
            state.note(result.message())
            revision++
        }
    }

    /** People this device remembers. NOT a statement about the roster. */
    fun savedContacts(): List<SavedContacts.Saved> {
        observe()
        return state?.savedContacts?.all() ?: emptyList()
    }

    /**
     * What has finished since authentication, for the screen to explain an
     * empty list with. Never gates anything.
     */
    fun initialising(): Boolean {
        observe()
        val s = state ?: return false
        return s.canSend() && !s.postLogin.rosterSeen
    }

    /**
     * Send the draft for [jid].
     *
     * [ChatState.beginSend] decides what is sent and records it; this schedules
     * the blocking call and hands the outcome back. No rule about duplication,
     * ordering or labelling is repeated here.
     */
    fun send(jid: String) {
        val core = this.core ?: return
        val state = this.state ?: return
        val message = state.beginSend(jid) ?: return
        revision++

        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                // getOrDefault, not a rethrow: a bridge failure is a failed
                // send, and the exception's text may name what it was handling.
                runCatching { core.sendUserText(jid, message.body) }
                    .getOrDefault(SendOutcome.FAILED)
            }
            state.completeSend(message, outcome)
            revision++
        }
    }

    // A `startSession(jid)` used to sit here. It read
    //
    //     withContext(Dispatchers.IO) { runCatching { core.startSession(jid) } }
    //
    // and discarded the result. It has been REMOVED rather than fixed,
    // because it had no caller -- [startEncryption] goes through
    // [EncryptionLauncher] and the launcher's provider calls `core` directly
    // -- and because what it was is a trap. `OtrApp.start_session` now raises
    // when the handshake cannot be built or cannot be sent, and that is the
    // entire point of the fix: the tap did nothing and said nothing. A
    // method on this class, named the obvious thing, that swallows exactly
    // those exceptions is what a future change would reach for, and the bug
    // would be back with no test able to see it.

    // -- encryption ----------------------------------------------------------
    //
    // THE GAP THIS CLOSES. `startSession` existed on this class, and on
    // `ChaquopyOtrCore`, and NO SCREEN CALLED IT. Nothing outside `crypto/` even
    // imported the encryption package. So `OtrApp.send_user_text` kept doing
    // the correct thing for "a conversation where nobody has asked for OTR" --
    // sending plaintext -- because on Android nobody could ask.

    /**
     * Built lazily, and only once a core exists.
     *
     * The providers need the engine: `OtrV4PlusProvider` reads the security
     * state and starts the DAKE through it. A launcher built before the
     * service bound would hold a dead lambda, which is the same bug
     * `RoomsViewModel.core` had.
     */
    private var launcher: EncryptionLauncher? = null

    private fun encryption(): EncryptionLauncher? {
        val core = this.core ?: return null
        launcher?.let { return it }
        val made = EncryptionLauncher(listOf(
            OtrV4PlusProvider(
                securityOf = { jid -> conversation(jid).security },
                startSession = { jid -> core.startSession(jid) },
            ),
            // Named rather than omitted. A provider that reports
            // NOT_IMPLEMENTED is checkable; a missing one is indistinguishable
            // from one nobody wrote.
            Omemo2Provider(backend = null),
            // Its transport parameter is not nullable and defaults to
            // MlsTransport.Unavailable, which is the honest value here.
            MlsProvider(),
        ))
        launcher = made
        return made
    }

    private fun refFor(jid: String): ConversationRef {
        val account = state?.account?.bareJid.orEmpty()
        return ConversationRef(account = account, target = jid, isGroup = false)
    }

    /**
     * What this conversation may be encrypted with, in order.
     *
     * Empty is a real answer and the screen must say so with
     * [encryptionUnavailableReason] rather than showing an empty menu.
     */
    fun encryptionOffered(jid: String): List<EncryptionKind> {
        observe()
        return encryption()?.offered(refFor(jid)) ?: emptyList()
    }

    fun encryptionUnavailableReason(jid: String): String =
        encryption()?.unavailableReason(refFor(jid))
            ?: "The connection is not ready yet."

    /**
     * Ask for encryption on this conversation.
     *
     * Goes through [EncryptionLauncher], which re-derives what is on offer, so
     * a stale screen cannot start a protocol that is no longer usable. The
     * outcome is reported as a notice either way: a control that silently does
     * nothing is what this whole trace found.
     */
    fun startEncryption(jid: String) {
        val state = this.state ?: return
        val launcher = encryption() ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                launcher.startDefault(refFor(jid))
            }
            if (!outcome.ok) {
                state.note(outcome.detail.ifBlank {
                    "Encryption could not be started." })
            }
            revision++
        }
    }

    override fun onCleared() {
        super.onCleared()
        // The redraw timer, and nothing else. The conversation and the
        // connection belong to the service and outlive this.
        pollJob?.cancel()
    }

    companion object {
        /**
         * How often to redraw.
         *
         * Not a poll of Python -- the service does that. This only decides how
         * quickly a message the service has already received appears on screen.
         */
        const val REDRAW_INTERVAL_MS = 400L
    }
}
