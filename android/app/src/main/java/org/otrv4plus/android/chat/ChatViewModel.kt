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
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.FileOutcome
import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.MetadataFinding
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.ConversationRef
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.EncryptionLauncher
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.MicPermission
import org.otrv4plus.android.crypto.MlsProvider
import org.otrv4plus.android.crypto.Omemo2Provider
import org.otrv4plus.android.crypto.OtrAvailability
import org.otrv4plus.android.crypto.OtrV4PlusProvider
import org.otrv4plus.android.crypto.SafeView
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.Verification

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

    // -- rooms ------------------------------------------------------------------

    /** Whether [jid] is a room: plaintext group chat, no OTR. See [ChatState.isRoom]. */
    fun isRoom(jid: String): Boolean { observe(); return state?.isRoom(jid) == true }

    /** Called when the Rooms screen opens [jid]: it is a room from now on. */
    fun noteRoom(jid: String) {
        state?.noteRoom(jid)
        revision++
    }

    /** Who is in each room, as last fetched. Empty until [refreshOccupants]. */
    private val occupants = mutableMapOf<String, List<org.otrv4plus.android.bridge.RoomOccupant>>()

    /** Whether the last occupant fetch failed, per room; shown, not hidden. */
    private val occupantsFailed = mutableSetOf<String>()

    fun occupants(jid: String): List<org.otrv4plus.android.bridge.RoomOccupant> {
        observe()
        return occupants[jid].orEmpty()
    }

    fun occupantsUnavailable(jid: String): Boolean { observe(); return jid in occupantsFailed }

    /** Whether the participant list is open, per room. Survives recreation. */
    private val occupantsShown = mutableSetOf<String>()

    fun occupantsShown(jid: String): Boolean { observe(); return jid in occupantsShown }

    fun toggleOccupants(jid: String) {
        if (!occupantsShown.remove(jid)) occupantsShown.add(jid)
        revision++
    }

    /** Ask the room who is in it. Over I2P this can take tens of seconds. */
    fun refreshOccupants(jid: String) {
        val c = core ?: return
        viewModelScope.launch {
            val (outcome, people) = withContext(Dispatchers.IO) {
                runCatching { c.roomOccupants(jid) }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "network", "") to emptyList())
            }
            if (outcome.ok) {
                occupants[jid] = people
                occupantsFailed.remove(jid)
            } else {
                occupantsFailed.add(jid)
            }
            revision++
        }
    }

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
                autoSecure()
                refreshDiscovery()
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
        lastAutoAttempt.remove(ChatState.bare(jid))
        autoSecure()
    }

    // -- automatic OTRv4+ -------------------------------------------------------
    //
    // Contact -> resource -> capability -> OTRv4+. Only for the conversation
    // on screen, only when the transport has confirmed an OTRv4Plus-capable
    // resource (`OtrAvailability.mayStart`), and the bridge re-checks that
    // itself -- this merely asks. Throttled per peer so a DAKE that takes
    // twenty seconds over I2P is not restarted every redraw.

    private val lastAutoAttempt = HashMap<String, Long>()

    private fun autoSecure() {
        val state = this.state ?: return
        val core = this.core ?: return
        val jid = state.openConversation ?: return
        if (!state.canSend() || state.isRoom(jid)) return
        val c = state.conversation(jid)
        if (c.security != org.otrv4plus.android.bridge.SecurityState.PLAINTEXT) return
        if (!OtrAvailability.mayStart(c.otrCapability)) return
        val now = System.currentTimeMillis()
        if (now - (lastAutoAttempt[jid] ?: 0L) < AUTO_RETRY_MS) return
        lastAutoAttempt[jid] = now
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { core.ensureOtr(jid) }
        }
    }

    // -- the one list of people ------------------------------------------------

    /** Roster, requests and server-listed online users, one row each. */
    val directory: List<OnlineUsers.Entry>
        get() { observe(); return state?.directory() ?: emptyList() }

    /** Why the list shows only contacts, or null when the server listed users. */
    val discoveryNote: String?
        get() {
            observe()
            val s = state ?: return null
            return OnlineUsers.discoveryNote(s.discovery, s.canSend())
        }

    private var lastDiscovery = 0L
    private var discovering = false

    /**
     * Ask the server who is online (XEP-0133), at most every
     * [DISCOVERY_INTERVAL_MS]. One round trip to our own server; nothing is
     * sent to any user. A server that does not offer it answers "none" and
     * is asked again only on the same slow interval.
     */
    fun refreshDiscovery(force: Boolean = false) {
        val state = this.state ?: return
        val core = this.core ?: return
        if (!state.canSend()) { lastDiscovery = 0L; return }
        val now = System.currentTimeMillis()
        if (discovering || (!force && now - lastDiscovery < DISCOVERY_INTERVAL_MS)) return
        lastDiscovery = now
        discovering = true
        viewModelScope.launch {
            val (outcome, found) = withContext(Dispatchers.IO) {
                runCatching { core.discoverOnlineUsers() }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "network", "") to null)
            }
            discovering = false
            // A failed ask leaves the last answer alone rather than claiming
            // that nobody is online.
            if (outcome.ok) state.applyDiscovery(found)
            revision++
        }
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
            // FORGOTTEN LOCALLY TOO, and only once the server confirmed it --
            // the mirror image of `addContact`, which saves only on `ok`.
            //
            // Without this the removal did not remove anything the user could
            // see. `conversations()` unions the roster with the message store
            // AND the saved list, so a contact dropped from the roster came
            // straight back from the local record, now rendered `saved =
            // false` -- "remembered here, not confirmed by the server" -- with
            // no way left to get rid of it.
            //
            // The HISTORY is deliberately untouched. A conversation outlives
            // the roster entry, so somebody the user has actually talked to
            // keeps their row and their messages; what goes is the local
            // record that was keeping an empty row alive on its own.
            if (result.ok) state.savedContacts.forget(bare)
            state.note(result.message())
            revision++
        }
    }

    /** What kind of chat [jid] is, for the delete dialog. */
    fun deletionKind(jid: String): ChatDeletion.Kind =
        if (isRoom(jid)) ChatDeletion.Kind.ROOM else ChatDeletion.Kind.DIRECT

    /** Whether [jid] is a room this session is in, so leaving means something. */
    fun inRoom(jid: String): Boolean { observe(); return state?.inRoomThisSession(jid) == true }

    /**
     * "Delete chat". Local deletion first and unconditionally -- it does not
     * wait on the network, and it is the part the user asked for. Then, if
     * asked, leave the room (never destroy it); then ask the server what it
     * keeps, and say exactly that. See [ChatDeletion].
     */
    fun deleteChat(jid: String, leaveRoom: Boolean = false) {
        val state = this.state ?: return
        val bare = ChatState.bare(jid.trim())
        val kind = deletionKind(bare)
        val deleted = state.deleteConversation(bare)
        revision++
        val core = this.core
        viewModelScope.launch {
            var left: Boolean? = null
            if (kind == ChatDeletion.Kind.ROOM && leaveRoom) {
                left = core != null && withContext(Dispatchers.IO) {
                    core.leaveRoom(bare, "").ok
                }
                if (left == true) state.forgetRoom(bare)
            }
            val (probe, mam) = if (core == null || !state.canSend()) null to null
                else withContext(Dispatchers.IO) {
                    core.archiveSupport(if (kind == ChatDeletion.Kind.ROOM) bare else "")
                }
            state.note(ChatDeletion.Outcome(
                kind = kind,
                deletedLocally = deleted,
                left = left,
                server = ChatDeletion.serverArchive(
                    answered = probe?.ok == true && mam != null, mam = mam == true),
            ).notice)
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
        // No Start button for a contact whose client has not been confirmed
        // to speak OTRv4Plus: a DAKE is never how that is found out.
        if (OtrAvailability.noStartReason(capability(jid)) != null) return emptyList()
        return encryption()?.offered(refFor(jid)) ?: emptyList()
    }

    fun encryptionUnavailableReason(jid: String): String =
        OtrAvailability.noStartReason(capability(jid))
            ?: encryption()?.unavailableReason(refFor(jid))
            ?: "The connection is not ready yet."

    private fun capability(jid: String): String =
        state?.capabilityOf(jid) ?: OtrAvailability.UNKNOWN

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

    // -- identity verification (SMP) -----------------------------------------
    //
    // No cryptography here. The proof is `Rust/src/smp.rs` -- X448 with
    // hybrid ML-KEM-1024 / ML-DSA-87 and the zero-knowledge proofs -- reached
    // through `OtrApp.smp_start` / `smp_respond`. What is here is which dialog
    // is open and what the user typed, and the typed text is handed to the
    // core and dropped on the same line.

    /** Whose prompt the user has asked for, or null. Never a passphrase. */
    private var verifyRequested: String? = null

    /**
     * Which prompt should be open for [jid], or null for none.
     *
     * Derived on every read from [Verification.prompt] rather than latched,
     * so an incoming request that arrives while the outgoing prompt is open
     * flips it to the one that will actually work — `smpRespond` resumes the
     * peer's held SMP1, `smpStart` would begin a competing run.
     */
    fun verificationPrompt(jid: String): Verification.Prompt? {
        observe()
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val core = this.core ?: return null
        return Verification.prompt(
            security = conversation(jid).security,
            secretRequired = runCatching { core.smpSecretRequired(jid) }
                .getOrDefault(false),
            requested = verifyRequested == jid,
        )
    }

    /** What the one verification control should be for [jid]. */
    fun verificationOffer(jid: String): Verification.Offer {
        observe()
        val conversation = conversation(jid)
        return Verification.offer(conversation.security, conversation.smp)
    }

    /** The user tapped Verify Identity. Opens the outgoing prompt only. */
    fun requestVerification(jid: String) {
        // Folded, because this is compared against the jid every later read
        // passes in. Two spellings here would mean the prompt is "open" for a
        // key nothing asks about, so the dialog never appears.
        verifyRequested = ChatState.bare(jid)
        revision++
    }

    /**
     * The user dismissed a prompt.
     *
     * An OUTGOING prompt closes and nothing else happens: no run had started.
     *
     * An INCOMING prompt means the peer's SMP1 is held in the core, and
     * closing the dialog without telling the engine would leave it held
     * forever while the initiator waited. So that case aborts, which is how
     * the state becomes CANCELLED rather than staying SECRET_REQUIRED.
     */
    fun dismissVerification(jid: String) {
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val incoming = verificationPrompt(jid) == Verification.Prompt.INCOMING
        verifyRequested = null
        revision++
        if (!incoming) return
        val core = this.core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.smpAbort(jid) } }
            revision++
        }
    }

    /**
     * Submit the passphrase for [jid].
     *
     * WHICH CALL IS NOT A DETAIL. An incoming prompt must go to `smpRespond`,
     * which binds the secret AND resumes the peer's held SMP1 into SMP2;
     * `smpStart` there would begin a second, competing run against a core that
     * is already holding one.
     *
     * [secret] is passed to the bridge and not retained: it is not assigned to
     * a field, not put in a notice, and not logged. The bridge hands it to the
     * engine, which copies it into Rust-owned zeroizing memory.
     */
    fun submitVerification(jid: String, secret: String) {
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        if (!Verification.acceptable(secret)) {
            state.note("The passphrase must be at least " +
                       "${Verification.MIN_SECRET} characters.")
            revision++
            return
        }
        val incoming = verificationPrompt(jid) == Verification.Prompt.INCOMING
        verifyRequested = null
        revision++
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                // getOrElse, not a rethrow: the exception's text comes from
                // the bridge and a PyException carries the engine's own
                // message. The CODE is what reaches the screen.
                runCatching {
                    if (incoming) core.smpRespond(jid, secret)
                    else core.smpStart(jid, secret)
                }
            }
            outcome.onFailure {
                state.note(
                    if (incoming) "The verification could not be answered."
                    else "The verification could not be started.")
            }
            revision++
        }
    }

    /** What to say about a finished run, or null while one is in flight. */
    fun verificationOutcome(jid: String): String? {
        observe()
        return Verification.outcome(conversation(jid).smp)
    }

    // ── calls ───────────────────────────────────────────────────────────────
    //
    // Every decision here is somebody else's: what to offer is `CallUi`, what
    // may happen is `otrv4plus_voice.VoiceCallManager` through the bridge.
    // This holds which direction a call is going -- a fact only the UI knows,
    // because RINGING means "they are calling us" and "we are calling them"
    // depending on who pressed the button.

    /** Which peer this device placed a call to, or null. Not a call state. */
    private var callingOut: String? = null

    /** Why voice cannot run here, cached: it is a fact about the device. */
    private var voiceReason: String? = null

    /**
     * Why the call control is or is not offered for [jid]. The ENGINE's
     * answer (`call_gate`) when it can be asked; otherwise what this side
     * knows, which is never more permissive. Deterministic: one gate per
     * state, rendered by [CallUi.control].
     */
    fun callGate(jid: String): Pair<CallUi.Gate, String> {
        observe()
        val core = this.core
        val bare = ChatState.bare(jid)
        val fromEngine = core?.let { c -> runCatching { c.callGate(bare) }.getOrNull() }
        if (fromEngine != null) return CallUi.Gate.of(fromEngine.first) to fromEngine.second
        return CallUi.localGate(
            connected = canSend(),
            isRoom = isRoom(bare),
            security = conversation(bare).security,
            // Not asked yet is not "voice works": the fallback never offers
            // what it has not checked.
            voiceUnavailableReason = voiceReason ?: "voice has not been checked yet",
            capability = capability(bare),
        ) to (voiceReason ?: "voice has not been checked yet")
    }

    /** What the call control should be for [jid]. Never a security claim. */
    fun callOffer(jid: String): CallUi.Offer {
        observe()
        val core = this.core
            ?: return CallUi.Offer.Unavailable("The connection is not ready yet.")
        if (voiceReason == null) {
            voiceReason = runCatching { core.voiceUnavailableReason() }
                .getOrDefault("Voice is not available on this device.")
        }
        return CallUi.offer(conversation(jid).security, voiceReason.orEmpty())
    }

    /** Where this peer's call has got to, and what the screen may offer. */
    fun callPhase(jid: String): CallUi.Phase {
        observe()
        val bare = ChatState.bare(jid)
        val state = state?.callState(bare) ?: CallState.IDLE
        return CallUi.phase(
            state,
            if (callingOut == bare) CallUi.Direction.OUTGOING
            else if (state == CallState.IDLE) CallUi.Direction.NONE
            else CallUi.Direction.INCOMING,
        )
    }

    /** How long the call has been up, formatted. Empty when none is. */
    fun callElapsed(jid: String): String {
        observe()
        val core = this.core ?: return ""
        if (!callPhase(jid).showsDuration) return ""
        return CallUi.elapsed(
            runCatching { core.callDurationSeconds(ChatState.bare(jid)) }
                .getOrDefault(0))
    }

    /**
     * Place a call, once the microphone is ours to use.
     *
     * [micGranted] is passed in rather than read here: this class cannot
     * touch Android, and a call placed without the permission fails inside
     * AAudio where the user cannot see why.
     */
    fun startCall(jid: String, micGranted: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        if (!micGranted) {
            state.note(MicPermission.REFUSED)
            revision++
            return
        }
        val bare = ChatState.bare(jid)
        // Held BEFORE the request, so the first poll after it already knows
        // which way the call is going. Set after, a RINGING state arriving
        // quickly would read as somebody calling us.
        callingOut = bare
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.startCall(bare) }.getOrDefault("unavailable")
            }
            if (outcome != "started") {
                callingOut = null
                CallUi.refusal(outcome)?.let { state.note(it) }
            }
            revision++
        }
    }

    /** Answer the call that is ringing. */
    fun answerCall(jid: String, micGranted: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: return
        if (!micGranted) {
            state.note(MicPermission.REFUSED)
            revision++
            return
        }
        val bare = ChatState.bare(jid)
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.answerCall(bare) }.getOrDefault("unavailable")
            }
            if (outcome != "started") CallUi.refusal(outcome)?.let(state::note)
            revision++
        }
    }

    /** End an active call, or reject a ringing one. */
    fun endCall(jid: String) {
        val core = this.core ?: return
        val bare = ChatState.bare(jid)
        // Cleared here rather than on the outcome: whatever the engine
        // answers, this device is no longer placing a call, and leaving the
        // flag set would render the next inbound ring as outgoing.
        callingOut = null
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.endCall(bare) } }
            revision++
        }
    }

    // ── files ───────────────────────────────────────────────────────────────
    //
    // Every decision is somebody else's: what to offer is `TransferUi`, what
    // may happen is `otrv4plus_filetransfer` through the bridge, which
    // enforces the SMP gate on both sides. This only carries the request.

    /** What the attach control should be for [jid]. Never a security claim. */
    fun transferOffer(jid: String): TransferUi.Offer {
        observe()
        return TransferUi.offer(conversation(jid).security)
    }

    /** Live transfers with [jid], newest state first read. */
    fun transfers(jid: String): List<FileTransferView> {
        observe()
        val core = this.core ?: return emptyList()
        val bare = ChatState.bare(jid)
        return runCatching { core.transfers() }.getOrDefault(emptyList())
            .filter { ChatState.bare(it.peer) == bare }
    }

    /** A verified received file the user asked to view, or null. */
    var viewing: FileTransferView? by mutableStateOf(null)
        private set

    private var receivedDir: String? = null

    /**
     * Whether [transfer] may be opened in the viewer: received, verified by
     * the engine, and inside the private received directory.
     */
    fun canOpen(transfer: FileTransferView): Boolean {
        if (transfer.outgoing || transfer.state != TransferUi.State.RECEIVED) return false
        val dir = receivedDir ?: core?.let { c ->
            runCatching { c.receivedFileDir() }.getOrDefault("").also {
                if (it.isNotBlank()) receivedDir = it
            }
        } ?: return false
        return SafeView.openable(transfer.path, dir)
    }

    /** Explicit tap only; nothing is ever opened on arrival. */
    fun openReceived(transfer: FileTransferView) {
        if (canOpen(transfer)) viewing = transfer
    }

    fun closeViewer() { viewing = null }

    private val rates = TransferUi.RateMeter()

    /**
     * The row for [transfer], with speed and ETA while bytes are moving.
     * The rate is sampled here, on each redraw, from the engine's own
     * progress; nothing is estimated for a transfer that is not moving.
     */
    fun transferRow(transfer: FileTransferView): TransferUi.Row {
        val moving = transfer.state == TransferUi.State.ACCEPTED &&
            transfer.progress > 0f && transfer.progress < 1f
        val rate = if (moving) rates.sample(
            transfer.id, (transfer.sizeBytes * transfer.progress).toLong(),
            transfer.sizeBytes, System.currentTimeMillis()) else null
        return TransferUi.row(transfer, rate)
    }

    /**
     * A picked file waiting on the user's metadata choice, or null.
     *
     * Held here rather than in the Composable so a rotation mid-dialog does
     * not lose the question -- and with it the path of a staged copy that
     * would then never be sent or deleted.
     */
    var pendingMetadata: PendingMetadata? by mutableStateOf(null)
        private set

    data class PendingMetadata(val jid: String, val path: String,
                               val question: String)

    /**
     * A file has been picked and staged. Look at it before anything is sent.
     *
     * [path] has been resolved by Android through the Storage Access
     * Framework and copied into this app's cache. Examined on the IO
     * dispatcher: it reads the file, and this is reached from a picker
     * callback on the main thread.
     */
    fun prepareFile(jid: String, path: String) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val finding = withContext(Dispatchers.IO) {
                runCatching { core.inspectFile(path) }
                    .getOrDefault(MetadataFinding.UNKNOWN)
            }
            when (val next = MetadataChoice.next(finding)) {
                is MetadataChoice.Next.Send -> sendFile(jid, path, false)
                is MetadataChoice.Next.SendUnchecked -> {
                    sendFile(jid, path, false)
                    state.note(next.notice)
                }
                is MetadataChoice.Next.Ask ->
                    pendingMetadata = PendingMetadata(jid, path, next.question)
            }
            revision++
        }
    }

    /** The user answered the metadata question. */
    fun answerMetadata(strip: Boolean) {
        val pending = pendingMetadata ?: return
        pendingMetadata = null
        sendFile(pending.jid, pending.path, strip)
    }

    /**
     * The user dismissed the question without answering.
     *
     * NOTHING IS SENT. Dismissing is not consent to either option, and the
     * staged copy is deleted rather than left in the cache.
     */
    fun cancelMetadata() {
        val pending = pendingMetadata ?: return
        pendingMetadata = null
        discardStaged(pending.path)
        revision++
    }

    /**
     * Offer a file, having settled the metadata question.
     *
     * The staged copy is deleted once the offer is made: the engine seals the
     * whole file into memory in `offer_file` and never reads the path again,
     * so the copy in the cache would only be a second plaintext of the
     * user's file left behind.
     */
    private fun sendFile(jid: String, path: String, strip: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: return
        val bare = ChatState.bare(jid)
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                val result = runCatching { core.sendFile(bare, path, strip) }
                    .getOrDefault(FileOutcome.UNAVAILABLE)
                discardStaged(path)
                result
            }
            TransferUi.refusal(outcome)?.let(state::note)
            revision++
        }
    }

    private fun discardStaged(path: String) {
        runCatching { java.io.File(path).delete() }
    }

    /** Incoming offers waiting for Accept or Decline. See [ChatState.pendingFileOffers]. */
    fun fileOffers(): List<OtrEvent.FileTransferChanged> {
        observe()
        return state?.pendingFileOffers ?: emptyList()
    }

    /** "Not now": the prompt goes; the offer stays in its conversation. */
    fun putAsideFileOffer(transferId: String) {
        state?.dismissFileOffer(transferId)
        revision++
    }

    /** Accept an offered transfer. */
    fun acceptTransfer(transferId: String) {
        val state = this.state ?: return
        val core = this.core ?: return
        state.dismissFileOffer(transferId)
        revision++
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.acceptFile(transferId) }
                    .getOrDefault(FileOutcome.UNAVAILABLE)
            }
            TransferUi.refusal(outcome)?.let(state::note)
            revision++
        }
    }

    /** Decline an offered transfer. */
    fun declineTransfer(transferId: String) {
        val core = this.core ?: return
        state?.dismissFileOffer(transferId)
        revision++
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { core.declineFile(transferId) }
            }
            revision++
        }
    }

    /**
     * Stop a transfer under way -- one of ours, or one we accepted. Not
     * [declineTransfer]: that answers an offer, and routing a cancel through
     * it found no offer and did nothing.
     */
    fun cancelTransfer(transferId: String) {
        val core = this.core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { core.cancelFile(transferId) }
            }
            revision++
        }
    }

    /** Where a finished file lands, for the screen to tell the user. */
    fun receivedFileDir(): String {
        observe()
        val core = this.core ?: return ""
        return runCatching { core.receivedFileDir() }.getOrDefault("")
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

        /** How long an automatic OTRv4+ start gets before it is retried. */
        const val AUTO_RETRY_MS = 45_000L
        const val DISCOVERY_INTERVAL_MS = 120_000L
    }
}
