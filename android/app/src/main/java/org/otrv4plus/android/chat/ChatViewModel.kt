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
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome

/**
 * The Android half of the chat: the poll loop, the coroutine scope, and
 * telling Compose when to look again.
 *
 * Every actual decision -- routing, presence, history, drafts, what a send
 * outcome means -- lives in [ChatState], which is plain Kotlin and has real
 * unit tests. This class deliberately holds no rules of its own; when a method
 * here does anything other than scheduling or state mirroring, it belongs
 * below.
 *
 * WHY IT IS A VIEWMODEL
 * ---------------------
 * The contact list, the message history, the drafts and the polling loop all
 * lived inside `ChatScreen`'s composable body. That works right up until the
 * composition goes away, which on Android happens for a rotation, a theme
 * change, a locale change or simply navigating -- and then the conversation is
 * gone. A Composable is a description of what to draw, not a place to keep what
 * was said.
 *
 * WHAT IT DELIBERATELY DOES NOT OWN
 * ---------------------------------
 * The connection. `ConnectionViewModel` owns [ChaquopyOtrCore] and therefore
 * the Python interpreter, the engine and the transport. This one is handed the
 * core and never constructs one, because two cores means two engines over the
 * same identity and trust files.
 */
class ChatViewModel(
    private val state: ChatState = ChatState(),
) : ViewModel() {

    /** The core, once a connection screen has one. Never built here. */
    private var core: ChaquopyOtrCore? = null
    private var pollJob: Job? = null

    /**
     * Redraw ticket, bumped whenever [state] changes underneath us.
     *
     * [ChatState] is deliberately not a Compose-observable type -- it must work
     * without Compose, and a future sealed [MessageStore] will be doing I/O. So
     * the ViewModel tells Compose when to look again, and every read below goes
     * through [observe] so that the ticket is actually read during composition.
     */
    private var revision by mutableStateOf(0)

    private fun observe() {
        @Suppress("UNUSED_EXPRESSION") revision
    }

    // -- what the UI reads ----------------------------------------------------

    val connection: ConnectionStatus get() { observe(); return state.connection }
    val droppedEvents: Int get() { observe(); return state.droppedEvents }
    val openConversation: String? get() { observe(); return state.openConversation }
    val fingerprintAlert: OtrEvent.FingerprintChanged?
        get() { observe(); return state.fingerprintAlert }

    fun conversations(): List<Conversation> { observe(); return state.conversations() }
    fun conversation(jid: String): Conversation { observe(); return state.conversation(jid) }
    fun messages(jid: String): List<Message> { observe(); return state.messages(jid) }
    fun draft(jid: String): String { observe(); return state.draft(jid) }
    fun canSend(): Boolean { observe(); return state.canSend() }

    // -- wiring ---------------------------------------------------------------

    /**
     * Attach the connection's core and start following it.
     *
     * Idempotent: calling it again with the same core does nothing, which
     * matters because a recomposition can call it and a recreated Activity
     * will. A second poll loop would drain the same event queue twice and every
     * other message would go missing -- each drain removes what it returns.
     */
    fun attach(core: ChaquopyOtrCore) {
        if (this.core === core && pollJob?.isActive == true) return
        pollJob?.cancel()
        this.core = core
        pollJob = viewModelScope.launch { pollLoop(core) }
    }

    private suspend fun pollLoop(core: ChaquopyOtrCore) {
        while (viewModelScope.isActive) {
            val batch = withContext(Dispatchers.IO) {
                runCatching {
                    Batch(
                        events = core.drainEvents(),
                        roster = core.contacts(),
                        dropped = core.eventsDropped(),
                        connection = core.connectionStatus(),
                    )
                }.getOrNull()
            }
            if (batch != null) apply(batch)
            delay(POLL_INTERVAL_MS)
        }
    }

    private fun apply(batch: Batch) {
        state.applyConnection(batch.connection)
        state.applyDropped(batch.dropped)
        state.applyRoster(batch.roster)
        for (event in batch.events) state.handle(event)
        revision++
    }

    // -- actions --------------------------------------------------------------

    fun setDraft(jid: String, text: String) {
        state.setDraft(jid, text)
        revision++
    }

    fun open(jid: String) {
        state.open(jid)
        revision++
    }

    fun closeConversation() {
        state.closeConversation()
        revision++
    }

    fun dismissFingerprintAlert() {
        state.dismissFingerprintAlert()
        revision++
    }

    /**
     * Add a contact to the roster and ask to see their presence.
     *
     * The engine call is off the main thread because it crosses into Python,
     * which blocks.
     */
    fun addContact(jid: String) {
        if (!state.validContact(jid)) return
        val core = this.core ?: return
        val bare = ChatState.bare(jid.trim())
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.addContact(bare) } }
            revision++
        }
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

    /** Start the DAKE with a peer. The engine does the work. */
    fun startSession(jid: String) {
        val core = this.core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.startSession(jid) } }
            revision++
        }
    }

    override fun onCleared() {
        super.onCleared()
        pollJob?.cancel()
    }

    private data class Batch(
        val events: List<OtrEvent>,
        val roster: List<Contact>,
        val dropped: Int,
        val connection: ConnectionStatus,
    )

    companion object {
        /**
         * How often to ask Python for news.
         *
         * Events are pulled rather than pushed because they are emitted on the
         * transport's asyncio loop thread; see `ChaquopyOtrCore.drainEvents`.
         * 500ms is fast enough to feel immediate and slow enough not to hold
         * the interpreter lock.
         */
        const val POLL_INTERVAL_MS = 500L
    }
}
