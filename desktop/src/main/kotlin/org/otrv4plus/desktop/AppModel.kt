// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.OtrBridgeException
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.Conversation
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.connection.ConnectProblem
import org.otrv4plus.android.connection.LinkPhase
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.ConversationRef
import org.otrv4plus.android.crypto.EncryptionLauncher
import org.otrv4plus.android.crypto.HandshakeUi
import org.otrv4plus.android.crypto.MlsProvider
import org.otrv4plus.android.crypto.Omemo2Provider
import org.otrv4plus.android.crypto.OtrAvailability
import org.otrv4plus.android.crypto.OtrV4PlusProvider
import org.otrv4plus.android.crypto.Verification
import org.otrv4plus.android.theme.ThemeTokens
import org.otrv4plus.desktop.engine.DesktopCore
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * The desktop's view model: the Android app's ChatViewModel and connection
 * service, without Android.
 *
 * The RULES are not here. They are in [ChatState] and the `crypto/`
 * helpers, compiled from the Android tree -- which conversation a message
 * belongs to, what a send outcome means, when verification or a call is
 * offered. This class does the platform half: run engine calls off the UI
 * thread, apply their results on it, and tell Compose to look again.
 *
 * Threading: [ChatState] is touched only on the UI thread. Engine calls run
 * on Dispatchers.IO; events pushed by the engine's reader thread are queued
 * and applied on the UI tick.
 */
class AppModel(
    private val core: DesktopCore,
    private val ui: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main),
) {
    val chat = ChatState()

    enum class Screen { STARTING, CONNECT, MAIN, FAILED, WIPED }
    enum class Tab { CHATS, PEOPLE, ROOMS, SETTINGS }

    /** Bumped whenever anything changes; screens read it to recompose. */
    var revision by mutableStateOf(0)
        private set
    var screen by mutableStateOf(Screen.STARTING)
        private set
    var tab by mutableStateOf(Tab.CHATS)
    var theme by mutableStateOf(ThemeTokens.DEFAULT)
    var startupFailure by mutableStateOf("")
        private set
    var fingerprint by mutableStateOf("")
        private set

    // -- connect form (the password is not kept here: it goes straight out) ----
    var jid by mutableStateOf(System.getenv("OTRV4PLUS_JID") ?: "")
    var server by mutableStateOf("")
    var samHost by mutableStateOf("127.0.0.1")
    var samPort by mutableStateOf("7656")
    var connecting by mutableStateOf(false)
        private set
    private var failuresInARow = 0

    private val inbox = ConcurrentLinkedQueue<OtrEvent>()
    private var loop: Job? = null

    init {
        core.setEventSink { inbox.add(it) }
    }

    private fun changed() { revision++ }

    // -- start-up ----------------------------------------------------------------

    fun start() {
        ui.launch {
            val init = withContext(Dispatchers.IO) { core.initialize() }
            if (!init.ok) {
                startupFailure = init.failureCode ?: "engine_failed"
                screen = Screen.FAILED
                return@launch
            }
            fingerprint = withContext(Dispatchers.IO) {
                runCatching { core.localFingerprint() }.getOrDefault("")
            }
            screen = Screen.CONNECT
            runLoop()
        }
    }

    private fun runLoop() {
        loop?.cancel()
        loop = ui.launch {
            var tick = 0
            while (isActive) {
                drainInbox()
                if (screen == Screen.MAIN || connecting) refresh(tick)
                tick++
                delay(TICK_MS)
            }
        }
    }

    private fun drainInbox() {
        var any = false
        while (true) {
            val event = inbox.poll() ?: break
            chat.handle(event)
            any = true
        }
        chat.takeRingChanges()
        if (any) changed()
    }

    private suspend fun refresh(tick: Int) {
        val status = withContext(Dispatchers.IO) { runCatching { core.connectionStatus() }.getOrNull() }
        if (status != null) chat.applyConnection(status) else chat.noteLinkFailure("status")
        if (tick % 2 == 0) {
            withContext(Dispatchers.IO) { runCatching { core.contacts() }.getOrNull() }
                ?.let { chat.applyRoster(it) }
        }
        val open = chat.openConversation
        if (open != null && !chat.isRoom(open)) {
            refreshConversation(open)
        }
        if (tick % 4 == 0) {
            transfers = withContext(Dispatchers.IO) { core.transfers() }
            groups = withContext(Dispatchers.IO) { runCatching { core.secureGroups() }.getOrDefault(emptyList()) }
            chat.noteSecureRooms(groups)
        }
        changed()
    }

    // -- connection --------------------------------------------------------------

    val phase: LinkPhase
        get() = LinkPhase.fromStage(chat.connection.stage, chat.connection.connected)

    /** The one line under the Connect button: the Android wording. */
    fun problemLine(): ConnectProblem.Line? = ConnectProblem.line(
        failure = chat.connection.code.ifBlank { null },
        connected = chat.connection.connected,
        retrying = connecting,
        failuresInARow = failuresInARow,
    )

    fun connect(password: String) {
        if (connecting) return
        connecting = true
        val account = jid.trim()
        ui.launch {
            val status = withContext(Dispatchers.IO) {
                runCatching {
                    core.prepare(account, server.trim(), samHost.trim(),
                                 samPort.trim().toIntOrNull() ?: 0)
                    core.connect(password)
                }.getOrElse { e ->
                    org.otrv4plus.android.bridge.ConnectionStatus(
                        stage = "failed", code = (e as? OtrBridgeException)?.code ?: "bridge_error")
                }
            }
            connecting = false
            chat.applyConnection(status)
            if (status.connected) {
                failuresInARow = 0
                chat.bindAccount(AccountScope.of(account))
                chat.applyConnection(status)
                screen = Screen.MAIN
            } else {
                failuresInARow++
            }
            changed()
        }
    }

    fun disconnect() {
        ui.launch {
            withContext(Dispatchers.IO) { runCatching { core.disconnect() } }
            chat.bindAccount(AccountScope.NONE)
            screen = Screen.CONNECT
            changed()
        }
    }

    // -- conversations -------------------------------------------------------------

    fun conversations(): List<Conversation> = chat.conversations()
    fun conversation(jid: String): Conversation = chat.conversation(jid)
    fun messages(jid: String): List<Message> = chat.messages(jid)
    fun draft(jid: String): String = chat.draft(jid)
    fun setDraft(jid: String, text: String) { chat.setDraft(jid, text); changed() }
    val openConversation: String? get() = chat.openConversation

    fun open(jid: String) {
        chat.open(jid)
        tab = Tab.CHATS
        lastAutoAttempt.remove(ChatState.bare(jid))
        changed()
    }

    fun close() { chat.closeConversation(); changed() }

    fun send(jid: String) {
        val message = chat.beginSend(jid) ?: return
        changed()
        ui.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.sendUserText(jid, message.body) }.getOrDefault(SendOutcome.FAILED)
            }
            chat.completeSend(message, outcome)
            changed()
        }
    }

    // -- encryption: started by the engine, never decided here ---------------------

    private val launcher by lazy {
        EncryptionLauncher(listOf(
            OtrV4PlusProvider(
                securityOf = { j -> chat.conversation(j).security },
                startSession = { j -> core.startSession(j) },
            ),
            Omemo2Provider(backend = null),
            MlsProvider(),
        ))
    }

    fun startEncryption(jid: String) {
        ui.launch {
            val ref = ConversationRef(account = chat.account.bareJid, target = jid, isGroup = false)
            val outcome = withContext(Dispatchers.IO) { launcher.startDefault(ref) }
            if (!outcome.ok) chat.note(outcome.detail.ifBlank { "Encryption could not be started." })
            changed()
        }
    }

    private val lastAutoAttempt = HashMap<String, Long>()
    var handshake by mutableStateOf(HandshakeUi.Status.IDLE)
        private set
    var callPhase by mutableStateOf(CallState.IDLE)
        private set
    var callSeconds by mutableStateOf(0)
        private set
    var callControl by mutableStateOf(CallUi.Control(true, false, "Call"))
        private set

    private suspend fun refreshConversation(jid: String) {
        val c = chat.conversation(jid)
        // Automatic OTRv4+, exactly as the app: only for the open
        // conversation, only for a peer whose client is confirmed capable.
        if (chat.canSend() && c.security == org.otrv4plus.android.bridge.SecurityState.PLAINTEXT &&
            OtrAvailability.mayStart(c.otrCapability)) {
            val now = System.currentTimeMillis()
            if (now - (lastAutoAttempt[jid] ?: 0L) >= AUTO_RETRY_MS) {
                lastAutoAttempt[jid] = now
                withContext(Dispatchers.IO) { runCatching { core.ensureOtr(jid) } }
            }
        }
        handshake = withContext(Dispatchers.IO) { core.handshakeStatus(jid) }
        callPhase = withContext(Dispatchers.IO) { core.callState(jid) }
        callSeconds = if (callPhase == CallState.ACTIVE)
            withContext(Dispatchers.IO) { core.callDurationSeconds(jid) } else 0
        val gate = withContext(Dispatchers.IO) { core.callGate(jid) }
        callControl = if (gate != null) CallUi.control(CallUi.Gate.of(gate.first), gate.second)
        else CallUi.control(CallUi.localGate(chat.canSend(), false, c.security, "", c.otrCapability))
    }

    // -- verification (the proof is Rust's; this is which dialog is open) ------------

    var verifyFor by mutableStateOf<String?>(null)

    fun verificationPrompt(jid: String): Verification.Prompt? {
        val c = chat.conversation(jid)
        return Verification.prompt(c.security,
            secretRequired = c.smp == org.otrv4plus.android.bridge.SmpState.SECRET_REQUIRED,
            requested = verifyFor == ChatState.bare(jid))
    }

    fun submitSecret(jid: String, secret: String, question: String = "") {
        val prompt = verificationPrompt(jid) ?: return
        verifyFor = null
        ui.launch {
            val refusal = withContext(Dispatchers.IO) {
                try {
                    if (prompt == Verification.Prompt.INCOMING) core.smpRespond(jid, secret)
                    else core.smpStart(jid, secret, question)
                    null
                } catch (e: OtrBridgeException) {
                    Verification.refusal(e.code) ?: "Verification could not start (${e.code})."
                }
            }
            refusal?.let { chat.note(it) }
            changed()
        }
    }

    fun abortVerification(jid: String) {
        verifyFor = null
        ui.launch { withContext(Dispatchers.IO) { runCatching { core.smpAbort(jid) } }; changed() }
    }

    // -- calls (the gate is the engine's) ----------------------------------------------

    fun call(jid: String) = callAction { core.startCall(jid) }
    fun answer(jid: String) = callAction { core.answerCall(jid) }
    fun hangUp(jid: String) = callAction { core.endCall(jid) }

    private fun callAction(block: () -> String) {
        ui.launch {
            val outcome = withContext(Dispatchers.IO) { block() }
            CallUi.refusal(outcome)?.let { chat.note(it) }
            changed()
        }
    }

    // -- files -------------------------------------------------------------------------

    var transfers by mutableStateOf<List<FileTransferView>>(emptyList())
        private set

    fun sendFile(jid: String, path: String, stripMetadata: Boolean) {
        ui.launch {
            val outcome = withContext(Dispatchers.IO) { core.sendFile(jid, path, stripMetadata) }
            org.otrv4plus.android.crypto.TransferUi.refusal(outcome)?.let { chat.note(it) }
            changed()
        }
    }

    fun acceptFile(id: String) = fileAction(id) { core.acceptFile(id) }
    fun declineFile(id: String) = fileAction(id) { core.declineFile(id) }

    private fun fileAction(id: String, block: () -> String) {
        chat.dismissFileOffer(id)
        ui.launch { withContext(Dispatchers.IO) { block() }; changed() }
    }

    // -- people and rooms ---------------------------------------------------------------

    var groups by mutableStateOf<List<String>>(emptyList())
        private set

    fun addContact(jid: String) = outcome { core.addContact(jid.trim()) }
    fun answerSubscription(jid: String, approve: Boolean) {
        chat.clearSubscription(jid)
        outcome { core.answerSubscription(jid, approve) }
    }
    fun joinRoom(room: String, nick: String) {
        outcome { core.joinRoom(room.trim(), nick.trim()) }
        chat.noteRoom(room.trim())
    }
    fun createSecureGroup(room: String) {
        outcome { core.createSecureGroup(room.trim()) }
        chat.noteRoom(room.trim())
    }
    fun acceptGroupInvite(room: String) {
        chat.clearGroupInvite(room)
        outcome { core.acceptGroupInvite(room) }
        chat.noteRoom(room)
    }
    fun declineGroupInvite(room: String) {
        chat.clearGroupInvite(room)
        outcome { core.declineGroupInvite(room) }
    }
    fun inviteToGroup(room: String, peer: String) = outcome { core.inviteToGroup(room, peer.trim()) }

    private fun outcome(block: () -> DesktopCore.Outcome) {
        ui.launch {
            val r = withContext(Dispatchers.IO) { block() }
            if (!r.ok) chat.note(r.detail.ifBlank { "That did not work (${r.code})." })
            changed()
        }
    }

    fun dismissNotice() { chat.dismissNotice(); changed() }
    fun dismissFingerprintAlert() { chat.dismissFingerprintAlert(); changed() }

    // -- Wipe & Exit -------------------------------------------------------------------

    fun wipeAndExit(onDone: () -> Unit) {
        ui.launch {
            withContext(Dispatchers.IO) { runCatching { core.wipe() } }
            chat.bindAccount(AccountScope.NONE)
            screen = Screen.WIPED
            changed()
            onDone()
        }
    }

    fun shutdown() {
        loop?.cancel()
        runCatching { core.shutdown() }
    }

    companion object {
        const val TICK_MS = 500L
        const val AUTO_RETRY_MS = 45_000L
    }
}
