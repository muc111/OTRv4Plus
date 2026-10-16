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
import org.otrv4plus.android.bridge.GroupCallState
import org.otrv4plus.android.bridge.GroupMember
import org.otrv4plus.android.bridge.GroupVerifyState
import org.otrv4plus.android.bridge.ProfileField
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
    val notifier: Notifier = Notifier(),
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
            // handle() is true only for a NEW stored 1:1 message: a
            // duplicate, a presence change or a room line never notifies
            // (the Android rule -- a peer must not be able to buzz at will).
            if (chat.handle(event)) notifier.message(
                when (event) {
                    is OtrEvent.MessageReceived -> event.peer
                    is OtrEvent.RoomMessageReceived -> event.room
                    else -> ""
                }, chat.openConversation)
            if (event is OtrEvent.GroupChanged && event.change == "call_ringing") notifier.call(group = true)
            any = true
        }
        // Only a verified peer's call can reach RINGING (CallAlert).
        for (change in chat.takeRingChanges()) {
            when (change) {
                org.otrv4plus.android.crypto.CallAlert.Change.START -> notifier.call()
                org.otrv4plus.android.crypto.CallAlert.Change.STOP -> notifier.stopRinging()
            }
        }
        if (any) changed()
    }

    /** The window came to the front or went behind. */
    fun setUiVisible(visible: Boolean) {
        chat.setUiVisible(visible)
        notifier.setUiVisible(visible)
        // XEP-0352: the server may hold back presence floods while nobody looks.
        ui.launch(Dispatchers.IO) { runCatching { core.setClientActive(visible) } }
        changed()
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
            // On screen: a read marker for what arrived (XEP-0333; the bridge
            // sends nothing when read receipts are off or nothing is new).
            if (chat.uiVisible) withContext(Dispatchers.IO) { runCatching { core.markDisplayed(open) } }
        }
        if (open != null && chat.isSecureRoom(open) && tick % 4 == 1) refreshGroup(open)
        if (tick % 10 == 3) refreshAvatars()
        if (tick % 20 == 7) runCatching { refreshBlocked() }
        if (tick % 4 == 0) {
            transfers = withContext(Dispatchers.IO) { core.transfers() }
            groups = withContext(Dispatchers.IO) { runCatching { core.secureGroups() }.getOrDefault(emptyList()) }
            chat.noteSecureRooms(groups)
            // Each group's members: its "n/m users verified" line.
            val members = withContext(Dispatchers.IO) {
                groups.associateWith { g -> runCatching { core.groupMembers(g).second }.getOrDefault(emptyList()) }
            }
            groupMembers = groupMembers + members.filterValues { it.isNotEmpty() }
            withContext(Dispatchers.IO) { runCatching { core.ownedRooms() }.getOrNull() }
                ?.let { chat.noteOwnedRooms(it) }
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
                    core.setPrivacy(sendTyping, sendReadReceipts)
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
    fun setDraft(jid: String, text: String) {
        chat.setDraft(jid, text)
        changed()
        typing(jid, text.isNotBlank())
    }

    // -- typing and read receipts (XEP-0085, XEP-0333) ---------------------------

    private var pausedJob: kotlinx.coroutines.Job? = null

    private fun typing(jid: String, active: Boolean) {
        pausedJob?.cancel()
        ui.launch(Dispatchers.IO) {
            runCatching { core.sendChatStateTo(jid, if (active) "composing" else "active") }
        }
        if (active) pausedJob = ui.launch {
            kotlinx.coroutines.delay(6_000)
            withContext(Dispatchers.IO) { runCatching { core.sendChatStateTo(jid, "paused") } }
        }
    }

    fun isTyping(jid: String): Boolean = chat.isTyping(jid)

    private fun privacyPrefs() = java.util.prefs.Preferences.userNodeForPackage(AppModel::class.java)

    var sendTyping by mutableStateOf(runCatching { privacyPrefs().getBoolean("send_typing", true) }.getOrDefault(true))
        private set
    var sendReadReceipts by mutableStateOf(runCatching { privacyPrefs().getBoolean("send_read_receipts", true) }.getOrDefault(true))
        private set

    /** Settings: what this device tells contacts. Applied to the engine now
     *  and on every connect. */
    fun setPrivacy(typing: Boolean, readReceipts: Boolean) {
        sendTyping = typing
        sendReadReceipts = readReceipts
        runCatching {
            privacyPrefs().putBoolean("send_typing", typing)
            privacyPrefs().putBoolean("send_read_receipts", readReceipts)
        }
        ui.launch(Dispatchers.IO) { runCatching { core.setPrivacy(typing, readReceipts) } }
    }
    val openConversation: String? get() = chat.openConversation

    fun open(jid: String) {
        chat.open(jid)
        tab = Tab.CHATS
        lastAutoAttempt.remove(ChatState.bare(jid))
        changed()
    }

    fun close() { chat.closeConversation(); changed() }

    // -- reply, correct, delete for everyone, react (otrv4plus_actions) --------

    var replyingTo by mutableStateOf<Message?>(null)
    var editing by mutableStateOf<Message?>(null)
        private set

    fun canAct(m: Message): Boolean =
        m.wireId.isNotEmpty() && !m.retracted &&
            m.security != org.otrv4plus.android.chat.SecurityLabel.SYSTEM

    fun startReply(m: Message) { editing = null; replyingTo = m; changed() }

    fun startEdit(m: Message) {
        if (!m.outgoing || !canAct(m)) return
        replyingTo = null
        editing = m
        chat.setDraft(m.conversationId, m.body)
        changed()
    }

    fun cancelCompose(jid: String) {
        if (editing != null) chat.setDraft(jid, "")
        editing = null
        replyingTo = null
        changed()
    }

    fun retract(m: Message) { if (m.outgoing && canAct(m)) act(m.conversationId, "retract", m, "", emptyList()) }

    fun react(m: Message, emoji: String) {
        if (canAct(m)) act(m.conversationId, "react", m, "", chat.toggledReaction(m, emoji))
    }

    private fun act(jid: String, action: String, target: Message, body: String, emojis: List<String>) {
        ui.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    core.sendAction(jid, action, target.wireId, body, emojis,
                                    org.otrv4plus.android.chat.MessageId.newWireId())
                }.getOrDefault(SendOutcome.FAILED)
            }
            if (outcome == SendOutcome.ENCRYPTED || outcome == SendOutcome.PLAINTEXT ||
                (outcome == SendOutcome.QUEUED && chat.isSecureRoom(jid))) {
                chat.applyChange(jid, action, target.wireId, body, emojis, outgoing = true)
            } else {
                chat.note(when (action) {
                    "edit" -> "Could not correct the message: no secure session yet."
                    "retract" -> "Could not delete the message for everyone."
                    else -> "Could not send the reaction."
                })
            }
            changed()
        }
    }

    fun send(jid: String) {
        editing?.let { target ->
            if (target.conversationId == ChatState.bare(jid)) {
                val text = chat.draft(jid).trim()
                editing = null
                chat.setDraft(jid, "")
                if (text.isNotEmpty() && text != target.body) act(jid, "edit", target, text, emptyList())
                changed()
                return
            }
        }
        val replyTo = replyingTo?.takeIf { it.conversationId == ChatState.bare(jid) && it.wireId.isNotEmpty() }
        val message = chat.beginSend(jid, replyTo) ?: return
        replyingTo = null
        pausedJob?.cancel()
        changed()
        ui.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    if (message.replyTo.isNotEmpty())
                        core.sendReply(jid, message.body, message.wireId, message.replyTo)
                    else core.sendUserText(jid, message.body, message.wireId)
                }.getOrDefault(SendOutcome.FAILED)
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

    /** The phone's colour: whether the next call's I2P path is built. */
    var callPath by mutableStateOf(CallUi.Readiness.COLD)
        private set
    var callPathSecondsLeft by mutableStateOf(0)
        private set

    /** Keep the next call's path built while a callable conversation is open. */
    fun refreshCallPath(build: Boolean) {
        ui.launch {
            val (code, left) = withContext(Dispatchers.IO) { core.callPath(build) }
            callPath = CallUi.Readiness.of(code)
            callPathSecondsLeft = left
        }
    }

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

    // -- voice notes (the recording stays in the Python host; see VoiceNotes) -----------

    var voiceSheet by mutableStateOf<org.otrv4plus.android.chat.VoiceSheet?>(null)
        private set
    private var voiceMode = org.otrv4plus.android.chat.VoiceNotes.DEFAULT
    private var voicePoll: Job? = null

    fun openVoiceSheet() {
        if (voiceSheet == null) voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Choosing(voiceMode)
    }

    fun chooseVoice(mode: String) {
        if (mode !in org.otrv4plus.android.chat.VoiceNotes.MODES) return
        voiceMode = mode
        val s = voiceSheet
        if (s is org.otrv4plus.android.chat.VoiceSheet.Choosing || s is org.otrv4plus.android.chat.VoiceSheet.Failed) {
            voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Choosing(mode)
        }
    }

    fun startVoiceNote() {
        val mode = voiceSheet?.mode ?: voiceMode
        ui.launch {
            val started = withContext(Dispatchers.IO) { core.voiceNoteStart() }
            if (started != "ok") {
                voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Failed(
                    mode, org.otrv4plus.android.chat.VoiceNotes.errorText(started))
                return@launch
            }
            voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Recording(mode)
            voicePoll?.cancel()
            voicePoll = ui.launch {
                while (voiceSheet is org.otrv4plus.android.chat.VoiceSheet.Recording) {
                    val st = withContext(Dispatchers.IO) { core.voiceNoteStatus() }
                    if (voiceSheet !is org.otrv4plus.android.chat.VoiceSheet.Recording) break
                    if (!st.recording) {
                        if (st.error.isNotEmpty()) {
                            voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Failed(
                                mode, org.otrv4plus.android.chat.VoiceNotes.errorText("no_microphone"))
                            withContext(Dispatchers.IO) { core.voiceNoteCancel() }
                        } else stopVoiceNote()
                        break
                    }
                    voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Recording(mode, st.seconds, st.level)
                    delay(200)
                }
            }
        }
    }

    fun stopVoiceNote() {
        val sheet = voiceSheet as? org.otrv4plus.android.chat.VoiceSheet.Recording ?: return
        voicePoll?.cancel()
        voiceSheet = org.otrv4plus.android.chat.VoiceSheet.Making(sheet.mode)
        ui.launch {
            // "" = the engine's private staging directory.
            val note = withContext(Dispatchers.IO) { core.voiceNoteStop(sheet.mode, "") }
            voiceSheet = if (note.error.isEmpty() && note.path.isNotEmpty())
                org.otrv4plus.android.chat.VoiceSheet.Ready(note.mode, note.path, note.seconds)
            else org.otrv4plus.android.chat.VoiceSheet.Failed(
                sheet.mode, org.otrv4plus.android.chat.VoiceNotes.errorText(note.error))
        }
    }

    /** Hear the ready note, or a received one ([path] of the container). */
    fun playVoiceNote(path: String) {
        ui.launch {
            val err = withContext(Dispatchers.IO) { core.voiceNotePlay(path) }
            if (err.isNotEmpty()) chat.note(org.otrv4plus.android.chat.VoiceNotes.errorText(err))
            changed()
        }
    }

    fun stopPlaying() { ui.launch { withContext(Dispatchers.IO) { core.voiceNotePlayStop() } } }

    fun sendVoiceNote(jid: String) {
        val ready = voiceSheet as? org.otrv4plus.android.chat.VoiceSheet.Ready ?: return
        voiceSheet = null
        // The engine deletes nothing it is handed; the note goes once offered.
        ui.launch {
            val outcome = withContext(Dispatchers.IO) {
                val o = core.sendFile(jid, ready.path, false)
                core.voiceNoteDiscard(ready.path)
                o
            }
            org.otrv4plus.android.crypto.TransferUi.refusal(outcome)?.let { chat.note(it) }
            changed()
        }
    }

    fun closeVoiceSheet() {
        val sheet = voiceSheet
        voiceSheet = null
        voicePoll?.cancel()
        ui.launch {
            withContext(Dispatchers.IO) {
                core.voiceNotePlayStop()
                when (sheet) {
                    is org.otrv4plus.android.chat.VoiceSheet.Recording -> core.voiceNoteCancel()
                    is org.otrv4plus.android.chat.VoiceSheet.Ready -> core.voiceNoteDiscard(sheet.path)
                    else -> {}
                }
            }
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
        // A secure group being set up from this moment, never an ordinary room.
        chat.noteJoiningSecure(room)
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

    // -- secure groups: verification and calls (the gates are the engine's) ---

    var groupMembers by mutableStateOf<Map<String, List<GroupMember>>>(emptyMap())
        private set

    fun groupVerify(room: String): GroupVerifyState = chat.groupVerifyState(room)
    fun groupCall(room: String): GroupCallState = chat.groupCallState(room)

    private suspend fun refreshGroup(room: String) {
        val (verify, call, members) = withContext(Dispatchers.IO) {
            Triple(core.groupVerifyState(room), core.groupCallState(room), core.groupMembers(room).second)
        }
        chat.noteGroupState(room, verify, call)
        groupMembers = groupMembers + (room to members)
    }

    fun refreshGroupNow(room: String) { ui.launch { refreshGroup(room); changed() } }

    /** The group passphrase goes to the engine and is not kept here. */
    fun startGroupVerify(room: String, passphrase: String) =
        groupAction("Verify") { core.startGroupVerify(room, passphrase) }
    fun verifyGroupMembers(room: String) = groupAction("Verify members") { core.verifyGroupMembers(room) }
    fun startGroupCall(room: String) = groupAction("Call") { core.startGroupCall(room) }
    fun joinGroupCall(room: String) = groupAction("Join") { core.joinGroupCall(room) }
    fun pauseGroupCall() = groupAction("Pause") { core.pauseGroupCall() }
    fun hangupGroupCall() = groupAction("Hang up") { core.hangupGroupCall() }
    fun removeGroupMember(room: String, member: String) =
        groupAction("Remove") { core.removeGroupMember(room, member) }
    fun leaveSecureGroup(room: String) = groupAction("Leave") { core.leaveSecureGroup(room) }
    fun deleteSecureGroup(room: String) = groupAction("Delete") { core.deleteSecureGroup(room) }

    /**
     * Whether a verified member's group call is joined by itself. Off by
     * default: the desktop has no per-app microphone prompt, so joining is
     * asked each time unless the user turns this on (Qubes: the microphone
     * is also attached to the qube by hand, in dom0).
     */
    var groupAutoJoin by mutableStateOf(false)
        private set

    /**
     * Message and call sounds (Notifier). On by default; the choice is one
     * boolean in the user's Java preferences -- nothing about any contact.
     */
    private var soundsState by mutableStateOf(
        runCatching { java.util.prefs.Preferences.userNodeForPackage(AppModel::class.java)
            .getBoolean(SOUNDS_KEY, true) }.getOrDefault(true)
            .also { notifier.sounds = it })
    var soundsOn: Boolean
        get() = soundsState
        set(value) {
            soundsState = value
            notifier.sounds = value
            if (!value) notifier.stopRinging()
            runCatching { java.util.prefs.Preferences.userNodeForPackage(AppModel::class.java)
                .putBoolean(SOUNDS_KEY, value) }
        }

    fun allowGroupAutoJoin(allowed: Boolean) {
        groupAutoJoin = allowed
        ui.launch { withContext(Dispatchers.IO) { core.setGroupCallAutoJoin(allowed) } }
    }

    private fun groupAction(label: String, block: () -> DesktopCore.Outcome) {
        val room = chat.openConversation
        ui.launch {
            val r = withContext(Dispatchers.IO) { block() }
            if (!r.ok) chat.note("$label: " + (org.otrv4plus.android.chat.GroupText.outcome(r.code)
                                               ?: r.detail.ifBlank { r.code }))
            if (room != null && chat.isSecureRoom(room)) refreshGroup(room)
            changed()
        }
    }

    // -- avatars: built from pixels the engine decoded --------------------------

    var avatars by mutableStateOf<Map<String, androidx.compose.ui.graphics.ImageBitmap>>(emptyMap())
        private set
    private val avatarIds = HashMap<String, String>()

    fun avatar(jid: String): androidx.compose.ui.graphics.ImageBitmap? = avatars[ChatState.bare(jid)]

    // -- blocking (XEP-0191) and spam reports (XEP-0377) ------------------------

    var blocked by mutableStateOf(emptySet<String>())
        private set
    var blockingSupported by mutableStateOf(false)
        private set

    fun isBlocked(jid: String): Boolean = ChatState.bare(jid) in blocked

    private suspend fun refreshBlocked() {
        val (list, supported) = withContext(Dispatchers.IO) { core.blockedContacts() }
        blocked = list.map { ChatState.bare(it) }.toSet()
        blockingSupported = supported
    }

    /** [report]: "spam" also reports them to the server's operator. */
    fun block(jid: String, report: String = "") {
        ui.launch {
            val r = withContext(Dispatchers.IO) { core.blockContact(jid, report) }
            if (r.ok) blocked = blocked + ChatState.bare(jid)
            else chat.note(r.detail.ifBlank { "Could not block." })
            changed()
        }
    }

    fun unblock(jid: String) {
        ui.launch {
            val r = withContext(Dispatchers.IO) { core.unblockContact(jid) }
            if (r.ok) blocked = blocked - ChatState.bare(jid)
            else chat.note(r.detail.ifBlank { "Could not unblock." })
            changed()
        }
    }

    private suspend fun refreshAvatars() {
        val index = withContext(Dispatchers.IO) { core.avatarIndex() }
        val next = HashMap(avatars)
        next.keys.retainAll(index.keys)
        for ((who, id) in index) {
            if (avatarIds[who] == id && who in next) continue
            val image = withContext(Dispatchers.IO) { core.avatarImage(who) } ?: continue
            Avatars.bitmap(image)?.let { next[who] = it; avatarIds[who] = id }
        }
        if (next != avatars) avatars = next
    }

    /** Publish the user's own picture: decoded, squared and re-encoded here. */
    fun setOwnAvatar(path: String) {
        ui.launch {
            val png = withContext(Dispatchers.Default) { Avatars.ownPng(java.io.File(path)) }
            if (png == null) { chat.note("That picture could not be read."); changed(); return@launch }
            val r = withContext(Dispatchers.IO) { core.setAvatar(png) }
            chat.note(if (r.ok) "Your picture is published." else r.detail.ifBlank { "The picture was not published (${r.code})." })
            refreshAvatars()
            changed()
        }
    }

    fun removeOwnAvatar() {
        ui.launch {
            val r = withContext(Dispatchers.IO) { core.removeAvatar() }
            if (!r.ok) chat.note(r.detail.ifBlank { "The picture was not removed (${r.code})." })
            refreshAvatars()
            changed()
        }
    }

    // -- the XMPP profile (vCard) ------------------------------------------------

    var profileFields by mutableStateOf<List<ProfileField>>(emptyList())
        private set
    var profile by mutableStateOf<Map<String, String>>(emptyMap())
        private set
    /** Someone else's profile, open in a dialog: (jid, fields) or null. */
    var viewing by mutableStateOf<Pair<String, Map<String, String>>?>(null)
        private set
    var profileBusy by mutableStateOf(false)
        private set

    fun loadProfile() {
        ui.launch {
            profileBusy = true
            val (fields, got) = withContext(Dispatchers.IO) { core.profileFields() to core.profileGet("") }
            profileFields = fields
            if (got.first.ok) profile = got.second
            else chat.note(got.first.detail.ifBlank { "Your profile could not be read (${got.first.code})." })
            profileBusy = false
            changed()
        }
    }

    fun saveProfile(values: Map<String, String>) {
        ui.launch {
            profileBusy = true
            val (r, saved) = withContext(Dispatchers.IO) { core.profileSet(values) }
            if (r.ok) { profile = saved; chat.note(org.otrv4plus.android.chat.ProfileText.saved(values, saved, profileFields)) }
            else chat.note(r.detail.ifBlank { "Your profile was not published (${r.code})." })
            profileBusy = false
            changed()
        }
    }

    fun viewProfile(jid: String) {
        ui.launch {
            if (profileFields.isEmpty()) profileFields = withContext(Dispatchers.IO) { core.profileFields() }
            val (r, values) = withContext(Dispatchers.IO) { core.profileGet(jid) }
            if (r.ok) viewing = jid to values
            else chat.note(r.detail.ifBlank { "Their profile could not be read (${r.code})." })
            changed()
        }
    }

    fun closeProfile() { viewing = null }

    fun dismissNotice() { chat.dismissNotice(); changed() }
    fun dismissFingerprintAlert() { chat.dismissFingerprintAlert(); changed() }

    // -- Wipe & Exit -------------------------------------------------------------------

    /** Wipe & Exit's opt-in: also delete the account on the server. Off by default. */
    var wipeDeletesAccount by mutableStateOf(false)

    fun wipeAndExit(onDone: () -> Unit) {
        val deleteAccount = wipeDeletesAccount
        ui.launch {
            withContext(Dispatchers.IO) { runCatching { core.wipe(deleteAccount) } }
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
        const val SOUNDS_KEY = "sounds"
    }
}
