// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
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
import org.otrv4plus.android.bridge.OtrBridgeException
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

// Files, location pins and voice notes, as the conversation screen offers
// them: split out of ChatViewModel (audit tidy 4). Extension functions on
// the view model; its state (the sheets, the staged file, the viewer)
// stays in the class, since an extension cannot hold any.

fun ChatViewModel.transferOffer(jid: String): TransferUi.Offer {
    observe()
    // A secure group: every other member verified (the bridge decides;
    // this only mirrors it). An ordinary room has no files at all.
    if (isRoom(jid)) {
        return if (isSecureRoom(jid))
            // Members not listed yet: still encrypted, still to be verified.
            TransferUi.groupOffer(groupMembers(jid)) ?: TransferUi.Offer.NeedsVerification
        else TransferUi.Offer.NeedsEncryption
    }
    return TransferUi.offer(conversation(jid).security)
}

fun ChatViewModel.transfers(jid: String): List<FileTransferView> {
    observe()
    val core = this.core ?: return emptyList()
    val bare = ChatState.bare(jid)
    return runCatching { core.transfers() }.getOrDefault(emptyList())
        .filter { ChatState.bare(it.peer) == bare }
        // Voice notes are bubbles in the chat, not files.
        .filterNot { VoiceNotes.looksLikeNote(it.filename) }
}

private fun ChatViewModel.receivedDirOrNull(): String? = receivedDir ?: core?.let { c ->
    runCatching { c.receivedFileDir() }.getOrDefault("").also {
        if (it.isNotBlank()) receivedDir = it
    }.ifBlank { null }
}

/**
 * Whether [transfer] may be opened in the viewer: received, verified by
 * the engine, and inside the private received directory.
 */
fun ChatViewModel.canOpen(transfer: FileTransferView): Boolean {
    if (transfer.outgoing || transfer.state != TransferUi.State.RECEIVED) return false
    val dir = receivedDirOrNull() ?: return false
    return SafeView.openable(transfer.path, dir)
}

fun ChatViewModel.openReceived(transfer: FileTransferView) {
    if (canOpen(transfer)) viewing = ViewedFile(transfer.path, transfer.filename)
}

/**
 * Whether a conversation line can open its file: a file we received and
 * the engine verified ([Message.filePath]), still in the private received
 * directory (deleted chats and Wipe remove it).
 */
fun ChatViewModel.canOpenLine(message: Message): Boolean {
    if (message.filePath.isEmpty()) return false
    val dir = receivedDirOrNull() ?: return false
    return SafeView.openable(message.filePath, dir) && java.io.File(message.filePath).isFile
}

fun ChatViewModel.openLine(message: Message) {
    if (canOpenLine(message)) viewing = ViewedFile(message.filePath, receivedName(message.filePath))
}

private fun ChatViewModel.receivedName(path: String): String =
    java.io.File(path).name.removeSuffix(".otrv")

/**
 * What metadata [plainPath] (the viewer's decrypted copy) still carries,
 * so the viewer can show that a picture's was stripped. Null if the
 * question could not be asked.
 */
fun ChatViewModel.inspectViewed(plainPath: String): MetadataFinding? {
    val c = core ?: return null
    return runCatching { c.inspectFile(plainPath) }.getOrNull()
}

fun ChatViewModel.closeViewer() { viewing = null }

/**
 * Decrypt a received container into [directory] for the viewer. Blocking;
 * the viewer calls it off the main thread. Null when it does not open.
 */
fun ChatViewModel.openReceivedTo(container: String, directory: String): String? {
    val c = core ?: return null
    val file = viewing ?: return null
    val dir = receivedDirOrNull() ?: return null
    if (file.path != container || !SafeView.openable(container, dir)) return null
    return c.openReceivedTo(container, directory)
}

/**
 * The row for [transfer], with speed and ETA while bytes are moving.
 * The rate is sampled here, on each redraw, from the engine's own
 * progress; nothing is estimated for a transfer that is not moving.
 */
fun ChatViewModel.transferRow(transfer: FileTransferView): TransferUi.Row {
    val moving = transfer.state == TransferUi.State.ACCEPTED &&
        transfer.progress > 0f && transfer.progress < 1f
    val rate = if (moving) rates.sample(
        transfer.id, (transfer.sizeBytes * transfer.progress).toLong(),
        transfer.sizeBytes, System.currentTimeMillis()) else null
    return TransferUi.row(transfer, rate)
}

/**
 * A file has been picked and staged. Look at it before anything is sent.
 *
 * [path] has been resolved by Android through the Storage Access
 * Framework and copied into this app's cache. Examined on the IO
 * dispatcher: it reads the file, and this is reached from a picker
 * callback on the main thread.
 */
fun ChatViewModel.prepareFile(jid: String, path: String) {
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

fun ChatViewModel.answerMetadata(strip: Boolean) {
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
fun ChatViewModel.cancelMetadata() {
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
private fun ChatViewModel.sendFile(jid: String, path: String, strip: Boolean) {
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
        val refusal = if (isRoom(jid)) TransferUi.groupRefusal(outcome)
                      else TransferUi.refusal(outcome)
        refusal?.let(state::note)
        revision++
    }
}

private fun ChatViewModel.discardStaged(path: String) {
    runCatching { java.io.File(path).delete() }
}

fun ChatViewModel.locationRefusal(jid: String): String? {
    observe()
    val offer = transferOffer(jid)
    return Location.shareRefusal(
        encrypted = offer !is TransferUi.Offer.NeedsEncryption,
        verified = offer is TransferUi.Offer.Available,
        group = isRoom(jid),
    )
}

fun ChatViewModel.canShareLocation(jid: String): Boolean = locationRefusal(jid) == null

fun ChatViewModel.openLocation(jid: String) {
    val refusal = locationRefusal(jid)
    if (refusal != null) {
        actionStatus = refusal
        return
    }
    actionStatus = null
    locationFor = ChatState.bare(jid)
    locationText = ""
    locationPin = null
    locationStatus = null
    gpsBusy = false
}

fun ChatViewModel.closeLocation() {
    locationFor = null
    locationPin = null
    locationText = ""
    locationStatus = null
    gpsBusy = false
}

fun ChatViewModel.typeLocation(text: String) {
    locationText = text.take(200)
    locationPin = Location.fromTyped(locationText)
    locationStatus = Location.typedStatus(locationText, locationPin)
}

fun ChatViewModel.gpsStarted() { gpsBusy = true; locationStatus = "Waiting for satellites… (outdoors works best)" }

fun ChatViewModel.gpsFinished(pin: Location.Pin?, failure: String?) {
    gpsBusy = false
    if (pin != null) {
        locationPin = pin
        locationText = pin.code
        locationStatus = null
    } else {
        locationStatus = failure ?: "No GPS fix."
    }
}

fun ChatViewModel.sendLocation() {
    val state = this.state ?: return
    val jid = locationFor ?: return
    val pin = locationPin ?: return
    locationRefusal(jid)?.let { locationStatus = it; return }
    val previous = state.draft(jid)
    val keepEditing = editing
    val keepReply = replyingTo
    editing = null
    replyingTo = null
    state.setDraft(jid, Location.body(pin))
    send(jid)
    state.setDraft(jid, previous)
    editing = keepEditing
    replyingTo = keepReply
    closeLocation()
}

fun ChatViewModel.requestFile(jid: String) {
    val hint = TransferUi.lockedHint(transferOffer(jid), isRoom(jid))
    if (hint == null) { actionStatus = null; pickFileFor = ChatState.bare(jid) }
    else actionStatus = hint
}

fun ChatViewModel.filePickerOpened() { pickFileFor = null }

fun ChatViewModel.requestVoice(jid: String) {
    val hint = TransferUi.lockedHint(transferOffer(jid), isRoom(jid))
    if (hint == null) { actionStatus = null; openVoiceSheet() }
    else actionStatus = hint
}

fun ChatViewModel.openVoiceSheet() {
    if (voiceSheet == null) voiceSheet = VoiceSheet.Choosing(voiceMode)
}

fun ChatViewModel.chooseVoice(mode: String) {
    if (mode !in VoiceNotes.MODES) return
    voiceMode = mode
    when (val s = voiceSheet) {
        is VoiceSheet.Choosing -> voiceSheet = s.copy(mode = mode)
        is VoiceSheet.Failed -> voiceSheet = VoiceSheet.Choosing(mode)
        else -> {}
    }
}

fun ChatViewModel.startVoiceNote(micGranted: Boolean) {
    val core = this.core ?: return
    val mode = voiceSheet?.mode ?: voiceMode
    if (!micGranted) {
        voiceSheet = VoiceSheet.Failed(mode, MicPermission.REFUSED)
        return
    }
    viewModelScope.launch {
        val started = withContext(Dispatchers.IO) { core.voiceNoteStart() }
        if (started != "ok") {
            voiceSheet = VoiceSheet.Failed(mode, VoiceNotes.errorText(started))
            return@launch
        }
        voiceSheet = VoiceSheet.Recording(mode)
        voicePoll?.cancel()
        voicePoll = viewModelScope.launch {
            while (voiceSheet is VoiceSheet.Recording) {
                val st = withContext(Dispatchers.IO) { core.voiceNoteStatus() }
                if (voiceSheet !is VoiceSheet.Recording) break
                if (!st.recording) {
                    // The limit was reached, or the microphone failed.
                    if (st.error.isNotEmpty()) {
                        voiceSheet = VoiceSheet.Failed(mode, VoiceNotes.errorText("no_microphone"))
                        core.voiceNoteCancel()
                    } else {
                        stopVoiceNote()
                    }
                    break
                }
                voiceSheet = VoiceSheet.Recording(mode, st.seconds, st.level)
                delay(200)
            }
        }
    }
}

fun ChatViewModel.stopVoiceNote(cacheDir: java.io.File? = voiceDir) {
    val core = this.core ?: return
    val sheet = voiceSheet as? VoiceSheet.Recording ?: return
    val dir = cacheDir ?: return
    voicePoll?.cancel()
    voiceSheet = VoiceSheet.Making(sheet.mode)
    viewModelScope.launch {
        val note = withContext(Dispatchers.IO) {
            core.voiceNoteStop(sheet.mode, java.io.File(dir, "outbox").also { it.mkdirs() }.absolutePath)
        }
        voiceSheet = if (note.error.isEmpty() && note.path.isNotEmpty()) {
            VoiceSheet.Ready(note.mode, note.path, note.seconds)
        } else {
            VoiceSheet.Failed(sheet.mode, VoiceNotes.errorText(note.error))
        }
    }
}

/**
 * Send the ready note. It travels as an encrypted file, but shows in the
 * chat as a voice-note bubble that plays, from a sealed copy the engine
 * keeps. The plaintext in the cache goes either way.
 */
fun ChatViewModel.sendVoiceNote(jid: String) {
    val ready = voiceSheet as? VoiceSheet.Ready ?: return
    val state = this.state ?: return
    val core = this.core ?: return
    voiceSheet = null
    val bare = ChatState.bare(jid)
    viewModelScope.launch {
        val (outcome, kept) = withContext(Dispatchers.IO) {
            val result = runCatching { core.sendVoiceNote(bare, ready.path) }
                .getOrDefault(FileOutcome.UNAVAILABLE to "")
            discardStaged(ready.path)
            result
        }
        if (outcome == FileOutcome.STARTED) {
            if (kept.isNotEmpty()) state.addOutgoingVoiceNote(bare, kept)
        } else {
            val refusal = if (isRoom(jid)) TransferUi.groupRefusal(outcome)
                          else TransferUi.refusal(outcome)
            refusal?.let(state::note)
        }
        revision++
    }
}

fun ChatViewModel.voiceWaveform(message: Message): VoiceWaveform? {
    val c = core ?: return null
    val s = state ?: return null
    if (message.voicePath.isEmpty() ||
        s.messages(message.conversationId).none { it.id == message.id && it.voicePath == message.voicePath })
        return null
    waveforms[message.voicePath]?.let { return it }
    return c.voiceNoteWaveform(message.voicePath)?.also { waveforms[message.voicePath] = it }
}

fun ChatViewModel.openVoiceNote(message: Message, directory: String): String? {
    val c = core ?: return null
    val s = state ?: return null
    if (message.voicePath.isEmpty() ||
        s.messages(message.conversationId).none { it.id == message.id && it.voicePath == message.voicePath })
        return null
    return c.openReceivedTo(message.voicePath, directory)
}

fun ChatViewModel.closeVoiceSheet() {
    val core = this.core
    val sheet = voiceSheet
    voiceSheet = null
    voicePoll?.cancel()
    viewModelScope.launch(Dispatchers.IO) {
        when (sheet) {
            is VoiceSheet.Recording -> core?.voiceNoteCancel()
            is VoiceSheet.Ready -> {
                core?.voiceNoteDiscard(sheet.path)
                discardStaged(sheet.path)
            }
            else -> {}
        }
    }
}

fun ChatViewModel.fileOffers(): List<OtrEvent.FileTransferChanged> {
    observe()
    return state?.pendingFileOffers ?: emptyList()
}

fun ChatViewModel.putAsideFileOffer(transferId: String) {
    state?.dismissFileOffer(transferId)
    revision++
}

fun ChatViewModel.acceptTransfer(transferId: String) {
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

fun ChatViewModel.declineTransfer(transferId: String) {
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
fun ChatViewModel.cancelTransfer(transferId: String) {
    val core = this.core ?: return
    viewModelScope.launch {
        withContext(Dispatchers.IO) {
            runCatching { core.cancelFile(transferId) }
        }
        revision++
    }
}

fun ChatViewModel.receivedFileDir(): String {
    observe()
    val core = this.core ?: return ""
    return runCatching { core.receivedFileDir() }.getOrDefault("")
}
