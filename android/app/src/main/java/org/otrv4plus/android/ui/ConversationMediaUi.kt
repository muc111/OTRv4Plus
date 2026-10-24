// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Location
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.MicPermission
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.HandshakeUi
import org.otrv4plus.android.crypto.Verification

// Files, calls and voice notes on the conversation screen. Split from ConversationScreen.kt;
// shared helpers there are internal for that reason.

/**
 * The attach control, and any transfer in flight.
 *
 * SAF, NOT A PATH THE APP INVENTED. `OpenDocument` hands back a content URI
 * the user chose and the system granted; it is copied into the app's own
 * cache and that path goes to the engine. The app never asks for storage
 * permissions and never walks the filesystem -- the user picks, and only
 * what they picked is readable.
 *
 * It decides nothing: [TransferUi.offer] says what may be offered and
 * [TransferUi.row] says what a transfer shows, both driven by
 * `TransferUiTest`.
 */
@Composable
internal fun TransferBar(model: ChatViewModel, jid: String, group: Boolean = false) {
    val context = LocalContext.current
    val transfers = model.transfers(jid)
    val offer = model.transferOffer(jid)

    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        // Copied rather than handed over as a URI. The engine takes a path,
        // and a content URI's grant is scoped to this Activity result -- it
        // would be gone by the time a background thread read the last chunk.
        val staged = runCatching { stageForSending(context, uri) }.getOrNull()
        // Examined before anything leaves: a photo carries where and when it
        // was taken, and the user decides whether that goes with it.
        if (staged != null) model.prepareFile(jid, staged)
    }

    // The composer's 📎 asked for the picker (the launcher lives here).
    val wanted = model.pickFileFor
    LaunchedEffect(wanted) {
        if (wanted != null && wanted == ChatState.bare(jid)) {
            model.filePickerOpened()
            picker.launch(arrayOf("*/*"))
        }
    }

    model.pendingMetadata?.takeIf { it.jid == ChatState.bare(jid) }?.let { pending ->
        AlertDialog(
            // Dismissing is not consent to either option: nothing is sent.
            onDismissRequest = { model.cancelMetadata() },
            title = { Text("Hidden information") },
            text = { Text(pending.question) },
            confirmButton = {
                TextButton(onClick = { model.answerMetadata(strip = true) }) {
                    Text(MetadataChoice.STRIP)
                }
            },
            dismissButton = {
                Row {
                    TextButton(onClick = { model.cancelMetadata() }) {
                        Text(MetadataChoice.CANCEL)
                    }
                    TextButton(onClick = { model.answerMetadata(strip = false) }) {
                        Text(MetadataChoice.KEEP)
                    }
                }
            },
        )
    }

    VoiceNoteSheet(model, jid)
    LocationSheet(model)

    model.viewing?.let { file ->
        FileViewerDialog(container = file.path, name = file.filename,
                         materialize = { dir -> model.openReceivedTo(file.path, dir) },
                         inspect = { plain -> model.inspectViewed(plain) },
                         onClose = { model.closeViewer() })
    }

    for (transfer in transfers) {
        val row = model.transferRow(transfer)
        // An ended transfer is a persisted line in the conversation already
        // (`TransferUi.statusLine`); a second, live copy of it here would say
        // the same thing twice and outlive nothing. The one exception is a
        // received file the engine VERIFIED: it gets an explicit "Open".
        if (row.finished) {
            if (model.canOpen(transfer)) {
                Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
                    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Text("${row.phase} · ${transfer.filename.ifBlank { "a file" }} — hashes verified",
                             modifier = Modifier.weight(1f),
                             style = MaterialTheme.typography.bodySmall,
                             maxLines = 1, overflow = TextOverflow.Ellipsis)
                        TextButton(onClick = { model.openReceived(transfer) }) { Text("Open") }
                    }
                }
            }
            continue
        }
        Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp,
                                                vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    // The phase in one word, then the sentence: the state is
                    // said in text, never by colour or a bar alone.
                    Text(row.phase,
                         style = MaterialTheme.typography.labelMedium,
                         fontWeight = FontWeight.SemiBold)
                    Text(row.label,
                         maxLines = 2,
                         overflow = TextOverflow.Ellipsis,
                         style = MaterialTheme.typography.bodySmall)
                    if (row.showsProgress) {
                        LinearProgressIndicator(
                            progress = { row.progress },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    if (row.detail.isNotBlank()) {
                        Text(row.detail,
                             style = MaterialTheme.typography.labelSmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                if (row.canAccept) {
                    TextButton(onClick = {
                        model.acceptTransfer(transfer.id)
                    }) { Text("Accept") }
                }
                if (row.canDecline) {
                    // Decline answers an offer; Cancel stops one under way.
                    // Two operations in the engine, so two calls here.
                    TextButton(onClick = {
                        if (row.canAccept) model.declineTransfer(transfer.id)
                        else model.cancelTransfer(transfer.id)
                    }) { Text(if (row.canAccept) "Decline" else "Cancel") }
                }
            }
        }
    }

    when (offer) {
        is TransferUi.Offer.Available ->
            TextButton(onClick = { picker.launch(arrayOf("*/*")) }) {
                Text(if (group) "Send a file to the group" else "Send a file")
            }
        is TransferUi.Offer.NeedsVerification ->
            TextButton(enabled = false, onClick = {}) {
                Text(if (group) "Send a file — every member must be verified first"
                     else "Send a file — SMP verification required")
            }
        // The plaintext banner above already offers the handshake; a second
        // disabled control would be noise.
        is TransferUi.Offer.NeedsEncryption -> Unit
    }
}

/**
 * Copy a picked document into this app's cache and return its path.
 *
 * INSIDE THE APP'S OWN CACHE, never a shared directory: what is copied here
 * is about to be encrypted and sent, and leaving a readable duplicate in
 * Downloads would undo the point of sending it privately. The engine seals
 * from this path and the copy is the user's own file, already on the device.
 */
internal fun stageForSending(context: android.content.Context,
                            uri: android.net.Uri): String {
    val name = displayName(context, uri)
    val outbox = java.io.File(context.cacheDir, "outbox").apply { mkdirs() }
    val target = java.io.File(outbox, name)
    context.contentResolver.openInputStream(uri).use { input ->
        requireNotNull(input)
        target.outputStream().use { output -> input.copyTo(output) }
    }
    return target.absolutePath
}

/**
 * The call control, and the call.
 *
 * ONE COMPOSABLE FOR BOTH because they are one thing to the user: the place
 * a call is started is the place it is shown. It decides nothing --
 * [CallUi.offer] says what may be offered and [CallUi.phase] says what a
 * call has got to, both driven by `CallUiTest`.
 *
 * NOTHING HERE CLAIMS A CALL IS SECURE. Every word comes from a [CallState]
 * the engine reported, and the engine reaches ACTIVE only after mutual key
 * confirmation. There is no optimistic "connected" that outlives its answer.
 */
@Composable
internal fun CallBar(model: ChatViewModel, jid: String) {
    val phase = model.callPhase(jid)
    val gateAndReason = model.callGate(jid)
    val context = LocalContext.current

    // Android's third fact, which it does not provide: whether WE have asked.
    // Without it "never asked" and "permanently denied" are the same two
    // flags, and confusing them means either never asking or asking forever
    // into a dialog that no longer appears. Survives recomposition and
    // process death via rememberSaveable.
    var askedBefore by rememberSaveable { mutableStateOf(false) }
    var explain by rememberSaveable { mutableStateOf(false) }
    var settings by rememberSaveable { mutableStateOf(false) }
    // What the pending grant is FOR. A launcher result carries no context of
    // its own, and answering a call when the user asked to place one would
    // be acting on the wrong intent.
    var answering by rememberSaveable { mutableStateOf(false) }

    fun granted(): Boolean =
        ContextCompat.checkSelfPermission(
            context, Manifest.permission.RECORD_AUDIO) ==
            PackageManager.PERMISSION_GRANTED

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { allowed ->
        askedBefore = true
        if (allowed) {
            if (answering) model.answerCall(jid, true)
            else model.startCall(jid, true)
        }
        answering = false
    }

    fun act(answer: Boolean) {
        answering = answer
        if (granted()) {
            if (answer) model.answerCall(jid, true) else model.startCall(jid, true)
            return
        }
        val activity = context as? Activity
        val rationale = activity != null &&
            ActivityCompat.shouldShowRequestPermissionRationale(
                activity, Manifest.permission.RECORD_AUDIO)
        when (MicPermission.decide(
            MicPermission.State(false, rationale, askedBefore))) {
            MicPermission.Decision.Proceed ->
                if (answer) model.answerCall(jid, true)
                else model.startCall(jid, true)
            MicPermission.Decision.Request ->
                launcher.launch(Manifest.permission.RECORD_AUDIO)
            MicPermission.Decision.ExplainThenRequest -> explain = true
            // The dialog is spent. Asking again would do nothing at all, so
            // the app says where to go instead of pretending to try.
            MicPermission.Decision.OpenSettings -> settings = true
        }
    }

    if (phase.active) {
        Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 12.dp,
                                                vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Text(phase.label,
                         style = MaterialTheme.typography.bodyMedium)
                    if (phase.showsDuration) {
                        Text(model.callElapsed(jid),
                             style = MaterialTheme.typography.labelSmall)
                    }
                }
                if (phase.canAnswer) {
                    Button(onClick = { act(answer = true) }) { Text("Answer") }
                }
                if (phase.canEnd) {
                    OutlinedButton(onClick = { model.endCall(jid) }) {
                        Text(if (phase.canAnswer) "Reject" else "End")
                    }
                }
            }
        }
    } else {
        // ONE GATE, FROM THE ENGINE, and never hidden without a word: every
        // state that is not "available" shows the control disabled with its
        // reason. The previous version hid it for anything it read as
        // plaintext -- and it read every peer off the roster as plaintext --
        // so "the call button did not appear" had no visible explanation.
        val (gate, reason) = gateAndReason
        val control = CallUi.control(gate, reason)
        if (control.visible) {
            // A phone, coloured by whether the call's I2P path is built yet.
            Row(Modifier.padding(horizontal = 12.dp, vertical = 4.dp)) {
                PhoneButton(model.callPath, model.callPathSecondsLeft,
                            enabled = control.enabled, disabledReason = control.label,
                            description = "Call") { act(answer = false) }
            }
        }
    }

    if (explain) {
        AlertDialog(
            onDismissRequest = { explain = false },
            title = { Text("Microphone") },
            text = { Text(MicPermission.RATIONALE) },
            confirmButton = {
                TextButton(onClick = {
                    explain = false
                    launcher.launch(Manifest.permission.RECORD_AUDIO)
                }) { Text("Continue") }
            },
            dismissButton = {
                TextButton(onClick = { explain = false }) { Text("Not now") }
            },
        )
    }

    if (settings) {
        AlertDialog(
            onDismissRequest = { settings = false },
            title = { Text("Microphone") },
            text = { Text(MicPermission.PERMANENTLY_DENIED) },
            confirmButton = {
                TextButton(onClick = {
                    settings = false
                    context.startActivity(
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                               Uri.fromParts("package", context.packageName,
                                             null)))
                }) { Text("Open settings") }
            },
            dismissButton = {
                TextButton(onClick = { settings = false }) { Text("Close") }
            },
        )
    }
}

/**
 * A voice note in the chat, sent or received: Play/Stop, its waveform, and
 * the time. The bars fill in as it plays (owner, 2026-10-20: "a visual of the
 * playback ... within the bubble"). The sealed copy is decrypted to the cache
 * only while it plays, and deleted after; the waveform is read in memory.
 */
@Composable
internal fun VoiceNoteBubble(message: Message, model: ChatViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var player by remember(message.id) { mutableStateOf<android.media.MediaPlayer?>(null) }
    var transient by remember(message.id) { mutableStateOf<java.io.File?>(null) }
    var failed by remember(message.id) { mutableStateOf(false) }
    var busy by remember(message.id) { mutableStateOf(false) }
    var position by remember(message.id) { mutableStateOf(0.0) }
    val wave by produceState<org.otrv4plus.android.chat.VoiceWaveform?>(null, message.id) {
        value = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            runCatching { model.voiceWaveform(message) }.getOrNull()
        }
    }
    fun stop() {
        player?.let { runCatching { it.stop() }; it.release() }
        player = null
        position = 0.0
        transient?.delete()
        transient = null
    }
    DisposableEffect(message.id) { onDispose { stop() } }
    LaunchedEffect(player) {
        val p = player ?: return@LaunchedEffect
        while (player === p) {
            position = runCatching { p.currentPosition / 1000.0 }.getOrDefault(position)
            kotlinx.coroutines.delay(50)
        }
    }
    val seconds = wave?.seconds ?: 0.0
    val bars = wave?.bars ?: org.otrv4plus.android.chat.VoiceNotes.placeholderBars()
    val played = if (player != null) org.otrv4plus.android.chat.VoiceNotes.playedBars(position, seconds, bars.size) else 0
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        if (player != null) {
            FilledTonalButton(onClick = { stop() }, contentPadding = PaddingValues(horizontal = 12.dp)) {
                Text("Stop")
            }
        } else {
            FilledTonalButton(enabled = !busy, contentPadding = PaddingValues(horizontal = 12.dp), onClick = {
                busy = true
                failed = false
                scope.launch {
                    val dir = java.io.File(context.cacheDir, "voice-play").absolutePath
                    val path = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        runCatching { model.openVoiceNote(message, dir) }.getOrNull()
                    }
                    busy = false
                    val file = path?.let { java.io.File(it) }
                    val p = file?.let { f ->
                        runCatching {
                            android.media.MediaPlayer().apply { setDataSource(f.absolutePath); prepare() }
                        }.getOrNull()
                    }
                    if (p == null) {
                        file?.delete()
                        failed = true
                        return@launch
                    }
                    transient = file
                    player = p
                    p.setOnCompletionListener { stop() }
                    p.start()
                }
            }) { Text(if (busy) "…" else "Play") }
        }
        // Sized by width, height from it: no fixed height in the chat screen
        // (test_android_chat_layout), and it shrinks on a narrow phone.
        VoiceWaveformBars(bars, played, outgoing = message.outgoing,
                          modifier = Modifier.weight(1f, fill = false)
                              .widthIn(min = 96.dp, max = 160.dp).aspectRatio(5.5f))
        Text(org.otrv4plus.android.chat.VoiceNotes.clock(if (player != null) position else seconds),
             style = MaterialTheme.typography.labelSmall)
    }
    if (failed) {
        Text("This voice note could not be played.",
             style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.error)
    }
}

/** The bars: played ones in the accent colour, the rest muted. */
@Composable
internal fun VoiceWaveformBars(bars: List<Float>, played: Int, outgoing: Boolean, modifier: Modifier) {
    val on = if (outgoing) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.primary
    val off = on.copy(alpha = 0.35f)
    androidx.compose.foundation.Canvas(modifier.semantics { contentDescription = "Voice note waveform" }) {
        if (bars.isEmpty()) return@Canvas
        val step = size.width / bars.size
        val w = (step * 0.6f).coerceAtLeast(1f)
        bars.forEachIndexed { i, level ->
            val h = (size.height * level.coerceIn(0.08f, 1f))
            drawRoundRect(
                color = if (i < played) on else off,
                topLeft = androidx.compose.ui.geometry.Offset(i * step + (step - w) / 2, (size.height - h) / 2),
                size = androidx.compose.ui.geometry.Size(w, h),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(w / 2, w / 2),
            )
        }
    }
}

/**
 * "Incoming file": who, what and how big, with Accept and Decline.
 *
 * Shown over whatever screen is open, because an offer waits on the user and
 * the conversation it belongs to may not be the one in front of them. Never
 * answered for them: dismissing is "not now", and the offer stays in the
 * conversation with its own Accept and Decline.
 */
@Composable
fun IncomingFileDialog(model: ChatViewModel) {
    val offer = model.fileOffers().firstOrNull() ?: return
    AlertDialog(
        onDismissRequest = { model.putAsideFileOffer(offer.transferId) },
        title = { Text(TransferUi.promptTitle()) },
        text = {
            Text(TransferUi.promptBody(
                model.conversation(offer.peer).displayName,
                offer.filename, offer.size))
        },
        confirmButton = {
            TextButton(onClick = { model.acceptTransfer(offer.transferId) }) {
                Text("Accept")
            }
        },
        dismissButton = {
            TextButton(onClick = { model.declineTransfer(offer.transferId) }) {
                Text("Decline")
            }
        },
    )
}
