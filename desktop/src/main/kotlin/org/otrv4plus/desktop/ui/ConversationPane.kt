// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Place
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.PlainTooltip
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.Location
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.chat.RoomPeople
import org.otrv4plus.android.chat.VoiceNotes
import org.otrv4plus.android.chat.VoiceSheet
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.DeniableChat
import org.otrv4plus.android.crypto.HandshakeUi
import org.otrv4plus.android.crypto.SecurityLevel
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.Verification
import org.otrv4plus.desktop.AppModel
import java.text.SimpleDateFormat
import java.util.Date

@Composable
fun ConversationPane(model: AppModel, jid: String) {
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    val c = model.conversation(jid)
    val isRoom = model.chat.isRoom(jid)
    var pendingFile by remember(jid) { mutableStateOf<String?>(null) }
    // Accepted, keys not here yet: a secure group being set up, never an
    // ordinary room (device report, 2026-10-16). Its panels wait for it.
    val joining = isRoom && model.chat.isJoiningRoom(jid)
    val secure = isRoom && model.chat.isSecureRoom(jid) && !joining
    var showMembers by remember(jid) { mutableStateOf(true) }
    var locationOpen by remember(jid) { mutableStateOf(false) }
    LaunchedEffect(jid, secure) { if (secure) model.refreshGroupNow(jid) }
    // Build and keep the next call's I2P path while this conversation is
    // open and a call could be made from it (10 minutes after the last ask).
    LaunchedEffect(jid, isRoom, secure) {
        while (true) {
            model.refreshCallPath(if (isRoom) secure else model.callControl.enabled)
            kotlinx.coroutines.delay(if (model.callPath == CallUi.Readiness.READY) 15_000L else 4_000L)
        }
    }

    Row(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).fillMaxHeight()) {
            Header(model, jid, isRoom, onMembers = if (isRoom && !joining) ({ showMembers = !showMembers }) else null) {
                path -> pendingFile = path
            }
            HorizontalDivider()
            if (!isRoom) {
                VerificationProgress(model, jid)
                CallBar(model, jid)
                HandshakeView(model.handshake)
            }
            if (joining) {
                Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(org.otrv4plus.android.chat.GroupText.JOINING_HEADER,
                         style = MaterialTheme.typography.labelSmall,
                         color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (secure) GroupBar(model, jid)
            FileOffers(model, jid)
            Messages(model, jid, isRoom, Modifier.weight(1f))
            Composer(model, jid, isRoom, c.security, onLocation = { locationOpen = true })
        }
        if (secure && showMembers) {
            VerticalDivider()
            GroupMembersPanel(model, jid, Modifier.width(300.dp))
        } else if (isRoom && !secure && !joining && showMembers) {
            VerticalDivider()
            RoomPeoplePanel(model, jid, Modifier.width(300.dp))
        }
    }

    if (!isRoom) model.verificationPrompt(jid)?.let { prompt -> SmpDialog(model, jid, prompt) }
    model.voiceSheet?.let { VoiceNoteDialog(model, jid, it) }
    if (locationOpen) LocationDialog(model, jid, onClose = { locationOpen = false })
    model.viewedFile?.let { file ->
        FileViewerDialog(container = file.path, name = file.filename,
                         materialize = { dir -> model.openReceivedTo(file.path, dir) },
                         inspect = { plain -> model.inspectViewed(plain) },
                         save = { destination -> model.saveViewedTo(file.path, destination) },
                         onClose = { model.closeViewer() })
    }
    pendingFile?.let { path ->
        MetadataDialog(path, onChoice = { strip ->
            pendingFile = null
            if (strip != null) model.sendFile(jid, path, strip)
        })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Header(model: AppModel, jid: String, isRoom: Boolean, onMembers: (() -> Unit)?,
                   onFile: (String) -> Unit) {
    val c = model.conversation(jid)
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically) {
        // The avatar and name open the contact's profile (vCard), read-only.
        val open = if (isRoom) Modifier else Modifier.clickable { model.viewProfile(jid) }
        Box(open) { Avatar(c.displayName.ifBlank { jid }, c.presence, image = model.avatar(jid)) }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f).then(open)) {
            Text(c.displayName.ifBlank { jid }, style = MaterialTheme.typography.titleMedium,
                 fontWeight = FontWeight.SemiBold)
            if (isRoom) {
                Text(if (model.chat.isSecureRoom(jid)) org.otrv4plus.android.chat.GroupText.securityLine(
                         org.otrv4plus.android.chat.GroupText.verifiedCount(model.groupMembers[jid].orEmpty()).first,
                         model.groupMembers[jid].orEmpty().size)
                     else "Room — not end-to-end encrypted",
                     style = MaterialTheme.typography.bodySmall,
                     color = if (model.chat.isSecureRoom(jid)) MaterialTheme.colorScheme.primary
                             else MaterialTheme.colorScheme.error)
            } else {
                val level = SecurityLevel.of(c.security)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(securityIcon(c.security), null, Modifier.size(14.dp), tint = securityColour(c.security))
                    Spacer(Modifier.width(4.dp))
                    Text(level.label, style = MaterialTheme.typography.bodySmall, color = securityColour(c.security))
                    if (model.isTyping(jid)) {
                        Spacer(Modifier.width(10.dp))
                        Text("typing\u2026", style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.primary)
                    }
                }
            }
        }
        if (!isRoom) {
            if (c.security == SecurityState.PLAINTEXT) {
                FilledTonalButton(onClick = { model.startEncryption(jid) }) {
                    Icon(Icons.Filled.Lock, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                    Text("Encrypt")
                }
                Spacer(Modifier.width(8.dp))
            }
            when (Verification.offer(c.security, c.smp)) {
                Verification.Offer.VERIFY -> OutlinedButton(onClick = { model.verifyFor = jid }) {
                    Icon(Icons.Filled.VerifiedUser, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                    Text("Verify")
                }
                Verification.Offer.ANSWERING -> Button(onClick = { model.verifyFor = jid }) { Text("Answer verification") }
                Verification.Offer.IN_PROGRESS -> TextButton(onClick = { model.abortVerification(jid) }) {
                    Text("Verifying… cancel")
                }
                Verification.Offer.VERIFIED -> Text("Verified", color = VerifiedBlue,
                                                    style = MaterialTheme.typography.labelLarge)
                Verification.Offer.HIDDEN -> {}
            }
            Spacer(Modifier.width(8.dp))
            val control = model.callControl
            if (control.visible) {
                // A phone coloured by the call path: red, amber, green.
                val tip = if (control.enabled) CallUi.readinessLabel(model.callPath, model.callPathSecondsLeft)
                          else control.label
                TooltipBox(TooltipDefaults.rememberPlainTooltipPositionProvider(),
                           tooltip = { PlainTooltip { Text(tip) } },
                           state = rememberTooltipState()) {
                    FilledIconButton(onClick = { model.call(jid) },
                                     enabled = control.enabled && model.callPhase == CallState.IDLE,
                                     colors = androidx.compose.material3.IconButtonDefaults.filledIconButtonColors(
                                         containerColor = androidx.compose.ui.graphics.Color(
                                             CallUi.readinessColour(model.callPath)),
                                         contentColor = androidx.compose.ui.graphics.Color.White)) {
                        Icon(Icons.Filled.Call, tip)
                    }
                }
            }
        }
        if (!isRoom && model.blockingSupported) {
            var askBlock by remember { mutableStateOf(false) }
            if (model.isBlocked(jid)) {
                TextButton(onClick = { model.unblock(jid) }) { Text("Unblock") }
            } else {
                TextButton(onClick = { askBlock = true }) {
                    Text("Block", color = MaterialTheme.colorScheme.error)
                }
            }
            if (askBlock) {
                var report by remember { mutableStateOf(false) }
                androidx.compose.material3.AlertDialog(
                    onDismissRequest = { askBlock = false },
                    title = { Text("Block ${c.displayName.ifBlank { jid }}?") },
                    text = {
                        Column {
                            Text("Their messages, calls and files stop reaching every device of this " +
                                 "account, and they no longer see when you are online. They are not told.")
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                androidx.compose.material3.Checkbox(checked = report, onCheckedChange = { report = it })
                                Text("Also report as spam to the server")
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { askBlock = false; model.block(jid, if (report) "spam" else "") }) {
                            Text("Block", color = MaterialTheme.colorScheme.error)
                        }
                    },
                    dismissButton = { TextButton(onClick = { askBlock = false }) { Text("Cancel") } },
                )
            }
        }
        if (DeniableChat.offered(c.security, isRoom)) DeniableButton(model, jid)
        if (onMembers != null) {
            TextButton(onClick = onMembers) {
                Icon(Icons.Filled.Groups, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                Text(if (isRoom && !model.chat.isSecureRoom(jid)) "People" else "Members")
            }
        }
        val offer = if (isRoom) null else TransferUi.offer(c.security)
        TooltipBox(TooltipDefaults.rememberPlainTooltipPositionProvider(),
                   tooltip = { PlainTooltip { Text(if (offer is TransferUi.Offer.Available || isRoom) "Send a file"
                                                   else "Verify this contact to send files") } },
                   state = rememberTooltipState()) {
            IconButton(onClick = { pickFile("Send a file")?.let(onFile) },
                       enabled = isRoom && model.chat.isSecureRoom(jid) || offer is TransferUi.Offer.Available) {
                Icon(Icons.Filled.AttachFile, "Send a file")
            }
        }
        TooltipBox(TooltipDefaults.rememberPlainTooltipPositionProvider(),
                   tooltip = { PlainTooltip { Text("Voice note, in a synthetic voice") } },
                   state = rememberTooltipState()) {
            IconButton(onClick = { model.openVoiceSheet() },
                       enabled = isRoom && model.chat.isSecureRoom(jid) || offer is TransferUi.Offer.Available) {
                Icon(Icons.Filled.Mic, "Voice note")
            }
        }
    }
}


@Composable
private fun CallBar(model: AppModel, jid: String) {
    val state = model.callPhase
    if (state == CallState.IDLE || state == CallState.ENDED) return
    val phase = CallUi.phase(state, if (state == CallState.RINGING) CallUi.Direction.INCOMING else CallUi.Direction.NONE)
    Surface(color = if (phase.connected) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Call, null)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(phase.label, fontWeight = FontWeight.Medium)
                if (phase.connected) Text(CallUi.elapsed(model.callSeconds), style = MaterialTheme.typography.bodySmall)
            }
            if (phase.canAnswer) {
                Button(onClick = { model.answer(jid) }) { Text("Answer") }
                Spacer(Modifier.width(8.dp))
            }
            if (phase.canEnd) {
                Button(onClick = { model.hangUp(jid) },
                       colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error,
                                                            contentColor = MaterialTheme.colorScheme.onError)) {
                    Icon(Icons.Filled.CallEnd, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                    Text(if (phase.canAnswer) "Decline" else "Hang up")
                }
            }
        }
    }
}

@Composable
private fun HandshakeView(status: HandshakeUi.Status) {
    val view = HandshakeUi.view(status) ?: return
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(view.title, style = MaterialTheme.typography.labelLarge)
        Text(view.detail + if (view.elapsed.isNotBlank()) " · ${view.elapsed}" else "",
             style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        LinearProgressIndicator(progress = { view.progress }, modifier = Modifier.fillMaxWidth().padding(top = 6.dp))
    }
}

@Composable
private fun FileOffers(model: AppModel, jid: String) {
    for (offer in model.chat.pendingFileOffers.filter { it.peer.substringBefore('/') == jid }) {
        Surface(color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(TransferUi.promptTitle(), fontWeight = FontWeight.Medium)
                    Text(TransferUi.promptBody(offer.peer, offer.filename, offer.size),
                         style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = { model.declineFile(offer.transferId) }) { Text("Decline") }
                Button(onClick = { model.acceptFile(offer.transferId) }) { Text("Accept") }
            }
        }
    }
    for (t in model.transfers.filter { it.peer.substringBefore('/') == jid }) {
        val row = TransferUi.row(t)
        // Voice notes are bubbles in the chat ([VoiceNoteRow]), not files.
        if (VoiceNotes.looksLikeNote(t.filename)) continue
        if (row.finished && !row.failed) continue
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
            Text("${t.filename} — ${row.label}", style = MaterialTheme.typography.bodySmall,
                 color = if (row.failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            if (row.showsProgress) {
                LinearProgressIndicator(progress = { row.progress }, modifier = Modifier.fillMaxWidth())
                Text(row.detail, style = MaterialTheme.typography.labelSmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/**
 * An ordinary room's people (owner, 2026-10-21: "click on the user to add to
 * roster ... if we have 100 people in this room we need a better way").
 * Search, sections by role with counts, and on each row Add / Message --
 * only for someone whose address the room revealed (RoomPeople).
 */
@Composable
private fun RoomPeoplePanel(model: AppModel, room: String, modifier: Modifier = Modifier) {
    LaunchedEffect(room) { if (model.roomPeople[room] == null) model.refreshRoomPeople(room) }
    var query by remember(room) { mutableStateOf("") }
    val people = model.roomPeople[room].orEmpty()
    Column(modifier.fillMaxHeight().padding(start = 12.dp, top = 12.dp, end = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(when {
                    room in model.roomPeopleFailed && people.isEmpty() -> "Could not ask the room who is here."
                    model.roomPeople[room] == null -> "Asking the room who is here…"
                    else -> RoomPeople.summary(people)
                 }, Modifier.weight(1f), style = MaterialTheme.typography.titleSmall,
                 color = MaterialTheme.colorScheme.primary)
            TextButton(onClick = { model.refreshRoomPeople(room) }) { Text("Refresh") }
        }
        if (people.size >= RoomPeople.SEARCH_FROM) {
            OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth().padding(end = 8.dp),
                              singleLine = true, placeholder = { Text("Search people") })
        }
        val me = model.chat.account.bareJid
        ScrollLazyColumn(Modifier.weight(1f)) {
            for (section in RoomPeople.sections(people, query)) {
                item(key = "h:" + section.title) {
                    Text(section.title, Modifier.padding(top = 10.dp, bottom = 2.dp),
                         style = MaterialTheme.typography.labelLarge,
                         color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                items(section.people, key = { "p:" + it.nick }) { p ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(p.nick, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(p.jid.ifBlank { RoomPeople.NO_ADDRESS_HINT },
                                 style = MaterialTheme.typography.labelSmall, maxLines = 1,
                                 overflow = TextOverflow.Ellipsis,
                                 color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        when (RoomPeople.action(p, me) { model.chat.isContact(it) }) {
                            RoomPeople.Action.ADD -> {
                                TextButton(onClick = { model.addContact(p.jid) }) { Text("Add") }
                                TextButton(onClick = { model.open(p.jid) }) { Text("Message") }
                            }
                            RoomPeople.Action.MESSAGE ->
                                TextButton(onClick = { model.open(p.jid) }) { Text("Message") }
                            RoomPeople.Action.SELF ->
                                Text("you", style = MaterialTheme.typography.labelSmall,
                                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                            RoomPeople.Action.NO_ADDRESS -> {}
                        }
                    }
                }
            }
        }
    }
}

/** A voice note, sent or received: Play/Stop, its waveform filling in as it
 *  plays, and the time (owner, 2026-10-20). The engine decrypts the sealed
 *  copy into memory and parses it as untrusted audio. */
@Composable
private fun VoiceNoteRow(m: Message, model: AppModel) {
    LaunchedEffect(m.voicePath) { model.loadWaveform(m.voicePath) }
    val wave = model.waveforms[m.voicePath]
    val playing = model.playingNote == m.voicePath
    val bars = wave?.bars ?: VoiceNotes.placeholderBars()
    val seconds = wave?.seconds ?: 0.0
    val played = if (playing) VoiceNotes.playedBars(model.playPosition, seconds, bars.size) else 0
    val fg = if (m.outgoing) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.primary
    Row(verticalAlignment = Alignment.CenterVertically) {
        if (playing) {
            FilledTonalButton(onClick = { model.stopPlaying() }) { Text("Stop") }
        } else {
            FilledTonalButton(onClick = { model.playVoiceNote(m.voicePath) }) { Text("Play") }
        }
        Spacer(Modifier.width(10.dp))
        androidx.compose.foundation.Canvas(Modifier.width(220.dp).height(32.dp)) {
            val step = size.width / bars.size
            val w = (step * 0.6f).coerceAtLeast(1f)
            bars.forEachIndexed { i, level ->
                val h = size.height * level.coerceIn(0.08f, 1f)
                drawRoundRect(
                    color = if (i < played) fg else fg.copy(alpha = 0.35f),
                    topLeft = androidx.compose.ui.geometry.Offset(i * step + (step - w) / 2, (size.height - h) / 2),
                    size = androidx.compose.ui.geometry.Size(w, h),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(w / 2, w / 2),
                )
            }
        }
        Spacer(Modifier.width(10.dp))
        Text(VoiceNotes.clock(if (playing) model.playPosition else seconds),
             style = MaterialTheme.typography.labelSmall,
             color = if (m.outgoing) MaterialTheme.colorScheme.onPrimaryContainer
                     else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private val timeFormat = SimpleDateFormat("HH:mm")

@Composable
private fun Messages(model: AppModel, jid: String, isRoom: Boolean, modifier: Modifier) {
    val messages = model.messages(jid)
    val listState = rememberLazyListState()
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1) }
    ScrollLazyColumn(modifier.fillMaxWidth().padding(start = 12.dp), state = listState,
               verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item { Spacer(Modifier.padding(4.dp)) }
        items(messages, key = { it.id }) { m -> Bubble(m, isRoom, model) }
        item { Spacer(Modifier.padding(4.dp)) }
    }
}

@Composable
private fun Bubble(m: Message, isRoom: Boolean, model: AppModel) {
    if (m.security == SecurityLabel.SYSTEM) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(m.body, style = MaterialTheme.typography.labelSmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant,
                 modifier = Modifier.clip(RoundedCornerShape(8.dp))
                     .background(MaterialTheme.colorScheme.surfaceVariant)
                     .padding(horizontal = 10.dp, vertical = 4.dp))
            // A received file's line IS a system line ("Received photo.jpg"),
            // so its Open lives here (device report, 2026-10-25: the viewer
            // never showed -- the button was only on ordinary bubbles).
            if (model.canOpenLine(m)) {
                TextButton(onClick = { model.openLine(m) }) { Text("Open") }
            }
        }
        return
    }
    val mine = m.outgoing
    Box(Modifier.fillMaxWidth(), contentAlignment = if (mine) Alignment.CenterEnd else Alignment.CenterStart) {
        Column(Modifier.widthIn(max = 560.dp)
                .clip(RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp,
                                         bottomStart = if (mine) 16.dp else 4.dp,
                                         bottomEnd = if (mine) 4.dp else 16.dp))
                .background(if (mine) MaterialTheme.colorScheme.primaryContainer
                            else MaterialTheme.colorScheme.surfaceVariant)
                .padding(horizontal = 12.dp, vertical = 8.dp)) {
            if (isRoom && !mine && m.sender.isNotBlank()) {
                Text(m.sender, style = MaterialTheme.typography.labelMedium,
                     color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold)
            }
            if (m.replyTo.isNotEmpty() && !m.retracted) {
                Text("\u21A9 " + m.replyPreview.ifBlank { "an earlier message" },
                     style = MaterialTheme.typography.labelSmall, maxLines = 2,
                     color = MaterialTheme.colorScheme.onSurfaceVariant,
                     modifier = Modifier.padding(bottom = 4.dp))
            }
            if (m.retracted) {
                Text("Message deleted", style = MaterialTheme.typography.bodyMedium,
                     color = MaterialTheme.colorScheme.onSurfaceVariant,
                     fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)
            } else {
                val pin = if (m.body.startsWith(Location.MARKER)) Location.parse(m.body) else null
                if (m.voicePath.isNotEmpty()) VoiceNoteRow(m, model)
                else if (pin != null) LocationCard(pin)
                else {
                    SelectionContainer {
                        Text(m.body, color = if (mine) MaterialTheme.colorScheme.onPrimaryContainer
                                             else MaterialTheme.colorScheme.onSurface)
                    }
                    // A received, verified file opens from its line, here and
                    // after a restart, in the in-app viewer (as on Android).
                    if (model.canOpenLine(m)) {
                        TextButton(onClick = { model.openLine(m) }) { Text("Open") }
                    }
                }
            }
            if (m.reactions.isNotEmpty()) {
                val counts = m.reactions.values.flatten().groupingBy { it }.eachCount()
                Row(Modifier.padding(top = 2.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    counts.forEach { (emoji, n) ->
                        Text(if (n > 1) "$emoji $n" else emoji,
                             modifier = Modifier.clip(RoundedCornerShape(10.dp))
                                 .background(if (emoji in m.reactions["me"].orEmpty())
                                                 MaterialTheme.colorScheme.secondaryContainer
                                             else MaterialTheme.colorScheme.surface)
                                 .clickable { model.react(m, emoji) }
                                 .padding(horizontal = 6.dp, vertical = 1.dp))
                    }
                }
            }
            Row(Modifier.align(Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                when (m.security) {
                    SecurityLabel.ENCRYPTED -> Icon(Icons.Filled.Lock, "Encrypted", Modifier.size(11.dp),
                                                    tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    SecurityLabel.PLAINTEXT -> Text("not encrypted ", style = MaterialTheme.typography.labelSmall,
                                                    color = MaterialTheme.colorScheme.error)
                    else -> {}
                }
                Spacer(Modifier.width(4.dp))
                if (model.canAct(m)) BubbleActions(m, model)
                Text(timeFormat.format(Date(m.at)) + (if (m.edited) " · edited" else "") + when (m.sendState) {
                    SendState.SENDING -> " · sending"
                    SendState.QUEUED -> " · queued until encrypted"
                    SendState.FAILED -> " · not sent"
                    SendState.SENT -> " · \u2713"
                    SendState.DELIVERED -> " · \u2713\u2713 delivered"
                    SendState.READ -> " · \u2713\u2713 read"
                    else -> ""
                }, style = MaterialTheme.typography.labelSmall,
                   color = if (m.sendState == SendState.FAILED) MaterialTheme.colorScheme.error
                           else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

private val QUICK_REACTIONS = listOf("\uD83D\uDC4D", "\u2764\uFE0F", "\uD83D\uDE02",
                                     "\uD83D\uDE2E", "\uD83D\uDE22", "\uD83D\uDE4F")

/** Reply, react, copy; correct and delete for everyone on our own. */
@Composable
private fun BubbleActions(m: Message, model: AppModel) {
    var open by remember { mutableStateOf(false) }
    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    Box {
        Text("\u22EF", color = MaterialTheme.colorScheme.onSurfaceVariant,
             modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable { open = true }
                 .padding(horizontal = 6.dp))
        androidx.compose.material3.DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            Row(Modifier.padding(horizontal = 8.dp)) {
                QUICK_REACTIONS.forEach { e ->
                    TextButton(onClick = { open = false; model.react(m, e) }) { Text(e) }
                }
            }
            androidx.compose.material3.DropdownMenuItem(text = { Text("Reply") },
                onClick = { open = false; model.startReply(m) })
            androidx.compose.material3.DropdownMenuItem(text = { Text("Copy") }, onClick = {
                open = false; clipboard.setText(androidx.compose.ui.text.AnnotatedString(m.body)) })
            // A secure-group member, by the address MLS proved (never the
            // nickname): add them, or go straight to a 1:1 chat.
            model.chat.memberOf(m)?.let { member ->
                HorizontalDivider()
                if (!model.chat.isContact(member)) {
                    androidx.compose.material3.DropdownMenuItem(text = { Text("Add to contacts") },
                        onClick = { open = false; model.addContact(member) })
                }
                androidx.compose.material3.DropdownMenuItem(text = { Text("Message privately") },
                    onClick = { open = false; model.open(member) })
            }
            if (m.outgoing) {
                androidx.compose.material3.DropdownMenuItem(text = { Text("Correct") },
                    onClick = { open = false; model.startEdit(m) })
                androidx.compose.material3.DropdownMenuItem(
                    text = { Text("Delete for everyone", color = MaterialTheme.colorScheme.error) },
                    onClick = { open = false; model.retract(m) })
            }
        }
    }
}

@Composable
private fun Composer(model: AppModel, jid: String, isRoom: Boolean, security: SecurityState,
                     onLocation: () -> Unit) {
    val text = model.draft(jid)
    val joining = isRoom && model.chat.isJoiningRoom(jid)
    val canSend = model.chat.canSend() && !joining
    val banner = model.editing?.takeIf { it.conversationId == jid }?.let { "Correcting your message" }
        ?: model.replyingTo?.takeIf { it.conversationId == jid }
            ?.let { "Replying to: " + it.body.lineSequence().firstOrNull().orEmpty().take(60) }
    if (banner != null) {
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Text(banner, style = MaterialTheme.typography.labelMedium,
                 color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
            TextButton(onClick = { model.cancelCompose(jid) }) { Text("Cancel") }
        }
    }
    Surface(tonalElevation = 2.dp) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            // A location pin: only inside encryption, and not mid-correction.
            if (banner == null && encryptedHere(model, jid, isRoom, security)) {
                IconButton(onClick = onLocation, enabled = canSend) {
                    Icon(Icons.Filled.Place, "Share a location")
                }
            }
            OutlinedTextField(
                value = text, onValueChange = { model.setDraft(jid, it) },
                modifier = Modifier.weight(1f).onPreviewKeyEvent { e ->
                    if (e.type == KeyEventType.KeyDown && e.key == Key.Enter && !e.isShiftPressed) {
                        if (canSend && text.isNotBlank()) model.send(jid); true
                    } else false
                },
                placeholder = { Text(when {
                    joining -> "Setting up end-to-end encryption — send once the group is ready"
                    !canSend -> "Not connected — your message will wait"
                    isRoom -> "Message the room"
                    security == SecurityState.PLAINTEXT -> "Message (not encrypted yet — press Encrypt)"
                    else -> "Encrypted message"
                }) },
                maxLines = 6,
                shape = RoundedCornerShape(24.dp),
            )
            Spacer(Modifier.width(8.dp))
            // Nothing typed and a voice note allowed here (verified contact,
            // or a secure group): the mic. Otherwise Send.
            val voice = if (isRoom) model.chat.isSecureRoom(jid)
                        else TransferUi.offer(security) is TransferUi.Offer.Available
            // Shown in every encrypted conversation so it can be found;
            // usable once the contact (or every group member) is verified.
            if (text.isBlank() && encryptedHere(model, jid, isRoom, security)) {
                FilledIconButton(onClick = { model.openVoiceSheet() }, enabled = canSend && voice) {
                    Icon(Icons.Filled.Mic, "Record a voice note")
                }
            } else {
                FilledIconButton(onClick = { model.send(jid) }, enabled = text.isNotBlank() && canSend) {
                    Icon(Icons.AutoMirrored.Filled.Send, "Send")
                }
            }
        }
    }
}

/**
 * SMP. The proof is Rust's (smp.rs); this is a text field whose content is
 * handed to the engine and dropped when the dialog closes.
 */
@Composable
private fun SmpDialog(model: AppModel, jid: String, prompt: Verification.Prompt) {
    var secret by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { model.verifyFor = null; secret = "" },
        title = { Text(if (prompt == Verification.Prompt.INCOMING) "Answer verification" else "Verify identity") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(Verification.explanation(prompt, jid), style = MaterialTheme.typography.bodyMedium)
                // Passphrase only, as on Android and Termux (owner, 2026-10-20:
                // no optional question).
                OutlinedTextField(secret, { secret = it }, singleLine = true,
                    label = { Text("Shared passphrase (${Verification.MIN_SECRET}+ characters)") },
                    visualTransformation = PasswordVisualTransformation())
            }
        },
        confirmButton = {
            Button(onClick = { val s = secret; secret = ""; model.submitSecret(jid, s) },
                   enabled = Verification.acceptable(secret)) { Text("Verify") }
        },
        dismissButton = { TextButton(onClick = { model.verifyFor = null; secret = "" }) { Text("Cancel") } },
    )
}

/** The y/n/c the Termux client asks, as a dialog. */
@Composable
private fun VoiceNoteDialog(model: AppModel, jid: String, sheet: VoiceSheet) {
    AlertDialog(
        onDismissRequest = { if (sheet !is VoiceSheet.Recording) model.closeVoiceSheet() },
        title = { Text("Voice note") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                when (sheet) {
                    is VoiceSheet.Choosing, is VoiceSheet.Failed -> {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            for (mode in VoiceNotes.MODES) {
                                FilterChip(selected = sheet.mode == mode, onClick = { model.chooseVoice(mode) },
                                           label = { Text(VoiceNotes.label(mode)) })
                            }
                        }
                        Text(VoiceNotes.detail(sheet.mode))
                        Text(VoiceNotes.CAVEAT, style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                        if (sheet is VoiceSheet.Failed) {
                            Text(sheet.message, color = MaterialTheme.colorScheme.error,
                                 style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    is VoiceSheet.Recording -> {
                        Text("Recording \u00b7 ${VoiceNotes.label(sheet.mode)} \u00b7 ${VoiceNotes.clock(sheet.seconds)}",
                             style = MaterialTheme.typography.titleMedium)
                        LinearProgressIndicator(progress = { sheet.level.toFloat().coerceIn(0f, 1f) },
                                                modifier = Modifier.fillMaxWidth())
                        Text(VoiceNotes.whileRecording(sheet.mode, "computer"),
                             style = MaterialTheme.typography.bodySmall)
                    }
                    is VoiceSheet.Making -> Text(VoiceNotes.making(sheet.mode))
                    is VoiceSheet.Ready -> {
                        Text("${VoiceNotes.label(sheet.mode)} \u00b7 ${VoiceNotes.clock(sheet.seconds)}",
                             style = MaterialTheme.typography.titleMedium)
                        Text("This is exactly what they will hear.", style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedButton(onClick = { model.playVoiceNote(sheet.path) }) { Text("Play") }
                            TextButton(onClick = { model.stopPlaying() }) { Text("Stop") }
                        }
                    }
                }
            }
        },
        confirmButton = {
            when (sheet) {
                is VoiceSheet.Choosing, is VoiceSheet.Failed -> Button(onClick = { model.startVoiceNote() }) { Text("Record") }
                is VoiceSheet.Recording -> Button(onClick = { model.stopVoiceNote() }) { Text("Stop") }
                is VoiceSheet.Ready -> Button(onClick = { model.sendVoiceNote(jid) }) { Text("Send") }
                is VoiceSheet.Making -> {}
            }
        },
        dismissButton = {
            if (sheet !is VoiceSheet.Making) {
                TextButton(onClick = { model.closeVoiceSheet() }) {
                    Text(if (sheet is VoiceSheet.Ready || sheet is VoiceSheet.Recording) "Discard" else "Close")
                }
            }
        },
    )
}

@Composable
private fun MetadataDialog(path: String, onChoice: (Boolean?) -> Unit) {
    AlertDialog(
        onDismissRequest = { onChoice(null) },
        title = { Text("Remove hidden information?") },
        text = {
            Text("${java.io.File(path).name} may carry hidden information: location, camera, " +
                 "author, edit history. Remove it before sending? If the file type cannot be " +
                 "cleaned, nothing is sent.")
        },
        confirmButton = { Button(onClick = { onChoice(true) }) { Text("Remove and send") } },
        dismissButton = {
            Row {
                TextButton(onClick = { onChoice(null) }) { Text("Cancel") }
                TextButton(onClick = { onChoice(false) }) { Text("Send as it is") }
            }
        },
    )
}

/** An encrypted conversation: where the 📍 and 🎤 are shown at all. */
private fun encryptedHere(model: AppModel, jid: String, isRoom: Boolean, security: SecurityState): Boolean =
    if (isRoom) model.chat.isSecureRoom(jid) else security != SecurityState.PLAINTEXT

/** Null when a location may go here; otherwise why not. Verified, not merely
 *  encrypted: see Location.shareRefusal. */
private fun locationRefusal(model: AppModel, jid: String, isRoom: Boolean, security: SecurityState): String? {
    val verified = if (isRoom) {
        val others = model.groupMembers[jid].orEmpty().filter { !it.me }
        others.isNotEmpty() && others.all { it.verified }
    } else TransferUi.offer(security) is TransferUi.Offer.Available
    return Location.shareRefusal(encryptedHere(model, jid, isRoom, security), verified, isRoom)
}

/**
 * Share a pin, typed: a full Plus Code or coordinates. No GPS here -- a
 * desktop has none, and asking the OS would mean a network location service.
 */
@Composable
private fun LocationDialog(model: AppModel, jid: String, onClose: () -> Unit) {
    var typed by remember { mutableStateOf("") }
    val pin = Location.fromTyped(typed)
    val refusal = locationRefusal(model, jid, model.chat.isRoom(jid), model.conversation(jid).security)
    val allowed = refusal == null
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Share a location") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Sent encrypted, as a Plus Code and coordinates. Nothing is looked up online.",
                     style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(typed, { typed = it }, singleLine = true,
                                  label = { Text("Plus Code or coordinates") })
                when {
                    pin != null -> Text("${pin.code}  ·  ${Location.coordinates(pin)}",
                                        fontFamily = FontFamily.Monospace,
                                        style = MaterialTheme.typography.bodySmall)
                    typed.isNotBlank() -> Text(Location.typedHint, style = MaterialTheme.typography.bodySmall,
                                               color = MaterialTheme.colorScheme.error)
                }
                refusal?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                val p = pin ?: return@Button
                // Through the ordinary send path, so it is encrypted exactly as
                // text is; whatever was being typed is put back afterwards.
                val kept = model.draft(jid)
                // (chat.setDraft, not model.setDraft: no "typing" goes out.)
                model.chat.setDraft(jid, Location.body(p))
                model.send(jid)
                model.chat.setDraft(jid, kept)
                onClose()
            }, enabled = allowed && pin != null) { Text("Send") }
        },
        dismissButton = { TextButton(onClick = onClose) { Text("Cancel") } },
    )
}

/** A pin in a bubble: the code, the coordinates, and Copy. */
@Composable
private fun LocationCard(pin: Location.Pin) {
    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(Location.MARKER, style = MaterialTheme.typography.labelLarge)
        SelectionContainer {
            Column {
                Text(pin.code, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                Text(Location.coordinates(pin) + (Location.accuracy(pin)?.let { "  $it" } ?: ""),
                     fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
        TextButton(onClick = {
            clipboard.setText(androidx.compose.ui.text.AnnotatedString(
                "${pin.code} (${Location.coordinates(pin)})"))
        }) { Text("Copy") }
    }
}

/** A moving bar while a verification runs, filling as its steps come back
 *  (owner, 2026-10-16: users must see it is actively trying). */
@Composable
private fun VerificationProgress(model: AppModel, jid: String) {
    val c = model.conversation(jid)
    val offer = Verification.offer(c.security, c.smp)
    if (offer != Verification.Offer.IN_PROGRESS && offer != Verification.Offer.ANSWERING) return
    val (step, total) = model.chat.smpSteps(jid) ?: (0 to 4)
    val fraction = Verification.progressFraction(step, total)
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        if (fraction == null) LinearProgressIndicator(Modifier.fillMaxWidth())
        else LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
        Text(Verification.progressLabel(step, total), style = MaterialTheme.typography.labelSmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}


/** L1: "Make Chat Deniable…" in an established 1:1 chat, asked first. */
@Composable
private fun DeniableButton(model: AppModel, jid: String) {
    var asking by remember(jid) { mutableStateOf(false) }
    TextButton(onClick = { asking = true }) { Text(DeniableChat.ACTION) }
    if (asking) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { asking = false },
            title = { Text(DeniableChat.TITLE) },
            text = { Text(DeniableChat.BODY) },
            confirmButton = {
                TextButton(onClick = { asking = false; model.makeChatDeniable(jid) }) {
                    Text(DeniableChat.CONFIRM)
                }
            },
            dismissButton = { TextButton(onClick = { asking = false }) { Text("Cancel") } },
        )
    }
}
