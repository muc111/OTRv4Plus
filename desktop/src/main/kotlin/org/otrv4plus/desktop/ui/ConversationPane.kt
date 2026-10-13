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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.crypto.CallUi
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
    val secure = isRoom && model.chat.isSecureRoom(jid)
    var showMembers by remember(jid) { mutableStateOf(true) }
    LaunchedEffect(jid, secure) { if (secure) model.refreshGroupNow(jid) }

    Row(Modifier.fillMaxSize()) {
        Column(Modifier.weight(1f).fillMaxHeight()) {
            Header(model, jid, isRoom, onMembers = if (secure) ({ showMembers = !showMembers }) else null) {
                path -> pendingFile = path
            }
            HorizontalDivider()
            if (!isRoom) {
                CallBar(model, jid)
                HandshakeView(model.handshake)
            }
            if (secure) GroupBar(model, jid)
            FileOffers(model, jid)
            Messages(model, jid, isRoom, Modifier.weight(1f))
            Composer(model, jid, isRoom, c.security)
        }
        if (secure && showMembers) {
            VerticalDivider()
            GroupMembersPanel(model, jid, Modifier.width(300.dp))
        }
    }

    if (!isRoom) model.verificationPrompt(jid)?.let { prompt -> SmpDialog(model, jid, prompt) }
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
                Text(if (model.chat.isSecureRoom(jid)) "Encrypted group (MLS)" else "Room — not end-to-end encrypted",
                     style = MaterialTheme.typography.bodySmall,
                     color = if (model.chat.isSecureRoom(jid)) MaterialTheme.colorScheme.primary
                             else MaterialTheme.colorScheme.error)
            } else {
                val level = SecurityLevel.of(c.security)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(securityIcon(c.security), null, Modifier.size(14.dp), tint = securityColour(c.security))
                    Spacer(Modifier.width(4.dp))
                    Text(level.label, style = MaterialTheme.typography.bodySmall, color = securityColour(c.security))
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
                TooltipBox(TooltipDefaults.rememberPlainTooltipPositionProvider(),
                           tooltip = { PlainTooltip { Text(control.label) } },
                           state = rememberTooltipState()) {
                    FilledIconButton(onClick = { model.call(jid) },
                                     enabled = control.enabled && model.callPhase == CallState.IDLE) {
                        Icon(Icons.Filled.Call, control.label)
                    }
                }
            }
        }
        if (onMembers != null) {
            TextButton(onClick = onMembers) {
                Icon(Icons.Filled.Groups, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp))
                Text("Members")
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

private val timeFormat = SimpleDateFormat("HH:mm")

@Composable
private fun Messages(model: AppModel, jid: String, isRoom: Boolean, modifier: Modifier) {
    val messages = model.messages(jid)
    val listState = rememberLazyListState()
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1) }
    LazyColumn(modifier.fillMaxWidth().padding(horizontal = 12.dp), state = listState,
               verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item { Spacer(Modifier.padding(4.dp)) }
        items(messages, key = { it.id }) { m -> Bubble(m, isRoom) }
        item { Spacer(Modifier.padding(4.dp)) }
    }
}

@Composable
private fun Bubble(m: Message, isRoom: Boolean) {
    if (m.security == SecurityLabel.SYSTEM) {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text(m.body, style = MaterialTheme.typography.labelSmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant,
                 modifier = Modifier.clip(RoundedCornerShape(8.dp))
                     .background(MaterialTheme.colorScheme.surfaceVariant)
                     .padding(horizontal = 10.dp, vertical = 4.dp))
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
            SelectionContainer {
                Text(m.body, color = if (mine) MaterialTheme.colorScheme.onPrimaryContainer
                                     else MaterialTheme.colorScheme.onSurface)
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
                Text(timeFormat.format(Date(m.at)) + when (m.sendState) {
                    SendState.SENDING -> " · sending"
                    SendState.QUEUED -> " · queued until encrypted"
                    SendState.FAILED -> " · not sent"
                    else -> ""
                }, style = MaterialTheme.typography.labelSmall,
                   color = if (m.sendState == SendState.FAILED) MaterialTheme.colorScheme.error
                           else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun Composer(model: AppModel, jid: String, isRoom: Boolean, security: SecurityState) {
    val text = model.draft(jid)
    val canSend = model.chat.canSend()
    Surface(tonalElevation = 2.dp) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = text, onValueChange = { model.setDraft(jid, it) },
                modifier = Modifier.weight(1f).onPreviewKeyEvent { e ->
                    if (e.type == KeyEventType.KeyDown && e.key == Key.Enter && !e.isShiftPressed) {
                        if (canSend && text.isNotBlank()) model.send(jid); true
                    } else false
                },
                placeholder = { Text(when {
                    !canSend -> "Not connected — your message will wait"
                    isRoom -> "Message the room"
                    security == SecurityState.PLAINTEXT -> "Message (not encrypted yet — press Encrypt)"
                    else -> "Encrypted message"
                }) },
                maxLines = 6,
                shape = RoundedCornerShape(24.dp),
            )
            Spacer(Modifier.width(8.dp))
            FilledIconButton(onClick = { model.send(jid) }, enabled = text.isNotBlank() && canSend) {
                Icon(Icons.AutoMirrored.Filled.Send, "Send")
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
    var question by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { model.verifyFor = null; secret = "" },
        title = { Text(if (prompt == Verification.Prompt.INCOMING) "Answer verification" else "Verify identity") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(Verification.explanation(prompt, jid), style = MaterialTheme.typography.bodyMedium)
                if (prompt == Verification.Prompt.OUTGOING) {
                    OutlinedTextField(question, { question = it }, singleLine = true,
                                      label = { Text("Question (optional; your contact sees it)") })
                }
                OutlinedTextField(secret, { secret = it }, singleLine = true,
                    label = { Text("Shared passphrase (${Verification.MIN_SECRET}+ characters)") },
                    visualTransformation = PasswordVisualTransformation())
            }
        },
        confirmButton = {
            Button(onClick = { val s = secret; secret = ""; model.submitSecret(jid, s, question) },
                   enabled = Verification.acceptable(secret)) { Text("Verify") }
        },
        dismissButton = { TextButton(onClick = { model.verifyFor = null; secret = "" }) { Text("Cancel") } },
    )
}

/** The y/n/c the Termux client asks, as a dialog. */
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
