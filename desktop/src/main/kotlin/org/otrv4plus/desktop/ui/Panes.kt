// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.Presence
import org.otrv4plus.android.theme.ThemeTokens
import org.otrv4plus.desktop.AppModel

@Composable
private fun PaneTitle(text: String, action: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
             modifier = Modifier.weight(1f))
        action()
    }
}

// -- People ------------------------------------------------------------------------

@Composable
fun PeoplePane(model: AppModel) {
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    var adding by remember { mutableStateOf(false) }
    // Who is online, fresh when the tab opens (as Android's People screen).
    androidx.compose.runtime.LaunchedEffect(Unit) { model.refreshOnline(force = true) }
    Column(Modifier.fillMaxSize()) {
        PaneTitle("People") {
            OutlinedButton(onClick = { model.refreshOnline(force = true) }) { Text("Look again") }
            Spacer(Modifier.width(8.dp))
            Button(onClick = { adding = true }) { Text("Add contact") }
        }
        for (req in model.chat.pendingSubscriptions) {
            Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("${req.peer} wants to add you as a contact.", Modifier.weight(1f))
                    TextButton(onClick = { model.answerSubscription(req.peer, false) }) { Text("Refuse") }
                    Button(onClick = { model.answerSubscription(req.peer, true) }) { Text("Accept") }
                }
            }
        }
        ScrollLazyColumn(Modifier.fillMaxSize()) {
            items(model.chat.directory(), key = { it.jid }) { e ->
                Row(Modifier.fillMaxWidth().clickable { model.open(e.jid) }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    val presence = model.conversation(e.jid).presence
                    Avatar(e.displayName.ifBlank { e.jid }, presence, image = model.avatar(e.jid))
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(e.displayName.ifBlank { e.jid }, fontWeight = FontWeight.Medium)
                        Text(e.facts.joinToString(" · "), style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (e.verified) Text("Verified", color = VerifiedBlue, style = MaterialTheme.typography.labelMedium)
                    else if (presence == Presence.ONLINE) Text("online", style = MaterialTheme.typography.labelMedium,
                                                                color = MaterialTheme.colorScheme.primary)
                }
                HorizontalDivider(Modifier.padding(start = 68.dp), color = MaterialTheme.colorScheme.surfaceVariant)
            }
        }
    }
    if (adding) TextPrompt("Add contact", "Their address (bob@server.i2p)", "Add",
                           onDone = { v -> adding = false; if (v != null && v.contains('@')) model.addContact(v) })
}

// -- Rooms -------------------------------------------------------------------------

@Composable
fun RoomsPane(model: AppModel) {
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    var joining by remember { mutableStateOf(false) }
    var creating by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        PaneTitle("Rooms and groups") {
            OutlinedButton(onClick = { joining = true }) { Text("Join room") }
            Spacer(Modifier.width(8.dp))
            Button(onClick = { creating = true }) { Text("New encrypted group") }
        }
        for (invite in model.chat.pendingGroupInvites) {
            Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("${invite.peer} invites you to an encrypted group")
                        Text(invite.room + if (invite.verified) " · from a verified contact" else " · sender NOT verified",
                             style = MaterialTheme.typography.bodySmall,
                             color = if (invite.verified) VerifiedBlue else MaterialTheme.colorScheme.error)
                    }
                    TextButton(onClick = { model.declineGroupInvite(invite.room) }) { Text("Decline") }
                    Button(onClick = { model.acceptGroupInvite(invite.room) }) { Text("Join") }
                }
            }
        }
        // "X asks to join" (owner, 2026-10-17): Invite sends the usual
        // OTRv4+ invitation to the address they gave.
        for (request in model.entryRequests()) {
            Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(org.otrv4plus.android.chat.GroupText.entryRequest(
                            request.requester, request.room))
                        Text(org.otrv4plus.android.chat.GroupText.ENTRY_REQUEST_NOTE,
                             style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = {
                        model.laterEntryRequest(request.room, request.requester)
                    }) { Text(org.otrv4plus.android.chat.GroupText.ENTRY_LATER) }
                    TextButton(onClick = {
                        model.answerEntryRequest(request.room, request.requester, false)
                    }) { Text(org.otrv4plus.android.chat.GroupText.ENTRY_DENY) }
                    Button(onClick = {
                        model.answerEntryRequest(request.room, request.requester, true)
                    }) { Text(org.otrv4plus.android.chat.GroupText.ENTRY_ACCEPT) }
                }
            }
        }
        model.groupPasswordFor?.let { room -> GroupRoomPasswordDialog(model, room) }
        model.roomPasswordPrompt?.let { prompt -> RoomPasswordDialog(model, prompt) }
        val rooms = (model.groups + model.conversations().map { it.jid }.filter { model.chat.isRoom(it) }).distinct()
        if (rooms.isEmpty()) {
            Text("No rooms yet. An encrypted group is end-to-end encrypted with MLS+ " +
                 "(X448 + ML-KEM-1024); an ordinary room is not.",
                 Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        ScrollLazyColumn(Modifier.fillMaxSize()) {
            items(rooms, key = { it }) { room ->
                val secure = room in model.groups || model.chat.isSecureRoom(room)
                Row(Modifier.fillMaxWidth().clickable { model.chat.noteRoom(room); model.open(room) }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Icon(if (secure) Icons.Filled.Lock else Icons.Filled.Groups, null,
                         tint = if (secure) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(room, fontWeight = FontWeight.Medium)
                        val members = model.groupMembers[room].orEmpty()
                        Text(if (secure) org.otrv4plus.android.chat.GroupText.securityLine(
                                 org.otrv4plus.android.chat.GroupText.verifiedCount(members).first, members.size)
                             else "Room — not end-to-end encrypted",
                             style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
            }
        }
    }
    // A name is enough; the app adds this server's rooms service (RoomAddress).
    if (joining) TextPrompt("Join room", "Room name", "Join",
                            onDone = { v -> joining = false
                                if (v != null) model.joinRoom(v, model.jid.substringBefore('@')) })
    if (creating) TextPrompt("New encrypted group", "Group name", "Create",
                             onDone = { v -> creating = false; if (v != null) model.createSecureGroup(v) })
}

// -- Settings ----------------------------------------------------------------------

@Composable
fun SettingsPane(model: AppModel, onWipe: () -> Unit) {
    var confirmWipe by remember { mutableStateOf(false) }
    ScrollColumn(Modifier.fillMaxSize()) {
        PaneTitle("Settings")
        Section("Account") {
            Text(model.chat.account.bareJid.ifBlank { model.jid })
            Text(model.chat.connection.sam.let { if (it.isBlank()) "" else "I2P SAM bridge: $it" },
                 style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.padding(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { model.disconnect() }) { Text("Sign out") }
                // The same dialog as Wipe & Exit at the bottom, here too so
                // nobody has to scroll to find it (owner, 2026-10-20).
                TextButton(onClick = { confirmWipe = true },
                           colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
                    Text("Wipe & Exit or delete account…")
                }
            }
        }
        Section("Profile") { ProfileSection(model) }
        Section("Group calls") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.Switch(checked = model.groupAutoJoin,
                                                  onCheckedChange = { model.allowGroupAutoJoin(it) })
                Spacer(Modifier.width(12.dp))
                Text("Join verified members' group calls by myself", Modifier.weight(1f))
            }
            Text("Off: you are asked each time (Join). On Qubes the microphone is also " +
                 "attached to this qube by hand: qvm-device mic attach otr-chat dom0:mic.",
                 style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Section("Notifications") {
            Text(if (org.otrv4plus.desktop.Notifier.findNotifySend() != null)
                     "On. They say \"New message\" or \"Incoming call\" and nothing more: never " +
                     "who, never what. Messages only while this window is not in front."
                 else "notify-send is not installed (package libnotify-bin), so there are none.",
                 style = MaterialTheme.typography.bodyMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.Switch(checked = model.soundsOn,
                                                  onCheckedChange = { model.soundsOn = it })
                Spacer(Modifier.width(12.dp))
                Text("Sounds for messages and calls", Modifier.weight(1f))
            }
        }
        Section("Privacy") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.Switch(checked = model.sendTyping,
                    onCheckedChange = { model.setPrivacy(it, model.sendReadReceipts) })
                Spacer(Modifier.width(12.dp))
                Text("Send typing notifications", Modifier.weight(1f))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.Switch(checked = model.sendReadReceipts,
                    onCheckedChange = { model.setPrivacy(model.sendTyping, it) })
                Spacer(Modifier.width(12.dp))
                Text("Send read receipts", Modifier.weight(1f))
            }
            Text("Only contacts who can already see when you are online are told. " +
                 "Delivery ticks are always answered, as in other messengers.",
                 style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Section("Your fingerprint") {
            SelectionContainer { Text(model.fingerprint, fontFamily = FontFamily.Monospace) }
            Text("Compare it with your contact in person, or verify with a shared passphrase.",
                 style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Section("Appearance") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (mode in ThemeTokens.Mode.entries) {
                    FilterChip(selected = model.theme == mode, onClick = { model.theme = mode },
                               label = { Text(mode.label) })
                }
            }
        }
        Section("How this app is built") {
            Text("This window holds no keys. Every key, cipher and proof is in the Rust core " +
                 "(otrv4_core), inside a separate engine process; this window sends it commands " +
                 "and shows what it answers. The engine is the same one the Android app and the " +
                 "terminal client run.", style = MaterialTheme.typography.bodyMedium)
        }
        Section("Wipe & Exit") {
            Text("Destroys this device's keys, sessions, chats and received files, then closes " +
                 "the app. You can also delete your account from the server: tick it in the next step.",
                 style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.padding(4.dp))
            Button(onClick = { confirmWipe = true },
                   colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error,
                                                        contentColor = MaterialTheme.colorScheme.onError)) {
                Text("Wipe & Exit")
            }
        }
        Spacer(Modifier.padding(12.dp))
    }
    if (confirmWipe) AlertDialog(
        onDismissRequest = { confirmWipe = false; model.wipeDeletesAccount = false },
        title = { Text("Wipe everything?") },
        text = {
            Column {
                Text("Your identity keys, every session and every received file on this device " +
                     "are destroyed. Contacts will see a new key next time. This cannot be undone.")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    androidx.compose.material3.Checkbox(
                        checked = model.wipeDeletesAccount,
                        onCheckedChange = { model.wipeDeletesAccount = it })
                    Text(org.otrv4plus.android.security.WipeAndExit.DELETE_ACCOUNT_OPTION,
                         color = MaterialTheme.colorScheme.error)
                }
                if (model.wipeDeletesAccount) {
                    Text(org.otrv4plus.android.security.WipeAndExit.DELETE_ACCOUNT_DETAIL,
                         style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(onClick = { confirmWipe = false; onWipe() },
                   colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)) {
                Text("Wipe & Exit")
            }
        },
        dismissButton = { TextButton(onClick = { confirmWipe = false; model.wipeDeletesAccount = false }) {
            Text("Cancel")
        } },
    )
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.widthIn(max = 720.dp).fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            content()
        }
    }
}

@Composable
fun TextPrompt(title: String, hint: String, confirm: String, onDone: (String?) -> Unit) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { onDone(null) },
        title = { Text(title) },
        text = { OutlinedTextField(value, { value = it }, singleLine = true, label = { Text(hint) },
                                   modifier = Modifier.fillMaxWidth()) },
        confirmButton = { Button(onClick = { onDone(value.trim()) }, enabled = value.isNotBlank()) { Text(confirm) } },
        dismissButton = { TextButton(onClick = { onDone(null) }) { Text("Cancel") } },
    )
}

/** A password-protected room refused us: ask, and say what the password is not. */
@androidx.compose.runtime.Composable
private fun RoomPasswordDialog(model: AppModel, prompt: org.otrv4plus.android.chat.RoomPassword.Prompt) {
    var password by androidx.compose.runtime.remember(prompt) { androidx.compose.runtime.mutableStateOf("") }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { model.roomPasswordPrompt = null },
        title = { Text("Room password") },
        text = {
            Column {
                Text(prompt.message,
                     color = if (prompt.retry) MaterialTheme.colorScheme.error
                             else MaterialTheme.colorScheme.onSurface)
                androidx.compose.material3.OutlinedTextField(
                    value = password, onValueChange = { password = it }, singleLine = true,
                    label = { Text("Password") },
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation())
                Text(org.otrv4plus.android.chat.RoomPassword.NOT_ENCRYPTION,
                     style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            androidx.compose.material3.TextButton(enabled = password.isNotBlank(),
                onClick = { model.joinRoom(prompt.room, prompt.nick, password); password = "" }) { Text("Join") }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = { model.roomPasswordPrompt = null }) { Text("Cancel") }
        },
    )
}

/** The room password for a secure group whose invitation did not carry it. */
@androidx.compose.runtime.Composable
private fun GroupRoomPasswordDialog(model: AppModel, room: String) {
    var password by androidx.compose.runtime.remember(room) { androidx.compose.runtime.mutableStateOf("") }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { model.groupPasswordFor = null },
        title = { Text("Room password") },
        text = {
            Column {
                Text(org.otrv4plus.android.chat.GroupText.outcome("group_password_needed").orEmpty(),
                     style = MaterialTheme.typography.bodySmall)
                androidx.compose.material3.OutlinedTextField(
                    value = password, onValueChange = { password = it }, singleLine = true,
                    label = { Text(room) },
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation())
            }
        },
        confirmButton = {
            androidx.compose.material3.TextButton(enabled = password.isNotEmpty(),
                onClick = { model.acceptGroupInvite(room, password); password = "" }) { Text("Join") }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = { model.groupPasswordFor = null }) { Text("Cancel") }
        },
    )
}
