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
    Column(Modifier.fillMaxSize()) {
        PaneTitle("People") { Button(onClick = { adding = true }) { Text("Add contact") } }
        for (req in model.chat.pendingSubscriptions) {
            Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("${req.peer} wants to add you as a contact.", Modifier.weight(1f))
                    TextButton(onClick = { model.answerSubscription(req.peer, false) }) { Text("Refuse") }
                    Button(onClick = { model.answerSubscription(req.peer, true) }) { Text("Accept") }
                }
            }
        }
        LazyColumn(Modifier.fillMaxSize()) {
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
        val rooms = (model.groups + model.conversations().map { it.jid }.filter { model.chat.isRoom(it) }).distinct()
        if (rooms.isEmpty()) {
            Text("No rooms yet. An encrypted group is end-to-end encrypted with MLS " +
                 "(X448 + ML-KEM-1024); an ordinary room is not.",
                 Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        LazyColumn(Modifier.fillMaxSize()) {
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
                        Text(if (secure) "Encrypted group" else "Room — not end-to-end encrypted",
                             style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
            }
        }
    }
    if (joining) TextPrompt("Join room", "room@conference.server.i2p", "Join",
                            onDone = { v -> joining = false
                                if (v != null) model.joinRoom(v, model.jid.substringBefore('@')) })
    if (creating) TextPrompt("New encrypted group", "group@conference.server.i2p", "Create",
                             onDone = { v -> creating = false; if (v != null) model.createSecureGroup(v) })
}

// -- Settings ----------------------------------------------------------------------

@Composable
fun SettingsPane(model: AppModel, onWipe: () -> Unit) {
    var confirmWipe by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
        PaneTitle("Settings")
        Section("Account") {
            Text(model.chat.account.bareJid.ifBlank { model.jid })
            Text(model.chat.connection.sam.let { if (it.isBlank()) "" else "I2P SAM bridge: $it" },
                 style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.padding(4.dp))
            OutlinedButton(onClick = { model.disconnect() }) { Text("Sign out") }
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
            Text("Destroys this device's keys, sessions and received files, then closes the app.",
                 style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.padding(4.dp))
            Button(onClick = { confirmWipe = true },
                   colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error,
                                                        contentColor = MaterialTheme.colorScheme.onError)) {
                Text("Wipe & Exit")
            }
        }
    }
    if (confirmWipe) AlertDialog(
        onDismissRequest = { confirmWipe = false },
        title = { Text("Wipe everything?") },
        text = { Text("Your identity keys, every session and every received file on this device " +
                      "are destroyed. Contacts will see a new key next time. This cannot be undone.") },
        confirmButton = {
            Button(onClick = { confirmWipe = false; onWipe() },
                   colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)) {
                Text("Wipe & Exit")
            }
        },
        dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Cancel") } },
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
