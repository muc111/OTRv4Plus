// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.ProfileText
import org.otrv4plus.android.connection.PasswordChange
import org.otrv4plus.desktop.AppModel

/**
 * Your picture and your XMPP profile (vcard-temp), the fields defined once
 * in android_bridge/profile.py. A profile is PUBLIC: the server and anyone
 * who asks can read it, so the section says so.
 */
@Composable
fun ProfileSection(model: AppModel) {
    LaunchedEffect(Unit) { model.loadProfile() }
    val values = remember { mutableStateMapOf<String, String>() }
    var loadedFrom by remember { mutableStateOf<Map<String, String>?>(null) }
    if (loadedFrom !== model.profile) {
        values.clear(); values.putAll(model.profile); loadedFrom = model.profile
    }
    val me = model.chat.account.bareJid.ifBlank { model.jid }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Avatar(me, image = model.avatar(me), size = 72)
        Spacer(Modifier.width(16.dp))
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    pickFile("Choose your picture")?.let { model.setOwnAvatar(it) }
                }) { Text("Change picture") }
                TextButton(onClick = { model.removeOwnAvatar() }) { Text("Remove") }
            }
            Text("Squared, scaled to 96 px and re-encoded here, so nothing from the " +
                 "original file (location, camera) is published.",
                 style = MaterialTheme.typography.labelSmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
    Spacer(Modifier.padding(4.dp))
    Text("Your profile is public: the server and anyone who asks can read it.",
         style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    for (f in model.profileFields) {
        OutlinedTextField(
            value = values[f.key].orEmpty(),
            onValueChange = { v -> values[f.key] = v.take(f.maxLength.takeIf { it > 0 } ?: v.length) },
            label = { Text(f.label) },
            singleLine = !f.multiline,
            minLines = if (f.multiline) 3 else 1,
            modifier = Modifier.fillMaxWidth(),
        )
    }
    if (model.profileFields.isEmpty() && !model.profileBusy) {
        Text("The profile fields could not be read. Connect first.",
             style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { model.saveProfile(values.toMap()) },
               enabled = !model.profileBusy && model.profileFields.isNotEmpty()) { Text("Publish profile") }
        TextButton(onClick = { model.loadProfile() }, enabled = !model.profileBusy) { Text("Reload") }
    }
    ChangePasswordSection(model)
}

/** Change the account's password on the server (shared rules: PasswordChange). */
@Composable
private fun ChangePasswordSection(model: AppModel) {
    var open by remember { mutableStateOf(false) }
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    fun reset() { current = ""; new = ""; confirm = ""; open = false }

    Spacer(Modifier.padding(4.dp))
    if (!open) {
        OutlinedButton(onClick = { open = true }) { Text(PasswordChange.TITLE + "…") }
        model.passwordStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        return
    }
    Text(PasswordChange.TITLE, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
    Text(PasswordChange.EXPLAINED, style = MaterialTheme.typography.bodySmall,
         color = MaterialTheme.colorScheme.onSurfaceVariant)
    @Composable
    fun field(label: String, value: String, onChange: (String) -> Unit) = OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true,
        enabled = !model.passwordBusy, visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )
    field("Current password", current) { current = it }
    field("New password (at least ${PasswordChange.MIN_LENGTH} characters)", new) { new = it }
    field("New password again", confirm) { confirm = it }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !model.passwordBusy && current.isNotEmpty() && new.isNotEmpty() && confirm.isNotEmpty(),
            onClick = { model.changePassword(current, new, confirm) { ok -> if (ok) reset() } },
        ) { Text(if (model.passwordBusy) "Changing…" else "Change") }
        TextButton(onClick = { reset() }, enabled = !model.passwordBusy) { Text("Cancel") }
    }
    model.passwordStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}

/** Someone's profile, read-only. Text only: nothing in it is a link or runs. */
@Composable
fun ProfileDialog(model: AppModel, jid: String, values: Map<String, String>) {
    AlertDialog(
        onDismissRequest = { model.closeProfile() },
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(jid, image = model.avatar(jid), size = 48)
                Spacer(Modifier.width(12.dp))
                Text(values["FN"].orEmpty().ifBlank { jid })
            }
        },
        text = {
            Column(Modifier.widthIn(min = 360.dp).heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                   verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(jid, style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                val shown = model.profileFields.filter { !values[it.key].isNullOrBlank() }
                if (shown.isEmpty()) Text(ProfileText.empty(jid), style = MaterialTheme.typography.bodyMedium)
                for (f in shown) {
                    Column {
                        Text(f.label, style = MaterialTheme.typography.labelMedium,
                             color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Medium)
                        SelectionContainer { Text(values[f.key].orEmpty()) }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { model.closeProfile() }) { Text("Close") } },
    )
}

/** The OS file chooser. Returns a path; the engine (or Avatars) reads it. */
fun pickFile(title: String): String? {
    val dialog = java.awt.FileDialog(null as java.awt.Frame?, title, java.awt.FileDialog.LOAD)
    dialog.isVisible = true
    val name = dialog.file ?: return null
    return java.io.File(dialog.directory, name).absolutePath
}
