// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.ConnectionViewModel
import org.otrv4plus.android.connection.PasswordChange

/**
 * "Change password", on our own profile. Closed until asked for; the three
 * fields are cleared once the server has accepted the new password, and are
 * never saved across a screen rotation (plain `remember`, not saveable).
 */
@Composable
fun ChangePasswordSection(model: ConnectionViewModel) {
    var open by remember { mutableStateOf(false) }
    var current by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var show by remember { mutableStateOf(false) }

    HorizontalDivider()
    if (!open) {
        OutlinedButton(onClick = { open = true }) { Text(PasswordChange.TITLE + "…") }
        model.signInChangeStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        return
    }
    Text(PasswordChange.TITLE, style = MaterialTheme.typography.titleMedium)
    Text(
        PasswordChange.EXPLAINED,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    val hidden = if (show) VisualTransformation.None else PasswordVisualTransformation()
    @Composable
    fun field(label: String, value: String, last: Boolean, onChange: (String) -> Unit) =
        OutlinedTextField(
            value = value, onValueChange = onChange, label = { Text(label) },
            singleLine = true, enabled = !model.signInChangeBusy,
            visualTransformation = hidden,
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = if (last) ImeAction.Done else ImeAction.Next),
            modifier = Modifier.fillMaxWidth(),
        )
    field("Current password", current, last = false) { current = it }
    field("New password (at least ${PasswordChange.MIN_LENGTH} characters)", new, last = false) { new = it }
    field("New password again", confirm, last = true) { confirm = it }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !model.signInChangeBusy && current.isNotEmpty() && new.isNotEmpty() &&
                confirm.isNotEmpty(),
            onClick = {
                model.changePassword(current, new, confirm) { ok ->
                    if (ok) { current = ""; new = ""; confirm = ""; open = false; show = false }
                }
            },
        ) { Text(if (model.signInChangeBusy) "Changing…" else "Change") }
        TextButton(onClick = { show = !show }) { Text(if (show) "Hide" else "Show") }
        TextButton(
            enabled = !model.signInChangeBusy,
            onClick = { current = ""; new = ""; confirm = ""; open = false; show = false },
        ) { Text("Cancel") }
    }
    if (model.signInChangeBusy) LinearProgressIndicator(Modifier.fillMaxWidth())
    model.signInChangeStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}
