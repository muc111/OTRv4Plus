// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable

/**
 * Asked after a message notification is tapped: whose message is waiting,
 * and whether to open it. The notification names nobody; the name appears
 * only here, inside the app. "Not now" leaves the conversation closed.
 */
@Composable
fun ArrivalPromptDialog(name: String, onView: () -> Unit, onNotNow: () -> Unit) {
    AlertDialog(
        onDismissRequest = onNotNow,
        title = { Text("New message") },
        text = { Text("A new message from $name is waiting. View it?") },
        confirmButton = { TextButton(onClick = onView) { Text("View") } },
        dismissButton = { TextButton(onClick = onNotNow) { Text("Not now") } },
    )
}
