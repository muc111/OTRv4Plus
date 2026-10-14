// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import org.otrv4plus.android.security.WipeAndExit

/**
 * The one Wipe & Exit control: a button, a confirmation, then the service's
 * teardown (`OtrConnectionService.wipeAndExit`, ordered by [WipeAndExit]).
 * Used on the connection screen and at the foot of the conversation list, so
 * both run exactly the same thing. Nothing happens without the confirmation.
 */
@Composable
fun WipeAndExitButton(onWipe: () -> Unit) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    OutlinedButton(
        onClick = { confirm = true },
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.error),
    ) { Text("Wipe & Exit") }
    if (confirm) WipeAndExitDialog(onWipe = onWipe, onDismiss = { confirm = false })
}

/**
 * The confirmation, shared by the button above and the "Wipe & Exit" item in
 * the screens' overflow menus: one dialog, one wording, one teardown order
 * (wipe first, then remove the task), wherever it is started from.
 */
@Composable
fun WipeAndExitDialog(onWipe: () -> Unit, onDismiss: () -> Unit) {
    val activity = LocalContext.current as? android.app.Activity
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(WipeAndExit.CONFIRM_TITLE) },
        text = { Text(WipeAndExit.CONFIRM_BODY) },
        confirmButton = {
            TextButton(
                onClick = {
                    onDismiss()
                    onWipe()
                    activity?.finishAndRemoveTask()
                },
                colors = ButtonDefaults.textButtonColors(
                    contentColor = MaterialTheme.colorScheme.error),
            ) { Text(WipeAndExit.CONFIRM) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(WipeAndExit.CANCEL) }
        },
    )
}
