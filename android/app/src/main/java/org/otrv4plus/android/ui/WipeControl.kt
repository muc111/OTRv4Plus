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
fun WipeAndExitButton(onWipe: (Boolean) -> Unit, offerAccountDeletion: Boolean = false) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    OutlinedButton(
        onClick = { confirm = true },
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.error),
    ) { Text("Wipe & Exit") }
    if (confirm) WipeAndExitDialog(onWipe = onWipe, onDismiss = { confirm = false },
                                   offerAccountDeletion = offerAccountDeletion)
}

/**
 * The confirmation, shared by the button above and the "Wipe & Exit" item in
 * the screens' overflow menus: one dialog, one wording, one teardown order
 * (wipe first, then remove the task), wherever it is started from.
 */
@Composable
fun WipeAndExitDialog(onWipe: (Boolean) -> Unit, onDismiss: () -> Unit,
                      offerAccountDeletion: Boolean = false) {
    val activity = LocalContext.current as? android.app.Activity
    // Off by default, every time the dialog opens.
    var deleteAccount by rememberSaveable { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(WipeAndExit.CONFIRM_TITLE) },
        text = {
            androidx.compose.foundation.layout.Column {
                Text(WipeAndExit.CONFIRM_BODY)
                if (offerAccountDeletion) {
                    androidx.compose.foundation.layout.Row(
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Checkbox(checked = deleteAccount, onCheckedChange = { deleteAccount = it })
                        Text(WipeAndExit.DELETE_ACCOUNT_OPTION,
                             color = MaterialTheme.colorScheme.error)
                    }
                    if (deleteAccount) {
                        Text(WipeAndExit.DELETE_ACCOUNT_DETAIL,
                             style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onDismiss()
                    onWipe(offerAccountDeletion && deleteAccount)
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
