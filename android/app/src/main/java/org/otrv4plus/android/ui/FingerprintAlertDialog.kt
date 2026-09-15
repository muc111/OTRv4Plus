// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import org.otrv4plus.android.bridge.OtrEvent

/**
 * The pinned long-term key for a contact is not the one that just answered.
 *
 * WHY THIS BLOCKS
 * ---------------
 * `OtrEvent.FingerprintChanged` is the engine saying the key it has seen for
 * this peer is not the key it pinned. That is either an ordinary reinstall or
 * somebody in the middle, and nothing available locally can tell the two
 * apart -- which is exactly why the decision belongs to the person and not to
 * the app. A toast, a banner or a line in the history would be dismissed
 * without being read, so this is a dialog that cannot be dismissed by tapping
 * outside it or by the back button.
 *
 * WHAT IS SHOWN
 * -------------
 * Both fingerprints, in full and selectable, because comparing them over a
 * channel the attacker does not control is the only thing that resolves this.
 * Fingerprints are public verification material -- they are meant to be read
 * aloud. No key, session secret or passphrase appears here.
 *
 * There is no "trust this key" button. Acknowledging clears the warning; it
 * does not re-pin anything, because re-pinning on the strength of a dialog the
 * user wanted to get rid of is how a machine-in-the-middle gets accepted.
 */
@Composable
fun FingerprintAlertDialog(
    alert: OtrEvent.FingerprintChanged,
    onAcknowledge: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { /* Deliberately inert: must be acknowledged. */ },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
        ),
        title = { Text("Their key has changed") },
        text = {
            Column {
                Text(
                    "The key answering for ${alert.peer} is not the one " +
                        "pinned for them. This happens when someone " +
                        "reinstalls — and it is also what an interception " +
                        "looks like. Until you have compared these with them " +
                        "some other way, treat this conversation as " +
                        "unverified.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                Text("Previously pinned",
                    style = MaterialTheme.typography.labelMedium)
                SelectionContainer {
                    Text(alert.storedFingerprint,
                        style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(8.dp))
                Text("Received now", style = MaterialTheme.typography.labelMedium)
                SelectionContainer {
                    Text(
                        alert.receivedFingerprint,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onAcknowledge) { Text("I understand") }
        },
    )
}
