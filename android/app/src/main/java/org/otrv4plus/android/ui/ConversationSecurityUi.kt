// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Location
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.MicPermission
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.HandshakeUi
import org.otrv4plus.android.crypto.Verification

// Encryption, verification and blocking parts of the conversation screen. Split from ConversationScreen.kt;
// shared helpers there are internal for that reason.

/**
 * The control that asks for encryption, or the sentence saying why not.
 *
 * WHY A BUTTON AND NOT A PICKER. With the providers this build ships —
 * OTRv4+ available, OMEMO 2 and MLS not implemented — the selector offers
 * exactly ONE protocol for a 1:1 and NONE for a room. A dropdown would imply
 * a decision the build cannot honour. The button names what it will start, so
 * the day a second protocol is genuinely available this becomes a picker and
 * not a lie in the meantime.
 *
 * WHY IT EXISTS AT ALL. Nothing in the Android UI could ask for OTR.
 * `ChatViewModel.startSession` had no caller and nothing outside `crypto/`
 * imported the encryption package, so every 1:1 stayed in the state
 * `OtrApp.send_user_text` calls "a conversation where nobody has asked for
 * OTR" — and correctly kept sending plaintext, forever, unless the far side
 * started it.
 *
 * An empty offer is a SENTENCE, never an empty menu: an empty menu is
 * indistinguishable from a broken one.
 */
@Composable
internal fun EncryptionOffer(
    offered: List<EncryptionKind>,
    reason: () -> String,
    onStart: () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (offered.isEmpty()) {
                Text(
                    reason(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f).padding(vertical = 8.dp),
                )
            } else {
                Text(
                    "This conversation can be encrypted.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                // Names the protocol rather than saying "Encrypt", because
                // which one it is matters and the label is the only place the
                // user is told.
                TextButton(onClick = onStart) {
                    Text("Start ${offered.first().label}")
                }
            }
        }
    }
}

/**
 * The identity-verification control, and the verified badge it becomes.
 *
 * WHY THIS IS SEPARATE FROM [EncryptionOffer]. They answer different
 * questions and appear at different times. Encryption asks "is this traffic
 * readable by the server"; verification asks "is this the person I think it
 * is". A conversation can be fully encrypted and completely unverified, which
 * is the normal state after a DAKE and is exactly what SMP exists to resolve.
 *
 * Hidden entirely before a session exists. There is nothing to verify without
 * one, and a disabled button would invite a user to wonder what they did
 * wrong -- [Verification.offer] returns HIDDEN and this draws nothing.
 */
@Composable
internal fun VerificationOffer(
    offer: Verification.Offer,
    steps: Pair<Int, Int>,
    onVerify: () -> Unit,
    onCancel: () -> Unit,
) {
    if (offer == Verification.Offer.HIDDEN) return
    val running = offer == Verification.Offer.IN_PROGRESS || offer == Verification.Offer.ANSWERING
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
      Column {
        // A moving bar while it runs (owner: users must see it is actively
        // trying); it fills as the SMP steps come back.
        if (running) {
            val fraction = Verification.progressFraction(steps.first, steps.second)
            if (fraction == null) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            else LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
        }
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                when (offer) {
                    // Says what verification WOULD buy, rather than just
                    // naming the feature. "Not verified" alone reads as a
                    // defect; this reads as a thing still to do.
                    Verification.Offer.VERIFY ->
                        "You have not checked who is on the other end."
                    Verification.Offer.IN_PROGRESS ->
                        Verification.progressLabel(steps.first, steps.second)
                    Verification.Offer.ANSWERING ->
                        "Answering their verification request… " +
                            Verification.progressLabel(steps.first, steps.second).removePrefix("Verifying… ")
                    Verification.Offer.VERIFIED -> "Identity Verified ✓"
                    Verification.Offer.HIDDEN -> ""
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f).padding(vertical = 8.dp),
            )
            when (offer) {
                Verification.Offer.VERIFY ->
                    TextButton(onClick = onVerify) { Text("Verify Identity") }
                // Cancel, not another Verify. A second run against a core
                // already holding one is the wrong operation, and the user's
                // only useful choice here is to stop.
                Verification.Offer.IN_PROGRESS,
                Verification.Offer.ANSWERING ->
                    TextButton(onClick = onCancel) { Text("Cancel") }
                // VERIFIED is a statement, not a control. Offering to verify
                // again would imply the last answer had expired.
                else -> Unit
            }
        }
      }
    }
}

/**
 * The passphrase prompt, for both directions.
 *
 * ONE DIALOG, TWO SENTENCES. The mechanism is identical either way -- both
 * sides type the same agreed text and the core proves they match without
 * transmitting it -- so a second dialog would be a second place to get the
 * handling of a secret wrong. Only the explanation differs, and it comes from
 * [Verification.explanation] where a JVM test can read it.
 *
 * WHY AN AUTOMATIC DIALOG IS SAFE HERE, AND WOULD NOT BE ON A TERMINAL
 * --------------------------------------------------------------------
 * docs/SECURITY_INVARIANTS.md INV-06: a remote peer may cause the client to ASK
 * for the passphrase, but may never cause the next thing the user types to
 * BECOME the passphrase. On a terminal those are one step apart, because
 * there is ONE input channel -- which is why `otrv4plus_smpflow.SmpFlow` puts
 * an explicit consent edge between them.
 *
 * Here the separation is structural instead. This field is its own widget: a
 * message typed into the composer goes to `ChatViewModel.send` and cannot
 * arrive here, whatever a peer does. The peer chooses when a dialog appears;
 * they cannot choose what any other input means.
 *
 * THE PASSPHRASE LIVES IN THIS COMPOSITION AND NOWHERE ELSE. `remember`, not
 * `rememberSaveable`: a saveable would put it in the savedInstanceState
 * Bundle, which Android writes to disk. It is cleared on both exits.
 */
@Composable
internal fun VerificationPrompt(
    prompt: Verification.Prompt,
    peer: String,
    onSubmit: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var secret by remember { mutableStateOf("") }
    val submit = {
        // Handed over and cleared on the same path, so the composition does
        // not keep it after the core has it.
        onSubmit(secret)
        secret = ""
    }
    val dismiss = {
        secret = ""
        onDismiss()
    }
    AlertDialog(
        onDismissRequest = dismiss,
        title = {
            Text(
                when (prompt) {
                    Verification.Prompt.OUTGOING -> "Verify Identity"
                    Verification.Prompt.INCOMING -> "Identity Verification"
                }
            )
        },
        text = {
            Column {
                Text(
                    Verification.explanation(prompt, peer),
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("Shared passphrase") },
                    singleLine = true,
                    // A passphrase prompt that shows the passphrase is not a
                    // passphrase prompt -- the same rule the connect screen
                    // applies to the account password.
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                    modifier = Modifier.fillMaxWidth()
                        .padding(top = 12.dp, bottom = 8.dp),
                )
                Text(
                    "Both of you must enter exactly the same text " +
                        "(${Verification.MIN_SECRET}-" +
                        "${Verification.MAX_SECRET} characters).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            // Disabled rather than failing after a round trip: the engine
            // refuses below the minimum and this says so before the wait.
            TextButton(
                enabled = Verification.acceptable(secret),
                onClick = submit,
            ) { Text("Verify") }
        },
        dismissButton = {
            TextButton(onClick = dismiss) { Text("Cancel") }
        },
    )
}

/**
 * What the engine says about this conversation, in words.
 *
 * ENCRYPTED without verification means the traffic is encrypted to somebody --
 * the DAKE ran, nobody checked who answered. That distinction is the whole
 * point of SMP, so the two must never read the same.
 */
@Composable
internal fun SecurityLine(state: SecurityState, capability: String = "unknown") {
    // Exhaustive on purpose -- no `else`. A new SecurityState must not be able
    // to arrive and quietly inherit whatever the fallback branch happened to
    // say; the compiler makes somebody decide what it means here.
    val (text, colour) = when (state) {
        // WHY it is not encrypted, from the capability: OTRv4+ on its way,
        // being checked, the contact offline, or their client does not speak
        // OTRv4Plus at all. Every variant says it is not encrypted.
        SecurityState.PLAINTEXT ->
            org.otrv4plus.android.crypto.OtrAvailability.plaintextLine(capability) to
                MaterialTheme.colorScheme.error
        SecurityState.ENCRYPTED ->
            "Encrypted, but you have not verified who is on the other end." to
                MaterialTheme.colorScheme.onSurfaceVariant
        SecurityState.FINGERPRINT ->
            "Encrypted. Their key matches the one pinned for them, but you " +
                "have not verified it in person." to
                MaterialTheme.colorScheme.onSurfaceVariant
        SecurityState.SMP_VERIFIED ->
            "Encrypted and verified." to VerifiedBlue
        // The loudest state in the app. Not a footnote and not a neutral
        // colour: the key is not the one pinned for this contact.
        SecurityState.FINGERPRINT_MISMATCH ->
            "WARNING: their key is not the one previously pinned for this " +
                "contact. Do not treat this conversation as verified." to
                MaterialTheme.colorScheme.error
    }
    // The level's mark, from the same model the conversation list uses, so a
    // conversation cannot read "Verified" in one place and something else in
    // the other -- and its shape carries the level without the colour.
    val mark = org.otrv4plus.android.crypto.SecurityLevel.of(state).mark
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(
            "$mark $text",
            style = MaterialTheme.typography.bodySmall,
            color = colour,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp,
                                                       vertical = 6.dp),
        )
    }
}

/**
 * Block a contact on the server (XEP-0191): every device of this account
 * stops receiving their messages and they stop seeing our presence. The
 * report (XEP-0377) goes to the server's operator, never to them.
 */
@Composable
internal fun BlockDialog(name: String, report: Boolean, onReport: (Boolean) -> Unit,
                        onBlock: (String) -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Block $name?") },
        text = {
            Column {
                Text("Their messages, calls and files stop reaching every device of " +
                     "this account, and they no longer see when you are online. " +
                     "They are not told.")
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = report, onCheckedChange = onReport)
                    Text("Also report as spam to the server")
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onBlock(if (report) "spam" else "") }) {
                Text("Block", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
