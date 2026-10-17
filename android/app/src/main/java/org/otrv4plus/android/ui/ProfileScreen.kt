// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.otrv4plus.android.chat.ChatViewModel

/**
 * The XMPP profile: ours to edit (with our picture), or a contact's to read.
 *
 * Every field comes from the bridge (`android_bridge/profile.py`), which
 * defines the set, caps each field and strips control and direction-override
 * characters -- from what we type before it is published, and from what a
 * contact's server returns before it is shown. Values are shown as plain
 * text: a web address is never a link here.
 *
 * Our picture is chosen here too. Whatever the user picks is decoded small,
 * cropped, scaled to 96 x 96 and saved again as a plain PNG ([OwnAvatar]),
 * so nothing else from the original file is published.
 *
 * @param jid blank for our own profile; a contact's address to view theirs.
 */
@Composable
fun ProfileScreen(
    model: ChatViewModel,
    ownJid: String,
    jid: String = "",
    onBack: () -> Unit,
    /** False when shown as a tab (our own profile): the bottom bar is the way out. */
    showBack: Boolean = true,
    /** Account actions under our own profile (Change password). */
    account: @Composable () -> Unit = {},
    /** A contact's profile: open their chat with the verification prompt. */
    onVerify: ((String) -> Unit)? = null,
) {
    val own = jid.isBlank()
    val context = LocalContext.current
    var enlarged by remember(jid) { mutableStateOf(false) }
    LaunchedEffect(jid) { model.loadProfile(jid); model.loadIdentity(jid) }

    // Our edits, keyed by field; reset whenever a profile is (re)loaded.
    val edits = remember(model.profileValues, jid) {
        mutableStateMapOf<String, String>().apply { putAll(model.profileValues) }
    }
    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        // Decoded off the main thread (a camera photo is megabytes); a
        // refusal says why rather than "could not be used".
        if (uri != null) model.setOwnAvatarFrom {
            when (val made = OwnAvatar.make(context, uri)) {
                is OwnAvatar.Made.Png -> made.bytes to ""
                is OwnAvatar.Made.Refused -> null to made.reason
            }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            // Edge to edge (MainActivity): inset from the status and
            // navigation bars like every non-Scaffold screen.
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (showBack) {
                TextButton(onClick = onBack) { Text("Back") }
                Spacer(Modifier.width(8.dp))
            }
            Text(
                if (own) "Your profile" else "Profile",
                style = MaterialTheme.typography.titleLarge,
            )
        }

        // ── picture ──────────────────────────────────────────────────────
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            val shown = if (own) ownJid else jid
            val picture = model.avatar(shown)
            if (picture != null) {
                Image(
                    bitmap = picture,
                    contentDescription = "Picture: tap to view it larger",
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(72.dp).clip(CircleShape)
                        .clickable(onClickLabel = "View larger") { enlarged = true },
                )
                if (enlarged) FullScreenPicture(picture) { enlarged = false }
            } else {
                Box(
                    Modifier.size(72.dp).clip(CircleShape)
                        .background(MaterialTheme.colorScheme.secondaryContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        shown.trimStart().take(1).uppercase().ifBlank { "?" },
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                    )
                }
            }
            Column {
                Text(shown, style = MaterialTheme.typography.bodyMedium)
                if (own) {
                    Row {
                        TextButton(onClick = { picker.launch(arrayOf("image/*")) }) {
                            Text("Choose picture")
                        }
                        TextButton(onClick = { model.removeOwnAvatar() }) {
                            Text("Remove")
                        }
                    }
                }
            }
        }
        if (own) {
            model.avatarStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            Text(
                "Your picture is scaled to 96 × 96 and saved again as a plain " +
                    "PNG before it is published, so nothing else from the " +
                    "original file (such as where a photo was taken) is sent. " +
                    "Only your contacts can see it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        HorizontalDivider()

        // ── fields ───────────────────────────────────────────────────────
        if (model.profileBusy && model.profileFields.isEmpty()) {
            CircularProgressIndicator()
        }
        for (field in model.profileFields) {
            if (own) {
                OutlinedTextField(
                    value = edits[field.key] ?: "",
                    onValueChange = { edits[field.key] = it.take(field.maxLength) },
                    label = { Text(field.label) },
                    singleLine = !field.multiline,
                    minLines = if (field.multiline) 3 else 1,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !model.profileBusy,
                )
            } else {
                val value = model.profileValues[field.key]
                if (!value.isNullOrBlank()) {
                    Column {
                        Text(
                            field.label,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Text(value, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        }

        model.profileStatus?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

        IdentitySection(model, own, jid, onVerify)

        if (own) {
            Button(
                onClick = { model.saveProfile(edits.toMap()) },
                enabled = !model.profileBusy && model.profileFields.isNotEmpty(),
            ) { Text("Save profile") }
            Text(
                "Your profile is public to every user of your XMPP server " +
                    "(that is how XMPP servers store it). Fill in only what " +
                    "you are happy for them to see. It is not encrypted.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            account()
        } else {
            Text(
                "Written by this person and shown as plain text. It is not " +
                    "verified: only their fingerprint and SMP prove who they are.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * A profile picture as large as the screen allows; a tap anywhere or Back
 * closes it. The picture is what the person published -- the app publishes
 * 96 x 96 (see [OwnAvatar]) -- so it is enlarged, not more detailed.
 */
@Composable
private fun FullScreenPicture(picture: ImageBitmap, onClose: () -> Unit) {
    Dialog(onDismissRequest = onClose,
           properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(
            Modifier.fillMaxSize().background(Color.Black)
                .clickable(onClickLabel = "Close", onClick = onClose),
            contentAlignment = Alignment.Center,
        ) {
            Image(
                bitmap = picture,
                contentDescription = "Profile picture",
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxWidth().aspectRatio(1f),
            )
        }
    }
}

/**
 * Whose key, and whether anyone checked (ProfileIdentity). The fingerprint is
 * the one the OTRv4+ session saw -- never anything from the profile above,
 * which the server stores and could change.
 */
@Composable
private fun IdentitySection(model: ChatViewModel, own: Boolean, jid: String,
                            onVerify: ((String) -> Unit)?) {
    HorizontalDivider()
    Text("Identity", style = MaterialTheme.typography.titleMedium)
    val mono = MaterialTheme.typography.bodyMedium.copy(
        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
    if (own) {
        Text("Your fingerprint", style = MaterialTheme.typography.labelMedium)
        androidx.compose.foundation.text.selection.SelectionContainer {
            Text(org.otrv4plus.android.chat.ProfileIdentity.group(model.ownFingerprint)
                     .ifBlank { "…" }, style = mono)
        }
        Text(org.otrv4plus.android.chat.ProfileIdentity.OWN_NOTE,
             style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    val view = org.otrv4plus.android.chat.ProfileIdentity.of(
        model.profileIdentity?.copy(localFingerprint = model.ownFingerprint))
    Text(view.status, style = MaterialTheme.typography.bodyMedium,
         color = if (view.alarm) MaterialTheme.colorScheme.error
                 else MaterialTheme.colorScheme.onSurface)
    if (view.theirs.isNotEmpty()) {
        Text("Their fingerprint", style = MaterialTheme.typography.labelMedium)
        androidx.compose.foundation.text.selection.SelectionContainer {
            Text(view.theirs, style = mono)
        }
        if (view.ours.isNotEmpty()) {
            Text("Yours", style = MaterialTheme.typography.labelMedium)
            androidx.compose.foundation.text.selection.SelectionContainer {
                Text(view.ours, style = mono)
            }
        }
        Text(org.otrv4plus.android.chat.ProfileIdentity.COMPARE,
             style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    var confirming by remember(jid) { mutableStateOf(false) }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (view.offerConfirm) {
            OutlinedButton(onClick = { confirming = true }) {
                Text(org.otrv4plus.android.chat.ProfileIdentity.CONFIRM_BUTTON)
            }
        }
        if (view.offerVerify && onVerify != null) {
            Button(onClick = { onVerify(jid) }) { Text("Verify with a shared secret") }
        }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text(org.otrv4plus.android.chat.ProfileIdentity.CONFIRM_TITLE) },
            text = { Text(org.otrv4plus.android.chat.ProfileIdentity.CONFIRM_BODY) },
            confirmButton = {
                TextButton(onClick = { confirming = false; model.confirmFingerprint(jid) }) {
                    Text(org.otrv4plus.android.chat.ProfileIdentity.CONFIRM_BUTTON)
                }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}
