// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
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
) {
    val own = jid.isBlank()
    val context = LocalContext.current
    LaunchedEffect(jid) { model.loadProfile(jid) }

    // Our edits, keyed by field; reset whenever a profile is (re)loaded.
    val edits = remember(model.profileValues, jid) {
        mutableStateMapOf<String, String>().apply { putAll(model.profileValues) }
    }
    val picker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) model.setOwnAvatar(OwnAvatar.pngFrom(context, uri))
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("Back") }
            Spacer(Modifier.width(8.dp))
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
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.size(72.dp).clip(CircleShape),
                )
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
