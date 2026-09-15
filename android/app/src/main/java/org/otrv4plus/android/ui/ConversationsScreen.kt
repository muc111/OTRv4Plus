// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Conversation
import org.otrv4plus.android.chat.Presence

/**
 * The home screen once you are connected: who you can talk to.
 *
 * Conversation-first. The list is the application; everything else --
 * diagnostics, licences, the connection -- is one tap away and not in the way.
 *
 * Every row comes from the real roster and the real message store. Nothing is
 * hard-coded, and a contact with no history still gets a row, because you have
 * to be able to start a conversation with someone you have never messaged.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationsScreen(
    model: ChatViewModel,
    onOpen: (String) -> Unit,
    onOpenConnection: () -> Unit = {},
    onOpenDiagnostics: () -> Unit = {},
    onOpenAbout: () -> Unit = {},
) {
    val conversations = model.conversations()
    var showAdd by rememberSaveable { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("OTRv4+") },
                actions = {
                    TextButton(onClick = onOpenConnection) {
                        Text(when {
                            model.link != ChatState.Link.OK -> "Checking…"
                            model.connection.connected -> "Connected"
                            else -> "Not connected"
                        })
                    }
                },
            )
        },
        floatingActionButton = {
            if (model.canSend()) {
                FloatingActionButton(onClick = { showAdd = true }) { Text("+") }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {

            // Three states, not two. Saying "not connected" when we have
            // merely failed to ASK is a claim the app cannot support, and it
            // is the one that stops the user trying.
            when {
                model.link == ChatState.Link.OK && !model.connection.connected ->
                    DisconnectedBanner(onOpenConnection)

                model.link == ChatState.Link.FAILING ->
                    LinkBanner(
                        "Cannot read the connection state" +
                            (model.readFailure?.let { " ($it)" } ?: "") + ".",
                    )

                model.link == ChatState.Link.UNKNOWN ->
                    LinkBanner("Checking the connection…")
            }

            model.notice?.let { notice ->
                NoticeBanner(notice) { model.dismissNotice() }
            }

            if (model.droppedEvents > 0) {
                Text(
                    "${model.droppedEvents} update(s) were dropped while the " +
                        "app was busy.",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }

            if (conversations.isEmpty()) {
                EmptyConversations(
                    connected = model.canSend(),
                    onAdd = { showAdd = true },
                )
            } else {
                LazyColumn(Modifier.weight(1f)) {
                    items(conversations, key = { it.jid }) { conversation ->
                        ConversationRow(conversation) { onOpen(conversation.jid) }
                        HorizontalDivider()
                    }
                }
            }

            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextButton(onClick = onOpenDiagnostics) { Text("Diagnostics") }
                TextButton(onClick = onOpenAbout) { Text("About & licences") }
            }
        }
    }

    if (showAdd) {
        AddContactDialog(
            onAdd = { jid -> model.addContact(jid); showAdd = false },
            onDismiss = { showAdd = false },
        )
    }
}

/**
 * "We do not know", which is not "it is down".
 *
 * Deliberately a different colour and a different sentence from
 * [DisconnectedBanner]. The failure it reports is in this app, not on the
 * network, and offering a Connect button here would send the user to fix
 * something that may not be broken. The code is shown because the alternative
 * -- what shipped -- was a silent failure that took a device round trip and a
 * source audit to identify.
 */
@Composable
private fun LinkBanner(text: String) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.fillMaxWidth().padding(12.dp),
        )
    }
}

/** The answer to something the user just did. Dismissible, because it is. */
@Composable
private fun NoticeBanner(text: String, onDismiss: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onDismiss) { Text("OK") }
        }
    }
}

@Composable
private fun DisconnectedBanner(onOpenConnection: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.errorContainer) {
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                "Not connected. Messages cannot be sent or received.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onOpenConnection) { Text("Connect") }
        }
    }
}

@Composable
private fun EmptyConversations(connected: Boolean, onAdd: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("No conversations yet",
            style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            if (connected)
                "Your roster is fetched when you connect, so anyone already " +
                    "on it appears here on its own. Add someone by address to " +
                    "start."
            else
                "Connect to fetch your contacts.",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (connected) {
            Spacer(Modifier.height(16.dp))
            Button(onClick = onAdd) { Text("Add a contact") }
        }
    }
}

/**
 * One row: who, whether they are there, what was last said, and when.
 *
 * The avatar is a letter in a circle. No avatar protocol is implemented and
 * inventing one would be a network request per contact -- which on an
 * anonymity-oriented client is a new place to leak who you talk to.
 */
@Composable
private fun ConversationRow(conversation: Conversation, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AvatarPlaceholder(conversation.displayName)

        Column(Modifier.weight(1f)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    conversation.displayName,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (conversation.unread > 0) FontWeight.Bold
                                 else FontWeight.Normal,
                    modifier = Modifier.weight(1f, fill = false),
                )
                if (conversation.lastAt > 0) {
                    Text(
                        formatTimestamp(conversation.lastAt),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    conversation.preview.ifBlank { presenceWord(conversation.presence) },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Spacer(Modifier.width(8.dp))
                PresenceDot(conversation.presence)
                if (conversation.unread > 0) {
                    Spacer(Modifier.width(6.dp))
                    UnreadBadge(conversation.unread)
                }
            }
        }
    }
}

@Composable
private fun AvatarPlaceholder(name: String) {
    Box(
        Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.secondaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            name.trimStart().take(1).uppercase().ifBlank { "?" },
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
        )
    }
}

/**
 * Presence as a word, not only a colour.
 *
 * A coloured dot alone is unreadable to anyone who cannot distinguish the
 * colours, and "unknown" and "offline" are genuinely different states that no
 * pair of colours makes obvious.
 */
@Composable
internal fun PresenceDot(presence: Presence) {
    Text(
        presenceWord(presence),
        style = MaterialTheme.typography.labelSmall,
        color = when (presence) {
            Presence.ONLINE -> MaterialTheme.colorScheme.primary
            Presence.OFFLINE -> MaterialTheme.colorScheme.onSurfaceVariant
            Presence.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
            // Not an error colour. Nothing is wrong: the other person has
            // simply not answered yet, and red would say otherwise.
            Presence.PENDING -> MaterialTheme.colorScheme.tertiary
        },
    )
}

internal fun presenceWord(presence: Presence): String = when (presence) {
    Presence.ONLINE -> "online"
    Presence.OFFLINE -> "offline"
    // Not "offline". We have not heard, which is a different claim.
    Presence.UNKNOWN -> "presence unknown"
    // Says WHY, which "presence unknown" cannot. A contact who has not yet
    // approved the request stays unknown for as long as they take to answer,
    // and without this the only conclusion available to the user is that the
    // app is broken.
    Presence.PENDING -> "waiting for them to accept"
}

@Composable
private fun UnreadBadge(count: Int) {
    Box(
        Modifier
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.primary)
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(
            if (count > 99) "99+" else count.toString(),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimary,
        )
    }
}

@Composable
private fun AddContactDialog(onAdd: (String) -> Unit, onDismiss: () -> Unit) {
    var jid by rememberSaveable { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add a contact") },
        text = {
            Column {
                Text(
                    "Their full address. Adding them asks to see their " +
                        "presence; they decide whether to allow it.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = jid,
                    onValueChange = { jid = it },
                    label = { Text("Address") },
                    placeholder = { Text("someone@server.i2p") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Email),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = jid.contains("@") && !jid.trim().endsWith("@"),
                onClick = { onAdd(jid.trim()) },
            ) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
