// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.OnlineUsers

/**
 * People: the one list of everybody this account knows about -- roster
 * contacts, people asking to add us, and people the Welcome room (or the
 * server) says are online. Opened from the button beside the connection
 * state on the chat list.
 *
 * BUILT FOR A BUSY SERVER. The rows are a LazyColumn keyed by bare JID, so
 * only what is on screen is composed, and search narrows the list locally
 * (`OnlineUsers.search`): nothing typed here is sent anywhere, so the search
 * box cannot be used to probe whether an account exists.
 *
 * NOTHING IS ADDED BY BEING SEEN. "Online — Add" rows have an Add button;
 * nothing else on this screen changes the roster, and appearing online (in
 * the Welcome room or anywhere) adds nobody.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeopleScreen(
    model: ChatViewModel,
    onBack: () -> Unit,
    onOpenChat: (String) -> Unit,
) {
    var query by rememberSaveable { mutableStateOf("") }
    var showing by rememberSaveable { mutableStateOf<String?>(null) }
    var confirmWelcome by remember { mutableStateOf(false) }
    val all = model.directory
    val shown = OnlineUsers.search(all, query)

    LaunchedEffect(Unit) { model.refreshDiscovery() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(OnlineUsers.directoryTitle(all)) },
                navigationIcon = { TextButton(onClick = onBack) { Text("Back") } },
                actions = {
                    TextButton(onClick = { model.refreshDiscovery(force = true) }) {
                        Text("Refresh")
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                placeholder = { Text("Search name or address") },
                modifier = Modifier.fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 4.dp),
            )
            model.discoveryNote?.let {
                Text(it, style = MaterialTheme.typography.bodySmall,
                     modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
            }
            if (model.welcomeMissing && model.canSend()) {
                OutlinedButton(
                    enabled = !model.creatingWelcome,
                    onClick = { confirmWelcome = true },
                    modifier = Modifier.padding(horizontal = 12.dp),
                ) {
                    Text(if (model.creatingWelcome) "Creating the Welcome room…"
                         else "Create the OTRv4Plus Welcome room")
                }
            }
            when {
                all.isEmpty() -> Text(
                    "Nobody yet. Add someone by address with + on the chat list.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp))
                shown.isEmpty() -> Text(
                    "Nobody matches “$query”.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(12.dp))
            }
            LazyColumn(Modifier.weight(1f)) {
                items(shown, key = { it.jid }) { entry ->
                    PersonRow(
                        entry,
                        onOpen = { showing = entry.jid },
                        onAdd = { model.addContact(entry.jid) },
                        onAccept = { model.answerSubscription(entry.jid, true) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }

    // Details: looked up by JID each composition, so a row that changes
    // (accepted, went offline) under an open sheet shows the new state.
    showing?.let { jid ->
        val entry = all.firstOrNull { it.jid == jid }
        if (entry == null) {
            // The person left the list (removed, account switched): close.
            LaunchedEffect(jid) { showing = null }
        } else {
            PersonDetails(
                entry,
                onChat = { showing = null; onOpenChat(entry.jid) },
                onAdd = { model.addContact(entry.jid) },
                onAccept = { model.answerSubscription(entry.jid, true) },
                onDismiss = { showing = null },
            )
        }
    }

    if (confirmWelcome) {
        AlertDialog(
            onDismissRequest = { confirmWelcome = false },
            title = { Text("Create the Welcome room?") },
            text = { Text(OnlineUsers.WELCOME_CREATE_WARNING) },
            confirmButton = {
                TextButton(onClick = { confirmWelcome = false; model.createWelcomeRoom() }) {
                    Text("Create")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmWelcome = false }) { Text("Cancel") }
            },
        )
    }
}

/** One compact row: name, then relation and security facts on one line. */
@Composable
private fun PersonRow(
    entry: OnlineUsers.Entry,
    onOpen: () -> Unit,
    onAdd: () -> Unit,
    onAccept: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onOpen)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(entry.displayName, style = MaterialTheme.typography.bodyMedium,
                 maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(entry.facts.joinToString(" · "),
                 style = MaterialTheme.typography.labelSmall,
                 maxLines = 1, overflow = TextOverflow.Ellipsis,
                 color = if (entry.verified) VerifiedBlue
                         else MaterialTheme.colorScheme.onSurfaceVariant)
        }
        RelationAction(entry, onAdd, onAccept)
    }
}

@Composable
private fun RelationAction(entry: OnlineUsers.Entry, onAdd: () -> Unit, onAccept: () -> Unit) {
    when (entry.relation) {
        OnlineUsers.Relation.ONLINE_ADD ->
            OutlinedButton(onClick = onAdd) { Text(entry.relation.action ?: "Add") }
        OnlineUsers.Relation.ACCEPT ->
            Button(onClick = onAccept) { Text(entry.relation.action ?: "Accept") }
        else -> {}
    }
}

@Composable
private fun PersonDetails(
    entry: OnlineUsers.Entry,
    onChat: () -> Unit,
    onAdd: () -> Unit,
    onAccept: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(entry.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for ((label, value) in OnlineUsers.details(entry)) {
                    Row {
                        Text("$label: ", style = MaterialTheme.typography.labelMedium)
                        Text(value, style = MaterialTheme.typography.bodySmall)
                    }
                }
                RelationAction(entry, onAdd, onAccept)
            }
        },
        confirmButton = { TextButton(onClick = onChat) { Text("Open chat") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
