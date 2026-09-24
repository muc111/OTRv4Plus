// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.chat.ChatDeletion
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Conversation
import org.otrv4plus.android.chat.OnlineUsers
import org.otrv4plus.android.chat.Presence
import org.otrv4plus.android.chat.RowSecurity
import org.otrv4plus.android.theme.ThemeTokens

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
    onOpenRooms: () -> Unit = {},
    onOpenDiagnostics: () -> Unit = {},
    onOpenAbout: () -> Unit = {},
    onWipeAndExit: (() -> Unit)? = null,
    theme: ThemeTokens.Mode = ThemeTokens.DEFAULT,
    onTheme: ((ThemeTokens.Mode) -> Unit)? = null,
) {
    var choosingTheme by rememberSaveable { mutableStateOf(false) }
    val conversations = model.conversations()
    var showAdd by rememberSaveable { mutableStateOf(false) }
    // A JID, not a Conversation: the row can change under an open dialog.
    var deleting by rememberSaveable { mutableStateOf<String?>(null) }

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

            // Above the conversation list and below the connection state,
            // because it is about this account rather than about any one
            // conversation. Every pending request is rendered: a second asker
            // hidden behind the first is a question the user never gets.
            for (request in model.pendingSubscriptions) {
                SubscriptionBanner(
                    request = request,
                    onAllow = { model.answerSubscription(request.peer, true) },
                    onDecline = { model.answerSubscription(request.peer, false) },
                    onIgnore = { model.dismissSubscription(request.peer) },
                    onRevoke = { model.removeContact(request.peer) },
                )
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

            // PEOPLE: one list -- roster, requests, and who the server says
            // is online -- with Add / Pending / Accept / Added per row.
            // Collapsed by default so it does not push the conversations off
            // a small screen; the counts are live either way.
            if (model.canSend()) {
                PeopleSection(
                    entries = model.directory,
                    note = model.discoveryNote,
                    onOpen = onOpen,
                    onAdd = { model.addContact(it) },
                    onAccept = { model.answerSubscription(it, true) },
                    onRefresh = { model.refreshDiscovery(force = true) },
                    welcomeMissing = model.welcomeMissing,
                    creatingWelcome = model.creatingWelcome,
                    onCreateWelcome = { model.createWelcomeRoom() },
                )
            }

            if (conversations.isEmpty()) {
                // `weight(1f)`, NOT the child's own fillMaxSize().
                //
                // THE BUG THIS FIXES. `EmptyConversations` declared
                // `Modifier.fillMaxSize()`, which in a non-scrolling Column
                // takes the whole remaining height -- so the Rooms / Debug /
                // About row below was laid out past the bottom of the screen
                // and could not be reached. The moment any conversation
                // existed the other branch ran instead, and that one IS
                // bounded by weight(1f), so the row reappeared.
                //
                // On a handset that read as "Rooms only works after somebody
                // messages me", which looked like an XMPP initialisation
                // fault and was a layout constraint.
                EmptyConversations(
                    modifier = Modifier.weight(1f),
                    connected = model.canSend(),
                    onAdd = { showAdd = true },
                )
            } else {
                LazyColumn(Modifier.weight(1f)) {
                    items(conversations, key = { it.jid }) { conversation ->
                        ConversationRow(
                            conversation,
                            onClick = { onOpen(conversation.jid) },
                            onLongClick = { deleting = conversation.jid },
                        )
                        HorizontalDivider()
                    }
                }
            }

            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // Rooms sit alongside one-to-one conversations rather
                // than inside them: a room is group chat and is not
                // end-to-end encrypted, and listing rooms among
                // conversations would blur two things that have
                // different guarantees.
                TextButton(onClick = onOpenRooms) { Text("Rooms") }
                TextButton(onClick = onOpenDiagnostics) { Text("Debug") }
                TextButton(onClick = onOpenAbout) { Text("About & licences") }
                if (onTheme != null) {
                    TextButton(onClick = { choosingTheme = true }) { Text("Theme") }
                }
            }
            // At the foot of the main list, beside Debug and Licences, so it
            // is reachable without going back to the connection screen. The
            // same control, confirmation and teardown as there.
            onWipeAndExit?.let { wipe ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.End) {
                    WipeAndExitButton(onWipe = wipe)
                }
            }
        }
    }

    deleting?.let { jid ->
        val kind = model.deletionKind(jid)
        val name = model.conversation(jid).displayName
        DeleteChatDialog(
            kind = kind,
            name = name,
            canLeave = kind == ChatDeletion.Kind.ROOM && model.inRoom(jid),
            onDelete = { leave -> model.deleteChat(jid, leaveRoom = leave); deleting = null },
            onDismiss = { deleting = null },
        )
    }

    if (choosingTheme && onTheme != null) {
        AlertDialog(
            onDismissRequest = { choosingTheme = false },
            title = { Text("Theme") },
            text = {
                Column {
                    for (mode in ThemeTokens.Mode.entries) {
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                onTheme(mode); choosingTheme = false
                            }.padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = mode == theme,
                                        onClick = { onTheme(mode); choosingTheme = false })
                            Text(mode.label + if (mode == ThemeTokens.DEFAULT) " (default)" else "")
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { choosingTheme = false }) { Text("Done") }
            },
        )
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

/**
 * Somebody asked to see this account's presence.
 *
 * TWO DIFFERENT BANNERS, because they are two different facts and rendering
 * them the same way would mean lying about one of them.
 *
 * Under `ASK` nothing has been answered: the user decides, and the buttons
 * are Allow and Decline. Under the shipped `ACCEPT` the server library said
 * yes before this app was told anything, so offering "Decline" would be
 * offering to undo something already done — the honest sentence is that they
 * can now see you, and the remedy is revoking.
 *
 * "Not now" is deliberately separate from "Decline". Declining tells the
 * asker no, which is itself a signal that this account exists and is in use;
 * saying nothing leaves them pending on the server. On an anonymity-oriented
 * messenger that difference belongs to the user.
 *
 * WHAT IT DOES NOT SAY. Nothing about encryption. A subscription grants
 * presence, not the ability to read anything: messages stay plaintext until a
 * DAKE runs, and the conversation screen is where that is said.
 */
@Composable
private fun SubscriptionBanner(
    request: OtrEvent.SubscriptionRequested,
    onAllow: () -> Unit,
    onDecline: () -> Unit,
    onIgnore: () -> Unit,
    onRevoke: () -> Unit,
) {
    val peer = ChatState.bare(request.peer)
    Surface(color = MaterialTheme.colorScheme.tertiaryContainer) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            Text(
                if (request.isQuestion) "$peer wants to see when you are online."
                else "$peer can now see when you are online.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
            )
            Text(
                "This shares your presence, not your messages.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(top = 2.dp),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (request.isQuestion) {
                    TextButton(onClick = onAllow) { Text("Allow") }
                    TextButton(onClick = onDecline) { Text("Decline") }
                    TextButton(onClick = onIgnore) { Text("Not now") }
                } else {
                    TextButton(onClick = onRevoke) { Text("Revoke") }
                    TextButton(onClick = onIgnore) { Text("OK") }
                }
            }
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
private fun EmptyConversations(
    modifier: Modifier = Modifier,
    connected: Boolean,
    onAdd: () -> Unit,
) {
    Column(
        modifier.fillMaxWidth().padding(32.dp),
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
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ConversationRow(
    conversation: Conversation,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth()
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongClick,
                onLongClickLabel = "Delete chat",
            )
            .padding(12.dp),
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
                    conversation.preview.ifBlank {
                        // "not in your contacts" beats "presence unknown"
                        // here: both are true, and only one of them says
                        // what to do about it.
                        if (conversation.canBeSaved) "not in your contacts"
                        else presenceWord(conversation.presence)
                    },
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
            SecurityBadge(conversation)
        }
    }
}

/**
 * What this row says about its security. A WORD, never a padlock.
 *
 * `ConversationScreen` states the rule this follows: an icon blurs "the
 * network is up" into "this is safe", and a padlock next to a plaintext
 * message is the one claim this project cannot afford to get wrong. The
 * decision lives in [RowSecurity], which is plain Kotlin and driven by
 * `RowSecurityTest`; this maps its three tones onto the theme and nothing
 * else.
 */
@Composable
private fun SecurityBadge(conversation: Conversation) {
    val badge = RowSecurity.badge(
        security = conversation.security,
        smp = conversation.smp,
        hasHistory = conversation.lastMessage != null,
    ) ?: return
    Text(
        // Mark first: its SHAPE tells the levels apart without colour.
        if (badge.mark.isEmpty()) badge.text else "${badge.mark} ${badge.text}",
        style = MaterialTheme.typography.labelSmall,
        color = when (badge.tone) {
            RowSecurity.Tone.ALARM -> MaterialTheme.colorScheme.error
            RowSecurity.Tone.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
            RowSecurity.Tone.GOOD -> VerifiedBlue
        },
    )
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

/**
 * Confirm "Delete chat". Every word comes from [ChatDeletion].
 *
 * A room gets "Delete and leave room" only when there is a room to leave, and
 * never anything that destroys it: destroying is an owner action on the
 * Rooms screen, for a room other people are in.
 */
@Composable
private fun DeleteChatDialog(
    kind: ChatDeletion.Kind,
    name: String,
    canLeave: Boolean,
    onDelete: (leave: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(ChatDeletion.confirmTitle(kind, name)) },
        text = { Text(ChatDeletion.confirmBody(kind)) },
        confirmButton = {
            Column(horizontalAlignment = Alignment.End) {
                if (canLeave) {
                    TextButton(
                        onClick = { onDelete(true) },
                        colors = ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error),
                    ) { Text(ChatDeletion.CONFIRM_AND_LEAVE) }
                }
                TextButton(
                    onClick = { onDelete(false) },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error),
                ) { Text(ChatDeletion.CONFIRM) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(ChatDeletion.CANCEL) } },
    )
}

/**
 * "PEOPLE (n · m online)", expandable. Each row names the relation in words
 * (Online — Add, Pending, Wants to add you — Accept, Online/Offline — Added)
 * and, separately, the security facts; a tap opens that person's one
 * conversation. The action button, when there is one, is the only thing on
 * the row that changes anything.
 */
@Composable
private fun PeopleSection(
    entries: List<OnlineUsers.Entry>,
    note: String?,
    onOpen: (String) -> Unit,
    onAdd: (String) -> Unit,
    onAccept: (String) -> Unit,
    onRefresh: () -> Unit,
    welcomeMissing: Boolean = false,
    creatingWelcome: Boolean = false,
    onCreateWelcome: () -> Unit = {},
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var confirmWelcome by remember { mutableStateOf(false) }
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                Modifier.fillMaxWidth().clickable { expanded = !expanded }
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(OnlineUsers.directoryTitle(entries),
                     style = MaterialTheme.typography.labelLarge)
                Text(if (expanded) "Hide" else "Show",
                     style = MaterialTheme.typography.labelSmall)
            }
            if (expanded) {
                note?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall,
                         modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
                }
                TextButton(onClick = onRefresh,
                           modifier = Modifier.padding(horizontal = 4.dp)) {
                    Text("Ask the server again")
                }
                // Only when the server has none, and only after the warning.
                if (welcomeMissing) {
                    OutlinedButton(
                        enabled = !creatingWelcome,
                        onClick = { confirmWelcome = true },
                        modifier = Modifier.padding(horizontal = 12.dp),
                    ) {
                        Text(if (creatingWelcome) "Creating the Welcome room…"
                             else "Create the OTRv4Plus Welcome room")
                    }
                }
                if (entries.isEmpty()) {
                    Text("Nobody yet. Add someone by address with +.",
                         style = MaterialTheme.typography.bodySmall,
                         modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
                }
                for (entry in entries) {
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpen(entry.jid) }
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(entry.displayName,
                                 style = MaterialTheme.typography.bodyMedium)
                            Text(
                                entry.facts.joinToString(" · "),
                                style = MaterialTheme.typography.labelSmall,
                                color = if (entry.verified) VerifiedBlue
                                        else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        when (entry.relation) {
                            OnlineUsers.Relation.ONLINE_ADD ->
                                OutlinedButton(onClick = { onAdd(entry.jid) }) {
                                    Text(entry.relation.action ?: "Add")
                                }
                            OnlineUsers.Relation.ACCEPT ->
                                Button(onClick = { onAccept(entry.jid) }) {
                                    Text(entry.relation.action ?: "Accept")
                                }
                            else -> {}
                        }
                    }
                }
            }
        }
    }
    if (confirmWelcome) {
        AlertDialog(
            onDismissRequest = { confirmWelcome = false },
            title = { Text("Create the Welcome room?") },
            text = { Text(OnlineUsers.WELCOME_CREATE_WARNING) },
            confirmButton = {
                TextButton(onClick = { confirmWelcome = false; onCreateWelcome() }) {
                    Text("Create")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmWelcome = false }) { Text("Cancel") }
            },
        )
    }
}
