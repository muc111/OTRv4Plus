// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.RoomsViewModel
import org.otrv4plus.android.chat.RoomPassword
import org.otrv4plus.android.chat.RoomSections
import androidx.compose.ui.graphics.Color

/**
 * Rooms: what this server hosts, and which of them you are in.
 *
 * THE ONE THING THIS SCREEN MUST SAY. A room is not encrypted. OTRv4+ is a
 * two-party protocol and a MUC message is fanned out by the service to
 * everybody present, so a room is plaintext to the server hosting it. That is
 * a property of group chat, not a gap in this app, and it is stated here in
 * one sentence rather than left to be inferred from the absence of a padlock —
 * an app that shows encryption on one screen and says nothing on another is
 * inviting the wrong conclusion.
 *
 * TWO KINDS, KEPT APART (owner, 2026-10-17). Encrypted groups (MLS) first:
 * yours, then the ones on this server you can ask to join. Plain rooms below
 * them, under a heading that says they are not encrypted -- the only place a
 * room password is offered. An encrypted group never gets one: it is
 * invite-only already (see RoomSections).
 *
 * THE SERVICE IS DISCOVERED, NOT ASSUMED. `conference.<domain>` is a
 * convention and not a rule; `rooms.`, `muc.` and `chat.` are all in use. The
 * app asks (XEP-0030) rather than guessing, because guessing wrong costs an
 * I2P round trip to find out.
 *
 * WHAT IS OFFERED IS WHAT THE SERVICE WILL ALLOW. Destroy appears only for an
 * owner, per `otrv4plus_muc.privileges` and XEP-0045 §5.1 — not as a courtesy,
 * but because a button that fails minutes after it is pressed teaches people
 * the app is unreliable. It is still the service that decides; this only
 * avoids inviting a refusal.
 */
@Composable
fun RoomsScreen(
    model: RoomsViewModel,
    defaultNick: String = "",
    onBack: () -> Unit = {},
    /** Called with the room JID once a join or create is confirmed. */
    onOpenRoom: (String) -> Unit = {},
    /** False when shown as a tab: the bottom bar is the way out. */
    showBack: Boolean = true,
) {
    val busy = model.busy
    val last = model.last

    var nick by rememberSaveable { mutableStateOf(defaultNick) }
    var address by rememberSaveable { mutableStateOf("") }
    // The room a Delete is waiting to be confirmed for (search row or typed).
    var deletingRoom by rememberSaveable { mutableStateOf<String?>(null) }

    // Once, when the screen is first shown AND there is something to ask.
    // Discovery is two round trips over I2P, so repeating it on every
    // recomposition would make the screen unusable; `model.discovered` is what
    // makes a second visit instant.
    //
    // Keyed on the core rather than on Unit: the service binding can land
    // after this screen is composed, and a Unit key would mean a screen opened
    // in that window asked a null core, gave up, and never tried again.
    LaunchedEffect(model.core, model.discovered, model.discoverTries) {
        // Again by itself a few times when the answer did not come (lost over
        // I2P, or asked before sign-in finished), then on "Look again".
        if (model.core != null && !model.discovered &&
            model.discoverTries < RoomsViewModel.MAX_AUTO_DISCOVER) {
            if (model.discoverTries > 0) kotlinx.coroutines.delay(RoomsViewModel.DISCOVER_RETRY_MS)
            model.discover()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            // The window no longer fits the decor -- MainActivity turns that
            // off so the keyboard is handled by exactly one mechanism -- so
            // every screen that is not a Scaffold has to inset itself. Without
            // this the title sits under the status bar and the last control
            // sits under the navigation bar.
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Rooms", style = MaterialTheme.typography.headlineMedium)

        // Said once, plainly, at the top. Not a warning banner in red: this is
        // how group chat works everywhere, and dressing it as an alarm would
        // make it something to dismiss rather than something to know.
        Text(
            "Two kinds of group. An encrypted group (\uD83D\uDD10, MLS+) is " +
                "private: only its members can read it, and members join by " +
                "invitation over an encrypted OTRv4+ conversation. A plain " +
                "room (#) is not end-to-end encrypted: " +
                "the server hosting the room can read it. " +
                "One-to-one conversations are different.",
            style = MaterialTheme.typography.bodySmall,
        )

        busy?.let {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(it, style = MaterialTheme.typography.bodySmall)
        }

        last?.let {
            Text(
                it.detail,
                style = MaterialTheme.typography.bodySmall,
                color = if (it.ok) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.error,
            )
            if (it.isAboutTheNickname) {
                Text("Try a different nickname.",
                    style = MaterialTheme.typography.bodySmall)
            } else if (it.worthRetrying) {
                TextButton(onClick = { model.clearLast() }) { Text("Dismiss") }
            }
        }

        // ── Which service ─────────────────────────────────────────────────
        val service = model.roomService
        if (!model.discovered && busy == null && model.discoverTries > 0) {
            // Not an answer yet: the question did not get through.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("The server's rooms list has not answered yet (replies " +
                         "can be lost over I2P).",
                     style = MaterialTheme.typography.bodySmall,
                     modifier = Modifier.weight(1f))
                TextButton(onClick = { model.discover() }) { Text("Look again") }
            }
        }
        if (model.discovered && service == null) {
            // A finding, not an empty screen. "We asked and there is no rooms
            // service here" is different from "we have not asked".
            Text(
                "This server does not advertise a rooms service, so there " +
                    "are no rooms to list. You can still join one by " +
                    "address if you know it.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        // ── Who you are in a room ─────────────────────────────────────────
        OutlinedTextField(
            value = nick,
            onValueChange = { nick = it },
            label = { Text("Nickname in rooms") },
            supportingText = {
                Text("How others see you. It does not have to be your " +
                     "username.")
            },
            singleLine = true,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth(),
        )

        // Move into the room the server confirmed we entered.
        //
        // There was no state for this at all, which is the other half of
        // "create never progresses to the next view". It is driven by the
        // authoritative outcome, so a refused join cannot open a room the
        // user is not in.
        LaunchedEffect(model.entered) {
            model.entered?.let { room ->
                model.clearEntered()
                onOpenRoom(room)
            }
        }

        // The server's list, sorted by kind (RoomSections): encrypted groups
        // we are not in, and plain rooms.
        val split = RoomSections.split(model.rooms, model.secureGroups)

        EncryptedGroupsSection(model, busy, service, nick, onOpenRoom)

        // ── Encrypted groups on this server we are not in ────────────────
        if (service != null && split.encrypted.isNotEmpty()) {
            Section(
                title = "🔐 " + RoomSections.ON_SERVER_TITLE,
                note = RoomSections.ON_SERVER_NOTE,
                color = MaterialTheme.colorScheme.secondaryContainer,
                action = {
                    TextButton(enabled = busy == null,
                               onClick = { model.refreshRooms(service) }) { Text("Refresh") }
                },
            ) {
                for (room in split.encrypted) {
                    ListedRoom(model, room, busy, onDelete = { deletingRoom = room.jid }) {
                        TextButton(
                            enabled = busy == null,
                            onClick = { model.joinListed(room, nick.trim()) },
                        ) { Text("Ask to join") }
                    }
                }
            }
        }

        PlainRoomsSection(model, busy, service, nick, split, address,
                          onAddressChange = { address = it },
                          onDelete = { deletingRoom = it })

        RoomDialogs(model, busy, deletingRoom, onDismissDelete = { deletingRoom = null })

        if (showBack) {
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onBack) { Text("Back") }
        }
    }
}

/** The encrypted groups this account holds keys for, and making a new one. */
@Composable
private fun EncryptedGroupsSection(
    model: RoomsViewModel,
    busy: String?,
    service: String?,
    nick: String,
    onOpenRoom: (String) -> Unit,
) {
    // ══ Encrypted groups ══════════════════════════════════════════════
    // Listed from the engine, not the server: these are the groups this
    // account holds keys for, whether or not their room is joined yet.
    LaunchedEffect(model.core) { if (model.core != null) model.refreshSecureGroups() }
    var deleting by rememberSaveable { mutableStateOf<String?>(null) }
    Section(
        title = "🔐 " + RoomSections.MINE_TITLE,
        note = RoomSections.MINE_NOTE,
        color = MaterialTheme.colorScheme.primaryContainer,
        action = {
            TextButton(enabled = busy == null, onClick = { model.refreshSecureGroups() }) {
                Text("Refresh")
            }
        },
    ) {
        if (model.secureGroups.isEmpty()) {
            Text("None yet. Create one below, or accept an invitation.",
                 style = MaterialTheme.typography.bodySmall)
        }
        for (group in model.secureGroups) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("🔐 $group", style = MaterialTheme.typography.bodyMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(enabled = busy == null,
                           onClick = { onOpenRoom(group) }) { Text("Open") }
                    OutlinedButton(enabled = busy == null,
                                   onClick = { model.leaveSecureGroup(group) }) { Text("Leave") }
                    if (model.canDelete(group)) {
                        OutlinedButton(enabled = busy == null,
                                       onClick = { deleting = group }) {
                            Text("Delete", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }

        HorizontalDivider()
        // A secure group: MLS end to end, the room carries ciphertext
        // only. Members are added by invitation over an encrypted OTRv4+
        // session. Its passphrase (owner design, 2026-10-10) is how
        // members verify each other later; group calls are among
        // verified members only. Kept in `remember` only: never into
        // the saved state. No room password: see
        // RoomsViewModel.createSecure.
        Text("New encrypted group", style = MaterialTheme.typography.titleSmall)
        Text(RoomSections.MLS_PLUS_NOTE, style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
        var groupName by rememberSaveable { mutableStateOf("") }
        var groupPassphrase by remember { mutableStateOf("") }
        OutlinedTextField(
            value = groupName,
            onValueChange = { groupName = it },
            label = { Text("Group name") },
            placeholder = { Text("team") },
            supportingText = {
                Text(service?.let { "Will be created on $it" }
                         ?: "Looking for this server's rooms service…",
                     style = MaterialTheme.typography.bodySmall)
            },
            singleLine = true,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = groupPassphrase,
            onValueChange = { groupPassphrase = it },
            label = { Text("Group passphrase (for verifying members)") },
            supportingText = {
                Text("8+ characters. Tell the members in person or on a call, " +
                     "never in a chat. Members type it to verify; only verified " +
                     "members are in group calls. Never stored or sent.",
                     style = MaterialTheme.typography.bodySmall)
            },
            singleLine = true,
            enabled = busy == null,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            enabled = busy == null && groupName.isNotBlank() && nick.isNotBlank() &&
                (groupPassphrase.isEmpty() || groupPassphrase.length >= 8),
            onClick = {
                model.createSecure(groupName.trim(), nick.trim(), groupPassphrase)
                groupPassphrase = ""
            },
        ) { Text("Create encrypted group") }
        Text("Invite members from the group once it is made. It needs no " +
                 "password: nobody can read it without an invitation.",
             style = MaterialTheme.typography.bodySmall)
    }
    deleting?.let { group ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete this group for everyone?") },
            text = { Text(org.otrv4plus.android.chat.GroupText.endConfirm(true, group)) },
            confirmButton = {
                TextButton(onClick = {
                    model.deleteSecureGroup(group)
                    deleting = null
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } },
        )
    }
}

/** Plain rooms: the ones we are in, the ones listed, and joining or creating by name. */
@Composable
private fun PlainRoomsSection(
    model: RoomsViewModel,
    busy: String?,
    service: String?,
    nick: String,
    split: RoomSections.Split,
    address: String,
    onAddressChange: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    // ══ Plain rooms ═══════════════════════════════════════════════════
    Section(
        title = "# " + RoomSections.PLAIN_TITLE,
        note = RoomSections.PLAIN_NOTE,
        noteColor = MaterialTheme.colorScheme.error,
        color = MaterialTheme.colorScheme.surfaceVariant,
        action = {
            if (service != null) {
                TextButton(enabled = busy == null,
                           onClick = { model.refreshRooms(service) }) { Text("Refresh") }
            }
        },
    ) {
        // Rooms you are in (an encrypted group is in its own section).
        val plainJoined = model.joined.filterKeys { it !in model.secureGroups }
        if (plainJoined.isNotEmpty()) {
            Text("You are in", style = MaterialTheme.typography.titleSmall)
            for ((room, standing) in plainJoined) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("# $room", style = MaterialTheme.typography.bodyMedium)
                    // Both, always. Affiliation is standing with the room
                    // and survives leaving; role is standing in this
                    // visit. An owner who joined as a visitor cannot
                    // speak, and showing only one of the two would make
                    // that unexplainable.
                    Text(
                        "${standing.affiliation} · ${standing.role}" +
                            if (!standing.speak) " · read-only" else "",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            enabled = busy == null,
                            onClick = { model.leave(room, standing.nick) },
                        ) { Text("Leave") }
                        if (standing.destroy) {
                            // Owners only. Offered to anybody else, this
                            // is a button that fails minutes after it is
                            // pressed.
                            OutlinedButton(
                                enabled = busy == null,
                                onClick = { model.destroy(room) },
                            ) { Text("Delete room") }
                        }
                    }
                }
            }
            HorizontalDivider()
        }

        // ── On this server ──
        if (service != null) {
            Text("On this server", style = MaterialTheme.typography.titleSmall)
            if (split.plain.isEmpty()) {
                // Not an error. A room configured as hidden is absent by
                // design, so an empty list says what is ADVERTISED and
                // nothing about what exists.
                Text(
                    "Nothing is advertised here. Rooms can be hidden, so " +
                        "there may still be some — join by address if you " +
                        "know one.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            for (room in split.plain) {
                ListedRoom(model, room, busy, onDelete = { onDelete(room.jid) }) {
                    TextButton(
                        enabled = busy == null && nick.isNotBlank() &&
                            !model.joined.containsKey(room.jid),
                        onClick = { model.joinListed(room, nick.trim()) },
                    ) {
                        Text(if (model.joined.containsKey(room.jid)) "In" else "Join")
                    }
                }
            }
            HorizontalDivider()
        }

        // ── Join or create by name ──
        Text("Join or create a plain room", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = address,
            onValueChange = onAddressChange,
            // A NAME, NOT AN ADDRESS.
            //
            // This asked for a full JID and somebody creating a room
            // typed the name of the room -- reasonably. What reached
            // slixmpp was a domainless JID, `join_muc_wait` sat on it for
            // its 300 s default, and the throw skipped the line that
            // cleared the spinner. `RoomAddress` builds the JID from the
            // DISCOVERED conference service instead; a full address is
            // still accepted for a room on another server.
            label = { Text("Room name") },
            placeholder = { Text("myroom") },
            supportingText = {
                Text(
                    service?.let { "Will be created on $it" }
                        ?: "Looking for this server's rooms service…",
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            singleLine = true,
            enabled = busy == null,
            modifier = Modifier.fillMaxWidth(),
        )
        // PASSWORD-PROTECTED CREATE, plain rooms only. Kept in
        // `remember` only: a password must not be written into the
        // saved-instance Bundle.
        var protect by remember { mutableStateOf(false) }
        var roomPassword by remember { mutableStateOf("") }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = protect, enabled = busy == null,
                     onCheckedChange = { protect = it; if (!it) roomPassword = "" })
            Text("Password protect a new room",
                 style = MaterialTheme.typography.bodyMedium)
        }
        if (protect) {
            OutlinedTextField(
                value = roomPassword,
                onValueChange = { roomPassword = it },
                label = { Text("Room password") },
                supportingText = {
                    Text("Only people who enter this password can join. " +
                             RoomPassword.NOT_ENCRYPTION,
                         style = MaterialTheme.typography.bodySmall)
                },
                singleLine = true,
                enabled = busy == null,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        val canAct = busy == null && address.isNotBlank() && nick.isNotBlank()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                enabled = canAct,
                onClick = { model.join(address.trim(), nick.trim()) },
            ) { Text("Join") }

            // Secondary, like Create account on the login screen and for
            // the same reason: joining is the common case and creating
            // happens once.
            OutlinedButton(
                enabled = canAct && (!protect || roomPassword.isNotBlank()),
                onClick = {
                    model.create(address.trim(), nick.trim(),
                                 if (protect) roomPassword else "")
                },
            ) { Text("Create") }

            // Moderation: a room that is not listed (hidden) can still be
            // deleted by its address -- offered only when the server says
            // it is ours (owner, 2026-10-16: nobody else should see it).
            if (address.isNotBlank() && model.canDelete(address)) {
                OutlinedButton(
                    enabled = busy == null,
                    onClick = { onDelete(address.trim()) },
                ) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            }
        }
    }
}

/** Delete-for-everyone, a room's password, and "ask to join?". */
@Composable
private fun RoomDialogs(
    model: RoomsViewModel,
    busy: String?,
    deletingRoom: String?,
    onDismissDelete: () -> Unit,
) {
    deletingRoom?.let { target ->
        AlertDialog(
            onDismissRequest = onDismissDelete,
            title = { Text("Delete this room for everyone?") },
            text = {
                Text("$target will be deleted on the server: everyone in it " +
                         "is removed and its history goes. Only its owner (who " +
                         "created it) or a server admin can do this. It cannot " +
                         "be undone.")
            },
            confirmButton = {
                TextButton(onClick = {
                    model.deleteRoom(target)
                    onDismissDelete()
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = onDismissDelete) { Text("Cancel") }
            },
        )
    }

    // THE PROMPT. A plain room the list marks as protected, or one the
    // service refused for want of a password (not-authorized); nothing
    // retries without the user.
    model.passwordPrompt?.let { prompt ->
        var entered by remember(prompt) { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { model.cancelPassword() },
            title = { Text("Room password") },
            text = {
                Column {
                    Text(prompt.message,
                         color = if (prompt.retry) MaterialTheme.colorScheme.error
                                 else MaterialTheme.colorScheme.onSurface)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = entered,
                        onValueChange = { entered = it },
                        label = { Text("Password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(RoomPassword.NOT_ENCRYPTION,
                         style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(enabled = entered.isNotBlank() && busy == null,
                           onClick = { model.submitPassword(entered) }) {
                    Text("Enter")
                }
            },
            dismissButton = {
                TextButton(onClick = { model.cancelPassword() }) { Text("Cancel") }
            },
        )
    }

    // "Ask to join?" -- asked first, because it posts our address in a
    // room whose occupants (and the server) can read it.
    model.askToJoinFor?.let { room ->
        AlertDialog(
            onDismissRequest = { model.cancelAskToJoin() },
            title = { Text(RoomPassword.NEEDS_INVITE_TITLE) },
            text = {
                Column {
                    Text(room, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(RoomPassword.NEEDS_INVITE)
                }
            },
            confirmButton = {
                TextButton(enabled = busy == null,
                           onClick = { model.askToJoin(room) }) { Text("Ask to join") }
            },
            dismissButton = {
                TextButton(onClick = { model.cancelAskToJoin() }) { Text("Cancel") }
            },
        )
    }
}

/** One kind of group: a tinted card with its heading and what it means. */
@Composable
private fun Section(
    title: String,
    note: String,
    color: Color,
    noteColor: Color = Color.Unspecified,
    action: @Composable () -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(color = color, shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.titleMedium,
                     modifier = Modifier.weight(1f))
                action()
            }
            Text(note, style = MaterialTheme.typography.bodySmall, color = noteColor)
            content()
        }
    }
}

/** A room the server lists: name, kind, size, and its one action. */
@Composable
private fun ListedRoom(
    model: RoomsViewModel,
    room: org.otrv4plus.android.bridge.RoomSummary,
    busy: String?,
    onDelete: () -> Unit,
    action: @Composable () -> Unit,
) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            // 🔐 only for a group whose keys are on this phone (a room
            // cannot fake that; its description can -- security audit,
            // 2026-10-11), # anything else, and 🔒 after the name when it
            // needs a password.
            Text(room.kindIcon + " " + room.label +
                     (if (room.password) " \uD83D\uDD12" else ""),
                 style = MaterialTheme.typography.bodyMedium)
            Text(room.kindText + " · " + room.jid, style = MaterialTheme.typography.bodySmall)
            // The service's own count. Absent when it gave none: "unknown"
            // is not written as "0 users".
            room.occupants?.let { n ->
                Text(if (n == 1) "1 user in the room" else "$n users in the room",
                     style = MaterialTheme.typography.bodySmall)
            }
        }
        Column(horizontalAlignment = Alignment.End) {
            action()
            // Only its owner or a server admin may, so only they see it
            // (owner, 2026-10-16).
            if (model.canDelete(room.jid)) {
                TextButton(enabled = busy == null, onClick = onDelete) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}
