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
) {
    val busy = model.busy
    val last = model.last

    var nick by rememberSaveable { mutableStateOf(defaultNick) }
    var address by rememberSaveable { mutableStateOf("") }

    // Once, when the screen is first shown AND there is something to ask.
    // Discovery is two round trips over I2P, so repeating it on every
    // recomposition would make the screen unusable; `model.discovered` is what
    // makes a second visit instant.
    //
    // Keyed on the core rather than on Unit: the service binding can land
    // after this screen is composed, and a Unit key would mean a screen opened
    // in that window asked a null core, gave up, and never tried again.
    LaunchedEffect(model.core, model.discovered) {
        if (model.core != null && !model.discovered) model.discover()
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
            "Rooms are group chat. Messages in a room are not end-to-end " +
                "encrypted — the server hosting the room can read them. " +
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

        // ── Rooms you are in ──────────────────────────────────────────────
        if (model.joined.isNotEmpty()) {
            Spacer(Modifier.height(4.dp))
            Text("You are in", style = MaterialTheme.typography.titleSmall)
            for ((room, standing) in model.joined) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(room, style = MaterialTheme.typography.bodyMedium)
                    // Both, always. Affiliation is standing with the room and
                    // survives leaving; role is standing in this visit. An
                    // owner who joined as a visitor cannot speak, and showing
                    // only one of the two would make that unexplainable.
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
                            // Owners only. Offered to anybody else, this is a
                            // button that fails minutes after it is pressed.
                            OutlinedButton(
                                enabled = busy == null,
                                onClick = { model.destroy(room) },
                            ) { Text("Delete room") }
                        }
                    }
                }
            }
        }

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

        // ── Join or create by name ────────────────────────────────────────
        Spacer(Modifier.height(4.dp))
        Text("Join a room", style = MaterialTheme.typography.titleSmall)
        OutlinedTextField(
            value = address,
            onValueChange = { address = it },
            // A NAME, NOT AN ADDRESS.
            //
            // This asked for a full JID and somebody creating a room typed
            // the name of the room -- reasonably. What reached slixmpp was a
            // domainless JID, `join_muc_wait` sat on it for its 300 s
            // default, and the throw skipped the line that cleared the
            // spinner. `RoomAddress` builds the JID from the DISCOVERED
            // conference service instead; a full address is still accepted
            // for a room on another server.
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
        // PASSWORD-PROTECTED CREATE. `remember`, not `rememberSaveable`: a
        // password must not be written into the saved-instance Bundle.
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

            // Secondary, like Create account on the login screen and for the
            // same reason: joining is the common case and creating happens
            // once.
            OutlinedButton(
                enabled = canAct && (!protect || roomPassword.isNotBlank()),
                onClick = {
                    model.create(address.trim(), nick.trim(),
                                 if (protect) roomPassword else "")
                },
            ) { Text("Create") }
        }

        // THE PROMPT. Opened only when the service refused a join for want
        // of a password (not-authorized); nothing retries without the user.
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

        // ── What the service advertises ───────────────────────────────────
        if (service != null) {
            Spacer(Modifier.height(4.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("On this server",
                    style = MaterialTheme.typography.titleSmall)
                TextButton(
                    enabled = busy == null,
                    onClick = { model.refreshRooms(service) },
                ) { Text("Refresh") }
            }
            if (model.rooms.isEmpty()) {
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
            for (room in model.rooms) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(room.label,
                            style = MaterialTheme.typography.bodyMedium)
                        Text(room.jid,
                            style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(
                        enabled = busy == null && nick.isNotBlank() &&
                            !model.joined.containsKey(room.jid),
                        onClick = { model.join(room.jid, nick.trim()) },
                    ) {
                        Text(if (model.joined.containsKey(room.jid)) "In"
                             else "Join")
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onBack) { Text("Back") }
    }
}
