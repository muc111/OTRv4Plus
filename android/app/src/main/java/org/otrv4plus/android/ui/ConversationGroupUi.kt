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

// Room and secure-group parts of the conversation screen. Split from ConversationScreen.kt;
// shared helpers there are internal for that reason.

/**
 * What a room is, and who is in it.
 *
 * The first line is the security statement, in the same place a one-to-one
 * conversation puts its own, and it never varies: XEP-0045 group chat has no
 * end-to-end encryption, so every occupant and the server read every line.
 * The mark is the NOT_ENCRYPTED one from [SecurityLevel].
 *
 * Participants are fetched from the room and can take a while over I2P, so
 * "asking the room…" is said while waiting and a failure is said as a
 * failure, with a retry, rather than showing an empty list that reads as
 * "nobody here".
 */
@Composable
internal fun RoomHeader(model: ChatViewModel, jid: String, onOpenChat: ((String) -> Unit)? = null) {
    val secure = model.isSecureRoom(jid)
    // Accepted, keys not here yet: a secure group being set up -- never shown
    // as an ordinary, unencrypted room (device report, 2026-10-16).
    val joining = model.isJoiningRoom(jid)
    val level = if (secure) org.otrv4plus.android.crypto.SecurityLevel.Level.ENCRYPTED_UNVERIFIED
                else org.otrv4plus.android.crypto.SecurityLevel.Level.NOT_ENCRYPTED
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
      Column {
        if (joining) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        if (secure && !joining) {
            Text("${level.mark} " + model.groupSecurityLine(jid),
                 style = MaterialTheme.typography.labelLarge,
                 modifier = Modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, top = 6.dp))
        }
        Text(
            "${level.mark} " + when {
                joining -> org.otrv4plus.android.chat.GroupText.JOINING_HEADER
                secure && model.isSyncingRoom(jid) -> org.otrv4plus.android.chat.GroupText.SYNCING_HEADER
                else -> org.otrv4plus.android.chat.GroupText.header(secure)
            },
            style = MaterialTheme.typography.bodySmall,
            color = if (secure) MaterialTheme.colorScheme.onSurfaceVariant
                    else MaterialTheme.colorScheme.error,
            // One line that scrolls, not a four-line paragraph above every
            // group (owner, 2026-10-17). The whole sentence is still the
            // text: screen readers read it in full; it only moves when it
            // does not fit.
            maxLines = 1,
            modifier = Modifier.fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 6.dp)
                .basicMarquee(iterations = Int.MAX_VALUE),
        )
      }
    }
    val ready = secure && !joining
    if (ready) GroupVerifyAndCallBar(model, jid)
    // Files to the whole group, over MLS; the same picker, metadata
    // question, rows and viewer as a 1:1 conversation.
    if (ready) TransferBar(model, jid, group = true)
    if (ready) SecureGroupPanel(model, jid)
    val expanded = model.occupantsShown(jid)
    val people = model.occupants(jid)
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            when {
                model.occupantsUnavailable(jid) -> "Could not ask the room who is here."
                people.isEmpty() -> "Asking the room who is here…"
                else -> "${people.size} in this room"
            },
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.weight(1f),
        )
        if (people.isNotEmpty()) {
            TextButton(onClick = { model.toggleOccupants(jid) }) { Text("People") }
        }
        TextButton(onClick = { model.refreshOccupants(jid) }) { Text("Refresh") }
    }
    // A sheet rather than a list in the header: a busy room is a hundred
    // rows, and inline they pushed the conversation off the screen (owner,
    // 2026-10-21: "we need a better way to view and add users").
    if (expanded && people.isNotEmpty()) {
        RoomPeopleSheet(model, jid, people, onOpenChat, onDismiss = { model.toggleOccupants(jid) })
    }
}

/**
 * Who is in a room: search, sections by role with counts, and on each row
 * Add (a contact request) and Message -- only for someone whose address the
 * room revealed (RoomPeople). A nickname alone offers nothing.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun RoomPeopleSheet(model: ChatViewModel, room: String,
                            people: List<org.otrv4plus.android.bridge.RoomOccupant>,
                            onOpenChat: ((String) -> Unit)?, onDismiss: () -> Unit) {
    var query by rememberSaveable(room) { mutableStateOf("") }
    val me = model.ownJid()
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Text(org.otrv4plus.android.chat.RoomPeople.summary(people),
                 style = MaterialTheme.typography.titleMedium)
            if (people.size >= org.otrv4plus.android.chat.RoomPeople.SEARCH_FROM) {
                OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth().padding(vertical = 6.dp),
                                  singleLine = true, placeholder = { Text("Search people") })
            }
            LazyColumn(Modifier.fillMaxWidth()) {
                for (section in org.otrv4plus.android.chat.RoomPeople.sections(people, query)) {
                    item(key = "h:" + section.title) {
                        Text(section.title, Modifier.padding(top = 12.dp, bottom = 4.dp),
                             style = MaterialTheme.typography.labelLarge,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    items(section.people, key = { "p:" + it.nick }) { p ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(p.nick, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(p.jid.ifBlank { org.otrv4plus.android.chat.RoomPeople.NO_ADDRESS_HINT },
                                     style = MaterialTheme.typography.labelSmall, maxLines = 1,
                                     overflow = TextOverflow.Ellipsis,
                                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            when (org.otrv4plus.android.chat.RoomPeople.action(p, me) { model.isContact(it) }) {
                                org.otrv4plus.android.chat.RoomPeople.Action.ADD -> {
                                    TextButton(onClick = { model.addContact(p.jid) }) { Text("Add") }
                                    if (onOpenChat != null) TextButton(onClick = {
                                        onDismiss(); onOpenChat(p.jid) }) { Text("Message") }
                                }
                                org.otrv4plus.android.chat.RoomPeople.Action.MESSAGE ->
                                    if (onOpenChat != null) TextButton(onClick = {
                                        onDismiss(); onOpenChat(p.jid) }) { Text("Message") }
                                org.otrv4plus.android.chat.RoomPeople.Action.SELF ->
                                    Text("you", style = MaterialTheme.typography.labelSmall)
                                org.otrv4plus.android.chat.RoomPeople.Action.NO_ADDRESS -> {}
                            }
                        }
                    }
                }
                item { Spacer(Modifier.padding(12.dp)) }
            }
        }
    }
}

/**
 * "This person is not in your contacts", and the one thing to do about it.
 *
 * The button is disabled while the link is down rather than hidden: the
 * remedy still exists, it just cannot be carried out this second, and hiding
 * it would make the explanation above it read as a dead end.
 */
@Composable
internal fun UnsavedSenderBanner(enabled: Boolean, onSave: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "Not in your contacts, so their availability stays unknown.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            TextButton(enabled = enabled, onClick = onSave) {
                Text("Save contact")
            }
        }
    }
}

/** Progress of an OTRv4+ handshake. Words first; the bar only confirms. */
@Composable
internal fun HandshakeCard(status: HandshakeUi.Status) {
    val view = HandshakeUi.view(status) ?: return
    Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
            Text(view.title, style = MaterialTheme.typography.labelLarge,
                 color = MaterialTheme.colorScheme.onSecondaryContainer)
            Text(view.detail, style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.onSecondaryContainer)
            LinearProgressIndicator(progress = { view.progress },
                                    modifier = Modifier.fillMaxWidth()
                                        .padding(vertical = 4.dp))
            Text(view.elapsed, style = MaterialTheme.typography.labelSmall,
                 color = MaterialTheme.colorScheme.onSecondaryContainer)
        }
    }
}

/**
 * Everyone online who is not in the group yet, with a tick box each; one
 * button invites them all (owner request, 2026-10-16). Each still gets their
 * own invitation over OTRv4+.
 */
@Composable
internal fun GroupInviteDialog(model: ChatViewModel, room: String, onDone: () -> Unit) {
    val people = model.groupInviteCandidates(room)
    val ticked = androidx.compose.runtime.remember(room) {
        androidx.compose.runtime.mutableStateListOf<String>()
    }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDone,
        title = { Text(org.otrv4plus.android.chat.GroupInvitePicker.TITLE) },
        text = {
            if (people.isEmpty()) {
                Text(org.otrv4plus.android.chat.GroupInvitePicker.EMPTY,
                     style = MaterialTheme.typography.bodySmall)
            } else {
                androidx.compose.foundation.lazy.LazyColumn(Modifier.heightIn(max = 360.dp)) {
                    items(people.size) { i ->
                        val p = people[i]
                        val on = p.jid in ticked
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                if (on) ticked.remove(p.jid) else ticked.add(p.jid)
                            },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            androidx.compose.material3.Checkbox(
                                checked = on,
                                onCheckedChange = { if (it) ticked.add(p.jid) else ticked.remove(p.jid) },
                            )
                            Column(Modifier.weight(1f)) {
                                Text(p.name, style = MaterialTheme.typography.bodyMedium)
                                Text(p.jid + if (p.contact) "" else "  (not a contact)",
                                     style = MaterialTheme.typography.labelSmall,
                                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = ticked.isNotEmpty(), onClick = {
                model.inviteManyToGroup(room, ticked.toList())
                onDone()
            }) { Text(org.otrv4plus.android.chat.GroupInvitePicker.button(ticked.size)) }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}

/**
 * A secure group's members: one summary line under the chat, and the list in
 * a sheet -- search, sections by verification with counts, one short row
 * each (GroupRoster). Owner (2026-10-25): "these groups could have 100 users
 * so clean display is needed"; the inline list pushed the chat off the
 * screen. Remove is the creator's only, and asks first.
 */
@Composable
internal fun SecureGroupPanel(model: ChatViewModel, jid: String) {
    var shown by rememberSaveable(jid) { mutableStateOf(false) }
    val verify = model.groupVerifyState(jid)
    val members = model.groupMembers(jid)
    // Read when the chat opens, and again as verification moves.
    LaunchedEffect(jid, verify.members) { model.refreshGroupMembers(jid) }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(org.otrv4plus.android.chat.GroupRoster.summary(members, verify.members),
             style = MaterialTheme.typography.labelMedium, maxLines = 1,
             overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        TextButton(onClick = { shown = true; model.refreshGroupMembers(jid) }) { Text("Members") }
    }
    if (shown) GroupMembersSheet(model, jid, members, verify) { shown = false }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun GroupMembersSheet(model: ChatViewModel, jid: String,
                               members: List<org.otrv4plus.android.bridge.GroupMember>,
                               verify: org.otrv4plus.android.bridge.GroupVerifyState,
                               onDismiss: () -> Unit) {
    val roster = org.otrv4plus.android.chat.GroupRoster
    var query by rememberSaveable(jid) { mutableStateOf("") }
    var invitee by rememberSaveable(jid) { mutableStateOf("") }
    var picking by rememberSaveable(jid) { mutableStateOf(false) }
    var removing by remember(jid) { mutableStateOf<List<String>>(emptyList()) }
    val failed = roster.failed(members, verify.members)
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Text(roster.summary(members, verify.members), style = MaterialTheme.typography.titleMedium)
            if (verify.canStart && failed.isNotEmpty()) {
                OutlinedButton(onClick = { removing = failed },
                               modifier = Modifier.padding(top = 6.dp)) {
                    Text(roster.removeFailedButton(failed.size), color = MaterialTheme.colorScheme.error)
                }
            }
            if (members.size >= roster.SEARCH_FROM) {
                OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth().padding(vertical = 6.dp),
                                  singleLine = true, placeholder = { Text("Search members") })
            }
            LazyColumn(Modifier.fillMaxWidth().weight(1f, fill = false)) {
                for (section in roster.sections(members, verify.members, query, verify.canStart)) {
                    item(key = "h:" + section.title) {
                        Text(section.title, Modifier.padding(top = 12.dp, bottom = 4.dp),
                             style = MaterialTheme.typography.labelLarge,
                             color = if (section.rows.first().status == org.otrv4plus.android.chat.GroupRoster.Status.FAILED)
                                 MaterialTheme.colorScheme.error
                             else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    items(section.rows, key = { "m:" + it.jid }) { row ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(row.name, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                     style = MaterialTheme.typography.bodyMedium)
                                Text(row.jid, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                     style = MaterialTheme.typography.labelSmall,
                                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (row.canRemove) {
                                TextButton(onClick = { removing = listOf(row.jid) }) { Text("Remove") }
                            }
                        }
                    }
                }
                item(key = "invite") {
                    Column(Modifier.padding(top = 12.dp)) {
                        HorizontalDivider()
                        OutlinedTextField(
                            value = invitee,
                            onValueChange = { invitee = it },
                            label = { Text("Invite a contact (user name or address)") },
                            singleLine = true,
                            // An address, so no auto-capital: "B@otrv4plus.i2p" was stored as
                            // the invitee and B's answer, from "b@...", was dropped as
                            // uninvited (device test). The bridge folds case too.
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            TextButton(
                                enabled = invitee.isNotBlank(),
                                onClick = { model.inviteToGroup(jid, invitee); invitee = "" },
                            ) { Text("Invite over OTRv4+") }
                            TextButton(onClick = { picking = true }) { Text("Invite people online…") }
                        }
                        GroupEndButtons(model, jid)
                        Spacer(Modifier.padding(12.dp))
                    }
                }
            }
        }
    }
    if (picking) GroupInviteDialog(model, jid) { picking = false }
    if (removing.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = { removing = emptyList() },
            title = { Text(if (removing.size == 1) "Remove this member?" else "Remove who failed?") },
            text = { Text(roster.removeConfirm(removing)) },
            confirmButton = {
                TextButton(onClick = {
                    if (removing == failed && removing.size > 1) model.removeFailedGroupMembers(jid)
                    else removing.forEach { model.removeGroupMember(jid, it) }
                    removing = emptyList()
                }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { removing = emptyList() }) { Text("Cancel") } },
        )
    }
}

/**
 * Owner design (2026-10-10): Verify the group with its passphrase; once every
 * member is verified the button becomes Call. A call rings the group and every
 * verified member joins by themselves (only when they have allowed the
 * microphone; otherwise they see Join). In a call: Pause and Hang up.
 */
@Composable
internal fun GroupVerifyAndCallBar(model: ChatViewModel, jid: String) {
    val context = androidx.compose.ui.platform.LocalContext.current
    fun micGranted(): Boolean = ContextCompat.checkSelfPermission(
        context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
    var pending by rememberSaveable { mutableStateOf<String?>(null) }   // "call" / "join"
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { allowed ->
        model.setGroupCallAutoJoin(allowed)
        if (allowed) {
            when (pending) {
                "call" -> model.startGroupCall(jid)
                "join" -> model.joinGroupCall(jid)
            }
        }
        pending = null
    }
    fun withMic(what: String) {
        if (micGranted()) {
            if (what == "call") model.startGroupCall(jid) else model.joinGroupCall(jid)
        } else {
            pending = what
            launcher.launch(Manifest.permission.RECORD_AUDIO)
        }
    }
    // Poll while this screen is up: verification and calls move by themselves.
    LaunchedEffect(jid) {
        model.setGroupCallAutoJoin(micGranted())
        while (true) {
            model.refreshGroupState(jid)
            kotlinx.coroutines.delay(2000)
        }
    }
    val verify = model.groupVerifyState(jid)
    val callState = model.groupCallState(jid)
    var asking by rememberSaveable { mutableStateOf(false) }

    Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
            when {
                callState.inCall -> {
                    Text(if (callState.paused) "In the group call (paused: nobody hears you)"
                         else "In the group call" +
                             if (callState.participants.isNotEmpty())
                                 " with ${callState.participants.joinToString()}" else "",
                         style = MaterialTheme.typography.bodyMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { model.pauseGroupCall(jid) }) {
                            Text(if (callState.paused) "Resume" else "Pause")
                        }
                        Button(onClick = { model.hangupGroupCall(jid) }) { Text("Hang up") }
                    }
                }
                callState.ringingFrom.isNotEmpty() -> {
                    Text("${callState.ringingFrom} is calling the group",
                         style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = { withMic("join") }) { Text("\uD83D\uDCDE Join") }
                }
                else -> {
                    val running = verify.members.count { it.value == "running" }
                    val anyVerified = verify.members.values.any { it == "verified" }
                    if (verify.active) {
                        // Owner request (2026-10-10): progress and an ETA until
                        // everyone who knew the passphrase is verified -- and
                        // (2026-10-16) moving from the first moment, so it is
                        // plain it is actively trying.
                        if (verify.total <= 0 || verify.done <= 0)
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        else LinearProgressIndicator(
                            progress = { verify.done.toFloat() / verify.total },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(org.otrv4plus.android.chat.GroupText.verifyProgress(
                                 verify.done, verify.total, verify.etaSeconds,
                                 verify.members, verify.excluded),
                             style = MaterialTheme.typography.labelSmall)
                    } else if (verify.members.isNotEmpty() && !verify.allVerified) {
                        Text(org.otrv4plus.android.chat.GroupText.verifiedSoFar(verify.members),
                             style = MaterialTheme.typography.labelSmall)
                    }
                    if (!model.groupCallAllowed(jid)) {
                        Text(org.otrv4plus.android.chat.GroupText.TEXT_ONLY,
                             style = MaterialTheme.typography.labelSmall)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        // Callable once the checks are done and someone is
                        // verified: anyone not verified is simply not in it.
                        // A large group is text only: no phone at all
                        // (owner, 2026-10-16; the engine refuses too).
                        if (anyVerified && running == 0 && model.groupCallAllowed(jid)) {
                            // The same phone as a 1:1 call, coloured by the path.
                            PhoneButton(model.callPath, model.callPathSecondsLeft,
                                        enabled = true, description = "Call the group") {
                                withMic("call")
                            }
                        }
                        // The creator starts verifying, from here; everyone
                        // else joins the run they start (owner, 2026-10-25).
                        // Once each (owner, 2026-10-25): nothing to offer when
                        // everyone is verified or has had their attempt.
                        if (org.otrv4plus.android.chat.GroupText.leftToVerify(verify.members)) {
                            when {
                                verify.startedBy.isNotEmpty() ->
                                    OutlinedButton(onClick = { asking = true }) {
                                        Text("Join the verification (${verify.startedBy})")
                                    }
                                verify.canStart ->
                                    OutlinedButton(onClick = { asking = true }) { Text("Verify group") }
                                !verify.active && verify.coordinator.isNotEmpty() ->
                                    Text(org.otrv4plus.android.chat.GroupText.waitingForCreator(verify.coordinator),
                                         style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }
    }
    if (asking) GroupPassphrasePrompt(model, jid, starting = verify.startedBy.isEmpty()) { asking = false }
}

/**
 * The group passphrase. Composition-local on purpose, like the SMP
 * passphrase in [VerificationPrompt]: a secret must not outlive its dialog
 * (not in the ViewModel, not in saved state).
 */
@Composable
internal fun GroupPassphrasePrompt(model: ChatViewModel, jid: String, starting: Boolean,
                                   close: () -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    run {
        AlertDialog(
            onDismissRequest = { passphrase = ""; close() },
            title = { Text(if (starting) "Verify the group" else "Join the verification") },
            text = {
                Column {
                    Text(org.otrv4plus.android.chat.GroupText.passphrasePrompt(starting),
                         style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("Group passphrase") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    model.startGroupVerify(jid, passphrase)
                    passphrase = ""
                    close()
                }) { Text("Verify") }
            },
            dismissButton = {
                TextButton(onClick = { passphrase = ""; close() }) { Text("Not now") }
            },
        )
    }
}

/**
 * Leave the group (this phone only), or delete it for everyone. Deleting is
 * the group creator's: the server lets only the room's owner (or a server
 * admin) destroy it, so only they are shown the button (owner, 2026-10-16).
 * Both ask first; neither can be undone.
 */
@Composable
internal fun GroupEndButtons(model: ChatViewModel, jid: String) {
    var asking by androidx.compose.runtime.saveable.rememberSaveable(jid) {
        androidx.compose.runtime.mutableStateOf("")
    }
    // Group calls are among verified members only: this sends our key to each
    // member over OTRv4+; SMP with a member (in their chat) completes it.
    TextButton(onClick = { model.verifyGroupMembers(jid) }) { Text("Verify members (for calls)") }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        TextButton(onClick = { asking = "leave" }) { Text("Leave group") }
        if (model.canDeleteGroup(jid)) {
            TextButton(onClick = { asking = "delete" }) {
                Text("Delete group for everyone", color = MaterialTheme.colorScheme.error)
            }
        }
    }
    if (asking.isNotEmpty()) {
        val delete = asking == "delete"
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { asking = "" },
            title = { Text(if (delete) "Delete this group?" else "Leave this group?") },
            text = {
                Text(org.otrv4plus.android.chat.GroupText.endConfirm(delete, jid))
            },
            confirmButton = {
                TextButton(onClick = {
                    if (delete) model.deleteSecureGroup(jid) else model.leaveSecureGroup(jid)
                    asking = ""
                }) { Text(if (delete) "Delete" else "Leave") }
            },
            dismissButton = { TextButton(onClick = { asking = "" }) { Text("Cancel") } },
        )
    }
}
