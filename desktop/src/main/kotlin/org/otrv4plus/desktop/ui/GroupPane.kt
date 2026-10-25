// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.GroupText
import org.otrv4plus.desktop.AppModel

/**
 * A secure group's verification and call, the Android app's design
 * (owner, 2026-10-10): Verify the group with its passphrase; once members
 * are verified, Call rings the group and every verified member joins. In a
 * call: Pause and Hang up. Everything said here is GroupText's.
 *
 * Nothing is decided here. Who is verified, who may be in a call and what
 * a passphrase proves are the engine's (group_verify.py over MLS, keys in
 * Rust); this shows what it reports and passes on what the user typed.
 */
@Composable
fun GroupBar(model: AppModel, room: String) {
    val verify = model.groupVerify(room)
    val call = model.groupCall(room)
    var asking by remember(room) { mutableStateOf(false) }

    Surface(color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
               verticalArrangement = Arrangement.spacedBy(6.dp)) {
            when {
                call.inCall -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(if (call.paused) Icons.Filled.MicOff else Icons.Filled.Call, null)
                    Spacer(Modifier.width(10.dp))
                    Text(if (call.paused) "In the group call (paused: nobody hears you)"
                         else "In the group call" + if (call.participants.isNotEmpty())
                             " with ${call.participants.joinToString()}" else "",
                         Modifier.weight(1f), fontWeight = FontWeight.Medium)
                    OutlinedButton(onClick = { model.pauseGroupCall() }) {
                        Text(if (call.paused) "Resume" else "Pause")
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { model.hangupGroupCall() },
                           colors = ButtonDefaults.buttonColors(
                               containerColor = MaterialTheme.colorScheme.error,
                               contentColor = MaterialTheme.colorScheme.onError)) {
                        Icon(Icons.Filled.CallEnd, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp)); Text("Hang up")
                    }
                }
                call.ringingFrom.isNotEmpty() -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Call, null)
                    Spacer(Modifier.width(10.dp))
                    Text("${call.ringingFrom} is calling the group", Modifier.weight(1f),
                         fontWeight = FontWeight.Medium)
                    Button(onClick = { model.joinGroupCall(room) }) { Text("Join") }
                }
                else -> {
                    val running = verify.members.count { it.value == "running" }
                    val anyVerified = verify.members.values.any { it == "verified" }
                    if (verify.active) {
                        // Moving from the first moment (owner, 2026-10-16:
                        // users must see it is actively trying); filling as
                        // members are verified.
                        if (verify.total <= 0 || verify.done <= 0) LinearProgressIndicator(Modifier.fillMaxWidth())
                        else LinearProgressIndicator(progress = { verify.done.toFloat() / verify.total },
                                                     modifier = Modifier.fillMaxWidth())
                        Text(GroupText.verifyProgress(verify.done, verify.total, verify.etaSeconds,
                                                      verify.members, verify.excluded),
                             style = MaterialTheme.typography.labelSmall)
                    } else if (verify.members.isNotEmpty() && !verify.allVerified) {
                        Text(GroupText.verifiedSoFar(verify.members),
                             style = MaterialTheme.typography.labelSmall)
                    } else if (verify.allVerified) {
                        Text("Every member is verified.", style = MaterialTheme.typography.labelSmall,
                             color = VerifiedBlue)
                    }
                    // A large group is text only (owner, 2026-10-16).
                    val callable = GroupText.callAllowed(model.groupMembers[room].orEmpty().size)
                    if (!callable) Text(GroupText.TEXT_ONLY, style = MaterialTheme.typography.labelSmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (anyVerified && running == 0 && callable) {
                            // The same phone as a 1:1 call, coloured by the path.
                            Button(onClick = { model.startGroupCall(room) },
                                   colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                                       containerColor = androidx.compose.ui.graphics.Color(
                                           org.otrv4plus.android.crypto.CallUi.readinessColour(model.callPath)),
                                       contentColor = androidx.compose.ui.graphics.Color.White)) {
                                Icon(Icons.Filled.Call, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text("Call the group · " + org.otrv4plus.android.crypto.CallUi.readinessLabel(
                                    model.callPath, model.callPathSecondsLeft))
                            }
                        }
                        // The creator starts verifying; everyone else joins the
                        // run they start (owner, 2026-10-25).
                        val left = GroupText.leftToVerify(verify.members)
                        if (left && (verify.startedBy.isNotEmpty() || verify.canStart)) {
                            OutlinedButton(onClick = { asking = true }) {
                                Icon(Icons.Filled.VerifiedUser, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(if (verify.startedBy.isNotEmpty())
                                         "Join the verification (${verify.startedBy})"
                                     else "Verify group")
                            }
                        } else if (left && !verify.active && verify.coordinator.isNotEmpty()) {
                            Text(org.otrv4plus.android.chat.GroupText.waitingForCreator(verify.coordinator),
                                 style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
    if (asking) GroupPassphraseDialog(starting = verify.startedBy.isEmpty(), onDone = { phrase ->
        asking = false
        if (phrase != null) model.startGroupVerify(room, phrase)
    })
}

/** The group passphrase: lives in this dialog only, and is dropped with it. */
@Composable
private fun GroupPassphraseDialog(starting: Boolean, onDone: (String?) -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { passphrase = ""; onDone(null) },
        title = { Text(if (starting) "Verify the group" else "Join the verification") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(org.otrv4plus.android.chat.GroupText.passphrasePrompt(starting),
                     style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(passphrase, { passphrase = it }, singleLine = true,
                                  label = { Text("Group passphrase") },
                                  visualTransformation = PasswordVisualTransformation(),
                                  modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            Button(onClick = { val p = passphrase; passphrase = ""; onDone(p) }) { Text("Verify") }
        },
        dismissButton = { TextButton(onClick = { passphrase = ""; onDone(null) }) { Text("Not now") } },
    )
}

/** Members, invites and the way out: the side panel of a secure group.
 *  A lazy list in sections with counts and search (GroupRoster): a group can
 *  have 100 members (owner, 2026-10-25). Remove is the creator's, and asks. */
@Composable
fun GroupMembersPanel(model: AppModel, room: String, modifier: Modifier = Modifier) {
    val roster = org.otrv4plus.android.chat.GroupRoster
    var invitee by remember(room) { mutableStateOf("") }
    var picking by remember(room) { mutableStateOf(false) }
    var ending by remember(room) { mutableStateOf("") }
    var query by remember(room) { mutableStateOf("") }
    var removing by remember(room) { mutableStateOf<List<String>>(emptyList()) }
    val members = model.groupMembers[room].orEmpty()
    val verify = model.groupVerify(room)
    val failed = roster.failed(members, verify.members)
    LazyColumn(modifier.fillMaxHeight().padding(start = 16.dp, top = 16.dp, bottom = 16.dp, end = 4.dp),
               verticalArrangement = Arrangement.spacedBy(6.dp)) {
        item(key = "title") {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Members", style = MaterialTheme.typography.titleSmall,
                     color = MaterialTheme.colorScheme.primary)
                Text(roster.summary(members, verify.members), style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (verify.canStart && failed.isNotEmpty()) {
                    OutlinedButton(onClick = { removing = failed }) {
                        Text(roster.removeFailedButton(failed.size), color = MaterialTheme.colorScheme.error)
                    }
                }
                if (members.size >= roster.SEARCH_FROM) {
                    OutlinedTextField(query, { query = it }, singleLine = true,
                                      placeholder = { Text("Search members") },
                                      modifier = Modifier.fillMaxWidth())
                }
            }
        }
        for (section in roster.sections(members, verify.members, query, verify.canStart)) {
            item(key = "h:" + section.title) {
                Text(section.title, style = MaterialTheme.typography.labelLarge,
                     modifier = Modifier.padding(top = 6.dp),
                     color = if (section.rows.first().status == org.otrv4plus.android.chat.GroupRoster.Status.FAILED)
                         MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
            items(section.rows, key = { "m:" + it.jid }) { row ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Avatar(row.jid, image = model.avatar(row.jid), size = 24)
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.weight(1f)) {
                        Text(row.name, style = MaterialTheme.typography.bodySmall, maxLines = 1,
                             overflow = TextOverflow.Ellipsis,
                             color = if (row.status == org.otrv4plus.android.chat.GroupRoster.Status.VERIFIED) VerifiedBlue
                                     else MaterialTheme.colorScheme.onSurface)
                        Text(row.jid, style = MaterialTheme.typography.labelSmall, maxLines = 1,
                             overflow = TextOverflow.Ellipsis,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    if (row.canRemove) TextButton(onClick = { removing = listOf(row.jid) }) { Text("Remove") }
                }
            }
        }
        item(key = "end") {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                HorizontalDivider()
                OutlinedTextField(invitee, { invitee = it }, singleLine = true,
                                  label = { Text("Invite a contact (address)") },
                                  modifier = Modifier.fillMaxWidth())
                Text("Invitations go over your encrypted OTRv4+ conversation with them; " +
                     "the room never sees them.", style = MaterialTheme.typography.labelSmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { model.inviteToGroup(room, invitee); invitee = "" },
                           enabled = invitee.contains('@')) { Text("Invite over OTRv4+") }
                    TextButton(onClick = { picking = true }) { Text("Invite people online…") }
                }
                HorizontalDivider()
                TextButton(onClick = { model.verifyGroupMembers(room) }) { Text("Verify members (for calls)") }
                TextButton(onClick = { ending = "leave" }) { Text("Leave group") }
                // Only the group's creator (its room's owner) or a server admin can
                // delete it, so only they see this (owner, 2026-10-16).
                if (model.chat.canDeleteRoom(room)) {
                    TextButton(onClick = { ending = "delete" }) {
                        Text("Delete group for everyone", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
    if (picking) GroupInviteDialog(model, room) { picking = false }
    if (removing.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = { removing = emptyList() },
            title = { Text(if (removing.size == 1) "Remove this member?" else "Remove who failed?") },
            text = { Text(roster.removeConfirm(removing)) },
            confirmButton = {
                Button(onClick = {
                    if (removing == failed) model.removeFailedGroupMembers(room)
                    else removing.forEach { model.removeGroupMember(room, it) }
                    removing = emptyList()
                }, colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error,
                                                        contentColor = MaterialTheme.colorScheme.onError)) {
                    Text("Remove")
                }
            },
            dismissButton = { TextButton(onClick = { removing = emptyList() }) { Text("Cancel") } },
        )
    }
    if (ending.isNotEmpty()) {
        val delete = ending == "delete"
        AlertDialog(
            onDismissRequest = { ending = "" },
            title = { Text(if (delete) "Delete this group?" else "Leave this group?") },
            text = { Text(GroupText.endConfirm(delete, room)) },
            confirmButton = {
                Button(onClick = {
                    if (delete) model.deleteSecureGroup(room) else model.leaveSecureGroup(room)
                    ending = ""
                }, colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error,
                                                        contentColor = MaterialTheme.colorScheme.onError)) {
                    Text(if (delete) "Delete" else "Leave")
                }
            },
            dismissButton = { TextButton(onClick = { ending = "" }) { Text("Cancel") } },
        )
    }
}


/** Everyone online not yet in the group, a tick box each, one Invite button
 *  (owner, 2026-10-16). Each person still gets their own OTRv4+ invitation. */
@Composable
private fun GroupInviteDialog(model: AppModel, room: String, onDone: () -> Unit) {
    // Fresh when opened: the Welcome room and the server's list (AppModel.refreshOnline).
    androidx.compose.runtime.LaunchedEffect(room) { model.refreshOnline(force = true) }
    val picker = org.otrv4plus.android.chat.GroupInvitePicker
    val people = model.groupInviteCandidates(room)
    val ticked = androidx.compose.runtime.remember(room) {
        androidx.compose.runtime.mutableStateListOf<String>()
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(picker.TITLE) },
        text = {
            if (people.isEmpty()) {
                Text(picker.EMPTY, style = MaterialTheme.typography.bodySmall)
            } else {
                androidx.compose.foundation.lazy.LazyColumn(
                    Modifier.heightIn(max = 400.dp)) {
                    items(people.size) { i ->
                        val p = people[i]
                        val on = p.jid in ticked
                        Row(Modifier.fillMaxWidth()
                                .clickable { if (on) ticked.remove(p.jid) else ticked.add(p.jid) },
                            verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.Checkbox(checked = on, onCheckedChange = {
                                if (it) ticked.add(p.jid) else ticked.remove(p.jid)
                            })
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
                model.inviteManyToGroup(room, ticked.toList()); onDone()
            }) { Text(picker.button(ticked.size)) }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}
