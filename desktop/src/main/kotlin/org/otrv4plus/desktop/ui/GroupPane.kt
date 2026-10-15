// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
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
                    if (verify.active && verify.total > 0) {
                        LinearProgressIndicator(progress = { verify.done.toFloat() / verify.total },
                                                modifier = Modifier.fillMaxWidth())
                        Text(GroupText.verifyProgress(verify.done, verify.total, verify.etaSeconds,
                                                      verify.members, verify.excluded),
                             style = MaterialTheme.typography.labelSmall)
                    } else if (verify.members.isNotEmpty() && !verify.allVerified) {
                        val notYet = verify.members.filterValues { it != "verified" }
                        Text("Verified: ${verify.members.count { it.value == "verified" }} of " +
                             "${verify.members.size} (not verified: ${notYet.keys.joinToString()})",
                             style = MaterialTheme.typography.labelSmall)
                    } else if (verify.allVerified) {
                        Text("Every member is verified.", style = MaterialTheme.typography.labelSmall,
                             color = VerifiedBlue)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (anyVerified && running == 0) {
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
                        if (!verify.allVerified) {
                            OutlinedButton(onClick = { asking = true }) {
                                Icon(Icons.Filled.VerifiedUser, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(if (verify.startedBy.isNotEmpty())
                                         "Join the verification (${verify.startedBy})"
                                     else "Verify group")
                            }
                        }
                    }
                }
            }
        }
    }
    if (asking) GroupPassphraseDialog(onDone = { phrase ->
        asking = false
        if (phrase != null) model.startGroupVerify(room, phrase)
    })
}

/** The group passphrase: lives in this dialog only, and is dropped with it. */
@Composable
private fun GroupPassphraseDialog(onDone: (String?) -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { passphrase = ""; onDone(null) },
        title = { Text("Verify the group") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Type the group passphrase. Every member who types the same one is " +
                     "verified with you; anyone else is left out of group calls. If you " +
                     "created this group with a passphrase, you can leave this empty.",
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

/** Members, invites and the way out: the side panel of a secure group. */
@Composable
fun GroupMembersPanel(model: AppModel, room: String, modifier: Modifier = Modifier) {
    var invitee by remember(room) { mutableStateOf("") }
    var ending by remember(room) { mutableStateOf("") }
    Column(modifier.fillMaxHeight().verticalScroll(rememberScrollState()).padding(16.dp),
           verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Members", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        val members = model.groupMembers[room].orEmpty()
        if (members.isEmpty()) {
            Text("Reading the group…", style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        for (m in members) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(m.jid, image = model.avatar(m.jid), size = 28)
                Spacer(Modifier.width(8.dp))
                Text(GroupText.memberLine(m.jid, m.me, m.verified, m.bound),
                     style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f),
                     color = if (m.verified) VerifiedBlue else MaterialTheme.colorScheme.onSurface)
                if (!m.me) TextButton(onClick = { model.removeGroupMember(room, m.jid) }) { Text("Remove") }
            }
        }
        HorizontalDivider()
        OutlinedTextField(invitee, { invitee = it }, singleLine = true,
                          label = { Text("Invite a contact (address)") }, modifier = Modifier.fillMaxWidth())
        Text("Invitations go over your encrypted OTRv4+ conversation with them; " +
             "the room never sees them.", style = MaterialTheme.typography.labelSmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
        Button(onClick = { model.inviteToGroup(room, invitee); invitee = "" },
               enabled = invitee.contains('@')) { Text("Invite over OTRv4+") }
        HorizontalDivider()
        TextButton(onClick = { model.verifyGroupMembers(room) }) { Text("Verify members (for calls)") }
        TextButton(onClick = { ending = "leave" }) { Text("Leave group") }
        TextButton(onClick = { ending = "delete" }) {
            Text("Delete group for everyone", color = MaterialTheme.colorScheme.error)
        }
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
