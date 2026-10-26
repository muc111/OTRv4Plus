// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import org.otrv4plus.android.connection.ConnectProblem
import org.otrv4plus.desktop.AppModel
import org.otrv4plus.desktop.SignInForm

/**
 * Sign in. The wording of every problem line is the Android app's
 * (ConnectProblem): quiet "still connecting" while I2P builds tunnels, an
 * error only for what is actually wrong.
 *
 * The password lives in this composable's state until Connect is pressed,
 * is handed to the engine, and is cleared on the same line.
 */
@Composable
fun ConnectScreen(model: AppModel) {
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    var password by remember { mutableStateOf("") }
    var advanced by remember { mutableStateOf(false) }

    val busy = model.connecting || model.registering
    val ready = model.account != null && password.isNotEmpty() && !busy

    fun go() {
        if (!ready) return
        model.connect(password)
        password = ""
    }

    fun create() {
        if (!ready) return
        model.register(password)
        password = ""
    }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Card(
            modifier = Modifier.widthIn(max = 460.dp).fillMaxWidth().padding(24.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        ) {
            Column(Modifier.padding(28.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Shield, null, tint = MaterialTheme.colorScheme.primary,
                         modifier = Modifier.size(36.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text("Off The Record v4 Plus", style = MaterialTheme.typography.headlineSmall,
                             fontWeight = FontWeight.SemiBold)
                        Text("OTRv4+ · post-quantum encrypted chat over I2P",
                             style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                // The phone's rule (SignIn): a username alone is on the
                // shipped server; a full address is used as typed.
                OutlinedTextField(model.jid, { model.jid = it }, singleLine = true,
                    label = { Text("Username") },
                    placeholder = { Text("your username") },
                    supportingText = {
                        val account = model.account
                        Text(when {
                            model.jid.isBlank() -> "Or a full address, like you@server.i2p"
                            account != null -> "Signs in as $account"
                            else -> SignInForm.problem(model.jid) ?: ""
                        })
                    },
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(password, { password = it }, singleLine = true,
                    label = { Text("Password") }, visualTransformation = PasswordVisualTransformation(),
                    keyboardActions = KeyboardActions(onDone = { go() }),
                    modifier = Modifier.fillMaxWidth())
                TextButton(onClick = { advanced = !advanced }) {
                    Text(if (advanced) "Hide connection settings" else "Connection settings")
                }
                if (advanced) {
                    OutlinedTextField(model.server, { model.server = it }, singleLine = true,
                        label = { Text("Server (blank: the address's domain)") },
                        modifier = Modifier.fillMaxWidth())
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(model.samHost, { model.samHost = it }, singleLine = true,
                            label = { Text("SAM host") }, modifier = Modifier.weight(2f))
                        OutlinedTextField(model.samPort, { model.samPort = it }, singleLine = true,
                            label = { Text("SAM port") }, modifier = Modifier.weight(1f))
                    }
                    Text("On Qubes the I2P router is in sys-i2p and reached at " +
                         "127.0.0.1:7656 through qrexec; leave these as they are.",
                         style = MaterialTheme.typography.bodySmall,
                         color = MaterialTheme.colorScheme.onSurfaceVariant)
                    // N1: a SAM bridge has no authentication. One off this
                    // machine is used only when typed here, and only by IP.
                    val host = model.samHost.trim().lowercase()
                    if (host.isNotEmpty() && host != "localhost" && !host.startsWith("127.") && host != "::1") {
                        Text(SAM_ELSEWHERE_WARNING, style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.error)
                    }
                }
                Button(onClick = { go() }, enabled = ready,
                       modifier = Modifier.fillMaxWidth().height(48.dp)) {
                    if (model.connecting) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp,
                                                  color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(10.dp))
                        Text("Connecting over I2P…")
                    } else Text("Connect")
                }
                // Second and outlined, as on the phone: almost every press is
                // a sign-in. A created account signs in straight away.
                OutlinedButton(onClick = { create() }, enabled = ready,
                               modifier = Modifier.fillMaxWidth().height(48.dp)) {
                    if (model.registering) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                        Text("Creating the account…")
                    } else Text("Create account")
                }
                model.registration?.let { r ->
                    Text(if (r.ok) "Account created, signing in…" else "Could not create the account",
                         style = MaterialTheme.typography.titleSmall,
                         color = if (r.ok) MaterialTheme.colorScheme.onSurface
                                 else MaterialTheme.colorScheme.error)
                    if (!r.ok) Text(r.detail.ifBlank { "The server said: ${r.code}" },
                                    style = MaterialTheme.typography.bodySmall)
                }
                model.problemLine()?.let { line ->
                    Text(line.text, style = MaterialTheme.typography.bodyMedium,
                         color = if (line.tone == ConnectProblem.Tone.ERROR) MaterialTheme.colorScheme.error
                                 else MaterialTheme.colorScheme.onSurfaceVariant)
                }
                // U1: no fingerprint on the sign-in screen. It is device-
                // binding material; it is shown under Identity once signed in.
            }
        }
    }
}


/** N1: shown under a SAM host that is not this machine. */
internal const val SAM_ELSEWHERE_WARNING =
    "A SAM bridge on another machine has no password: anyone who can reach it " +
        "can use it, and it sees which I2P destinations you connect to. Use only " +
        "one you run yourself, given by its IP address (a name would need DNS)."
