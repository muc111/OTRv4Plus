package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.ConnectionViewModel
import org.otrv4plus.android.bridge.ChaquopyOtrCore

/**
 * The first screen that does something real.
 *
 * The whole path, with nothing simulated:
 *
 *     APK -> Chaquopy -> android_bridge.connection -> SAM probe
 *         -> i2pd -> I2P tunnel -> XMPP c2s -> SASL
 *
 * Two deliberate choices.
 *
 * **Check router is a separate button.** A SAM HELLO is a local handshake that
 * answers in milliseconds; building a tunnel takes up to four minutes. Rolling
 * them together means a user whose router is not running watches a spinner for
 * four minutes and learns nothing. Pressed first, it answers "is there a router
 * at all" immediately -- and on this build it also answers an open question
 * from ANDROID_I2P_FEASIBILITY.md §2, which claims an app cannot reach another
 * app's SAM bridge on loopback. If this button says `ok` against i2pd running
 * in Termux, that claim is wrong and bundling a router is a convenience rather
 * than a precondition.
 *
 * **No security state anywhere on this screen.** Being connected to a server
 * says nothing about whether any conversation is encrypted, and the two are
 * easy to blur into a reassuring green tick that means nothing. Security state
 * belongs to the engine and appears on the conversation screen, derived from
 * `OtrCore.securityState`, once there is a conversation to have.
 *
 * Nothing long-lived is owned here. The core, the connection and every call
 * into Python belong to [ConnectionViewModel], which survives Activity
 * recreation and runs the work off the main thread -- a tunnel build on the
 * main thread is an ANR, not a slow connection, and a tunnel build in a
 * screen-scoped coroutine is one the screen stops waiting for the moment the
 * phone is turned.
 *
 * What this screen does own is what is typed into it, and the password in
 * particular is deliberately NOT hoisted: it must not outlive the composition.
 */
@Composable
fun ConnectScreen(
    model: ConnectionViewModel = viewModel(),
    onOpenDiagnostics: () -> Unit = {},
    onOpenAbout: () -> Unit = {},
    onConnected: (ChaquopyOtrCore) -> Unit = {},
) {
    // Everything long-lived belongs to the ViewModel, which survives Activity
    // recreation -- a rotation, a theme change, a font-size change. This
    // screen used to own the core in `remember`, which does not survive any
    // of those: rotating during a tunnel build built a SECOND core, with a
    // second engine over the same identity and trust files, while the first
    // kept its worker thread and its half-open tunnel.
    val core = model.core
    val init = model.init
    val status = model.status
    val probe = model.probe
    val busy = model.busy
    val error = model.error

    // The only state that genuinely belongs to the screen: what is typed into
    // it. The password in particular must not outlive the composition, so it
    // is emphatically NOT hoisted into the ViewModel.
    var jid by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("OTRv4+", style = MaterialTheme.typography.headlineMedium)

        val ready = init?.ok == true
        if (init == null) {
            CircularProgressIndicator()
            Text("Starting Python and loading the Rust core...")
            return@Column
        }
        if (!ready) {
            // The stack did not come up. Connecting is not the problem to
            // solve and offering it would waste the user's time.
            Text(
                "The OTRv4+ core did not start, so there is nothing to " +
                    "connect with.",
                style = MaterialTheme.typography.bodyMedium,
            )
            init?.failureCode?.let { StatusRow("Failure", it) }
            Button(onClick = onOpenDiagnostics) { Text("Open diagnostics") }
            return@Column
        }

        // ── Where we are connecting ───────────────────────────────────────
        Card(Modifier.fillMaxWidth()) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text("Server", style = MaterialTheme.typography.titleSmall)
                Text(
                    status.server.ifBlank { "(none configured)" },
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    if (status.isDefaultServer)
                        "The default server. You can point this at your own."
                    else
                        "Your own server.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    "I2P SAM bridge: ${status.sam.ifBlank { "127.0.0.1:7656" }}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        // ── Account ───────────────────────────────────────────────────────
        OutlinedTextField(
            value = jid,
            onValueChange = { jid = it },
            label = { Text("Address") },
            placeholder = { Text("you@server.i2p") },
            singleLine = true,
            enabled = !status.connected && busy == null,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            enabled = !status.connected && busy == null,
            // Never echoed. The same rule the terminal client enforces with
            // termios: a password prompt that shows the password is not a
            // password prompt.
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )

        // ── Actions ───────────────────────────────────────────────────────
        //
        // Every one of these hands off to the ViewModel rather than launching
        // in a screen-scoped coroutine. A `rememberCoroutineScope()` is
        // cancelled when the composition goes away, which on Android includes
        // a rotation -- so a connect started here would stop being waited on
        // halfway through its own tunnel build.
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                enabled = busy == null,
                onClick = { model.checkRouter(jid) },
            ) { Text("Check router") }

            Button(
                enabled = busy == null && !status.connected &&
                    jid.isNotBlank() && password.isNotBlank(),
                onClick = {
                    model.connect(jid, password)
                    // Cleared immediately, on both paths: a rejected password
                    // is a reason to retype it, and a connected session has no
                    // further use for it here. The ViewModel never keeps a
                    // copy, so after this line the only one left is inside
                    // slixmpp, where SASL needs it.
                    password = ""
                },
            ) { Text("Connect") }

            if (status.connected) {
                OutlinedButton(
                    enabled = busy == null,
                    onClick = { model.disconnect() },
                ) { Text("Disconnect") }
            }
        }

        // Only while an attempt is actually running. This is the one control
        // that must not be disabled by `busy`, because `busy` is precisely the
        // state it exists to get out of: without it, backing out of a cold
        // tunnel meant waiting up to four minutes or killing the app, and
        // killing the app left the tunnel building.
        if (model.connecting) {
            OutlinedButton(onClick = { model.cancelConnect() }) {
                Text("Cancel")
            }
        }

        busy?.let {
            Spacer(Modifier.height(4.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(it, style = MaterialTheme.typography.bodySmall)
        }

        // ── What happened ─────────────────────────────────────────────────
        Spacer(Modifier.height(4.dp))
        StatusRow("State", stageLabel(status.stage))
        if (status.jid.isNotBlank()) StatusRow("Account", status.jid)

        probe?.let {
            Spacer(Modifier.height(4.dp))
            Text("I2P router", style = MaterialTheme.typography.titleSmall)
            StatusRow("Reachable", if (it.reachable) "yes" else "no")
            if (it.version.isNotBlank()) StatusRow("SAM version", it.version)
            SelectionContainer {
                Text(it.detail, style = MaterialTheme.typography.bodySmall)
            }
        }

        if (status.detail.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text(
                if (status.stage == "failed") "Could not connect"
                else "Connection",
                style = MaterialTheme.typography.titleSmall,
            )
            if (status.code.isNotBlank() && status.stage == "failed") {
                StatusRow("Reason", status.code)
            }
            SelectionContainer {
                Text(status.detail, style = MaterialTheme.typography.bodySmall)
            }
        }

        // Shown only after a failure. On the happy path it is noise; on a
        // failure it is the difference between "the call failed" and "the call
        // got the wrong arguments", which from a handset are otherwise the
        // same observation. The password appears here as present/absent only.
        if (status.stage == "failed" && status.inputs.isNotBlank()) {
            Spacer(Modifier.height(4.dp))
            Text("What reached the transport",
                style = MaterialTheme.typography.titleSmall)
            StatusRow("Worker thread", if (status.workerAlive) "alive" else "not running")
            SelectionContainer {
                Text(status.inputs, style = MaterialTheme.typography.bodySmall)
            }
        }

        error?.let {
            // A Kotlin-side throw, as opposed to a reported Python failure.
            // The class name only: an exception's message can carry what the
            // engine was handling.
            Text(
                "The app itself failed while doing that ($it).",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        if (status.connected) {
            Spacer(Modifier.height(8.dp))
            // Hands the SAME core to the chat screen. A second
            // ChaquopyOtrCore would build a second engine against the same
            // identity and trust files, and the chat would be talking down a
            // socket nothing had connected.
            Button(onClick = { onConnected(core) }) { Text("Open chat") }
        }

        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            // Disabled while connected. The diagnostics screen builds its own
            // engine, and two EnhancedSessionManagers on one device would open
            // the same identity and trust files twice.
            TextButton(
                enabled = !status.connected && busy == null,
                onClick = onOpenDiagnostics,
            ) { Text("Diagnostics") }

            // Never disabled, and reachable before anyone signs in: the
            // licence notice and the third-party attribution are obligations
            // that do not depend on the app's state.
            TextButton(onClick = onOpenAbout) { Text("About & licences") }
        }
    }
}

/**
 * Stage names for a person.
 *
 * Kept distinct rather than collapsed into "connecting", because which stage
 * is slow tells the user what to do: a stall at `building_tunnels` is normal
 * and wants patience, a stall anywhere else does not.
 */
private fun stageLabel(stage: String): String = when (stage) {
    "idle" -> "Not connected"
    "checking_router" -> "Checking for an I2P router"
    "building_tunnels" -> "Building I2P tunnels (this is the slow part)"
    "connecting" -> "Connecting to the server"
    "authenticating" -> "Signing in"
    "connected" -> "Connected"
    "disconnected" -> "Disconnected"
    "cancelled" -> "Stopped"
    "failed" -> "Failed"
    else -> stage
}
