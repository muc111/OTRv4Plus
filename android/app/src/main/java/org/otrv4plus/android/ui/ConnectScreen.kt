package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.InitResult
import org.otrv4plus.android.bridge.RouterProbe

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
 * Every call into Python runs on [Dispatchers.IO]. A tunnel build on the main
 * thread is an ANR, not a slow connection.
 */
@Composable
fun ConnectScreen(
    onOpenDiagnostics: () -> Unit = {},
    onConnected: (ChaquopyOtrCore) -> Unit = {},
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // One core for the lifetime of the screen. It owns the Python interpreter,
    // the engine and the transport; rebuilding it on recomposition would start
    // a second interpreter and lose the connection.
    val core = remember { ChaquopyOtrCore(context) }


    var init by remember { mutableStateOf<InitResult?>(null) }
    var status by remember { mutableStateOf(ConnectionStatus()) }
    var probe by remember { mutableStateOf<RouterProbe?>(null) }
    var jid by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf<String?>("Starting Python...") }
    var error by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        init = withContext(Dispatchers.IO) { core.initialize() }
        busy = null
    }

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
            onValueChange = { jid = it; error = null },
            label = { Text("Address") },
            placeholder = { Text("you@server.i2p") },
            singleLine = true,
            enabled = !status.connected && busy == null,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; error = null },
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
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                enabled = busy == null,
                onClick = {
                    error = null
                    busy = "Checking for a router..."
                    scope.launch {
                        val got = withContext(Dispatchers.IO) {
                            runCatching {
                                core.prepareConnection(jid.trim())
                                core.probeRouter()
                            }
                        }
                        got.onSuccess { probe = it }
                            .onFailure { error = it.javaClass.simpleName }
                        status = withContext(Dispatchers.IO) {
                            runCatching { core.connectionStatus() }
                                .getOrDefault(status)
                        }
                        busy = null
                    }
                },
            ) { Text("Check router") }

            Button(
                enabled = busy == null && !status.connected &&
                    jid.isNotBlank() && password.isNotBlank(),
                onClick = {
                    error = null
                    busy = "Connecting. A cold I2P tunnel can take minutes."
                    scope.launch {
                        val got = withContext(Dispatchers.IO) {
                            runCatching {
                                core.prepareConnection(jid.trim())
                                core.connect(password)
                            }
                        }
                        got.onSuccess { status = it }
                            .onFailure { error = it.javaClass.simpleName }
                        // Cleared on both paths: a rejected password is a
                        // reason to retype it, and a connected session has no
                        // further use for it here.
                        password = ""
                        busy = null
                    }
                },
            ) { Text("Connect") }

            if (status.connected) {
                OutlinedButton(
                    enabled = busy == null,
                    onClick = {
                        busy = "Disconnecting..."
                        scope.launch {
                            val got = withContext(Dispatchers.IO) {
                                runCatching { core.disconnect() }
                            }
                            got.onSuccess { status = it }
                                .onFailure { error = it.javaClass.simpleName }
                            busy = null
                        }
                    },
                ) { Text("Disconnect") }
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
        // Disabled while connected. The diagnostics screen builds its own
        // engine, and two EnhancedSessionManagers on one device would open the
        // same identity and trust files twice.
        TextButton(
            enabled = !status.connected && busy == null,
            onClick = onOpenDiagnostics,
        ) { Text("Diagnostics") }
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
    "failed" -> "Failed"
    else -> stage
}
