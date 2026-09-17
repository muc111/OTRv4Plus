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
import org.otrv4plus.android.connection.SignIn

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
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectScreen(
    model: ConnectionViewModel = viewModel(),
    onOpenDiagnostics: () -> Unit = {},
    onOpenAbout: () -> Unit = {},
    onConnected: () -> Unit = {},
) {
    // Everything long-lived belongs to the ViewModel, which survives Activity
    // recreation -- a rotation, a theme change, a font-size change. This
    // screen used to own the core in `remember`, which does not survive any
    // of those: rotating during a tunnel build built a SECOND core, with a
    // second engine over the same identity and trust files, while the first
    // kept its worker thread and its half-open tunnel.
    val init = model.init
    val status = model.status
    val busy = model.busy
    val error = model.error
    val registration = model.registration

    // The only state that genuinely belongs to the screen: what is typed into
    // it. The password in particular must not outlive the composition, so it
    // is emphatically NOT hoisted into the ViewModel.
    // The USERNAME, not a full address. The domain comes from the server
    // dropdown, because making somebody type a domain they just picked from a
    // list is the kind of thing that makes an app feel like a config file. A
    // full address is still accepted and respected -- see SignIn.resolve.
    var account by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    // Stored as a Boolean rather than the enum: `rememberSaveable` puts this
    // in a Bundle, and a primitive needs no argument about whether a custom
    // Saver is required.
    var customServerChosen by rememberSaveable { mutableStateOf(false) }
    var customServer by rememberSaveable { mutableStateOf("") }
    val choice = if (customServerChosen) SignIn.Choice.CUSTOM
                 else SignIn.Choice.DEFAULT

    // What a connect attempt would resolve to. Every rule is in SignIn, which
    // has no Android import and is tested by being executed.
    val problem = SignIn.problem(account, choice, customServer)
    val target = SignIn.resolve(account, choice, customServer)

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
        //
        // A DROPDOWN, not a b32 field. The destination hash for the default
        // server is compiled into android_bridge/settings.py and applied by
        // the bridge; nobody has to know it exists. Custom routing is still
        // possible -- it is one selection away -- but it is not the price of
        // signing in.
        var serverMenuOpen by remember { mutableStateOf(false) }
        ExposedDropdownMenuBox(
            expanded = serverMenuOpen,
            onExpandedChange = { serverMenuOpen = !serverMenuOpen },
        ) {
            OutlinedTextField(
                value = when (choice) {
                    SignIn.Choice.DEFAULT -> SignIn.DEFAULT_DOMAIN
                    SignIn.Choice.CUSTOM -> "Another server"
                },
                onValueChange = {},
                readOnly = true,
                label = { Text("Server") },
                trailingIcon = {
                    ExposedDropdownMenuDefaults.TrailingIcon(serverMenuOpen)
                },
                enabled = !status.connected && busy == null,
                modifier = Modifier
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
                    .fillMaxWidth(),
            )
            ExposedDropdownMenu(
                expanded = serverMenuOpen,
                onDismissRequest = { serverMenuOpen = false },
            ) {
                DropdownMenuItem(
                    text = { Text(SignIn.DEFAULT_DOMAIN) },
                    onClick = {
                        customServerChosen = false
                        serverMenuOpen = false
                    },
                )
                DropdownMenuItem(
                    text = { Text("Another server\u2026") },
                    onClick = {
                        customServerChosen = true
                        serverMenuOpen = false
                    },
                )
            }
        }

        if (choice == SignIn.Choice.CUSTOM) {
            OutlinedTextField(
                value = customServer,
                onValueChange = { customServer = it },
                label = { Text("Server address") },
                placeholder = { Text("chat.example.i2p") },
                supportingText = {
                    Text("A domain, or a full .b32.i2p destination.")
                },
                singleLine = true,
                enabled = !status.connected && busy == null,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        // ── Account ───────────────────────────────────────────────────────
        OutlinedTextField(
            value = account,
            onValueChange = { account = it },
            label = { Text("Username") },
            placeholder = { Text("alice") },
            supportingText = {
                // Says where they are about to end up, without making them
                // assemble it themselves.
                Text(target?.jid ?: (problem ?: ""))
            },
            isError = account.isNotBlank() && problem != null,
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
        // `model.connecting` included so a login in progress disables both
        // buttons. It did not before: `busy` is set by the register path and
        // by start-up, never by a login, so during the 30-120 s an I2P tunnel
        // takes the Log in button stayed live and a second press started a
        // second attempt. The service rejects the duplicate
        // (`already_connecting`), so nothing broke — but the user got a red
        // code for pressing a button that looked enabled.
        val canSubmit = busy == null && !model.connecting && !status.connected &&
            target != null && password.isNotBlank()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                enabled = canSubmit,
                onClick = {
                    model.connect(target!!.jid, password, target.server)
                    // Cleared immediately, on both paths: a rejected password
                    // is a reason to retype it, and a connected session has no
                    // further use for it here. The ViewModel never keeps a
                    // copy, so after this line the only one left is inside
                    // slixmpp, where SASL needs it.
                    password = ""
                },
            ) { Text("Log in") }

            // SECOND, and an outlined button rather than a filled one.
            //
            // Almost every press on this screen is a login; account creation
            // happens once. Giving both the same weight would make the
            // commoner action the one you have to look for, and on a server
            // that does not offer XEP-0077 -- which we cannot know until we
            // ask -- it is four minutes to find out.
            //
            // It deliberately does NOT then sign in. See
            // ConnectionController.register: two operations, two outcomes,
            // so a registration that worked and a login that did not can be
            // told apart.
            OutlinedButton(
                enabled = canSubmit,
                onClick = {
                    model.register(target!!.jid, password, target.server)
                    password = ""
                },
            ) { Text("Create account") }

            if (status.connected) {
                OutlinedButton(
                    enabled = busy == null,
                    onClick = { model.disconnect() },
                ) { Text("Sign out") }
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

            // THE SAME MECHANISM "Create account" USES -- a
            // LinearProgressIndicator and a line of text -- rather than a
            // second spinner that behaves subtly differently.
            //
            // Register could set `busy` on the line after the call because it
            // runs in a ViewModel coroutine. A login cannot: the service owns
            // the attempt, so the only in-progress signal was `phase`, which
            // does not exist until the service has started and the next poll
            // tick has read it. Between the tap and that tick the screen said
            // nothing at all, on the one operation that can take two minutes.
            // `LoginProgress` covers that gap and expires on its own so this
            // cannot become a permanent spinner.
            Spacer(Modifier.height(4.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(model.connectingLabel,
                 style = MaterialTheme.typography.bodySmall)
        }

        busy?.let {
            Spacer(Modifier.height(4.dp))
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(it, style = MaterialTheme.typography.bodySmall)
        }

        // ── What happened ─────────────────────────────────────────────────
        //
        // ONE LINE, and it is a sentence. This screen used to carry the SAM
        // probe's raw detail, the failure code, the worker-thread state and
        // `inputs` -- the literal arguments that crossed into the transport.
        // All of it is genuinely useful and none of it belongs in front of
        // somebody trying to sign in: a login screen that reports
        // `stream_failed` and `worker thread: alive` reads as broken even when
        // it is working. It moved to the Debug screen, where somebody who
        // wants it can go and find it.
        Spacer(Modifier.height(4.dp))
        StatusRow("State", stageLabel(status.stage))

        // Registration is its own outcome, not a connection state. Placed
        // here rather than merged into the status line because a success ends
        // with nobody signed in, and rendering that as part of the connection
        // would put "Not connected" next to "your account was created".
        registration?.let {
            Spacer(Modifier.height(4.dp))
            Text(
                if (it.ok) "Account created" else "Could not create the account",
                style = MaterialTheme.typography.titleSmall,
                color = if (it.ok) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.error,
            )
            Text(it.detail, style = MaterialTheme.typography.bodySmall)
            if (it.ok) {
                Text(
                    "Now press Log in with the same details.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        if (status.detail.isNotBlank() && status.stage == "failed") {
            Spacer(Modifier.height(4.dp))
            Text("Could not connect",
                style = MaterialTheme.typography.titleSmall)
            SelectionContainer {
                Text(status.detail, style = MaterialTheme.typography.bodySmall)
            }
        }

        error?.let {
            // A Kotlin-side throw, as opposed to a reported Python failure.
            // The class name only: an exception's message can carry what the
            // engine was handling.
            //
            // THIS LINE IS WHAT SHOWED `transport_failed` NEXT TO A WORKING
            // SESSION. The poll used to fold the service's connection failure
            // into `error`, and folded it one way only -- so a first attempt
            // that failed, followed by a backoff retry that connected, left
            // "The app itself failed while doing that (transport_failed)" on
            // screen permanently. The two are separate fields now; this one is
            // only ever a Kotlin throw, which is what the sentence claims.
            Text(
                "The app itself failed while doing that ($it).",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        // The connection's own last failure, and ONLY when it is still the
        // authoritative answer.
        //
        // Not while connected: the last attempt's verdict is superseded by a
        // session that exists, and printing it there is the untruth this whole
        // fix is about. Not while connecting either: an attempt in progress
        // has not failed yet, and the previous attempt's code next to a
        // running progress bar reads as the current one having failed.
        if (!status.connected && !model.connecting) {
            model.connectionFailure?.let {
                Text(
                    "The last connection attempt failed ($it).",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        if (status.connected) {
            Spacer(Modifier.height(8.dp))
            // No object is handed over. The chat screens read the core from
            // the ViewModel that owns it, so navigation carries nothing that
            // could go stale or be duplicated.
            Button(onClick = onConnected) { Text("Open conversations") }
        }

        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            // Disabled while connected. The diagnostics screen builds its own
            // engine, and two EnhancedSessionManagers on one device would open
            // the same identity and trust files twice.
            TextButton(
                enabled = !status.connected && busy == null,
                onClick = onOpenDiagnostics,
            ) { Text("Debug") }

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
    // Not "Disconnected": the account now exists and nobody is signed in,
    // which is a different thing to say to somebody who has just pressed
    // Create account.
    "registered" -> "Account created — not signed in"
    "disconnected" -> "Disconnected"
    "cancelled" -> "Stopped"
    "failed" -> "Failed"
    else -> stage
}
