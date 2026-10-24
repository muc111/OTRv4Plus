package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.platform.LocalContext
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.ConnectionViewModel
import org.otrv4plus.android.BuildConfig
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
 * from docs/ANDROID_I2P_FEASIBILITY.md §2, which claims an app cannot reach another
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

    // The only state that genuinely belongs to the screen: what is typed into
    // it. The password in particular must not outlive the composition, so it
    // is emphatically NOT hoisted into the ViewModel.
    // The USERNAME, not a full address. The domain comes from the server
    // dropdown, because making somebody type a domain they just picked from a
    // list is the kind of thing that makes an app feel like a config file. A
    // full address is still accepted and respected -- see SignIn.resolve.
    var account by rememberSaveable { mutableStateOf(SignIn.INITIAL_USERNAME) }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    // Stored as a Boolean rather than the enum: `rememberSaveable` puts this
    // in a Bundle, and a primitive needs no argument about whether a custom
    // Saver is required.
    var customServerChosen by rememberSaveable { mutableStateOf(false) }
    var customServer by rememberSaveable { mutableStateOf("") }
    var wiping by rememberSaveable { mutableStateOf(false) }
    val choice = if (customServerChosen) SignIn.Choice.CUSTOM
                 else SignIn.Choice.DEFAULT

    // What a connect attempt would resolve to. Every rule is in SignIn, which
    // has no Android import and is tested by being executed.
    val problem = SignIn.problem(account, choice, customServer)
    val target = SignIn.resolve(account, choice, customServer)

    // `model.connecting` included so a login in progress disables both
    // buttons: during the 30-120 s an I2P tunnel takes, a second press would
    // start a second attempt.
    val canSubmit = busy == null && !model.connecting && !status.connected &&
        target != null && password.isNotBlank()
    val editable = !status.connected && busy == null && !model.connecting

    // One function, used by the button and by the keyboard's Done key.
    // The password is cleared on the same line on both paths: a rejected
    // password is a reason to retype it, and a connected session has no
    // further use for it here. The ViewModel never keeps a copy.
    fun logIn() {
        if (!canSubmit) return
        model.connect(target!!.jid, password, target.server)
        password = ""
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            // The window no longer fits the decor -- MainActivity turns that
            // off so the keyboard is handled by exactly one mechanism -- so
            // every screen that is not a Scaffold has to inset itself.
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        ConnectHeader(model, busy, target, onOpenAbout, onOpenDiagnostics,
                      onWipe = { wiping = true })
        if (wiping) {
            WipeAndExitDialog(onWipe = { model.wipeAndExit(it) }, onDismiss = { wiping = false },
                              offerAccountDeletion = model.phase == org.otrv4plus.android.connection.LinkPhase.CONNECTED)
        }

        val ready = init?.ok == true
        if (init == null) {
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally))
            Text("Getting ready…", Modifier.align(Alignment.CenterHorizontally),
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
            return@Column
        }
        if (!ready) {
            // The stack did not come up. Connecting is not the problem to
            // solve and offering it would waste the user's time.
            Text(
                "The app could not start its encryption engine, so it cannot " +
                    "connect. Restarting the app usually fixes this; if it does " +
                    "not, reinstall it.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (BuildConfig.DEV_DIAGNOSTICS) {
                init?.failureCode?.let { StatusRow("Failure", it) }
                Button(onClick = onOpenDiagnostics) { Text("Open diagnostics") }
            }
            return@Column
        }

        ServerChoice(choice, editable, customServer,
                     onCustomServerChange = { customServer = it },
                     onChoose = { customServerChosen = it })

        // ── Account ───────────────────────────────────────────────────────
        OutlinedTextField(
            value = account,
            onValueChange = { account = it },
            label = { Text("Username") },
            placeholder = { Text(SignIn.USERNAME_HINT) },
            supportingText = {
                // Says where they are about to end up, without making them
                // assemble it themselves.
                Text(target?.jid ?: (problem ?: ""))
            },
            isError = account.isNotBlank() && problem != null,
            singleLine = true,
            enabled = editable,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email,
                                              imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            singleLine = true,
            enabled = editable,
            // Hidden unless the user asks to see it, and hidden again on
            // every new screen: a password prompt that shows the password by
            // default is not a password prompt.
            visualTransformation = if (showPassword) VisualTransformation.None
                                   else PasswordVisualTransformation(),
            trailingIcon = {
                TextButton(onClick = { showPassword = !showPassword }) {
                    Text(if (showPassword) "Hide" else "Show")
                }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password,
                                              imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { logIn() }),
            modifier = Modifier.fillMaxWidth(),
        )

        // ── Actions ───────────────────────────────────────────────────────
        //
        // Every one of these hands off to the ViewModel rather than launching
        // in a screen-scoped coroutine: a rotation cancels a composition's
        // scope, and a connect started there would stop being waited on
        // halfway through its own tunnel build.
        if (!status.connected) {
            Button(
                enabled = canSubmit,
                onClick = { logIn() },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Log in") }

            // SECOND, and an outlined button rather than a filled one: almost
            // every press here is a login; account creation happens once.
            // It deliberately does NOT then sign in (ConnectionController.
            // register): a registration that worked and a login that did not
            // stay two outcomes.
            OutlinedButton(
                enabled = canSubmit,
                onClick = {
                    model.register(target!!.jid, password, target.server)
                    password = ""
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Create account") }
        } else {
            // No object is handed over. The chat screens read the core from
            // the ViewModel that owns it.
            Button(onClick = onConnected, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Text("Open chats")
            }
            // No Disconnect (owner, 2026-10-16): the app stays connected,
            // and its built-in router warm, until SIGN OUT, which forgets
            // this account (credentials and history), or until the app is
            // closed. Wipe & Exit (in ⋮) destroys everything.
            OutlinedButton(
                enabled = busy == null,
                onClick = { model.logout() },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Sign out") }
        }

        // Only while an attempt is actually running. The one control that is
        // not disabled by `busy`, because `busy` is the state it gets out of.
        if (model.connecting) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(model.connectingLabel, style = MaterialTheme.typography.bodySmall)
            model.routerLabel?.let {
                Text(it, style = MaterialTheme.typography.bodySmall,
                     color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onClick = { model.cancelConnect() }) { Text("Cancel") }
        }

        busy?.let {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text(it, style = MaterialTheme.typography.bodySmall)
        }

        ConnectOutcome(model)
    }
}

/** Which server: the default, or another typed in full. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ServerChoice(
    choice: SignIn.Choice,
    editable: Boolean,
    customServer: String,
    onCustomServerChange: (String) -> Unit,
    onChoose: (custom: Boolean) -> Unit,
) {
    // ── Where we are connecting ───────────────────────────────────────
    //
    // A DROPDOWN, not a b32 field. The destination hash for the default
    // server is compiled into android_bridge/settings.py and applied by
    // the bridge; nobody has to know it exists.
    //
    // NO ROUTER CHOICE. An I2P app already running on the phone is used;
    // otherwise the router built into the app starts (RouterChoice.decide).
    var serverMenuOpen by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = serverMenuOpen,
        onExpandedChange = { if (editable) serverMenuOpen = !serverMenuOpen },
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
            enabled = editable,
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
                    onChoose(false)
                    serverMenuOpen = false
                },
            )
            DropdownMenuItem(
                text = { Text("Another server…") },
                onClick = {
                    onChoose(true)
                    serverMenuOpen = false
                },
            )
        }
    }

    if (choice == SignIn.Choice.CUSTOM) {
        OutlinedTextField(
            value = customServer,
            onValueChange = onCustomServerChange,
            label = { Text("Server address") },
            placeholder = { Text("chat.example.i2p") },
            supportingText = {
                // The route comes from the name (android_bridge.route):
                // .i2p -> I2P, .onion -> Tor, anything else -> clearnet
                // TLS with a checked certificate.
                Text("A domain (clearnet, .i2p or .onion), or a " +
                     "full .b32.i2p destination.")
            },
            singleLine = true,
            enabled = editable,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri,
                                              imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** The app's name, and everything that is not signing in, behind ⋮. */
@Composable
private fun ConnectHeader(
    model: ConnectionViewModel,
    busy: String?,
    target: SignIn.Target?,
    onOpenAbout: () -> Unit,
    onOpenDiagnostics: () -> Unit,
    onWipe: () -> Unit,
) {
    val status = model.status
    var menuOpen by remember { mutableStateOf(false) }
    // ── Who we are ────────────────────────────────────────────────────
    //
    // The name in words (owner, 2026-10-14: people asked what OTRv4+
    // means), and everything that is not signing in tucked behind ⋮:
    // Test server, About & licences, Debug (debug builds only) and Wipe &
    // Exit. Three buttons in a row read as clutter; a login screen has
    // one job.
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("Off The Record v4 Plus",
                 style = MaterialTheme.typography.headlineSmall,
                 fontWeight = FontWeight.SemiBold)
            Text("Private messaging over I2P, with post-quantum OTRv4+ encryption",
                 style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Box {
            TextButton(onClick = { menuOpen = true }) {
                Text("⋮", style = MaterialTheme.typography.titleLarge)
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                // Reaches the server and stops: no sign-in, no account,
                // no password. Needs only the address.
                DropdownMenuItem(
                    text = { Text("Test server") },
                    enabled = busy == null && !status.connected && target != null,
                    onClick = {
                        menuOpen = false
                        model.testServer(target!!.jid, target.server)
                    },
                )
                // Never disabled: the licence notice and the attribution
                // are obligations that do not depend on the app's state.
                DropdownMenuItem(
                    text = { Text("About & licences") },
                    onClick = { menuOpen = false; onOpenAbout() },
                )
                // Debug builds only. A release build is for people who
                // want to chat, not to read a transport trace.
                if (BuildConfig.DEV_DIAGNOSTICS) {
                    DropdownMenuItem(
                        text = { Text("Debug") },
                        enabled = !status.connected && busy == null,
                        onClick = { menuOpen = false; onOpenDiagnostics() },
                    )
                }
                HorizontalDivider()
                DropdownMenuItem(
                    text = { Text("Wipe & Exit", color = MaterialTheme.colorScheme.error) },
                    onClick = { menuOpen = false; onWipe() },
                )
            }
        }
    }
}

/** What happened: the stage, the account or server-test result, and any problem. */
@Composable
private fun ConnectOutcome(model: ConnectionViewModel) {
    val status = model.status
    val registration = model.registration
    val error = model.error
    // ── What happened ─────────────────────────────────────────────────
    //
    // ONE LINE, and it is a sentence -- and none at all while there is
    // nothing to say. The transport's codes and arguments are on the
    // Debug screen of a debug build, where somebody who wants them can
    // find them.
    if (status.stage != "idle" && !model.connecting) {
        StatusRow("State", stageLabel(status.stage))
        // How long it took this time, router and retries included.
        if (status.connected) {
            model.connectTiming?.let {
                StatusRow("Connected in",
                          org.otrv4plus.android.connection.ConnectTiming.line(it))
            }
        }
    }

    // Registration is its own outcome, not a connection state.
    registration?.let {
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

    model.identityChange?.let { change ->
        ServerIdentityWarning(
            change = change,
            onTrust = { model.trustNewServerAddress() },
            onKeep = { model.dismissIdentityChange() },
        )
    }

    model.serverTest?.let {
        Text(
            if (it.ok) "Server test: reached" else "Server test: failed",
            style = MaterialTheme.typography.titleSmall,
            color = if (it.ok) MaterialTheme.colorScheme.onSurface
                    else MaterialTheme.colorScheme.error,
        )
        SelectionContainer {
            Text(it.detail + (if (BuildConfig.DEV_DIAGNOSTICS)
                                  "\n${it.code}" + (if (it.reached.isNotBlank()) " · reached ${it.reached}" else "")
                              else ""),
                 style = MaterialTheme.typography.bodySmall)
        }
    }

    // What went wrong, if anything did -- and NOT while the app is still
    // doing its job (owner report, 2026-10-11). ConnectProblem decides:
    // expected I2P start-up trouble is a quiet "still connecting" line
    // until it has repeated; a wrong password or a security stop is an
    // error at once.
    val problemLine = org.otrv4plus.android.connection.ConnectProblem.line(
        failure = model.failureCode,
        connected = status.connected,
        retrying = model.connecting,
        failuresInARow = model.failuresInARow,
        bundledRouterUpMs = model.bundledRouterUpMs,
    )
    problemLine?.let { line ->
        val isError = line.tone == org.otrv4plus.android.connection.ConnectProblem.Tone.ERROR
        Text(
            line.text,
            style = MaterialTheme.typography.bodySmall,
            color = if (isError) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        // The transport's own sentence, for an error only.
        if (isError && status.detail.isNotBlank() && status.stage == "failed") {
            SelectionContainer {
                Text(status.detail, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    error?.let {
        // A Kotlin-side throw, as opposed to a reported Python failure.
        // The class name only, and only in a debug build: an exception's
        // message can carry what the engine was handling.
        Text(
            "Something went wrong in the app" +
                (if (BuildConfig.DEV_DIAGNOSTICS) " ($it)." else ". Please try again."),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

/**
 * SECURITY_ISSUES X1, the user-visible half.
 *
 * The server's `.i2p` name now resolves to a different I2P destination --
 * a different key -- than the one this phone trusted. The connection was
 * stopped before anything reached the new destination, so no password went
 * to it. Moving to the new address needs TWO deliberate presses (the button,
 * then the confirmation), and even then nothing connects: the user presses
 * Log in again themselves.
 */
@Composable
private fun ServerIdentityWarning(
    change: org.otrv4plus.android.bridge.ServerIdentityChange,
    onTrust: () -> Unit,
    onKeep: () -> Unit,
) {
    var confirming by remember { mutableStateOf(false) }
    Spacer(Modifier.height(4.dp))
    Text(
        "Security warning: the server's address changed",
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.error,
    )
    Text(
        "${change.server} now points at a different I2P destination than " +
            "the one this phone trusted. The connection was stopped before " +
            "anything was sent to it, and you were not signed in. This can " +
            "be the server moving, or someone impersonating it. Check with " +
            "the server's operator before trusting the new address.",
        style = MaterialTheme.typography.bodySmall,
    )
    SelectionContainer {
        Column {
            Text("Trusted: ${change.trusted}",
                style = MaterialTheme.typography.bodySmall)
            Text("Now:     ${change.seen}",
                style = MaterialTheme.typography.bodySmall)
        }
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = onKeep) { Text("Keep the old address") }
        TextButton(onClick = { confirming = true }) { Text("Trust new address\u2026") }
    }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Trust the new address?") },
            text = {
                Text(
                    "Only if the operator of ${change.server} confirmed the " +
                        "move to ${change.seen}. Your password will be used " +
                        "with that destination the next time you log in.",
                )
            },
            confirmButton = {
                TextButton(onClick = { confirming = false; onTrust() }) {
                    Text("Trust it")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirming = false }) { Text("Cancel") }
            },
        )
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
    // Only .i2p servers pass through checking_router and only .onion (or an
    // explicit Tor choice) through checking_tor; a clearnet server goes
    // straight to connecting (android_bridge.route).
    "checking_router" -> "Checking for an I2P router"
    "checking_tor" -> "Checking for Tor (Orbot)"
    "building_tunnels" -> "Building the I2P or Tor tunnel (this is the slow part)"
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
