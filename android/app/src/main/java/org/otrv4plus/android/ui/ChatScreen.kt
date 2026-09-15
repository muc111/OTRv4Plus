package org.otrv4plus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityDetails
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState

/**
 * One message as the screen holds it.
 *
 * [encrypted] is not decoration. An outgoing message only exists here if
 * `sendMessage` returned without throwing, and the facade refuses to send
 * unencrypted rather than downgrading -- so `true` on an outgoing message is a
 * fact the engine established, not a hope. An incoming message is marked from
 * the security state at the moment it arrived.
 */
data class ChatMessage(
    val body: String,
    val outgoing: Boolean,
    val at: Long,
    val encrypted: Boolean,
)

/**
 * Contacts and conversations.
 *
 * Every security statement on this screen comes from the engine through
 * [ChaquopyOtrCore] -- `securityState`, `securityDetails`, `smpState`. None of
 * it is computed here, and none of it is inferred from whether a message
 * looked encrypted. That rule is the whole reason `android_bridge.events`
 * exists: the terminal client infers UI state by substring-matching printed
 * English, its own source warns that peer-influenced text can reach those
 * matchers, and Android must never do that.
 *
 * Events are polled rather than pushed. See `ChaquopyOtrCore.drainEvents`:
 * they are emitted on the transport's asyncio loop thread, and pulling keeps
 * the thread decision here instead of spreading it across every handler.
 */
@Composable
fun ChatScreen(
    core: ChaquopyOtrCore,
    onOpenDiagnostics: () -> Unit = {},
    onOpenAbout: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()

    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    var selected by remember { mutableStateOf<String?>(null) }
    val history = remember { mutableStateMapOf<String, List<ChatMessage>>() }
    var details by remember { mutableStateOf<SecurityDetails?>(null) }
    var banner by remember { mutableStateOf<String?>(null) }
    var mismatch by remember { mutableStateOf<OtrEvent.FingerprintChanged?>(null) }
    var gaps by remember { mutableStateOf(0) }
    // The connection, as the transport currently sees it. Polled with the
    // rest: the keepalive can declare the stream dead at any moment, and a
    // contact list that keeps rendering while nothing can be sent is how you
    // type into the void and blame the other person for not replying.
    var connection by remember { mutableStateOf(ConnectionStatus()) }

    fun append(peer: String, msg: ChatMessage) {
        history[peer] = (history[peer] ?: emptyList()) + msg
    }

    // The single polling loop. One place that talks to Python on a schedule,
    // rather than each widget arranging its own refresh.
    LaunchedEffect(Unit) {
        while (true) {
            val batch = withContext(Dispatchers.IO) {
                runCatching {
                    val events = core.drainEvents()
                    val roster = core.contacts()
                    val dropped = core.eventsDropped()
                    Poll(events, roster, dropped, core.connectionStatus())
                }.getOrNull()
            }
            if (batch != null) {
                val events = batch.events
                val roster = batch.roster
                contacts = roster
                gaps = batch.dropped
                connection = batch.connection
                for (event in events) {
                    when (event) {
                        is OtrEvent.MessageReceived -> append(
                            event.peer,
                            ChatMessage(
                                body = event.body,
                                outgoing = false,
                                at = System.currentTimeMillis(),
                                // From the engine's own state for that peer,
                                // not from the shape of the payload.
                                encrypted = roster.firstOrNull {
                                    it.jid == event.peer
                                }?.security?.let { it != SecurityState.PLAINTEXT }
                                    ?: false,
                            ),
                        )

                        // Blocking, not informational. The pinned key changed:
                        // either the peer reinstalled, or someone is standing
                        // in the middle, and the UI must not let the user talk
                        // past it without choosing.
                        is OtrEvent.FingerprintChanged -> mismatch = event

                        is OtrEvent.SessionChanged ->
                            banner = "Session with ${short(event.peer)}: " +
                                securityWord(event.security)

                        is OtrEvent.SmpFinished ->
                            banner = when (event.state) {
                                SmpState.VERIFIED ->
                                    "${short(event.peer)} is verified."
                                SmpState.FAILED ->
                                    "Verification FAILED for ${short(event.peer)} " +
                                        "— the passphrases did not match, or " +
                                        "someone is in the middle."
                                else -> null
                            }

                        is OtrEvent.Failed ->
                            banner = "Error: ${event.code}"

                        else -> Unit
                    }
                }
                selected?.let { peer ->
                    details = withContext(Dispatchers.IO) {
                        runCatching { core.securityDetails(peer) }.getOrNull()
                    }
                }
            }
            delay(500)
        }
    }

    mismatch?.let { event ->
        FingerprintMismatchDialog(event) { mismatch = null }
    }

    val peer = selected
    if (peer == null) {
        ContactList(
            contacts = contacts,
            gaps = gaps,
            onPick = { selected = it },
            onAdd = { jid ->
                scope.launch {
                    withContext(Dispatchers.IO) {
                        runCatching { core.addContact(jid) }
                    }
                }
            },
            onOpenDiagnostics = onOpenDiagnostics,
            onOpenAbout = onOpenAbout,
            connection = connection,
        )
    } else {
        Conversation(
            peer = peer,
            messages = history[peer] ?: emptyList(),
            details = details,
            banner = banner,
            onDismissBanner = { banner = null },
            onBack = { selected = null; details = null },
            onSend = { body ->
                scope.launch {
                    val ok = withContext(Dispatchers.IO) {
                        runCatching { core.sendMessage(peer, body) }
                    }
                    ok.onSuccess {
                        // Only on success. The facade refuses to send
                        // unencrypted rather than downgrading, so a message
                        // that threw did NOT go out and must not appear as
                        // though it did.
                        append(peer, ChatMessage(body, true,
                            System.currentTimeMillis(), true))
                    }.onFailure {
                        banner = "Not sent: ${it.javaClass.simpleName}. " +
                            "Start encryption first."
                    }
                }
            },
            onStartOtr = {
                scope.launch {
                    banner = "Starting the handshake — this takes about 20s " +
                        "over I2P."
                    withContext(Dispatchers.IO) {
                        runCatching { core.startSession(peer) }
                    }.onFailure { banner = "Handshake failed: ${it.javaClass.simpleName}" }
                }
            },
            onVerify = { secret, question ->
                scope.launch {
                    withContext(Dispatchers.IO) {
                        runCatching { core.smpStart(peer, secret, question) }
                    }.onFailure { banner = "Verification could not start." }
                }
            },
            onAnswerSmp = { secret ->
                scope.launch {
                    withContext(Dispatchers.IO) {
                        runCatching { core.smpRespond(peer, secret) }
                    }.onFailure { banner = "Could not answer the verification." }
                }
            },
        )
    }
}

// ── Contacts ────────────────────────────────────────────────────────────────

@Composable
private fun ContactList(
    contacts: List<Contact>,
    gaps: Int,
    onPick: (String) -> Unit,
    onAdd: (String) -> Unit,
    onOpenDiagnostics: () -> Unit,
    onOpenAbout: () -> Unit,
    connection: ConnectionStatus,
) {
    var adding by remember { mutableStateOf("") }

    Column(Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)) {

        Text("Contacts", style = MaterialTheme.typography.headlineSmall)

        // Who you are and whether the stream is up. Both were invisible here,
        // and the second one matters: a dead stream looks exactly like a quiet
        // conversation until you notice nothing has arrived for an hour.
        AccountLine(connection)

        if (gaps > 0) {
            // A gap is worth saying. Silently losing messages is the bug
            // report nobody can reproduce.
            Text("$gaps update(s) were dropped while the app was busy.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error)
        }

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = adding,
                onValueChange = { adding = it },
                label = { Text("Add by address") },
                placeholder = { Text("someone@server.i2p") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                modifier = Modifier.weight(1f),
            )
            Button(
                enabled = adding.contains("@") && !adding.endsWith("@"),
                onClick = { onAdd(adding.trim()); adding = "" },
            ) { Text("Add") }
        }

        if (contacts.isEmpty()) {
            Text(
                "No contacts yet. Add one by address, or wait for them to " +
                    "add you — incoming requests are accepted automatically. " +
                    "Your roster is fetched when you connect, so anyone " +
                    "already on it appears here on its own.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        LazyColumn(Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(contacts, key = { it.jid }) { contact ->
                ContactRow(contact) { onPick(contact.jid) }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onOpenDiagnostics) { Text("Diagnostics") }
            // The third-party notices and the licence statement. Reachable
            // from here as well as from the connection screen, so it is never
            // more than one tap away wherever the user happens to be.
            TextButton(onClick = onOpenAbout) { Text("About & licences") }
        }
    }
}

/**
 * The account, and whether the stream is actually up.
 *
 * `connected` comes from the transport, which the keepalive clears the moment
 * a round trip stops being answered. So this goes amber the moment the
 * session dies rather than when the user gives up waiting for a reply.
 */
@Composable
private fun AccountLine(connection: ConnectionStatus) {
    Column {
        if (connection.jid.isNotBlank()) {
            Text(
                connection.jid,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (connection.connected) {
            Text("Connected", style = MaterialTheme.typography.bodySmall)
        } else {
            Text(
                "Not connected — messages cannot be sent or received. " +
                    "Go back and reconnect.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/** One poll's worth of state. A named type rather than a Triple, because
 *  four unlabelled positions is where the wrong one gets read. */
private data class Poll(
    val events: List<OtrEvent>,
    val roster: List<Contact>,
    val dropped: Int,
    val connection: ConnectionStatus,
)

@Composable
private fun ContactRow(contact: Contact, onClick: () -> Unit) {
    Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            Modifier.padding(12.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(contact.displayName, maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodyLarge)
                Text(
                    if (contact.online) "online" else "offline",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            SecurityChip(contact.security)
        }
    }
}

/**
 * The security state, from the engine.
 *
 * Deliberately not a padlock on its own. A padlock is read as "safe", and
 * ENCRYPTED without verification means the traffic is encrypted to *somebody*
 * — the DAKE has run but nobody has checked it was the right person. The word
 * is what distinguishes the two, so the word is what is shown.
 */
@Composable
private fun SecurityChip(state: SecurityState) {
    val (label, colour) = when (state) {
        SecurityState.PLAINTEXT -> "not encrypted" to MaterialTheme.colorScheme.error
        SecurityState.ENCRYPTED -> "encrypted, unverified" to Color(0xFFB8860B)
        SecurityState.FINGERPRINT -> "fingerprint pinned" to Color(0xFF2E7D32)
        SecurityState.SMP_VERIFIED -> "verified" to Color(0xFF1B5E20)
        SecurityState.FINGERPRINT_MISMATCH -> "KEY CHANGED" to
            MaterialTheme.colorScheme.error
    }
    Text(label, color = colour, style = MaterialTheme.typography.labelMedium)
}

private fun securityWord(state: SecurityState): String = when (state) {
    SecurityState.PLAINTEXT -> "not encrypted"
    SecurityState.ENCRYPTED -> "encrypted, not yet verified"
    SecurityState.FINGERPRINT -> "fingerprint pinned"
    SecurityState.SMP_VERIFIED -> "verified"
    SecurityState.FINGERPRINT_MISMATCH -> "the key CHANGED"
}

private fun short(jid: String) = jid.substringBefore('@')

// ── Conversation ────────────────────────────────────────────────────────────

@Composable
private fun Conversation(
    peer: String,
    messages: List<ChatMessage>,
    details: SecurityDetails?,
    banner: String?,
    onDismissBanner: () -> Unit,
    onBack: () -> Unit,
    onSend: (String) -> Unit,
    onStartOtr: () -> Unit,
    onVerify: (String, String) -> Unit,
    onAnswerSmp: (String) -> Unit,
) {
    var draft by remember(peer) { mutableStateOf("") }
    var verifying by remember(peer) { mutableStateOf(false) }
    var answering by remember(peer) { mutableStateOf(false) }
    val listState = rememberLazyListState()

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
    }

    Column(Modifier.fillMaxSize()) {
        // Header and the security banner, from the engine.
        Surface(tonalElevation = 2.dp) {
            Column(Modifier.fillMaxWidth().padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = onBack) { Text("Back") }
                    Text(short(peer), style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f))
                    details?.let { SecurityChip(it.security) }
                }
                details?.let { SecurityLine(it) }
            }
        }

        banner?.let {
            Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
                Row(Modifier.fillMaxWidth().padding(8.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text(it, Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = onDismissBanner) { Text("OK") }
                }
            }
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(messages) { Bubble(it) }
        }

        // Actions, gated on what the engine reports rather than on a guess.
        val security = details?.security ?: SecurityState.PLAINTEXT
        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (security == SecurityState.PLAINTEXT) {
                Button(onClick = onStartOtr) { Text("Start encryption") }
            } else {
                OutlinedButton(onClick = { verifying = true }) { Text("Verify") }
                if (details?.smp == SmpState.IN_PROGRESS) {
                    Button(onClick = { answering = true }) { Text("Answer") }
                }
            }
        }

        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                placeholder = {
                    Text(
                        if (security == SecurityState.PLAINTEXT)
                            "Start encryption to send"
                        else "Message",
                    )
                },
                // Sending is refused below PLAINTEXT by the facade anyway;
                // disabling here means the refusal is visible before the user
                // has typed a message and lost it.
                enabled = security != SecurityState.PLAINTEXT,
                modifier = Modifier.weight(1f),
            )
            Button(
                enabled = draft.isNotBlank() &&
                    security != SecurityState.PLAINTEXT,
                onClick = { onSend(draft); draft = "" },
            ) { Text("Send") }
        }
    }

    if (verifying) {
        PassphraseDialog(
            title = "Verify ${short(peer)}",
            explanation = "Agree a phrase with them through some other " +
                "channel — in person, or a call you already trust. Type the " +
                "same phrase on both devices. It is never sent.",
            withQuestion = true,
            onDismiss = { verifying = false },
            onConfirm = { secret, question ->
                verifying = false
                onVerify(secret, question)
            },
        )
    }
    if (answering) {
        PassphraseDialog(
            title = "Answer ${short(peer)}",
            explanation = "They started verification. Type the phrase you " +
                "agreed. It is never sent.",
            withQuestion = false,
            onDismiss = { answering = false },
            onConfirm = { secret, _ ->
                answering = false
                onAnswerSmp(secret)
            },
        )
    }
}

@Composable
private fun SecurityLine(details: SecurityDetails) {
    Column(Modifier.padding(top = 4.dp)) {
        if (details.security == SecurityState.ENCRYPTED) {
            Text(
                "Encrypted, but nobody has checked who is on the other end. " +
                    "Verify to be sure.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        details.peerFingerprint?.let {
            SelectionContainer {
                Text("Their key: $it",
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun Bubble(message: ChatMessage) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement =
            if (message.outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = if (message.outgoing)
                MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.widthIn(max = 280.dp),
        ) {
            Column(Modifier.padding(10.dp)) {
                SelectionContainer {
                    Text(message.body, style = MaterialTheme.typography.bodyMedium)
                }
                if (!message.encrypted) {
                    Text("not encrypted",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelSmall)
                }
            }
        }
    }
}

// ── Dialogs ─────────────────────────────────────────────────────────────────

/**
 * Asks for the shared passphrase, hidden.
 *
 * Two rules from the terminal client carry over exactly.
 *
 * It never echoes: a password prompt that shows the password is not a password
 * prompt, and the CLI goes as far as manipulating termios to guarantee it.
 * [PasswordVisualTransformation] is the equivalent here.
 *
 * It is only ever reached by the local user pressing a button. Nothing a peer
 * sends can open this dialog or route typed text into an SMP secret. That is
 * INV-06, and it exists because a remote peer being able to turn the next
 * thing you type into a passphrase is a real attack, not a theoretical one.
 */
@Composable
private fun PassphraseDialog(
    title: String,
    explanation: String,
    withQuestion: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var secret by remember { mutableStateOf("") }
    var question by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(explanation, style = MaterialTheme.typography.bodySmall)
                if (withQuestion) {
                    OutlinedTextField(
                        value = question,
                        onValueChange = { question = it },
                        label = { Text("Hint (optional, sent in the clear)") },
                        singleLine = true,
                    )
                }
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("Shared phrase") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions =
                        KeyboardOptions(keyboardType = KeyboardType.Password),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = secret.isNotBlank(),
                onClick = {
                    onConfirm(secret, question)
                    // Cleared immediately. It is passed straight through to
                    // the engine and never retained here.
                    secret = ""
                },
            ) { Text("Verify") }
        },
        dismissButton = {
            TextButton(onClick = { secret = ""; onDismiss() }) { Text("Cancel") }
        },
    )
}

/**
 * The pinned key changed. Blocking, and deliberately not reassuring.
 *
 * Either the peer reinstalled, or someone is standing in the middle. The UI
 * cannot tell which and must not pretend to: it says both, and makes the user
 * choose rather than offering a dismiss that reads as "fine".
 */
@Composable
private fun FingerprintMismatchDialog(
    event: OtrEvent.FingerprintChanged,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { /* not dismissible by tapping away */ },
        title = { Text("The key for ${short(event.peer)} changed") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "This means one of two things, and there is no way for " +
                        "the app to tell them apart: they reinstalled, or " +
                        "someone is intercepting this conversation.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                SelectionContainer {
                    Column {
                        Text("Pinned:", style = MaterialTheme.typography.labelSmall)
                        Text(event.storedFingerprint,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(4.dp))
                        Text("Now offering:",
                            style = MaterialTheme.typography.labelSmall)
                        Text(event.receivedFingerprint,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
                Text(
                    "Check the new key with them over a channel you already " +
                        "trust before sending anything else.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("I understand") }
        },
    )
}
