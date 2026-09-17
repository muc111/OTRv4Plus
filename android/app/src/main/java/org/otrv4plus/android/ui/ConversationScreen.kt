// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.Verification

/**
 * One conversation: history above, composer below.
 *
 * THE SECURITY LINE IS NOT A PADLOCK.
 *
 * It is a word, and it comes from the engine. Being connected to XMPP says
 * nothing about whether this conversation is encrypted, and the two are easy
 * to blur into a reassuring icon that means "the network is up". A padlock
 * next to a plaintext message would be the one claim this project cannot
 * afford to get wrong, so there is no padlock: there is a sentence saying what
 * is actually true, including when what is true is "not encrypted".
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationScreen(
    model: ChatViewModel,
    jid: String,
    onBack: () -> Unit,
) {
    val conversation = model.conversation(jid)
    val messages = model.messages(jid)
    val listState = rememberLazyListState()

    // Scroll to the newest ONLY when the user is already near the bottom.
    // Yanking the view down while somebody is reading back through yesterday
    // is the single most irritating thing a chat app does.
    LaunchedEffect(messages.size) {
        if (messages.isEmpty()) return@LaunchedEffect
        val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
        val atBottom = last >= messages.size - 2
        if (atBottom) listState.animateScrollToItem(messages.size - 1)
    }

    Scaffold(
        // THE IME IS HANDLED HERE, ONCE.
        //
        // The defect: this was on the inner Column instead, and the window was
        // ALSO resizing behind it. `MainActivity` now turns decor fitting off
        // so the window stops resizing on every API level (see there), which
        // leaves exactly one mechanism — and it has to be the Scaffold, not
        // the content.
        //
        // On the Scaffold the whole thing shrinks by the keyboard height, so
        // `bottomBar` lands on top of the keyboard and the content lambda's
        // padding is computed from what is genuinely left. On the inner Column
        // the Scaffold still believed it had the full window: it placed the
        // composer under the keyboard and handed the content a padding that
        // reserved space for a composer that was no longer there.
        modifier = Modifier.imePadding(),
        topBar = {
            TopAppBar(
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("Back") }
                },
                title = {
                    Column {
                        Text(
                            conversation.displayName,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.titleMedium,
                        )
                        PresenceDot(conversation.presence)
                    }
                },
            )
        },
        bottomBar = {
            Composer(
                draft = model.draft(jid),
                enabled = model.canSend(),
                onChange = { model.setDraft(jid, it) },
                onSend = { model.send(jid) },
            )
        },
    ) { padding ->
        // `padding` FIRST, then `fillMaxSize`: the padding reduces the
        // constraints and the fill takes what is left of them. Reversed, the
        // Column would size itself to the full window and then be inset,
        // overflowing by exactly the padding.
        //
        // No `imePadding()` here. It is on the Scaffold above, and having it
        // in both places is what subtracted the keyboard twice.
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize(),
        ) {
            SecurityLine(conversation.security)

            // The remedy, next to the statement of the problem.
            //
            // Only while the conversation is actually plaintext: once a DAKE
            // has run, offering to start one again is offering to do something
            // already done. FINGERPRINT_MISMATCH is deliberately NOT included
            // -- that conversation IS encrypted, to somebody, and the answer
            // to it is the blocking dialog, not another handshake.
            if (conversation.security == SecurityState.PLAINTEXT) {
                EncryptionOffer(
                    offered = model.encryptionOffered(jid),
                    reason = { model.encryptionUnavailableReason(jid) },
                    onStart = { model.startEncryption(jid) },
                )
            }

            // Verification. Its own row, because it answers a different
            // question from the one above: encryption asks whether the server
            // can read this, verification asks who is on the other end. The
            // row draws nothing at all until there is a session to verify.
            VerificationOffer(
                offer = model.verificationOffer(jid),
                onVerify = { model.requestVerification(jid) },
                onCancel = { model.dismissVerification(jid) },
            )

            // The prompt, in BOTH directions. `verificationPrompt` is derived
            // from the engine's state on every read, so an incoming request
            // opens this with no button pressed -- which is the requirement:
            // the Verify Identity control is only for initiating.
            model.verificationPrompt(jid)?.let { prompt ->
                VerificationPrompt(
                    prompt = prompt,
                    peer = conversation.displayName,
                    onSubmit = { model.submitVerification(jid, it) },
                    onDismiss = { model.dismissVerification(jid) },
                )
            }

            // Somebody who messaged us and was never added.
            //
            // Not an error and not a warning: a message from a stranger is
            // still a message, and the conversation works. What it explains is
            // why their presence says nothing and will go on saying nothing —
            // the server does not send us the presence of somebody we have not
            // subscribed to, so this is permanent rather than slow. Saving
            // them is what asks.
            if (conversation.canBeSaved) {
                UnsavedSenderBanner(
                    enabled = model.canSend(),
                    onSave = { model.addContact(conversation.jid) },
                )
            }

            if (messages.isEmpty()) {
                Box(Modifier.weight(1f).fillMaxWidth(),
                    contentAlignment = Alignment.Center) {
                    Text(
                        "No messages yet.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    contentPadding = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    items(messages, key = { it.id }) { Bubble(it) }
                }
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
private fun UnsavedSenderBanner(enabled: Boolean, onSave: () -> Unit) {
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

/**
 * The control that asks for encryption, or the sentence saying why not.
 *
 * WHY A BUTTON AND NOT A PICKER. With the providers this build ships —
 * OTRv4+ available, OMEMO 2 and MLS not implemented — the selector offers
 * exactly ONE protocol for a 1:1 and NONE for a room. A dropdown would imply
 * a decision the build cannot honour. The button names what it will start, so
 * the day a second protocol is genuinely available this becomes a picker and
 * not a lie in the meantime.
 *
 * WHY IT EXISTS AT ALL. Nothing in the Android UI could ask for OTR.
 * `ChatViewModel.startSession` had no caller and nothing outside `crypto/`
 * imported the encryption package, so every 1:1 stayed in the state
 * `OtrApp.send_user_text` calls "a conversation where nobody has asked for
 * OTR" — and correctly kept sending plaintext, forever, unless the far side
 * started it.
 *
 * An empty offer is a SENTENCE, never an empty menu: an empty menu is
 * indistinguishable from a broken one.
 */
@Composable
private fun EncryptionOffer(
    offered: List<EncryptionKind>,
    reason: () -> String,
    onStart: () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (offered.isEmpty()) {
                Text(
                    reason(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f).padding(vertical = 8.dp),
                )
            } else {
                Text(
                    "This conversation can be encrypted.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                // Names the protocol rather than saying "Encrypt", because
                // which one it is matters and the label is the only place the
                // user is told.
                TextButton(onClick = onStart) {
                    Text("Start ${offered.first().label}")
                }
            }
        }
    }
}

/**
 * The identity-verification control, and the verified badge it becomes.
 *
 * WHY THIS IS SEPARATE FROM [EncryptionOffer]. They answer different
 * questions and appear at different times. Encryption asks "is this traffic
 * readable by the server"; verification asks "is this the person I think it
 * is". A conversation can be fully encrypted and completely unverified, which
 * is the normal state after a DAKE and is exactly what SMP exists to resolve.
 *
 * Hidden entirely before a session exists. There is nothing to verify without
 * one, and a disabled button would invite a user to wonder what they did
 * wrong -- [Verification.offer] returns HIDDEN and this draws nothing.
 */
@Composable
private fun VerificationOffer(
    offer: Verification.Offer,
    onVerify: () -> Unit,
    onCancel: () -> Unit,
) {
    if (offer == Verification.Offer.HIDDEN) return
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Row(
            Modifier.fillMaxWidth().padding(start = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                when (offer) {
                    // Says what verification WOULD buy, rather than just
                    // naming the feature. "Not verified" alone reads as a
                    // defect; this reads as a thing still to do.
                    Verification.Offer.VERIFY ->
                        "You have not checked who is on the other end."
                    Verification.Offer.IN_PROGRESS ->
                        "Verifying… this takes a minute over I2P."
                    Verification.Offer.ANSWERING ->
                        "Answering their verification request…"
                    Verification.Offer.VERIFIED -> "Identity Verified ✓"
                    Verification.Offer.HIDDEN -> ""
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f).padding(vertical = 8.dp),
            )
            when (offer) {
                Verification.Offer.VERIFY ->
                    TextButton(onClick = onVerify) { Text("Verify Identity") }
                // Cancel, not another Verify. A second run against a core
                // already holding one is the wrong operation, and the user's
                // only useful choice here is to stop.
                Verification.Offer.IN_PROGRESS,
                Verification.Offer.ANSWERING ->
                    TextButton(onClick = onCancel) { Text("Cancel") }
                // VERIFIED is a statement, not a control. Offering to verify
                // again would imply the last answer had expired.
                else -> Unit
            }
        }
    }
}

/**
 * The passphrase prompt, for both directions.
 *
 * ONE DIALOG, TWO SENTENCES. The mechanism is identical either way -- both
 * sides type the same agreed text and the core proves they match without
 * transmitting it -- so a second dialog would be a second place to get the
 * handling of a secret wrong. Only the explanation differs, and it comes from
 * [Verification.explanation] where a JVM test can read it.
 *
 * WHY AN AUTOMATIC DIALOG IS SAFE HERE, AND WOULD NOT BE ON A TERMINAL
 * --------------------------------------------------------------------
 * SECURITY_INVARIANTS.md INV-06: a remote peer may cause the client to ASK
 * for the passphrase, but may never cause the next thing the user types to
 * BECOME the passphrase. On a terminal those are one step apart, because
 * there is ONE input channel -- which is why `otrv4plus_smpflow.SmpFlow` puts
 * an explicit consent edge between them.
 *
 * Here the separation is structural instead. This field is its own widget: a
 * message typed into the composer goes to `ChatViewModel.send` and cannot
 * arrive here, whatever a peer does. The peer chooses when a dialog appears;
 * they cannot choose what any other input means.
 *
 * THE PASSPHRASE LIVES IN THIS COMPOSITION AND NOWHERE ELSE. `remember`, not
 * `rememberSaveable`: a saveable would put it in the savedInstanceState
 * Bundle, which Android writes to disk. It is cleared on both exits.
 */
@Composable
private fun VerificationPrompt(
    prompt: Verification.Prompt,
    peer: String,
    onSubmit: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var secret by remember { mutableStateOf("") }
    val submit = {
        // Handed over and cleared on the same path, so the composition does
        // not keep it after the core has it.
        onSubmit(secret)
        secret = ""
    }
    val dismiss = {
        secret = ""
        onDismiss()
    }
    AlertDialog(
        onDismissRequest = dismiss,
        title = {
            Text(
                when (prompt) {
                    Verification.Prompt.OUTGOING -> "Verify Identity"
                    Verification.Prompt.INCOMING -> "Identity Verification"
                }
            )
        },
        text = {
            Column {
                Text(
                    Verification.explanation(prompt, peer),
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("Shared passphrase") },
                    singleLine = true,
                    // A passphrase prompt that shows the passphrase is not a
                    // passphrase prompt -- the same rule the connect screen
                    // applies to the account password.
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(onDone = { submit() }),
                    modifier = Modifier.fillMaxWidth()
                        .padding(top = 12.dp, bottom = 8.dp),
                )
                Text(
                    "Both of you must enter exactly the same text " +
                        "(${Verification.MIN_SECRET}-" +
                        "${Verification.MAX_SECRET} characters).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = {
            // Disabled rather than failing after a round trip: the engine
            // refuses below the minimum and this says so before the wait.
            TextButton(
                enabled = Verification.acceptable(secret),
                onClick = submit,
            ) { Text("Verify") }
        },
        dismissButton = {
            TextButton(onClick = dismiss) { Text("Cancel") }
        },
    )
}

/**
 * What the engine says about this conversation, in words.
 *
 * ENCRYPTED without verification means the traffic is encrypted to somebody --
 * the DAKE ran, nobody checked who answered. That distinction is the whole
 * point of SMP, so the two must never read the same.
 */
@Composable
private fun SecurityLine(state: SecurityState) {
    // Exhaustive on purpose -- no `else`. A new SecurityState must not be able
    // to arrive and quietly inherit whatever the fallback branch happened to
    // say; the compiler makes somebody decide what it means here.
    val (text, colour) = when (state) {
        SecurityState.PLAINTEXT ->
            "Not encrypted — anything sent here is readable by the server." to
                MaterialTheme.colorScheme.error
        SecurityState.ENCRYPTED ->
            "Encrypted, but you have not verified who is on the other end." to
                MaterialTheme.colorScheme.onSurfaceVariant
        SecurityState.FINGERPRINT ->
            "Encrypted. Their key matches the one pinned for them, but you " +
                "have not verified it in person." to
                MaterialTheme.colorScheme.onSurfaceVariant
        SecurityState.SMP_VERIFIED ->
            "Encrypted and verified." to MaterialTheme.colorScheme.primary
        // The loudest state in the app. Not a footnote and not a neutral
        // colour: the key is not the one pinned for this contact.
        SecurityState.FINGERPRINT_MISMATCH ->
            "WARNING: their key is not the one previously pinned for this " +
                "contact. Do not treat this conversation as verified." to
                MaterialTheme.colorScheme.error
    }
    Surface(color = MaterialTheme.colorScheme.surfaceVariant) {
        Text(
            text,
            style = MaterialTheme.typography.bodySmall,
            color = colour,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp,
                                                       vertical = 6.dp),
        )
    }
}

/**
 * One message.
 *
 * Long bodies wrap and long words break rather than pushing the bubble off
 * screen; the width cap is a fraction of the parent so it holds on any device.
 */
@Composable
private fun Bubble(message: Message) {
    val outgoing = message.outgoing
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            Modifier
                .fillMaxWidth(0.82f)
                .wrapContentWidth(if (outgoing) Alignment.End else Alignment.Start)
                .clip(RoundedCornerShape(12.dp))
                .background(
                    if (outgoing) MaterialTheme.colorScheme.primaryContainer
                    else MaterialTheme.colorScheme.surfaceVariant
                )
                .padding(horizontal = 10.dp, vertical = 6.dp),
        ) {
            SelectionContainer {
                Text(message.body, style = MaterialTheme.typography.bodyMedium)
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(formatTimestamp(message.at),
                    style = MaterialTheme.typography.labelSmall)
                statusWord(message)?.let {
                    Text(
                        it,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (message.sendState == SendState.FAILED)
                            MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/**
 * The short status under a message.
 *
 * "Queued" is its own word because it is its own state: the engine is holding
 * the text until there is a session, exactly as the terminal client reports
 * `[queued] will send once OTR is ready`. It has not failed and it has not
 * been delivered, and saying either would be false.
 *
 * "Not encrypted" appears on inbound plaintext so a message readable by the
 * server never looks the same as one that was not.
 */
private fun statusWord(message: Message): String? = when {
    message.sendState == SendState.SENDING -> "sending"
    message.sendState == SendState.QUEUED -> "queued — waiting for encryption"
    message.sendState == SendState.FAILED -> "not sent"
    message.sendState == SendState.SENT &&
        message.security == SecurityLabel.ENCRYPTED -> "sent, encrypted"
    // Said outright rather than left to the absence of the word "encrypted".
    // This message was readable by the server, and a bare "sent" next to a
    // "sent, encrypted" three lines up invites exactly the wrong reading.
    message.sendState == SendState.SENT &&
        message.security == SecurityLabel.PLAINTEXT -> "sent, not encrypted"
    message.sendState == SendState.SENT -> "sent"
    !message.outgoing && message.security == SecurityLabel.PLAINTEXT ->
        "not encrypted"
    else -> null
}

/**
 * The composer: always visible, always at the bottom.
 *
 * The draft lives in the ViewModel, so it survives a recomposition, a presence
 * update redrawing the list, leaving the conversation and coming back, and
 * Activity recreation.
 *
 * Send is refused for blank input in the ViewModel as well as disabled here.
 * Two places, because the button is not the only route in -- the IME action is
 * the other, and a guard on only one of them is a guard on neither.
 */
@Composable
private fun Composer(
    draft: String,
    enabled: Boolean,
    onChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Column {
            if (!enabled) {
                Text(
                    "Not connected — you can type, but nothing will be sent.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp),
                )
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.Bottom,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = onChange,
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Message") },
                    // Several lines, then it scrolls. A composer that grows
                    // without limit eats the conversation it belongs to.
                    maxLines = 5,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = { onSend() }),
                )
                Button(
                    onClick = onSend,
                    enabled = enabled && draft.isNotBlank(),
                ) { Text("Send") }
            }
        }
    }
}

/** hh:mm for today, otherwise a date. Local time, no seconds. */
internal fun formatTimestamp(at: Long): String {
    if (at <= 0) return ""
    val now = java.util.Calendar.getInstance()
    val then = java.util.Calendar.getInstance().apply { timeInMillis = at }
    val sameDay =
        now.get(java.util.Calendar.YEAR) == then.get(java.util.Calendar.YEAR) &&
        now.get(java.util.Calendar.DAY_OF_YEAR) == then.get(java.util.Calendar.DAY_OF_YEAR)
    val pattern = if (sameDay) "HH:mm" else "d MMM HH:mm"
    return java.text.SimpleDateFormat(pattern, java.util.Locale.getDefault())
        .format(java.util.Date(at))
}
