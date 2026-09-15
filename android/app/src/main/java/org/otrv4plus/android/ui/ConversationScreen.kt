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
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState

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
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                // The keyboard must not cover the composer or the last
                // message. Applied here rather than per-widget so there is one
                // place that decides it.
                .imePadding(),
        ) {
            SecurityLine(conversation.security)

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
