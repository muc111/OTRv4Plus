// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.Location
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.MicPermission
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.HandshakeUi
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
    onOpenProfile: ((String) -> Unit)? = null,
    /** Open another conversation (a group member's 1:1 chat). */
    onOpenChat: ((String) -> Unit)? = null,
) {
    val conversation = model.conversation(jid)
    val messages = model.messages(jid)
    val listState = rememberLazyListState()
    // A ROOM is plaintext group chat, and this screen says so instead of
    // offering encryption, verification, calls or files -- none of which a
    // room can have. The bridge refuses all four for a room regardless.
    val room = model.isRoom(jid)
    LaunchedEffect(jid, room) { if (room) model.refreshOccupants(jid) }
    // The phone's colour: while a conversation that can call is open, the
    // next call's I2P path is built and kept (10 minutes after the last
    // look); elsewhere its state is only read.
    LaunchedEffect(jid, room) {
        while (true) {
            val callable = if (room) model.isSecureRoom(jid) && model.groupCallAllowed(jid) &&
                                     model.groupMembers(jid).any { !it.me && it.verified }
                           else model.callGate(jid).first == CallUi.Gate.AVAILABLE
            model.refreshCallPath(callable)
            kotlinx.coroutines.delay(if (model.callPath == CallUi.Readiness.READY) 15_000L else 4_000L)
        }
    }

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
                    ConversationTitle(model, jid, conversation, onOpenProfile)
                },
                actions = {
                    ConversationMenu(model, jid, onOpenProfile)
                },
            )
        },
        bottomBar = {
            Composer(
                draft = model.draft(jid),
                // A secure group still being set up sends nothing (the
                // engine refuses too): said here rather than "not connected".
                enabled = model.canSend() && !model.isJoiningRoom(jid),
                held = if (model.isJoiningRoom(jid))
                           "Setting up end-to-end encryption — you can type; it can be sent once the group is ready."
                       else null,
                onChange = { model.setDraft(jid, it) },
                onSend = { model.send(jid) },
                banner = model.editing?.takeIf { it.conversationId == ChatState.bare(jid) }
                    ?.let { "Correcting your message" }
                    ?: model.replyingTo?.takeIf { it.conversationId == ChatState.bare(jid) }
                        ?.let { "Replying to: " + (it.body.lineSequence().firstOrNull() ?: "").take(60) },
                onCancel = { model.cancelCompose(jid) },
                status = model.actionStatus,
                // The mic: a disguised, encrypted voice note. Offered where a
                // file may be sent (verified contact, or a secure group whose
                // members are all verified); nowhere else.
                // Shown in every encrypted conversation; until the contact (or
                // every group member) is verified a tap explains instead.
                onVoice = if (model.transferOffer(jid) !is TransferUi.Offer.NeedsEncryption)
                              ({ model.requestVoice(jid) }) else null,
                onAttach = if (model.transferOffer(jid) !is TransferUi.Offer.NeedsEncryption)
                               ({ model.requestFile(jid) }) else null,
                // A location pin: shown in every encrypted conversation, sent
                // only once the contact (or every group member) is verified;
                // until then a tap explains and the GPS is never started.
                onLocation = if (model.transferOffer(jid) !is TransferUi.Offer.NeedsEncryption)
                                 ({ model.openLocation(jid) }) else null,
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
            if (model.askBlock == jid) {
                BlockDialog(
                    name = conversation.displayName,
                    report = model.blockReport,
                    onReport = { model.blockReport = it },
                    onBlock = { report -> model.askBlock = null; model.block(jid, report) },
                    onDismiss = { model.askBlock = null },
                )
            }
            if (!room && model.isBlocked(jid)) {
                Surface(color = MaterialTheme.colorScheme.errorContainer) {
                    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Text("Blocked: nothing they send reaches you.",
                             style = MaterialTheme.typography.bodySmall,
                             color = MaterialTheme.colorScheme.onErrorContainer,
                             modifier = Modifier.weight(1f))
                        TextButton(onClick = { model.unblock(jid) }) { Text("Unblock") }
                    }
                }
            }
            if (room) {
                RoomHeader(model, jid, onOpenChat)
            } else {
                ContactHeader(model, jid, conversation)
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
                    items(messages, key = { it.id }) { Bubble(it, model, onOpenChat) }
                }
            }
        }
    }
}

/** The name, picture and presence (or "typing…") at the top. */
@Composable
internal fun ConversationTitle(
    model: ChatViewModel,
    jid: String,
    conversation: org.otrv4plus.android.chat.Conversation,
    onOpenProfile: ((String) -> Unit)?,
) {
    Row(verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
      // A person's picture opens their profile, as in every
      // messenger (owner, 2026-10-16). A room has no profile.
      if (!model.isRoom(jid)) {
          AvatarPlaceholder(
              conversation.displayName, model.avatar(jid), size = 36.dp,
              onClick = onOpenProfile?.let { open -> { open(jid) } },
          )
      }
      Column {
          Text(
              conversation.displayName,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
              style = MaterialTheme.typography.titleMedium,
          )
          // "typing..." (XEP-0085) replaces the presence line
          // while it lasts, as messengers do.
          if (!model.isRoom(jid) && model.isTyping(jid)) {
              Text("typing\u2026", style = MaterialTheme.typography.labelSmall,
                   color = MaterialTheme.colorScheme.primary)
          } else {
              PresenceDot(conversation.presence)
          }
      }
    }
}

/** ⋮ for a person: their profile, and blocking. A room has neither. */
@Composable
internal fun ConversationMenu(model: ChatViewModel, jid: String, onOpenProfile: ((String) -> Unit)?) {
    // A person's profile and blocking; a room has neither.
    if (!model.isRoom(jid)) {
        Box {
            TextButton(onClick = { model.conversationMenu = true }) {
                Text("\u22EE", style = MaterialTheme.typography.titleLarge)
            }
            DropdownMenu(expanded = model.conversationMenu,
                         onDismissRequest = { model.conversationMenu = false }) {
                if (onOpenProfile != null) {
                    DropdownMenuItem(text = { Text("Profile") },
                                     onClick = { model.conversationMenu = false; onOpenProfile(jid) })
                }
                // L1: in every established 1:1 OTRv4+ chat.
                if (org.otrv4plus.android.crypto.DeniableChat.offered(
                        model.conversation(jid).security, isRoom = false)) {
                    DropdownMenuItem(text = { Text(org.otrv4plus.android.crypto.DeniableChat.ACTION) },
                                     onClick = { model.conversationMenu = false; model.askDeniable = jid })
                }
                if (model.blockingSupported) {
                    if (model.isBlocked(jid)) {
                        DropdownMenuItem(text = { Text("Unblock") },
                                         onClick = { model.conversationMenu = false; model.unblock(jid) })
                    } else {
                        DropdownMenuItem(
                            text = { Text("Block\u2026", color = MaterialTheme.colorScheme.error) },
                            onClick = { model.conversationMenu = false; model.askBlock = jid })
                    }
                }
            }
        }
        model.askDeniable?.takeIf { it == jid }?.let { MakeDeniableDialog(model, it) }
    }
}

/** "Make this chat deniable?": every word from [DeniableChat]. */
@Composable
internal fun MakeDeniableDialog(model: ChatViewModel, jid: String) {
    val text = org.otrv4plus.android.crypto.DeniableChat
    AlertDialog(
        onDismissRequest = { model.askDeniable = null },
        title = { Text(text.TITLE) },
        text = { Text(text.BODY) },
        confirmButton = { TextButton(onClick = { model.makeChatDeniable(jid) }) { Text(text.CONFIRM) } },
        dismissButton = { TextButton(onClick = { model.askDeniable = null }) { Text("Cancel") } },
    )
}

/** Above a one-to-one chat: its security, the handshake, calls and files,
 *  encryption and verification, and the unsaved-sender note. */
@Composable
internal fun ContactHeader(
    model: ChatViewModel,
    jid: String,
    conversation: org.otrv4plus.android.chat.Conversation,
) {
    SecurityLine(conversation.security, conversation.otrCapability)
    // The handshake, while it runs: step, parts received, elapsed.
    // Without it a DAKE over I2P looked like nothing happening.
    if (conversation.security == SecurityState.PLAINTEXT) {
        HandshakeCard(model.handshake(jid))
    }

    // Directly under the security line, because it is the same
    // subject: what this conversation is, and what it lets you do.
    CallBar(model, jid)

    // Same subject again: what this conversation lets you do.
    TransferBar(model, jid)

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
        steps = model.verificationSteps(jid),
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
}

/** The document's own name, or a neutral one. Never a path from the URI. */
internal fun displayName(context: android.content.Context,
                        uri: android.net.Uri): String {
    val fallback = "shared-file"
    val cursor = runCatching {
        context.contentResolver.query(uri, null, null, null, null)
    }.getOrNull() ?: return fallback
    cursor.use {
        val column = it.getColumnIndex(
            android.provider.OpenableColumns.DISPLAY_NAME)
        if (column < 0 || !it.moveToFirst()) return fallback
        val raw = runCatching { it.getString(column) }.getOrNull()
        // Basename only. A provider-supplied name is somebody else's string
        // and must not be able to carry a path separator into a File().
        val name = raw?.substringAfterLast('/')?.substringAfterLast('\\')
        return name?.takeIf { candidate -> candidate.isNotBlank() } ?: fallback
    }
}

/**
 * One message.
 *
 * Long bodies wrap and long words break rather than pushing the bubble off
 * screen; the width cap is a fraction of the parent so it holds on any device.
 */
@Composable
internal fun Bubble(message: Message, model: ChatViewModel, onOpenChat: ((String) -> Unit)? = null) {
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
            // A room line says who wrote it, ABOVE and apart from the body, so
            // a body that begins "Bob: " cannot pass for a line from Bob.
            if (message.sender.isNotEmpty() && !outgoing) {
                Text(
                    message.sender,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            // A reply quotes what it answers (XEP-0461), as it was then.
            if (message.replyTo.isNotEmpty() && !message.retracted) {
                Surface(
                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.6f),
                    shape = RoundedCornerShape(6.dp),
                    modifier = Modifier.padding(bottom = 4.dp),
                ) {
                    Text("\u21A9 " + message.replyPreview.ifBlank { "an earlier message" },
                         style = MaterialTheme.typography.labelSmall,
                         maxLines = 2, overflow = TextOverflow.Ellipsis,
                         modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp))
                }
            }
            if (message.retracted) {
                Text("Message deleted", style = MaterialTheme.typography.bodyMedium,
                     color = MaterialTheme.colorScheme.onSurfaceVariant,
                     fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)
            } else {
                // A pin is shown as a card; anything else (or a pin a client
                // mangled) as the text it is.
                val pin = if (message.body.startsWith(Location.MARKER)) Location.parse(message.body) else null
                if (message.voicePath.isNotEmpty()) {
                    VoiceNoteBubble(message, model)
                } else if (pin != null) {
                    LocationCard(pin)
                } else {
                    SelectionContainer {
                        Text(message.body, style = MaterialTheme.typography.bodyMedium)
                    }
                    // A received, verified file opens from its line, here and
                    // after a restart, in the in-app viewer.
                    if (model.canOpenLine(message)) {
                        TextButton(onClick = { model.openLine(message) }) { Text("Open") }
                    }
                }
            }
            // Reactions (XEP-0444): each emoji once, with how many chose it.
            if (message.reactions.isNotEmpty()) {
                val counts = message.reactions.values.flatten().groupingBy { it }.eachCount()
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.padding(top = 2.dp)) {
                    counts.forEach { (emoji, n) ->
                        val mine = emoji in message.reactions["me"].orEmpty()
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (mine) MaterialTheme.colorScheme.secondaryContainer
                                    else MaterialTheme.colorScheme.surface,
                            modifier = Modifier.clickable { model.react(message, emoji) },
                        ) {
                            Text(if (n > 1) "$emoji $n" else emoji,
                                 style = MaterialTheme.typography.labelMedium,
                                 modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp))
                        }
                    }
                }
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(formatTimestamp(message.at) + if (message.edited) " \u00B7 edited" else "",
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
                if (model.canAct(message)) MessageActions(message, model, onOpenChat)
            }
        }
    }
}

/** The quick reactions offered on every message, as in other messengers. */
internal val QUICK_REACTIONS = listOf("\uD83D\uDC4D", "\u2764\uFE0F", "\uD83D\uDE02",
                                     "\uD83D\uDE2E", "\uD83D\uDE22", "\uD83D\uDE4F")

/**
 * Reply, react, copy -- and for our own messages, correct and delete for
 * everyone. In an encrypted conversation each is sent inside the OTR
 * payload; the server learns nothing about which message was acted on.
 */
@Composable
internal fun MessageActions(message: Message, model: ChatViewModel,
                           onOpenChat: ((String) -> Unit)? = null) {
    val clipboard = androidx.compose.ui.platform.LocalClipboardManager.current
    Box {
        Text("\u22EF", style = MaterialTheme.typography.labelLarge,
             color = MaterialTheme.colorScheme.onSurfaceVariant,
             modifier = Modifier.clip(RoundedCornerShape(8.dp))
                 .clickable { model.actionsFor = message.id }
                 .padding(horizontal = 6.dp))
        DropdownMenu(expanded = model.actionsFor == message.id,
                     onDismissRequest = { model.actionsFor = null }) {
            Row(Modifier.padding(horizontal = 8.dp)) {
                QUICK_REACTIONS.forEach { emoji ->
                    TextButton(onClick = { model.react(message, emoji) },
                               contentPadding = PaddingValues(4.dp),
                               modifier = Modifier.width(40.dp)) { Text(emoji) }
                }
            }
            HorizontalDivider()
            DropdownMenuItem(text = { Text("Reply") }, onClick = { model.startReply(message) })
            DropdownMenuItem(text = { Text("Copy") }, onClick = {
                clipboard.setText(androidx.compose.ui.text.AnnotatedString(message.body))
                model.actionsFor = null
            })
            // A secure-group member, by the address MLS proved (never the
            // nickname): add them, or go straight to a 1:1 chat.
            model.memberOf(message)?.let { member ->
                HorizontalDivider()
                if (!model.isContact(member)) {
                    DropdownMenuItem(text = { Text("Add to contacts") }, onClick = {
                        model.actionsFor = null
                        model.addContact(member)
                    })
                }
                if (onOpenChat != null) {
                    DropdownMenuItem(text = { Text("Message privately") }, onClick = {
                        model.actionsFor = null
                        onOpenChat(member)
                    })
                }
            }
            if (message.outgoing) {
                DropdownMenuItem(text = { Text("Correct") }, onClick = { model.startEdit(message) })
                DropdownMenuItem(
                    text = { Text("Delete for everyone", color = MaterialTheme.colorScheme.error) },
                    onClick = { model.retract(message) })
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
internal fun statusWord(message: Message): String? = when {
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
    // Ticks as in every messenger: one for sent, two for delivered (a
    // XEP-0184 receipt), "read" once the contact's app says they saw it
    // (XEP-0333). Each still says whether it was encrypted.
    message.sendState == SendState.DELIVERED ->
        "\u2713\u2713 delivered" + encryptedSuffix(message)
    message.sendState == SendState.READ ->
        "\u2713\u2713 read" + encryptedSuffix(message)
    !message.outgoing && message.security == SecurityLabel.PLAINTEXT ->
        "not encrypted"
    else -> null
}

internal fun encryptedSuffix(message: Message): String = when (message.security) {
    SecurityLabel.ENCRYPTED -> ", encrypted"
    SecurityLabel.PLAINTEXT -> ", not encrypted"
    else -> ""
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
internal fun Composer(
    draft: String,
    enabled: Boolean,
    onChange: (String) -> Unit,
    onSend: () -> Unit,
    banner: String? = null,
    onCancel: () -> Unit = {},
    status: String? = null,
    onVoice: (() -> Unit)? = null,
    onLocation: (() -> Unit)? = null,
    onAttach: (() -> Unit)? = null,
    held: String? = null,
) {
    Surface(tonalElevation = 3.dp) {
        Column {
            // Replying to, or correcting, a message: said, with a way out.
            banner?.let {
                Row(Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text(it, style = MaterialTheme.typography.labelMedium,
                         color = MaterialTheme.colorScheme.primary,
                         maxLines = 1, overflow = TextOverflow.Ellipsis,
                         modifier = Modifier.weight(1f))
                    TextButton(onClick = onCancel) { Text("Cancel") }
                }
            }
            status?.let {
                Text(it, style = MaterialTheme.typography.labelSmall,
                     color = MaterialTheme.colorScheme.error,
                     modifier = Modifier.padding(horizontal = 12.dp, vertical = 2.dp))
            }
            if (!enabled) {
                Text(
                    held ?: "Not connected — you can type, but nothing will be sent.",
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
                onLocation?.let {
                    IconButton(onClick = it, enabled = enabled,
                               modifier = Modifier.semantics { contentDescription = "Share a location" }) {
                        Text("📍")
                    }
                }
                onAttach?.let {
                    IconButton(onClick = it, enabled = enabled,
                               modifier = Modifier.semantics { contentDescription = "Send a file" }) {
                        Text("📎")
                    }
                }
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
                if (draft.isBlank() && onVoice != null) {
                    // Nothing typed: the mic, as in every messenger.
                    FilledIconButton(onClick = onVoice, enabled = enabled) {
                        MicIcon(contentDescription = "Record a voice note")
                    }
                } else {
                    Button(
                        onClick = onSend,
                        enabled = enabled && draft.isNotBlank(),
                    ) { Text("Send") }
                }
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
