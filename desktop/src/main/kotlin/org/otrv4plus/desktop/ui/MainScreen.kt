// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Groups
import androidx.compose.material.icons.filled.People
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.foundation.horizontalScroll
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.chat.Conversation
import org.otrv4plus.android.chat.Presence
import org.otrv4plus.android.chat.RowSecurity
import org.otrv4plus.android.connection.LinkPhase
import org.otrv4plus.desktop.AppModel

@Composable
fun MainScreen(model: AppModel, onWipe: () -> Unit) {
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    Row(Modifier.fillMaxSize()) {
        NavigationRail(containerColor = MaterialTheme.colorScheme.surface) {
            Spacer(Modifier.padding(top = 8.dp))
            RailItem(model, AppModel.Tab.CHATS, Icons.AutoMirrored.Filled.Chat, "Chats",
                     badge = model.conversations().sumOf { it.unread })
            RailItem(model, AppModel.Tab.PEOPLE, Icons.Filled.People, "People",
                     badge = model.chat.pendingSubscriptions.size)
            RailItem(model, AppModel.Tab.ROOMS, Icons.Filled.Groups, "Rooms",
                     badge = model.chat.pendingGroupInvites.size,
                     flashing = model.unseenInvites())
            RailItem(model, AppModel.Tab.SETTINGS, Icons.Filled.Settings, "Settings")
        }
        VerticalDivider()
        Column(Modifier.fillMaxSize()) {
            LinkBanner(model)
            model.chat.notice?.let { Notice(it) { model.dismissNotice() } }
            OtherSessionsBanner(model)
            IncomingCallBanner(model)
            model.chat.fingerprintAlert?.let { alert ->
                Notice("The identity key of ${alert.peer} has CHANGED. Do not trust this " +
                       "conversation until you have verified them again.",
                       alarm = true) { model.dismissFingerprintAlert() }
            }
            model.viewing?.let { (who, values) -> ProfileDialog(model, who, values) }
            when (model.tab) {
                AppModel.Tab.CHATS -> ChatsPane(model)
                AppModel.Tab.PEOPLE -> PeoplePane(model)
                AppModel.Tab.ROOMS -> RoomsPane(model)
                AppModel.Tab.SETTINGS -> SettingsPane(model, onWipe)
            }
        }
    }
}

/**
 * Someone is calling, whatever is on screen. Owner report (2026-10-20): a
 * call from the phone "not going through" -- the desktop rang only inside
 * the caller's own chat, so with any other chat (or the Welcome room) open
 * there was nothing to answer, and the phone gave up. Only a verified
 * contact's call can ring (the engine's gate).
 */
@Composable
private fun IncomingCallBanner(model: AppModel) {
    for (peer in model.chat.ringingPeers()) {
        val name = model.conversation(peer).displayName.ifBlank { peer }
        Surface(color = MaterialTheme.colorScheme.tertiaryContainer) {
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Call, null, tint = MaterialTheme.colorScheme.onTertiaryContainer)
                Spacer(Modifier.width(10.dp))
                Text("Incoming call from $name", Modifier.weight(1f),
                     color = MaterialTheme.colorScheme.onTertiaryContainer,
                     fontWeight = FontWeight.Medium)
                TextButton(onClick = { model.hangUp(peer) }) { Text("Decline") }
                Spacer(Modifier.width(8.dp))
                Button(onClick = { model.answerFromPrompt(peer) }) { Text("Answer") }
            }
        }
    }
}

/** Our own account signed in somewhere else (owner, 2026-10-16). A server
 *  admin can end those sessions; anyone else is told to change the password. */
@Composable
private fun OtherSessionsBanner(model: AppModel) {
    val line = org.otrv4plus.android.chat.AccountSessions.banner(model.otherSessions)
    val status = model.sessionsStatus
    if (line == null && status == null) return
    Surface(color = MaterialTheme.colorScheme.errorContainer) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            line?.let {
                Text(it, color = MaterialTheme.colorScheme.onErrorContainer,
                     style = MaterialTheme.typography.bodyMedium)
            }
            status?.let {
                Text(it, color = MaterialTheme.colorScheme.onErrorContainer,
                     style = MaterialTheme.typography.bodySmall)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (line != null && model.isServerAdmin) {
                    TextButton(onClick = { model.endOtherSessions() }) {
                        Text(org.otrv4plus.android.chat.AccountSessions.END_BUTTON)
                    }
                }
                if (status != null) {
                    TextButton(onClick = { model.sessionsStatus = null }) { Text("OK") }
                }
            }
        }
    }
}

@Composable
private fun RailItem(model: AppModel, tab: AppModel.Tab, icon: androidx.compose.ui.graphics.vector.ImageVector,
                     label: String, badge: Int = 0, flashing: Int = 0) {
    // [flashing]: things on this tab not seen yet (InviteAttention). The tab
    // pulses and says how many, so it is noticed from any other tab.
    val pulse = if (flashing > 0) {
        val transition = rememberInfiniteTransition(label = "rail-$label")
        val alpha by transition.animateFloat(
            initialValue = 0.85f, targetValue = 0.15f, label = "rail-$label-alpha",
            animationSpec = infiniteRepeatable(tween(650), RepeatMode.Reverse))
        alpha
    } else 0f
    NavigationRailItem(
        selected = model.tab == tab,
        onClick = { model.tab = tab },
        icon = {
            Box(Modifier.clip(CircleShape)
                .background(MaterialTheme.colorScheme.error.copy(alpha = pulse))
                .padding(4.dp)) {
                Icon(icon, label)
                if (flashing > 0) {
                    Text("$flashing", Modifier.align(Alignment.TopEnd).clip(CircleShape)
                        .background(MaterialTheme.colorScheme.error)
                        .padding(horizontal = 4.dp),
                        color = MaterialTheme.colorScheme.onError,
                        style = MaterialTheme.typography.labelSmall)
                } else if (badge > 0) {
                    Box(Modifier.align(Alignment.TopEnd).size(8.dp).clip(CircleShape)
                        .background(MaterialTheme.colorScheme.error))
                }
            }
        },
        label = { Text(if (flashing > 0) "$label · new" else label) },
    )
}

/** Connection state, said quietly while I2P is still working. */
@Composable
private fun LinkBanner(model: AppModel) {
    val phase = model.phase
    if (phase == LinkPhase.CONNECTED) return
    val text = when (phase) {
        LinkPhase.FAILED -> model.problemLine()?.text ?: "The connection failed."
        LinkPhase.STOPPED -> "Not connected."
        LinkPhase.RECONNECTING ->
            "Reconnecting over I2P by itself… messages you type are kept until it is back."
        else -> "Connecting over I2P… the first time can take a few minutes; it carries on by itself."
    }
    Surface(color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f).padding(vertical = 8.dp),
                 style = MaterialTheme.typography.bodySmall)
            // Failed or stopped, it does not come back by itself: a way back
            // to the login form, without restarting the app (device report,
            // 2026-10-27: "disconnected ... without an option to re login").
            if (phase == LinkPhase.FAILED || phase == LinkPhase.STOPPED) {
                TextButton(onClick = { model.disconnect() }) { Text("Log in again") }
            }
        }
    }
}

@Composable
fun Notice(text: String, alarm: Boolean = false, onDismiss: () -> Unit) {
    Surface(color = if (alarm) MaterialTheme.colorScheme.errorContainer
                    else MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f).padding(vertical = 8.dp), style = MaterialTheme.typography.bodySmall,
                 color = if (alarm) MaterialTheme.colorScheme.onErrorContainer
                         else MaterialTheme.colorScheme.onPrimaryContainer)
            TextButton(onClick = onDismiss) { Text("Dismiss") }
        }
    }
}

@Composable
private fun ChatsPane(model: AppModel) {
    // Read here as well as in MainScreen: the open chat and the list are
    // plain fields, and Compose may skip this pane when MainScreen redraws,
    // which left a click on another chat doing nothing (owner, 2026-10-20).
    @Suppress("UNUSED_VARIABLE") val r = model.revision
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(320.dp).fillMaxHeight()) {
            Text("Chats", Modifier.padding(16.dp), style = MaterialTheme.typography.titleLarge,
                 fontWeight = FontWeight.SemiBold)
            val all = model.conversations()
            val kindOf = all.associate { it.jid to org.otrv4plus.android.chat.ChatKinds.kind(
                model.chat.isRoom(it.jid), model.chat.isSecureRoom(it.jid)) }
            val chips = org.otrv4plus.android.chat.ChatKinds.chips(kindOf.values.toList())
            var filterName by androidx.compose.runtime.saveable.rememberSaveable {
                androidx.compose.runtime.mutableStateOf(org.otrv4plus.android.chat.ChatKinds.Filter.ALL.name) }
            val filter = org.otrv4plus.android.chat.ChatKinds.Filter.valueOf(filterName).takeIf { it in chips }
                ?: org.otrv4plus.android.chat.ChatKinds.Filter.ALL
            val list = all.filter { filter.admits(kindOf.getValue(it.jid)) }
            if (chips.isNotEmpty()) {
                // Jump to one kind of chat (ChatKinds).
                Row(Modifier.fillMaxWidth()
                        .horizontalScroll(androidx.compose.foundation.rememberScrollState())
                        .padding(horizontal = 12.dp).padding(bottom = 6.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (chip in chips) {
                        androidx.compose.material3.FilterChip(
                            selected = chip == filter, onClick = { filterName = chip.name },
                            label = { Text(org.otrv4plus.android.chat.ChatKinds.chipLabel(chip, kindOf.values.toList())) })
                    }
                }
            }
            if (all.isEmpty()) {
                Text("No chats yet. Open People to start one.",
                     Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant,
                     style = MaterialTheme.typography.bodyMedium)
            }
            ScrollLazyColumn(Modifier.fillMaxSize()) {
                items(list, key = { it.jid }) { c ->
                    ConversationRow(model, c, kindOf.getValue(c.jid),
                                    selected = model.openConversation == c.jid)
                }
            }
        }
        VerticalDivider()
        Box(Modifier.fillMaxSize()) {
            val open = model.openConversation
            if (open == null) EmptyPane() else ConversationPane(model, open)
        }
    }
}

@Composable
private fun EmptyPane() {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center,
           horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(Icons.AutoMirrored.Filled.Chat, null, Modifier.size(56.dp),
             tint = MaterialTheme.colorScheme.outline)
        Spacer(Modifier.padding(6.dp))
        Text("Select a chat", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("Keys never leave the engine; this window only shows what it is told.",
             style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
    }
}

/** A round picture: the contact's avatar (built from engine-decoded pixels), or an initial. */
@Composable
fun Avatar(name: String, presence: Presence = Presence.UNKNOWN, size: Int = 40,
           image: androidx.compose.ui.graphics.ImageBitmap? = null) {
    Box {
        Box(Modifier.size(size.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center) {
            if (image != null) {
                androidx.compose.foundation.Image(image, null, Modifier.size(size.dp),
                    contentScale = androidx.compose.ui.layout.ContentScale.Crop)
            } else {
                Text(name.trim().take(1).uppercase().ifBlank { "?" },
                     color = MaterialTheme.colorScheme.onPrimaryContainer, fontWeight = FontWeight.Bold)
            }
        }
        if (presence == Presence.ONLINE) {
            Box(Modifier.align(Alignment.BottomEnd).size(12.dp).clip(CircleShape)
                .background(MaterialTheme.colorScheme.surface).padding(2.dp)) {
                Box(Modifier.fillMaxSize().clip(CircleShape).background(Color(0xFF4CAF50)))
            }
        }
    }
}

@Composable
private fun ConversationRow(model: AppModel, c: Conversation, kind: org.otrv4plus.android.chat.ChatKinds.Kind,
                            selected: Boolean) {
    // The kind's colour at 50% behind the row and a stripe down its left
    // edge (ChatKinds); the open chat gets a stronger stripe and an outline.
    val hue = Color(kind.hue)
    val outline = MaterialTheme.colorScheme.primary
    Row(Modifier.fillMaxWidth()
            .drawBehind {
                drawRect(hue.copy(alpha = org.otrv4plus.android.chat.ChatKinds.TINT))
                drawRect(hue, size = size.copy(width = (if (selected) 8 else 4).dp.toPx()))
                if (selected) drawRect(outline, style = androidx.compose.ui.graphics.drawscope.Stroke(2.dp.toPx()))
            }
            .clickable { model.open(c.jid) }
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Avatar(c.displayName.ifBlank { c.jid }, c.presence, image = model.avatar(c.jid))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(c.displayName.ifBlank { c.jid }, maxLines = 1, overflow = TextOverflow.Ellipsis,
                     fontWeight = if (c.unread > 0) FontWeight.Bold else FontWeight.Medium,
                     modifier = Modifier.weight(1f))
                if (model.chat.isRoom(c.jid)) {
                    Icon(Icons.Filled.Groups, "Room", Modifier.size(16.dp),
                         tint = MaterialTheme.colorScheme.outline)
                } else {
                    Icon(securityIcon(c.security), null, Modifier.size(16.dp), tint = securityColour(c.security))
                }
            }
            val badge = if (model.chat.isRoom(c.jid)) {
                if (model.chat.isSecureRoom(c.jid)) RowSecurity.group(model.chat.isSyncingRoom(c.jid)) else null
            } else RowSecurity.badge(c.security, c.smp, c.lastMessage != null)
            Text(c.preview.ifBlank { badge?.text ?: "" }, maxLines = 1, overflow = TextOverflow.Ellipsis,
                 style = MaterialTheme.typography.bodySmall,
                 color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(kind.label, style = MaterialTheme.typography.labelSmall,
                 color = MaterialTheme.colorScheme.onSurface)
        }
        if (c.unread > 0) {
            Spacer(Modifier.width(8.dp))
            Box(Modifier.clip(CircleShape).background(MaterialTheme.colorScheme.primary)
                    .padding(horizontal = 7.dp, vertical = 2.dp)) {
                Text("${c.unread}", color = MaterialTheme.colorScheme.onPrimary,
                     style = MaterialTheme.typography.labelSmall)
            }
        }
    }
    HorizontalDivider(Modifier.padding(start = 68.dp), color = MaterialTheme.colorScheme.surfaceVariant)
}
