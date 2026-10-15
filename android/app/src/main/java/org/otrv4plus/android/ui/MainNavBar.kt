// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.chat.OnlineUsers

/** The four top-level places, one tap each. */
enum class MainTab { CHATS, PEOPLE, ROOMS, PROFILE }

/**
 * A top-level screen with the bottom navigation under it.
 *
 * Shown on the four tabs once signed in, and NOWHERE ELSE: inside a
 * conversation the history and the keyboard get the whole height (back
 * returns to the tab it was opened from), and secondary screens -- a
 * contact's profile, About, Debug, sign-in -- are reached from a tab and go
 * back to it.
 *
 * The bar takes the navigation-bar inset itself; it is consumed here, so the
 * screen above (with its own Scaffold or insets) does not add it again.
 */
@Composable
fun MainTabs(
    current: MainTab,
    model: ChatViewModel,
    onSelect: (MainTab) -> Unit,
    content: @Composable () -> Unit,
) {
    Scaffold(
        bottomBar = { MainNavBar(current, model, onSelect) },
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)
                .consumeWindowInsets(WindowInsets.navigationBars)) {
            content()
        }
    }
}

/** Text glyphs rather than icon fonts: this app ships no icon library. */
@Composable
fun MainNavBar(current: MainTab, model: ChatViewModel, onSelect: (MainTab) -> Unit) {
    NavigationBar {
        NavigationBarItem(
            selected = current == MainTab.CHATS, onClick = { onSelect(MainTab.CHATS) },
            icon = {
                val unread = model.conversations().sumOf { it.unread }
                if (unread > 0) BadgedBox(badge = { Badge { Text(if (unread > 99) "99+" else "$unread") } }) {
                    Text("💬")
                } else Text("💬")
            },
            label = { Text("Chats") },
        )
        NavigationBarItem(
            selected = current == MainTab.PEOPLE, onClick = { onSelect(MainTab.PEOPLE) },
            icon = {
                val waiting = model.pendingSubscriptions.size
                if (waiting > 0) BadgedBox(badge = { Badge { Text("$waiting") } }) { Text("👥") }
                else Text("👥")
            },
            label = { Text(if (model.canSend()) OnlineUsers.peopleButton(model.directory) else "People",
                           maxLines = 1, overflow = TextOverflow.Ellipsis) },
        )
        NavigationBarItem(
            selected = current == MainTab.ROOMS, onClick = { onSelect(MainTab.ROOMS) },
            icon = {
                val invites = model.groupInvites().size
                if (invites > 0) BadgedBox(badge = { Badge { Text("$invites") } }) { Text("#") }
                else Text("#")
            },
            label = { Text("Rooms") },
        )
        NavigationBarItem(
            selected = current == MainTab.PROFILE, onClick = { onSelect(MainTab.PROFILE) },
            icon = { Text("👤") }, label = { Text("Profile") },
        )
    }
}
