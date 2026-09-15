// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.ui.AboutScreen
import org.otrv4plus.android.ui.ConnectScreen
import org.otrv4plus.android.ui.ConversationScreen
import org.otrv4plus.android.ui.ConversationsScreen
import org.otrv4plus.android.ui.DevShellScreen
import org.otrv4plus.android.ui.FingerprintAlertDialog

/**
 * Single Activity, Compose, unidirectional data flow.
 *
 * NAVIGATION
 * ----------
 * A saveable enum plus a saveable JID. Not a navigation library, and not an
 * object graph: everything in navigation state survives Activity recreation
 * because everything in it is a String.
 *
 *     Connect ──► Conversations ──► Conversation(jid)
 *                      │
 *                      ├──► About & licences
 *                      └──► Diagnostics
 *
 * Back unwinds that, which is what the system back button already means.
 *
 * WHAT IS NOT IN NAVIGATION STATE
 * -------------------------------
 * The core, the connection and the transport. Those belong to
 * [ConnectionViewModel], which is scoped to the Activity's retained instance
 * and therefore survives the recreation that discards this composition. An
 * earlier version put the `ChaquopyOtrCore` itself into a `remember`, so a
 * rotation during a tunnel build produced a second Python engine over the same
 * identity and trust files while the first kept its worker thread.
 *
 * There is no launcher disguise. One was specified and withdrawn on
 * 2026-09-14: Play's Deceptive Behavior policy forbids an app that
 * misrepresents its identity. The protection it was reaching for is unchanged
 * and lives where it belongs -- at rest, under AES-256-GCM, behind a password
 * or keyfile. See ANDROID_PHASE2_REPORT.md §15.7.
 */
class MainActivity : ComponentActivity() {

    private enum class Screen { CONNECT, CONVERSATIONS, CONVERSATION, ABOUT, DIAGNOSTICS }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // FLAG_SECURE from the start. The app must not appear in the recents
        // thumbnail or accept screenshots; setting it here means no later
        // screen can forget to.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        setContent {
            MaterialTheme {
                Surface {
                    val connection: ConnectionViewModel = viewModel()
                    val chat: ChatViewModel = viewModel()

                    var screen by rememberSaveable { mutableStateOf(Screen.CONNECT) }
                    // A JID, never a Conversation object. Stable, saveable, and
                    // still correct after the roster is refetched.
                    var openJid by rememberSaveable { mutableStateOf<String?>(null) }

                    // One place that hands the core over, and it is idempotent:
                    // a second attach with the same core is a no-op, so a
                    // recomposition cannot start a second polling loop draining
                    // the same event queue.
                    LaunchedEffect(connection.core) { chat.attach(connection.core) }

                    when (screen) {
                        Screen.ABOUT -> {
                            BackHandler { screen = Screen.CONVERSATIONS }
                            AboutScreen(onBack = { screen = Screen.CONVERSATIONS })
                        }

                        Screen.DIAGNOSTICS -> {
                            BackHandler { screen = Screen.CONVERSATIONS }
                            DevShellScreen()
                        }

                        Screen.CONVERSATION -> {
                            val jid = openJid
                            if (jid == null) {
                                // Defensive: a restored state with no JID is a
                                // list, not a blank conversation.
                                screen = Screen.CONVERSATIONS
                            } else {
                                BackHandler {
                                    chat.closeConversation()
                                    screen = Screen.CONVERSATIONS
                                }
                                LaunchedEffect(jid) { chat.open(jid) }
                                ConversationScreen(
                                    model = chat,
                                    jid = jid,
                                    onBack = {
                                        chat.closeConversation()
                                        screen = Screen.CONVERSATIONS
                                    },
                                )
                            }
                        }

                        Screen.CONVERSATIONS -> {
                            // Back from the list goes to the connection screen
                            // WITHOUT disconnecting: the core and its socket
                            // belong to the ViewModel and outlive this.
                            BackHandler { screen = Screen.CONNECT }
                            ConversationsScreen(
                                model = chat,
                                onOpen = { jid ->
                                    openJid = jid
                                    screen = Screen.CONVERSATION
                                },
                                onOpenConnection = { screen = Screen.CONNECT },
                                onOpenDiagnostics = { screen = Screen.DIAGNOSTICS },
                                onOpenAbout = { screen = Screen.ABOUT },
                            )
                        }

                        Screen.CONNECT -> ConnectScreen(
                            model = connection,
                            onOpenDiagnostics = { screen = Screen.DIAGNOSTICS },
                            onOpenAbout = { screen = Screen.ABOUT },
                            onConnected = { screen = Screen.CONVERSATIONS },
                        )
                    }

                    // Above every screen, because a changed pinned key is not
                    // news about one conversation -- it is a reason to stop.
                    // Rendered here rather than inside the chat screens so it
                    // cannot be missed by being on the wrong one.
                    chat.fingerprintAlert?.let { alert ->
                        FingerprintAlertDialog(
                            alert = alert,
                            onAcknowledge = { chat.dismissFingerprintAlert() },
                        )
                    }
                }
            }
        }
    }
}
