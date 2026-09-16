// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.ui.AboutScreen
import org.otrv4plus.android.ui.ConnectScreen
import org.otrv4plus.android.ui.ConversationScreen
import org.otrv4plus.android.ui.ConversationsScreen
import org.otrv4plus.android.ui.DevShellScreen
import org.otrv4plus.android.ui.RoomsScreen
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
 *     Log in ──► Conversations ──► Conversation(jid)
 *        │             │
 *        │             ├──► Rooms
 *        │             ├──► About & licences
 *        └─────────────┴──► Debug
 *
 * Back unwinds that, which is what the system back button already means.
 *
 * Debug hangs off BOTH, and its back goes to whichever the user came from.
 * It is reachable before anyone has signed in -- which is when a connection
 * problem is most likely -- and always returning to the conversation list sent
 * somebody who had not signed in yet to an empty screen with no way out.
 *
 * Rooms sit beside conversations rather than inside them. A room is group chat
 * and is not end-to-end encrypted; listing rooms among one-to-one
 * conversations would blur two things with different guarantees.
 *
 * WHAT IS NOT IN NAVIGATION STATE
 * -------------------------------
 * The core, the connection and the transport. Those belong to
 * `OtrConnectionService`, which outlives this Activity AND the process being
 * backgrounded; [ConnectionViewModel] merely binds to it and reads its state.
 *
 * Two earlier versions got this wrong in the same direction. The first put the
 * `ChaquopyOtrCore` in a `remember`, so a rotation during a tunnel build
 * produced a second Python engine over the same identity and trust files. The
 * second moved it to the ViewModel, which fixed rotation and not the real
 * problem: Android kills a backgrounded process with nothing holding it up, so
 * the connection died whenever the user looked at something else and every
 * message sent to them in between was lost.
 *
 * There is no launcher disguise. One was specified and withdrawn on
 * 2026-09-14: Play's Deceptive Behavior policy forbids an app that
 * misrepresents its identity. The protection it was reaching for is unchanged
 * and lives where it belongs -- at rest, under AES-256-GCM, behind a password
 * or keyfile. See ANDROID_PHASE2_REPORT.md §15.7.
 */
class MainActivity : ComponentActivity() {

    private enum class Screen { CONNECT, CONVERSATIONS, CONVERSATION, ROOMS, ABOUT, DIAGNOSTICS }

    /**
     * Asking for POST_NOTIFICATIONS, which on API 33+ is not optional.
     *
     * The manifest has declared it since the service was written, and a
     * declared-but-never-requested permission is DENIED: every notification is
     * dropped silently, including the foreground-service one. So on a modern
     * handset the connection would have been running with no visible
     * notification and no arrival alerts, and nothing would have said why.
     *
     * A refusal is not an error. The app works without it -- the connection
     * keeps running and messages keep arriving -- the user simply is not told
     * about them until they open it. So the result is deliberately discarded:
     * there is nothing to retry and nothing to nag about.
     */
    private val askNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    /**
     * The same [ConnectionViewModel] the composition uses.
     *
     * Obtained here as well because [onStart] and [onStop] are outside the
     * composition. `ViewModelProvider(this)` and Compose's `viewModel()` share
     * this Activity's `ViewModelStore`, so this is one object, not two.
     *
     * `ViewModelProvider` rather than the `by viewModels()` delegate: that
     * delegate lives in `activity-ktx`, which is only a transitive dependency
     * here, and this is the same object either way.
     */
    private val connection: ConnectionViewModel by lazy {
        ViewModelProvider(this)[ConnectionViewModel::class.java]
    }

    /**
     * Whether a screen is in front of the user.
     *
     * The service needs it to decide whether an arriving message is worth a
     * notification: a message that lands while the app is on screen is already
     * visible, and interrupting somebody about something they are looking at is
     * how people end up turning notifications off.
     *
     * ON_START/ON_STOP rather than the service binding. The binding is created
     * with the ViewModel and released in `onCleared`, so it stays up while the
     * app is backgrounded -- which is the one state this has to detect.
     */
    override fun onStart() {
        super.onStart()
        connection.setUiVisible(true)
    }

    override fun onStop() {
        connection.setUiVisible(false)
        super.onStop()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

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
                    // `connection` is the Activity's property above, not a
                    // second `viewModel()` call: one name for one object, so
                    // there is no doubt that onStart and the composition are
                    // talking to the same ViewModel. Its state fields are
                    // snapshot state, so reading them here still recomposes.
                    val chat: ChatViewModel = viewModel()
                    // Rooms are their own ViewModel rather than more fields
                    // on the connection's: discovery is two I2P round trips
                    // and its results outlive the screen, but none of it has
                    // anything to do with whether the link is up.
                    val roomsModel: RoomsViewModel = viewModel()
                    LaunchedEffect(connection.core) {
                        roomsModel.core = connection.core
                    }

                    var screen by rememberSaveable { mutableStateOf(Screen.CONNECT) }
                    // A JID, never a Conversation object. Stable, saveable, and
                    // still correct after the roster is refetched.
                    var openJid by rememberSaveable { mutableStateOf<String?>(null) }

                    // One place that hands the core over, and it is idempotent:
                    // a second attach with the same core is a no-op, so a
                    // recomposition cannot start a second polling loop draining
                    // the same event queue.
                    // Nullable now: the core lives in the service and there is
                    // a window before the binding lands. Re-keyed on it, so
                    // the chat attaches the moment it arrives and re-attaches
                    // if the service is ever rebound.
                    // A user who has signed in before should not be shown a
                    // login screen again just because the process restarted.
                    // Does nothing when nothing is remembered.
                    LaunchedEffect(Unit) { connection.resumeIfRemembered() }

                    LaunchedEffect(connection.core, connection.chat) {
                        val core = connection.core
                        val state = connection.chat
                        if (core != null && state != null) chat.attach(core, state)
                    }

                    when (screen) {
                        Screen.ABOUT -> {
                            BackHandler { screen = Screen.CONVERSATIONS }
                            AboutScreen(onBack = { screen = Screen.CONVERSATIONS })
                        }

                        Screen.DIAGNOSTICS -> {
                            // Back to where the user came from. Debug is
                            // reachable from the login screen as well as from
                            // the conversation list, and always returning to
                            // the list sent somebody who had not signed in yet
                            // to an empty screen they could not get out of.
                            val back = if (connection.status.connected)
                                Screen.CONVERSATIONS else Screen.CONNECT
                            BackHandler { screen = back }
                            DevShellScreen(
                                core = connection.core,
                                status = connection.status,
                                probe = connection.probe,
                                busy = connection.busy,
                                onCheckRouter = {
                                    connection.checkRouter(
                                        connection.status.jid)
                                },
                            )
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
                                onOpenRooms = { screen = Screen.ROOMS },
                                onOpenDiagnostics = { screen = Screen.DIAGNOSTICS },
                                onOpenAbout = { screen = Screen.ABOUT },
                            )
                        }

                        Screen.ROOMS -> {
                            BackHandler { screen = Screen.CONVERSATIONS }
                            RoomsScreen(
                                model = roomsModel,
                                // Seeded from the account's localpart, which
                                // is what people pick anyway. Editable: a
                                // nickname in a room is not an identity claim
                                // and the app should not imply it is.
                                defaultNick = connection.status.jid
                                    .substringBefore('@'),
                                onBack = { screen = Screen.CONVERSATIONS },
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
