// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.chat.ChatViewModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import org.otrv4plus.android.ui.AboutScreen
import org.otrv4plus.android.ui.ArrivalPromptDialog
import org.otrv4plus.android.ui.ChangePasswordSection
import org.otrv4plus.android.ui.EntryRequestPrompt
import org.otrv4plus.android.ui.OtrTheme
import org.otrv4plus.android.ui.ThemeStore
import org.otrv4plus.android.ui.ConnectScreen
import org.otrv4plus.android.ui.ConversationScreen
import org.otrv4plus.android.ui.ConversationsScreen
import org.otrv4plus.android.ui.MainTab
import org.otrv4plus.android.ui.MainTabs
import org.otrv4plus.android.ui.DevShellScreen
import org.otrv4plus.android.ui.PeopleScreen
import org.otrv4plus.android.ui.ProfileScreen
import org.otrv4plus.android.ui.RoomsScreen
import org.otrv4plus.android.ui.FingerprintAlertDialog
import org.otrv4plus.android.ui.IncomingFileDialog
import org.otrv4plus.android.security.WipeAndExit

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
 * or keyfile. See docs/ANDROID_PHASE2_REPORT.md §15.7.
 */
class MainActivity : ComponentActivity() {

    private enum class Screen { CONNECT, CONVERSATIONS, CONVERSATION, ROOMS, PEOPLE, ABOUT, DIAGNOSTICS, PROFILE }

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
    /**
     * Bumped on every tap of the message notification. AppRoot reacts by
     * showing the chat list and asking whose message to open, never by
     * opening a conversation itself ([org.otrv4plus.android.chat.ArrivalPrompt]).
     */
    private var arrivalTaps by mutableStateOf(0)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == ACTION_OPEN_ARRIVAL) arrivalTaps++
    }

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

        // Reopened while Wipe & Exit is still ending calls and closing the
        // tunnel. The process is alive for those seconds, and a screen built
        // now would render whatever it could still reach. Nothing is shown;
        // the process ends when the wipe does.
        if (WipeAndExit.inProgress) {
            finishAndRemoveTask()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        // ONE MECHANISM FOR THE KEYBOARD, ON EVERY API LEVEL.
        //
        // The chat history collapsed into a strip at the top of the screen as
        // soon as the input was focused, and the cause was the keyboard being
        // subtracted twice.
        //
        // `targetSdk` is 35, where Android enforces edge-to-edge and the
        // window no longer resizes for the IME — so `Modifier.imePadding()` is
        // the right and necessary tool. But `minSdk` is 26, and on Android 14
        // and earlier the theme here (`Theme.Material.Light.NoActionBar`) gets
        // the platform default of `adjustResize`: the WINDOW shrinks by the
        // keyboard height, and then `imePadding()` subtracted that same height
        // AGAIN from a window that had already lost it. Two subtractions plus
        // the composer left the message list a sliver.
        //
        // Turning decor fitting off makes the modern behaviour the behaviour
        // everywhere: the window keeps its full height, the insets are
        // reported, and Compose applies them exactly once. It is also what
        // `enableEdgeToEdge()` does underneath, without the dependency.
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // FLAG_SECURE from the start. The app must not appear in the recents
        // thumbnail or accept screenshots; setting it here means no later
        // screen can forget to.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        // A tap that started the Activity; a recreation (rotation) is not
        // a second tap.
        if (savedInstanceState == null && intent?.action == ACTION_OPEN_ARRIVAL) arrivalTaps++

        setContent {
            AppRoot()
        }
    }

    /** Theme, navigation state and the screen being shown; dialogs that
     *  must not depend on which screen is open are drawn over all of them. */
    @Composable
    private fun AppRoot() {
        // Dark purple by default; the user's choice, once made, persists
        // (ThemeStore: ordinary preferences, not secret).
        var themeMode by remember { mutableStateOf(ThemeStore.load(this)) }
        OtrTheme(themeMode) {
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
                // Whose profile the Profile screen shows; blank = ours.
                var profileOf by rememberSaveable { mutableStateOf("") }
                // Where a contact's profile goes back to: their chat, or
                // the chat list when opened from a picture there.
                var profileBack by rememberSaveable { mutableStateOf(Screen.CONVERSATION) }
                // The tab a conversation was opened from, so leaving the
                // conversation goes back there (Chats, People or Rooms).
                var lastTab by rememberSaveable { mutableStateOf(Screen.CONVERSATIONS) }

                // The bottom navigation, on the four top-level screens only.
                fun selectTab(tab: MainTab) {
                    val target = when (tab) {
                        MainTab.CHATS -> Screen.CONVERSATIONS
                        MainTab.PEOPLE -> Screen.PEOPLE
                        MainTab.ROOMS -> Screen.ROOMS
                        MainTab.PROFILE -> { profileOf = ""; Screen.PROFILE }
                    }
                    lastTab = target
                    screen = target
                }
                fun openChat(jid: String) {
                    connection.arrivalAnswered(jid)
                    openJid = jid
                    screen = Screen.CONVERSATION
                }
                fun openProfile(jid: String, back: Screen) {
                    profileOf = jid
                    profileBack = back
                    screen = Screen.PROFILE
                }

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

                // A message notification was tapped. Never straight into a
                // conversation: back to the chat list, then ask about the
                // most recent sender. The service may still be binding after
                // a cold start, so wait briefly for it.
                var askAbout by remember { mutableStateOf<String?>(null) }
                LaunchedEffect(arrivalTaps) {
                    if (arrivalTaps == 0) return@LaunchedEffect
                    if (screen != Screen.CONNECT) {
                        if (screen == Screen.CONVERSATION) chat.closeConversation()
                        lastTab = Screen.CONVERSATIONS
                        screen = Screen.CONVERSATIONS
                    }
                    withTimeoutOrNull(5_000) { snapshotFlow { connection.core }.first { it != null } }
                    askAbout = connection.nextArrival()
                }

                LaunchedEffect(connection.core, connection.chat) {
                    val core = connection.core
                    val state = connection.chat
                    if (core != null && state != null) {
                        chat.attach(core, state)
                        val (typing, read) = org.otrv4plus.android.ui.PrivacyStore.load(this@MainActivity)
                        chat.setPrivacy(typing, read)
                    }
                }

                when (screen) {
                    Screen.PROFILE -> ProfileRoute(chat, profileOf, back = { screen = profileBack },
                                                   selectTab = ::selectTab, openChat = ::openChat)

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
                            ConversationRoute(chat, jid,
                                back = { chat.closeConversation(); screen = lastTab },
                                openProfile = ::openProfile, openChat = ::openChat)
                        }
                    }

                    Screen.CONVERSATIONS -> ChatsRoute(chat, ::selectTab, ::openChat, go = { screen = it },
                        openProfile = ::openProfile, theme = themeMode,
                        onTheme = { mode -> themeMode = mode; ThemeStore.save(this@MainActivity, mode) })

                    Screen.PEOPLE -> {
                        BackHandler { selectTab(MainTab.CHATS) }
                        MainTabs(MainTab.PEOPLE, chat, ::selectTab) {
                            PeopleScreen(
                                model = chat,
                                onBack = { selectTab(MainTab.CHATS) },
                                onOpenChat = ::openChat,
                                onOpenProfile = { who -> openProfile(who, Screen.PEOPLE) },
                                showBack = false,
                            )
                        }
                    }

                    Screen.ROOMS -> RoomsRoute(chat, roomsModel, ::selectTab, ::openChat)

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

                // The incoming-file prompt, here for the same reason: an
                // offer waits on the user whichever screen is open. The
                // fingerprint alert goes first; a changed key is not the
                // moment to accept a file.
                if (chat.fingerprintAlert == null) IncomingFileDialog(chat)

                EntryRequestPrompt(chat, shown = screen != Screen.CONNECT && chat.fingerprintAlert == null)

                // Whose message is waiting, asked only once signed in and
                // with no key-change alert in front of it.
                val who = askAbout
                if (who != null && screen != Screen.CONNECT && chat.fingerprintAlert == null) {
                    ArrivalPromptDialog(
                        name = chat.conversation(who).displayName,
                        onView = { askAbout = null; openChat(who) },
                        onNotNow = {
                            connection.arrivalAnswered(who)
                            askAbout = connection.nextArrival()
                        },
                    )
                }
            }
        }
    }

    /** Our own profile (a tab) or a contact's (full screen, back to where it came from). */
    @Composable
    private fun ProfileRoute(chat: ChatViewModel, profileOf: String, back: () -> Unit,
                             selectTab: (MainTab) -> Unit, openChat: (String) -> Unit) {
        // Our own profile is a tab (bottom bar, back to
        // Chats); a contact's is opened from their
        // conversation and goes back to it, full screen.
        if (profileOf.isBlank()) {
            BackHandler { selectTab(MainTab.CHATS) }
            MainTabs(MainTab.PROFILE, chat, selectTab) {
                ProfileScreen(
                    model = chat,
                    ownJid = connection.status.jid,
                    jid = "",
                    onBack = { selectTab(MainTab.CHATS) },
                    showBack = false,
                    account = { ChangePasswordSection(connection) },
                )
            }
        } else {
            BackHandler { back() }
            ProfileScreen(
                model = chat,
                ownJid = connection.status.jid,
                jid = profileOf,
                onBack = { back() },
                // The chat, with the verification prompt
                // open: the one place SMP runs.
                onVerify = { who ->
                    chat.requestVerification(who)
                    openChat(who)
                },
            )
        }
    }

    /** One conversation: no bottom bar, Back returns to the tab it came from. */
    @Composable
    private fun ConversationRoute(chat: ChatViewModel, jid: String, back: () -> Unit,
                                  openProfile: (String, Screen) -> Unit, openChat: (String) -> Unit) {
        // No bottom bar in a conversation: the history
        // and the keyboard get the whole height. Back
        // returns to the tab it was opened from.
        BackHandler { back() }
        LaunchedEffect(jid) { chat.open(jid) }
        ConversationScreen(
            model = chat,
            jid = jid,
            onBack = { back() },
            onOpenProfile = { who -> openProfile(who, Screen.CONVERSATION) },
            onOpenChat = { who ->
                chat.closeConversation()
                openChat(who)
            },
        )
    }

    /** The chat list, as the Chats tab. Back goes to the connection screen without disconnecting. */
    @Composable
    private fun ChatsRoute(chat: ChatViewModel, selectTab: (MainTab) -> Unit, openChat: (String) -> Unit,
                           go: (Screen) -> Unit, openProfile: (String, Screen) -> Unit,
                           theme: org.otrv4plus.android.theme.ThemeTokens.Mode,
                           onTheme: (org.otrv4plus.android.theme.ThemeTokens.Mode) -> Unit) {
        // Back from the list goes to the connection screen
        // WITHOUT disconnecting: the core and its socket
        // belong to the ViewModel and outlive this.
        BackHandler { go(Screen.CONNECT) }
        MainTabs(MainTab.CHATS, chat, selectTab) {
            ConversationsScreen(
                model = chat,
                onOpen = openChat,
                onOpenConnection = { go(Screen.CONNECT) },
                onOpenRooms = { selectTab(MainTab.ROOMS) },
                onOpenPeople = { selectTab(MainTab.PEOPLE) },
                onOpenDiagnostics = { go(Screen.DIAGNOSTICS) },
                onOpenAbout = { go(Screen.ABOUT) },
                onOpenProfile = { selectTab(MainTab.PROFILE) },
                onOpenContactProfile = { who -> openProfile(who, Screen.CONVERSATIONS) },
                onWipeAndExit = { deleteAccount -> connection.wipeAndExit(deleteAccount) },
                theme = theme,
                onTheme = onTheme,
            )
        }
    }

    /** The Rooms tab; a room the server confirmed opens as a chat. */
    @Composable
    private fun RoomsRoute(chat: ChatViewModel, roomsModel: RoomsViewModel,
                           selectTab: (MainTab) -> Unit, openChat: (String) -> Unit) {
        BackHandler { selectTab(MainTab.CHATS) }
        MainTabs(MainTab.ROOMS, chat, selectTab) {
            RoomsScreen(
                model = roomsModel,
                // Seeded from the account's localpart, which
                // is what people pick anyway. Editable: a
                // nickname in a room is not an identity claim
                // and the app should not imply it is.
                defaultNick = connection.status.jid
                    .substringBefore('@'),
                onBack = { selectTab(MainTab.CHATS) },
                showBack = false,
                // Only fires once the server has confirmed the
                // join or create. Previously nothing carried
                // that outcome anywhere, so a successful
                // create left the user on the Rooms screen
                // with no way to reach the room it had just
                // made -- reported as "it never progresses to
                // the next view".
                onOpenRoom = { room ->
                    // A room from here on: group chat, not
                    // an OTR conversation with the room JID.
                    chat.noteRoom(room)
                    openChat(room)
                },
            )
        }
    }

    companion object {
        /** The message notification's tap; the intent names nobody. */
        const val ACTION_OPEN_ARRIVAL = "org.otrv4plus.android.OPEN_ARRIVAL"
    }
}
