package org.otrv4plus.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.lifecycle.viewmodel.compose.viewModel
import org.otrv4plus.android.ui.AboutScreen
import org.otrv4plus.android.ui.ChatScreen
import org.otrv4plus.android.ui.ConnectScreen
import org.otrv4plus.android.ui.DevShellScreen

/**
 * Single Activity, Compose, unidirectional data flow.
 *
 * Phase 2 scope only: this hosts a development shell that proves the
 * Kotlin -> Chaquopy -> Python -> Rust path works on a real device -- which it
 * now has, on a handset. The real screens are Phase 3 and are being built.
 *
 * There is no launcher disguise. One was specified (a working calculator as the
 * icon and first screen) and withdrawn on 2026-09-14: Play's Deceptive Behavior
 * policy forbids an app that misrepresents its identity, and a store listing
 * that says "calculator" over a messenger is what that policy describes. The
 * protection it was reaching for is unchanged and lives where it belongs -- at
 * rest, under AES-256-GCM, behind a password or keyfile. See
 * ANDROID_PHASE2_REPORT.md §15.7.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // FLAG_SECURE from the start. The finished app must not appear in the
        // recents thumbnail or accept screenshots once past the unlock screen;
        // setting it now means no later screen can forget to.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )

        setContent {
            MaterialTheme {
                Surface {
                    // Four destinations, still no navigation library. The
                    // chat screen manages contacts-versus-conversation
                    // internally, so this is a small enum rather than a graph;
                    // navigation-compose earns its place when a deep link or a
                    // back stack that outlives the process does.
                    //
                    // rememberSaveable, not remember: these decide which
                    // screen you are looking at, and losing them on a rotation
                    // throws a connected user back to the connect screen. The
                    // connection itself is unaffected -- the ViewModel holds
                    // it -- but being bounced out of a conversation because
                    // the phone turned is the kind of thing that reads as the
                    // app having crashed.
                    val model: ConnectionViewModel = viewModel()
                    var showDiagnostics by rememberSaveable { mutableStateOf(false) }
                    var showAbout by rememberSaveable { mutableStateOf(false) }
                    // A Boolean rather than the core itself. The core is not
                    // Saveable -- it owns a Python interpreter -- and it does
                    // not need to be: the ViewModel already survives
                    // recreation, so this only has to remember WHICH screen,
                    // not which object.
                    var inChat by rememberSaveable { mutableStateOf(false) }

                    when {
                        // Checked before the others so it is reachable from
                        // every screen: the third-party notices are a
                        // distribution obligation, not a feature that may be
                        // unreachable in some state.
                        showAbout -> {
                            BackHandler { showAbout = false }
                            AboutScreen(onBack = { showAbout = false })
                        }

                        showDiagnostics -> {
                            BackHandler { showDiagnostics = false }
                            DevShellScreen()
                        }

                        inChat -> {
                            // Back returns to the connection screen without
                            // disconnecting: the core, and the socket it owns,
                            // belong to the ViewModel and outlive both.
                            BackHandler { inChat = false }
                            ChatScreen(
                                core = model.core,
                                onOpenDiagnostics = { showDiagnostics = true },
                                onOpenAbout = { showAbout = true },
                            )
                        }

                        else -> ConnectScreen(
                            // The same ViewModel instance the chat screen
                            // reads its core from, resolved against this
                            // Activity, so the connection survives a rotation
                            // instead of being rebuilt alongside a second
                            // Python engine.
                            model = model,
                            onOpenDiagnostics = { showDiagnostics = true },
                            onOpenAbout = { showAbout = true },
                            onConnected = { inChat = true },
                        )
                    }
                }
            }
        }
    }
}
