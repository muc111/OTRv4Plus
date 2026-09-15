package org.otrv4plus.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.activity.compose.BackHandler
import org.otrv4plus.android.bridge.ChaquopyOtrCore
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
                    var showDiagnostics by remember { mutableStateOf(false) }
                    var showAbout by remember { mutableStateOf(false) }
                    var chatCore by remember {
                        mutableStateOf<ChaquopyOtrCore?>(null)
                    }

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

                        chatCore != null -> {
                            // Back returns to the connection screen without
                            // disconnecting: the core, and the socket it owns,
                            // outlive this composition.
                            BackHandler { chatCore = null }
                            ChatScreen(
                                core = chatCore!!,
                                onOpenDiagnostics = { showDiagnostics = true },
                                onOpenAbout = { showAbout = true },
                            )
                        }

                        else -> ConnectScreen(
                            onOpenDiagnostics = { showDiagnostics = true },
                            onOpenAbout = { showAbout = true },
                            onConnected = { chatCore = it },
                        )
                    }
                }
            }
        }
    }
}
