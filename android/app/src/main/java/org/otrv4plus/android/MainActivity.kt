package org.otrv4plus.android

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import org.otrv4plus.android.ui.DevShellScreen

/**
 * Single Activity, Compose, unidirectional data flow.
 *
 * Phase 2 scope only: this hosts a development shell that proves the
 * Kotlin -> Chaquopy -> Python -> Rust path works on a real device. The
 * calculator disguise, the unlock flow and every real screen are later phases
 * and are deliberately absent.
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
                Surface { DevShellScreen() }
            }
        }
    }
}
