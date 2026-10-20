// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import org.otrv4plus.desktop.engine.DesktopCore
import org.otrv4plus.desktop.engine.Engine
import org.otrv4plus.desktop.ui.ConnectScreen
import org.otrv4plus.desktop.ui.MainScreen
import org.otrv4plus.desktop.ui.OtrTheme
import kotlin.system.exitProcess

fun main() = application {
    val model = remember {
        var core: DesktopCore? = null
        val (engine, process) = Engine.launch(onEvent = { core?.deliver(it) })
        Runtime.getRuntime().addShutdownHook(Thread { runCatching { process.destroy() } })
        core = DesktopCore(engine)
        AppModel(core).also { it.start() }
    }
    Window(
        onCloseRequest = { model.shutdown(); exitApplication() },
        // The version from the jar's manifest (desktop/build.gradle.kts);
        // absent when run from classes, as in tests.
        title = "Off The Record v4 Plus" +
            (AppModel::class.java.`package`?.implementationVersion?.let { " $it" } ?: ""),
        state = rememberWindowState(size = DpSize(1180.dp, 780.dp)),
        icon = remember { appIcon() },
    ) {
        DisposableEffect(Unit) { onDispose { model.shutdown() } }
        // Notifications for messages only while the window is not in front.
        val focused = androidx.compose.ui.platform.LocalWindowInfo.current.isWindowFocused
        androidx.compose.runtime.LaunchedEffect(focused) { model.setUiVisible(focused) }
        App(model, onWipe = { model.wipeAndExit { exitProcess(0) } })
    }
}

/** The app's icon (the Android launcher icon, put in the jar by the build),
 *  or none: a missing icon must not stop the app starting. */
private fun appIcon(): androidx.compose.ui.graphics.painter.Painter? = runCatching {
    AppModel::class.java.getResourceAsStream("/otrv4plus.png")?.use { stream ->
        androidx.compose.ui.graphics.painter.BitmapPainter(
            org.jetbrains.skia.Image.makeFromEncoded(stream.readBytes()).toComposeImageBitmap())
    }
}.getOrNull()

@Composable
fun App(model: AppModel, onWipe: () -> Unit) {
    OtrTheme(model.theme) {
        // A Surface, not a background: it also sets the content colour, so
        // text outside a Material component is onBackground, not black.
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            when (model.screen) {
                AppModel.Screen.STARTING -> Centered {
                    CircularProgressIndicator()
                    Text("Starting the engine…", Modifier.padding(top = 16.dp))
                }
                AppModel.Screen.FAILED -> Centered {
                    Text("The engine did not start (${model.startupFailure}).",
                         color = MaterialTheme.colorScheme.error)
                    Text("Run `otrv4plus` in a terminal to see why.", Modifier.padding(top = 8.dp))
                }
                AppModel.Screen.WIPED -> Centered { Text("Wiped.") }
                AppModel.Screen.CONNECT -> ConnectScreen(model)
                AppModel.Screen.MAIN -> MainScreen(model, onWipe)
            }
        }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center,
           horizontalAlignment = Alignment.CenterHorizontally) { content() }
}
