package org.otrv4plus.android.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.otrv4plus.android.BuildConfig
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.InitResult
import androidx.compose.ui.platform.LocalContext

/**
 * The Phase 2 development shell.
 *
 * Shows whether the stack came up, and nothing else. In a debug build it also
 * offers the diagnostics detail; in release, [BuildConfig.DEV_DIAGNOSTICS] is
 * false and the detail screen's source is not even compiled in (it lives in
 * src/debug/).
 */
@Composable
fun DevShellScreen() {
    val context = LocalContext.current
    var result by remember { mutableStateOf<InitResult?>(null) }
    var running by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        // Never on the main thread: interpreter start plus engine construction
        // is far too slow, and the engine expects a worker thread.
        result = withContext(Dispatchers.IO) { ChaquopyOtrCore(context).initialize() }
        running = false
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("OTRv4+ integration shell", style = MaterialTheme.typography.headlineSmall)

        if (running) {
            CircularProgressIndicator()
            Text("Starting Python and loading the Rust core...")
            return@Column
        }

        val r = result
        if (r == null) {
            Text("Initialization produced no result.")
            return@Column
        }

        StatusRow("Overall", if (r.ok) "OK" else "FAILED")
        StatusRow("Python", r.pythonVersion.ifBlank { "unknown" })
        StatusRow("ABI", r.abi)
        StatusRow("Rust core loaded", r.rustCoreLoaded.toString())
        StatusRow("Engine initialized", r.engineInitialized.toString())
        r.failureCode?.let { StatusRow("Failure", it) }

        // The detail, and the way to get it off the device.
        //
        // This screen sets FLAG_SECURE, so it cannot be screenshotted -- which
        // is correct for a messenger and stays. The first person to run this
        // app therefore had a failure they could see and could not report.
        // Copying the report to the clipboard solves that without weakening
        // the screenshot protection at all, and text pastes better than a
        // photograph anyway.
        if (!r.ok) {
            r.failureDetail?.let {
                Spacer(Modifier.height(4.dp))
                Text("Detail", style = MaterialTheme.typography.titleSmall)
                SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
            r.failureFrames?.let {
                Spacer(Modifier.height(4.dp))
                Text("Where", style = MaterialTheme.typography.titleSmall)
                SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall) }
            }

            val clipboard = LocalClipboardManager.current
            var copied by remember { mutableStateOf(false) }
            Spacer(Modifier.height(8.dp))
            Button(onClick = {
                clipboard.setText(AnnotatedString(reportText(r)))
                copied = true
            }) {
                Text(if (copied) "Copied — paste it into the bug report" else "Copy report")
            }
        }

        if (BuildConfig.DEV_DIAGNOSTICS) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Debug build: full diagnostics available. " +
                    "This panel is absent from release builds.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/**
 * The whole report as one pasteable block.
 *
 * Built from [InitResult] only, so it carries exactly what the screen shows
 * and cannot acquire a field that was never rendered.
 */
private fun reportText(r: InitResult): String = buildString {
    appendLine("OTRv4+ Android start-up report")
    appendLine("overall: ${if (r.ok) "OK" else "FAILED"}")
    appendLine("python: ${r.pythonVersion.ifBlank { "unknown" }}")
    appendLine("abi: ${r.abi}")
    appendLine("rust core loaded: ${r.rustCoreLoaded}")
    appendLine("engine initialized: ${r.engineInitialized}")
    r.failureCode?.let { appendLine("failure: $it") }
    r.failureDetail?.let { appendLine("detail: $it") }
    r.failureFrames?.let { appendLine("where:"); appendLine(it) }
}

@Composable
private fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
