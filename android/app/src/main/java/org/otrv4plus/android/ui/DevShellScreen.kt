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
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

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
            var exportError by remember { mutableStateOf<String?>(null) }

            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                // Export to a file and hand it to whatever app the user picks.
                // A 50-line report does not survive being retyped from a photo,
                // and this screen sets FLAG_SECURE so there is no photo to take.
                Button(onClick = {
                    exportError = try {
                        shareReport(context, fullReport(r)); null
                    } catch (t: Throwable) {
                        t.javaClass.simpleName
                    }
                }) { Text("Export report") }

                OutlinedButton(onClick = {
                    clipboard.setText(AnnotatedString(fullReport(r)))
                    copied = true
                }) { Text(if (copied) "Copied" else "Copy") }
            }
            exportError?.let {
                Text("Export failed ($it) — use Copy instead.",
                    style = MaterialTheme.typography.bodySmall)
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
private fun fullReport(r: InitResult): String = buildString {
    appendLine("OTRv4+ Android start-up report")
    appendLine("overall: ${if (r.ok) "OK" else "FAILED"}")
    appendLine("python: ${r.pythonVersion.ifBlank { "unknown" }}")
    appendLine("abi: ${r.abi}")
    appendLine("rust core loaded: ${r.rustCoreLoaded}")
    appendLine("engine initialized: ${r.engineInitialized}")
    r.failureCode?.let { appendLine("failure: $it") }
    r.failureDetail?.let { appendLine("detail: $it") }
    r.failureFrames?.let { appendLine("where:"); appendLine(it) }
    // The full diagnostic report, rendered by android_bridge.diagnostics,
    // which is where the redaction rule lives. Appended rather than
    // reformatted: this file must not become a second place that decides what
    // a diagnostic may contain.
    r.diagnosticsText?.let { appendLine(); appendLine(it) }
}

/**
 * Write the report to the cache and offer it to another app.
 *
 * Via FileProvider, so what leaves is a one-shot read grant for exactly this
 * file. The app holds no storage permission and this adds none.
 */
private fun shareReport(context: Context, text: String) {
    val dir = File(context.cacheDir, "diagnostics").apply { mkdirs() }
    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    val file = File(dir, "otrv4plus-report-$stamp.txt")
    file.writeText(text)

    val uri = FileProvider.getUriForFile(
        context, "${context.packageName}.diagnostics", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_SUBJECT, "OTRv4+ Android diagnostic report")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, "Export diagnostic report"))
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
