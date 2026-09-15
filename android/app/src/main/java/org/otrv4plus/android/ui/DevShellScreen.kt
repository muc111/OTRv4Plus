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
fun DevShellScreen(core: ChaquopyOtrCore? = null) {
    val context = LocalContext.current
    var result by remember { mutableStateOf<InitResult?>(null) }
    var running by remember { mutableStateOf(true) }

    // THE SERVICE'S CORE, never a new one.
    //
    // This used to do `ChaquopyOtrCore(context).initialize()`, which built a
    // SECOND Python interpreter and a second engine over the same identity and
    // trust files -- from the diagnostics screen, whose whole job is to tell
    // you whether the first one is healthy. Opening it while connected was
    // enough to have two engines writing the same records.
    LaunchedEffect(core) {
        if (core == null) {
            running = false
            return@LaunchedEffect
        }
        // Never on the main thread: interpreter start plus engine construction
        // is far too slow, and the engine expects a worker thread. Idempotent
        // on an already-started core.
        result = withContext(Dispatchers.IO) {
            runCatching { core.initialize() }.getOrNull()
        }
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

        StatusRow("Build", BuildConfig.BUILD_ID)
        StatusRow("Overall", if (r.ok) "OK" else "FAILED")
        StatusRow("Python", r.pythonVersion.ifBlank { "unknown" })
        StatusRow("ABI", r.abi)
        StatusRow("Rust core loaded", r.rustCoreLoaded.toString())
        StatusRow("Engine initialized", r.engineInitialized.toString())
        r.failureCode?.let { StatusRow("Failure", it) }

        // Failure detail, when there is one. Null on a healthy start, so these
        // simply do not render rather than needing a guard.
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

        // ALWAYS offered, success or failure.
        //
        // These used to sit inside `if (!r.ok)`, on the assumption that a
        // report is something you need when things break. That was wrong in
        // the way that matters: the first time the stack came up green, the
        // buttons vanished, FLAG_SECURE blocked a screenshot, and there was no
        // way to get the good news off the device at all.
        //
        // A working run is evidence too -- the Python version, the ABI, the
        // Rust core's symbol count and the self-test results are exactly what
        // closes the device gates in ANDROID_PHASE2_REPORT.md §14, and they
        // are only worth collecting if they can be sent.
        val clipboard = LocalClipboardManager.current
        var copied by remember { mutableStateOf(false) }
        var exportError by remember { mutableStateOf<String?>(null) }

        Spacer(Modifier.height(8.dp))

        // THE ERROR LOG, which is the one that diagnoses a live fault.
        //
        // The start-up report below is a snapshot taken at launch: versions,
        // ABI, whether the Rust core loaded. Useful, and useless for "it was
        // connected and then it said DISCONNECTING", because by then the
        // snapshot is minutes old and contains none of what happened since.
        //
        // This one is the event trace: every state change, presence event,
        // roster call, keepalive probe and exception, in order, with the
        // connection's current state on top. The run-up to a failure is
        // usually the whole answer.
        Text("Error log", style = MaterialTheme.typography.titleSmall)
        Text(
            "Everything the connection did, in order. No passwords, keys or "
            + "message contents — see the top of the file.",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                exportError = try {
                    // Rendered in Python, where the redaction rule lives.
                    // Off the main thread would be tidier, but this is a
                    // string build over an in-memory ring and the alternative
                    // is a button that does nothing for a frame.
                    DiagnosticsExport.share(
                        context,
                        core?.diagnosticReport() ?: NO_CORE,
                        prefix = "otrv4plus-log",
                        subject = "OTRv4+ error log",
                        chooserTitle = "Share error log",
                    )
                    null
                } catch (t: Throwable) {
                    t.javaClass.simpleName
                }
            }) { Text("Share error log") }

            OutlinedButton(onClick = {
                clipboard.setText(
                    AnnotatedString(core?.diagnosticSummary() ?: NO_CORE))
                copied = true
            }) { Text(if (copied) "Copied" else "Copy error details") }
        }
        exportError?.let {
            Text("Share failed ($it) — use Copy instead.",
                style = MaterialTheme.typography.bodySmall)
        }

        Spacer(Modifier.height(16.dp))

        // The start-up snapshot, kept: it is what closes the environment
        // gates in ANDROID_PHASE2_REPORT.md §14, and a working run is
        // evidence too. FLAG_SECURE blocks a screenshot, so if it cannot be
        // exported it cannot leave the device at all.
        Text("Start-up report", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                exportError = try {
                    DiagnosticsExport.share(
                        context, fullReport(r),
                        prefix = "otrv4plus-startup",
                        subject = "OTRv4+ start-up report",
                        chooserTitle = "Export start-up report",
                    )
                    null
                } catch (t: Throwable) {
                    t.javaClass.simpleName
                }
            }) { Text("Export start-up report") }

            // Copy, still offered, and not a duplicate of the one above:
            // this is the fallback for when no app answers the share intent.
            // Dropping it in favour of the error-log pair was a regression --
            // a device with no mail or notes app installed would have had no
            // way to produce a start-up report at all, and FLAG_SECURE means
            // there is no screenshot either.
            OutlinedButton(onClick = {
                clipboard.setText(AnnotatedString(fullReport(r)))
                copied = true
            }) { Text(if (copied) "Copied" else "Copy") }
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
    // First line after the title, because it is the first question asked of
    // any report: is this the build that was meant to be under test?
    appendLine("build: ${BuildConfig.BUILD_ID} (${BuildConfig.VERSION_NAME})")
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

/** Shown when the screen is reached before the service has a core. */
private const val NO_CORE =
    "No connection has been prepared in this session, so there is no " +
        "connection state or event history to report.\n"

/** Shared with [ConnectScreen]; `private` here would be file-private. */
@Composable
internal fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
