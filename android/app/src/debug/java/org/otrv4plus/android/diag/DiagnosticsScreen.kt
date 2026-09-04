package org.otrv4plus.android.diag

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.chaquo.python.Python
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Full integration diagnostics -- DEBUG BUILDS ONLY.
 *
 * This file lives in `src/debug/`, so it is not compiled into a release APK at
 * all. That is stronger than hiding it behind a runtime flag: there is no code
 * path to reach, and nothing to re-enable by flipping a boolean.
 *
 * What it may show: Android version, ABI, Python version, whether the Rust
 * extension loaded, which required symbols are present, whether a live Rust
 * self-test passed, and a truncated public fingerprint prefix.
 *
 * What it must never show: private keys, seeds, passwords, session secrets,
 * ratchet state, or message plaintext. `android_bridge.diagnostics.collect()`
 * is responsible for never producing those, and
 * tests/test_android_diagnostics.py asserts it against real output -- including
 * a check that no long hex run appears anywhere in the report.
 */
@Composable
fun DiagnosticsScreen() {
    val context = LocalContext.current
    var lines by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(Unit) {
        lines = withContext(Dispatchers.IO) { collectDiagnostics() }
        loading = false
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text("Integration diagnostics", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Debug build only. Not present in release.",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(12.dp))

        if (loading) {
            CircularProgressIndicator()
        } else {
            lines.forEach { (key, value) ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(key, style = MaterialTheme.typography.bodySmall)
                    Text(value, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/** Flatten the Python report into displayable rows. Values are already safe. */
private fun collectDiagnostics(): List<Pair<String, String>> = try {
    val py = Python.getInstance()
    val report = py.getModule("android_bridge.diagnostics").callAttr("collect")
    val out = mutableListOf<Pair<String, String>>()
    for (group in listOf("python", "abi", "rust_core", "otrv4plus", "rust_selftest")) {
        val section = report.callAttr("get", group) ?: continue
        out += group to ""
        section.callAttr("items").asList().forEach { entry ->
            val pair = entry.asList()
            out += "  ${pair[0]}" to pair[1].toString()
        }
    }
    out += "ok" to (report.callAttr("get", "ok")?.toString() ?: "unknown")
    out
} catch (t: Throwable) {
    listOf("diagnostics failed" to t.javaClass.simpleName)
}
