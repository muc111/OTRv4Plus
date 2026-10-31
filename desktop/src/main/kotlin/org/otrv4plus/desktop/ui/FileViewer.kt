// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.ui

import androidx.compose.foundation.HorizontalScrollbar
import androidx.compose.foundation.Image
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.MetadataFinding
import org.otrv4plus.android.crypto.ExifReader
import org.otrv4plus.android.crypto.FileExport
import org.otrv4plus.android.crypto.FileFacts
import org.otrv4plus.android.crypto.HiddenData
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.PdfScan
import org.otrv4plus.android.crypto.SafeView
import java.io.File

/**
 * A received file, viewed inside the desktop app: the same three tabs as the
 * Android viewer (File, Metadata, Hidden content), the same facts and checks
 * (FileFacts, ExifReader, HiddenData, PdfScan, shared from the Android tree),
 * and Save to… to copy it out.
 *
 * The container is decrypted by the engine into a TRANSIENT copy in
 * [viewDirectory] (0700), emptied before each open and when the viewer
 * closes; Wipe & Exit deletes it first. Pictures are decoded by Skia, text is
 * shown as characters; nothing is run, and no other program sees the file
 * unless the user saves it.
 */
@Composable
fun FileViewerDialog(
    container: String,
    name: String,
    materialize: (directory: String) -> String?,
    inspect: (plainPath: String) -> MetadataFinding?,
    save: (destination: String) -> Long?,
    onClose: () -> Unit,
) {
    val viewDir = remember { viewDirectory() }
    var path by remember(container) { mutableStateOf<String?>(null) }
    var kind by remember(container) { mutableStateOf<SafeView.Kind?>(null) }
    var confirmSave by remember { mutableStateOf(false) }
    var saveNote by remember(container) { mutableStateOf<String?>(null) }
    var metadataLine by remember(container) { mutableStateOf<String?>(null) }
    var pdfFindings by remember(container) { mutableStateOf<Set<PdfScan.Finding>>(emptySet()) }
    var tab by remember(container) { mutableStateOf(ViewerTab.FILE) }
    var facts by remember(container) { mutableStateOf<ViewerFacts?>(null) }
    val scope = rememberCoroutineScope()
    DisposableEffect(container) {
        onDispose { viewDir.listFiles()?.forEach { it.delete() } }
    }
    LaunchedEffect(container) {
        val plain = withContext(Dispatchers.IO) {
            viewDir.mkdirs()
            viewDir.setReadable(false, false); viewDir.setReadable(true, true)
            viewDir.setWritable(false, false); viewDir.setWritable(true, true)
            viewDir.setExecutable(false, false); viewDir.setExecutable(true, true)
            viewDir.listFiles()?.forEach { it.delete() }
            runCatching { materialize(viewDir.path) }.getOrNull()
        }
        path = plain
        kind = if (plain == null) SafeView.Kind.UNSUPPORTED else withContext(Dispatchers.IO) {
            runCatching {
                val head = ByteArray(SafeView.HEAD_BYTES)
                val n = File(plain).inputStream().use { it.read(head) }.coerceAtLeast(0)
                SafeView.kindOf(head.copyOf(n))
            }.getOrDefault(SafeView.Kind.UNSUPPORTED)
        }
        if (plain != null && kind == SafeView.Kind.IMAGE) {
            metadataLine = MetadataChoice.receivedSummary(
                withContext(Dispatchers.IO) { runCatching { inspect(plain) }.getOrNull() })
        }
        if (plain != null && kind == SafeView.Kind.PDF) {
            // A scan of the bytes, not a parse: unreadable counts as hidden.
            pdfFindings = withContext(Dispatchers.IO) {
                runCatching { PdfScan.scan(File(plain)) }
                    .getOrDefault(setOf(PdfScan.Finding.HIDDEN))
            }
            metadataLine = PdfScan.summary(pdfFindings)
        }
        val k = kind
        if (plain != null && k != null) {
            facts = withContext(Dispatchers.IO) {
                runCatching { readViewerFacts(plain, name, k, pdfFindings) }
                    .getOrDefault(ViewerFacts(emptyList(), null))
            }
        }
    }
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(0.92f), shape = MaterialTheme.shapes.large) {
            Column(Modifier.fillMaxSize().padding(16.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(name.ifBlank { "Received file" }, style = MaterialTheme.typography.titleMedium)
                        Text("Received and hash-verified · shown inside this app" +
                                 (kind?.let { " · ${it.label}" } ?: ""),
                             style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(enabled = path != null, onClick = { confirmSave = true }) {
                        Text(SAVE_BUTTON, maxLines = 1)
                    }
                    Spacer(Modifier.size(8.dp))
                    TextButton(onClick = onClose) { Text("Close") }
                }
                saveNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                TabRow(selectedTabIndex = tab.ordinal) {
                    for (t in ViewerTab.entries) {
                        Tab(selected = tab == t, onClick = { tab = t }, text = { Text(t.title) })
                    }
                }
                Box(Modifier.weight(1f).fillMaxWidth().padding(top = 8.dp)) {
                    val p = path
                    when {
                        tab == ViewerTab.METADATA -> MetadataTab(facts, metadataLine)
                        tab == ViewerTab.HIDDEN -> HiddenContentTab(facts, kind, pdfFindings)
                        kind == null -> Text("Opening…")
                        p == null -> Text("The file could not be opened.")
                        kind == SafeView.Kind.IMAGE -> ImageBody(p)
                        kind == SafeView.Kind.TEXT -> TextBody(p)
                        else -> Text(NOT_SHOWN_HERE)
                    }
                }
            }
        }
    }
    if (confirmSave) {
        AlertDialog(
            onDismissRequest = { confirmSave = false },
            title = { Text(FileExport.TITLE) },
            text = { Text(FileExport.warning(name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmSave = false
                    val destination = pickSaveFile(FileExport.safeName(name))
                    if (destination != null) scope.launch {
                        val bytes = withContext(Dispatchers.IO) { runCatching { save(destination) }.getOrNull() }
                        saveNote = FileExport.result(bytes)
                    }
                }) { Text("Choose where") }
            },
            dismissButton = { TextButton(onClick = { confirmSave = false }) { Text("Cancel") } },
        )
    }
}

/**
 * Where the viewer's transient plaintext lives, 0700.
 *
 * In memory where the system has a per-user RAM filesystem: on Linux,
 * `$XDG_RUNTIME_DIR` (a 0700 tmpfs the login session owns, gone at logout),
 * else `/dev/shm`. A copy there never reaches the disk, so no SSD can keep
 * it (unless the system swaps it out). Elsewhere -- macOS, Windows -- there is
 * no such place, and it falls back beside the received files, where it is
 * deleted on close and by Wipe & Exit.
 */
fun viewDirectory(
    env: (String) -> String? = { System.getenv(it) },
    home: String = System.getProperty("user.home"),
    isDir: (File) -> Boolean = { it.isDirectory && it.canWrite() },
): File {
    val user = System.getProperty("user.name").orEmpty().filter { it.isLetterOrDigit() }
    val ram = listOfNotNull(env("XDG_RUNTIME_DIR")?.takeIf { it.startsWith("/") }?.let(::File),
                            File("/dev/shm"))
        .firstOrNull(isDir)
    return if (ram != null) File(ram, "otrv4plus-view" + if (ram.path == "/dev/shm") "-$user" else "")
           else File(home, ".otrv4plus${File.separator}view")
}

/** The desktop's own save dialog; null when cancelled. */
private fun pickSaveFile(suggested: String): String? {
    val dialog = java.awt.FileDialog(null as java.awt.Frame?, FileExport.TITLE, java.awt.FileDialog.SAVE)
    dialog.file = suggested
    dialog.isVisible = true
    val chosen = dialog.file ?: return null
    return File(dialog.directory, chosen).absolutePath
}

/** The label differs from Android's "Save to device…" only in the word for the place. */
internal const val SAVE_BUTTON = "Save to…"

internal const val NOT_SHOWN_HERE =
    "This kind of file is not shown inside the desktop app yet (pictures and text are). " +
        "Nothing in it has been opened or run. Use Save to… to open it in another program; " +
        "the Metadata and Hidden content tabs still apply."

/** Pictures larger than this many pixels are not decoded for the preview. */
private const val MAX_PREVIEW_PIXELS = 50_000_000L

@Composable
private fun ImageBody(path: String) {
    var bitmap by remember(path) { mutableStateOf<ImageBitmap?>(null) }
    var failed by remember(path) { mutableStateOf<String?>(null) }
    LaunchedEffect(path) {
        val result = withContext(Dispatchers.IO) {
            runCatching<Pair<ImageBitmap?, String?>> {
                val file = File(path)
                if (file.length() > HiddenData.MAX_SCAN_BYTES * 2L) return@runCatching Pair(null, "too large to preview")
                val bytes = file.readBytes()
                val codec = org.jetbrains.skia.Codec.makeFromData(org.jetbrains.skia.Data.makeFromBytes(bytes))
                if (codec.width.toLong() * codec.height > MAX_PREVIEW_PIXELS) {
                    return@runCatching Pair(null, "too large to preview (${codec.width} × ${codec.height})")
                }
                Pair(org.jetbrains.skia.Image.makeFromEncoded(bytes).toComposeImageBitmap(), null)
            }.getOrElse { Pair(null, "could not be decoded") }
        }
        bitmap = result.first
        failed = result.second
    }
    val b = bitmap
    when {
        b != null -> ZoomableImage(b)
        failed != null -> Text("The image $failed. Its Metadata and Hidden content tabs still apply.")
        else -> Text("Decoding…")
    }
}

/** Fit to the window, or 1× to 8× with scrolling: the Android viewer's range. */
@Composable
private fun ZoomableImage(bitmap: ImageBitmap) {
    var zoom by remember(bitmap) { mutableStateOf(0) }   // 0 = fit
    Column(Modifier.fillMaxSize()) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { zoom = 0 }) { Text("Fit") }
            TextButton(enabled = zoom != 1, onClick = { zoom = if (zoom <= 1) 1 else zoom / 2 }) { Text("−") }
            TextButton(enabled = zoom < 8, onClick = { zoom = if (zoom == 0) 1 else zoom * 2 }) { Text("+") }
            Text(if (zoom == 0) "fit" else "${zoom}×", style = MaterialTheme.typography.labelMedium)
        }
        if (zoom == 0) {
            Image(bitmap, "Received image", Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
        } else {
            val density = LocalDensity.current
            val w = with(density) { (bitmap.width * zoom).toDp() }
            val h = with(density) { (bitmap.height * zoom).toDp() }
            // Device report (2026-10-25): zoomed in, the picture could not be
            // moved. A desktop scroll area answers the wheel only (Shift for
            // across), never a mouse drag, and showed no bars. Now: drag to
            // pan, both scroll bars, and each zoom step stays centred.
            val down = rememberScrollState()
            val across = rememberScrollState()
            LaunchedEffect(zoom) {
                withFrameNanos { }            // the new size is laid out first
                down.scrollTo(down.maxValue / 2)
                across.scrollTo(across.maxValue / 2)
            }
            Box(Modifier.fillMaxSize()) {
                Box(Modifier.fillMaxSize()
                        .pointerInput(zoom) {
                            detectDragGestures { change, drag ->
                                change.consume()
                                across.dispatchRawDelta(-drag.x)
                                down.dispatchRawDelta(-drag.y)
                            }
                        }
                        .verticalScroll(down)
                        .horizontalScroll(across)) {
                    Image(bitmap, "Received image", Modifier.size(w, h), contentScale = ContentScale.FillBounds)
                }
                VerticalScrollbar(rememberScrollbarAdapter(down),
                                  Modifier.align(Alignment.CenterEnd).fillMaxHeight())
                HorizontalScrollbar(rememberScrollbarAdapter(across),
                                    Modifier.align(Alignment.BottomStart).fillMaxWidth())
            }
        }
    }
}

@Composable
private fun TextBody(path: String) {
    var text by remember(path) { mutableStateOf<String?>(null) }
    var truncated by remember(path) { mutableStateOf(false) }
    LaunchedEffect(path) {
        withContext(Dispatchers.IO) {
            val f = File(path)
            val bytes = f.inputStream().use { input ->
                val buf = ByteArray(minOf(f.length(), SafeView.TEXT_LIMIT_BYTES.toLong()).toInt())
                var off = 0
                while (off < buf.size) {
                    val n = input.read(buf, off, buf.size - off)
                    if (n < 0) break
                    off += n
                }
                buf.copyOf(off)
            }
            truncated = f.length() > SafeView.TEXT_LIMIT_BYTES
            text = String(bytes, Charsets.UTF_8)
        }
    }
    ScrollColumn(Modifier.fillMaxSize()) {
        if (truncated) Text("Showing the first ${SafeView.TEXT_LIMIT_BYTES / 1024} KB.",
                            style = MaterialTheme.typography.labelSmall)
        SelectionContainer {
            Text(text ?: "Reading…", fontFamily = FontFamily.Monospace,
                 style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ── the information tabs: the Android viewer's (FileViewerTabs.kt), in desktop terms ──

/** The viewer's three tabs, named as on Android. */
internal enum class ViewerTab(val title: String) {
    FILE("File"), METADATA("Metadata"), HIDDEN("Hidden content"),
}

internal data class ViewerFacts(val facts: List<FileFacts.Fact>, val hidden: HiddenData.Report?)

/**
 * What the two information tabs show. BLOCKING: call it on Dispatchers.IO.
 * A picture is read whole only up to [HiddenData.MAX_SCAN_BYTES]; past that
 * only its first megabyte (dimensions and EXIF live there) and the
 * appended-data check says it was not done.
 */
internal fun readViewerFacts(path: String, name: String, kind: SafeView.Kind,
                             pdfFindings: Set<PdfScan.Finding>): ViewerFacts {
    val file = File(path)
    var width: Int? = null
    var height: Int? = null
    var hidden: HiddenData.Report? = null
    val extra = mutableListOf<FileFacts.Fact>()
    if (kind == SafeView.Kind.IMAGE) {
        val whole = file.length() <= HiddenData.MAX_SCAN_BYTES
        val bytes = if (whole) file.readBytes() else file.inputStream().use { it.readNBytes(1 shl 20) }
        runCatching {
            val codec = org.jetbrains.skia.Codec.makeFromData(org.jetbrains.skia.Data.makeFromBytes(bytes))
            width = codec.width.takeIf { it > 0 }
            height = codec.height.takeIf { it > 0 }
        }
        val exif = ExifReader.read(bytes)
        FileFacts.position(exif.latLong)?.let(extra::add)
        extra += FileFacts.exif { tag -> exif[tag] }
        hidden = if (!whole) {
            HiddenData.Report(HiddenData.Status.NOT_CHECKED, "picture",
                              reason = "larger than ${HiddenData.MAX_SCAN_BYTES / 1048576} MB")
        } else {
            runCatching { HiddenData.scan(bytes) }.getOrNull()
        }
    }
    val facts = FileFacts.basic(name, kind.label, file, width, height).toMutableList()
    facts += extra
    if (kind == SafeView.Kind.PDF) facts += FileFacts.pdf(pdfFindings)
    return ViewerFacts(facts, hidden)
}

/** Every fact, label over value, in one scrolling column: nothing is cut off. */
@Composable
internal fun MetadataTab(facts: ViewerFacts?, summary: String?) {
    ScrollColumn(Modifier.fillMaxSize()) {
        summary?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
        }
        if (facts == null) {
            Text("Reading…", style = MaterialTheme.typography.bodySmall)
            return@ScrollColumn
        }
        if (facts.facts.size <= 5 && summary == null) {
            Text("No metadata fields beyond the file itself.",
                 style = MaterialTheme.typography.bodySmall)
        }
        SelectionContainer {
            Column {
                for (f in facts.facts) {
                    Text(f.label, style = MaterialTheme.typography.labelMedium)
                    Text(f.value, style = MaterialTheme.typography.bodySmall,
                         modifier = Modifier.padding(bottom = 6.dp))
                }
            }
        }
    }
}

/** What this computer can check for content a viewer does not show. */
@Composable
internal fun HiddenContentTab(facts: ViewerFacts?, kind: SafeView.Kind?,
                              pdfFindings: Set<PdfScan.Finding>) {
    ScrollColumn(Modifier.fillMaxSize()) {
        when (kind) {
            SafeView.Kind.IMAGE -> {
                val report = facts?.hidden
                Text(if (report == null) "Checking…" else HiddenData.describe(report),
                     style = MaterialTheme.typography.bodyMedium)
            }
            SafeView.Kind.PDF -> Text(
                PdfScan.summary(pdfFindings)
                    ?: "No scripts, actions, attached files, outbound links or media found.",
                style = MaterialTheme.typography.bodyMedium)
            else -> Text("Hidden content is checked in pictures and PDFs.",
                         style = MaterialTheme.typography.bodyMedium)
        }
        Spacer(Modifier.height(12.dp))
        HorizontalDivider()
        Spacer(Modifier.height(8.dp))
        Text(HIDDEN_SCOPE, style = MaterialTheme.typography.bodySmall,
             color = MaterialTheme.colorScheme.onSurfaceVariant,
             modifier = Modifier.fillMaxWidth())
    }
}

/** What the tab does not check yet, said rather than implied (as on Android). */
internal const val HIDDEN_SCOPE =
    "Checked here: data appended after the end of a picture, and a PDF's scripts, " +
        "attachments and other active parts. Not checked yet: data hidden in the " +
        "pixels themselves (least-significant-bit steganography) and edited or " +
        "layered areas -- those need the forensics tools that are still to come."
