// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaPlayer
import android.widget.MediaController
import android.widget.VideoView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.MetadataFinding
import org.otrv4plus.android.crypto.FileExport
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.PdfScan
import org.otrv4plus.android.crypto.SafeView
import java.io.File

/**
 * The in-app viewer for a RECEIVED, VERIFIED file.
 *
 * Opened only by a tap on a verified transfer (`SafeView.openable`), never
 * automatically. The kind comes from the file's bytes, not its name
 * (`SafeView.kindOf`). Everything is rendered by the platform's local
 * decoders — no WebView, no network, no scripting: an image is decoded to a
 * bitmap, text is shown as characters, a PDF page is rasterised by
 * PdfRenderer in an isolated process (PdfRenderService), audio and video
 * play from the private path.
 *
 * Leaving the app is a separate, explicit step ("Open with another app…")
 * with a warning first; see [handOff].
 */
@Composable
fun FileViewerDialog(
    container: String,
    name: String,
    materialize: (directory: String) -> String?,
    onClose: () -> Unit,
    /** What metadata the decrypted copy carries (pictures only), or null. */
    inspect: (plainPath: String) -> MetadataFinding? = { null },
) {
    val context = LocalContext.current
    // The received file rests as a sealed `.otrv` container. It is decrypted
    // (by Rust, through the bridge) into a TRANSIENT copy under cache/view/,
    // which is emptied before each open and deleted when this dialog goes;
    // Wipe & Exit removes the cache as well. No other plaintext copy exists.
    val viewDir = remember { File(context.cacheDir, VIEW_DIRECTORY) }
    var path by remember(container) { mutableStateOf<String?>(null) }
    var kind by remember(container) { mutableStateOf<SafeView.Kind?>(null) }
    var confirmHandoff by remember { mutableStateOf(false) }
    var confirmSave by remember { mutableStateOf(false) }
    var saveNote by remember(container) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    // Android's own save dialog: the user picks the place, the app gets
    // write access to that one new document and nothing else.
    val saver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(FileExport.MIME)) { uri ->
        val source = path
        if (uri == null || source == null) return@rememberLauncherForActivityResult
        scope.launch {
            val bytes = withContext(Dispatchers.IO) { saveTo(context, uri, source) }
            saveNote = FileExport.result(bytes)
        }
    }
    var metadataLine by remember(container) { mutableStateOf<String?>(null) }
    var pdfFindings by remember(container) { mutableStateOf<Set<PdfScan.Finding>>(emptySet()) }
    var tab by remember(container) { mutableStateOf(ViewerTab.FILE) }
    var facts by remember(container) { mutableStateOf<ViewerFacts?>(null) }
    DisposableEffect(container) {
        onDispose { viewDir.listFiles()?.forEach { it.delete() } }
    }
    LaunchedEffect(container) {
        val plain = withContext(Dispatchers.IO) {
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
    // Edge to edge: from Android 15 a full-screen dialog is drawn under the
    // status and navigation bars whatever `decorFitsSystemWindows` says, so
    // the bars' space is taken here (safeDrawing). Without it the row under
    // the picture or PDF -- Open with, zoom, page -- sat behind the
    // navigation bar (device report, Pixel 7 / Android 17).
    Dialog(onDismissRequest = onClose,
           properties = DialogProperties(usePlatformDefaultWidth = false,
                                         decorFitsSystemWindows = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize()
                       .windowInsetsPadding(WindowInsets.safeDrawing)
                       .padding(12.dp)) {
                Row(Modifier.fillMaxWidth()) {
                    Column(Modifier.weight(1f)) {
                        Text(name.ifBlank { "Received file" },
                             style = MaterialTheme.typography.titleMedium)
                        Text("Received and hash-verified · shown inside this app" +
                                 (kind?.let { " · ${it.label}" } ?: ""),
                             style = MaterialTheme.typography.labelSmall)
                    }
                    TextButton(onClick = onClose) { Text("Close") }
                }
                // File | Metadata | Hidden content (owner, 2026-10-24). The
                // Metadata tab is its own scrolling column, so no field is
                // ever pushed off the screen by the picture.
                TabRow(selectedTabIndex = tab.ordinal) {
                    for (t in ViewerTab.entries) {
                        Tab(selected = tab == t, onClick = { tab = t },
                            text = { Text(t.title) })
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
                        kind == SafeView.Kind.PDF -> PdfBody(p)
                        kind == SafeView.Kind.AUDIO -> AudioBody(p)
                        kind == SafeView.Kind.VIDEO -> VideoBody(p)
                        else -> Text(
                            "This kind of file cannot be shown inside the app. " +
                                "Nothing in it has been opened or run.")
                    }
                }
                saveNote?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                OutlinedButton(enabled = path != null, onClick = { confirmSave = true },
                               modifier = Modifier.fillMaxWidth()) {
                    Text(FileExport.BUTTON)
                }
                OutlinedButton(enabled = path != null, onClick = { confirmHandoff = true },
                               modifier = Modifier.fillMaxWidth()) {
                    Text("Open with another app…")
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
                    saver.launch(FileExport.safeName(name))
                }) { Text("Choose where") }
            },
            dismissButton = { TextButton(onClick = { confirmSave = false }) { Text("Cancel") } },
        )
    }
    if (confirmHandoff) {
        AlertDialog(
            onDismissRequest = { confirmHandoff = false },
            title = { Text("Leave OTRv4Plus?") },
            text = { Text(listOfNotNull(SafeView.handoffWarning(name),
                                        PdfScan.handoffNote(pdfFindings)).joinToString(" ")) },
            confirmButton = {
                TextButton(onClick = {
                    confirmHandoff = false
                    path?.let { handOff(context, it, name, kind ?: SafeView.Kind.UNSUPPORTED) }
                }) { Text("Open with another app") }
            },
            dismissButton = {
                TextButton(onClick = { confirmHandoff = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun ImageBody(path: String) {
    var bitmap by remember(path) { mutableStateOf<Bitmap?>(null) }
    var failed by remember(path) { mutableStateOf(false) }
    LaunchedEffect(path) {
        bitmap = withContext(Dispatchers.IO) {
            runCatching {
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(path, bounds)
                var sample = 1
                while (bounds.outWidth / sample > SafeView.IMAGE_MAX_SIDE ||
                       bounds.outHeight / sample > SafeView.IMAGE_MAX_SIDE) sample *= 2
                BitmapFactory.decodeFile(path, BitmapFactory.Options().apply {
                    inSampleSize = sample
                })
            }.getOrNull()
        }
        failed = bitmap == null
    }
    when {
        bitmap != null -> ZoomableImage(bitmap!!.asImageBitmap(), "Received image")
        failed -> Text("The image could not be decoded.")
        else -> Text("Decoding…")
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
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        if (truncated) Text("Showing the first ${SafeView.TEXT_LIMIT_BYTES / 1024} KB.",
                            style = MaterialTheme.typography.labelSmall)
        Text(text ?: "Reading…", fontFamily = FontFamily.Monospace,
             style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun PdfBody(path: String) {
    val context = LocalContext.current
    // Rendered in PdfRenderService's isolated process, never in this one.
    val pdf = remember(path) { IsolatedPdf(context.applicationContext) }
    DisposableEffect(pdf) { onDispose { pdf.close() } }
    var page by remember(path) { mutableIntStateOf(0) }
    var count by remember(path) { mutableIntStateOf(0) }
    var bitmap by remember(path) { mutableStateOf<Bitmap?>(null) }
    var failed by remember(path) { mutableStateOf(false) }
    LaunchedEffect(path, page) {
        val shown = withContext(Dispatchers.IO) { pdf.render(File(path), page) }
        if (shown == null) failed = true
        else {
            count = shown.pages
            bitmap = shown.bitmap
        }
    }
    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when {
                failed -> Text("This PDF could not be shown. Nothing in it was run.")
                bitmap != null -> key(page) {
                    ZoomableImage(bitmap!!.asImageBitmap(), "PDF page ${page + 1}")
                }
                else -> Text("Rendering…")
            }
        }
        Row {
            TextButton(enabled = page > 0, onClick = { page-- }) { Text("Previous") }
            Text("Page ${page + 1} of $count", Modifier.padding(12.dp))
            TextButton(enabled = page < count - 1, onClick = { page++ }) { Text("Next") }
        }
    }
}

@Composable
private fun AudioBody(path: String) {
    var playing by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    val player = remember(path) {
        runCatching { MediaPlayer().apply { setDataSource(path); prepare() } }
            .onFailure { failed = true }.getOrNull()
    }
    DisposableEffect(player) { onDispose { player?.release() } }
    if (failed || player == null) {
        Text("This audio could not be played.")
        return
    }
    player.setOnCompletionListener { playing = false }
    Button(onClick = {
        if (playing) player.pause() else player.start()
        playing = !playing
    }) { Text(if (playing) "Pause" else "Play") }
}

@Composable
private fun VideoBody(path: String) {
    val holder = remember { arrayOfNulls<VideoView>(1) }
    DisposableEffect(path) { onDispose { holder[0]?.stopPlayback() } }
    AndroidView(
        factory = { ctx ->
            VideoView(ctx).apply {
                holder[0] = this
                setMediaController(MediaController(ctx).also { it.setAnchorView(this) })
                setVideoPath(path)
            }
        },
        modifier = Modifier.fillMaxSize(),
    )
}

/**
 * The explicit exit: copy into `cache/handoff/` (the only FileProvider path
 * besides diagnostics/), grant one app read access to that one copy, and let
 * the user choose the app. The private original is never exposed; Wipe &
 * Exit clears the cache, copy included.
 */
private fun handOff(context: Context, path: String, name: String, kind: SafeView.Kind) {
    runCatching {
        val dir = File(context.cacheDir, HANDOFF_DIRECTORY).apply { mkdirs() }
        dir.listFiles()?.forEach { it.delete() }
        val safeName = FileExport.safeName(name)
        val copy = File(dir, safeName)
        File(path).copyTo(copy, overwrite = true)
        val uri = FileProvider.getUriForFile(
            context, "${context.packageName}.diagnostics", copy)
        val mime = when (kind) {
            SafeView.Kind.IMAGE -> "image/*"
            SafeView.Kind.TEXT -> "text/plain"
            SafeView.Kind.PDF -> "application/pdf"
            SafeView.Kind.AUDIO -> "audio/*"
            SafeView.Kind.VIDEO -> "video/*"
            SafeView.Kind.UNSUPPORTED -> "application/octet-stream"
        }
        val view = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mime)
            clipData = ClipData.newRawUri("", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(view, "Open with")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

/**
 * Write the decrypted file at [source] to the document the user just created.
 * Bytes copied, or null; a failed copy deletes the half-written document so
 * nothing partial is left where the user will look for the file.
 */
private fun saveTo(context: Context, uri: android.net.Uri, source: String): Long? {
    val resolver = context.contentResolver
    val copied = runCatching {
        resolver.openOutputStream(uri, "w")!!.use { out ->
            File(source).inputStream().use { FileExport.copy(it, out) }
        }
    }.getOrNull()
    if (copied == null) {
        runCatching { android.provider.DocumentsContract.deleteDocument(resolver, uri) }
    }
    return copied
}

/** The cache subdirectory an explicit handoff copy is placed in. */
const val HANDOFF_DIRECTORY = "handoff"

/** Where the viewer's transient decrypted copy lives while it is open. */
const val VIEW_DIRECTORY = "view"

/**
 * A picture that can be pinched, dragged, double-tapped and zoomed with
 * buttons. The rules (limits, steps, how far it may be dragged) are [Zoom].
 */
@Composable
private fun ZoomableImage(image: ImageBitmap, description: String) {
    var scale by remember { mutableStateOf(Zoom.MIN) }
    var pan by remember { mutableStateOf(Offset.Zero) }
    var view by remember { mutableStateOf(Size.Zero) }
    fun settle(next: Float, by: Offset = Offset.Zero) {
        scale = Zoom.clamp(next)
        pan = Offset(Zoom.clampPan(pan.x + by.x, scale, view.width),
                     Zoom.clampPan(pan.y + by.y, scale, view.height))
    }
    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxWidth().clipToBounds()
                .onSizeChanged { view = Size(it.width.toFloat(), it.height.toFloat()) }
                .pointerInput(Unit) {
                    detectTransformGestures { _, drag, zoom, _ -> settle(scale * zoom, drag) }
                }
                .pointerInput(Unit) {
                    detectTapGestures(onDoubleTap = { settle(Zoom.doubleTap(scale)) })
                }) {
            Image(image, contentDescription = description,
                  modifier = Modifier.fillMaxSize().graphicsLayer {
                      scaleX = scale
                      scaleY = scale
                      translationX = pan.x
                      translationY = pan.y
                  })
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
            TextButton(enabled = scale > Zoom.MIN, onClick = { settle(Zoom.zoomOut(scale)) }) {
                Text("−", style = MaterialTheme.typography.titleLarge)
            }
            TextButton(enabled = scale > Zoom.MIN, onClick = { settle(Zoom.MIN) }) {
                Text(Zoom.label(scale))
            }
            TextButton(enabled = scale < Zoom.MAX, onClick = { settle(Zoom.zoomIn(scale)) }) {
                Text("+", style = MaterialTheme.typography.titleLarge)
            }
        }
    }
}

/** A thin bar on the right showing where [state] is, when there is more to scroll. */
internal fun Modifier.verticalScrollbar(state: ScrollState): Modifier = drawWithContent {
    drawContent()
    val total = state.maxValue
    if (total <= 0 || total == Int.MAX_VALUE) return@drawWithContent
    val visible = size.height
    val thumb = (visible * visible / (visible + total)).coerceAtLeast(24.dp.toPx())
    val top = (visible - thumb) * state.value / total
    drawRoundRect(
        color = androidx.compose.ui.graphics.Color.Gray.copy(alpha = 0.6f),
        topLeft = Offset(size.width - 4.dp.toPx(), top),
        size = Size(4.dp.toPx(), thumb),
        cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx()),
    )
}
