// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.pdf.PdfRenderer
import android.media.MediaPlayer
import android.os.ParcelFileDescriptor
import android.widget.MediaController
import android.widget.VideoView
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
 * PdfRenderer, audio and video play from the private path.
 *
 * Leaving the app is a separate, explicit step ("Open with another app…")
 * with a warning first; see [handOff].
 */
@Composable
fun FileViewerDialog(path: String, name: String, onClose: () -> Unit) {
    val context = LocalContext.current
    var kind by remember(path) { mutableStateOf<SafeView.Kind?>(null) }
    var confirmHandoff by remember { mutableStateOf(false) }
    LaunchedEffect(path) {
        kind = withContext(Dispatchers.IO) {
            runCatching {
                val head = ByteArray(SafeView.HEAD_BYTES)
                val n = File(path).inputStream().use { it.read(head) }.coerceAtLeast(0)
                SafeView.kindOf(head.copyOf(n))
            }.getOrDefault(SafeView.Kind.UNSUPPORTED)
        }
    }
    Dialog(onDismissRequest = onClose,
           properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().padding(12.dp)) {
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
                Box(Modifier.weight(1f).fillMaxWidth()) {
                    when (kind) {
                        null -> Text("Opening…")
                        SafeView.Kind.IMAGE -> ImageBody(path)
                        SafeView.Kind.TEXT -> TextBody(path)
                        SafeView.Kind.PDF -> PdfBody(path)
                        SafeView.Kind.AUDIO -> AudioBody(path)
                        SafeView.Kind.VIDEO -> VideoBody(path)
                        SafeView.Kind.UNSUPPORTED -> Text(
                            "This kind of file cannot be shown inside the app. " +
                                "Nothing in it has been opened or run.")
                    }
                }
                OutlinedButton(onClick = { confirmHandoff = true },
                               modifier = Modifier.fillMaxWidth()) {
                    Text("Open with another app…")
                }
            }
        }
    }
    if (confirmHandoff) {
        AlertDialog(
            onDismissRequest = { confirmHandoff = false },
            title = { Text("Leave OTRv4Plus?") },
            text = { Text(SafeView.handoffWarning(name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmHandoff = false
                    handOff(context, path, name, kind ?: SafeView.Kind.UNSUPPORTED)
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
        bitmap != null -> Image(bitmap!!.asImageBitmap(), contentDescription = "Received image",
                                modifier = Modifier.fillMaxSize())
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
    var page by remember(path) { mutableIntStateOf(0) }
    var count by remember(path) { mutableIntStateOf(0) }
    var bitmap by remember(path) { mutableStateOf<Bitmap?>(null) }
    var failed by remember(path) { mutableStateOf(false) }
    LaunchedEffect(path, page) {
        withContext(Dispatchers.IO) {
            runCatching {
                ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY).use { fd ->
                    PdfRenderer(fd).use { renderer ->
                        count = renderer.pageCount
                        renderer.openPage(page.coerceIn(0, count - 1)).use { p ->
                            val scale = SafeView.IMAGE_MAX_SIDE.toFloat() /
                                maxOf(p.width, p.height).coerceAtLeast(1)
                            val bmp = Bitmap.createBitmap(
                                (p.width * scale).toInt().coerceAtLeast(1),
                                (p.height * scale).toInt().coerceAtLeast(1),
                                Bitmap.Config.ARGB_8888)
                            bmp.eraseColor(android.graphics.Color.WHITE)
                            p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            bitmap = bmp
                        }
                    }
                }
            }.onFailure { failed = true }
        }
    }
    Column(Modifier.fillMaxSize()) {
        Box(Modifier.weight(1f).fillMaxWidth()) {
            when {
                failed -> Text("This PDF could not be rendered.")
                bitmap != null -> Image(bitmap!!.asImageBitmap(),
                                        contentDescription = "PDF page ${page + 1}",
                                        modifier = Modifier.fillMaxSize())
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
        val safeName = name.replace(Regex("[^A-Za-z0-9._ -]"), "_").ifBlank { "file" }
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

/** The cache subdirectory an explicit handoff copy is placed in. */
const val HANDOFF_DIRECTORY = "handoff"
