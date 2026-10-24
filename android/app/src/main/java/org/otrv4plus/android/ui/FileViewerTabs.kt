// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.otrv4plus.android.crypto.FileFacts
import org.otrv4plus.android.crypto.HiddenData
import org.otrv4plus.android.crypto.PdfScan
import org.otrv4plus.android.crypto.SafeView
import java.io.File

/** The viewer's three tabs (owner, 2026-10-24). */
internal enum class ViewerTab(val title: String) {
    FILE("File"), METADATA("Metadata"), HIDDEN("Hidden content"),
}

/** What the Metadata and Hidden content tabs show, read once per file. */
internal data class ViewerFacts(
    val facts: List<FileFacts.Fact>,
    val hidden: HiddenData.Report?,
)

/**
 * Read everything the two information tabs need. BLOCKING: call it on
 * Dispatchers.IO. The picture is read whole only for the appended-data check
 * and only up to [HiddenData.MAX_SCAN_BYTES]; its dimensions come from the
 * header, never a full decode.
 */
internal fun readViewerFacts(path: String, name: String, kind: SafeView.Kind,
                             pdfFindings: Set<PdfScan.Finding>): ViewerFacts {
    val file = File(path)
    var width: Int? = null
    var height: Int? = null
    if (kind == SafeView.Kind.IMAGE) {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        runCatching { BitmapFactory.decodeFile(path, bounds) }
        width = bounds.outWidth.takeIf { it > 0 }
        height = bounds.outHeight.takeIf { it > 0 }
    }
    val facts = FileFacts.basic(name, kind.label, file, width, height).toMutableList()
    var hidden: HiddenData.Report? = null
    if (kind == SafeView.Kind.IMAGE) {
        runCatching {
            val exif = android.media.ExifInterface(path)
            FileFacts.position(FloatArray(2).takeIf { exif.getLatLong(it) }
                ?.let { doubleArrayOf(it[0].toDouble(), it[1].toDouble()) })?.let(facts::add)
            facts += FileFacts.exif { tag -> exif.getAttribute(tag) }
        }
        hidden = if (file.length() > HiddenData.MAX_SCAN_BYTES) {
            HiddenData.Report(HiddenData.Status.NOT_CHECKED, "picture",
                              reason = "larger than ${HiddenData.MAX_SCAN_BYTES / 1048576} MB")
        } else {
            runCatching { HiddenData.scan(file.readBytes()) }.getOrNull()
        }
    }
    if (kind == SafeView.Kind.PDF) facts += FileFacts.pdf(pdfFindings)
    return ViewerFacts(facts, hidden)
}

/** Every fact, label over value, in one scrolling column: nothing is cut off. */
@Composable
internal fun MetadataTab(facts: ViewerFacts?, summary: String?) {
    val scroll = rememberScrollState()
    Column(Modifier.fillMaxSize().verticalScrollbar(scroll).verticalScroll(scroll)
               .padding(end = 8.dp)) {
        summary?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
        }
        if (facts == null) {
            Text("Reading…", style = MaterialTheme.typography.bodySmall)
            return@Column
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

/** What this phone can check for content a viewer does not show. */
@Composable
internal fun HiddenContentTab(facts: ViewerFacts?, kind: SafeView.Kind?,
                              pdfFindings: Set<PdfScan.Finding>) {
    val scroll = rememberScrollState()
    Column(Modifier.fillMaxSize().verticalScrollbar(scroll).verticalScroll(scroll)
               .padding(end = 8.dp)) {
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

/** What the tab does not check yet, said rather than implied. */
internal const val HIDDEN_SCOPE =
    "Checked here: data appended after the end of a picture, and a PDF's scripts, " +
        "attachments and other active parts. Not checked yet: data hidden in the " +
        "pixels themselves (least-significant-bit steganography) and edited or " +
        "layered areas -- those need the forensics tools that are still to come."
