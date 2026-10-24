// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.File
import java.util.Locale

/**
 * What the viewer's Metadata tab lists: the file itself, then every
 * metadata field it carries. Values the sender chose (camera names, comments)
 * are shown as text, shortened, never interpreted.
 *
 * The EXIF fields are read on the phone by the platform's ExifInterface
 * (FileViewerTabs); this holds which ones, their labels and the formatting,
 * as plain Kotlin that FileFactsTest drives.
 */
object FileFacts {

    data class Fact(val label: String, val value: String)

    /** Longest value shown; a sender's comment can be any length. */
    const val MAX_VALUE = 300

    /** EXIF tag name (as ExifInterface spells it) -> label. Position, time,
     *  device and authorship first: the fields that say who, where, when. */
    val EXIF_TAGS: List<Pair<String, String>> = listOf(
        "GPSLatitude" to "GPS latitude", "GPSLatitudeRef" to "GPS latitude ref",
        "GPSLongitude" to "GPS longitude", "GPSLongitudeRef" to "GPS longitude ref",
        "GPSAltitude" to "GPS altitude", "GPSDateStamp" to "GPS date",
        "GPSTimeStamp" to "GPS time", "GPSProcessingMethod" to "GPS method",
        "DateTimeOriginal" to "Taken", "DateTimeDigitized" to "Digitised",
        "DateTime" to "Modified", "OffsetTimeOriginal" to "Time zone",
        "Make" to "Camera make", "Model" to "Camera model",
        "BodySerialNumber" to "Camera serial", "LensMake" to "Lens make",
        "LensModel" to "Lens model", "LensSerialNumber" to "Lens serial",
        "CameraOwnerName" to "Camera owner", "Artist" to "Artist",
        "Copyright" to "Copyright", "Software" to "Software",
        "ImageDescription" to "Description", "UserComment" to "Comment",
        "ImageUniqueID" to "Image ID", "ImageWidth" to "Width (EXIF)",
        "ImageLength" to "Height (EXIF)", "Orientation" to "Orientation",
        "FNumber" to "Aperture", "ExposureTime" to "Exposure",
        "PhotographicSensitivity" to "ISO", "FocalLength" to "Focal length",
        "Flash" to "Flash", "WhiteBalance" to "White balance",
    )

    fun size(bytes: Long): String = when {
        bytes >= 1L shl 20 -> String.format(Locale.ROOT, "%.1f MB (%d bytes)", bytes / 1048576.0, bytes)
        bytes >= 1L shl 10 -> String.format(Locale.ROOT, "%.1f KB (%d bytes)", bytes / 1024.0, bytes)
        else -> "$bytes bytes"
    }

    /** A sender-chosen value made safe to show: control and direction
     *  characters replaced, shortened. */
    fun clean(value: String): String {
        val shown = value.map { c ->
            if (c.isISOControl() || c in '​'..'‏' || c in '‪'..'‮' ||
                c in '⁦'..'⁩') ' ' else c
        }.joinToString("").trim()
        return if (shown.length > MAX_VALUE) shown.take(MAX_VALUE) + "…" else shown
    }

    /** The file itself: name, kind, size, dimensions. No hash here: Kotlin
     *  does no cryptography of its own (tests/test_crypto_source_of_truth),
     *  and the transfer already verified the file's hash in the engine. */
    fun basic(name: String, kind: String, file: File, width: Int?, height: Int?): List<Fact> =
        buildList {
            add(Fact("Name", clean(name.ifBlank { "(none)" })))
            add(Fact("Kind", kind))
            add(Fact("Size", size(file.length())))
            if (width != null && height != null && width > 0 && height > 0)
                add(Fact("Dimensions", "$width × $height pixels"))
        }

    /** EXIF facts from a tag reader, in [EXIF_TAGS] order, empty ones skipped. */
    fun exif(read: (String) -> String?): List<Fact> =
        EXIF_TAGS.mapNotNull { (tag, label) ->
            read(tag)?.takeIf { it.isNotBlank() }?.let { Fact(label, clean(it)) }
        }

    /** A decimal position, for a GPS pair the reader resolved. */
    fun position(latLong: DoubleArray?): Fact? =
        latLong?.takeIf { it.size == 2 }?.let {
            Fact("Position", String.format(Locale.ROOT, "%.6f, %.6f", it[0], it[1]))
        }

    /** What the PDF check found, one fact each. */
    fun pdf(found: Set<PdfScan.Finding>): List<Fact> =
        if (found.isEmpty()) listOf(Fact("PDF contents", "no scripts, actions, attachments, " +
                                         "outbound links or media found"))
        else found.map { Fact("PDF contains", it.words) }
}
