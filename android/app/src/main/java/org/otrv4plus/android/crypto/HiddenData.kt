// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * Data appended after the end of a picture: the viewer's Hidden Content tab.
 *
 * The commonest way to hide a file in a photo is to append it -- an archive
 * after a JPEG's end-of-image marker or a PNG's IEND chunk. Viewers stop at
 * the end marker and never show it; the bytes travel with the picture. This
 * walks the format's own structure to find where the picture really ends
 * (an EOI inside an embedded EXIF thumbnail is skipped, because a JPEG's
 * segments carry their lengths), reports what follows, and names what it
 * looks like. Detection only: nothing found here is opened or run.
 *
 * Steganography that changes the pixels themselves (LSB and the like) needs
 * the pixel analysis of the next phase; this check cannot see it, and the
 * tab says so.
 *
 * Plain Kotlin on a byte array; HiddenDataTest drives it.
 */
object HiddenData {

    /** Larger files are not read into memory for this check. */
    const val MAX_SCAN_BYTES = 32 * 1024 * 1024

    enum class Status { NOTHING_APPENDED, APPENDED, NOT_CHECKED }

    data class Report(
        val status: Status,
        val format: String,
        /** Offset just past the picture's end marker, when found. */
        val pictureEnd: Int? = null,
        val appendedBytes: Int = 0,
        val looksLike: String? = null,
        val reason: String = "",
    )

    fun scan(bytes: ByteArray): Report {
        val (format, end) = when {
            isJpeg(bytes) -> "JPEG" to jpegEnd(bytes)
            isPng(bytes) -> "PNG" to pngEnd(bytes)
            isWebp(bytes) -> "WebP" to webpEnd(bytes)
            else -> return Report(Status.NOT_CHECKED, "other",
                                  reason = "only JPEG, PNG and WebP pictures are checked")
        }
        if (end == null) {
            return Report(Status.NOT_CHECKED, format,
                          reason = "the picture's structure could not be followed to its end")
        }
        val extra = bytes.size - end
        if (extra <= 0) return Report(Status.NOTHING_APPENDED, format, end)
        return Report(Status.APPENDED, format, end, extra, sniff(bytes, end))
    }

    fun describe(r: Report): String = when (r.status) {
        Status.NOT_CHECKED -> "Appended data: not checked (${r.reason})."
        Status.NOTHING_APPENDED ->
            "Appended data: none. Nothing follows the end of this ${r.format}."
        Status.APPENDED ->
            "Appended data: ${r.appendedBytes} bytes follow the end of this ${r.format}" +
                " (from byte ${r.pictureEnd}); they look like ${r.looksLike}. A viewer " +
                "never shows them. Some cameras and editors leave a little padding " +
                "there; anything larger was put there on purpose."
    }

    // -- formats ---------------------------------------------------------------

    private fun u(b: ByteArray, i: Int) = b[i].toInt() and 0xFF

    private fun isJpeg(b: ByteArray) = b.size >= 3 && u(b, 0) == 0xFF && u(b, 1) == 0xD8 &&
        u(b, 2) == 0xFF

    private val PNG_SIG = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)

    private fun isPng(b: ByteArray) = b.size >= 8 && b.copyOf(8).contentEquals(PNG_SIG)

    private fun isWebp(b: ByteArray) = b.size >= 12 && ascii(b, 0, 4) == "RIFF" &&
        ascii(b, 8, 4) == "WEBP"

    private fun ascii(b: ByteArray, at: Int, n: Int) =
        if (at + n > b.size) "" else String(b, at, n, Charsets.ISO_8859_1)

    /** Offset just past EOI, following segment lengths and entropy data. */
    internal fun jpegEnd(b: ByteArray): Int? {
        var i = 2
        val n = b.size
        while (i < n) {
            if (u(b, i) != 0xFF) return null
            while (i < n && u(b, i) == 0xFF) i++          // fill bytes
            if (i >= n) return null
            val marker = u(b, i++)
            when {
                marker == 0xD9 -> return i                    // EOI
                marker == 0x01 || marker in 0xD0..0xD8 -> continue   // no length
            }
            if (i + 2 > n) return null
            val len = (u(b, i) shl 8) or u(b, i + 1)
            if (len < 2 || i + len > n) return null
            i += len
            if (marker == 0xDA) {                            // SOS: entropy data
                while (true) {
                    if (i + 1 >= n) return null
                    if (u(b, i) == 0xFF) {
                        val next = u(b, i + 1)
                        if (next == 0x00 || next in 0xD0..0xD7) { i += 2; continue }
                        break                                // a real marker
                    }
                    i++
                }
            }
        }
        return null
    }

    /** Offset just past the IEND chunk's CRC. */
    internal fun pngEnd(b: ByteArray): Int? {
        var i = 8
        while (i + 12 <= b.size) {
            val len = ((u(b, i) shl 24) or (u(b, i + 1) shl 16) or (u(b, i + 2) shl 8) or
                u(b, i + 3)).toLong() and 0xFFFFFFFFL
            val type = ascii(b, i + 4, 4)
            val next = i + 12L + len
            if (next > b.size) return null
            if (type == "IEND") return next.toInt()
            i = next.toInt()
        }
        return null
    }

    /** RIFF's own length, padded to even. */
    internal fun webpEnd(b: ByteArray): Int? {
        val size = (u(b, 4) or (u(b, 5) shl 8) or (u(b, 6) shl 16) or (u(b, 7) shl 24))
            .toLong() and 0xFFFFFFFFL
        val end = 8 + size + (size and 1)
        return if (end <= b.size) end.toInt() else null
    }

    /** What the bytes from [at] look like, by their first bytes. */
    internal fun sniff(b: ByteArray, at: Int): String {
        fun starts(vararg sig: Int) = at + sig.size <= b.size &&
            sig.indices.all { u(b, at + it) == sig[it] }
        return when {
            starts(0x50, 0x4B, 0x03, 0x04) -> "a ZIP archive (or a document or app packed as one)"
            starts(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C) -> "a 7-Zip archive"
            starts(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07) -> "a RAR archive"
            starts(0x1F, 0x8B) -> "gzip-compressed data"
            starts(0x42, 0x5A, 0x68) -> "bzip2-compressed data"
            starts(0x25, 0x50, 0x44, 0x46) -> "a PDF document"
            starts(0x89, 0x50, 0x4E, 0x47) -> "another PNG picture"
            starts(0xFF, 0xD8, 0xFF) -> "another JPEG picture"
            starts(0x47, 0x49, 0x46, 0x38) -> "a GIF picture"
            starts(0x4F, 0x67, 0x67, 0x53) -> "Ogg audio"
            starts(0x49, 0x44, 0x33) -> "MP3 audio"
            starts(0x52, 0x49, 0x46, 0x46) -> "a RIFF file (WAV, AVI or WebP)"
            (at until b.size).all { b[it] == 0.toByte() } -> "zero padding"
            printable(b, at) -> "text"
            else -> "unrecognised data (possibly encrypted)"
        }
    }

    private fun printable(b: ByteArray, at: Int): Boolean {
        val end = minOf(b.size, at + 512)
        if (end <= at) return false
        val ok = (at until end).count {
            val c = u(b, it)
            c == 9 || c == 10 || c == 13 || c in 32..126 || c >= 0xC2
        }
        return ok * 100 / (end - at) >= 95
    }
}
