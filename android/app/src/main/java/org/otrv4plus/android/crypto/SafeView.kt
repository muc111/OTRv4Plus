// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.File

/**
 * What the in-app viewer may show for a received file, and whether it may be
 * opened at all.
 *
 * THE TYPE COMES FROM THE BYTES. A file arrives with a name the SENDER chose;
 * "holiday.jpg" can be anything. The kind is decided from the file's own
 * leading bytes, and the name is used for nothing but display. A file whose
 * bytes match no kind the viewer can render safely is UNSUPPORTED: nothing
 * is interpreted, and the only way out of the app is the explicit "Open with
 * another app" handoff, which asks first.
 *
 * ONLY VERIFIED FILES. [openable] requires the engine's verified path
 * (`FileTransferView.path`, set only after every hash check) inside the
 * private received directory. Nothing opens automatically; each view is a tap.
 *
 * Plain Kotlin, driven by `SafeViewTest`.
 */
object SafeView {

    enum class Kind(val label: String) {
        IMAGE("image"),
        TEXT("text"),
        PDF("PDF"),
        AUDIO("audio"),
        VIDEO("video"),
        UNSUPPORTED("file"),
    }

    /** How many leading bytes [kindOf] needs. */
    const val HEAD_BYTES = 64

    /** Text shown in-app is capped; the rest is not read. */
    const val TEXT_LIMIT_BYTES = 256 * 1024

    /** Images larger than this on either side are downsampled to fit. */
    const val IMAGE_MAX_SIDE = 2048

    @JvmStatic
    fun kindOf(head: ByteArray): Kind {
        fun at(i: Int, vararg b: Int) =
            head.size >= i + b.size && b.indices.all { head[i + it] == b[it].toByte() }
        fun ascii(i: Int, s: String) = at(i, *s.map { it.code }.toIntArray())
        return when {
            at(0, 0xFF, 0xD8, 0xFF) -> Kind.IMAGE                              // JPEG
            at(0, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) -> Kind.IMAGE // PNG
            ascii(0, "GIF87a") || ascii(0, "GIF89a") -> Kind.IMAGE
            ascii(0, "RIFF") && ascii(8, "WEBP") -> Kind.IMAGE
            ascii(0, "%PDF-") -> Kind.PDF
            ascii(0, "RIFF") && ascii(8, "WAVE") -> Kind.AUDIO
            ascii(0, "OggS") || ascii(0, "fLaC") || ascii(0, "ID3") -> Kind.AUDIO
            at(0, 0xFF, 0xFB) || at(0, 0xFF, 0xF3) || at(0, 0xFF, 0xF2) -> Kind.AUDIO // MP3
            ascii(4, "ftyp") -> if (ascii(8, "M4A ")) Kind.AUDIO else Kind.VIDEO
            at(0, 0x1A, 0x45, 0xDF, 0xA3) -> Kind.VIDEO                       // WebM/MKV
            looksLikeText(head) -> Kind.TEXT
            else -> Kind.UNSUPPORTED
        }
    }

    /** UTF-8 with no NULs or control bytes beyond tab/CR/LF/FF. */
    @JvmStatic
    fun looksLikeText(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return true
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            if (v == 0) return false
            if (v < 0x20 && v != 0x09 && v != 0x0A && v != 0x0D && v != 0x0C) return false
        }
        // A multibyte sequence cut at the end of the sample is not an error.
        val decoder = Charsets.UTF_8.newDecoder()
        return runCatching {
            decoder.decode(java.nio.ByteBuffer.wrap(bytes, 0, trimPartial(bytes)))
        }.isSuccess
    }

    private fun trimPartial(bytes: ByteArray): Int {
        var end = bytes.size
        var back = 0
        while (back < 3 && end - back - 1 >= 0) {
            val v = bytes[end - back - 1].toInt() and 0xFF
            if (v and 0xC0 == 0x80) { back++; continue }
            if (v and 0xC0 == 0xC0) end -= back + 1
            break
        }
        return end
    }

    /**
     * Whether [path] may be opened: a regular file, inside [receivedDir]
     * after resolving links and `..`. Anything else -- empty, elsewhere, a
     * directory -- is refused.
     */
    @JvmStatic
    fun openable(path: String, receivedDir: String): Boolean {
        if (path.isBlank() || receivedDir.isBlank()) return false
        return runCatching {
            val file = File(path).canonicalFile
            val dir = File(receivedDir).canonicalFile
            file.isFile && file.parentFile == dir
        }.getOrDefault(false)
    }

    /** The warning before a file leaves the app. */
    @JvmStatic
    fun handoffWarning(name: String): String =
        "Open ${name.ifBlank { "this file" }} in another app? That app will get " +
            "a copy and can keep it, and it may contact the network. The copy " +
            "made for it stays in this app's cache until the next handoff " +
            "replaces it or Wipe & Exit clears it."
}
