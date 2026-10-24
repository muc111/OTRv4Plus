// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * What a received PDF asks a viewer to DO, found from its structure.
 *
 * The in-app viewer runs none of it: pages are rasterised in an isolated
 * process (`ui/PdfRenderService.kt`) and nothing else is interpreted. This is
 * for the user, and above all for "Open with another app": a full PDF app may
 * run scripts, follow actions or open attachments, and the user should know
 * that before handing the file over.
 *
 * A scan of names in the file's bytes. Names inside compressed object
 * streams cannot be seen without parsing the PDF -- which is exactly what
 * this process must not do -- so such a file is reported as [Finding.HIDDEN]
 * and "nothing found" is never claimed for it.
 *
 * Plain Kotlin, driven by `PdfScanTest`.
 */
object PdfScan {

    enum class Finding(val words: String) {
        SCRIPTS("scripts"),
        AUTO_ACTIONS("actions that run when it is opened"),
        LAUNCH("a command to start another program"),
        ATTACHMENTS("attached files"),
        OUTBOUND("links or forms that contact the internet"),
        RICH_MEDIA("embedded media or XFA forms"),
        HIDDEN("compressed parts this check cannot see into"),
    }

    /** PDF name -> what it means. Names are matched after `#xx` decoding. */
    private val NAMES = mapOf(
        "JavaScript" to Finding.SCRIPTS, "JS" to Finding.SCRIPTS,
        "OpenAction" to Finding.AUTO_ACTIONS, "AA" to Finding.AUTO_ACTIONS,
        "Launch" to Finding.LAUNCH,
        "EmbeddedFile" to Finding.ATTACHMENTS, "EmbeddedFiles" to Finding.ATTACHMENTS,
        "FileAttachment" to Finding.ATTACHMENTS,
        "URI" to Finding.OUTBOUND, "SubmitForm" to Finding.OUTBOUND,
        "GoToR" to Finding.OUTBOUND, "GoToE" to Finding.OUTBOUND,
        "ImportData" to Finding.OUTBOUND,
        "RichMedia" to Finding.RICH_MEDIA, "XFA" to Finding.RICH_MEDIA,
        "ObjStm" to Finding.HIDDEN,
    )

    /** Files larger than this are scanned this far and reported [Finding.HIDDEN]. */
    const val SCAN_LIMIT_BYTES = 64 * 1024 * 1024

    private val NAME = Regex("""/([A-Za-z0-9#]{1,64})""")
    private val ESCAPE = Regex("""#([0-9A-Fa-f]{2})""")

    @JvmStatic
    fun scan(bytes: ByteArray, complete: Boolean = true): Set<Finding> {
        // ISO-8859-1 maps each byte to one char, so nothing is lost or merged.
        val text = String(bytes, Charsets.ISO_8859_1)
        val found = sortedSetOf<Finding>()
        for (m in NAME.findAll(text)) {
            val name = ESCAPE.replace(m.groupValues[1]) {
                it.groupValues[1].toInt(16).toChar().toString()
            }
            NAMES[name]?.let { found += it }
        }
        if (!complete) found += Finding.HIDDEN
        return found
    }

    /** Read at most [SCAN_LIMIT_BYTES] of [file] and [scan] it. */
    @JvmStatic
    fun scan(file: java.io.File): Set<Finding> {
        val size = file.length()
        val bytes = file.inputStream().use { input ->
            val buf = ByteArray(minOf(size, SCAN_LIMIT_BYTES.toLong()).toInt())
            var off = 0
            while (off < buf.size) {
                val n = input.read(buf, off, buf.size - off)
                if (n < 0) break
                off += n
            }
            if (off == buf.size) buf else buf.copyOf(off)
        }
        return scan(bytes, complete = size <= SCAN_LIMIT_BYTES)
    }

    /** One line for the viewer, or null when nothing was found. */
    @JvmStatic
    fun summary(found: Set<Finding>): String? {
        if (found.isEmpty()) return null
        return "This PDF contains " + found.joinToString(", ") { it.words } +
            ". None of it runs here: the pages are shown as pictures."
    }

    /** Added to the handoff warning when [found] is not empty. */
    @JvmStatic
    fun handoffNote(found: Set<Finding>): String? {
        if (found.isEmpty()) return null
        return "It contains " + found.joinToString(", ") { it.words } +
            ", which a PDF app may run or follow."
    }
}
