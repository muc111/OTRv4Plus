// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.InputStream
import java.io.OutputStream

/**
 * "Save to device": a received file copied out of the app, to a place the
 * user picks in Android's own save dialog (Storage Access Framework).
 *
 * Owner (2026-10-24): files stayed inside the app, and Wipe & Exit destroys
 * everything inside the app. A saved copy is the user's, outside the app: no
 * permission is asked for, the app gets write access to that one document
 * only, and Wipe & Exit does not reach it -- which is the point, and also
 * exactly what the warning says before anything is written.
 *
 * Plain Kotlin; FileExportTest drives it.
 */
object FileExport {

    /** Every file is offered as bytes: the name keeps its extension, and a
     *  document provider does not rename an octet stream. */
    const val MIME = "application/octet-stream"

    /** A name safe to suggest: the sender chose it. */
    fun safeName(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._ -]"), "_").trim('.', ' ').ifBlank { "file" }

    const val BUTTON = "Save to device…"
    const val TITLE = "Save a copy outside OTRv4Plus?"

    fun warning(name: String): String =
        "${name.ifBlank { "This file" }} will be saved where you choose, decrypted. " +
            "That copy is outside this app: Wipe & Exit does not delete it, it is " +
            "not encrypted, and other apps allowed to read your files can read it."

    /** Copy all of [input] to [output] and flush. Returns the bytes copied. */
    fun copy(input: InputStream, output: OutputStream): Long {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            output.write(buffer, 0, n)
            total += n
        }
        output.flush()
        return total
    }

    /** What to say afterwards. [bytes] null: it failed; -1: cancelled. */
    fun result(bytes: Long?): String? = when {
        bytes == null -> "The file could not be saved. Nothing was written."
        bytes < 0 -> null
        else -> "Saved (${bytes} bytes), outside the app. Wipe & Exit does not delete it."
    }
}
