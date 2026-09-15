// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Getting a diagnostic off the handset without a developer.
 *
 * The workflow this exists for, in full:
 *
 *     Diagnostics -> Export error log -> Android Sharesheet -> pick an app
 *
 * No ADB, no root, no Termux, no logcat, no terminal. The previous answer to
 * "what went wrong on your phone" required all five, which meant in practice
 * that nobody ever answered it.
 *
 * WHAT LEAVES THE DEVICE
 * ----------------------
 * A file in the app's own cache, handed over as a `content://` URI through
 * [FileProvider] with a one-shot read grant for exactly that file. No raw
 * filesystem path is exposed, the app holds no storage permission, and this
 * adds none. The receiving app can read the file it was given and nothing
 * else.
 *
 * WHAT IS IN IT
 * -------------
 * Not decided here. The text is rendered by `android_bridge.report`, which is
 * the one place that knows the redaction rule. This file writes bytes and
 * builds an Intent; it does not format, filter or append, because a second
 * renderer is a second place to forget the rule.
 */
object DiagnosticsExport {

    /** The cache subdirectory the FileProvider grant is scoped to. */
    const val DIRECTORY = "diagnostics"

    /** The FileProvider authority, as declared in the manifest. */
    fun authority(context: Context): String = "${context.packageName}.$DIRECTORY"

    /**
     * Write [text] to a timestamped file and offer it to another app.
     *
     * Returns the file written, so a caller can say where it went. Throws on
     * failure rather than swallowing: the caller shows the user an error and
     * offers Copy instead, which is a better outcome than a button that looks
     * like it worked.
     *
     * Exporting touches nothing but the cache. It does not stop the service,
     * disturb the connection or alter any chat state -- a diagnostic that
     * changes what it is diagnosing is worse than none, and being able to
     * export WHILE connected is most of the point.
     */
    fun share(context: Context, text: String,
              prefix: String = "otrv4plus-log",
              subject: String = "OTRv4+ diagnostic log",
              chooserTitle: String = "Export error log"): File {
        val dir = File(context.cacheDir, DIRECTORY).apply { mkdirs() }
        prune(dir)
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val file = File(dir, "$prefix-$stamp.txt")
        file.writeText(text)

        val uri = FileProvider.getUriForFile(context, authority(context), file)
        val send = Intent(Intent.ACTION_SEND).apply {
            // text/plain, so every mail, chat and notes app offers itself.
            // The file is .txt for the same reason: the person receiving it
            // has to be able to open it without being told how.
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, subject)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(send, chooserTitle)
        // Started from a Context that may not be an Activity when this is
        // reached from a service-owned screen.
        chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(chooser)
        return file
    }

    /**
     * Keep the newest few reports and delete the rest.
     *
     * These are exported and then forgotten. Android will reclaim the cache
     * eventually, but "eventually" on a device with plenty of free space can
     * be never, and a folder of stale reports full of JIDs is a small thing
     * that should not accumulate.
     */
    private fun prune(dir: File, keep: Int = 3) {
        runCatching {
            dir.listFiles()
                ?.sortedByDescending { it.lastModified() }
                ?.drop(keep)
                ?.forEach { it.delete() }
        }
    }
}
