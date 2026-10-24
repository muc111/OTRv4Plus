// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.app.Service
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import java.io.DataOutputStream
import java.nio.ByteBuffer

/**
 * Renders one page of a received PDF, in an ISOLATED process.
 *
 * A PDF is parsed by native code (fonts, images, compressed streams), and a
 * bug in that code is reached by whoever sent the file. So it is not parsed
 * where the decrypted messages and keys live. This service runs with
 * `android:isolatedProcess="true"` (AndroidManifest.xml): no permissions, no
 * access to the app's files, no network. It is handed an open, read-only
 * descriptor for the one transient copy being viewed, and writes back raw
 * pixels -- a fixed header and width x height x 4 bytes -- so the app reads
 * no image format from it either (`IsolatedPdf` bounds every size).
 *
 * OtrApplication does not start Python in this process.
 */
class PdfRenderService : Service() {

    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != RENDER) return super.onTransact(code, data, reply, flags)
            val pdf = data.readFileDescriptor()
            val page = data.readInt()
            val maxSide = data.readInt().coerceIn(1, MAX_SIDE)
            val out = data.readFileDescriptor()
            val result = runCatching { render(pdf, page, maxSide) }
            runCatching { pdf?.close() }
            val rendered = result.getOrNull()
            reply?.writeInt(rendered?.pages ?: -1)
            if (rendered == null || out == null) {
                runCatching { out?.close() }
                return true
            }
            // Written after the reply, so the caller is already reading.
            Thread {
                runCatching {
                    DataOutputStream(ParcelFileDescriptor.AutoCloseOutputStream(out)
                        .buffered(64 * 1024)).use { s ->
                        s.writeInt(rendered.width)
                        s.writeInt(rendered.height)
                        s.write(rendered.pixels)
                    }
                }
            }.start()
            return true
        }
    }

    private class Page(val pages: Int, val width: Int, val height: Int, val pixels: ByteArray)

    private fun render(fd: ParcelFileDescriptor?, index: Int, maxSide: Int): Page? {
        fd ?: return null
        PdfRenderer(fd).use { renderer ->
            val count = renderer.pageCount
            if (count <= 0) return null
            renderer.openPage(index.coerceIn(0, count - 1)).use { p ->
                val scale = maxSide.toFloat() / maxOf(p.width, p.height).coerceAtLeast(1)
                val w = (p.width * scale).toInt().coerceIn(1, maxSide)
                val h = (p.height * scale).toInt().coerceIn(1, maxSide)
                val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
                bmp.eraseColor(android.graphics.Color.WHITE)
                p.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                val buf = ByteBuffer.allocate(w * h * 4)
                bmp.copyPixelsToBuffer(buf)
                bmp.recycle()
                return Page(count, w, h, buf.array())
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    companion object {
        const val RENDER = IBinder.FIRST_CALL_TRANSACTION

        /** The largest side either process accepts. */
        const val MAX_SIDE = 2048
    }
}
