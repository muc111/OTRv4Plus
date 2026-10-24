// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.io.DataInputStream
import java.io.File
import java.nio.ByteBuffer

/**
 * The app's side of [PdfRenderService]: bind, ask for a page, read pixels.
 *
 * Everything the isolated process sends back is treated as untrusted: the
 * page count must be positive, the size within [PdfRenderService.MAX_SIDE],
 * and exactly width x height x 4 bytes are read -- no more. A renderer that
 * crashes or answers out of bounds gives null, and the viewer says the PDF
 * could not be shown.
 *
 * Blocking calls; use from Dispatchers.IO. [close] unbinds, and Android ends
 * an isolated process once nothing is bound to it: a renderer stuck on a
 * hostile file dies when the viewer closes, and the blocked call fails.
 */
class IsolatedPdf(private val context: Context) : AutoCloseable {

    class Page(val pages: Int, val bitmap: Bitmap)

    private var binder: IBinder? = null
    private var connection: ServiceConnection? = null

    private suspend fun bind(): IBinder? {
        binder?.takeIf { it.isBinderAlive }?.let { return it }
        val ready = CompletableDeferred<IBinder?>()
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                binder = service
                ready.complete(service)
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                binder = null
            }
            override fun onBindingDied(name: ComponentName?) {
                binder = null
                ready.complete(null)
            }
        }
        connection?.let { runCatching { context.unbindService(it) } }
        connection = conn
        val ok = context.bindService(Intent(context, PdfRenderService::class.java), conn,
                                     Context.BIND_AUTO_CREATE)
        if (!ok) return null
        return withTimeoutOrNull(TIMEOUT_MS) { ready.await() }
    }

    suspend fun render(file: File, page: Int, maxSide: Int = PdfRenderService.MAX_SIDE): Page? {
        val service = bind() ?: return null
        val (read, write) = ParcelFileDescriptor.createPipe()
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pdf ->
                data.writeFileDescriptor(pdf.fileDescriptor)
                data.writeInt(page)
                data.writeInt(maxSide)
                data.writeFileDescriptor(write.fileDescriptor)
                if (!service.transact(PdfRenderService.RENDER, data, reply, 0)) return null
            }
            write.close()
            val pages = reply.readInt()
            if (pages <= 0) return null
            readPixels(read, pages, maxSide)
        } catch (_: Exception) {
            null
        } finally {
            data.recycle()
            reply.recycle()
            runCatching { write.close() }
            runCatching { read.close() }
        }
    }

    private fun readPixels(read: ParcelFileDescriptor, pages: Int, maxSide: Int): Page? {
        DataInputStream(ParcelFileDescriptor.AutoCloseInputStream(read).buffered(64 * 1024)).use { s ->
            val w = s.readInt()
            val h = s.readInt()
            if (w !in 1..maxSide || h !in 1..maxSide) return null
            val pixels = ByteArray(w * h * 4)
            s.readFully(pixels)
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            bmp.copyPixelsFromBuffer(ByteBuffer.wrap(pixels))
            return Page(pages, bmp)
        }
    }

    override fun close() {
        connection?.let { runCatching { context.unbindService(it) } }
        connection = null
        binder = null
    }

    companion object {
        /** How long to wait for the isolated process to start. */
        const val TIMEOUT_MS = 20_000L
    }
}
