// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import java.io.ByteArrayOutputStream
import org.otrv4plus.android.chat.AvatarPixels

/**
 * The user's OWN picture, made into an avatar: decoded small, centre-cropped,
 * scaled to [AvatarPixels.OWN_SIZE] and RE-ENCODED as PNG.
 *
 * Re-encoding is the point. Nothing of the original file is published --
 * no EXIF location or camera serial, no embedded thumbnail, no trailing
 * data -- only the pixels, at 96 x 96. The bridge then checks the result with
 * the same decoder it uses on everybody else's avatar before publishing.
 *
 * This is the one place a platform image decoder reads a file, and it is a
 * file the user picked from their own device; a peer's avatar never comes
 * here (see `android_bridge/avatar.py`). Bounds are read first and the image
 * is decoded at a sample size, so a huge picture is never held in full.
 */
object OwnAvatar {

    /** Larger than any phone camera; a "picture" bigger than this is refused. */
    private const val MAX_PIXELS = 100_000_000L

    fun pngFrom(context: Context, uri: Uri): ByteArray? = runCatching {
        val resolver = context.contentResolver
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        resolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        val w = bounds.outWidth
        val h = bounds.outHeight
        if (w <= 0 || h <= 0 || w.toLong() * h > MAX_PIXELS) return null
        val options = BitmapFactory.Options().apply {
            inSampleSize = AvatarPixels.sampleSize(w, h)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val decoded = resolver.openInputStream(uri)?.use {
            BitmapFactory.decodeStream(it, null, options)
        } ?: return null
        val (left, top, side) = AvatarPixels.centreSquare(decoded.width, decoded.height)
        val square = Bitmap.createBitmap(decoded, left, top, side, side)
        val size = AvatarPixels.OWN_SIZE
        val scaled = Bitmap.createScaledBitmap(square, size, size, true)
        ByteArrayOutputStream().use { out ->
            scaled.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        }
    }.getOrNull()
}
