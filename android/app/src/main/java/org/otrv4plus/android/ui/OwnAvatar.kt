// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.Build
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
 * is decoded at a reduced size, so a huge picture is never held in full.
 *
 * WHY TWO DECODERS (device report, 2026-10-15: "unable to upload a profile
 * photo"). `BitmapFactory` alone could not read HEIC/HEIF -- what many
 * cameras save by default -- on a number of phones, and ignored the EXIF
 * orientation, so a portrait photo came out on its side. On Android 9+
 * `ImageDecoder` reads HEIC, JPEG, PNG and WebP and applies the orientation
 * itself; on 8.x `BitmapFactory` is used and the orientation applied from the
 * file's EXIF here. Either way the bitmap is a SOFTWARE one: a hardware bitmap
 * cannot be cropped or re-encoded.
 *
 * Call it off the main thread: it reads and decodes a file.
 */
object OwnAvatar {

    /** Larger than any phone camera; a "picture" bigger than this is refused. */
    private const val MAX_PIXELS = 100_000_000L

    /** Decoded at least this large on the short side, then scaled down. */
    private const val DECODE_SHORT_SIDE = AvatarPixels.OWN_SIZE * 2

    /** The PNG, or why not. */
    sealed interface Made {
        data class Png(val bytes: ByteArray) : Made
        data class Refused(val reason: String) : Made
    }

    fun pngFrom(context: Context, uri: Uri): ByteArray? =
        (make(context, uri) as? Made.Png)?.bytes

    fun make(context: Context, uri: Uri): Made = try {
        // Any format this phone can read (owner, 2026-10-16: "select any
        // image format and it should convert for our limits"): ImageDecoder
        // first (HEIC/HEIF, AVIF on 12+, WebP, JPEG, PNG, GIF, BMP, DNG),
        // then BitmapFactory for what it rejects. The engine fits the
        // result to its size limit (avatar.fit).
        val bitmap = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                         decodeModernOrNull(context, uri) ?: decodeLegacy(context, uri)
                     else decodeLegacy(context, uri)
        if (bitmap == null) Made.Refused("That file is not a picture this phone can read.")
        else Made.Png(encode(bitmap))
    } catch (_: TooLarge) {
        Made.Refused("That picture is too large.")
    } catch (_: OutOfMemoryError) {
        Made.Refused("That picture is too large.")
    } catch (_: SecurityException) {
        Made.Refused("The app was not allowed to read that picture.")
    } catch (_: Exception) {
        Made.Refused("That picture could not be read.")
    }

    private class TooLarge : Exception()

    private fun decodeModernOrNull(context: Context, uri: Uri): Bitmap? = try {
        decodeModern(context, uri)
    } catch (e: TooLarge) {
        throw e
    } catch (e: SecurityException) {
        throw e
    } catch (_: Exception) {
        null
    }

    private fun decodeModern(context: Context, uri: Uri): Bitmap? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val source = ImageDecoder.createSource(context.contentResolver, uri)
        return ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
            val w = info.size.width
            val h = info.size.height
            if (w <= 0 || h <= 0 || w.toLong() * h > MAX_PIXELS) throw TooLarge()
            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            decoder.isMutableRequired = false
            // Only as big as needed: the short side at DECODE_SHORT_SIDE.
            val short = minOf(w, h)
            if (short > DECODE_SHORT_SIDE) {
                val scale = DECODE_SHORT_SIDE.toDouble() / short
                decoder.setTargetSize(maxOf(1, (w * scale).toInt()), maxOf(1, (h * scale).toInt()))
            }
        }
    }

    private fun decodeLegacy(context: Context, uri: Uri): Bitmap? {
        val resolver = context.contentResolver
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        resolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        val w = bounds.outWidth
        val h = bounds.outHeight
        if (w <= 0 || h <= 0) return null
        if (w.toLong() * h > MAX_PIXELS) throw TooLarge()
        val options = BitmapFactory.Options().apply {
            inSampleSize = AvatarPixels.sampleSize(w, h, DECODE_SHORT_SIDE)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val decoded = resolver.openInputStream(uri)?.use {
            BitmapFactory.decodeStream(it, null, options)
        } ?: return null
        val degrees = runCatching {
            resolver.openInputStream(uri)?.use { stream ->
                when (ExifInterface(stream).getAttributeInt(
                        ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)) {
                    ExifInterface.ORIENTATION_ROTATE_90 -> 90f
                    ExifInterface.ORIENTATION_ROTATE_180 -> 180f
                    ExifInterface.ORIENTATION_ROTATE_270 -> 270f
                    else -> 0f
                }
            } ?: 0f
        }.getOrDefault(0f)
        if (degrees == 0f) return decoded
        val m = Matrix().apply { postRotate(degrees) }
        return Bitmap.createBitmap(decoded, 0, 0, decoded.width, decoded.height, m, true)
    }

    /** Centre square, OWN_SIZE x OWN_SIZE, PNG. */
    private fun encode(decoded: Bitmap): ByteArray {
        val (left, top, side) = AvatarPixels.centreSquare(decoded.width, decoded.height)
        val square = Bitmap.createBitmap(decoded, left, top, side, side)
        val size = AvatarPixels.OWN_SIZE
        val scaled = Bitmap.createScaledBitmap(square, size, size, true)
        return ByteArrayOutputStream().use { out ->
            check(scaled.compress(Bitmap.CompressFormat.PNG, 100, out)) { "PNG encoding failed" }
            out.toByteArray()
        }
    }
}
