// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import org.otrv4plus.android.bridge.AvatarImage
import org.otrv4plus.android.chat.AvatarPixels
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import javax.imageio.ImageIO
import javax.imageio.ImageReadParam

/**
 * Pictures, with the Android app's rules (shared [AvatarPixels]).
 *
 * A CONTACT'S picture is never decoded here. The engine's bounded decoder
 * (android_bridge/avatar.py: size and dimension limits checked before a
 * byte is inflated) hands over RGBA pixels, and this builds the image from
 * those numbers. An image decoder bug in the JVM therefore cannot be
 * reached by a file somebody else sent.
 *
 * OUR OWN picture is the user's own file: read with the dimensions checked
 * before decoding, subsampled while decoding, cut to the centre square,
 * scaled to [AvatarPixels.OWN_SIZE] and re-encoded as PNG -- so what is
 * published carries none of the original file's metadata. The engine then
 * checks it like anybody's.
 */
object Avatars {

    private const val MAX_PIXELS = 100_000_000L

    fun bitmap(image: AvatarImage): ImageBitmap? {
        val argb = AvatarPixels.argb(image.rgba, image.width, image.height) ?: return null
        val out = BufferedImage(image.width, image.height, BufferedImage.TYPE_INT_ARGB)
        out.setRGB(0, 0, image.width, image.height, argb, 0, image.width)
        return out.toComposeImageBitmap()
    }

    fun ownPng(file: File): ByteArray? = runCatching {
        ImageIO.createImageInputStream(file).use { input ->
            val reader = ImageIO.getImageReaders(input).asSequence().firstOrNull() ?: return null
            try {
                reader.input = input
                val w = reader.getWidth(0)
                val h = reader.getHeight(0)
                if (w <= 0 || h <= 0 || w.toLong() * h > MAX_PIXELS) return null
                val step = AvatarPixels.sampleSize(w, h)
                val param: ImageReadParam = reader.defaultReadParam.apply {
                    setSourceSubsampling(step, step, 0, 0)
                }
                val decoded = reader.read(0, param)
                val (left, top, side) = AvatarPixels.centreSquare(decoded.width, decoded.height)
                val size = AvatarPixels.OWN_SIZE
                val scaled = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
                scaled.createGraphics().apply {
                    setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                                     RenderingHints.VALUE_INTERPOLATION_BICUBIC)
                    drawImage(decoded, 0, 0, size, size, left, top, left + side, top + side, null)
                    dispose()
                }
                ByteArrayOutputStream().use { out ->
                    ImageIO.write(scaled, "png", out)
                    out.toByteArray()
                }
            } finally {
                reader.dispose()
            }
        }
    }.getOrNull()
}
