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

    /**
     * Our own picture as a small PNG, from any image file. Owner
     * (2026-10-16): "we should be able to select any image format and it
     * should convert for our limits". ImageIO reads PNG, JPEG, GIF, BMP and
     * TIFF; anything else (WebP, HEIC/HEIF, AVIF, ...) is converted by an
     * image tool already on this computer, if there is one ([CONVERTERS]).
     * The engine then fits the result to its size limit (avatar.fit).
     */
    fun ownPng(file: File): ByteArray? {
        val decoded = runCatching { readWithImageIO(file) }.getOrNull()
            ?: runCatching { readWithConverter(file) }.getOrNull()
            ?: return null
        return runCatching { squarePng(decoded) }.getOrNull()
    }

    private fun readWithImageIO(file: File): BufferedImage? =
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
                reader.read(0, param)
            } finally {
                reader.dispose()
            }
        }

    /**
     * Tools tried, in order, for a format ImageIO cannot read. Each writes
     * one PNG frame (at most 512 px) to stdout; no shell, the path is one
     * argument. They only ever read the user's own file.
     */
    private val CONVERTERS: List<(String) -> List<String>> = listOf(
        { p -> listOf("magick", "$p[0]", "-auto-orient", "-thumbnail", "512x512", "png:-") },
        { p -> listOf("convert", "$p[0]", "-auto-orient", "-thumbnail", "512x512", "png:-") },
        { p -> listOf("dwebp", "-quiet", p, "-png", "-o", "-") },
        { p -> listOf("ffmpeg", "-v", "error", "-i", p, "-frames:v", "1",
                      "-vf", "scale='min(512,iw)':-2", "-f", "image2pipe", "-c:v", "png", "-") },
    )

    private const val CONVERT_SECONDS = 30L
    private const val CONVERT_MAX_BYTES = 32 * 1024 * 1024

    private fun readWithConverter(file: File): BufferedImage? {
        for (command in CONVERTERS) {
            val png = runCatching { run(command(file.absolutePath)) }.getOrNull() ?: continue
            val image = runCatching { ImageIO.read(java.io.ByteArrayInputStream(png)) }.getOrNull()
            if (image != null && image.width > 0 && image.height > 0) return image
        }
        return null
    }

    private fun run(command: List<String>): ByteArray? {
        val process = ProcessBuilder(command)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
        val out = java.util.concurrent.CompletableFuture.supplyAsync {
            process.inputStream.use { it.readNBytes(CONVERT_MAX_BYTES) }
        }
        if (!process.waitFor(CONVERT_SECONDS, java.util.concurrent.TimeUnit.SECONDS)) {
            process.destroyForcibly()
            return null
        }
        val bytes = out.get(5, java.util.concurrent.TimeUnit.SECONDS)
        return if (process.exitValue() == 0 && bytes.isNotEmpty()) bytes else null
    }

    private fun squarePng(decoded: BufferedImage): ByteArray {
        val (left, top, side) = AvatarPixels.centreSquare(decoded.width, decoded.height)
        val size = AvatarPixels.OWN_SIZE
        val scaled = BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB)
        scaled.createGraphics().apply {
            setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                             RenderingHints.VALUE_INTERPOLATION_BICUBIC)
            drawImage(decoded, 0, 0, size, size, left, top, left + side, top + side, null)
            dispose()
        }
        return ByteArrayOutputStream().use { out ->
            ImageIO.write(scaled, "png", out)
            out.toByteArray()
        }
    }
}
