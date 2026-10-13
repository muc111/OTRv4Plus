// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * A contact's avatar as pixel NUMBERS, never as an image file.
 *
 * The Python bridge (`android_bridge/avatar.py`) is the only code that reads
 * a peer's picture: PNG only, size- and dimension-capped, hash-checked and
 * decoded in bounded pure Python. What arrives here is raw RGBA, which this
 * turns into the `IntArray` that `Bitmap.createBitmap(int[], …)` takes -- so
 * no Android image decoder (Skia, libpng, libjpeg, libwebp) ever parses bytes
 * a peer chose. A crafted image aimed at one has nothing to aim at.
 *
 * Plain Kotlin, no Android import, so it is tested by being run.
 */
object AvatarPixels {

    /** The bridge's MAX_DIMENSION; anything larger is refused here too. */
    const val MAX_SIDE = 256

    /** The size our own picture is scaled to before it is published. */
    const val OWN_SIZE = 96

    /**
     * 0xAARRGGBB per pixel, or null when the dimensions are out of range or
     * do not match the data -- a mismatch is never "fixed up".
     */
    fun argb(rgba: ByteArray, width: Int, height: Int): IntArray? {
        if (width !in 1..MAX_SIDE || height !in 1..MAX_SIDE) return null
        if (rgba.size != width * height * 4) return null
        val out = IntArray(width * height)
        for (i in out.indices) {
            val o = i * 4
            val r = rgba[o].toInt() and 0xFF
            val g = rgba[o + 1].toInt() and 0xFF
            val b = rgba[o + 2].toInt() and 0xFF
            val a = rgba[o + 3].toInt() and 0xFF
            out[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
        }
        return out
    }

    /** Lines of "jid<TAB>id" from the bridge, as a map; malformed lines dropped. */
    fun index(lines: List<String>): Map<String, String> =
        lines.mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size != 2) return@mapNotNull null
            val jid = parts[0].trim().lowercase()
            val id = parts[1].trim().lowercase()
            if (jid.isEmpty() || id.length != 40 ||
                !id.all { it in '0'..'9' || it in 'a'..'f' }) null
            else jid to id
        }.toMap()

    /**
     * The centred square of a [width] x [height] picture, as
     * (left, top, side): what our own avatar is cropped to before scaling.
     */
    fun centreSquare(width: Int, height: Int): Triple<Int, Int, Int> {
        val side = minOf(width, height)
        return Triple((width - side) / 2, (height - side) / 2, side)
    }

    /**
     * The decode sample size (a power of two) that keeps a [width] x
     * [height] picture at least [target] on its short side: our own picture
     * is decoded at a fraction of its size, never in full.
     */
    fun sampleSize(width: Int, height: Int, target: Int = OWN_SIZE): Int {
        var sample = 1
        val short = minOf(width, height)
        while (short / (sample * 2) >= target && sample < 1024) sample *= 2
        return sample
    }
}
