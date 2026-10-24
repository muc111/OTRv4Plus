// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * The EXIF fields of a JPEG, PNG or WebP picture, read from its bytes.
 *
 * The desktop app has no Android `ExifInterface`, and its Metadata tab has to
 * show the same fields as the phone's ([FileFacts.EXIF_TAGS]). So this reads
 * the TIFF block itself: IFD0, the Exif IFD and the GPS IFD, and nothing
 * else. It is parsing only: no decoding of pixels, no network, nothing run.
 * Every offset is bounds-checked and each IFD is visited once, so a crafted
 * file gets an empty result rather than an exception or a loop.
 *
 * Values are spelled as `ExifInterface.getAttribute` spells them (rationals
 * as "n/d", several values comma-separated), so [FileFacts.exif] shows the
 * same text on both apps. Plain Kotlin; ExifReaderTest drives it.
 */
object ExifReader {

    /** What was found: tag name -> value, and the GPS position if complete. */
    class Tags(val values: Map<String, String>, val latLong: DoubleArray?) {
        operator fun get(tag: String): String? = values[tag]
    }

    private val EMPTY = Tags(emptyMap(), null)

    /** The longest value kept; a comment can be any length. */
    private const val MAX_VALUE_BYTES = 4096

    private val IFD0 = mapOf(
        0x010E to "ImageDescription", 0x010F to "Make", 0x0110 to "Model",
        0x0112 to "Orientation", 0x0131 to "Software", 0x0132 to "DateTime",
        0x013B to "Artist", 0x8298 to "Copyright", 0x0100 to "ImageWidth",
        0x0101 to "ImageLength",
    )
    private val EXIF = mapOf(
        0x829A to "ExposureTime", 0x829D to "FNumber", 0x8827 to "PhotographicSensitivity",
        0x9003 to "DateTimeOriginal", 0x9004 to "DateTimeDigitized",
        0x9011 to "OffsetTimeOriginal", 0x9209 to "Flash", 0x920A to "FocalLength",
        0x9286 to "UserComment", 0xA403 to "WhiteBalance", 0xA420 to "ImageUniqueID",
        0xA430 to "CameraOwnerName", 0xA431 to "BodySerialNumber", 0xA433 to "LensMake",
        0xA434 to "LensModel", 0xA435 to "LensSerialNumber",
    )
    private val GPS = mapOf(
        0x01 to "GPSLatitudeRef", 0x02 to "GPSLatitude", 0x03 to "GPSLongitudeRef",
        0x04 to "GPSLongitude", 0x06 to "GPSAltitude", 0x07 to "GPSTimeStamp",
        0x1B to "GPSProcessingMethod", 0x1D to "GPSDateStamp",
    )
    private const val EXIF_POINTER = 0x8769
    private const val GPS_POINTER = 0x8825

    /** The picture's EXIF, or no tags when it has none or is not a picture. */
    fun read(bytes: ByteArray): Tags = runCatching {
        val block = tiffBlock(bytes) ?: return EMPTY
        parseTiff(bytes, block.first, block.second)
    }.getOrDefault(EMPTY)

    /** Where the TIFF block starts and how long it is, or null. */
    internal fun tiffBlock(b: ByteArray): Pair<Int, Int>? = when {
        b.size >= 4 && u8(b, 0) == 0xFF && u8(b, 1) == 0xD8 -> jpeg(b)
        b.size >= 8 && u8(b, 0) == 0x89 && ascii(b, 1, "PNG") -> png(b)
        b.size >= 12 && ascii(b, 0, "RIFF") && ascii(b, 8, "WEBP") -> webp(b)
        else -> null
    }

    private fun jpeg(b: ByteArray): Pair<Int, Int>? {
        var i = 2
        while (i + 4 <= b.size && u8(b, i) == 0xFF) {
            val marker = u8(b, i + 1)
            if (marker == 0xFF) { i++; continue }               // fill byte
            if (marker == 0x01 || marker in 0xD0..0xD8) { i += 2; continue }
            if (marker == 0xDA || marker == 0xD9) return null   // pixels: no EXIF before them
            val len = (u8(b, i + 2) shl 8) or u8(b, i + 3)
            if (len < 2 || i + 2 + len > b.size) return null
            val start = i + 4
            if (marker == 0xE1 && len >= 8 && ascii(b, start, "Exif") &&
                u8(b, start + 4) == 0 && u8(b, start + 5) == 0) {
                return (start + 6) to (len - 8)
            }
            i += 2 + len
        }
        return null
    }

    private fun png(b: ByteArray): Pair<Int, Int>? {
        var i = 8
        while (i + 12 <= b.size) {
            val len = u32be(b, i)
            if (len < 0 || len > b.size - i - 12) return null
            if (ascii(b, i + 4, "eXIf")) return (i + 8) to len.toInt()
            if (ascii(b, i + 4, "IEND")) return null
            i += 12 + len.toInt()
        }
        return null
    }

    private fun webp(b: ByteArray): Pair<Int, Int>? {
        var i = 12
        while (i + 8 <= b.size) {
            val len = u32le(b, i + 4)
            if (len < 0 || len > b.size - i - 8) return null
            val start = i + 8
            if (ascii(b, i, "EXIF")) {
                // Some writers keep JPEG's "Exif\0\0" prefix here as well.
                return if (len >= 6 && ascii(b, start, "Exif") && u8(b, start + 4) == 0)
                    (start + 6) to (len.toInt() - 6) else start to len.toInt()
            }
            i = start + len.toInt() + (len.toInt() and 1)
        }
        return null
    }

    private class Tiff(val b: ByteArray, val base: Int, val size: Int, val le: Boolean) {
        fun ok(off: Long, n: Long) = off >= 0 && n >= 0 && off + n <= size
        fun u16(off: Int): Int = if (le) u8(b, base + off) or (u8(b, base + off + 1) shl 8)
                                 else (u8(b, base + off) shl 8) or u8(b, base + off + 1)
        fun u32(off: Int): Long = if (le) (u16(off).toLong() or (u16(off + 2).toLong() shl 16))
                                  else ((u16(off).toLong() shl 16) or u16(off + 2).toLong())
    }

    private fun parseTiff(b: ByteArray, base: Int, size: Int): Tags {
        if (size < 8 || base < 0 || base + size > b.size) return EMPTY
        val le = when {
            ascii(b, base, "II") -> true
            ascii(b, base, "MM") -> false
            else -> return EMPTY
        }
        val t = Tiff(b, base, size, le)
        if (t.u16(2) != 42) return EMPTY
        val out = LinkedHashMap<String, String>()
        val raw = HashMap<String, List<Pair<Long, Long>>>()
        val seen = HashSet<Long>()
        val pointers = ifd(t, t.u32(4), IFD0, out, raw, seen)
        pointers[EXIF_POINTER]?.let { ifd(t, it, EXIF, out, raw, seen) }
        pointers[GPS_POINTER]?.let { ifd(t, it, GPS, out, raw, seen) }
        return Tags(out, latLong(raw, out))
    }

    /** One IFD's wanted tags into [out]; returns the sub-IFD pointers it holds. */
    private fun ifd(t: Tiff, offset: Long, wanted: Map<Int, String>,
                    out: MutableMap<String, String>,
                    raw: MutableMap<String, List<Pair<Long, Long>>>,
                    seen: MutableSet<Long>): Map<Int, Long> {
        if (!seen.add(offset) || !t.ok(offset, 2)) return emptyMap()
        val count = t.u16(offset.toInt())
        if (!t.ok(offset + 2, count * 12L)) return emptyMap()
        val pointers = HashMap<Int, Long>()
        for (e in 0 until count) {
            val at = offset.toInt() + 2 + e * 12
            val tag = t.u16(at)
            val type = t.u16(at + 2)
            val n = t.u32(at + 4)
            if (tag == EXIF_POINTER || tag == GPS_POINTER) {
                pointers[tag] = t.u32(at + 8); continue
            }
            val name = wanted[tag] ?: continue
            val unit = when (type) { 1, 2, 7 -> 1; 3 -> 2; 4, 9 -> 4; 5, 10 -> 8; else -> continue }
            val bytes = n * unit
            if (n <= 0 || bytes > MAX_VALUE_BYTES) continue
            val data = if (bytes <= 4) at + 8 else t.u32(at + 8).toInt()
            if (!t.ok(data.toLong(), bytes)) continue
            val value = when (type) {
                2 -> String(t.b, t.base + data, bytes.toInt(), Charsets.ISO_8859_1)
                         .substringBefore('\u0000').trim()
                7 -> undefined(t, data, bytes.toInt(), name)
                1 -> (0 until n.toInt()).joinToString(",") { u8(t.b, t.base + data + it).toString() }
                3 -> (0 until n.toInt()).joinToString(",") { t.u16(data + it * 2).toString() }
                4 -> (0 until n.toInt()).joinToString(",") { t.u32(data + it * 4).toString() }
                9 -> (0 until n.toInt()).joinToString(",") { t.u32(data + it * 4).toInt().toString() }
                else -> {
                    val pairs = (0 until n.toInt()).map {
                        val num = t.u32(data + it * 8)
                        val den = t.u32(data + it * 8 + 4)
                        if (type == 10) num.toInt().toLong() to den.toInt().toLong() else num to den
                    }
                    raw[name] = pairs
                    pairs.joinToString(",") { "${it.first}/${it.second}" }
                }
            }
            if (value != null && value.isNotBlank()) out[name] = value
        }
        return pointers
    }

    /** UserComment and GPSProcessingMethod: an 8-byte charset code, then text. */
    private fun undefined(t: Tiff, data: Int, len: Int, name: String): String? {
        if (name != "UserComment" && name != "GPSProcessingMethod") return null
        if (len <= 8) return null
        val code = String(t.b, t.base + data, 8, Charsets.ISO_8859_1)
        val body = t.base + data + 8
        val text = if (code.startsWith("UNICODE")) {
            String(t.b, body, len - 8, if (t.le) Charsets.UTF_16LE else Charsets.UTF_16BE)
        } else {
            String(t.b, body, len - 8, Charsets.UTF_8)
        }
        return text.trim('\u0000', ' ')
    }

    private fun latLong(raw: Map<String, List<Pair<Long, Long>>>,
                        out: Map<String, String>): DoubleArray? {
        fun degrees(tag: String, ref: String, negative: String): Double? {
            val parts = raw[tag]?.takeIf { it.size == 3 } ?: return null
            if (parts.any { it.second == 0L }) return null
            val (d, m, s) = parts.map { it.first.toDouble() / it.second }
            val v = d + m / 60 + s / 3600
            return if (out[ref]?.trim()?.uppercase() == negative) -v else v
        }
        val lat = degrees("GPSLatitude", "GPSLatitudeRef", "S") ?: return null
        val lon = degrees("GPSLongitude", "GPSLongitudeRef", "W") ?: return null
        if (lat !in -90.0..90.0 || lon !in -180.0..180.0) return null
        return doubleArrayOf(lat, lon)
    }

    private fun u8(b: ByteArray, i: Int): Int = b[i].toInt() and 0xFF
    private fun ascii(b: ByteArray, i: Int, s: String): Boolean =
        i >= 0 && i + s.length <= b.size && s.indices.all { b[i + it] == s[it].code.toByte() }
    private fun u32be(b: ByteArray, i: Int): Long =
        (u8(b, i).toLong() shl 24) or (u8(b, i + 1).toLong() shl 16) or
            (u8(b, i + 2).toLong() shl 8) or u8(b, i + 3).toLong()
    private fun u32le(b: ByteArray, i: Int): Long =
        u8(b, i).toLong() or (u8(b, i + 1).toLong() shl 8) or
            (u8(b, i + 2).toLong() shl 16) or (u8(b, i + 3).toLong() shl 24)
}
