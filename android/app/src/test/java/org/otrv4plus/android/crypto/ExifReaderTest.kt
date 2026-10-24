// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** EXIF read from bytes, the same fields on desktop as on the phone. */
class ExifReaderTest {

    // A big-endian TIFF block: IFD0 (Make, Model, Artist, GPS pointer) and a
    // GPS IFD at 51°30'0" N, 0°7'30" W.
    private fun tiff(bigEndian: Boolean = true, gpsLoops: Boolean = false): ByteArray {
        val out = ByteArrayOutputStream()
        fun u16(v: Int) = if (bigEndian) { out.write(v shr 8 and 0xFF); out.write(v and 0xFF) }
                          else { out.write(v and 0xFF); out.write(v shr 8 and 0xFF) }
        fun u32(v: Long) = if (bigEndian) { u16((v shr 16).toInt()); u16((v and 0xFFFF).toInt()) }
                           else { u16((v and 0xFFFF).toInt()); u16((v shr 16).toInt()) }
        out.write(if (bigEndian) 'M'.code else 'I'.code); out.write(if (bigEndian) 'M'.code else 'I'.code)
        u16(42); u32(8)
        // IFD0 at 8: 4 entries -> 2 + 48 + 4 = 54 bytes, data from 62.
        val make = "Canon\u0000".toByteArray(Charsets.ISO_8859_1)          // 6, at 62
        val model = "EOS 5D\u0000".toByteArray(Charsets.ISO_8859_1)        // 7, at 68
        val artist = "Jane Doe\u0000".toByteArray(Charsets.ISO_8859_1)     // 9, at 75
        val gpsAt = 84L
        u16(4)
        u16(0x010F); u16(2); u32(make.size.toLong()); u32(62)
        u16(0x0110); u16(2); u32(model.size.toLong()); u32(68)
        u16(0x013B); u16(2); u32(artist.size.toLong()); u32(75)
        u16(0x8825); u16(4); u32(1); u32(if (gpsLoops) 8 else gpsAt)
        u32(0)
        out.write(make); out.write(model); out.write(artist)
        // GPS IFD at 84: 4 entries -> 54 bytes, rationals from 138.
        u16(4)
        u16(0x01); u16(2); u32(2); out.write('N'.code); out.write(0); u16(0)
        u16(0x02); u16(5); u32(3); u32(138)
        u16(0x03); u16(2); u32(2); out.write('W'.code); out.write(0); u16(0)
        u16(0x04); u16(5); u32(3); u32(162)
        u32(0)
        for ((n, d) in listOf(51L to 1L, 30L to 1L, 0L to 1L, 0L to 1L, 7L to 1L, 30L to 1L)) {
            u32(n); u32(d)
        }
        return out.toByteArray()
    }

    private fun jpeg(tiff: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0xFF.toByte(), 0xD8.toByte()))
        out.write(byteArrayOf(0xFF.toByte(), 0xE0.toByte(), 0, 4, 0, 0))      // APP0, 2 bytes
        val len = tiff.size + 8
        out.write(byteArrayOf(0xFF.toByte(), 0xE1.toByte(), (len shr 8).toByte(), len.toByte()))
        out.write("Exif".toByteArray()); out.write(0); out.write(0)
        out.write(tiff)
        out.write(byteArrayOf(0xFF.toByte(), 0xDA.toByte(), 0, 2))
        out.write(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
        return out.toByteArray()
    }

    private fun png(tiff: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(),
                              0x0D, 0x0A, 0x1A, 0x0A))
        fun chunk(type: String, data: ByteArray) {
            val n = data.size
            out.write(byteArrayOf((n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte()))
            out.write(type.toByteArray()); out.write(data); out.write(ByteArray(4))
        }
        chunk("IHDR", ByteArray(13))
        chunk("eXIf", tiff)
        chunk("IEND", ByteArray(0))
        return out.toByteArray()
    }

    private fun webp(tiff: ByteArray, prefix: Boolean): ByteArray {
        val data = if (prefix) "Exif\u0000\u0000".toByteArray(Charsets.ISO_8859_1) + tiff else tiff
        val out = ByteArrayOutputStream()
        fun le32(n: Int) = out.write(byteArrayOf(n.toByte(), (n shr 8).toByte(), (n shr 16).toByte(), (n shr 24).toByte()))
        out.write("RIFF".toByteArray()); le32(0); out.write("WEBP".toByteArray())
        out.write("VP8X".toByteArray()); le32(10); out.write(ByteArray(10))
        out.write("EXIF".toByteArray()); le32(data.size); out.write(data)
        if (data.size % 2 == 1) out.write(0)
        return out.toByteArray()
    }

    private fun assertFull(tags: ExifReader.Tags) {
        assertEquals("Canon", tags["Make"])
        assertEquals("EOS 5D", tags["Model"])
        assertEquals("Jane Doe", tags["Artist"])
        assertEquals("51/1,30/1,0/1", tags["GPSLatitude"])
        assertEquals("W", tags["GPSLongitudeRef"])
        val pos = assertNotNull(tags.latLong)
        assertEquals(51.5, pos[0], 1e-9)
        assertEquals(-0.125, pos[1], 1e-9)
    }

    @Test fun `a JPEG's EXIF and GPS are read`() = assertFull(ExifReader.read(jpeg(tiff())))
    @Test fun `little-endian TIFF reads the same`() = assertFull(ExifReader.read(jpeg(tiff(bigEndian = false))))
    @Test fun `a PNG eXIf chunk is read`() = assertFull(ExifReader.read(png(tiff())))
    @Test fun `a WebP EXIF chunk is read, with or without the Exif prefix`() {
        assertFull(ExifReader.read(webp(tiff(), prefix = false)))
        assertFull(ExifReader.read(webp(tiff(), prefix = true)))
    }

    @Test
    fun `the facts the Metadata tab shows come from it`() {
        val tags = ExifReader.read(jpeg(tiff()))
        val facts = FileFacts.exif { tags[it] }
        assertTrue(facts.any { it.label == "Camera make" && it.value == "Canon" })
        assertTrue(facts.any { it.label == "Artist" && it.value == "Jane Doe" })
        assertEquals("Position", FileFacts.position(tags.latLong)?.label)
    }

    @Test
    fun `a picture with no EXIF, or not a picture, has no tags`() {
        val bare = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xDA.toByte(), 0, 2)
        assertTrue(ExifReader.read(bare).values.isEmpty())
        assertTrue(ExifReader.read("hello".toByteArray()).values.isEmpty())
        assertNull(ExifReader.read(ByteArray(0)).latLong)
    }

    @Test
    fun `a looping IFD pointer is visited once and ends`() {
        val tags = ExifReader.read(jpeg(tiff(gpsLoops = true)))
        assertEquals("Canon", tags["Make"])
        assertNull(tags.latLong)
    }

    @Test
    fun `a truncated block gives what it can and never throws`() {
        val full = jpeg(tiff())
        for (cut in full.indices step 7) ExifReader.read(full.copyOf(cut))
    }
}
