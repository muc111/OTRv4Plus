// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.util.zip.CRC32
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HiddenDataTest {

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /** SOI, an APP1 segment holding a whole thumbnail JPEG (with its own
     *  EOI), a quantisation table, SOS with entropy data containing a stuffed
     *  FF00 and a restart marker, then EOI. */
    private fun jpeg(): ByteArray {
        val thumb = b(0xFF, 0xD8, 0x11, 0x22, 0xFF, 0xD9)
        val app1 = b(0xFF, 0xE1, 0x00, 2 + thumb.size) + thumb
        val dqt = b(0xFF, 0xDB, 0x00, 0x04, 0x00, 0x01)
        val sos = b(0xFF, 0xDA, 0x00, 0x03, 0x01)
        val entropy = b(0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD3, 0x56)
        return b(0xFF, 0xD8) + app1 + dqt + sos + entropy + b(0xFF, 0xD9)
    }

    private fun chunk(type: String, data: ByteArray): ByteArray {
        val t = type.toByteArray(Charsets.ISO_8859_1)
        val crc = CRC32().apply { update(t); update(data) }.value
        val len = data.size
        return b(len ushr 24, (len ushr 16) and 0xFF, (len ushr 8) and 0xFF, len and 0xFF) +
            t + data + b((crc ushr 24).toInt() and 0xFF, (crc ushr 16).toInt() and 0xFF,
                         (crc ushr 8).toInt() and 0xFF, crc.toInt() and 0xFF)
    }

    private fun png(): ByteArray =
        b(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) +
            chunk("IHDR", ByteArray(13)) + chunk("IDAT", b(1, 2, 3)) + chunk("IEND", ByteArray(0))

    @Test
    fun `a clean JPEG ends at its own EOI, not the thumbnail's`() {
        val img = jpeg()
        val r = HiddenData.scan(img)
        assertEquals(HiddenData.Status.NOTHING_APPENDED, r.status)
        assertEquals(img.size, r.pictureEnd)
    }

    @Test
    fun `a ZIP appended to a JPEG is found and named`() {
        val img = jpeg()
        val zip = b(0x50, 0x4B, 0x03, 0x04) + ByteArray(40) { 7 }
        val r = HiddenData.scan(img + zip)
        assertEquals(HiddenData.Status.APPENDED, r.status)
        assertEquals(img.size, r.pictureEnd)
        assertEquals(zip.size, r.appendedBytes)
        assertTrue("ZIP" in r.looksLike!!)
        assertTrue("${zip.size} bytes" in HiddenData.describe(r))
    }

    @Test
    fun `text after a PNG's IEND is found`() {
        val img = png()
        val r = HiddenData.scan(img + "meet at the usual place\n".toByteArray())
        assertEquals(HiddenData.Status.APPENDED, r.status)
        assertEquals(img.size, r.pictureEnd)
        assertEquals("text", r.looksLike)
        assertEquals(HiddenData.Status.NOTHING_APPENDED, HiddenData.scan(img).status)
    }

    @Test
    fun `a WebP's RIFF length marks its end`() {
        val body = "WEBP".toByteArray() + ByteArray(9)
        val size = body.size
        val img = "RIFF".toByteArray() + b(size, 0, 0, 0) + body + ByteArray(1)
        assertEquals(HiddenData.Status.NOTHING_APPENDED, HiddenData.scan(img).status)
        val r = HiddenData.scan(img + ByteArray(8))
        assertEquals("zero padding", r.looksLike)
    }

    @Test
    fun `a truncated or unknown file is reported as not checked, not clean`() {
        val cut = jpeg().copyOf(12)
        assertEquals(HiddenData.Status.NOT_CHECKED, HiddenData.scan(cut).status)
        assertEquals(HiddenData.Status.NOT_CHECKED, HiddenData.scan(b(1, 2, 3, 4)).status)
        assertTrue("not checked" in HiddenData.describe(HiddenData.scan(cut)))
    }

    @Test
    fun `a PNG chunk length past the end does not overflow`() {
        val bad = b(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                    0xFF, 0xFF, 0xFF, 0xF0) + "IDAT".toByteArray() + ByteArray(8)
        assertEquals(HiddenData.Status.NOT_CHECKED, HiddenData.scan(bad).status)
    }
}
