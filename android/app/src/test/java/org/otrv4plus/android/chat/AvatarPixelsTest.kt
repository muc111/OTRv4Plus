// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AvatarPixelsTest {

    @Test
    fun `rgba becomes argb, alpha in the top byte`() {
        val rgba = byteArrayOf(
            0x11, 0x22, 0x33, 0xFF.toByte(),
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0x80.toByte(),
        )
        val argb = AvatarPixels.argb(rgba, 2, 1)!!
        assertContentEquals(intArrayOf(0xFF112233.toInt(), 0x80AABBCC.toInt()), argb)
    }

    @Test
    fun `a size mismatch is refused, never fixed up`() {
        assertNull(AvatarPixels.argb(ByteArray(15), 2, 2))
        assertNull(AvatarPixels.argb(ByteArray(17), 2, 2))
    }

    @Test
    fun `dimensions outside the bridge's limits are refused`() {
        assertNull(AvatarPixels.argb(ByteArray(0), 0, 0))
        assertNull(AvatarPixels.argb(ByteArray(257 * 4), 257, 1))
        assertNull(AvatarPixels.argb(ByteArray(4), -1, -1))
    }

    @Test
    fun `the index keeps only well-formed lines`() {
        val id = "0123456789abcdef0123456789abcdef01234567"
        val map = AvatarPixels.index(listOf(
            "Bob@x.i2p\t$id",
            "eve@x.i2p\tnot-a-hash",
            "no tab here",
            "a\tb\tc",
        ))
        assertEquals(mapOf("bob@x.i2p" to id), map)
    }

    @Test
    fun `own picture is centre-cropped and decoded small`() {
        assertEquals(Triple(100, 0, 300), AvatarPixels.centreSquare(500, 300))
        assertEquals(Triple(0, 50, 200), AvatarPixels.centreSquare(200, 300))
        assertEquals(1, AvatarPixels.sampleSize(150, 150))
        assertEquals(16, AvatarPixels.sampleSize(4000, 3000))
    }
}
