// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FileFactsTest {

    @Test
    fun `basic facts describe the file`() {
        val f = File.createTempFile("facts", ".bin").apply { writeBytes(ByteArray(2048)); deleteOnExit() }
        val facts = FileFacts.basic("photo.jpg", "Image", f, 4032, 3024).associate { it.label to it.value }
        assertEquals("2.0 KB (2048 bytes)", facts["Size"])
        assertEquals("4032 × 3024 pixels", facts["Dimensions"])
        assertNull(facts["SHA-256"], "Kotlin does no cryptography of its own")
    }

    @Test
    fun `exif facts come in order, empty ones skipped, values cleaned`() {
        val tags = mapOf("Model" to "Pixel 7", "Make" to "Google", "GPSLatitude" to "51/1,30/1,0/1",
                         "Software" to "", "UserComment" to "a‮b\u0007c")
        val facts = FileFacts.exif { tags[it] }
        assertEquals(listOf("GPS latitude", "Camera make", "Camera model", "Comment"),
                     facts.map { it.label })
        assertEquals("a b c", facts.last().value)
    }

    @Test
    fun `a long sender value is shortened`() {
        assertTrue(FileFacts.clean("x".repeat(1000)).length <= FileFacts.MAX_VALUE + 1)
    }

    @Test
    fun `a position needs both coordinates`() {
        assertEquals("51.500000, -0.120000", FileFacts.position(doubleArrayOf(51.5, -0.12))!!.value)
        assertNull(FileFacts.position(null))
    }

    @Test
    fun `pdf findings are listed one per fact`() {
        val facts = FileFacts.pdf(setOf(PdfScan.Finding.SCRIPTS, PdfScan.Finding.ATTACHMENTS))
        assertEquals(2, facts.size)
        assertTrue(FileFacts.pdf(emptySet()).single().value.startsWith("no scripts"))
    }
}
