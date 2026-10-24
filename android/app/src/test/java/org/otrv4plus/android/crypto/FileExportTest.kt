// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FileExportTest {

    @Test
    fun `the copy is byte for byte, larger than one buffer`() {
        val data = Random(7).nextBytes(200_000)
        val out = ByteArrayOutputStream()
        assertEquals(data.size.toLong(), FileExport.copy(ByteArrayInputStream(data), out))
        assertContentEquals(data, out.toByteArray())
    }

    @Test
    fun `an empty file copies as empty`() {
        val out = ByteArrayOutputStream()
        assertEquals(0L, FileExport.copy(ByteArrayInputStream(ByteArray(0)), out))
    }

    @Test
    fun `a sender's name cannot reach another directory or hide its extension`() {
        assertEquals("_.._etc_passwd", FileExport.safeName("/../etc/passwd"))
        assertEquals("photo.jpg", FileExport.safeName("photo.jpg"))
        assertEquals("file", FileExport.safeName("..."))
        assertEquals("a_b.pdf", FileExport.safeName("a‮b.pdf"))
    }

    @Test
    fun `the warning says what Wipe and Exit will not do`() {
        val w = FileExport.warning("report.pdf")
        assertTrue("Wipe & Exit does not delete it" in w)
        assertTrue("not encrypted" in w)
    }

    @Test
    fun `the result line distinguishes saved, failed and cancelled`() {
        assertTrue(FileExport.result(12)!!.startsWith("Saved (12 bytes)"))
        assertTrue("could not be saved" in FileExport.result(null)!!)
        assertNull(FileExport.result(-1))
    }
}
