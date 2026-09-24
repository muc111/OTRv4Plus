// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The viewer decides by bytes, opens only verified private files. */
class SafeViewTest {

    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun s(text: String) = text.toByteArray(Charsets.ISO_8859_1)

    @Test
    fun `kinds come from the bytes`() {
        assertEquals(SafeView.Kind.IMAGE, SafeView.kindOf(b(0xFF, 0xD8, 0xFF, 0xE0)))
        assertEquals(SafeView.Kind.IMAGE,
                     SafeView.kindOf(b(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)))
        assertEquals(SafeView.Kind.IMAGE, SafeView.kindOf(s("GIF89a....")))
        assertEquals(SafeView.Kind.IMAGE, SafeView.kindOf(s("RIFF\u0000\u0000\u0000\u0000WEBPVP8 ")))
        assertEquals(SafeView.Kind.PDF, SafeView.kindOf(s("%PDF-1.7\n")))
        assertEquals(SafeView.Kind.AUDIO, SafeView.kindOf(s("OggS\u0000")))
        assertEquals(SafeView.Kind.AUDIO, SafeView.kindOf(s("RIFF\u0000\u0000\u0000\u0000WAVEfmt ")))
        assertEquals(SafeView.Kind.VIDEO, SafeView.kindOf(s("\u0000\u0000\u0000\u0018ftypmp42")))
        assertEquals(SafeView.Kind.AUDIO, SafeView.kindOf(s("\u0000\u0000\u0000\u0018ftypM4A ")))
        assertEquals(SafeView.Kind.TEXT, SafeView.kindOf("hello, wörld\n".toByteArray()))
    }

    @Test
    fun `the name does not decide the kind`() {
        // An executable named holiday.jpg is still not an image.
        assertEquals(SafeView.Kind.UNSUPPORTED, SafeView.kindOf(s("\u007fELF\u0002\u0001\u0001")))
        assertEquals(SafeView.Kind.UNSUPPORTED, SafeView.kindOf(s("PK\u0003\u0004")))
    }

    @Test
    fun `binary is not text, and a cut multibyte tail is still text`() {
        assertFalse(SafeView.looksLikeText(b(0x41, 0x00, 0x42)))
        assertFalse(SafeView.looksLikeText(b(0x41, 0x01, 0x42)))
        val euro = "price €".toByteArray()
        assertTrue(SafeView.looksLikeText(euro.copyOf(euro.size - 1)))
        assertFalse(SafeView.looksLikeText(b(0x41, 0xC3, 0x28, 0x41)))
    }

    @Test
    fun `only a file directly inside the received directory opens`() {
        val dir = Files.createTempDirectory("recv").toFile()
        val inside = File(dir, "a.txt").apply { writeText("x") }
        val outside = Files.createTempFile("elsewhere", ".txt").toFile()
        val sub = File(dir, "sub").apply { mkdirs() }
        File(sub, "b.txt").writeText("y")
        assertTrue(SafeView.openable(inside.path, dir.path))
        assertFalse(SafeView.openable(outside.path, dir.path))
        assertFalse(SafeView.openable("${dir.path}/../${outside.name}", dir.path))
        assertFalse(SafeView.openable(File(sub, "b.txt").path, dir.path),
                    "the partial-work subdirectory is not the received directory")
        assertFalse(SafeView.openable(sub.path, dir.path))
        assertFalse(SafeView.openable("", dir.path))
        assertFalse(SafeView.openable(File(dir, "missing").path, dir.path))
    }

    @Test
    fun `the handoff warning says the file leaves the app`() {
        val w = SafeView.handoffWarning("x.pdf")
        assertTrue("another app" in w && "copy" in w && "Wipe & Exit" in w)
    }
}
