// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.otrv4plus.android.crypto.PdfScan.Finding

class PdfScanTest {

    private fun scan(text: String) = PdfScan.scan(text.toByteArray(Charsets.ISO_8859_1))

    private val plain = "%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n" +
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n" +
        "3 0 obj << /Type /Page /MediaBox [0 0 612 792] /Font << /F1 4 0 R >> >> endobj\n%%EOF"

    @Test
    fun `a plain document has nothing to report`() {
        assertEquals(emptySet(), scan(plain))
        assertNull(PdfScan.summary(scan(plain)))
        assertNull(PdfScan.handoffNote(scan(plain)))
    }

    @Test
    fun `scripts and opening actions are found`() {
        val found = scan(plain + "<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
        assertEquals(setOf(Finding.SCRIPTS, Finding.AUTO_ACTIONS), found)
    }

    @Test
    fun `escaped names are decoded before matching`() {
        // "/J#61vaScript" is "/JavaScript" to a PDF reader.
        assertEquals(setOf(Finding.SCRIPTS), scan(plain + "<< /S /J#61vaScript >>"))
        assertEquals(setOf(Finding.LAUNCH), scan(plain + "<< /S /#4C#61unch >>"))
    }

    @Test
    fun `every risky kind is named`() {
        val found = scan(plain + "/Launch /EmbeddedFiles /URI /SubmitForm /RichMedia /XFA /AA")
        assertEquals(setOf(Finding.LAUNCH, Finding.ATTACHMENTS, Finding.OUTBOUND,
                           Finding.RICH_MEDIA, Finding.AUTO_ACTIONS), found)
    }

    @Test
    fun `compressed object streams are never reported as clean`() {
        assertEquals(setOf(Finding.HIDDEN), scan(plain + "<< /Type /ObjStm /N 5 >>"))
        assertEquals(setOf(Finding.HIDDEN),
                     PdfScan.scan(plain.toByteArray(), complete = false))
    }

    @Test
    fun `the words reach the screen and the handoff warning`() {
        val found = setOf(Finding.SCRIPTS)
        val line = assertNotNull(PdfScan.summary(found))
        assertTrue("scripts" in line && "None of it runs here" in line, line)
        assertTrue("scripts" in assertNotNull(PdfScan.handoffNote(found)))
    }

    @Test
    fun `a file is read only up to the limit`() {
        val f = java.io.File.createTempFile("scan", ".pdf")
        try {
            f.writeText(plain + " /JavaScript")
            assertEquals(setOf(Finding.SCRIPTS), PdfScan.scan(f))
        } finally {
            f.delete()
        }
    }
}
