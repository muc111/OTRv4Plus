// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Settings → Diagnostics → Save diagnostic report writes a file only its owner can read. */
class DiagnosticReportFileTest {

    @Test
    fun itGoesToDownloadsWhenThereIsOneElseHome() {
        val home = Files.createTempDirectory("home").toFile()
        assertEquals(home, reportDirectory(home))
        val downloads = java.io.File(home, "Downloads").apply { mkdir() }
        assertEquals(downloads, reportDirectory(home))
    }

    @Test
    fun theFileIsOwnerOnlyAndNamedLikeThePhones() {
        val dir = Files.createTempDirectory("reports").toFile()
        val file = writeReport("OTRv4+ diagnostic report\nbody\n", dir)
        assertTrue(Regex("otrv4plus-log-\\d{8}-\\d{6}\\.txt").matches(file.name), file.name)
        assertEquals("OTRv4+ diagnostic report\nbody\n", file.readText())
        assertEquals("rw-------",
                     PosixFilePermissions.toString(Files.getPosixFilePermissions(file.toPath())))
    }
}
