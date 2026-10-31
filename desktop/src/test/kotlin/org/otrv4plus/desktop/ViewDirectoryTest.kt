// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import org.otrv4plus.desktop.ui.viewDirectory
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The viewer's decrypted copy goes to RAM where the system has a place for it. */
class ViewDirectoryTest {

    @Test
    fun theLoginSessionsRamDirectoryComesFirst() {
        val d = viewDirectory(env = { if (it == "XDG_RUNTIME_DIR") "/run/user/1000" else null },
                              home = "/home/a", isDir = { true })
        assertEquals(File("/run/user/1000/otrv4plus-view"), d)
    }

    @Test
    fun devShmWhenThereIsNoSessionDirectory() {
        val d = viewDirectory(env = { null }, home = "/home/a", isDir = { it.path == "/dev/shm" })
        assertTrue(d.path.startsWith("/dev/shm/otrv4plus-view"))
    }

    @Test
    fun aRelativeRuntimeDirIsIgnored() {
        val d = viewDirectory(env = { "relative" }, home = "/home/a", isDir = { it.path != "/dev/shm" })
        assertEquals(File("/home/a", ".otrv4plus${File.separator}view"), d)
    }

    @Test
    fun withNoRamFilesystemItFallsBackBesideTheFiles() {
        val d = viewDirectory(env = { null }, home = "/home/a", isDir = { false })
        assertEquals(File("/home/a", ".otrv4plus${File.separator}view"), d)
    }
}
