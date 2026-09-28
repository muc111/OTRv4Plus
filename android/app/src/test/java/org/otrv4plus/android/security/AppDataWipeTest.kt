// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The storage stage of Wipe & Exit against a directory laid out the way
 * Android lays out /data/data/<package>, populated with what the app and its
 * libraries actually write there.
 *
 * Device report: ~11.28 MB of user data and ~254 KB of cache survived the old
 * wipe, which deleted a list of known paths and kept the Python runtime and
 * shared_prefs on purpose. These tests hold the sweep to "nothing left but
 * the system's lib link", measured before and after.
 */
class AppDataWipeTest {

    private fun write(p: Path, bytes: Int) {
        Files.createDirectories(p.parent)
        Files.write(p, ByteArray(bytes) { (it % 251).toByte() })
    }

    /** A realistic app data directory, plus things outside it. */
    private class Layout(val data: Path, val external: Path, val outside: Path)

    private fun populate(): Layout {
        val base = Files.createTempDirectory("appdata")
        val data = base.resolve("data/org.otrv4plus.android")
        val external = base.resolve("sdcard/Android/data/org.otrv4plus.android")
        val outside = base.resolve("system/app/lib/arm64")
        write(outside.resolve("libotrv4_core.so"), 4096)
        write(base.resolve("sdcard/Download/saved-by-user.jpg"), 2048)
        // The Python runtime Chaquopy extracts: the bulk of the residue.
        write(data.resolve("files/chaquopy/bootstrap.imy"), 3_000_000)
        write(data.resolve("files/chaquopy/stdlib-common.imy"), 6_000_000)
        write(data.resolve("files/chaquopy/requirements-arm64.imy"), 2_000_000)
        // The vault and the Python home.
        write(data.resolve("files/vault/chat.alice.idx"), 4096)
        write(data.resolve("files/vault/account.credentials"), 512)
        write(data.resolve("files/.otrv4plus/files/photo.jpg"), 150_000)
        write(data.resolve("files/.otrv4plus/files/.incoming/partial.bin"), 30_000)
        // Everything else Android and libraries create.
        write(data.resolve("cache/outbox/send.bin"), 100_000)
        write(data.resolve("cache/diagnostics/report.txt"), 1_000)
        write(data.resolve("code_cache/startup_agents/x.dex"), 150_000)
        write(data.resolve("databases/androidx.work.db"), 40_960)
        write(data.resolve("databases/androidx.work.db-wal"), 8_192)
        write(data.resolve("shared_prefs/otrv4plus.ui.xml"), 128)
        write(data.resolve("no_backup/androidx.work.workdb.lck"), 0)
        write(data.resolve("app_webview/Default/Cookies"), 20_480)
        write(external.resolve("files/export.otrv"), 64_000)
        write(external.resolve("cache/tmp.bin"), 4_000)
        // The system's link to the installed native libraries.
        Files.createSymbolicLink(data.resolve("lib"), outside)
        // A link planted inside app storage, pointing outside it.
        Files.createSymbolicLink(data.resolve("files/escape"), outside)
        return Layout(data, external, outside)
    }

    @Test
    fun `everything the app owns is removed, measured before and after`() {
        val l = populate()
        val result = AppDataWipe.wipe(listOf(l.data, l.external))
        assertTrue(result.before.totalBytes > 11_000_000, "the fixture is not realistic")
        assertTrue(result.before.byTopLevel.keys.any { it.endsWith(":files") })
        assertTrue(result.before.byTopLevel.keys.any { it.endsWith(":code_cache") })
        assertEquals(0L, result.after.totalBytes)
        assertTrue(result.after.entries.isEmpty(), "left: ${result.after.entries}")
        assertTrue(result.failed.isEmpty())
        assertTrue(result.complete)
        for (name in listOf("files", "cache", "code_cache", "databases", "shared_prefs",
                            "no_backup", "app_webview")) {
            assertFalse(Files.exists(l.data.resolve(name)), "$name survived")
        }
    }

    @Test
    fun `links are never followed`() {
        val l = populate()
        AppDataWipe.wipe(listOf(l.data, l.external))
        // The system lib link is kept, and neither link's target was touched.
        assertTrue(Files.isSymbolicLink(l.data.resolve("lib")))
        assertTrue(Files.exists(l.outside.resolve("libotrv4_core.so")),
                   "a link inside app storage turned the wipe onto something else")
        assertFalse(Files.exists(l.data.resolve("files/escape")), "the planted link survived")
    }

    @Test
    fun `the lib link is reported as preserved and nothing else is`() {
        val l = populate()
        val result = AppDataWipe.wipe(listOf(l.data, l.external))
        assertEquals(listOf("lib"), result.preserved.map { it.substringAfterLast(':') })
    }

    @Test
    fun `files the user saved to shared storage are not app data`() {
        val l = populate()
        AppDataWipe.wipe(listOf(l.data, l.external))
        val saved = l.external.parent.parent.parent.resolve("Download/saved-by-user.jpg")
        assertTrue(Files.exists(saved))
    }

    @Test
    fun `a second wipe finds nothing and fails nothing`() {
        val l = populate()
        AppDataWipe.wipe(listOf(l.data, l.external))
        val again = AppDataWipe.wipe(listOf(l.data, l.external))
        assertEquals(0, again.before.fileCount)
        assertTrue(again.complete)
    }

    @Test
    fun `a missing root is simply empty`() {
        val base = Files.createTempDirectory("appdata")
        val result = AppDataWipe.wipe(listOf(base.resolve("nope")))
        assertTrue(result.complete)
        assertEquals(0, result.before.entries.size)
    }

    @Test
    fun `the summary carries sizes and never a file name`() {
        val l = populate()
        val text = AppDataWipe.summary(AppDataWipe.wipe(listOf(l.data, l.external)))
        assertTrue("before:" in text && "after: 0 entries, 0 bytes" in text, text)
        for (name in listOf("chat.alice", "photo", "account", "export")) {
            assertFalse(name in text, "the summary names $name")
        }
    }
}
