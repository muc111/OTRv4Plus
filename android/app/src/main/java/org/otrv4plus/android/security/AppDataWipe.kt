// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * Wipe & Exit, storage stage: everything the app owns on disk, measured and
 * removed. Plain Kotlin on java.nio, so it is tested by being run.
 *
 * WHY THIS REPLACED A LIST OF KNOWN FILES
 * ---------------------------------------
 * A handset measured ~11.28 MB of user data and ~254 KB of cache left after
 * Wipe & Exit. The wipe deleted what it knew about -- the vault directory,
 * the contents of `cache/`, and `~/.otrv4plus` from Python -- and kept, by
 * design, `files/chaquopy/` (the extracted Python runtime, most of those
 * megabytes) and `shared_prefs/`. It never looked at `code_cache/` (counted
 * as cache by Settings), `databases/`, `no_backup/`, `app_*` directories a
 * library creates with getDir(), or app-specific external storage. A
 * whitelist of known paths is exactly the design that lets the next
 * persistent file escape.
 *
 * So this walks the app's ROOTS -- its private data directory and its
 * app-specific external directories -- and removes every entry under them.
 * Nothing is kept for being "configuration": the Python runtime is
 * re-extracted on the next launch and the theme returns to its default.
 *
 * WHAT IT WILL NOT TOUCH
 * ----------------------
 *  * Symbolic links are never FOLLOWED. A link inside the tree is removed as
 *    a link; what it points at is left alone, so a link planted in app
 *    storage cannot turn the wipe into deletion of something else.
 *  * A top-level `lib` link in the data directory is the system's pointer to
 *    the installed native libraries (owned by the package manager, read-only
 *    to the app). It is preserved, and reported as preserved.
 *  * Files the user explicitly saved to shared storage (Downloads, a
 *    document picker target) are the user's, outside every root, and stay.
 *
 * WHAT "REMOVED" MEANS
 * --------------------
 * Unlinked. Android app storage is under file-based encryption, and the
 * vault's records are sealed under an AndroidKeyStore key that the vault
 * step deletes (cryptographic erasure). Nothing here claims physical erasure
 * of flash: wear levelling can keep old blocks until the controller erases
 * them. Python has already overwritten what it wrote, best effort, before
 * this runs.
 */
object AppDataWipe {

    /** One file or directory, as measured. [path] is relative to its root. */
    data class Entry(val root: String, val path: String, val bytes: Long, val directory: Boolean)

    /** What was on disk at one moment. */
    data class Inventory(val entries: List<Entry>) {
        val totalBytes: Long get() = entries.filterNot { it.directory }.sumOf { it.bytes }
        val fileCount: Int get() = entries.count { !it.directory }

        /** Bytes per top-level directory under each root ("files", "cache", ...). */
        val byTopLevel: Map<String, Long>
            get() = entries.filterNot { it.directory }
                .groupBy { it.root + ":" + it.path.substringBefore('/') }
                .mapValues { (_, v) -> v.sumOf { it.bytes } }
                .toSortedMap()
    }

    data class Result(
        val before: Inventory,
        val after: Inventory,
        /** Entries that could not be removed (relative paths). */
        val failed: List<String>,
        /** Entries deliberately left: the system `lib` link. */
        val preserved: List<String>,
    ) {
        /** Nothing is left but what is preserved on purpose. */
        val complete: Boolean get() = failed.isEmpty() && after.entries.isEmpty()
    }

    /** The top-level names in the data directory that belong to the system. */
    val SYSTEM_OWNED = setOf("lib")

    private fun isLink(p: Path) = Files.isSymbolicLink(p)

    /** Measure a root without following links. A missing root is empty. */
    fun inventory(roots: List<Path>, skipTopLevel: Set<String> = SYSTEM_OWNED): Inventory {
        val out = mutableListOf<Entry>()
        for (root in roots) {
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) continue
            val children = runCatching { Files.list(root).use { it.toList() } }.getOrDefault(emptyList())
            for (child in children.sorted()) {
                if (child.fileName.toString() in skipTopLevel && isLink(child)) continue
                walk(root, child, out)
            }
        }
        return Inventory(out)
    }

    private fun walk(root: Path, p: Path, out: MutableList<Entry>) {
        val rel = root.relativize(p).toString().replace('\\', '/')
        val link = isLink(p)
        val dir = !link && Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)
        val size = if (dir || link) 0L else runCatching { Files.size(p) }.getOrDefault(0L)
        out += Entry(root.toString(), rel, size, dir)
        if (dir) {
            val children = runCatching { Files.list(p).use { it.toList() } }.getOrDefault(emptyList())
            for (c in children.sorted()) walk(root, c, out)
        }
    }

    /**
     * Remove everything under every root. Never follows a link, never
     * throws, and attempts every entry even after a failure.
     */
    fun wipe(roots: List<Path>, keepTopLevel: Set<String> = SYSTEM_OWNED): Result {
        val before = inventory(roots, keepTopLevel)
        val failed = mutableListOf<String>()
        val preserved = mutableListOf<String>()
        for (root in roots) {
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) continue
            val children = runCatching { Files.list(root).use { it.toList() } }.getOrDefault(emptyList())
            for (child in children) {
                val name = child.fileName.toString()
                if (name in keepTopLevel && isLink(child)) {
                    preserved += "$root:$name"
                    continue
                }
                remove(child, root, failed)
            }
        }
        val after = inventory(roots, keepTopLevel)
        return Result(before, after, failed, preserved)
    }

    private fun remove(p: Path, root: Path, failed: MutableList<String>) {
        if (!isLink(p) && Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
            val children = runCatching { Files.list(p).use { it.toList() } }.getOrDefault(emptyList())
            for (c in children) remove(c, root, failed)
        }
        try {
            Files.deleteIfExists(p)          // a link is deleted as a link
        } catch (e: IOException) {
            failed += root.relativize(p).toString()
        } catch (e: SecurityException) {
            failed += root.relativize(p).toString()
        }
    }

    /** A short human summary for diagnostics: sizes only, never names. */
    fun summary(result: Result): String =
        "before: %d files, %d bytes; after: %d entries, %d bytes; failed: %d; preserved: %s".format(
            result.before.fileCount, result.before.totalBytes,
            result.after.entries.size, result.after.totalBytes,
            result.failed.size, result.preserved.map { it.substringAfterLast(':') })
}
