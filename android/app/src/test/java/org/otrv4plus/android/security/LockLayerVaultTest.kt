// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The app lock's vault layer (docs/APP_LOCK_PASSPHRASE.md). */
class LockLayerVaultTest {

    /** Stands in for Rust: "seals" by prefixing the magic and the name. */
    private class FakeLock : AppLockCrypto {
        override var unlocked = true
        override fun seal(name: String, plaintext: ByteArray): ByteArray =
            MAGIC + name.toByteArray() + byteArrayOf(0) + plaintext.map { (it.toInt() xor 0x5A).toByte() }

        override fun open(name: String, record: ByteArray): ByteArray? {
            val head = MAGIC + name.toByteArray() + byteArrayOf(0)
            if (record.size < head.size || !record.copyOfRange(0, head.size).contentEquals(head)) return null
            return record.copyOfRange(head.size, record.size).map { (it.toInt() xor 0x5A).toByte() }.toByteArray()
        }

        companion object { val MAGIC = "OTRVAI1\u0000".toByteArray() }
    }

    private val store = InMemoryVault()
    private val lock = FakeLock()
    private var enrolled = false
    private val vault = LockLayerVault(store, "vault", { enrolled }, { lock })

    @Test
    fun withoutTheLockNothingChanges() {
        vault.put("a", "plain".toByteArray())
        assertArrayEquals("plain".toByteArray(), store.get("a"))
        assertArrayEquals("plain".toByteArray(), vault.get("a"))
    }

    @Test
    fun withTheLockEveryRecordIsSealedUnderItsName() {
        enrolled = true
        vault.put("credentials", "pw".toByteArray())
        val stored = store.get("credentials")!!
        assertTrue(LockLayerVault.isSealed(stored))
        assertArrayEquals("pw".toByteArray(), vault.get("credentials"))
    }

    @Test
    fun lockedMeansAnErrorNeverAnEmptyAnswer() {
        enrolled = true
        vault.put("identity", "key".toByteArray())
        lock.unlocked = false
        for (op in listOf<() -> Unit>({ vault.get("identity") }, { vault.put("x", byteArrayOf(1)) })) {
            try { op(); fail("a locked vault answered") } catch (_: AppLockedException) {}
        }
        // A missing record is still just missing.
        assertNull(vault.get("never-written"))
    }

    @Test
    fun aRecordFromBeforeSetUpIsSealedWhenRead() {
        store.put("history", "old".toByteArray())
        enrolled = true
        assertArrayEquals("old".toByteArray(), vault.get("history"))
        assertTrue(LockLayerVault.isSealed(store.get("history")!!))
        assertArrayEquals("old".toByteArray(), vault.get("history"))
    }

    @Test
    fun setUpSealsEverythingAlreadyStored() {
        store.put("a", "1".toByteArray())
        store.put("b", "2".toByteArray())
        enrolled = true
        assertEquals(2, vault.sealEverything(listOf("a", "b", "missing")))
        assertTrue(LockLayerVault.isSealed(store.get("a")!!))
        assertEquals(0, vault.sealEverything(listOf("a", "b")))
    }

    @Test
    fun aSealedRecordMovedToAnotherNameDoesNotOpen() {
        enrolled = true
        vault.put("credentials", "pw".toByteArray())
        store.put("history", store.get("credentials")!!)
        assertNull(vault.get("history"))
    }

    @Test
    fun sealedRecordsWithNoLockRecordAreGoneNotGarbage() {
        enrolled = true
        vault.put("a", "x".toByteArray())
        enrolled = false
        assertNull(vault.get("a"))
    }

    @Test
    fun innermostSeesThroughTheLayers() {
        val keystoreStandIn = InMemoryVault()
        val layered = LatchedVault(LockLayerVault(keystoreStandIn, "vault", { false }, { null }))
        assertTrue(LockLayerVault.innermost(layered) === keystoreStandIn)
    }

    @Test
    fun passphrasesBecomeBytesWithoutAString() {
        val chars = "pässwörd".toCharArray()
        assertArrayEquals("pässwörd".toByteArray(Charsets.UTF_8), Passphrase.utf8(chars))
        assertTrue(Passphrase.same("abc".toCharArray(), "abc".toCharArray()))
        assertFalse(Passphrase.same("abc".toCharArray(), "abd".toCharArray()))
        assertEquals(null, Passphrase.problem("12345678".toCharArray(), "12345678".toCharArray()))
        assertTrue(Passphrase.problem("short".toCharArray(), "short".toCharArray())!!.contains("8"))
        assertTrue(Passphrase.problem("12345678".toCharArray(), "12345679".toCharArray())!!.contains("not the same"))
    }

    @Test
    fun autoLockIsDueAfterItsTimeAndWhenTheClockGoesBackwards() {
        assertFalse(AutoLock.due(AutoLock.MINUTES_5, 299_999))
        assertTrue(AutoLock.due(AutoLock.MINUTES_5, 300_000))
        assertTrue(AutoLock.due(AutoLock.SECONDS_30, -1))
        assertFalse(AutoLock.due(AutoLock.NEVER, Long.MAX_VALUE))
        assertEquals(AutoLock.DEFAULT, AutoLock.of("bogus"))
    }
}
