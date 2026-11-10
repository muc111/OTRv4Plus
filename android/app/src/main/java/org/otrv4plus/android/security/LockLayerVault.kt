// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

/**
 * The app lock's layer over a [Vault] (docs/APP_LOCK_PASSPHRASE.md).
 *
 * Once the app lock has been set up, every record is sealed by Rust under a
 * subkey of the 256-bit data key BEFORE the Keystore layer seals it again.
 * The data key never enters Kotlin: [AppLockCrypto] passes the bytes to
 * Rust and back.
 *
 * Locked means unreadable, and it is said, not hidden: every read and write
 * throws [AppLockedException]. A vault that answered "nothing stored" while
 * locked would invite the code above it to start afresh -- a new identity
 * key over the sealed one (F3) -- and that must never happen.
 *
 * Records written before the lock was set up are read once more (only while
 * unlocked) and sealed on the spot; [sealEverything] does all of them at
 * set-up. Before any set-up the layer passes everything straight through,
 * so an app that never uses the lock behaves exactly as before.
 *
 * Plain Kotlin: tested on the JVM with a fake [AppLockCrypto].
 */
class LockLayerVault(
    val inner: Vault,
    private val section: String,
    private val enrolled: () -> Boolean,
    private val crypto: () -> AppLockCrypto?,
) : Vault {

    override fun put(name: String, bytes: ByteArray) {
        if (!enrolled()) return inner.put(name, bytes)
        inner.put(name, ready().seal(key(name), bytes))
    }

    override fun get(name: String): ByteArray? {
        val raw = inner.get(name) ?: return null
        val sealed = isSealed(raw)
        if (!enrolled()) {
            // Sealed records with no lock record mean the lock record was
            // lost: they cannot be opened by anyone, so they are not there.
            return if (sealed) null else raw
        }
        val lock = ready()
        if (sealed) return lock.open(key(name), raw)
        // From before the lock was set up: seal it now, keep reading it.
        runCatching { inner.put(name, lock.seal(key(name), raw)) }
        return raw
    }

    override fun remove(name: String) = inner.remove(name)

    override fun clear() = inner.clear()

    /** Seal every record of this section still stored without the layer.
     *  Returns how many were sealed. Needs the inner vault to list names. */
    fun sealEverything(names: List<String>): Int {
        val lock = ready()
        var count = 0
        for (name in names) {
            val raw = inner.get(name) ?: continue
            if (isSealed(raw)) continue
            inner.put(name, lock.seal(key(name), raw))
            raw.fill(0)
            count++
        }
        return count
    }

    private fun key(name: String) = "$section/$name"

    private fun ready(): AppLockCrypto {
        val lock = crypto() ?: throw AppLockedException()
        if (!lock.unlocked) throw AppLockedException()
        return lock
    }

    companion object {
        /** The inner layer's magic (Rust app_lock.rs VAULT_MAGIC). */
        private val MAGIC = "OTRVAI1\u0000".toByteArray(Charsets.US_ASCII)

        fun isSealed(record: ByteArray): Boolean =
            record.size >= MAGIC.size && MAGIC.indices.all { record[it] == MAGIC[it] }

        /** The vault under any layering ([LatchedVault], this). */
        fun innermost(vault: Vault): Vault = when (vault) {
            is LockLayerVault -> innermost(vault.inner)
            is LatchedVault -> innermost(vault.inner)
            else -> vault
        }
    }
}

/** The Rust side of the layer. Implemented over Chaquopy (AppLock). */
interface AppLockCrypto {
    val unlocked: Boolean
    fun seal(name: String, plaintext: ByteArray): ByteArray
    /** Null when the record does not open (damaged, or another key). */
    fun open(name: String, record: ByteArray): ByteArray?
}

/** The app is locked: nothing sealed can be read or written until unlock. */
class AppLockedException : IllegalStateException("the app is locked")

/**
 * A passphrase as UTF-8 bytes, without ever making a String: the chars are
 * encoded straight into a byte array, and the encoder's buffer and the chars
 * are zeroed. The caller zeroes the returned array once used.
 */
object Passphrase {
    /** Fewer characters than this are refused at set-up. */
    const val MIN_LENGTH = 8

    fun utf8(chars: CharArray): ByteArray {
        val buffer = Charsets.UTF_8.newEncoder()
            .encode(java.nio.CharBuffer.wrap(chars))
        val out = ByteArray(buffer.remaining())
        buffer.get(out)
        if (buffer.hasArray()) buffer.array().fill(0)
        return out
    }

    /** Whether [a] and [b] hold the same characters, in constant time. */
    fun same(a: CharArray, b: CharArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    /** What is wrong with a new passphrase, or null when it is acceptable. */
    fun problem(new: CharArray, again: CharArray): String? = when {
        new.size < MIN_LENGTH -> "Use at least $MIN_LENGTH characters."
        !same(new, again) -> "The two passphrases are not the same."
        else -> null
    }
}

/** How long the app may stay in the background before it locks. */
enum class AutoLock(val millis: Long, val label: String) {
    SECONDS_30(30_000L, "30 seconds"),
    MINUTE_1(60_000L, "1 minute"),
    MINUTES_5(5 * 60_000L, "5 minutes"),
    MINUTES_15(15 * 60_000L, "15 minutes"),
    HOUR_1(60 * 60_000L, "1 hour"),
    NEVER(-1L, "Only when I lock it"),
    ;

    companion object {
        val DEFAULT = MINUTES_5
        fun of(name: String?): AutoLock = entries.firstOrNull { it.name == name } ?: DEFAULT

        /**
         * Whether a background stay of [awayMillis] locks under [choice]. A
         * negative stay (the clock went backwards) locks: failing closed
         * costs one passphrase, failing open costs the lock.
         */
        fun due(choice: AutoLock, awayMillis: Long): Boolean =
            choice != NEVER && (awayMillis < 0 || awayMillis >= choice.millis)
    }
}
