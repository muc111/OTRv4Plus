// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

/**
 * Somewhere to put bytes that must not be readable from the disk.
 *
 * WHY AN INTERFACE
 * ----------------
 * The only implementation that matters is [KeystoreVault], which cannot be
 * constructed or executed outside an Android build -- `AndroidKeyStore` is a
 * platform provider. Everything that decides WHAT to store, WHEN to clear it
 * and HOW it is encoded lives above this line in plain Kotlin, where it has
 * real unit tests; below it is one small class whose whole job is
 * `Cipher.doFinal`.
 *
 * That split is deliberate and has already earned itself twice on this branch.
 * Logic that can only run on a device is logic that gets checked by reading it.
 *
 * THE CONTRACT
 * ------------
 * * [put] replaces. There is no append.
 * * [get] returns null for absent, AND for anything it cannot open --
 *   wrong key, tampered record, truncated file, a key the user has
 *   invalidated by changing their lock screen. The caller cannot tell those
 *   apart and must not try: every one of them means "you do not have this
 *   data", and the only safe response is to behave as though it was never
 *   there.
 * * [remove] is idempotent.
 *
 * `name` is a caller-chosen identifier bound into the authenticated data, so a
 * record sealed under one name cannot be opened under another. That is what
 * stops stored credentials being replayed as stored history.
 */
interface Vault {

    /** Seal [bytes] under [name], replacing anything already there. */
    fun put(name: String, bytes: ByteArray)

    /** The bytes sealed under [name], or null if they are not available. */
    fun get(name: String): ByteArray?

    /** Forget [name]. Idempotent. */
    fun remove(name: String)

    /** Forget everything this vault holds. For logout. */
    fun clear()
}

/**
 * A [Vault] that keeps nothing beyond the process.
 *
 * For tests, and for a build where the platform vault could not be opened.
 * The second case is the important one: an app that cannot reach the Keystore
 * must degrade to "nothing is remembered", never to "it is written in the
 * clear instead".
 */
class InMemoryVault : Vault {

    private val lock = Any()
    private val entries = HashMap<String, ByteArray>()

    override fun put(name: String, bytes: ByteArray) = synchronized(lock) {
        entries[name] = bytes.copyOf()
    }

    override fun get(name: String): ByteArray? = synchronized(lock) {
        entries[name]?.copyOf()
    }

    override fun remove(name: String) = synchronized(lock) {
        entries.remove(name)?.fill(0)
        Unit
    }

    override fun clear() = synchronized(lock) {
        for (value in entries.values) value.fill(0)
        entries.clear()
    }
}
