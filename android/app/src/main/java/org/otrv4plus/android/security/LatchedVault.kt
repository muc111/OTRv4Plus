// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

/**
 * A [Vault] that can be shut for good. Wipe & Exit shuts it first.
 *
 * WHY THIS EXISTS
 * ---------------
 * Wipe & Exit destroys the vault, but the objects that write to it -- the
 * message store, the saved-contact list, the credential store -- are still
 * alive in the process until it ends, and more than one thread can reach
 * them: the drain loop, a screen marking a conversation read, a send that
 * completes. Cancelling the drain loop does not wait for a write already in
 * progress. A write that lands after the vault is destroyed but before the
 * process ends puts a record back, and on the next launch that record is a
 * conversation the user was told had been erased.
 *
 * Latching closes that at the one place every write goes through. After
 * [latch]: [put] does nothing, [get] returns nothing, and [remove] and
 * [clear] still work, because they only ever take away. Latching cannot be
 * undone; the process ends at the end of the wipe and a new process builds
 * a new vault.
 */
class LatchedVault(val inner: Vault) : Vault {

    private val lock = Any()

    @Volatile
    private var latched = false

    /**
     * Refuse every future write and read. Idempotent.
     *
     * Takes the same lock as [put], so a write already in progress finishes
     * BEFORE this returns and is then removed by the wipe's `clear`, rather
     * than finishing after it.
     */
    fun latch() = synchronized(lock) { latched = true }

    val isLatched: Boolean get() = latched

    override fun put(name: String, bytes: ByteArray) = synchronized(lock) {
        if (!latched) inner.put(name, bytes)
    }

    override fun get(name: String): ByteArray? =
        if (latched) null else inner.get(name)

    override fun remove(name: String) = inner.remove(name)

    override fun clear() = inner.clear()
}
