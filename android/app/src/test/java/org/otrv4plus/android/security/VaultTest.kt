// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The contract every [Vault] owes its callers. */
class VaultTest {

    @Test
    fun `absent is null`() {
        assertNull(InMemoryVault().get("nothing"))
    }

    @Test
    fun `what goes in comes out`() {
        val vault = InMemoryVault()
        vault.put("a", byteArrayOf(1, 2, 3))
        assertEquals(listOf<Byte>(1, 2, 3), vault.get("a")?.toList())
    }

    @Test
    fun `put replaces`() {
        val vault = InMemoryVault()
        vault.put("a", byteArrayOf(1))
        vault.put("a", byteArrayOf(2))
        assertEquals(listOf<Byte>(2), vault.get("a")?.toList())
    }

    @Test
    fun `names are independent`() {
        val vault = InMemoryVault()
        vault.put("a", byteArrayOf(1))
        vault.put("b", byteArrayOf(2))
        assertEquals(listOf<Byte>(1), vault.get("a")?.toList())
        assertEquals(listOf<Byte>(2), vault.get("b")?.toList())
    }

    @Test
    fun `remove is idempotent`() {
        val vault = InMemoryVault()
        vault.remove("never there")
        vault.put("a", byteArrayOf(1))
        vault.remove("a")
        vault.remove("a")
        assertNull(vault.get("a"))
    }

    @Test
    fun `clear forgets everything`() {
        val vault = InMemoryVault()
        vault.put("a", byteArrayOf(1))
        vault.put("b", byteArrayOf(2))
        vault.clear()
        assertNull(vault.get("a"))
        assertNull(vault.get("b"))
    }

    @Test
    fun `stored bytes are copied in`() {
        // Otherwise the caller can mutate what the vault believes it holds --
        // and callers here wipe their arrays after storing them.
        val vault = InMemoryVault()
        val mine = byteArrayOf(1, 2, 3)
        vault.put("a", mine)
        mine.fill(0)
        assertEquals(listOf<Byte>(1, 2, 3), vault.get("a")?.toList())
    }

    @Test
    fun `returned bytes are copied out`() {
        val vault = InMemoryVault()
        vault.put("a", byteArrayOf(1, 2, 3))
        vault.get("a")?.fill(9)
        assertEquals(listOf<Byte>(1, 2, 3), vault.get("a")?.toList())
    }

    @Test
    fun `an empty value is not the same as an absent one`() {
        val vault = InMemoryVault()
        vault.put("a", ByteArray(0))
        assertTrue(vault.get("a") != null)
        assertEquals(0, vault.get("a")?.size)
    }
}
