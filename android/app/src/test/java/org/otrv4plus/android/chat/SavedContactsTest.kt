// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Remembering a contact across sessions, WITHOUT claiming the server agreed.
 *
 * THE DISTINCTION THESE ENFORCE. The vault remembers "this account asked to
 * keep this JID". The XMPP roster remains the only authority on subscription,
 * presence and whether the other person accepted. Merging them would let a tap
 * on this phone render as a confirmed relationship.
 */
class SavedContactsTest {

    /** The real KeystoreVault needs AndroidKeyStore; this is its contract. */
    private class FakeVault : Vault {
        val records = HashMap<String, ByteArray>()
        var readable = true
        override fun put(name: String, bytes: ByteArray) {
            records[name] = bytes
        }
        override fun get(name: String): ByteArray? =
            if (!readable) null else records[name]
        override fun remove(name: String) {
            records.remove(name)
        }
        override fun clear() {
            records.clear()
        }
    }

    private val alice = AccountScope.of("alice@xmpp-elite.i2p")
    private val bob = AccountScope.of("bob@xmpp-elite.i2p")

    private fun store(vault: Vault? = FakeVault(), on: AccountScope = alice) =
        SavedContacts(vault).also { it.bind(on) }

    // ── it persists ──────────────────────────────────────────────────────────

    @Test
    fun `a saved contact survives a restart`() {
        val vault = FakeVault()
        store(vault).save("carol@xmpp-elite.i2p", "Carol", at = 100L)

        // A new process: a fresh object over the same vault.
        val revived = SavedContacts(vault).also { it.bind(alice) }
        assertEquals(listOf("carol@xmpp-elite.i2p"), revived.all().map { it.jid })
        assertEquals("Carol", revived.all().single().displayName)
        assertEquals(100L, revived.all().single().savedAt)
    }

    @Test
    fun `saving is idempotent and keeps the original timestamp`() {
        val vault = FakeVault()
        val s = store(vault)
        assertTrue(s.save("carol@xmpp-elite.i2p", "Carol", at = 100L))
        assertFalse(s.save("carol@xmpp-elite.i2p", "Carol", at = 999L),
                    "re-saving reported a change")
        assertEquals(100L, s.all().single().savedAt)
    }

    @Test
    fun `a jid is stored bare and case-folded`() {
        val s = store()
        s.save("Carol@XMPP-Elite.i2p/phone")
        assertEquals("carol@xmpp-elite.i2p", s.all().single().jid)
        assertTrue(s.isSaved("carol@xmpp-elite.i2p/laptop"))
    }

    @Test
    fun `forgetting removes it and persists the removal`() {
        val vault = FakeVault()
        val s = store(vault)
        s.save("carol@xmpp-elite.i2p")
        assertTrue(s.forget("carol@xmpp-elite.i2p"))
        assertTrue(SavedContacts(vault).also { it.bind(alice) }.all().isEmpty())
    }

    // ── it belongs to one account ────────────────────────────────────────────

    @Test
    fun `another account does not see these contacts`() {
        val vault = FakeVault()
        store(vault, alice).save("carol@xmpp-elite.i2p")

        val dave = SavedContacts(vault).also { it.bind(bob) }
        assertTrue(dave.all().isEmpty(),
                   "bob can read alice's saved contacts")
    }

    @Test
    fun `nothing is stored before an account is established`() {
        val vault = FakeVault()
        val s = SavedContacts(vault)   // never bound
        assertFalse(s.save("carol@xmpp-elite.i2p"))
        assertTrue(s.all().isEmpty())
        assertTrue(vault.records.isEmpty())
    }

    @Test
    fun `signing out forgets the account's list`() {
        val vault = FakeVault()
        val s = store(vault)
        s.save("carol@xmpp-elite.i2p")
        s.forgetAccount()
        assertTrue(s.all().isEmpty())
        assertTrue(vault.records.isEmpty())
    }

    // ── it never asserts anything cryptographic or server-side ───────────────

    @Test
    fun `the record carries only local facts`() {
        // If a field for subscription, presence, a fingerprint or a key ever
        // appears here, this store has started duplicating the roster or the
        // engine -- and a second source of truth about identity is exactly
        // what the separation exists to prevent.
        val fields = SavedContacts.Saved::class.java.declaredFields
            .map { it.name }
            .filterNot { it.startsWith("$") }
            .toSet()
        assertEquals(setOf("jid", "displayName", "savedAt"), fields)
    }

    @Test
    fun `no roster or crypto concept is persisted`() {
        val vault = FakeVault()
        store(vault).save("carol@xmpp-elite.i2p", "Carol", at = 7L)
        val written = String(vault.records.values.single())
        for (forbidden in listOf("subscription", "presence", "fingerprint",
                                 "password", "pending", "smp")) {
            assertFalse(written.contains(forbidden, ignoreCase = true),
                        "the saved record mentions $forbidden")
        }
    }

    // ── a damaged record does not become a contact ───────────────────────────

    @Test
    fun `an unreadable vault yields an empty list rather than throwing`() {
        val vault = FakeVault()
        store(vault).save("carol@xmpp-elite.i2p")
        vault.readable = false
        assertTrue(SavedContacts(vault).also { it.bind(alice) }.all().isEmpty())
    }

    @Test
    fun `a truncated record is skipped, not guessed at`() {
        val vault = FakeVault()
        vault.records["contacts." + alice.key] =
            "not-a-jid\ncarol@xmpp-elite.i2p\tCarol\t5".toByteArray()
        val s = SavedContacts(vault).also { it.bind(alice) }
        assertEquals(listOf("carol@xmpp-elite.i2p"), s.all().map { it.jid })
    }

    @Test
    fun `a display name containing a separator cannot corrupt the record`() {
        val vault = FakeVault()
        store(vault).save("carol@xmpp-elite.i2p", "Ca\trol\nX")
        val revived = SavedContacts(vault).also { it.bind(alice) }
        assertEquals(1, revived.all().size)
        assertEquals("carol@xmpp-elite.i2p", revived.all().single().jid)
    }

    @Test
    fun `rubbish input is refused`() {
        val s = store()
        assertFalse(s.save(""))
        assertFalse(s.save("   "))
        assertFalse(s.save("no-at-sign"))
        assertTrue(s.all().isEmpty())
    }
}
