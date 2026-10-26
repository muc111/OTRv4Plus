// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.PersistentMessageStore
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeniableChatTest {

    @Test fun `offered only once a session is established`() {
        assertTrue(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.SMP_VERIFIED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.FINGERPRINT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.PLAINTEXT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.FINGERPRINT_MISMATCH, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = true))
    }

    @Test fun `the words describe the mechanism and claim nothing more`() {
        val all = listOf(DeniableChat.ACTION, DeniableChat.TITLE, DeniableChat.BODY,
                         DeniableChat.outcome("made_deniable"), DeniableChat.outcome("no_session"))
        assertTrue(all.none { "deniable messaging" in it.lowercase() })
        assertTrue("not been independently reviewed" in DeniableChat.BODY)
        assertTrue("stay encrypted" in DeniableChat.BODY)
    }

    // ── the history goes with the session (owner, 2026-10-26) ───────────────

    private class Disk : Vault {
        val entries = LinkedHashMap<String, ByteArray>()
        override fun put(name: String, bytes: ByteArray) { entries[name] = bytes.copyOf() }
        override fun get(name: String): ByteArray? = entries[name]?.copyOf()
        override fun remove(name: String) { entries.remove(name) }
        override fun clear() { entries.clear() }
    }

    private val owner = "owner@otrv4plus.i2p"
    private val alice = "alice@otrv4plus.i2p"
    private val bob = "bob@otrv4plus.i2p"

    private fun process(disk: Disk): Pair<ChatState, PersistentMessageStore> {
        val store = PersistentMessageStore(disk)
        val chat = ChatState(store).apply { bindVault(disk) }
        chat.bindAccount(AccountScope.of(owner))
        return chat to store
    }

    private fun say(store: PersistentMessageStore, id: String, to: String) =
        store.append(Message(id, to, "hi $id", false, 1_000L, SendState.NONE,
                             SecurityLabel.ENCRYPTED, ""))

    @Test fun `made deniable, the chat's history is deleted here and stays deleted`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice); say(store, "a2", alice); say(store, "b1", bob)
        val said = DeniableChat.apply("made_deniable", chat, alice)
        assertTrue("history was deleted" in said, said)
        assertTrue(store.messages(alice).isEmpty())
        assertFalse(disk.entries.containsKey(AccountScope.of(owner).entryFor(alice)),
            "gone from the vault, not only from the screen")
        assertEquals(1, store.messages(bob).size, "another chat is untouched")
        val (_, restarted) = process(disk)
        assertTrue(restarted.messages(alice).isEmpty(), "a restart does not bring it back")
    }

    @Test fun `the new session's messages are the only ones shown`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "old", alice)
        DeniableChat.apply("made_deniable", chat, alice)
        say(store, "new", alice)
        assertEquals(listOf("new"), store.messages(alice).map { it.id })
    }

    @Test fun `no session, nothing deleted`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice)
        DeniableChat.apply("no_session", chat, alice)
        assertEquals(1, store.messages(alice).size)
    }

    @Test fun `the dialog says the history goes`() {
        assertTrue("history is deleted from this device" in DeniableChat.BODY)
    }
}
