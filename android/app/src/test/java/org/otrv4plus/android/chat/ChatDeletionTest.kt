// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * "Delete chat", one-to-one and room: persistent, and honest about the server.
 *
 * A new [ChatState] over the same [Disk] is a restart, as in
 * `WipePersistenceTest`.
 */
class ChatDeletionTest {

    private class Disk : Vault {
        val entries = LinkedHashMap<String, ByteArray>()
        override fun put(name: String, bytes: ByteArray) { entries[name] = bytes.copyOf() }
        override fun get(name: String): ByteArray? = entries[name]?.copyOf()
        override fun remove(name: String) { entries.remove(name) }
        override fun clear() { entries.clear() }
    }

    private val owner = "owner@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"
    private val room = "english@conference.xmpp-elite.i2p"

    private fun process(disk: Disk): Pair<ChatState, PersistentMessageStore> {
        val store = PersistentMessageStore(disk)
        val chat = ChatState(store).apply { bindVault(disk) }
        chat.bindAccount(AccountScope.of(owner))
        return chat to store
    }

    private fun say(store: MessageStore, id: String, to: String, sender: String = "") =
        store.append(Message(id, to, "hi $id", false, 1_000L, SendState.NONE,
                             SecurityLabel.ENCRYPTED, sender))

    private fun Contact(jid: String, name: String) = org.otrv4plus.android.bridge.Contact(
        jid, name, PeerPresence.ONLINE, SecurityState.PLAINTEXT, SmpState.NOT_VERIFIED, false)

    private fun jids(chat: ChatState) = chat.conversations().map { it.jid }.toSet()

    @Test
    fun `deleting a one-to-one chat removes its history from the vault and it stays deleted`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice)
        say(store, "b1", bob)
        chat.setDraft(alice, "unsent")
        val aliceEntry = AccountScope.of(owner).entryFor(alice)
        assertTrue(aliceEntry in disk.entries)

        assertTrue(chat.deleteConversation(alice))
        assertEquals(setOf(bob), jids(chat))
        assertEquals("", chat.draft(alice))
        assertFalse(aliceEntry in disk.entries, "the record is still in the vault")
        val index = String(disk.entries.getValue(AccountScope.of(owner).indexName))
        assertFalse(alice in index, "the index still names the deleted conversation")

        val (again, againStore) = process(disk)
        assertEquals(setOf(bob), jids(again))
        assertEquals(emptyList(), againStore.messages(alice))
        val (third, _) = process(disk)
        assertEquals(setOf(bob), jids(third))
    }

    @Test
    fun `a roster contact's deleted chat does not come back with the next roster poll`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        chat.applyRoster(listOf(Contact(alice, "Alice")))
        say(store, "a1", alice)
        chat.deleteConversation(alice)
        chat.applyRoster(listOf(Contact(alice, "Alice")))
        assertEquals(emptySet(), jids(chat))

        val (restarted, _) = process(disk)
        restarted.applyRoster(listOf(Contact(alice, "Alice")))
        assertEquals(emptySet(), jids(restarted), "a restart brought the row back")
    }

    @Test
    fun `a new message, a send, or opening it brings a deleted chat back`() {
        val disk = Disk()
        val (chat, _) = process(disk)
        chat.applyRoster(listOf(Contact(alice, "Alice"), Contact(bob, "Bob")))
        chat.deleteConversation(alice)
        chat.deleteConversation(bob)
        chat.receive(OtrEvent.MessageReceived(peer = alice, body = "back", timestamp = 2.0))
        assertTrue(alice in jids(chat))
        chat.open(bob)
        assertTrue(bob in jids(chat))
        assertEquals(emptySet(), chat.deleted.all())
    }

    @Test
    fun `a room's stored history is still a room after a restart, and deleting it is local`() {
        val disk = Disk()
        val (chat, _) = process(disk)
        chat.receiveRoom(OtrEvent.RoomMessageReceived(room = room, sender = "ann",
                                                      body = "hello", timestamp = 1.0))
        assertTrue(chat.isRoom(room))
        assertTrue(chat.inRoomThisSession(room))

        val (restarted, _) = process(disk)
        assertTrue(restarted.isRoom(room), "a room's history came back as a 1:1 chat")
        assertFalse(restarted.inRoomThisSession(room),
                    "membership does not survive the stream; nothing to leave")

        assertTrue(restarted.deleteConversation(room))
        val (third, _) = process(disk)
        assertEquals(emptySet(), jids(third))
    }

    @Test
    fun `marking a deleted chat read leaves no empty record behind`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice)
        chat.deleteConversation(alice)
        store.markRead(alice)
        assertFalse(AccountScope.of(owner).entryFor(alice) in disk.entries)
    }

    @Test
    fun `sign out forgets the deleted list and the saved contacts with the history`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        chat.savedContacts.save(alice, "Alice")
        chat.deleteConversation(bob)
        store.forgetAccount()
        chat.forgetAccountRecords()
        assertEquals(emptyList(), disk.entries.keys.filter {
            it.startsWith("contacts.") || it.startsWith(DeletedConversations.RECORD_PREFIX)
        })
    }

    // -- what the user is told --------------------------------------------------

    @Test
    fun `no outcome ever claims the server deleted anything`() {
        for (kind in ChatDeletion.Kind.entries) for (server in ChatDeletion.ServerArchive.entries)
            for (left in listOf(null, true, false)) for (local in listOf(true, false)) {
                val text = ChatDeletion.Outcome(kind, local, left, server).message
                assertTrue("Server-side deletion is not supported" in text, text)
                assertFalse("deleted from the server" in text.lowercase(), text)
            }
    }

    @Test
    fun `an unanswered probe is unknown, not no archive`() {
        assertEquals(ChatDeletion.ServerArchive.UNKNOWN,
                     ChatDeletion.serverArchive(answered = false, mam = false))
        assertEquals(ChatDeletion.ServerArchive.ADVERTISED,
                     ChatDeletion.serverArchive(answered = true, mam = true))
        assertEquals(ChatDeletion.ServerArchive.NOT_ADVERTISED,
                     ChatDeletion.serverArchive(answered = true, mam = false))
        val text = ChatDeletion.Outcome(ChatDeletion.Kind.DIRECT, true, null,
            ChatDeletion.ServerArchive.UNKNOWN).message
        assertTrue("could not be checked" in text)
    }

    @Test
    fun `a room is never said to be destroyed, and leaving says it still exists`() {
        val text = ChatDeletion.Outcome(ChatDeletion.Kind.ROOM, true, true,
            ChatDeletion.ServerArchive.NOT_ADVERTISED).message
        assertTrue("still exists" in text)
        for (s in listOf(ChatDeletion.confirmBody(ChatDeletion.Kind.ROOM), text,
                         ChatDeletion.CONFIRM, ChatDeletion.CONFIRM_AND_LEAVE)) {
            assertFalse("destroyed for" in s.lowercase() || "destroy the room" in s.lowercase(), s)
        }
        assertTrue("not destroyed" in ChatDeletion.confirmBody(ChatDeletion.Kind.ROOM))
    }
}
