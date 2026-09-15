// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * History, de-duplication and bounds.
 *
 * These run as plain JVM unit tests: the store imports nothing from Android
 * and nothing from Compose, which is the point of it being an interface rather
 * than a database. A persistence layer that can only be tested on a device is
 * a persistence layer that does not get tested.
 */
class MessageStoreTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    private fun message(
        id: String,
        conversation: String = alice,
        body: String = "hello",
        outgoing: Boolean = false,
        at: Long = 1_000L,
        sendState: SendState = SendState.NONE,
        security: SecurityLabel = SecurityLabel.PLAINTEXT,
    ) = Message(id, conversation, body, outgoing, at, sendState, security)

    @Test
    fun `an appended message comes back`() {
        val store = InMemoryMessageStore()
        assertTrue(store.append(message("m1")))
        assertEquals(listOf("m1"), store.messages(alice).map { it.id })
    }

    @Test
    fun `the same id is not appended twice`() {
        // The defence against an optimistic echo, a replayed event and a
        // recomposition all appending the same message.
        val store = InMemoryMessageStore()
        assertTrue(store.append(message("m1")))
        assertFalse(store.append(message("m1")))
        assertEquals(1, store.messages(alice).size)
    }

    @Test
    fun `identical bodies with different ids are both kept`() {
        // Sending the same word twice on purpose is ordinary.
        val store = InMemoryMessageStore()
        store.append(message("m1", body = "ok"))
        store.append(message("m2", body = "ok"))
        assertEquals(2, store.messages(alice).size)
    }

    @Test
    fun `conversations do not mix`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", conversation = alice, body = "for alice"))
        store.append(message("m2", conversation = bob, body = "for bob"))
        assertEquals(listOf("for alice"), store.messages(alice).map { it.body })
        assertEquals(listOf("for bob"), store.messages(bob).map { it.body })
    }

    @Test
    fun `update replaces in place rather than appending`() {
        // This is what stops an optimistic message and its own result becoming
        // two messages.
        val store = InMemoryMessageStore()
        val sending = message("m1", outgoing = true, sendState = SendState.SENDING)
        store.append(sending)
        assertTrue(store.update(sending.copy(sendState = SendState.SENT)))
        assertEquals(1, store.messages(alice).size)
        assertEquals(SendState.SENT, store.messages(alice).first().sendState)
    }

    @Test
    fun `update of an unknown id does nothing`() {
        val store = InMemoryMessageStore()
        assertFalse(store.update(message("nope")))
        assertEquals(0, store.messages(alice).size)
    }

    @Test
    fun `history is bounded and drops the oldest`() {
        // Unbounded is a memory leak with a polite name: a long session on a
        // phone would grow until Android killed the process.
        val store = InMemoryMessageStore(perConversationLimit = 3)
        repeat(5) { store.append(message("m$it", at = it.toLong())) }
        val ids = store.messages(alice).map { it.id }
        assertEquals(listOf("m2", "m3", "m4"), ids)
    }

    @Test
    fun `an evicted id can be appended again`() {
        // Otherwise the de-duplication set grows without bound, which is the
        // leak the message cap was supposed to close.
        val store = InMemoryMessageStore(perConversationLimit = 2)
        store.append(message("m1"))
        store.append(message("m2"))
        store.append(message("m3"))        // evicts m1
        assertTrue(store.append(message("m1")))
    }

    @Test
    fun `last message is the most recent`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", body = "first"))
        store.append(message("m2", body = "second"))
        assertEquals("second", store.lastMessage(alice)?.body)
    }

    @Test
    fun `last message of an empty conversation is null`() {
        assertNull(InMemoryMessageStore().lastMessage(alice))
    }

    @Test
    fun `inbound messages raise the unread count`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", outgoing = false))
        store.append(message("m2", outgoing = false))
        assertEquals(2, store.unread(alice))
    }

    @Test
    fun `outgoing messages do not raise the unread count`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", outgoing = true))
        assertEquals(0, store.unread(alice))
    }

    @Test
    fun `system notes do not raise the unread count`() {
        // A session-state note is not something the user has to read.
        val store = InMemoryMessageStore()
        store.append(message("m1", security = SecurityLabel.SYSTEM))
        assertEquals(0, store.unread(alice))
    }

    @Test
    fun `marking read clears the count for that conversation only`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", conversation = alice))
        store.append(message("m2", conversation = bob))
        store.markRead(alice)
        assertEquals(0, store.unread(alice))
        assertEquals(1, store.unread(bob))
    }

    @Test
    fun `conversation ids list only conversations with history`() {
        val store = InMemoryMessageStore()
        store.append(message("m1", conversation = alice))
        assertEquals(setOf(alice), store.conversationIds())
    }

    @Test
    fun `clear forgets everything`() {
        val store = InMemoryMessageStore()
        store.append(message("m1"))
        store.clear()
        assertEquals(0, store.messages(alice).size)
        assertEquals(0, store.unread(alice))
        assertTrue(store.conversationIds().isEmpty())
    }
}
