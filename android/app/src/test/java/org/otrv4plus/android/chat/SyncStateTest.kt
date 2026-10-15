// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SendOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Ticks, typing, copies from our other devices and the archive
 * (XEP-0184, -0333, -0085, -0280, -0313), in the chat state.
 */
class SyncStateTest {

    private val bob = "bob@otrv4plus.i2p"

    private fun state(): ChatState {
        val s = ChatState()
        s.now = { 1_600_000_000_000L }
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        return s
    }

    private fun sent(s: ChatState, text: String, outcome: SendOutcome = SendOutcome.ENCRYPTED): Message {
        s.setDraft(bob, text)
        val m = s.beginSend(bob)!!
        s.completeSend(m, outcome)
        return m
    }

    @Test
    fun `every sent message has its own random wire id and a unique id`() {
        val s = state()
        val a = sent(s, "one")
        val b = sent(s, "two")
        assertTrue(a.wireId.length == 32 && b.wireId.length == 32 && a.wireId != b.wireId)
        assertTrue(a.id.contains(a.wireId))
    }

    @Test
    fun `a receipt makes it delivered and a read marker reads it and everything before`() {
        val s = state()
        val a = sent(s, "one")
        val b = sent(s, "two")
        s.handle(OtrEvent.MessageDelivered(bob, b.wireId))
        assertEquals(SendState.DELIVERED, s.messages(bob).last().sendState)
        assertEquals(SendState.SENT, s.messages(bob).first().sendState)
        s.handle(OtrEvent.MessageDisplayed(bob, b.wireId))
        assertEquals(listOf(SendState.READ, SendState.READ), s.messages(bob).map { it.sendState })
        // Never backwards.
        s.handle(OtrEvent.MessageDelivered(bob, a.wireId))
        assertEquals(SendState.READ, s.messages(bob).first().sendState)
        // And ticks never notify.
        assertFalse(s.handle(OtrEvent.MessageDelivered(bob, "nope")))
    }

    @Test
    fun `a receipt that beats the send call is not undone by it`() {
        val s = state()
        s.setDraft(bob, "quick")
        val m = s.beginSend(bob)!!
        s.handle(OtrEvent.MessageDelivered(bob, m.wireId))
        s.completeSend(m, SendOutcome.ENCRYPTED)
        val now = s.messages(bob).single()
        assertEquals(SendState.DELIVERED, now.sendState)
        assertEquals(SecurityLabel.ENCRYPTED, now.security)
    }

    @Test
    fun `a message from another device of ours shows once, as plaintext, without a sound`() {
        val s = state()
        val e = OtrEvent.MessageSentElsewhere(bob, "from my laptop", 1_600_000_000.0, "W1", "carbon")
        assertFalse(s.handle(e))
        assertFalse(s.handle(e.copy(source = "archive")))
        val m = s.messages(bob).single()
        assertTrue(m.outgoing)
        assertEquals(SecurityLabel.PLAINTEXT, m.security)
    }

    @Test
    fun `our own message coming back from the archive is not shown twice`() {
        val s = state()
        val m = sent(s, "hello", SendOutcome.PLAINTEXT)
        s.handle(OtrEvent.MessageSentElsewhere(bob, "hello", 1_600_000_000.0, m.wireId, "archive"))
        assertEquals(1, s.messages(bob).size)
    }

    @Test
    fun `the same inbound message live, as a carbon and archived is one message`() {
        val s = state()
        assertTrue(s.handle(OtrEvent.MessageReceived(bob, "hi", 1_600_000_000.0, "W9", "live")))
        assertFalse(s.handle(OtrEvent.MessageReceived(bob, "hi", 1_600_000_100.0, "W9", "carbon")))
        assertFalse(s.handle(OtrEvent.MessageReceived(bob, "hi", 1_600_000_200.0, "W9", "archive")))
        assertEquals(1, s.messages(bob).size)
    }

    @Test
    fun `a copy is plaintext whatever the session is now, and the archive does not ring`() {
        val s = state()
        s.handle(OtrEvent.SessionChanged(bob, SecurityState.ENCRYPTED))
        assertFalse(s.handle(OtrEvent.MessageReceived(bob, "old", 1_500_000_000.0, "A1", "archive")))
        assertTrue(s.handle(OtrEvent.MessageReceived(bob, "copy", 1_600_000_000.0, "C1", "carbon")))
        assertTrue(s.handle(OtrEvent.MessageReceived(bob, "secret", 1_600_000_001.0, "L1", "live")))
        val labels = s.messages(bob).associate { it.body to it.security }
        assertEquals(SecurityLabel.PLAINTEXT, labels["old"])
        assertEquals(SecurityLabel.PLAINTEXT, labels["copy"])
        assertEquals(SecurityLabel.ENCRYPTED, labels["secret"])
    }

    @Test
    fun `typing shows until a message, a pause, or thirty seconds`() {
        val s = state()
        var t = 1_600_000_000_000L
        s.now = { t }
        s.handle(OtrEvent.ChatStateChanged(bob, "composing"))
        assertTrue(s.isTyping(bob))
        s.handle(OtrEvent.ChatStateChanged(bob, "paused"))
        assertFalse(s.isTyping(bob))
        s.handle(OtrEvent.ChatStateChanged(bob, "composing"))
        s.handle(OtrEvent.MessageReceived(bob, "done", 1_600_000_000.0))
        assertFalse(s.isTyping(bob))
        s.handle(OtrEvent.ChatStateChanged(bob, "composing"))
        t += 31_000
        assertFalse(s.isTyping(bob))
    }

    @Test
    fun `every new field survives the codec, and v2 history still reads`() {
        val m = Message(
            id = "out:x:w:1", conversationId = bob, body = "body\u001fwith separators\u001e",
            outgoing = true, at = 5L, sendState = SendState.READ,
            security = SecurityLabel.ENCRYPTED, wireId = "W\u0002X", edited = true,
            retracted = false, replyTo = "R1", replyPreview = "quoted\u0003",
            reactions = linkedMapOf("me" to listOf("👍", "❤"), "b\u0002ob" to listOf("x\u0003")),
        )
        assertEquals(m, MessageCodec.decode(MessageCodec.encode(m)))
        val all = MessageCodec.decodeAll(MessageCodec.encodeAll(listOf(m), unread = 2))
        assertEquals(listOf(m), all)
        // A v2 store (8 fields) from the previous build.
        val v2 = "2\u001f0\u001e" + listOf("m1", bob, "0", "1000", "SENT", "PLAINTEXT", "", "old body")
            .joinToString("\u001f")
        val old = MessageCodec.decodeAll(v2).single()
        assertEquals("old body", old.body)
        assertEquals("", old.wireId)
    }

    @Test
    fun `a contact can correct and delete their own message but never ours`() {
        val s = state()
        val mine = sent(s, "my words")
        s.handle(OtrEvent.MessageReceived(bob, "teh", 1_600_000_000.0, "T1", "live"))
        s.handle(OtrEvent.MessageChanged(bob, "edit", "T1", "the", emptyList(), false, "live"))
        s.handle(OtrEvent.MessageChanged(bob, "edit", mine.wireId, "I owe Bob 100", emptyList(), false, "live"))
        s.handle(OtrEvent.MessageChanged(bob, "retract", mine.wireId, "", emptyList(), false, "live"))
        val byBody = s.messages(bob)
        assertEquals("my words", byBody.first { it.outgoing }.body)
        assertFalse(byBody.first { it.outgoing }.retracted)
        val theirs = byBody.first { !it.outgoing }
        assertEquals("the", theirs.body)
        assertTrue(theirs.edited)
        s.handle(OtrEvent.MessageChanged(bob, "retract", "T1", "", emptyList(), false, "live"))
        assertTrue(s.messages(bob).first { !it.outgoing }.retracted)
        assertEquals("", s.messages(bob).first { !it.outgoing }.body)
    }

    @Test
    fun `reactions replace each reactor's set and an empty set removes it`() {
        val s = state()
        val m = sent(s, "lunch?")
        s.handle(OtrEvent.MessageChanged(bob, "react", m.wireId, "", listOf("\uD83D\uDC4D"), false, "live"))
        assertTrue(s.applyChange(bob, "react", m.wireId, "", s.toggledReaction(s.messages(bob).single(), "\u2764"), true))
        assertEquals(mapOf(bob to listOf("\uD83D\uDC4D"), "me" to listOf("\u2764")), s.messages(bob).single().reactions)
        s.handle(OtrEvent.MessageChanged(bob, "react", m.wireId, "", listOf("\uD83D\uDE02"), false, "live"))
        s.handle(OtrEvent.MessageChanged(bob, "react", m.wireId, "", emptyList(), true, "carbon"))
        assertEquals(mapOf(bob to listOf("\uD83D\uDE02")), s.messages(bob).single().reactions)
    }

    @Test
    fun `a reply quotes what it answers, both ways`() {
        val s = state()
        s.handle(OtrEvent.MessageReceived(bob, "Are you coming tonight?\nbring food", 1_600_000_000.0, "Q1", "live"))
        val question = s.messages(bob).single()
        s.setDraft(bob, "yes")
        val reply = s.beginSend(bob, question)!!
        assertEquals("Q1", reply.replyTo)
        assertEquals("Are you coming tonight?", reply.replyPreview)
        s.handle(OtrEvent.MessageReceived(bob, "great", 1_600_000_100.0, "R2", "live", replyTo = reply.wireId))
        assertEquals("yes", s.messages(bob).last().replyPreview)
    }
}
