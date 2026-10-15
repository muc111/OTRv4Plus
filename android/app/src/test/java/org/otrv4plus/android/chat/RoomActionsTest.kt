// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Replies, corrections, deletions and reactions in a plain room. */
class RoomActionsTest {

    private val room = "lobby@rooms.example.test"

    private fun state(): ChatState {
        val s = ChatState()
        s.now = { 1_600_000_000_000L }
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        return s
    }

    private fun said(s: ChatState, nick: String, body: String, ref: String, t: Double = 1_600_000_000.0,
                     replyTo: String = "") =
        s.handle(OtrEvent.RoomMessageReceived(room, nick, body, t, messageId = ref, replyTo = replyTo))

    @Test
    fun `a room message is known by the rooms id and shown once`() {
        val s = state()
        said(s, "bob", "hi", "R1")
        said(s, "bob", "hi", "R1", t = 1_600_000_100.0)       // replayed, archived
        assertEquals(listOf("R1"), s.messages(room).map { it.wireId })
    }

    @Test
    fun `only the same nickname may correct or delete a message`() {
        val s = state()
        said(s, "bob", "teh", "R1")
        s.handle(OtrEvent.MessageChanged(room, "edit", "R1", "forged", emptyList(), false, "live", "mallory"))
        assertEquals("teh", s.messages(room).single().body)
        s.handle(OtrEvent.MessageChanged(room, "retract", "R1", "", emptyList(), false, "live", "mallory"))
        assertFalse(s.messages(room).single().retracted)
        s.handle(OtrEvent.MessageChanged(room, "edit", "R1", "the", emptyList(), false, "live", "bob"))
        assertEquals("the", s.messages(room).single().body)
        s.handle(OtrEvent.MessageChanged(room, "retract", "R1", "", emptyList(), false, "live", "bob"))
        assertTrue(s.messages(room).single().retracted)
    }

    @Test
    fun `reactions are per nickname`() {
        val s = state()
        said(s, "bob", "lunch?", "R1")
        s.handle(OtrEvent.MessageChanged(room, "react", "R1", "", listOf("ok"), false, "live", "carol"))
        s.handle(OtrEvent.MessageChanged(room, "react", "R1", "", listOf("no"), false, "live", "dave"))
        assertEquals(mapOf("carol" to listOf("ok"), "dave" to listOf("no")),
                     s.messages(room).single().reactions)
    }

    @Test
    fun `our message takes the rooms id when the room reflects it`() {
        val s = state()
        s.noteRoom(room)
        s.setDraft(room, "hello")
        val m = s.beginSend(room)!!
        s.completeSend(m, SendOutcome.PLAINTEXT)
        s.handle(OtrEvent.RoomMessageAcked(room, m.wireId, "R9"))
        assertEquals("R9", s.messages(room).single().wireId)
        // So a reaction naming R9 lands on it.
        s.handle(OtrEvent.MessageChanged(room, "react", "R9", "", listOf("ok"), false, "live", "bob"))
        assertEquals(mapOf("bob" to listOf("ok")), s.messages(room).single().reactions)
    }

    @Test
    fun `a reply quotes what it answers and our archived lines are ours`() {
        val s = state()
        said(s, "bob", "Are you coming?", "R1")
        said(s, "carol", "yes", "R2", replyTo = "R1")
        assertEquals("Are you coming?", s.messages(room).last().replyPreview)
        s.handle(OtrEvent.RoomMessageReceived(room, "me", "from my laptop", 1_600_000_200.0,
                                              messageId = "R3", source = "archive", own = true))
        assertTrue(s.messages(room).last().outgoing)
    }
}

/** The same in a SECURE GROUP: bound to the MLS-authenticated JID, not a nickname. */
class SecureGroupActionsTest {

    private val room = "secret@conference.example.i2p"

    private fun state(): ChatState {
        val s = ChatState()
        s.now = { 1_600_000_000_000L }
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        return s
    }

    private fun said(s: ChatState, nick: String, jid: String, body: String, ref: String) =
        s.handle(OtrEvent.RoomMessageReceived(room, nick, body, 1_600_000_000.0, encrypted = true,
                                              senderIdentity = jid, messageId = ref))

    private fun change(s: ChatState, action: String, ref: String, nick: String, jid: String,
                       body: String = "", emojis: List<String> = emptyList()) =
        s.handle(OtrEvent.MessageChanged(room, action, ref, body, emojis, false, "live", nick, jid))

    @Test
    fun `the author's JID may correct and delete`() {
        val s = state()
        said(s, "bob", "bob@x.i2p", "teh", "B1")
        assertEquals("bob@x.i2p", s.messages(room).single().author)
        change(s, "edit", "B1", "bob", "Bob@X.i2p", "the")
        assertEquals("the", s.messages(room).single().body)
        change(s, "retract", "B1", "bob", "bob@x.i2p")
        assertTrue(s.messages(room).single().retracted)
    }

    @Test
    fun `a taken-over nickname, another JID, or the same localpart elsewhere cannot`() {
        val s = state()
        said(s, "bob", "bob@x.i2p", "mine", "B1")
        change(s, "edit", "B1", "bob", "mallory@x.i2p", "forged")      // nickname takeover
        change(s, "edit", "B1", "bobby", "bob@y.i2p", "forged")        // same localpart, other server
        change(s, "edit", "B1", "bob", "", "forged")                   // no MLS identity at all
        change(s, "retract", "B1", "bob", "carol@x.i2p")
        val m = s.messages(room).single()
        assertEquals("mine", m.body)
        assertFalse(m.retracted)
    }

    @Test
    fun `reactions are per JID and nobody may touch ours`() {
        val s = state()
        s.noteRoom(room)
        said(s, "bob", "bob@x.i2p", "lunch?", "B1")
        change(s, "react", "B1", "x", "carol@x.i2p", emojis = listOf("ok"))
        change(s, "react", "B1", "x", "Carol@x.i2p", emojis = listOf("no"))
        assertEquals(mapOf("carol@x.i2p" to listOf("no")), s.messages(room).single().reactions)
        s.setDraft(room, "my line")
        val ours = s.beginSend(room)!!
        s.completeSend(ours, SendOutcome.ENCRYPTED)
        change(s, "edit", ours.wireId, "me", "bob@x.i2p", "forged")
        assertEquals("my line", s.messages(room).last().body)
    }

    @Test
    fun `the author survives the codec, and v3 history still reads`() {
        val m = Message(id = "r:1", conversationId = room, body = "b", outgoing = false, at = 1L,
                        sendState = SendState.NONE, security = SecurityLabel.ENCRYPTED,
                        sender = "bob", wireId = "B1", author = "bob@x.i2p")
        assertEquals(m, MessageCodec.decode(MessageCodec.encode(m)))
        assertEquals(listOf(m), MessageCodec.decodeAll(MessageCodec.encodeAll(listOf(m))))
        val v3 = "3\u001f0\u001e" + listOf("m1", room, "0", "1", "NONE", "ENCRYPTED", "bob", "B1",
                                            "", "", "", "", "old").joinToString("\u001f")
        val old = MessageCodec.decodeAll(v3).single()
        assertEquals("old", old.body)
        assertEquals("", old.author)
    }
}
