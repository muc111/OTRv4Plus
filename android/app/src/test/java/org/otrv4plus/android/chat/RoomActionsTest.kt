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
