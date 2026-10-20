// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.crypto.TransferUi.State
import org.otrv4plus.android.security.InMemoryVault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A voice note is a message in the chat, sent or received, that plays --
 * not a file offer and not a "file received" line (owner, 2026-10-20).
 */
class VoiceNoteMessagesTest {

    private fun chat(vault: InMemoryVault = InMemoryVault()): ChatState =
        ChatState(PersistentMessageStore(vault)).apply {
            bindVault(vault)
            bindAccount(AccountScope.of("owner@x.i2p"))
        }

    private fun transfer(state: String, outgoing: Boolean = false) =
        OtrEvent.FileTransferChanged("Bob@X.i2p/phone", "t1", "voice-note-0a1b.ogg", 9_000,
                                     outgoing, state, "")

    @Test
    fun `a voice note is never an offer and leaves no file lines`() {
        val c = chat()
        assertFalse(c.handle(transfer(State.OFFERED)))
        assertTrue(c.pendingFileOffers.isEmpty())
        c.handle(transfer(State.ACCEPTED))
        c.handle(transfer(State.RECEIVED))
        assertTrue(c.messages("bob@x.i2p").isEmpty(), c.messages("bob@x.i2p").toString())
    }

    @Test
    fun `a failed one says so`() {
        val c = chat()
        c.handle(transfer(State.FAILED))
        val line = c.messages("bob@x.i2p").single()
        assertEquals(SecurityLabel.SYSTEM, line.security)
        assertTrue("voice note" in line.body.lowercase(), line.body)
    }

    @Test
    fun `a received note is a message that plays, announced once`() {
        val c = chat()
        val e = OtrEvent.VoiceNoteReceived("Bob@X.i2p/phone", "t1", "/state/voice-note-0a1b.ogg.otrv", "")
        assertTrue(c.handle(e))
        assertFalse(c.handle(e), "the same note twice")
        val m = c.messages("bob@x.i2p").single()
        assertEquals("/state/voice-note-0a1b.ogg.otrv", m.voicePath)
        assertEquals(VoiceNotes.BODY, m.body)
        assertFalse(m.outgoing)
        assertEquals(SecurityLabel.ENCRYPTED, m.security)
    }

    @Test
    fun `a note we sent can be played back too`() {
        val c = chat()
        val m = assertNotNull(c.addOutgoingVoiceNote("Bob@X.i2p", "/state/voice-note-sent-1.ogg.otrv"))
        assertTrue(m.outgoing)
        assertEquals("/state/voice-note-sent-1.ogg.otrv", c.messages("bob@x.i2p").single().voicePath)
    }

    @Test
    fun `the voice path survives the codec and v4 history still reads`() {
        val m = Message(id = "voice:t1", conversationId = "bob@x.i2p", body = VoiceNotes.BODY,
                        outgoing = false, at = 1L, sendState = SendState.NONE,
                        security = SecurityLabel.ENCRYPTED, voicePath = "/state/v.ogg.otrv")
        assertEquals(m, MessageCodec.decode(MessageCodec.encode(m)))
        assertEquals(listOf(m), MessageCodec.decodeAll(MessageCodec.encodeAll(listOf(m))))
        val v4 = "4\u001f0\u001e" + listOf("m1", "bob@x.i2p", "0", "1", "NONE", "ENCRYPTED", "", "W1",
                                            "", "", "", "", "", "old").joinToString("\u001f")
        val old = MessageCodec.decodeAll(v4).single()
        assertEquals("old", old.body)
        assertEquals("", old.voicePath)
    }
}
