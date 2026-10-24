// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.MetadataFinding
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.TransferUi.State
import org.otrv4plus.android.security.InMemoryVault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A received picture opens from its line, and the viewer says what metadata
 * it carries. Owner, 2026-10-24: "it should allow me to open and view image
 * within the app and also display metadata so we can confirm its stripped".
 * The Open button used to live only on the live transfer row, gone after a
 * restart.
 */
class ReceivedFileLinesTest {

    private fun chat(vault: InMemoryVault = InMemoryVault()): ChatState =
        ChatState(PersistentMessageStore(vault)).apply {
            bindVault(vault)
            bindAccount(AccountScope.of("owner@x.i2p"))
        }

    private fun transfer(state: String, outgoing: Boolean, path: String) =
        OtrEvent.FileTransferChanged("Bob@X.i2p/phone", "t1", "cat.jpg", 9_000,
                                     outgoing, state, "", path)

    @Test
    fun `a received file's line keeps its container so it can be opened later`() {
        val c = chat()
        c.handle(transfer(State.RECEIVED, outgoing = false, path = "/state/cat.jpg.otrv"))
        assertEquals("/state/cat.jpg.otrv", c.messages("bob@x.i2p").single().filePath)
    }

    @Test
    fun `a sent file's line has nothing to open`() {
        val c = chat()
        c.handle(transfer(State.DELIVERED, outgoing = true, path = "/somewhere/cat.jpg"))
        assertEquals("", c.messages("bob@x.i2p").single().filePath)
    }

    @Test
    fun `the file path survives the codec and v5 history still reads`() {
        val m = Message(id = "file:t1:RECEIVED", conversationId = "bob@x.i2p", body = "File received",
                        outgoing = false, at = 1L, sendState = SendState.NONE,
                        security = SecurityLabel.SYSTEM, filePath = "/state/cat.jpg.otrv")
        assertEquals(m, MessageCodec.decode(MessageCodec.encode(m)))
        assertEquals(listOf(m), MessageCodec.decodeAll(MessageCodec.encodeAll(listOf(m))))
        val v5 = "5\u001f0\u001e" + listOf("m1", "bob@x.i2p", "0", "1", "NONE", "ENCRYPTED", "", "W1",
                                            "", "", "", "", "", "/v.ogg.otrv", "old").joinToString("\u001f")
        val old = MessageCodec.decodeAll(v5).single()
        assertEquals("old", old.body)
        assertEquals("/v.ogg.otrv", old.voicePath)
        assertEquals("", old.filePath)
    }

    @Test
    fun `the viewer says what metadata a picture carries`() {
        val clean = MetadataChoice.receivedSummary(MetadataFinding("jpeg", false, 0, true))
        assertTrue(clean.startsWith("Metadata: none") && "EXIF" in clean, clean)
        val dirty = MetadataChoice.receivedSummary(MetadataFinding("jpeg", true, 812, true))
        assertTrue("812 bytes" in dirty, dirty)
        val unknown = MetadataChoice.receivedSummary(null)
        assertTrue("could not be checked" in unknown, unknown)
        assertTrue("could not be checked" in
                   MetadataChoice.receivedSummary(MetadataFinding("unknown", false, 0, false)))
    }
}
