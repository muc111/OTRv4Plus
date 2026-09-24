// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.PersistentMessageStore
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.crypto.TransferUi.State
import org.otrv4plus.android.security.InMemoryVault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A transfer's row and its lasting line are driven by the engine's state.
 * "Never stuck at transferring": every ending has a line, SENT says it is
 * waiting for confirmation, and nothing here depends on a timer.
 */
class TransferStatesTest {

    private fun view(state: String, outgoing: Boolean = false, progress: Float = 0f,
                     reason: String = "") =
        FileTransferView("t1", "bob@x.i2p", "photo.jpg", 40_960, outgoing,
                         accepted = state != State.OFFERED && state != State.WAITING,
                         cancelled = state in setOf(State.CANCELLED, State.DECLINED, State.FAILED),
                         progress = progress, state = state, reason = reason)

    @Test
    fun `an incoming offer can be accepted or declined and shows the size`() {
        val row = TransferUi.row(view(State.OFFERED))
        assertTrue(row.canAccept && row.canDecline)
        assertTrue("40 KB" in row.label, row.label)
        assertFalse(row.showsProgress)
    }

    @Test
    fun `a moving transfer shows bytes and a percentage and can be cancelled`() {
        val row = TransferUi.row(view(State.ACCEPTED, progress = 0.25f))
        assertTrue(row.showsProgress && row.canDecline && !row.canAccept)
        assertEquals("10 KB of 40 KB · 25%", row.detail)
        assertTrue("Receiving" in row.label)
        assertTrue("Sending" in TransferUi.row(view(State.ACCEPTED, outgoing = true)).label)
    }

    @Test
    fun `sent is not delivered`() {
        val sent = TransferUi.row(view(State.SENT, outgoing = true, progress = 1f))
        assertTrue("waiting for them to confirm" in sent.label, sent.label)
        assertFalse(sent.finished)
        val done = TransferUi.row(view(State.DELIVERED, outgoing = true, progress = 1f))
        assertTrue(done.finished && !done.canDecline && !done.showsProgress)
    }

    @Test
    fun `every ending is finished, with no buttons, and failure says why`() {
        for (state in State.TERMINAL) {
            val row = TransferUi.row(view(state, reason = "verify_failed"))
            assertTrue(row.finished, state)
            assertFalse(row.canAccept || row.canDecline || row.showsProgress, state)
        }
        val failed = TransferUi.row(view(State.FAILED, reason = "verify_failed"))
        assertTrue(failed.failed)
        assertTrue("hashes" in failed.label, failed.label)
    }

    @Test
    fun `the lasting lines say exactly what happened`() {
        assertEquals("File received successfully — photo.jpg (hashes verified)",
            TransferUi.statusLine(State.RECEIVED, false, "photo.jpg", ""))
        assertEquals("File sent successfully — photo.jpg (they received it and verified it)",
            TransferUi.statusLine(State.DELIVERED, true, "photo.jpg", ""))
        assertTrue(TransferUi.statusLine(State.FAILED, false, "photo.jpg", "auth_failed")!!
            .startsWith("File transfer failed — photo.jpg"))
        assertTrue("declined" in TransferUi.statusLine(State.DECLINED, true, "p", "by_peer")!!)
        assertTrue("cancelled" in TransferUi.statusLine(State.CANCELLED, false, "p", "by_peer")!!)
        assertTrue("Waiting for them to confirm" in
            TransferUi.statusLine(State.SENT, true, "p", "")!!)
        for (moving in listOf(State.OFFERED, State.WAITING, State.ACCEPTED))
            assertNull(TransferUi.statusLine(moving, false, "p", ""), moving)
    }

    @Test
    fun `every reason code has words and an unknown one still does`() {
        for (r in listOf("lost_chunk", "auth_failed", "verify_failed", "transport",
                         "by_peer", "by_us", "", "something_new"))
            assertTrue(TransferUi.reasonText(r).isNotBlank(), r)
    }

    // -- through ChatState --------------------------------------------------------

    private fun event(state: String, outgoing: Boolean = false, id: String = "t1",
                      reason: String = "") =
        OtrEvent.FileTransferChanged("Bob@X.i2p/phone", id, "photo.jpg", 40_960,
                                     outgoing, state, reason)

    private fun chat(vault: InMemoryVault = InMemoryVault()): ChatState =
        ChatState(PersistentMessageStore(vault)).apply {
            bindVault(vault)
            bindAccount(AccountScope.of("owner@x.i2p"))
        }

    @Test
    fun `an offer is prompted once, announced once, and cleared by any answer`() {
        val c = chat()
        assertTrue(c.handle(event(State.OFFERED)), "a new offer was not announced")
        assertFalse(c.handle(event(State.OFFERED)), "the same offer buzzed twice")
        assertEquals(listOf("t1"), c.pendingFileOffers.map { it.transferId })
        c.handle(event(State.ACCEPTED))
        assertEquals(emptyList(), c.pendingFileOffers)
        assertFalse(c.handle(event(State.OFFERED, outgoing = true, id = "t2")),
                    "our own offer prompted us")
    }

    @Test
    fun `an ending becomes one lasting line that survives a restart`() {
        val vault = InMemoryVault()
        val c = chat(vault)
        c.handle(event(State.OFFERED))
        c.handle(event(State.ACCEPTED))
        c.handle(event(State.RECEIVED))
        c.handle(event(State.RECEIVED))                 // a repeat is one line
        val lines = c.messages("bob@x.i2p").filter { it.security == SecurityLabel.SYSTEM }
        assertEquals(1, lines.size)
        assertTrue("File received successfully" in lines[0].body)

        val again = chat(vault)
        assertEquals(lines.map { it.body },
            again.messages("bob@x.i2p").filter { it.security == SecurityLabel.SYSTEM }.map { it.body })
        assertEquals(emptyList(), again.pendingFileOffers, "an offer outlived the process")
    }

    @Test
    fun `a file line does not count as unread`() {
        val c = chat()
        c.handle(event(State.RECEIVED))
        assertEquals(0, c.conversations().first { it.jid == "bob@x.i2p" }.unread)
    }

    @Test
    fun `signing in as somebody else drops the last account's offers`() {
        val c = chat()
        c.handle(event(State.OFFERED))
        c.bindAccount(AccountScope.of("dave@x.i2p"))
        assertEquals(emptyList(), c.pendingFileOffers)
    }
}
