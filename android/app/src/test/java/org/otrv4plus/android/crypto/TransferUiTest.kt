// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.FileOutcome
import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.SecurityState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the file controls may offer, driven rather than read.
 *
 * The rule at the top is the one that matters: a file is only offered to a
 * verified peer. A file is a thing you cannot take back, and encryption
 * alone proves nobody is reading it in transit, not who is at the far end.
 */
class TransferUiTest {

    private fun transfer(
        filename: String = "notes.txt",
        outgoing: Boolean = false,
        accepted: Boolean = false,
        cancelled: Boolean = false,
        progress: Float = 0f,
        size: Long = 2048,
    ) = FileTransferView("id", "bob@x.i2p", filename, size, outgoing,
                         accepted, cancelled, progress)

    // ── the gate ────────────────────────────────────────────────────────────

    @Test
    fun `only a verified conversation may send a file`() {
        assertEquals(TransferUi.Offer.Available,
            TransferUi.offer(SecurityState.SMP_VERIFIED))
        for (state in SecurityState.entries - SecurityState.SMP_VERIFIED) {
            assertTrue(TransferUi.offer(state) !is TransferUi.Offer.Available,
                "$state was offered a file transfer unverified")
        }
    }

    @Test
    fun `encryption without verification points at verification`() {
        for (state in listOf(SecurityState.ENCRYPTED,
                             SecurityState.FINGERPRINT)) {
            assertEquals(TransferUi.Offer.NeedsVerification,
                TransferUi.offer(state))
        }
    }

    @Test
    fun `a changed key does not invite the user to verify`() {
        assertEquals(TransferUi.Offer.NeedsEncryption,
            TransferUi.offer(SecurityState.FINGERPRINT_MISMATCH))
    }

    @Test
    fun `every security state has an answer`() {
        for (state in SecurityState.entries) TransferUi.offer(state)
    }

    // ── rows ────────────────────────────────────────────────────────────────

    @Test
    fun `an incoming offer can be accepted or declined`() {
        val row = TransferUi.row(transfer())
        assertTrue(row.canAccept)
        assertTrue(row.canDecline)
        assertTrue("notes.txt" in row.label)
        assertTrue("2 KB" in row.label, "the size is not shown: ${row.label}")
    }

    @Test
    fun `an outgoing transfer is never acceptable by the sender`() {
        assertFalse(TransferUi.row(transfer(outgoing = true)).canAccept,
            "the sender was offered a button to accept their own file")
    }

    @Test
    fun `an accepted transfer is not acceptable again`() {
        // A second Accept is a button that does nothing.
        assertFalse(TransferUi.row(transfer(accepted = true)).canAccept)
    }

    @Test
    fun `an accepted transfer shows progress and an unaccepted one does not`() {
        assertTrue(TransferUi.row(transfer(accepted = true)).showsProgress)
        assertFalse(TransferUi.row(transfer(accepted = false)).showsProgress,
            "progress was shown for a transfer nobody has accepted")
    }

    @Test
    fun `an outgoing offer says it is waiting`() {
        val row = TransferUi.row(transfer(outgoing = true, accepted = false))
        assertTrue("waiting" in row.label, row.label)
        assertFalse(row.showsProgress)
    }

    @Test
    fun `a cancelled transfer offers nothing`() {
        val row = TransferUi.row(transfer(cancelled = true))
        assertFalse(row.canAccept)
        assertFalse(row.canDecline)
        assertTrue("cancelled" in row.label)
    }

    @Test
    fun `a transfer with no filename still reads as something`() {
        // The name comes from a peer. Blank must not render an empty row.
        assertTrue(TransferUi.row(transfer(filename = "")).label.isNotBlank())
    }

    @Test
    fun `every combination produces a row`() {
        for (outgoing in listOf(true, false)) {
            for (accepted in listOf(true, false)) {
                for (cancelled in listOf(true, false)) {
                    val row = TransferUi.row(
                        transfer(outgoing = outgoing, accepted = accepted,
                                 cancelled = cancelled))
                    assertTrue(row.label.isNotBlank())
                }
            }
        }
    }

    // ── the small things ────────────────────────────────────────────────────

    @Test
    fun `sizes read as a person would say them`() {
        assertEquals("512 B", TransferUi.humanBytes(512))
        assertEquals("2 KB", TransferUi.humanBytes(2048))
        assertEquals("1.0 MB", TransferUi.humanBytes(1024L * 1024))
        assertEquals("2.5 MB", TransferUi.humanBytes((2.5 * 1024 * 1024).toLong()))
    }

    @Test
    fun `a started transfer needs nothing said about it`() {
        assertNull(TransferUi.refusal(FileOutcome.STARTED))
    }

    @Test
    fun `every refusal code says something`() {
        for (code in FileOutcome.ALL) {
            if (code == FileOutcome.STARTED) continue
            assertTrue(TransferUi.refusal(code)?.isNotBlank() == true,
                "$code produced no explanation")
        }
    }

    @Test
    fun `the unverified refusal names the remedy`() {
        assertTrue("Verify" in TransferUi.refusal(FileOutcome.UNVERIFIED)!!)
    }

    @Test
    fun `an unknown outcome is still explained`() {
        assertTrue(TransferUi.refusal("something_new")?.isNotBlank() == true)
    }
}
