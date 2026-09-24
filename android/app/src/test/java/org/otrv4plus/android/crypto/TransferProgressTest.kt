// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.FileTransferView
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Phases, speed and ETA: named from engine state, never invented. */
class TransferProgressTest {

    private fun t(state: String, progress: Float = 0f, outgoing: Boolean = false) =
        FileTransferView("id", "bob@x", "a.bin", 1_000_000, outgoing,
                         accepted = state != "offered", cancelled = false,
                         progress = progress, state = state)

    @Test
    fun `every phase is named`() {
        val P = TransferUi.Phase
        assertEquals(P.WAITING, TransferUi.phase(t("offered")))
        assertEquals(P.WAITING, TransferUi.phase(t("waiting", outgoing = true)))
        assertEquals(P.PREPARING, TransferUi.phase(t("accepted", 0f, outgoing = true)))
        assertEquals(P.ACCEPTED, TransferUi.phase(t("accepted", 0f)))
        assertEquals(P.SENDING, TransferUi.phase(t("accepted", 0.4f, outgoing = true)))
        assertEquals(P.RECEIVING, TransferUi.phase(t("accepted", 0.4f)))
        assertEquals(P.VERIFYING, TransferUi.phase(t("accepted", 1f)))
        assertEquals(P.VERIFYING, TransferUi.phase(t("sent", 1f, outgoing = true)))
        assertEquals(P.COMPLETED, TransferUi.phase(t("received", 1f)))
        assertEquals(P.COMPLETED, TransferUi.phase(t("delivered", 1f, outgoing = true)))
        assertEquals(P.FAILED, TransferUi.phase(t("failed")))
        assertEquals(P.CANCELLED, TransferUi.phase(t("cancelled")))
        assertEquals(P.DECLINED, TransferUi.phase(t("declined")))
        assertEquals(P.RECEIVING, TransferUi.row(t("accepted", 0.5f)).phase)
    }

    @Test
    fun `the first sample only says it is calculating`() {
        val m = TransferUi.RateMeter()
        val r = m.sample("a", 0, 1000, 0)
        assertNull(r.bytesPerSecond)
        assertEquals("Calculating ETA…", r.text())
    }

    @Test
    fun `a steady rate gives a speed and an ETA`() {
        val m = TransferUi.RateMeter()
        m.sample("a", 0, 100_000, 0)
        var r = m.sample("a", 10_000, 100_000, 1_000)
        r = m.sample("a", 20_000, 100_000, 2_000)
        assertNotNull(r.bytesPerSecond)
        assertEquals(10_000.0, r.bytesPerSecond!!, 1.0)
        assertEquals(8L, r.etaSeconds)
        assertTrue(r.text().contains("ETA 8 s"), r.text())
    }

    @Test
    fun `the rate is weighted toward the recent, not the average`() {
        val m = TransferUi.RateMeter(alpha = 0.5)
        m.sample("a", 0, 1_000_000, 0)
        m.sample("a", 100_000, 1_000_000, 1_000)        // 100 kB/s
        val r = m.sample("a", 110_000, 1_000_000, 2_000) // then 10 kB/s
        // EWMA 0.5*10k + 0.5*100k = 55k; the whole-run average would be 55k
        // too here, so check a third step pulls further toward the new rate.
        val r2 = m.sample("a", 120_000, 1_000_000, 3_000)
        assertTrue(r2.bytesPerSecond!! < r.bytesPerSecond!!)
        assertTrue(r2.bytesPerSecond!! < 120_000.0 / 3.0 + 1)
    }

    @Test
    fun `a stall says ETA unavailable instead of a number`() {
        val m = TransferUi.RateMeter()
        m.sample("a", 0, 100_000, 0)
        m.sample("a", 10_000, 100_000, 1_000)
        val r = m.sample("a", 10_000, 100_000, 1_000 + TransferUi.RateMeter.STALL_MS)
        assertTrue(r.stalled)
        assertNull(r.etaSeconds)
        assertEquals("ETA unavailable", r.text())
    }

    @Test
    fun `durations read naturally`() {
        assertEquals("45 s", TransferUi.duration(45))
        assertEquals("3 min 20 s", TransferUi.duration(200))
        assertEquals("1 h 05 min", TransferUi.duration(3900))
    }

    @Test
    fun `the moving detail carries bytes, percent, speed and ETA`() {
        val rate = TransferUi.Rate(2048.0, 30)
        val row = TransferUi.row(t("accepted", 0.5f), rate)
        assertTrue(row.detail.contains("%"), row.detail)
        assertTrue(row.detail.contains("2 KB/s"), row.detail)
        assertTrue(row.detail.contains("ETA 30 s"), row.detail)
    }
}
