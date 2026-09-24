// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The handshake card: shown only while one runs, in words, from real steps. */
class HandshakeUiTest {

    private fun s(stage: String, step: Int, have: Int = 0, of: Int = 0, elapsed: Int = 0) =
        HandshakeUi.Status(stage, step, 3, have, of, elapsed)

    @Test
    fun `nothing is shown when idle or established`() {
        assertNull(HandshakeUi.view(HandshakeUi.Status.IDLE))
        assertNull(HandshakeUi.view(s("established", 3)))
    }

    @Test
    fun `every stage has words and a step`() {
        for ((stage, step) in listOf("receiving_request" to 1, "waiting_reply" to 1,
                                     "receiving_reply" to 2, "replying" to 2,
                                     "waiting_confirm" to 2, "receiving_confirm" to 3)) {
            val v = HandshakeUi.view(s(stage, step))
            assertNotNull(v, stage)
            assertTrue("step $step of 3" in v.title, v.title)
            assertTrue(v.detail != "Working", "no words for $stage")
        }
    }

    @Test
    fun `parts arriving move the bar and are named`() {
        val none = HandshakeUi.view(s("receiving_reply", 2, 0, 2))!!
        val half = HandshakeUi.view(s("receiving_reply", 2, 1, 2))!!
        assertTrue("1 of 2 parts" in half.detail)
        assertTrue(half.progress > none.progress)
        assertEquals((1f + 0.5f) / 3f, half.progress, 0.001f)
    }

    @Test
    fun `the bar never claims done or nothing`() {
        assertTrue(HandshakeUi.view(s("waiting_reply", 1))!!.progress > 0f)
        assertTrue(HandshakeUi.view(s("receiving_confirm", 3, 3, 3))!!.progress < 1f)
    }

    @Test
    fun `elapsed says why it takes long`() {
        val v = HandshakeUi.view(s("waiting_reply", 1, elapsed = 75))!!
        assertTrue(v.elapsed.startsWith("1 min 15 s"))
        assertTrue("I2P" in v.elapsed)
    }

    @Test
    fun `a failure is said, not shown as progress`() {
        val v = HandshakeUi.view(s("failed", 0))!!
        assertTrue("failed" in v.title)
        assertEquals(0f, v.progress)
    }
}
