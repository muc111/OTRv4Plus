// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DrainPaceTest {

    @Test
    fun `on screen it stays live`() {
        assertEquals(DrainPace.VISIBLE_MS, DrainPace.intervalMs(uiVisible = true, inCall = false))
        assertTrue((0L..40L).all { DrainPace.readsState(it, uiVisible = true, inCall = false) })
    }

    @Test
    fun `in the background it slows and reads state only now and then`() {
        assertEquals(DrainPace.BACKGROUND_MS, DrainPace.intervalMs(uiVisible = false, inCall = false))
        val reads = (0L until 30L).count { DrainPace.readsState(it, uiVisible = false, inCall = false) }
        assertEquals(2, reads)
        assertEquals(30_000L, DrainPace.BACKGROUND_MS * DrainPace.BACKGROUND_STATE_EVERY)
    }

    @Test
    fun `a call keeps the fast pace with the screen off`() {
        assertEquals(DrainPace.VISIBLE_MS, DrainPace.intervalMs(uiVisible = false, inCall = true))
        assertTrue(DrainPace.readsState(7, uiVisible = false, inCall = true))
    }

    @Test
    fun `events are never more than two seconds late`() {
        assertFalse(DrainPace.intervalMs(false, false) > 2_000L)
    }
}
