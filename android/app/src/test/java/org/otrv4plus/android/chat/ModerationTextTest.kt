// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Moderation
import org.otrv4plus.android.bridge.RoomOutcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ModerationTextTest {

    private val ok = RoomOutcome(true, "ok", "")

    @Test
    fun `the state is said plainly`() {
        assertEquals("Not banned.", ModerationText.status(Moderation(ok)))
        assertEquals("Banned permanently.", ModerationText.status(Moderation(ok, true, 0)))
        assertEquals("Banned until 2026-10-24 20:43 UTC.",
                     ModerationText.status(Moderation(ok, true, 1_792_874_580)))
        assertEquals("An admin cannot be banned.", ModerationText.status(
            Moderation(RoomOutcome(false, "moderation_refused", "An admin cannot be banned."))))
    }

    @Test
    fun `days are a whole number from 1 to ten years`() {
        assertEquals(7, ModerationText.days(" 7 "))
        assertNull(ModerationText.days("0"))
        assertNull(ModerationText.days("-2"))
        assertNull(ModerationText.days("3651"))
        assertNull(ModerationText.days("seven"))
    }
}
