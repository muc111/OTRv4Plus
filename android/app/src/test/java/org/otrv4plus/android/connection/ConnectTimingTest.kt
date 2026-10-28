// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals

class ConnectTimingTest {

    @Test
    fun `minutes and seconds, hours when it comes to that`() {
        assertEquals("0:07", ConnectTiming.clock(7_400))
        assertEquals("3:42", ConnectTiming.clock(222_000))
        assertEquals("1:02:05", ConnectTiming.clock(3_725_000))
    }

    @Test
    fun `a warm router shows only the total`() {
        assertEquals("0:38", ConnectTiming.line(ConnectTiming.Result(38_000, null, 1)))
    }

    @Test
    fun `the router's share is shown when it was waited for`() {
        assertEquals("4:10 (I2P router 2:30, sign-in 1:40), 2 attempts",
            ConnectTiming.line(ConnectTiming.Result(250_000, 150_000, 2)))
    }

    @Test
    fun `the report's note carries every part, the router as 0 when it was not waited for`() {
        assertEquals("total_ms=145000 router_ms=110000 attempts=1",
            ConnectTiming.note(ConnectTiming.Result(145_000, 110_000, 1)))
        assertEquals("total_ms=38000 router_ms=0 attempts=2",
            ConnectTiming.note(ConnectTiming.Result(38_000, null, 2)))
    }
}
