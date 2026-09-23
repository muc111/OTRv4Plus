// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.CallState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** When an incoming call rings the phone, driven over every transition. */
class CallAlertTest {

    @Test
    fun `a call that starts ringing rings`() {
        assertEquals(CallAlert.Change.START,
            CallAlert.change(CallState.IDLE, CallState.RINGING))
    }

    @Test
    fun `ringing reported twice rings once`() {
        // Otherwise one call buzzes the phone once per drain.
        assertNull(CallAlert.change(CallState.RINGING, CallState.RINGING))
    }

    @Test
    fun `leaving ringing takes the notification down whatever happened`() {
        for (next in CallState.entries - CallState.RINGING) {
            assertEquals(CallAlert.Change.STOP,
                CallAlert.change(CallState.RINGING, next),
                "RINGING -> $next left the phone ringing")
        }
    }

    @Test
    fun `nothing but ringing ever rings`() {
        // An outgoing call (INVITING...), an active call, or an ending one
        // must never produce an incoming-call notification.
        for (previous in CallState.entries) {
            for (next in CallState.entries - CallState.RINGING) {
                if (previous == CallState.RINGING) continue
                assertNull(CallAlert.change(previous, next),
                    "$previous -> $next produced a notification change")
            }
        }
    }
}
