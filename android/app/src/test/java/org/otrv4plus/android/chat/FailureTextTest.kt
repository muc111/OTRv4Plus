// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Nothing the bridge reports is silent unless it is listed as quiet. */
class FailureTextTest {

    @Test
    fun `a call that could not go out says why`() {
        assertTrue(FailureText.text("call_tunnel", "bob@x.i2p")!!.contains("I2P"))
        assertTrue(FailureText.text("call_not_placed", "bob@x.i2p") != null)
    }

    @Test
    fun `a code this build does not know is named, not dropped`() {
        assertEquals(FailureText.fallback("brand_new_code"),
                     FailureText.text("brand_new_code", null))
        assertTrue("brand_new_code" in FailureText.fallback("brand_new_code"))
    }

    @Test
    fun `a peer's malformed control message does not write to the screen`() {
        for (code in FailureText.QUIET.keys) assertNull(FailureText.text(code, "room@muc.x.i2p"), code)
    }

    @Test
    fun `the earlier maps still decide their own codes`() {
        assertTrue(FailureText.text("smp_cooldown", "bob@x.i2p")!!.contains("30 seconds"))
        assertTrue(FailureText.text("group_keys_missing", "room@muc.x.i2p")!!.contains("keys"))
    }

    @Test
    fun `a failure reaches the conversation`() {
        val s = ChatState().apply { bindAccount(AccountScope.of("me@x.i2p")) }
        s.handle(org.otrv4plus.android.bridge.OtrEvent.Failed("bob@x.i2p", "group_send_failed"))
        assertTrue(s.notice!!.contains("could not be sent"), s.notice)
        s.dismissNotice()
        s.handle(org.otrv4plus.android.bridge.OtrEvent.Failed("room@muc.x.i2p", "call_control_failed"))
        assertNull(s.notice, "a quiet code wrote to the screen")
    }
}
