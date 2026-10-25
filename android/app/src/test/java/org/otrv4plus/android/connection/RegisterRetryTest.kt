// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegisterRetryTest {

    @Test
    fun `not reached through a warming built-in router is tried again`() {
        assertTrue(RegisterRetry.again("network", attempt = 1, elapsedMs = 0, builtInRouter = true))
        assertTrue(RegisterRetry.again("timeout", attempt = 9, elapsedMs = 9 * 60_000L, builtInRouter = true))
        assertTrue(RegisterRetry.again("i2p_destination_unreachable", 2, 60_000L, true))
    }

    @Test
    fun `within the budget only`() {
        assertFalse(RegisterRetry.again("network", 20, RegisterRetry.BUDGET_MS, builtInRouter = true))
    }

    @Test
    fun `through a router already up, a few tries`() {
        assertTrue(RegisterRetry.again("network", 1, 0, builtInRouter = false))
        assertTrue(RegisterRetry.again("network", 2, 0, builtInRouter = false))
        assertFalse(RegisterRetry.again("network", RegisterRetry.READY_ROUTER_TRIES, 0, builtInRouter = false))
    }

    @Test
    fun `what the server said is final at once`() {
        for (code in listOf("ok", "conflict", "not_acceptable", "not_allowed", "forbidden",
                            "registration_captcha_required", "resource_constraint",
                            "server_identity_changed", "tor_unavailable")) {
            assertFalse(RegisterRetry.again(code, 1, 0, builtInRouter = true), code)
        }
    }

    @Test
    fun `the pause grows and stops growing`() {
        assertEquals(listOf(5_000L, 10_000L, 20_000L, 30_000L, 30_000L),
                     (1..5).map(RegisterRetry::delayMs))
    }

    @Test
    fun `progress says which try and what the router is doing`() {
        assertEquals("Creating the account…", RegisterRetry.progress(1, null))
        assertEquals("Creating the account (try 3)… Built-in router: starting",
                     RegisterRetry.progress(3, "Built-in router: starting"))
    }
}
