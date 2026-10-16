// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Owner (2026-10-16): another sign-in of our account must be said. */
class AccountSessionsTest {

    @Test
    fun `no other session shows nothing`() {
        assertNull(AccountSessions.banner(0))
    }

    @Test
    fun `another session is a warning that says what to do`() {
        val one = AccountSessions.banner(1)!!
        assertTrue("another device" in one)
        assertTrue("change your password" in one)
        assertTrue("3 other devices" in AccountSessions.banner(3)!!)
    }

    @Test
    fun `signing them out says they can come back`() {
        val text = AccountSessions.outcome(true, "ok", 2)
        assertTrue("2 other session" in text)
        assertTrue("change it" in text)
        assertTrue("no other session" in AccountSessions.outcome(true, "ok", 0))
    }

    @Test
    fun `a refusal is explained`() {
        assertTrue("server admin" in AccountSessions.outcome(false, "forbidden", 0))
        assertTrue("(timeout)" in AccountSessions.outcome(false, "timeout", 0))
    }
}
