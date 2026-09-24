// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What Create account tells the user, and where it points them next.
 *
 * The codes are Python's, from `otrv4plus_registration.CODES`, and they cross
 * the bridge as strings. Nothing here re-derives a meaning: the two questions
 * this type answers are the two the screen actually has — "is retyping the
 * username the fix" and "is trying again pointless" — and they exist so the UI
 * does not branch on string literals in four places and get one of them wrong.
 */
class RegistrationOutcomeTest {

    private fun outcome(code: String, ok: Boolean = false) =
        RegistrationOutcome(ok = ok, code = code, detail = "…")

    @Test
    fun `success is success`() {
        assertTrue(outcome("ok", ok = true).ok)
    }

    // ── put the focus where the fix is ──────────────────────────────────────

    @Test
    fun `a taken username is about the username`() {
        assertTrue(outcome("conflict").isAboutTheUsername)
    }

    @Test
    fun `details the server rejected are about the username`() {
        assertTrue(outcome("not_acceptable").isAboutTheUsername)
    }

    @Test
    fun `a network failure is not about the username`() {
        assertFalse(outcome("network").isAboutTheUsername,
            "sending the user back to retype a name that was fine")
    }

    @Test
    fun `a timeout is not about the username`() {
        assertFalse(outcome("timeout").isAboutTheUsername)
    }

    // ── do not invite a retry that cannot work ──────────────────────────────

    @Test
    fun `a server with no in-band registration is permanent`() {
        assertTrue(outcome("unsupported").isPermanent)
    }

    @Test
    fun `a server that forbids it is permanent`() {
        for (code in listOf("not_allowed", "service_unavailable", "forbidden")) {
            assertTrue(outcome(code).isPermanent, code)
        }
    }

    @Test
    fun `a timeout is worth trying again`() {
        assertFalse(outcome("timeout").isPermanent,
            "over I2P a slow round trip is ordinary, not a refusal")
    }

    @Test
    fun `a network failure is worth trying again`() {
        assertFalse(outcome("network").isPermanent)
    }

    @Test
    fun `a taken username is worth trying again with another one`() {
        assertFalse(outcome("conflict").isPermanent)
    }

    @Test
    fun `resource constraint is temporary, not permanent`() {
        assertFalse(outcome("resource_constraint").isPermanent,
            "the server said 'not right now', which is not 'never'")
    }

    // ── the two questions are independent ───────────────────────────────────

    @Test
    fun `no code is both`() {
        for (code in listOf("ok", "conflict", "not_acceptable", "unsupported",
                            "not_allowed", "service_unavailable", "forbidden",
                            "not_authorized", "resource_constraint", "timeout",
                            "network", "cancelled", "unknown")) {
            val o = outcome(code)
            assertFalse(o.isAboutTheUsername && o.isPermanent,
                "$code asks the user to fix a field on a server that will " +
                    "never accept it")
        }
    }

    @Test
    fun `an unrecognised code claims nothing`() {
        val o = outcome("something-python-grew-later")
        assertFalse(o.isAboutTheUsername)
        assertFalse(o.isPermanent)
    }

    // ── it is not a connection ──────────────────────────────────────────────

    @Test
    fun `a successful registration is not a session`() {
        // The type has no `connected` field at all, which is the point: a
        // ConnectionStatus would render "connected: false" next to a success
        // and read as a failure to somebody who had just created an account.
        val fields = RegistrationOutcome::class.java.declaredFields
            .map { it.name }
        assertFalse(fields.contains("connected"))
        assertEquals(setOf("ok", "code", "detail"),
            fields.filter { !it.contains('$') }.toSet())
    }
}
