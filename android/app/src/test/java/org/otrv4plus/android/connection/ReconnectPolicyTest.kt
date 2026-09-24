// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Reconnect, and the four ways it goes wrong.
 *
 * Executed rather than reasoned about, which is the point of the policy being
 * plain Kotlin: two racing attempts, a busy loop, and a reconnect after the
 * user said stop are all invisible in review and all obvious here.
 */
class ReconnectPolicyTest {

    private fun policy() = ReconnectPolicy(
        firstDelayMs = 1_000, maxDelayMs = 8_000, factor = 2.0)

    // ── no reconnect after an explicit disconnect ───────────────────────────

    @Test
    fun `an explicit disconnect stops reconnecting`() {
        val p = policy()
        p.onUserDisconnect()
        assertNull(p.nextDelayMs())
    }

    @Test
    fun `an explicit disconnect refuses further attempts`() {
        val p = policy()
        p.onUserDisconnect()
        assertFalse(p.beginAttempt())
    }

    @Test
    fun `the disconnect latch survives later failures`() {
        // The failure that follows a deliberate teardown is not a reason to
        // come back.
        val p = policy()
        p.onUserDisconnect()
        repeat(3) { assertNull(p.nextDelayMs()) }
    }

    @Test
    fun `pressing connect clears the latch`() {
        val p = policy()
        p.onUserDisconnect()
        p.onUserConnect()
        assertTrue(p.beginAttempt())
        p.endAttempt()
        assertEquals(1_000L, p.nextDelayMs())
    }

    // ── no overlapping attempts ─────────────────────────────────────────────

    @Test
    fun `a second attempt is refused while one is in flight`() {
        // Two means two SAM tunnels and two XMPP streams for one account.
        val p = policy()
        assertTrue(p.beginAttempt())
        assertFalse(p.beginAttempt())
    }

    @Test
    fun `finishing an attempt allows the next`() {
        val p = policy()
        assertTrue(p.beginAttempt())
        p.endAttempt()
        assertTrue(p.beginAttempt())
    }

    @Test
    fun `ending an attempt that never began is harmless`() {
        val p = policy()
        p.endAttempt()
        assertTrue(p.beginAttempt())
    }

    // ── no busy loop, bounded growth ────────────────────────────────────────

    @Test
    fun `the delay grows`() {
        val p = policy()
        assertEquals(1_000L, p.nextDelayMs())
        assertEquals(2_000L, p.nextDelayMs())
        assertEquals(4_000L, p.nextDelayMs())
    }

    @Test
    fun `the delay is capped`() {
        val p = policy()
        repeat(10) { p.nextDelayMs() }
        assertEquals(8_000L, p.nextDelayMs())
    }

    @Test
    fun `no delay is ever shorter than the first`() {
        // The guard against a failure that returns instantly spinning the CPU
        // and the I2P router together.
        val p = policy()
        repeat(20) {
            val delay = p.nextDelayMs()
            assertTrue(delay != null && delay >= 1_000L, "delay was $delay")
        }
    }

    @Test
    fun `a success resets the backoff`() {
        val p = policy()
        p.nextDelayMs()
        p.nextDelayMs()
        p.onConnected()
        assertEquals(1_000L, p.nextDelayMs())
    }

    @Test
    fun `there is no attempt limit`() {
        // A phone out of signal for an hour must still reconnect when it comes
        // back. The bound is on the delay, not on the number of tries.
        val p = policy()
        repeat(500) { p.nextDelayMs() }
        assertEquals(8_000L, p.nextDelayMs())
    }

    @Test
    fun `attempts are counted`() {
        val p = policy()
        assertEquals(0, p.attempts)
        p.nextDelayMs()
        p.nextDelayMs()
        assertEquals(2, p.attempts)
    }

    // ── the shipped numbers ─────────────────────────────────────────────────

    @Test
    fun `the default first delay is in the order of a tunnel build`() {
        // A cold I2P tunnel is 30-90s. Retrying after two seconds just queues
        // another doomed attempt behind the one still building.
        assertTrue(ReconnectPolicy.DEFAULT_FIRST_DELAY_MS >= 10_000L)
        assertTrue(
            ReconnectPolicy.DEFAULT_MAX_DELAY_MS >
                ReconnectPolicy.DEFAULT_FIRST_DELAY_MS)
    }

    @Test
    fun `the default policy behaves like the tuned one`() {
        val p = ReconnectPolicy()
        assertEquals(ReconnectPolicy.DEFAULT_FIRST_DELAY_MS, p.nextDelayMs())
        p.onUserDisconnect()
        assertNull(p.nextDelayMs())
    }
}
