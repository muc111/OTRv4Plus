// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The Log in button's in-progress state.
 *
 * TWO DEFECTS ON A HANDSET, ONE FILE.
 *
 * Pressing Log in changed nothing on screen. `busy` is set by the register
 * path and at start-up, never by a login, and the only other signal --
 * `phase` -- does not exist until the service has started AND the next poll
 * tick has read it back. On I2P the operation that follows takes 30-120+
 * seconds, so the button looked ignored at exactly the moment a user decides
 * whether the app is working or frozen.
 *
 * The obvious fix -- a flag set on tap, cleared when a phase arrives -- can
 * stick forever if the service never reports, leaving a permanent spinner and
 * two permanently disabled buttons. `TheTapCannotStickForever` is the half of
 * these tests that matters most.
 */
class LoginProgressTest {

    /** A clock the test moves by hand. No sleeping, no flakes. */
    private class Clock(var t: Long = 1_000L) {
        fun advance(ms: Long) { t += ms }
    }

    private fun at(clock: Clock) = LoginProgress { clock.t }

    // ── the press is visible immediately ─────────────────────────────────────

    @Test
    fun `nothing is in progress before the button is pressed`() {
        assertFalse(at(Clock()).inProgress(LinkPhase.STOPPED))
    }

    @Test
    fun `the tap shows progress before the service has any phase`() {
        // THE DEFECT. The service has not started, so the phase is still
        // STOPPED -- and the user has to see something anyway.
        val p = at(Clock())
        p.requested()
        assertTrue(p.inProgress(LinkPhase.STOPPED),
                   "the press produced no visible change")
    }

    @Test
    fun `the label says something truthful before the service answers`() {
        val p = at(Clock())
        p.requested()
        assertEquals("Connecting...", p.label(LinkPhase.STOPPED))
    }

    @Test
    fun `the label names the slow part once the phase says so`() {
        // On a two-minute operation, which slow part is running is the
        // difference between waiting and force-quitting.
        val p = at(Clock())
        p.requested()
        assertTrue(p.label(LinkPhase.CONNECTING).contains("I2P"))
        assertTrue(p.label(LinkPhase.RECONNECTING).contains("again"))
    }

    // ── the service takes over ───────────────────────────────────────────────

    @Test
    fun `progress continues once the service reports a busy phase`() {
        val clock = Clock()
        val p = at(clock)
        p.requested()
        p.observe(LinkPhase.CONNECTING)
        // Well past the handover deadline: the phase is carrying it now.
        clock.advance(LoginProgress.HANDOVER_MS * 10)
        assertTrue(p.inProgress(LinkPhase.CONNECTING),
                   "a long tunnel build stopped showing progress")
    }

    @Test
    fun `progress ends when the connection succeeds`() {
        val p = at(Clock())
        p.requested()
        p.observe(LinkPhase.CONNECTED)
        assertFalse(p.inProgress(LinkPhase.CONNECTED))
    }

    @Test
    fun `progress ends when the connection genuinely fails`() {
        // A real failure is an answer. Continuing to show "connecting" over it
        // would be the UI contradicting what it is reporting.
        val p = at(Clock())
        p.requested()
        p.observe(LinkPhase.FAILED)
        assertFalse(p.inProgress(LinkPhase.FAILED))
    }

    @Test
    fun `a reconnect still counts as in progress`() {
        // Waiting out a backoff IS the app working on it; showing it as idle
        // invites a second attempt.
        assertTrue(at(Clock()).inProgress(LinkPhase.RECONNECTING))
    }

    @Test
    fun `signing out is not a login in progress`() {
        assertFalse(at(Clock()).inProgress(LinkPhase.DISCONNECTING))
    }

    // ── the tap cannot stick forever ─────────────────────────────────────────

    inner class TheTapCannotStickForever

    @Test
    fun `an unanswered tap expires instead of spinning forever`() {
        // THE FIX'S OWN FAILURE MODE. If the service never starts, or starts
        // and reports nothing, a naive flag leaves a permanent spinner and two
        // permanently disabled buttons -- worse than the missing spinner.
        val clock = Clock()
        val p = at(clock)
        p.requested()
        assertTrue(p.inProgress(LinkPhase.STOPPED))

        clock.advance(LoginProgress.HANDOVER_MS + 1)
        assertFalse(p.inProgress(LinkPhase.STOPPED),
                    "the screen would be stuck with no way out")
    }

    @Test
    fun `the deadline does not cut off a real connection attempt`() {
        // The deadline covers the handover only. An I2P tunnel may take
        // minutes and the phase reports that perfectly well.
        val clock = Clock()
        val p = at(clock)
        p.requested()
        p.observe(LinkPhase.CONNECTING)
        clock.advance(120_000L)
        assertTrue(p.inProgress(LinkPhase.CONNECTING))
    }

    @Test
    fun `cancelling clears the tap at once`() {
        val p = at(Clock())
        p.requested()
        p.cancelled()
        assertFalse(p.inProgress(LinkPhase.STOPPED))
    }

    @Test
    fun `cancelling while the service is still busy does not hang the screen`() {
        // Back or Cancel during a tunnel build. The phase may lag; the tap
        // must not be what keeps the spinner alive.
        val p = at(Clock())
        p.requested()
        p.observe(LinkPhase.CONNECTING)
        p.cancelled()
        assertFalse(p.inProgress(LinkPhase.STOPPED))
    }

    // ── pressing twice ───────────────────────────────────────────────────────

    @Test
    fun `a second press extends rather than confuses the state`() {
        val clock = Clock()
        val p = at(clock)
        p.requested()
        clock.advance(LoginProgress.HANDOVER_MS - 1)
        p.requested()
        clock.advance(LoginProgress.HANDOVER_MS - 1)
        assertTrue(p.inProgress(LinkPhase.STOPPED),
                   "the second press should be the one that counts")
    }

    @Test
    fun `a stale tap does not resurrect after the phase went idle`() {
        val clock = Clock()
        val p = at(clock)
        p.requested()
        p.observe(LinkPhase.CONNECTED)
        assertFalse(p.inProgress(LinkPhase.STOPPED))
        clock.advance(1)
        assertFalse(p.inProgress(LinkPhase.STOPPED))
    }

    @Test
    fun `observing an idle phase does not by itself clear a fresh tap`() {
        // STOPPED is what the service reports before it has started. Clearing
        // on it would reintroduce the blind window the tap exists to cover.
        val p = at(Clock())
        p.requested()
        p.observe(LinkPhase.STOPPED)
        assertTrue(p.inProgress(LinkPhase.STOPPED))
    }
}

/**
 * What the screen is allowed to say about a failure.
 *
 * THE HANDSET REPORT, as an executable rule: "pressing Login causes the UI to
 * report transport_failed ... however, despite that reported failure, the
 * login subsequently succeeds and the app connects."
 *
 * The latch that produced it lived in `ConnectionViewModel`, which imports
 * Compose and cannot be compiled outside CI. The DECISION it makes lives in
 * `LoginProgress.problemToShow`, which can be.
 */
class ConnectionProblemTest {

    private class Clock(var t: Long = 1_000L)

    private fun at(clock: Clock) = LoginProgress { clock.t }

    @Test
    fun `a failure is shown when nothing has superseded it`() {
        // Not masked. A real failure with no later success is the answer.
        val p = at(Clock())
        assertEquals("transport_failed",
            p.problemToShow(connected = false, phase = LinkPhase.FAILED,
                            failure = "transport_failed"))
    }

    @Test
    fun `a successful connection cannot still report transport_failed`() {
        // THE BUG. Attempt one fails, the backoff retries, attempt two
        // connects -- and the screen went on showing the first verdict.
        val p = at(Clock())
        assertEquals(null,
            p.problemToShow(connected = true, phase = LinkPhase.CONNECTED,
                            failure = "transport_failed"),
            "a working session still reported the failed attempt")
    }

    @Test
    fun `an attempt still running does not show last time's failure`() {
        val p = at(Clock())
        assertEquals(null,
            p.problemToShow(connected = false, phase = LinkPhase.CONNECTING,
                            failure = "transport_failed"))
    }

    @Test
    fun `a reconnect in progress does not show the failure that caused it`() {
        val p = at(Clock())
        assertEquals(null,
            p.problemToShow(connected = false, phase = LinkPhase.RECONNECTING,
                            failure = "connect_failed"))
    }

    @Test
    fun `the tapped-but-unanswered window shows no failure either`() {
        // The press has been taken and the service has not spoken yet. Showing
        // the previous attempt's code here is what makes a fresh press look
        // like it failed instantly.
        val p = at(Clock())
        p.requested()
        assertEquals(null,
            p.problemToShow(connected = false, phase = LinkPhase.STOPPED,
                            failure = "transport_failed"))
    }

    @Test
    fun `once the tap expires the real failure comes back`() {
        // The window suppresses, it does not erase. If nothing succeeded, the
        // user must still end up being told.
        val clock = Clock()
        val p = at(clock)
        p.requested()
        clock.t += LoginProgress.HANDOVER_MS + 1
        assertEquals("transport_failed",
            p.problemToShow(connected = false, phase = LinkPhase.STOPPED,
                            failure = "transport_failed"))
    }

    @Test
    fun `no failure means nothing to show`() {
        val p = at(Clock())
        assertEquals(null, p.problemToShow(false, LinkPhase.STOPPED, null))
        assertEquals(null, p.problemToShow(false, LinkPhase.STOPPED, ""))
    }

    @Test
    fun `being connected outranks every phase`() {
        // A drop mid-poll can pair connected=true with a busy phase. The
        // session existing is the stronger fact.
        val p = at(Clock())
        for (phase in LinkPhase.entries) {
            assertEquals(null, p.problemToShow(true, phase, "transport_failed"),
                         "connected + $phase still showed a failure")
        }
    }
}
