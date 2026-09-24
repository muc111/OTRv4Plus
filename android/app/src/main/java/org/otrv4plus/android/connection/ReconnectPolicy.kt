// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * When to try again, and when not to.
 *
 * Plain Kotlin with no clock, no coroutines and no Android, for the same
 * reason `ChatState` is: reconnect logic that can only run inside a service on
 * a device is reconnect logic that gets checked by reading it, and the bugs it
 * hides -- two attempts racing, a busy loop, reconnecting after the user said
 * stop -- are all invisible until they are happening on someone's phone.
 *
 * The caller owns the waiting. This owns the decision.
 *
 * THE FOUR THINGS IT HAS TO GET RIGHT
 * -----------------------------------
 * 1. **No reconnect after an explicit disconnect.** "Stop" means stop. A
 *    policy that reconnects anyway takes the I2P tunnel back up and the user
 *    cannot tell why. [onUserDisconnect] latches until [onUserConnect].
 * 2. **No overlapping attempts.** Two in flight means two SAM tunnels and two
 *    XMPP streams for one account, and the second one's failure tears down the
 *    first one's success. [beginAttempt] is the single-flight gate and it is
 *    the caller's job to honour it.
 * 3. **No busy loop.** The delay grows, and it is bounded below by
 *    [firstDelayMs] so a failure that returns instantly cannot spin.
 * 4. **Bounded growth.** Capped at [maxDelayMs]; an unbounded backoff
 *    eventually means "never" without saying so.
 *
 * THE NUMBERS
 * -----------
 * A cold I2P tunnel is 30-90 seconds (ANDROID_DEVICE_TEST.md §3 step 7), so
 * retrying after two seconds would simply queue another doomed attempt behind
 * the one still building. The first delay is therefore in the same order as a
 * tunnel build rather than the sub-second figure a clearnet client would use.
 * The terminal client's IRC reconnect settled on 30/60/90/120s for the same
 * reason; this is that shape, as a capped doubling.
 */
class ReconnectPolicy(
    private val firstDelayMs: Long = DEFAULT_FIRST_DELAY_MS,
    private val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
    private val factor: Double = 2.0,
) {

    /** Consecutive failures since the last success or user action. */
    var attempts: Int = 0
        private set

    /** True once the user has asked to disconnect, until they ask to connect. */
    var suppressed: Boolean = false
        private set

    /** True while an attempt is in flight. */
    var inFlight: Boolean = false
        private set

    /** The user pressed Connect. Clears the latch and the backoff. */
    fun onUserConnect() {
        suppressed = false
        attempts = 0
    }

    /**
     * The user pressed Disconnect.
     *
     * Latched rather than a one-shot flag: the failure that follows a
     * deliberate disconnect must not be treated as a reason to come back.
     */
    fun onUserDisconnect() {
        suppressed = true
        attempts = 0
    }

    /** A connection succeeded. The next failure starts from the first delay. */
    fun onConnected() {
        attempts = 0
    }

    /**
     * Claim the right to attempt a connection.
     *
     * Returns false when one is already in flight, or when the user has asked
     * to stay disconnected. The caller must not proceed on false.
     */
    fun beginAttempt(): Boolean {
        if (suppressed || inFlight) return false
        inFlight = true
        return true
    }

    /** Release the single-flight gate. Always call this, including on failure. */
    fun endAttempt() {
        inFlight = false
    }

    /**
     * How long to wait before trying again, or null for "do not".
     *
     * Null means exactly that and nothing else: the user asked to stay
     * disconnected. There is no attempt limit, because a phone that has been
     * out of signal for an hour should still reconnect when it comes back --
     * the bound is on the DELAY, not on the number of tries.
     */
    fun nextDelayMs(): Long? {
        if (suppressed) return null
        val step = attempts
        attempts = step + 1
        var delay = firstDelayMs.toDouble()
        repeat(step) {
            delay *= factor
            if (delay >= maxDelayMs) return maxDelayMs
        }
        return delay.toLong().coerceIn(firstDelayMs, maxDelayMs)
    }

    companion object {
        /** In the order of an I2P tunnel build, not of a clearnet retry. */
        const val DEFAULT_FIRST_DELAY_MS = 30_000L

        /** Five minutes. Long enough to be quiet, short enough to recover. */
        const val DEFAULT_MAX_DELAY_MS = 300_000L
    }
}
