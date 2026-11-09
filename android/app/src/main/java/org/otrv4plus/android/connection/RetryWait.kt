// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The wait between reconnect attempts, which the phone waking up cuts short.
 *
 * WHY: device report 2026-11-09 (Pixel 7). After a session timeout at
 * 19:52:12 the policy chose a ~60 s wait (ReconnectPolicy), and the next
 * attempt ran at 19:59:08. With the screen off, Android's Doze suspends the
 * CPU, so a coroutine `delay` fires only at the next maintenance window --
 * and Doze ignores wake locks, so holding one would not have helped. What
 * does help is not waiting out the rest of a backoff once the phone is awake
 * again: screen on, unlock, Doze exit or a new network [wake] the wait, and
 * the attempt starts at once.
 *
 * It also measures how late a wait that ran to the end was ([Outcome.lateMs],
 * on a clock that counts sleep), so a report can say "the phone was asleep"
 * instead of showing minutes of silence.
 *
 * Plain Kotlin with an injected clock, like ReconnectPolicy, so it is tested
 * on the JVM.
 */
class RetryWait(
    /** Milliseconds on a clock that keeps counting while the CPU sleeps. */
    private val clock: () -> Long,
    /** A wake this soon after the wait began is ignored: no retry storm. */
    private val minWaitMs: Long = MIN_WAIT_MS,
) {
    private val nudges = Channel<String>(Channel.CONFLATED)

    @Volatile
    private var startedAt: Long = -1L

    /** True while [await] is waiting. */
    val waiting: Boolean get() = startedAt >= 0

    /**
     * Cut the current wait short, saying why ([reason], a fixed word).
     * Returns whether it did: false when nothing is waiting, or the wait
     * began less than [minWaitMs] ago.
     */
    fun wake(reason: String): Boolean {
        val began = startedAt
        if (began < 0 || clock() - began < minWaitMs) return false
        return nudges.trySend(reason).isSuccess
    }

    /** Wait up to [waitMs], or until [wake]. */
    suspend fun await(waitMs: Long): Outcome {
        // A wake left over from before this wait must not end it.
        while (nudges.tryReceive().isSuccess) { /* drain */ }
        val began = clock()
        startedAt = began
        val woke = try {
            withTimeoutOrNull(waitMs.coerceAtLeast(0L)) { nudges.receive() }
        } finally {
            startedAt = -1L
        }
        val late = if (woke == null) (clock() - (began + waitMs)).coerceAtLeast(0L) else 0L
        return Outcome(wokenBy = woke, lateMs = late)
    }

    /** How a wait ended: [wokenBy] the reason it was cut short, or null when
     *  it ran out; [lateMs] how far past its end it ran (sleep). */
    data class Outcome(val wokenBy: String?, val lateMs: Long) {
        /** Late enough that the phone, not the policy, chose the time. */
        val slept: Boolean get() = lateMs >= LATE_MS
    }

    companion object {
        const val MIN_WAIT_MS = 2_000L
        const val LATE_MS = 30_000L
    }
}
