// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * How long the last connection took, for the Connect screen. Owner
 * (2026-10-17): "each time I log in I know exactly how many mins and secs it
 * took".
 *
 * Measured from the start of the run -- Connect pressed, the app resuming,
 * or the stream dropping -- to signed in: the router, retries and backoff
 * included, because that is the wait the person had. The part spent waiting
 * for the built-in router to open its SAM bridge is shown on its own.
 *
 * Plain Kotlin, so `ConnectTimingTest` runs it.
 */
object ConnectTiming {

    data class Result(
        val totalMs: Long,
        /** Waiting for the built-in router; null when it was ready or not used. */
        val routerMs: Long?,
        /** Attempts in this run, the successful one included. */
        val attempts: Int,
    )

    /** "0:07", "3:42", "1:02:05". */
    fun clock(ms: Long): String {
        val s = ms.coerceAtLeast(0) / 1000
        return if (s >= 3600) "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60)
               else "%d:%02d".format(s / 60, s % 60)
    }

    fun line(r: Result): String = buildString {
        append(clock(r.totalMs))
        val router = r.routerMs?.takeIf { it >= 1_000 }
        if (router != null) {
            append(" (I2P router ").append(clock(router))
            append(", sign-in ").append(clock(r.totalMs - router)).append(")")
        }
        if (r.attempts > 1) append(", ").append(r.attempts).append(" attempts")
    }

    /**
     * The same result for the diagnostic report, as `key=value` pairs that
     * `android_bridge/report.py` reads back (`connect_timing`). Owner,
     * 2026-10-28: the report showed only the clock time of CONNECTED, not
     * the 2:25 the sign-in took.
     */
    fun note(r: Result): String =
        "total_ms=${r.totalMs} router_ms=${r.routerMs ?: 0} attempts=${r.attempts}"
}
