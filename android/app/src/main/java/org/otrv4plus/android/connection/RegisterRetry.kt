// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * When Create account tries again (owner, 2026-10-25: "it should be checking
 * for i2p running ... or launch bundle router to establish connection only
 * then should it attempt to create the new user ... and auto sign in").
 *
 * The service picks and waits for the router exactly as Log in does
 * (`chooseRouter`), then registers. A freshly started built-in router cannot
 * reach the server for its first minutes, so "not reached" and "no answer"
 * are tried again with a growing pause, within [BUDGET_MS]. Anything the
 * server actually SAID -- taken, refused, needs a CAPTCHA -- is final at once:
 * retrying would not change it, and a refused name must go back to the user.
 * Plain Kotlin; RegisterRetryTest drives it.
 */
object RegisterRetry {

    /** The longest Create account keeps trying while the server is not reached. */
    const val BUDGET_MS = 10 * 60_000L

    /** Through a router that was already up (the I2P app): a few tries only. */
    const val READY_ROUTER_TRIES = 3

    /** Not reached, or no answer: the route, not the server, said no. */
    private val TRANSIENT = setOf(
        "network", "timeout", "server_closed_connection", "tcp_failure",
        "i2p_destination_unreachable", "i2p_name_not_found", "i2p_session_failed",
        "transport_failed", "connect_failed",
    )

    fun transient(code: String): Boolean = code in TRANSIENT

    /**
     * Whether to try again after attempt number [attempt] (1 = the first)
     * failed with [code], [elapsedMs] after Create account was pressed.
     * [builtInRouter]: this attempt went through the router this app started.
     */
    fun again(code: String, attempt: Int, elapsedMs: Long, builtInRouter: Boolean): Boolean {
        if (!transient(code)) return false
        if (elapsedMs >= BUDGET_MS) return false
        return builtInRouter || attempt < READY_ROUTER_TRIES
    }

    /** The pause before attempt [attempt] + 1: 5 s, 10 s, 20 s, then 30 s. */
    fun delayMs(attempt: Int): Long = when {
        attempt <= 1 -> 5_000L
        attempt == 2 -> 10_000L
        attempt == 3 -> 20_000L
        else -> 30_000L
    }

    /** Shown while it works: what it is waiting for, in words. */
    fun progress(attempt: Int, routerLabel: String?): String = buildString {
        append("Creating the account")
        if (attempt > 1) append(" (try $attempt)")
        append("…")
        if (!routerLabel.isNullOrBlank()) append(" $routerLabel")
    }
}
