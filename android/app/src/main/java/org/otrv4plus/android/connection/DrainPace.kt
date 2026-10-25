// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * How often the connection service reads the engine (owner report,
 * 2026-10-25: "uses a lot of battery compared to CLI"; the phone spent its
 * screen-off time awake, never in deep sleep).
 *
 * The drain loop ran every 500 ms whatever the screen, and each pass crossed
 * into Python four times -- link status, the whole roster, the dropped-event
 * count and the events. On screen that is what keeps the app live. With the
 * app in the background nobody sees the roster or the status line, so:
 * events every [BACKGROUND_MS] (a notification is at most that late), and
 * status and roster only every [BACKGROUND_STATE_EVERY] passes. A call in
 * progress keeps the fast pace: a ring or a hang-up must not wait.
 * Plain Kotlin; DrainPaceTest drives it.
 */
object DrainPace {
    const val VISIBLE_MS = 500L
    const val BACKGROUND_MS = 2_000L

    /** In the background, status and roster every this many passes (30 s). */
    const val BACKGROUND_STATE_EVERY = 15

    fun intervalMs(uiVisible: Boolean, inCall: Boolean): Long =
        if (uiVisible || inCall) VISIBLE_MS else BACKGROUND_MS

    /** Whether pass [tick] reads the link status and the roster. */
    fun readsState(tick: Long, uiVisible: Boolean, inCall: Boolean): Boolean =
        uiVisible || inCall || tick % BACKGROUND_STATE_EVERY == 0L
}
