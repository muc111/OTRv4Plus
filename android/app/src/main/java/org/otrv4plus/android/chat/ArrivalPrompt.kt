// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Who sent the messages a notification was posted for, so that tapping it
 * asks inside the app before any conversation is shown.
 *
 * The notification itself names nobody ([InboundAlerts]). Tapping it used to
 * bring back whatever screen was last open, often a conversation, so the
 * user saw messages they had not chosen to read. Now the tap lands on the
 * chat list and the app asks, for one sender at a time: "New message from
 * Alice. View it?". "Not now" leaves the conversation closed, which is the
 * point when the sender is somebody the user means to ignore.
 *
 * Memory only. Nothing here reaches the disk, a notification or an intent:
 * the names are shown behind the app, which is behind the lock screen and
 * FLAG_SECURE.
 *
 * Plain Kotlin and synchronized: [arrived] runs on the service's drain loop,
 * the rest on the main thread.
 */
class ArrivalPrompt {

    // Insertion order is arrival order; a repeat sender moves to the end.
    private val waiting = LinkedHashSet<String>()

    /** A notification was posted for a message from (or in) [from]. */
    @Synchronized
    fun arrived(from: String) {
        if (from.isBlank()) return
        waiting.remove(from)
        waiting.add(from)
    }

    /** The sender to ask about now: the most recent, or null for none. */
    @Synchronized
    fun next(): String? = waiting.lastOrNull()

    /**
     * The user answered for [from], or opened that conversation some other
     * way. Either way, nothing about it is left to ask.
     */
    @Synchronized
    fun answered(from: String) {
        waiting.remove(from)
    }

    /** Signed out, or wiped: nobody's name outlives the session. */
    @Synchronized
    fun clear() {
        waiting.clear()
    }

    /** Everyone still waiting, oldest first. */
    @Synchronized
    fun pending(): List<String> = waiting.toList()
}
