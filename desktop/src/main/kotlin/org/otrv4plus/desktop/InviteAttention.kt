// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

/**
 * Whether the Rooms tab should flash, and for how many invitations.
 *
 * Owner (2026-10-26): an invitation to a group came through and was missed.
 * It sat on the Rooms tab while Chats was open, marked only by a small dot.
 * The tab now flashes, with a count, until the invitations have been on
 * screen. Opening Rooms counts as seeing every invitation waiting there; one
 * that arrives afterwards flashes again. An invitation accepted or declined
 * is gone from [unseen]'s input and is forgotten here too.
 */
class InviteAttention {

    private val seen = HashSet<String>()

    /**
     * How many of [pending] (the rooms invited to) have not been on screen
     * yet. [onRooms]: the Rooms tab is open now, so they all are.
     */
    fun unseen(pending: List<String>, onRooms: Boolean): Int {
        val waiting = pending.toSet()
        seen.retainAll(waiting)
        if (onRooms) seen.addAll(waiting)
        return waiting.count { it !in seen }
    }
}
