// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomSummary

/**
 * The Rooms tab, sorted by the one difference that matters (owner,
 * 2026-10-17: "the room tab needs revamped to show these differences much
 * better"):
 *
 *  - ENCRYPTED GROUPS (MLS). Invite-only: a member adds you over OTRv4+.
 *    No room password -- it would admit to a room whose messages you still
 *    cannot read. Someone outside asks to join instead.
 *  - PLAIN ROOMS. Not end-to-end encrypted; the server reads them. The only
 *    place a room password is offered, and it is access control, not
 *    secrecy.
 *
 * Plain Kotlin, so `RoomSectionsTest` runs it.
 */
object RoomSections {

    data class Split(
        /** Encrypted groups on the server that this phone holds no keys for. */
        val encrypted: List<RoomSummary>,
        /** Everything else that is not one of ours: plain rooms. */
        val plain: List<RoomSummary>,
    )

    /**
     * [mine]: the encrypted groups this account holds keys for, listed in
     * their own section above, so not again here. A room that only CLAIMS to
     * be encrypted (its description says so) is listed as an encrypted group
     * to ask about: anybody can write the claim, but asking only posts our
     * address, and an invitation still has to come over OTRv4+.
     */
    fun split(rooms: List<RoomSummary>, mine: Collection<String>): Split {
        val ours = mine.map { it.lowercase() }.toSet()
        val listed = rooms.filter { it.jid.lowercase() !in ours }
        return Split(
            encrypted = listed.filter { it.secure || it.claimsSecure },
            plain = listed.filter { !it.secure && !it.claimsSecure },
        )
    }

    /** One request per group per [ASK_EVERY_MS] from this phone. */
    const val ASK_EVERY_MS = 10 * 60_000L

    fun mayAsk(lastAskedMs: Long?, nowMs: Long): Boolean =
        lastAskedMs == null || nowMs - lastAskedMs >= ASK_EVERY_MS || nowMs < lastAskedMs

    fun askAgainIn(lastAskedMs: Long, nowMs: Long): String {
        val minutes = ((ASK_EVERY_MS - (nowMs - lastAskedMs)) / 60_000L).coerceAtLeast(1)
        return "You asked recently. You can ask again in $minutes min."
    }

    const val ASKED =
        "Asked. The group's members see your request; if one of them invites " +
            "you, the invitation appears in your chats."

    const val MINE_TITLE = "Your encrypted groups"
    const val MINE_NOTE =
        "End-to-end encrypted (MLS). Only members can read them, and members " +
            "join by invitation over OTRv4+. No room password is needed."

    const val ON_SERVER_TITLE = "Encrypted groups on this server"
    const val ON_SERVER_NOTE =
        "These rooms say they are encrypted groups. You are not a member: " +
            "ask to join, and a member can invite you over OTRv4+."

    const val PLAIN_TITLE = "Plain rooms (not encrypted)"
    const val PLAIN_NOTE =
        "Messages in a plain room are NOT end-to-end encrypted: the server " +
            "hosting it can read them. A room password only controls who " +
            "gets in. Use an encrypted group for anything private."
}
