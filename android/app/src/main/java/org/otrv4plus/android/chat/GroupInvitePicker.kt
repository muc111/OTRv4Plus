// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Who can be ticked in "Invite people" for a secure group.
 *
 * Owner (2026-10-16): "the app would be better viewing all users available
 * online and tick box for invite then send all at once" -- one name typed
 * at a time was the only way. The list is everyone the server says is
 * online (contacts first), minus ourselves and the group's members. Each
 * ticked person still gets their own invitation over OTRv4+; the bridge adds
 * those who accept, several in one change when they accept close together.
 *
 * Plain Kotlin, shared with the desktop app; GroupInvitePickerTest drives it.
 */
object GroupInvitePicker {

    data class Candidate(val jid: String, val name: String, val contact: Boolean)

    /** Online people who are not already in the group, contacts first. */
    fun candidates(directory: List<OnlineUsers.Entry>, members: Collection<String>,
                   me: String): List<Candidate> {
        val skip = members.map { ChatState.bare(it).lowercase() }.toSet() +
            ChatState.bare(me).lowercase()
        return directory
            .filter { it.relation == OnlineUsers.Relation.ADDED_ONLINE ||
                      it.relation == OnlineUsers.Relation.ONLINE_ADD }
            .filter { ChatState.bare(it.jid).lowercase() !in skip }
            .distinctBy { ChatState.bare(it.jid).lowercase() }
            .map { Candidate(ChatState.bare(it.jid), it.displayName,
                             it.relation == OnlineUsers.Relation.ADDED_ONLINE) }
            .sortedWith(compareBy({ !it.contact }, { it.name.lowercase() }))
    }

    fun button(count: Int): String = when (count) {
        0 -> "Invite"
        1 -> "Invite 1 person"
        else -> "Invite $count people"
    }

    const val TITLE = "Invite people online"
    const val EMPTY = "Nobody else is online right now. You can still type an address below."

    fun sent(count: Int): String =
        if (count == 1) "Invitation sent over OTRv4+." else "$count invitations sent over OTRv4+."
}
