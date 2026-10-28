// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

/**
 * The words of the Rooms tab's server listing (owner, 2026-10-28: "Server
 * Admin should be able to scan for groups and join if they wish and delete
 * groups etc. Desktop app should allow for this feature").
 *
 * What an admin can and cannot do is said as it is. An admin sees every
 * room and may delete any of them; an admin may NOT read an encrypted
 * group: its keys come only with an invitation over OTRv4+, so for an
 * admin as for anyone "join" is Ask to join, and a member decides.
 *
 * Plain Kotlin, so `ServerRoomsTest` runs it.
 */
object ServerRooms {

    fun title(admin: Boolean): String =
        if (admin) "Every room on this server (you are its admin)" else "Rooms on this server"

    fun note(admin: Boolean): String =
        if (admin) "Hidden rooms are listed too. You can delete any room or group. " +
            "You cannot read an encrypted group: ask to join, and a member can invite you."
        else "Only rooms the server advertises. Rooms can be hidden: join one by name if you know it."

    const val EMPTY = "The server lists no rooms besides yours."

    const val ASK_TEXT =
        "Your address is posted in the group's room. Its members decide: one of them can " +
            "invite you over OTRv4+. Until then you hold no keys and cannot read it, even " +
            "as the server's admin."

    fun deleteText(room: String, held: Boolean): String =
        if (held) "$room is one of your encrypted groups. Every member is removed and the room " +
            "is deleted from the server. This cannot be undone."
        else "$room is deleted from the server for everyone in it. Members of an encrypted " +
            "group are told when they next sign in, and their app ends its copy. This cannot " +
            "be undone."
}
