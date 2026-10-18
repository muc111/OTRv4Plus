// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Who is offered "Delete for everyone" on a room or a secure group (MLS+
 * groups are MUC rooms carrying ciphertext: the same rule, no special case).
 *
 *  - the room's OWNER (its creator), as the room's own roster reports us;
 *  - a SERVER ADMIN (rc.88): the server lists its XEP-0133 commands to this
 *    account, and Prosody counts its admins as owners of every room;
 *  - nobody else: they get Leave only (rc.83, a security boundary).
 *
 * A room ADMIN affiliation is not enough: XEP-0045 10.9 lets only an owner
 * destroy a room, so the server refuses an admin's destroy, and a button
 * that always fails is the thing rc.83 removed.
 *
 * The SERVER decides every destroy; this only avoids offering a refusal.
 * Plain Kotlin, shared with the desktop app; RoomDeletionTest drives it.
 */
object RoomDeletion {

    enum class Action { LEAVE, DELETE }

    /** What to offer, from the room's [affiliation] for us and [serverAdmin]. */
    fun actions(affiliation: String, serverAdmin: Boolean): Set<Action> =
        if (mayDelete(affiliation.trim().lowercase() == "owner", serverAdmin))
            setOf(Action.LEAVE, Action.DELETE)
        else setOf(Action.LEAVE)

    /** [owner]: the server reports us as the room's owner. */
    fun mayDelete(owner: Boolean, serverAdmin: Boolean): Boolean = owner || serverAdmin

    /** Said when Delete is pressed while another operation is running. */
    fun waitFor(running: String): String =
        "Wait for \"${running.trim().trimEnd('.')}\" to finish, then try again."
}
