// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import com.chaquo.python.PyObject

/** [AccountAdminApi] over the connection controller. */
internal class ChaquopyAccountAdmin(private val handles: BridgeHandles) : AccountAdminApi {

    private fun requireApp(): PyObject = handles.requireApp()

    private fun call(name: String, vararg args: Any): PyObject? =
        handles.call(name, *args)

    /** Rooms we are in as owner (creator, or a server admin): the only
     *  ones a delete button is shown for. */
    override fun ownedRooms(): List<String>? {
        val result = call("owned_rooms") ?: return null
        if (!outcomeOf(result).ok) return null
        return listValue(result)?.asList()?.map { it.toString() } ?: emptyList()
    }

    /** Whether this account administers its server (XEP-0133 commands
     *  listed to it); null when the server did not say. */
    /**
     * A server admin's moderation of [account]: "status", "ban" ([days] 0 =
     * permanent) or "unban". The server runs it for its admins only
     * (prosody/mod_otrv4plus_moderation.lua).
     */
    override fun moderate(op: String, account: String, days: Int, reason: String): Moderation {
        val result = call("moderate", op, account, days, reason)
            ?: return Moderation(notPrepared())
        val value = listValue(result)
        return Moderation(
            outcome = outcomeOf(result),
            banned = value?.let { flag(it, "banned") } ?: false,
            until = value?.let { entry(it, "until").toLongOrNull() } ?: -1,
            said = value?.let { entry(it, "message") }.orEmpty(),
        )
    }

    override fun serverAdmin(): Boolean? {
        val result = call("server_admin") ?: return null
        if (!outcomeOf(result).ok) return null
        return result.callAttr("get", "value")?.toBoolean()
    }

    /** How many other sessions of our own account the server told us
     *  about; null when unknown (not connected). */
    override fun otherSessions(): Int? {
        val result = call("other_sessions") ?: return null
        if (!outcomeOf(result).ok) return null
        return listValue(result)?.asList()?.size ?: 0
    }

    /** Sign out our account's other sessions (server admins only): the
     *  outcome and how many were ended. */
    override fun endOtherSessions(): Pair<RoomOutcome, Int> {
        val result = call("end_other_sessions") ?: return notPrepared() to 0
        val ended = runCatching { result.callAttr("get", "value")?.toInt() }.getOrNull() ?: 0
        return outcomeOf(result) to ended
    }

    /**
     * Change the account's password on the server (XEP-0077). The engine
     * checks [currentPassword] against the one it signed in with; neither is
     * kept, logged or put in any status here.
     */
    override fun changePassword(currentPassword: String, newPassword: String): RoomOutcome {
        val result = call("change_password", currentPassword, newPassword)
            ?: return notPrepared()
        return outcomeOf(result)
    }

    override fun destroyRoom(room: String, reason: String): RoomOutcome {
        val result = call("destroy_room", room, reason) ?: return notPrepared()
        return outcomeOf(result)
    }

    /**
     * What the server advertises about keeping [jid]'s history (our own
     * account when blank). `null` mam when it did not answer: unknown is not
     * "no archive". Asked, never acted on -- see `ChatDeletion`.
     */
    override fun archiveSupport(jid: String): Pair<RoomOutcome, Boolean?> {
        val result = call("archive_support", jid) ?: return notPrepared() to null
        val outcome = outcomeOf(result)
        if (!outcome.ok) return outcome to null
        val mam = runCatching {
            listValue(result)?.callAttr("get", "mam")?.toBoolean()
        }.getOrNull()
        return outcome to mam
    }

    /**
     * Create the OTRv4Plus Welcome room (explicit user action only).
     * Returns the outcome and the settings the server did NOT apply.
     */
    override fun createWelcomeRoom(): Pair<RoomOutcome, List<String>> {
        val result = call("create_welcome_room") ?: return notPrepared() to emptyList()
        val outcome = outcomeOf(result)
        val missing = runCatching {
            listValue(result)?.callAttr("get", "missing")?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        return outcome to missing
    }
}

/**
 * The account and server side: rooms we own, moderation, server-admin
 * standing, our other sessions, the password, room destruction, archive
 * support and the Welcome room. Through the connection controller. Split
 * out of [ChaquopyOtrCore], which implements it by delegation.
 */
interface AccountAdminApi {
    fun ownedRooms(): List<String>?
    fun moderate(op: String, account: String, days: Int = 0, reason: String = ""): Moderation
    fun serverAdmin(): Boolean?
    fun otherSessions(): Int?
    fun endOtherSessions(): Pair<RoomOutcome, Int>
    fun changePassword(currentPassword: String, newPassword: String): RoomOutcome
    fun destroyRoom(room: String, reason: String = ""): RoomOutcome
    fun archiveSupport(jid: String = ""): Pair<RoomOutcome, Boolean?>
    fun createWelcomeRoom(): Pair<RoomOutcome, List<String>>
}
