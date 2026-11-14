// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import com.chaquo.python.PyObject

/** [SecureGroupsApi] over the connection controller. Every call answers;
 *  none throws (see [BridgeHandles.call]). */
internal class ChaquopyGroups(private val handles: BridgeHandles) : SecureGroupsApi {

    private fun requireApp(): PyObject = handles.requireApp()

    private fun call(name: String, vararg args: Any): PyObject? =
        handles.call(name, *args)

    // -- secure groups (MLS; android_bridge.groups) ---------------------------

    /** A new room that is an OTRv4Plus secure group from its first message. */
    override fun createSecureGroup(room: String, password: String,
                          passphrase: String): RoomOutcome {
        val result = call("create_secure_group", room, password, passphrase)
            ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Verify every member with the group passphrase ("" = the one set at creation). */
    override fun startGroupVerify(room: String, passphrase: String): RoomOutcome {
        val result = call("start_group_verify", room, passphrase) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Who is verified in [room], and a verification someone started. */
    override fun groupVerifyState(room: String): GroupVerifyState {
        val result = call("group_verify_state", room) ?: return GroupVerifyState()
        val value = listValue(result) ?: return GroupVerifyState()
        val members = mutableMapOf<String, String>()
        runCatching {
            value.callAttr("get", "members")?.asMap()?.forEach { (k, v) ->
                members[k.toString()] = v.toString()
            }
        }
        fun int(key: String): Int =
            runCatching { value.callAttr("get", key)?.toInt() }.getOrNull() ?: 0
        val excluded = runCatching {
            value.callAttr("get", "excluded")?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        return GroupVerifyState(
            members = members,
            allVerified = flag(value, "all_verified"),
            startedBy = entry(value, "started_by"),
            active = flag(value, "active"),
            done = int("done"),
            total = int("total"),
            etaSeconds = int("eta"),
            excluded = excluded,
            coordinator = entry(value, "coordinator"),
            canStart = flag(value, "can_start"),
        )
    }

    /** Verified members' calls are joined by themselves only with the microphone allowed. */
    override fun setGroupCallAutoJoin(allowed: Boolean) {
        call("set_group_call_auto_join", allowed)
    }

    override fun startGroupCall(room: String): RoomOutcome =
        call("start_group_call", room)?.let { outcomeOf(it) } ?: notPrepared()

    override fun joinGroupCall(room: String): RoomOutcome =
        call("join_group_call", room)?.let { outcomeOf(it) } ?: notPrepared()

    override fun pauseGroupCall(): RoomOutcome =
        call("pause_group_call")?.let { outcomeOf(it) } ?: notPrepared()

    override fun hangupGroupCall(): RoomOutcome =
        call("hangup_group_call")?.let { outcomeOf(it) } ?: notPrepared()

    override fun groupCallState(room: String): GroupCallState {
        val result = call("group_call_state", room) ?: return GroupCallState()
        val value = listValue(result) ?: return GroupCallState()
        val people = runCatching {
            value.callAttr("get", "participants")?.asList()?.map { it.toString() }
        }.getOrNull() ?: emptyList()
        return GroupCallState(
            inCall = flag(value, "in_call"),
            paused = flag(value, "paused"),
            participants = people,
            ringingFrom = entry(value, "ringing_from"),
            micSilent = flag(value, "mic_silent"),
        )
    }

    /** Invite [peer] over our encrypted OTRv4+ session with them. */
    override fun inviteToGroup(room: String, peer: String): RoomOutcome {
        val result = call("invite_to_group", room, peer) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Ask the members of the encrypted group [room] to invite us
     *  (`ConnectionController.request_group_entry`). */
    /** The creator's Accept or Deny to "X asks to join". On a denial the
     *  second value is the seconds before they can be shown asking again. */
    override fun answerEntryRequest(room: String, requester: String, accept: Boolean): Pair<RoomOutcome, Int> {
        val result = call("answer_entry_request", room, requester, accept) ?: return notPrepared() to 0
        val wait = if (accept) 0 else runCatching { listValue(result)?.toInt() }.getOrNull() ?: 0
        return outcomeOf(result) to wait
    }

    override fun requestGroupEntry(room: String): RoomOutcome {
        val result = call("request_group_entry", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** [password]: the room's, when the user typed it (the inviter's, sent
     *  with the invitation, is used otherwise). */
    override fun acceptGroupInvite(room: String, password: String): RoomOutcome {
        val result = call("accept_group_invite", room, password) ?: return notPrepared()
        return outcomeOf(result)
    }

    override fun declineGroupInvite(room: String): RoomOutcome {
        val result = call("decline_group_invite", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    override fun removeGroupMember(room: String, member: String): RoomOutcome {
        val result = call("remove_group_member", room, member) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** The creator removes everyone whose verification failed, in one commit. */
    override fun removeFailedGroupMembers(room: String): RoomOutcome {
        val result = call("remove_failed_group_members", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Send this phone's group key to each member; the detail says who needs SMP. */
    override fun verifyGroupMembers(room: String): RoomOutcome {
        val result = call("verify_group_members", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Delete a secure group for everyone (its creator only; the server checks). */
    override fun deleteSecureGroup(room: String): RoomOutcome {
        val result = call("delete_secure_group", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** "Make Group Deniable" (F4): see SecureGroups.make_deniable. */
    override fun makeGroupDeniable(room: String): RoomOutcome {
        val result = call("make_group_deniable", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    /** Who our earlier group keys wait for (F4): see SecureGroups.keys_waiting. */
    override fun groupKeysWaiting(room: String): List<String> {
        val result = call("group_publication_waiting", room) ?: return emptyList()
        if (!outcomeOf(result).ok) return emptyList()
        return listValue(result)?.asList()?.map { it.toString() } ?: emptyList()
    }

    override fun leaveSecureGroup(room: String): RoomOutcome {
        val result = call("leave_secure_group", room) ?: return notPrepared()
        return outcomeOf(result)
    }

    override fun groupMembers(room: String): Pair<RoomOutcome, List<GroupMember>> {
        val result = call("group_members", room) ?: return notPrepared() to emptyList()
        val members = mutableListOf<GroupMember>()
        listValue(result)?.let { items ->
            for (item in items.asList()) {
                members += GroupMember(
                    jid = entry(item, "jid"),
                    fingerprint = entry(item, "fingerprint"),
                    me = entry(item, "me") == "True",
                    verified = entry(item, "verified") == "True",
                    bound = entry(item, "bound") == "True",
                    failed = entry(item, "failed") == "True",
                )
            }
        }
        return outcomeOf(result) to members
    }

    override fun secureGroups(): List<String> {
        val result = call("secure_groups") ?: return emptyList()
        return listValue(result)?.asList()?.map { it.toString() } ?: emptyList()
    }
}

/**
 * Secure groups (MLS) and group calls, as the Android bridge offers them:
 * `android_bridge.groups` through the connection controller. Split out of
 * [ChaquopyOtrCore], which implements it by delegation; callers are unchanged.
 */
interface SecureGroupsApi {
    fun createSecureGroup(room: String, password: String = "",
                          passphrase: String = ""): RoomOutcome
    fun startGroupVerify(room: String, passphrase: String): RoomOutcome
    fun groupVerifyState(room: String): GroupVerifyState
    fun setGroupCallAutoJoin(allowed: Boolean)
    fun startGroupCall(room: String): RoomOutcome
    fun joinGroupCall(room: String): RoomOutcome
    fun pauseGroupCall(): RoomOutcome
    fun hangupGroupCall(): RoomOutcome
    fun groupCallState(room: String): GroupCallState
    fun inviteToGroup(room: String, peer: String): RoomOutcome
    fun answerEntryRequest(room: String, requester: String, accept: Boolean): Pair<RoomOutcome, Int>
    fun requestGroupEntry(room: String): RoomOutcome
    fun acceptGroupInvite(room: String, password: String = ""): RoomOutcome
    fun declineGroupInvite(room: String): RoomOutcome
    fun removeGroupMember(room: String, member: String): RoomOutcome
    fun removeFailedGroupMembers(room: String): RoomOutcome
    fun verifyGroupMembers(room: String): RoomOutcome
    fun deleteSecureGroup(room: String): RoomOutcome
    fun makeGroupDeniable(room: String): RoomOutcome
    fun groupKeysWaiting(room: String): List<String>
    fun leaveSecureGroup(room: String): RoomOutcome
    fun groupMembers(room: String): Pair<RoomOutcome, List<GroupMember>>
    fun secureGroups(): List<String>
}
