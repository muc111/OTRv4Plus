// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent

/**
 * What to say about a secure group. Plain Kotlin, so the words are tested.
 *
 * An OTRv4Plus secure group is MLS over a room: the room and its server carry
 * ciphertext only. Membership is not identity: a member is "verified" only
 * when their MLS key arrived over an SMP-verified OTRv4+ session with them.
 */
object GroupText {

    const val SECURE_HEADER =
        "End-to-end encrypted group (MLS+, hybrid X448 + ML-KEM-1024 and " +
            "Ed448 + ML-DSA-87). The room and its server carry only " +
            "ciphertext; they still see who is in the room and when."

    const val PLAIN_HEADER =
        "Room — not end-to-end encrypted. Everyone in the room and the " +
            "server can read every message."

    fun header(secure: Boolean): String = if (secure) SECURE_HEADER else PLAIN_HEADER

    /**
     * The most members a group may have and still call. The same number as
     * `android_bridge/group_call.MAX_PARTICIPANTS`, which refuses too: each
     * phone sends its audio to every other one over I2P. Owner (2026-10-16):
     * "a hard limit ... large groups will have to stay text only".
     */
    const val MAX_CALL_MEMBERS = 5

    /** Whether a group of [members] (us included) may call at all. Unknown
     *  (0: the member list has not arrived) is not a reason to hide it. */
    fun callAllowed(members: Int): Boolean = members <= MAX_CALL_MEMBERS

    const val TEXT_ONLY = "Text only: group calls take at most " +
        "$MAX_CALL_MEMBERS members."

    /**
     * The group's security line. Owner (2026-10-16): "Encrypted Chat | 5/6
     * users verified". [total] is everyone in the group.
     */
    fun securityLine(verified: Int, total: Int): String =
        if (total <= 0) "Encrypted Chat"
        else "Encrypted Chat | $verified/$total users verified"

    /**
     * [verified]/[total] from the member list: each member whose key we
     * verified (SMP or the group passphrase), and us once a verification we
     * took part in has succeeded. Owner (2026-10-16): a new group read
     * "1/1 verified" before anyone was added or verified -- it is 0/1 until
     * a verification completes, and then counts up as each member does.
     */
    fun verifiedCount(members: List<org.otrv4plus.android.bridge.GroupMember>): Pair<Int, Int> {
        val others = members.count { !it.me && it.verified }
        val us = if (others > 0) members.count { it.me } else 0
        return (others + us) to members.size
    }

    /** Between accepting an invitation and the group's keys arriving.
     *  Device report (2026-10-16): the room was shown as unencrypted then. */
    const val JOINING_HEADER = "Secure group (MLS+): setting up end-to-end encryption… " +
        "This can take a minute over I2P. Nothing can be sent until it is ready."

    /** While a secure group catches up after a sign-in or reconnect. */
    const val SYNCING_HEADER = "Secure group (MLS+), syncing: messages you type wait " +
        "until it is back in sync, then go encrypted."

    fun memberLine(jid: String, me: Boolean, verified: Boolean, bound: Boolean): String = when {
        me -> "$jid (you)"
        verified -> "$jid — verified (key received over a verified OTRv4+ session)"
        bound -> "$jid — key received over OTRv4+, not verified with SMP"
        else -> "$jid — not verified by you"
    }

    fun invite(event: OtrEvent.GroupInvited): String =
        "${event.peer} invited you to the secure group ${event.room}" +
            if (event.verified) "." else " (this contact is not SMP-verified)."

    /** "bob@x asks to join the encrypted group team@rooms.x." */
    fun entryRequest(requester: String, room: String): String =
        "$requester asks to join the encrypted group $room."

    /** Under every request: what Invite does, and why a false claim is harmless. */
    const val ENTRY_REQUEST_NOTE =
        "Invite sends the usual invitation over OTRv4+ to that address, so " +
            "only its real owner can accept it. Do you know them?"

    /** "2 of 4 verified · about 1 min 30 s left · excluded: c@x (wrong passphrase)" */
    fun verifyProgress(done: Int, total: Int, etaSeconds: Int,
                       members: Map<String, String>, excluded: List<String>): String {
        if (total <= 0) return "Starting the group verification… (a minute or two over I2P)"
        val verified = members.count { it.value == "verified" }
        val running = members.count { it.value == "running" }
        val waiting = members.count { it.value == "waiting" || it.value == "not_verified" }
        val parts = mutableListOf("$verified of $total verified")
        if (running + waiting > 0) {
            parts += if (etaSeconds >= 60) "about ${etaSeconds / 60} min ${etaSeconds % 60} s left"
                     else "about $etaSeconds s left"
        }
        if (running > 0) parts += "$running checking"
        if (waiting > 0) parts += "$waiting not joined yet"
        if (excluded.isNotEmpty()) {
            parts += "excluded (wrong passphrase, not in calls): ${excluded.joinToString()}"
        }
        return parts.joinToString(" · ")
    }

    /** What leaving or deleting a group does, asked before doing it. */
    fun endConfirm(delete: Boolean, room: String): String = if (delete)
        "The room $room is deleted on the server and every member's copy of the " +
            "group ends. Only the group's creator can do this. It cannot be undone."
    else
        "This phone forgets the group's keys and leaves $room. The others keep " +
            "the group; to come back, a member has to invite you again."

    /** A notice for a change worth telling the user about, or null. */
    fun describe(event: OtrEvent.GroupChanged): String? = when (event.change) {
        "removed_us" -> "You were removed from ${event.room}. You can no longer read it."
        "joining" -> "Joining ${event.room}: setting up end-to-end encryption…"
        "join_expired" -> "The invitation to ${event.room} expired before its keys " +
            "arrived. Ask to be invited again."
        // Accepting an invitation back replaces this device's old copy of
        // the group; the old copy sees that as its removal. Nobody removed us.
        "replaced" -> "Your old copy of ${event.room} was replaced because you " +
            "accepted the new invitation. The new copy arrives in a moment."
        "commit_lost" -> "A group change in ${event.room} crossed with another " +
            "member's and was dropped. Try it again."
        "invite_declined" -> "${event.detail} declined the invitation to ${event.room}."
        "idle_removed" -> "Removed from ${event.room} after 72 hours without a key " +
            "update (their device was away): ${event.detail}. Invite them again " +
            "over OTRv4+ to bring them back."
        "refused" -> refusal(event.detail, event.room)
        // Back in the room after a reconnect or sign-in: what is typed waits
        // until the group is in sync, or it would be sent on an old key and lost.
        "deleted" -> "${event.room} was deleted (its room is gone). Its keys are gone " +
            "from this phone; the messages already here stay."
        "reinvited" -> "${event.detail} invited you again to ${event.room}, which this " +
            "phone is already in. Accept only if the group stopped working here: " +
            "this phone's copy is replaced with the current one."
        "member_verified" -> "${event.detail} is verified in ${event.room}: group calls " +
            "with them are possible."
        "held_change" -> "A change to ${event.room} is landing: your message waits and " +
            "goes, encrypted, right after."
        "verify_started" -> "${event.detail} started verifying ${event.room} with the " +
            "group passphrase. Open the group and type it to join."
        "member_verify_failed" -> "${event.detail}: the group passphrases did not " +
            "match. Not verified, and not in group calls."
        "group_verified" -> "Every member of ${event.room} is verified. You can call the group."
        "verify_finished" -> "Verification of ${event.room} finished: " +
            event.detail.replace("verified=", "verified ").replace(";excluded=", "; excluded ") + "."
        "call_ringing" -> "${event.detail} is calling the group ${event.room}."
        "held" -> "${event.room} is still syncing: your messages wait until the " +
            "group is back in sync (a few seconds), then go encrypted."
        "synced" -> if (event.detail.isNotEmpty()) {
            "${event.room} is back in sync: ${event.detail} waiting message(s) sent, encrypted."
        } else null
        else -> null
    }

    fun refusal(code: String, room: String): String = when (code) {
        "inviter_fingerprint_mismatch" ->
            "Did not join $room: the group did not hold the key the inviter " +
                "sent over OTRv4+. Somebody else's group may have been presented."
        "unsolicited_welcome" -> "Ignored a group join for $room that you did not accept."
        "uninvited_key_package" -> "Ignored a request to join $room that you did not invite."
        "welcome_refused", "welcome_for_another_room" ->
            "Could not join $room: the group data was invalid."
        "too_many_invites" -> "Too many pending group invitations; one was ignored."
        else -> "A secure-group operation for $room was refused."
    }

    /** A group failure reported by the bridge, worth telling the user, or null. */
    fun failure(code: String, room: String?): String? = when (code) {
        "group_joining" ->
            "${room ?: "This group"} is still setting up end-to-end encryption. " +
                "Nothing was sent; send it once the group is ready."
        "group_keys_missing" ->
            "${room ?: "This room"} is an encrypted group, but this device has no " +
                "keys for it, so its messages cannot be shown and nothing can be " +
                "sent there. Ask a member to invite you again."
        "groups_state_unreadable" ->
            "Your saved secure groups could not be opened on this device. The " +
                "file was kept. Groups you were in need a new invitation."
        "state_in_use" ->
            "Another copy of the app for this account is holding its secure " +
                "groups. Close it and sign in again."
        "room_not_persistent" ->
            "The server would not keep ${room ?: "this group"}'s room while " +
                "everyone is offline: when the last member leaves, the server " +
                "deletes it and the group has to be made again. The server's " +
                "admin can allow it (Prosody: muc_room_default_persistent = true)."
        else -> null
    }

    /** For an operation the user started. */
    fun outcome(code: String): String? = when (code) {
        "ok" -> null
        "otr_required" -> "Start an encrypted OTRv4+ conversation with this contact first."
        "groups_unavailable" -> "This build does not include group encryption."
        "no_invite" -> "That invitation has expired."
        "group_exists" -> "That room is already a secure group."
        "waiting_for_otr" -> "No encrypted OTRv4+ session with them yet, so one is " +
            "being started; the invitation goes as soon as it is ready " +
            "(usually one to two minutes over I2P)."
        "waiting_for_contact" -> "They are not a contact yet, so a contact request " +
            "was sent; the invitation goes over OTRv4+ once they accept."
        "otrv4plus_unavailable" -> "This contact's app does not support OTRv4+, " +
            "so they cannot be invited to a secure group."
        "legacy_group" -> "This group was made before the hybrid (X448 + ML-KEM-1024) " +
            "suite and cannot take new members. Create a new group to add people."
        "commit_pending" -> "Waiting for the room to confirm a group change. Try again shortly."
        "passphrase_needed" -> "Type the group passphrase to verify the group."
        "passphrase_too_short" -> "The group passphrase must be 8 characters or more."
        "no_verified_member" -> "Nobody in this group is verified yet: verify the group first."
        "call_in_progress" -> "You are already in a group call."
        "group_too_large" -> TEXT_ONLY
        "group_password_needed" -> "This group's room has a password. Enter it to join " +
            "(ask whoever invited you)."
        "no_call" -> "Nobody is calling in this group."
        "call_audio_unavailable" -> "The call could not use the microphone or speaker."
        "forbidden", "not_allowed" -> "Only the group's creator (the room's owner) can " +
            "delete it for everyone. Leave it instead to remove it from this phone."
        else -> "The group operation did not complete ($code)."
    }
}
