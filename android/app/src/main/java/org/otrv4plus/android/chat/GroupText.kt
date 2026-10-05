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
        "End-to-end encrypted group (MLS, hybrid X448 + ML-KEM-1024 and " +
            "Ed448 + ML-DSA-87). The room and its server carry only " +
            "ciphertext; they still see who is in the room and when."

    const val PLAIN_HEADER =
        "Room — not end-to-end encrypted. Everyone in the room and the " +
            "server can read every message."

    fun header(secure: Boolean): String = if (secure) SECURE_HEADER else PLAIN_HEADER

    /** While a secure group catches up after a sign-in or reconnect. */
    const val SYNCING_HEADER = "Secure group (MLS), syncing: messages you type wait " +
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

    /** A notice for a change worth telling the user about, or null. */
    fun describe(event: OtrEvent.GroupChanged): String? = when (event.change) {
        "removed_us" -> "You were removed from ${event.room}. You can no longer read it."
        "commit_lost" -> "A group change in ${event.room} crossed with another " +
            "member's and was dropped. Try it again."
        "invite_declined" -> "${event.detail} declined the invitation to ${event.room}."
        "idle_removed" -> "Removed from ${event.room} after 72 hours without a key " +
            "update (their device was away): ${event.detail}. Invite them again " +
            "over OTRv4+ to bring them back."
        "refused" -> refusal(event.detail, event.room)
        // Back in the room after a reconnect or sign-in: what is typed waits
        // until the group is in sync, or it would be sent on an old key and lost.
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
        "otrv4plus_unavailable" -> "This contact's app does not support OTRv4+, " +
            "so they cannot be invited to a secure group."
        "legacy_group" -> "This group was made before the hybrid (X448 + ML-KEM-1024) " +
            "suite and cannot take new members. Create a new group to add people."
        "commit_pending" -> "Waiting for the room to confirm a group change. Try again shortly."
        else -> "The group operation did not complete ($code)."
    }
}
