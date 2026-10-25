// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.Verification

/**
 * What the conversation shows for a failure the bridge reports
 * (`ErrorOccurred`, which arrives here as OtrEvent.Failed).
 *
 * NOTHING IS SILENT BY DEFAULT. Codes used to reach the screen only when one
 * of three maps knew them, and every other code was dropped: pressing Call
 * did nothing visible when the call could not go out (owner, 2026-10-24),
 * and a failed group send, invitation or verification answer said nothing
 * either. Now a code is a sentence, or it is in [QUIET] with the reason it
 * stays off the screen, or it gets [fallback], which names it.
 * tests/test_failures_reach_the_screen.py fails when the bridge emits a code
 * that is in none of them.
 */
object FailureText {

    /** Kept off the screen on purpose, and why. */
    val QUIET: Map<String, String> = mapOf(
        // Failures while handling a control message that the PEER sent. A
        // line per malformed message would let anyone in the group write to
        // our screen; each is logged to Diagnostics instead.
        "call_control_failed" to "a peer's group-call control message",
        "verify_control_failed" to "a peer's group-verification control message",
        "file_control_failed" to "a peer's group-file control message",
        "file_signal_failed" to "a peer's file-transfer control message",
        "epoch_listener_failed" to "an internal listener on a group key change",
    )

    fun text(code: String, peer: String?): String? {
        Verification.refusal(code)?.let { return it }
        CallUi.failure(code)?.let { return it }
        GroupText.failure(code, peer)?.let { return it }
        SPECIFIC[code]?.let { return it }
        if (code in QUIET) return null
        return fallback(code)
    }

    /** For a code this build has no sentence for: say that something failed,
     *  and which, rather than nothing. */
    fun fallback(code: String): String =
        "Something did not work ($code). Profile → Diagnostics has the details."

    private val SPECIFIC: Map<String, String> = mapOf(
        "no_transport" to "Not connected to the server.",
        "protocol_send_failed" to "A message to this contact could not be sent. Try again.",
        "decrypt_failed" to "A message from this contact could not be decrypted.",
        // Owner, 2026-10-24: a 1:1 message is never sent unencrypted.
        "waiting_for_contact" to "Not sent yet: they are not a contact, so a contact request was sent. Your message waits, and goes encrypted (OTRv4+) as soon as they accept.",
        "plaintext_refused" to "Not sent yet: this contact's app is not offering OTRv4+ encryption right now. Your message waits and goes only once an encrypted session is up; it is never sent unencrypted.",
        // A2: the same identity without, or with another, post-quantum key is
        // what an attacker able to forge the classical key looks like.
        "pq_v2_required" to "Encryption with this contact was refused: their app is too old for this one's security requirements. Both of you need this version or newer.",
        "pq_downgrade" to "Encryption with this contact was refused: their app did not prove its post-quantum key this time. Ask them in person whether they reinstalled or went back to an older version.",
        "pq_key_changed" to "Encryption with this contact was refused: their post-quantum key has changed. Ask them in person whether they reinstalled before trusting them again.",
        "smp_not_produced" to "The verification could not be started. Try again.",
        "smp_respond_failed" to "Your verification answer could not be sent. Try again.",
        "smp_resume_failed" to "The verification could not be continued. Ask them to start it again.",
        "smp_resume_unsupported" to "The verification could not be continued. Ask them to start it again.",
        "smp_held_request_gone" to "Their verification request expired. Ask them to start it again.",
        "group_send_failed" to "The message could not be sent to the group. Try again.",
        "group_invite_failed" to "The invitation could not be sent. Try again.",
        "group_remove_failed" to "The member could not be removed. Try again.",
        "group_welcome_send_failed" to "An invitation could not be delivered. Invite them again.",
        "group_signal_unencrypted" to "A group control message arrived unencrypted and was refused.",
        "room_plaintext_refused" to "An unencrypted message in this encrypted group was refused.",
        "room_message_rejected" to "The server rejected a message in this room.",
        "call_full" to "The group call is full.",
        // The call's keys follow the group's: a key change in the group that
        // the call could not take up.
        "call_rekey_failed" to "The group call could not move to the group's new keys. Leave the call and join it again.",
        // An offer from a member this device has not verified is refused.
        "group_file_unverified" to "A file offered in this group was refused: the sender is not verified.",
        // The periodic key change; the group keeps its current keys.
        "group_rekey_failed" to "The group's scheduled key change did not happen. It keeps its current keys and tries again later.",
        // A Welcome resent until its time ran out, never confirmed.
        "group_welcome_unconfirmed" to "An invitation to this group was never confirmed. Invite them again if they did not join.",
        "groups_state_too_large" to "Your secure groups' saved state is too large to save. Leave groups you no longer use.",
    )
}
