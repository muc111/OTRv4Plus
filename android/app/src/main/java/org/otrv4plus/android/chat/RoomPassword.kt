// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomOutcome

/**
 * Password-protected rooms: when to ask, and what a room password is.
 *
 * The SERVICE decides whether a room needs a password: a join without one is
 * refused with `not-authorized` (XEP-0045 §7.2.6), and that refusal is what
 * opens the prompt. Nothing here guesses or retries on its own; every retry is
 * the user typing a password and pressing Enter.
 *
 * A room password controls who may ENTER. It is not end-to-end encryption:
 * the server still reads everything said in the room. The screens say so.
 *
 * Plain Kotlin, driven by `RoomPasswordTest`. Mirrors
 * `otrv4plus_muc.validate_room_password`.
 */
object RoomPassword {

    const val NOT_AUTHORIZED = "not_authorized"
    const val MAX_LENGTH = 128

    /** What the prompt shows. [retry] is true after a refused password. */
    data class Prompt(val room: String, val nick: String, val message: String,
                      val retry: Boolean)

    /** The prompt to show after a join, or null when none is needed. */
    @JvmStatic
    fun afterJoin(room: String, nick: String, outcome: RoomOutcome,
                  triedPassword: Boolean): Prompt? {
        if (outcome.ok || outcome.code != NOT_AUTHORIZED) return null
        return if (triedPassword)
            Prompt(room, nick, "That password was not accepted. Try again.", true)
        else
            Prompt(room, nick, "This room is password protected. Enter its " +
                "password to join.", false)
    }

    /**
     * The prompt to show BEFORE joining a room the list already marks as
     * needing a password, or null. Asking first saves a refused round trip,
     * which over I2P is tens of seconds (owner, 2026-10-17: "ensure proper
     * prompts for entering password and joining").
     */
    @JvmStatic
    fun beforeJoin(room: String, nick: String, needsPassword: Boolean): Prompt? =
        if (needsPassword) Prompt(room, nick, "This room is password protected. " +
            "Enter its password to join.", false) else null

    /**
     * Said instead of a password prompt for an encrypted group whose keys
     * this phone does not hold. Its password admits to the ROOM only; what
     * is said there is encrypted for the group's members, and only a member
     * can add someone (with an invitation over OTRv4+).
     */
    const val NEEDS_INVITE_TITLE = "Ask to join this group?"
    const val NEEDS_INVITE =
        "This is an end-to-end encrypted group: only its members can read " +
            "it, and only a member can add you. Ask to join posts your " +
            "address in the group's room, once. Its members see that you " +
            "asked and can invite you; the invitation arrives in your chats " +
            "over OTRv4+. Anyone in the room, and the server, can see that " +
            "you asked."

    /** Null if [password] may be used; otherwise why not. */
    @JvmStatic
    fun problem(password: String): String? = when {
        password.isBlank() -> "Enter a password for the room."
        password.length > MAX_LENGTH -> "That password is too long (limit $MAX_LENGTH characters)."
        password.any { it.code < 32 } -> "A room password cannot contain control characters."
        else -> null
    }

    /** Said wherever a room password is set or entered. */
    const val NOT_ENCRYPTION =
        "A room password only controls who can enter. Messages in the room " +
            "are not end-to-end encrypted: the server can read them."
}
