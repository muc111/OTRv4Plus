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
