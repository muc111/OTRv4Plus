// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Moderation
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * What the Moderation section on a profile says (owner, 2026-10-17: "Perm ban
 * or unban ... for server admin / mod use only. No one else should see it";
 * timed bans removed 2026-10-25). Shown only to an account the
 * SERVER lists its admin commands to; the server
 * (prosody/mod_otrv4plus_moderation.lua) runs every ban. Plain Kotlin, so
 * `ModerationTextTest` runs it.
 */
object ModerationText {

    const val TITLE = "Moderation (server admin)"

    const val NOTE =
        "Only you, as this server's admin, see this. A ban is permanent: it " +
            "signs them out at once and refuses every sign-in until you lift it " +
            "with Unban. It cannot be used on another admin or on yourself."

    fun utc(epochSeconds: Long): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date(epochSeconds * 1000))

    /** One line: the state, or why it could not be read. */
    fun status(m: Moderation?): String = when {
        m == null -> "Checking…"
        !m.outcome.ok -> m.outcome.detail.ifBlank { "Could not ask the server (${m.outcome.code})." }
        !m.banned -> "Not banned."
        m.until == 0L -> "Banned permanently."
        else -> "Banned until ${utc(m.until)}."
    }

    /** Bans are permanent only (owner, 2026-10-25); "until" above is for a
     *  timed ban an earlier build stored, which still ends on its date. */
    fun confirm(jid: String): String =
        "Ban $jid permanently? They are signed out now and cannot sign in again until you lift the ban."
}
