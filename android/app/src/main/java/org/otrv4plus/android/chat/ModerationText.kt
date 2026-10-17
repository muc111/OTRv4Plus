// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Moderation
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * What the Moderation section on a profile says (owner, 2026-10-17: ban an
 * account "for set amount of days or Perm ban or unban ... for server admin /
 * mod use only. No one else should see it"). Shown only to an account the
 * SERVER lists its admin commands to; the server
 * (prosody/mod_otrv4plus_moderation.lua) runs every ban. Plain Kotlin, so
 * `ModerationTextTest` runs it.
 */
object ModerationText {

    const val TITLE = "Moderation (server admin)"

    const val NOTE =
        "Only you, as this server's admin, see this. A ban signs them out at " +
            "once and refuses every sign-in until it ends. It cannot be used " +
            "on another admin or on yourself."

    const val MAX_DAYS = 3650

    /** The number typed for "Ban for … days", or null when it is not 1..MAX_DAYS. */
    fun days(typed: String): Int? =
        typed.trim().toIntOrNull()?.takeIf { it in 1..MAX_DAYS }

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

    fun confirm(jid: String, days: Int): String =
        if (days == 0) "Ban $jid permanently? They are signed out now and cannot sign in again until you lift the ban."
        else "Ban $jid for $days day${if (days == 1) "" else "s"}? They are signed out now and cannot sign in until it ends."
}
