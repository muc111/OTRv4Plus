// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * What the app says when OUR account is signed in somewhere else too.
 *
 * Owner (2026-10-16): signed in as alice on the terminal while alice was
 * signed in on the phone, and nothing said so -- "i don't want people using
 * same login details and cloning accounts". XMPP allows several sessions per
 * account and the server tells each about the others, so the app can say so.
 * A server admin can also end them (XEP-0133); stopping them signing in again
 * needs a new password, or the server limited to one session.
 *
 * Plain Kotlin, shared by the desktop app, so a JVM test reads every line.
 */
object AccountSessions {

    /** The warning, or null when this is the only session. */
    fun banner(others: Int): String? = when {
        others <= 0 -> null
        others == 1 -> "Your account is also signed in on another device. " +
            "If that isn't you, change your password now."
        else -> "Your account is also signed in on $others other devices. " +
            "If that isn't you, change your password now."
    }

    /** Label of the button a server admin gets. */
    const val END_BUTTON = "Sign out other devices"

    /** After [END_BUTTON]: [ended] sessions, or the server's [code]. */
    fun outcome(ok: Boolean, code: String, ended: Int): String = when {
        ok && ended == 0 -> "There was no other session to sign out."
        ok -> "Signed out $ended other session(s). They can sign in again " +
            "with the password: change it if that wasn't you."
        code == "forbidden" || code == "not_authorized" ->
            "The server refused: only a server admin can sign out sessions."
        else -> "The server did not sign the other sessions out ($code)."
    }
}
