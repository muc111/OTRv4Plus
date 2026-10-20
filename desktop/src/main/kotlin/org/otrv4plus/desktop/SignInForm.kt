// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import org.otrv4plus.android.connection.SignIn

/**
 * What the desktop Connect screen's account field means. Owner (2026-10-20):
 * "i had to type full address it should act same as phone and allow only
 * username to be typed and auto add @otrv4plus.i2p".
 *
 * The phone's rules ([SignIn]): a bare username takes a domain, a full
 * address is used as typed. The desktop has no server dropdown, only the
 * optional route field in Connection settings, so the domain a bare
 * username takes is that field when it names a host, and the shipped
 * server's otherwise. A `.b32.i2p` route is a destination, not a name, so a
 * username is never put "@" one.
 */
object SignInForm {

    /** Why the form cannot be used yet, in the phone's words; null when it can. */
    fun problem(typed: String): String? = SignIn.problem(typed, SignIn.Choice.DEFAULT, "")

    /** The account [typed] signs in as, given the route field [server]. */
    fun account(typed: String, server: String): String? {
        if (problem(typed) != null) return null
        val t = typed.trim()
        if (t.contains("@")) return t
        val route = server.trim()
        val domain = if (route.isEmpty() || route.endsWith(".b32.i2p", ignoreCase = true))
            SignIn.DEFAULT_DOMAIN else route
        return "$t@$domain"
    }
}
