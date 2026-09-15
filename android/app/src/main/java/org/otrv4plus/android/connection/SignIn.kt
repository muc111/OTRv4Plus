// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * Turning what a person typed into an account and a route.
 *
 * WHY THESE ARE TWO DIFFERENT THINGS
 * ----------------------------------
 * A JID's domain is the XMPP **virtual host** -- the name in `alice@here`, the
 * thing the server calls itself, the thing that appears in every address a
 * contact gives out. The route is the I2P destination a SAM stream is opened
 * to, which is a 52-character hash and is not a name at all: nothing resolves
 * it, the label IS the address.
 *
 * One server can front several virtual hosts, and a virtual host can move
 * between destinations, so the two cannot be collapsed into one field. The
 * profile carries both for that reason.
 *
 * WHAT THE USER SHOULD HAVE TO KNOW
 * ---------------------------------
 * Their username, their password, and which server they are on. NOT a b32
 * address. The mapping from "xmpp-elite.i2p" to its destination hash is
 * shipped in `android_bridge/settings.DEFAULT_SERVER` and applied here, so
 * the sign-in screen is an ordinary sign-in screen.
 *
 * That default is routing information, not a trust anchor, and compiling it in
 * does not make it one: the DAKE pins the peer's identity key end to end by
 * TOFU, so a substituted server at that address costs availability and
 * metadata and cannot read a message or impersonate a contact.
 *
 * WHY PLAIN KOTLIN
 * ----------------
 * No Android import, so every rule below is tested by being run rather than
 * by being read. The screen renders; this decides.
 */
object SignIn {

    /**
     * The virtual host of the server the app ships pointing at.
     *
     * The NAME, not the route. The route lives in Python and is applied by
     * leaving [Target.server] blank, which is what "use the compiled-in
     * default" means at the bridge.
     */
    const val DEFAULT_DOMAIN = "xmpp-elite.i2p"

    /** What the dropdown offers. */
    enum class Choice {
        /** The shipped server. Its b32 route is applied internally. */
        DEFAULT,

        /** Somewhere else, named by the user. */
        CUSTOM,
    }

    /**
     * An account and the route to reach it.
     *
     * [server] blank means "use the compiled-in default", which is how the
     * bridge already spells it -- `ConnectionProfile.server` is deliberately
     * left empty rather than eagerly filled so that `is_default_server` can
     * tell a deliberate choice from an inherited one.
     */
    data class Target(val jid: String, val server: String) {
        val usesDefaultRoute: Boolean get() = server.isEmpty()
    }

    /** Why a sign-in cannot be attempted yet. Null when it can. */
    fun problem(account: String, choice: Choice, custom: String): String? {
        val typed = account.trim()
        if (typed.isEmpty()) return "Enter your username."
        if (typed.startsWith("@") || typed.endsWith("@"))
            return "That address is missing a part."
        if (typed.count { it == '@' } > 1)
            return "An address has one @ in it."
        if (typed.any { it.isWhitespace() })
            return "An address cannot contain spaces."
        if (choice == Choice.CUSTOM) {
            val host = custom.trim()
            if (host.isEmpty()) return "Enter your server's address."
            if (host.any { it.isWhitespace() })
                return "A server address cannot contain spaces."
            if (!host.contains(".")) return "That does not look like a server."
        }
        return null
    }

    /**
     * Resolve what was typed.
     *
     * A bare username takes the selected server's domain, which is the whole
     * point of the dropdown: "alice" plus "xmpp-elite.i2p" is an account, and
     * making somebody type the domain they just picked from a list is the kind
     * of thing that makes an app feel like a configuration file.
     *
     * A FULL address is respected as typed. Somebody who writes
     * `alice@elsewhere.i2p` means it, and silently rewriting their domain to
     * match a dropdown would connect them somewhere they did not ask for.
     * The route still comes from the dropdown, because a virtual host and a
     * destination are different things and the user may well be reaching
     * another host through a server they can route to.
     *
     * Returns null when [problem] would not. Callers check that first.
     */
    fun resolve(account: String, choice: Choice, custom: String): Target? {
        if (problem(account, choice, custom) != null) return null
        val typed = account.trim()
        val domain = when (choice) {
            Choice.DEFAULT -> DEFAULT_DOMAIN
            Choice.CUSTOM -> custom.trim()
        }
        val jid = if (typed.contains("@")) typed else "$typed@$domain"
        // DEFAULT leaves the route blank so the bridge applies the compiled-in
        // b32. CUSTOM routes to the host the user named: they gave one name,
        // and inventing a second would be guessing.
        val server = when (choice) {
            Choice.DEFAULT -> ""
            Choice.CUSTOM -> domain
        }
        return Target(jid, server)
    }

    /**
     * Which choice a remembered JID came from.
     *
     * So a returning user sees the dropdown they left it on rather than the
     * default, and a custom server does not silently revert on the next
     * launch.
     */
    fun choiceFor(jid: String): Choice =
        if (domainOf(jid).equals(DEFAULT_DOMAIN, ignoreCase = true))
            Choice.DEFAULT else Choice.CUSTOM

    /** The part after the @, or "" when there is not one. */
    fun domainOf(jid: String): String =
        jid.trim().substringAfter('@', "").substringBefore('/')

    /** The part before the @, for showing a remembered account in the field. */
    fun usernameOf(jid: String): String = jid.trim().substringBefore('@')
}
