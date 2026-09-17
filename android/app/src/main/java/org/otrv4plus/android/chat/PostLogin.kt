// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * What has actually finished since authentication, as one observable answer.
 *
 * WHY THIS EXISTS
 * ---------------
 * There was no post-login lifecycle to point at. Authentication completed,
 * `XmppTransport._announce()` sent presence and asked for the roster, the
 * service's drain loop polled contacts, and the screen rendered whatever
 * happened to be there on that tick. Every piece worked; nothing said whether
 * the sequence had got anywhere.
 *
 * The cost of that is not theoretical. An empty conversation list means
 * either "your roster has nobody in it" or "the roster has not arrived yet",
 * and with no readiness state the screen could not tell a user which — so a
 * working app and a stalled one looked identical, and a handset report of
 * "contacts do not appear" could not be answered without a log.
 *
 * WHAT IT IS NOT
 * --------------
 * Not a gate. Nothing waits on it and no feature is disabled by it; the
 * pieces already run concurrently and should. It is an OBSERVATION of what
 * has completed, so the UI can say "still fetching" instead of implying
 * "nobody is here".
 *
 * Deliberately NOT a claim about the server. [rosterSeen] means a roster read
 * returned — including one that returned nothing, which is a real answer for
 * a new account. It does not mean anybody is on it, and it says nothing about
 * subscriptions.
 *
 * Plain Kotlin, no Android import, so the rule is executed rather than read.
 */
class PostLogin {

    /** The account is authenticated and the stream is up. */
    var authenticated: Boolean = false
        private set

    /**
     * A roster read has come back at least once since authenticating.
     *
     * True for an EMPTY roster too. "The server told us you have no contacts"
     * and "we have not asked yet" are different, and conflating them is what
     * makes an empty screen unreadable.
     */
    var rosterSeen: Boolean = false
        private set

    /** How many roster entries the last read returned. */
    var rosterSize: Int = 0
        private set

    /** Service discovery has run, whatever it found. */
    var servicesDiscovered: Boolean = false
        private set

    /** The MUC service found by discovery, or null when there is none. */
    var roomService: String? = null
        private set

    /** Everything that follows authentication has reported in. */
    val ready: Boolean get() = authenticated && rosterSeen

    /**
     * What to tell somebody looking at an empty conversation list.
     *
     * Null when there is nothing to explain — either the list is not empty or
     * we are not connected, and both are already covered by other lines on
     * that screen.
     */
    fun emptyListExplanation(conversationCount: Int): String? = when {
        conversationCount > 0 -> null
        !authenticated -> null
        !rosterSeen -> "Fetching your contacts…"
        else -> null
    }

    fun onAuthenticated() {
        if (authenticated) return
        authenticated = true
    }

    /** A roster read returned [size] entries. */
    fun onRoster(size: Int) {
        if (!authenticated) return
        rosterSeen = true
        rosterSize = size
    }

    /** Discovery finished; [service] is the MUC component or null. */
    fun onServices(service: String?) {
        servicesDiscovered = true
        roomService = service?.takeIf { it.isNotBlank() }
    }

    /**
     * The session ended — signed out, dropped, or a different account.
     *
     * Everything resets, including [servicesDiscovered]: the MUC service
     * belongs to the server that was connected to, and carrying it into the
     * next session would offer to build room JIDs against a host this account
     * may never have spoken to.
     */
    fun onSignedOut() {
        authenticated = false
        rosterSeen = false
        rosterSize = 0
        servicesDiscovered = false
        roomService = null
    }
}
