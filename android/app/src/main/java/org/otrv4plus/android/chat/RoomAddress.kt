// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Turning what the user typed into a room JID, or saying why not.
 *
 * WHY THIS EXISTS
 * ---------------
 * The Rooms screen asked for a full address -- "Room address", placeholder
 * `general@rooms.example.i2p`. Somebody creating a room types the name of the
 * room. What then reached slixmpp was a domainless JID, `join_muc_wait` sat on
 * it for its 300 s default, and the throw that eventually came back skipped
 * the line that cleared the spinner. The visible bug was "Create room hangs
 * forever"; the cause started here, with a field asking for something nobody
 * should have to know.
 *
 * The user types `myroom`. The service comes from XEP-0030 discovery against
 * the server actually connected to. Neither is guessed and neither is
 * hard-coded.
 *
 * WHY IT IS ITS OWN FILE
 * ----------------------
 * Plain Kotlin, no Android import, so the rule is executed by a JVM test
 * rather than reviewed. Every screen in this project is first compiled by CI,
 * so anything decidable off-device is decided off-device.
 */
object RoomAddress {

    /**
     * What to do with what was typed.
     *
     * [Resolved] carries a JID that is safe to hand to the bridge.
     * [Rejected] carries a sentence for the user and NOTHING is sent --
     * refusing here is the difference between an error in a second and a
     * five-minute wait on a JID that was never going to work.
     */
    sealed interface Outcome {
        data class Resolved(val jid: String) : Outcome
        data class Rejected(val reason: String) : Outcome
    }

    /**
     * Resolve [typed] against the discovered conference [service].
     *
     * [service] is the MUC component XEP-0030 found on the connected server,
     * or null/blank when discovery has not run or found none. A null service
     * is a REFUSAL, not a fallback to some default domain: inventing a
     * conference host would send a join to a server that may not exist and
     * would take the full timeout to find out.
     *
     * A full JID is accepted as typed. Somebody who knows the address of a
     * room on another server should be able to use it, and the field has
     * always taken one — removing that would be a regression to fix a
     * different problem.
     */
    fun resolve(typed: String, service: String?): Outcome {
        val name = typed.trim()
        if (name.isEmpty()) {
            return Outcome.Rejected("Enter a room name.")
        }
        if (name.contains('@')) {
            return full(name)
        }
        if (name.contains('/')) {
            return Outcome.Rejected(
                "A room name cannot contain \"/\".")
        }
        if (!isValidLocalPart(name)) {
            return Outcome.Rejected(
                "A room name cannot contain spaces or any of : \" < > & ' ")
        }
        val host = service?.trim().orEmpty()
        if (host.isEmpty()) {
            // The honest refusal. "No rooms service" is a fact about the
            // server, and it is not the user's typing.
            return Outcome.Rejected(
                "No rooms service has been found on this server yet. Open " +
                    "Rooms and let discovery finish, or type a full room " +
                    "address.")
        }
        return Outcome.Resolved("${name.lowercase()}@${host.lowercase()}")
    }

    /** A JID the user typed in full: validated, never rebuilt. */
    private fun full(typed: String): Outcome {
        val local = typed.substringBefore('@')
        val host = typed.substringAfter('@').substringBefore('/')
        if (local.isEmpty() || host.isEmpty()) {
            return Outcome.Rejected(
                "That is not a room address. Use `room` or `room@service`.")
        }
        if (!isValidLocalPart(local) || !isValidHost(host)) {
            return Outcome.Rejected(
                "That room address contains characters a JID cannot have.")
        }
        // The resource is dropped deliberately: in a MUC JID the resource is
        // the occupant nickname, which this app carries separately. Joining
        // `room@svc/someone` would ask to be that someone.
        return Outcome.Resolved("${local.lowercase()}@${host.lowercase()}")
    }

    /**
     * RFC 7622 forbids these in a localpart outright.
     *
     * Deliberately not a full JID validator -- the server is the authority on
     * what it will accept, and a client that second-guesses it rejects
     * addresses that would have worked. This catches only what cannot be a
     * JID at all, which is what turns a five-minute timeout into an
     * immediate sentence.
     */
    private fun isValidLocalPart(text: String): Boolean =
        text.isNotEmpty() &&
            text.none { it.isWhitespace() } &&
            text.none { it in "\"&'/:<>@" }

    private fun isValidHost(text: String): Boolean =
        text.isNotEmpty() &&
            text.none { it.isWhitespace() } &&
            text.none { it in "\"&'/:<>@" } &&
            !text.startsWith(".") && !text.endsWith(".")
}
