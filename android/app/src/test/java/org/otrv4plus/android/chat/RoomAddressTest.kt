// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Turning a typed room name into a JID.
 *
 * THE HANDSET BUG. The field asked for a full "Room address"; the user typed
 * `myroom`. A domainless JID reached slixmpp, `join_muc_wait` sat on it for
 * its 300 s default, and the throw that eventually came back skipped the line
 * that cleared the spinner. Visible symptom: "Create room loads forever."
 */
class RoomAddressTest {

    private val service = "rooms.xmpp-elite.i2p"

    private fun resolved(typed: String, svc: String? = service): String {
        val outcome = RoomAddress.resolve(typed, svc)
        assertTrue(outcome is RoomAddress.Outcome.Resolved,
                   "rejected: ${(outcome as? RoomAddress.Outcome.Rejected)?.reason}")
        return outcome.jid
    }

    private fun rejected(typed: String, svc: String? = service): String {
        val outcome = RoomAddress.resolve(typed, svc)
        assertTrue(outcome is RoomAddress.Outcome.Rejected,
                   "unexpectedly resolved to ${(outcome as? RoomAddress.Outcome.Resolved)?.jid}")
        return outcome.reason
    }

    // ── the case that was broken ─────────────────────────────────────────────

    @Test
    fun `a bare name becomes a JID on the discovered service`() {
        assertEquals("myroom@rooms.xmpp-elite.i2p", resolved("myroom"))
    }

    @Test
    fun `the service is the discovered one, never a hard-coded default`() {
        assertEquals("myroom@conference.example.i2p",
                     resolved("myroom", "conference.example.i2p"))
    }

    @Test
    fun `surrounding whitespace is not part of the name`() {
        assertEquals("myroom@rooms.xmpp-elite.i2p", resolved("  myroom  "))
    }

    @Test
    fun `a room name is case-folded like any JID`() {
        assertEquals("myroom@rooms.xmpp-elite.i2p", resolved("MyRoom"))
    }

    // ── a full address still works ───────────────────────────────────────────

    @Test
    fun `a full address is taken as typed`() {
        assertEquals("general@other.i2p",
                     resolved("general@other.i2p", service))
    }

    @Test
    fun `a full address works even with no service discovered`() {
        // Somebody who knows the address of a room elsewhere should not be
        // blocked by this server having no conference component.
        assertEquals("general@other.i2p", resolved("general@other.i2p", null))
    }

    @Test
    fun `an occupant resource is dropped rather than joined as`() {
        // In a MUC JID the resource is the nickname. Joining `room@svc/bob`
        // would be asking to be bob.
        assertEquals("general@other.i2p", resolved("general@other.i2p/bob"))
    }

    // ── refusals happen here, not after five minutes ─────────────────────────

    @Test
    fun `no discovered service is an honest refusal, not a guess`() {
        // Inventing `conference.<domain>` would send a join to a host that may
        // not exist and take the full timeout to find out.
        val reason = rejected("myroom", null)
        assertTrue(reason.contains("rooms service"), reason)
    }

    @Test
    fun `a blank service is treated as none`() {
        assertTrue(rejected("myroom", "   ").isNotEmpty())
    }

    @Test
    fun `an empty name is refused`() {
        assertTrue(rejected("").isNotEmpty())
        assertTrue(rejected("   ").isNotEmpty())
    }

    @Test
    fun `a name with a space is refused immediately`() {
        assertTrue(rejected("my room").isNotEmpty())
    }

    @Test
    fun `characters a JID cannot contain are refused`() {
        for (bad in listOf("my\"room", "my&room", "my'room", "my<room",
                           "my>room", "my:room")) {
            assertTrue(rejected(bad).isNotEmpty(), "accepted $bad")
        }
    }

    @Test
    fun `a bare name containing a slash is refused`() {
        assertTrue(rejected("my/room").isNotEmpty())
    }

    @Test
    fun `an address missing either half is refused`() {
        assertTrue(rejected("@service.i2p").isNotEmpty())
        assertTrue(rejected("room@").isNotEmpty())
    }

    @Test
    fun `every refusal carries a sentence for the user`() {
        for (bad in listOf("", "my room", "@x.i2p", "room@")) {
            val reason = rejected(bad)
            assertTrue(reason.isNotBlank(), "no reason for $bad")
            // A code is not an explanation.
            assertTrue(reason.any { it == ' ' }, "not a sentence: $reason")
        }
    }
}
