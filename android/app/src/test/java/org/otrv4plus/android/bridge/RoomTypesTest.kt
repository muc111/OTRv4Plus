// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The room types the UI binds to.
 *
 * Note what is NOT tested here: whether an owner may destroy a room. That is
 * decided once, in `otrv4plus_muc.privileges`, from XEP-0045 §5.1, and tested
 * by being executed in `tests/test_muc_rules.py`. A second derivation on this
 * side could disagree with the first, and the disagreement would show up as a
 * button that fails minutes after it is pressed — over I2P, long enough for
 * the user to have moved on.
 *
 * What is tested is what this side genuinely decides: which service hosts
 * rooms, whether a retry is worth offering, and what to show when the service
 * advertised no name.
 */
class RoomTypesTest {

    // ── finding the rooms service ───────────────────────────────────────────

    @Test
    fun `a conference text identity hosts rooms`() {
        assertTrue(
            DiscoveredService("rooms.x.i2p", "Chatrooms", "conference", "text")
                .hostsRooms)
    }

    @Test
    fun `a file store does not`() {
        assertFalse(
            DiscoveredService("upload.x.i2p", "Uploads", "store", "file")
                .hostsRooms)
    }

    @Test
    fun `an IRC gateway is a conference but not a text one`() {
        // XEP-0045's identity is conference/text specifically. A gateway
        // advertises conference/irc and joining it as a MUC would not work.
        assertFalse(
            DiscoveredService("irc.x.i2p", "IRC", "conference", "irc")
                .hostsRooms)
    }

    @Test
    fun `a service that answered nothing claims nothing`() {
        assertFalse(DiscoveredService("x.i2p", "", "", "").hostsRooms)
    }

    // ── what to show for a room ─────────────────────────────────────────────

    @Test
    fun `a named room shows its name`() {
        assertEquals("General",
            RoomSummary("general@rooms.x.i2p", "General").label)
    }

    @Test
    fun `an unnamed room shows its localpart rather than the whole jid`() {
        assertEquals("general", RoomSummary("general@rooms.x.i2p", "").label)
    }

    @Test
    fun `a blank name is treated as absent`() {
        assertEquals("general", RoomSummary("general@rooms.x.i2p", "   ").label)
    }

    // ── standing ────────────────────────────────────────────────────────────

    @Test
    fun `the default standing claims nothing`() {
        val s = RoomStanding()
        assertFalse(s.speak)
        assertFalse(s.destroy)
        assertFalse(s.moderates)
        assertEquals("none", s.affiliation)
        assertEquals("none", s.role)
    }

    @Test
    fun `moderation controls are worth showing to a moderator`() {
        assertTrue(RoomStanding(kick = true).moderates)
    }

    @Test
    fun `and to an owner who is not one`() {
        assertTrue(RoomStanding(destroy = true, configure = true).moderates)
    }

    @Test
    fun `an ordinary participant sees no moderation controls`() {
        assertFalse(RoomStanding(speak = true, invite = true).moderates)
    }

    @Test
    fun `the two questions are carried separately`() {
        // An owner who joined as a visitor: cannot speak, can still destroy.
        val s = RoomStanding(affiliation = "owner", role = "visitor",
                             speak = false, destroy = true)
        assertFalse(s.speak)
        assertTrue(s.destroy)
    }

    // ── what a failure invites the user to do ───────────────────────────────

    @Test
    fun `a timeout is worth trying again`() {
        assertTrue(RoomOutcome(false, "timeout", "…").worthRetrying)
    }

    @Test
    fun `a full room is worth trying again`() {
        assertTrue(RoomOutcome(false, "service_unavailable", "…").worthRetrying)
    }

    @Test
    fun `a ban is not`() {
        assertFalse(RoomOutcome(false, "forbidden", "…").worthRetrying,
            "a ban will not stop being a ban, and a retry over I2P is four " +
                "minutes of somebody's evening")
    }

    @Test
    fun `a members-only room is not`() {
        assertFalse(
            RoomOutcome(false, "registration_required", "…").worthRetrying)
    }

    @Test
    fun `a taken nickname points at the nickname`() {
        val o = RoomOutcome(false, "conflict", "…")
        assertTrue(o.isAboutTheNickname)
        assertFalse(o.worthRetrying,
            "retrying with the same nickname gets the same answer")
    }

    @Test
    fun `a network failure does not point at the nickname`() {
        assertFalse(RoomOutcome(false, "network", "…").isAboutTheNickname)
    }

    @Test
    fun `an unrecognised code claims nothing`() {
        val o = RoomOutcome(false, "something-python-grew-later", "…")
        assertFalse(o.worthRetrying)
        assertFalse(o.isAboutTheNickname)
    }

    @Test
    fun `no failure is both about the nickname and worth a plain retry`() {
        for (code in listOf("conflict", "forbidden", "registration_required",
                            "not_authorized", "not_allowed", "not_acceptable",
                            "service_unavailable", "item_not_found",
                            "bad_request", "unsupported", "timeout",
                            "network", "cancelled", "unknown")) {
            val o = RoomOutcome(false, code, "…")
            assertFalse(o.isAboutTheNickname && o.worthRetrying, code)
        }
    }
}
