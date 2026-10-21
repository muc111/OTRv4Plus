// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomOccupant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** A room's people list: sections, search, and who can be added. */
class RoomPeopleTest {

    private val alice = RoomOccupant("Alice", "moderator", "owner", "alice@x.i2p")
    private val bob = RoomOccupant("bob", "participant", "none", "bob@x.i2p")
    private val carol = RoomOccupant("carol", "participant", "none", "")
    private val dave = RoomOccupant("dave", "visitor", "none", "dave@x.i2p")
    private val me = RoomOccupant("me", "participant", "none", "Owner@x.i2p")

    @Test
    fun `sections by role with counts, moderators first`() {
        val s = RoomPeople.sections(listOf(dave, carol, bob, alice))
        assertEquals(listOf("Moderators (1)", "Participants (2)", "Visitors (1)"), s.map { it.title })
        assertEquals(listOf("bob", "carol"), s[1].people.map { it.nick })
    }

    @Test
    fun `search finds by nickname or address, and empty sections go`() {
        val s = RoomPeople.sections(listOf(alice, bob, dave), "DAVE@")
        assertEquals(listOf("Visitors (1)"), s.map { it.title })
        assertEquals(listOf(alice), RoomPeople.sections(listOf(alice, bob), "ali").single().people)
        assertTrue(RoomPeople.sections(listOf(alice), "zzz").isEmpty())
    }

    @Test
    fun `only a revealed address can be added, and never ourselves`() {
        val contacts = setOf("bob@x.i2p")
        val act = { p: RoomOccupant -> RoomPeople.action(p, "owner@x.i2p") { it in contacts } }
        assertEquals(RoomPeople.Action.ADD, act(alice))
        assertEquals(RoomPeople.Action.MESSAGE, act(bob))
        assertEquals(RoomPeople.Action.NO_ADDRESS, act(carol))
        assertEquals(RoomPeople.Action.SELF, act(me))
        // A nickname that looks like an address is still only a nickname.
        assertEquals(RoomPeople.Action.NO_ADDRESS, act(RoomOccupant("eve@x.i2p", "participant", "none", "")))
    }

    @Test
    fun `a hundred people are all listed and searchable`() {
        val many = (1..100).map { RoomOccupant("user$it", "participant", "none", "user$it@x.i2p") }
        assertEquals(100, RoomPeople.sections(many).single().people.size)
        assertEquals(12, RoomPeople.sections(many, "user1").single().people.size)  // 1, 10-19, 100
        assertEquals("100 people in this room", RoomPeople.summary(many))
    }
}
