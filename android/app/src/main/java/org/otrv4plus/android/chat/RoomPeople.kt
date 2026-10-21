// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.RoomOccupant

/**
 * A room's people list: search, sections by role, and what each row offers.
 * Owner (2026-10-21): "click on the user to add to roster ... if we have 100
 * people in this room we need a better way to view and add users".
 *
 * Plain Kotlin, shared by the phone and the desktop, driven by
 * `RoomPeopleTest`.
 *
 * WHO CAN BE ADDED. Only someone whose real address the ROOM SERVICE put in
 * their presence ([RoomOccupant.jid]) -- a non-anonymous room such as
 * Welcome. A nickname is the room's label and anyone can pick any; adding
 * by nickname would add whoever the room says. With no address, a row
 * offers nothing and says why.
 */
object RoomPeople {

    /** A search box from this many people up. */
    const val SEARCH_FROM = 8

    /** What a row offers. */
    enum class Action {
        /** Not a contact: Add (a contact request) and Message. */
        ADD,
        /** Already a contact: Message. */
        MESSAGE,
        /** Us. */
        SELF,
        /** The room did not reveal their address. */
        NO_ADDRESS,
    }

    data class Section(val title: String, val people: List<RoomOccupant>)

    fun roleLabel(role: String): String = when (role) {
        "moderator" -> "Moderator"
        "participant" -> "Participant"
        "visitor" -> "Visitor"
        else -> ""
    }

    /** Case-insensitive match on the nickname or the revealed address. */
    fun matches(p: RoomOccupant, query: String): Boolean {
        val q = query.trim()
        if (q.isEmpty()) return true
        return p.nick.contains(q, ignoreCase = true) || p.jid.contains(q, ignoreCase = true)
    }

    /** Moderators, then participants, then visitors, then anyone else;
     *  each "Title (n)", alphabetical inside, empty sections left out. */
    fun sections(people: List<RoomOccupant>, query: String = ""): List<Section> {
        val shown = people.filter { matches(it, query) }
        val order = listOf("moderator" to "Moderators", "participant" to "Participants",
                           "visitor" to "Visitors")
        val known = order.map { it.first }.toSet()
        val out = mutableListOf<Section>()
        for ((role, title) in order) {
            val group = shown.filter { it.role == role }.sortedBy { it.nick.lowercase() }
            if (group.isNotEmpty()) out += Section("$title (${group.size})", group)
        }
        val rest = shown.filter { it.role !in known }.sortedBy { it.nick.lowercase() }
        if (rest.isNotEmpty()) out += Section("Others (${rest.size})", rest)
        return out
    }

    fun action(p: RoomOccupant, self: String, isContact: (String) -> Boolean): Action {
        val jid = ChatState.bare(p.jid)
        return when {
            jid.isEmpty() || '@' !in jid -> Action.NO_ADDRESS
            jid == ChatState.bare(self) -> Action.SELF
            isContact(jid) -> Action.MESSAGE
            else -> Action.ADD
        }
    }

    /** Under a row with no address. */
    const val NO_ADDRESS_HINT = "This room does not show their address"

    /** The header line: how many, and how many can be added. */
    fun summary(people: List<RoomOccupant>): String {
        val n = people.size
        return if (n == 1) "1 person in this room" else "$n people in this room"
    }
}
