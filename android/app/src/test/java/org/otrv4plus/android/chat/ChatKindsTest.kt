// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.chat.ChatKinds.Filter
import org.otrv4plus.android.chat.ChatKinds.Kind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The chat list's kinds, tints and filter chips (owner, 2026-10-23). */
class ChatKindsTest {

    @Test
    fun `each chat has one kind`() {
        assertEquals(Kind.PERSON, ChatKinds.kind(isRoom = false, isSecureRoom = false))
        assertEquals(Kind.GROUP, ChatKinds.kind(isRoom = true, isSecureRoom = true))
        assertEquals(Kind.PUBLIC, ChatKinds.kind(isRoom = true, isSecureRoom = false))
        // A group being set up is already a group.
        assertEquals(Kind.GROUP, ChatKinds.kind(isRoom = false, isSecureRoom = true))
    }

    @Test
    fun `three different colours, a 50 percent tint, and words as well`() {
        assertEquals(3, Kind.entries.map { it.hue }.toSet().size)
        assertEquals(0.5f, ChatKinds.TINT)
        assertTrue("not encrypted" in Kind.PUBLIC.label)
        assertNotEquals(Kind.GROUP.label, Kind.PERSON.label)
    }

    @Test
    fun `chips only when there is more than one kind, with counts`() {
        assertTrue(ChatKinds.chips(listOf(Kind.PERSON, Kind.PERSON)).isEmpty())
        val kinds = listOf(Kind.PERSON, Kind.GROUP, Kind.GROUP, Kind.PUBLIC)
        assertEquals(listOf(Filter.ALL, Filter.PEOPLE, Filter.GROUPS, Filter.PUBLIC), ChatKinds.chips(kinds))
        assertEquals(listOf(Filter.ALL, Filter.PEOPLE, Filter.PUBLIC),
                     ChatKinds.chips(listOf(Kind.PERSON, Kind.PUBLIC)))
        assertEquals("Groups (2)", ChatKinds.chipLabel(Filter.GROUPS, kinds))
        assertEquals("All", ChatKinds.chipLabel(Filter.ALL, kinds))
    }

    @Test
    fun `a filter admits only its kind`() {
        assertTrue(Filter.ALL.admits(Kind.PUBLIC))
        assertTrue(Filter.PEOPLE.admits(Kind.PERSON) && !Filter.PEOPLE.admits(Kind.GROUP))
        assertTrue(Filter.PUBLIC.admits(Kind.PUBLIC) && !Filter.PUBLIC.admits(Kind.GROUP))
    }
}
