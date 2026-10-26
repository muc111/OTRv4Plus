// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The creator's join-request prompt (owner, 2026-10-25). */
class EntryRequestTextTest {

    @Test fun `a request from history alerts too`() {
        assertEquals(Attention.Kind.ENTRY_REQUEST,
                     Attention.of(OtrEvent.GroupEntryRequested("g@rooms.x", "bob@x", false)))
        assertEquals(Attention.Kind.ENTRY_REQUEST,
                     Attention.of(OtrEvent.GroupEntryRequested("g@rooms.x", "bob@x", true)))
    }

    @Test fun `the wait reads in minutes hours and days`() {
        assertEquals("15 minutes", GroupText.waitText(900))
        assertEquals("30 minutes", GroupText.waitText(1800))
        assertEquals("1 hour", GroupText.waitText(3600))
        assertEquals("4 hours", GroupText.waitText(4 * 3600))
        assertEquals("2 days", GroupText.waitText(2 * 86400))
        assertEquals("Denied. bob@x cannot ask to join again for 15 minutes.",
                     GroupText.entryDenied("bob@x", 900))
    }

    @Test fun `the prompt says what deny does`() {
        assertTrue("15 minutes, then 30, then 60" in GroupText.ENTRY_REQUEST_NOTE)
        assertTrue("your encrypted group" in GroupText.entryRequest("bob@x", "g@rooms.x"))
        assertEquals("Only the group's creator answers requests to join.",
                     GroupText.outcome("only_the_creator_admits"))
    }
}
