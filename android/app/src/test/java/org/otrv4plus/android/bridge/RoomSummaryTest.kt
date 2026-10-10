// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class RoomSummaryTest {

    @Test
    fun `a group and a channel look different, and a password says so`() {
        val group = RoomSummary("lmao@conference.x.i2p", "", secure = true)
        val channel = RoomSummary("chat@conference.x.i2p", "Chat")
        val locked = RoomSummary("club@conference.x.i2p", "", password = true)
        assertNotEquals(group.kindIcon, channel.kindIcon)
        assertEquals("#", channel.kindIcon)
        assertEquals("Encrypted group", group.kindText)
        assertEquals("Channel", channel.kindText)
        assertEquals("Channel, password needed", locked.kindText)
        assertEquals("lmao", group.label)
    }
}
