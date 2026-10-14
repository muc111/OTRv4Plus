// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import org.otrv4plus.android.chat.SoundPolicy.Sound

class SoundPolicyTest {

    @Test
    fun `in the background a message notifies`() {
        assertEquals(Sound.NOTIFICATION, SoundPolicy.forMessage(false, null, "bob@x.i2p"))
        assertEquals(Sound.NOTIFICATION, SoundPolicy.forMessage(false, "bob@x.i2p", "bob@x.i2p"))
    }

    @Test
    fun `on screen in another conversation a message plays a tone`() {
        assertEquals(Sound.IN_APP_TONE, SoundPolicy.forMessage(true, "carol@x.i2p", "bob@x.i2p"))
        assertEquals(Sound.IN_APP_TONE, SoundPolicy.forMessage(true, null, "bob@x.i2p"))
    }

    @Test
    fun `the conversation you are reading makes no sound`() {
        assertEquals(Sound.NONE, SoundPolicy.forMessage(true, "bob@x.i2p", "Bob@x.i2p/phone"))
    }

    @Test
    fun `a 1to1 call rings until answered and a group call rings once`() {
        assertEquals(Sound.RING_REPEATING, SoundPolicy.forCall(group = false))
        assertEquals(Sound.RING_ONCE, SoundPolicy.forCall(group = true))
    }
}
