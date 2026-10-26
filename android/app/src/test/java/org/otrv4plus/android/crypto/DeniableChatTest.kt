// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeniableChatTest {

    @Test fun `offered only once a session is established`() {
        assertTrue(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.SMP_VERIFIED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.FINGERPRINT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.PLAINTEXT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.FINGERPRINT_MISMATCH, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = true))
    }

    @Test fun `the words describe the mechanism and claim nothing more`() {
        val all = listOf(DeniableChat.ACTION, DeniableChat.TITLE, DeniableChat.BODY,
                         DeniableChat.outcome("made_deniable"), DeniableChat.outcome("no_session"))
        assertTrue(all.none { "deniable messaging" in it.lowercase() })
        assertTrue("not been independently reviewed" in DeniableChat.BODY)
        assertTrue("stay encrypted" in DeniableChat.BODY)
    }
}
