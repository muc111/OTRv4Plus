// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.chat.RowSecurity
import org.otrv4plus.android.crypto.SecurityLevel.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The three-level model, driven over every engine state. */
class SecurityLevelTest {

    @Test
    fun `only an smp verified session is verified`() {
        for (state in SecurityState.entries) {
            val verified = SecurityLevel.of(state) == Level.VERIFIED
            assertEquals(state == SecurityState.SMP_VERIFIED, verified,
                "$state is described as verified")
        }
    }

    @Test
    fun `a pinned key is not verification`() {
        assertEquals(Level.ENCRYPTED_UNVERIFIED, SecurityLevel.of(SecurityState.FINGERPRINT))
    }

    @Test
    fun `plaintext does not encrypt and neither does a changed key`() {
        assertFalse(SecurityLevel.encrypts(SecurityLevel.of(SecurityState.PLAINTEXT)))
        assertFalse(SecurityLevel.encrypts(Level.KEY_CHANGED))
        assertTrue(SecurityLevel.encrypts(Level.ENCRYPTED_UNVERIFIED))
        assertTrue(SecurityLevel.encrypts(Level.VERIFIED))
    }

    @Test
    fun `calls files and media are offered at the verified level only`() {
        for (level in Level.entries) {
            assertEquals(level == Level.VERIFIED, SecurityLevel.offersGatedFeatures(level))
        }
    }

    @Test
    fun `the levels are distinguishable without colour`() {
        // Distinct shapes AND distinct words: either alone tells them apart.
        assertEquals(Level.entries.size, Level.entries.map { it.mark }.toSet().size)
        assertEquals(Level.entries.size, Level.entries.map { it.label }.toSet().size)
    }

    @Test
    fun `there is exactly one tick`() {
        assertEquals(listOf(Level.VERIFIED), Level.entries.filter { "✓" in it.mark })
    }

    @Test
    fun `the conversation list says the same thing as this model`() {
        for (state in SecurityState.entries) {
            val badge = RowSecurity.badge(state, SmpState.NOT_VERIFIED, hasHistory = true)
                ?: continue
            assertEquals(SecurityLevel.of(state).label, badge.text,
                "the list and the model disagree about $state")
            assertEquals(SecurityLevel.of(state).mark, badge.mark)
        }
    }
}
