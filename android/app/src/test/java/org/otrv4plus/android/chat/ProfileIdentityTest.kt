// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.otrv4plus.android.bridge.SecurityDetails
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState

class ProfileIdentityTest {

    private fun details(security: SecurityState, smp: SmpState = SmpState.NOT_VERIFIED,
                        peer: String? = "a1b2c3d4e5f6a7b8") = SecurityDetails(
        "bob@otrv4plus.i2p", security, smp, "", "00112233445566778899", peer, false)

    @Test fun groupsOfFourForReadingAloud() {
        assertEquals("A1B2 C3D4 E5F6", ProfileIdentity.group("a1:b2:c3:d4:e5:f6"))
    }

    @Test fun noSessionShowsNoKey() {
        val v = ProfileIdentity.of(details(SecurityState.PLAINTEXT, peer = null))
        assertEquals("", v.theirs)
        assertFalse(v.offerVerify)
        assertTrue(v.status.startsWith("No encrypted chat"))
    }

    @Test fun encryptedUnverifiedOffersVerify() {
        val v = ProfileIdentity.of(details(SecurityState.ENCRYPTED))
        assertTrue(v.offerVerify)
        assertEquals("A1B2 C3D4 E5F6 A7B8", v.theirs)
        assertEquals("0011 2233 4455 6677 8899", v.ours)
    }

    @Test fun verifiedSaysSoAndOffersNothing() {
        val v = ProfileIdentity.of(details(SecurityState.SMP_VERIFIED, SmpState.VERIFIED))
        assertTrue(v.status.startsWith("Verified"))
        assertFalse(v.offerVerify)
    }

    @Test fun aChangedKeyIsAnAlarmAndOffersVerify() {
        val v = ProfileIdentity.of(details(SecurityState.FINGERPRINT_MISMATCH))
        assertTrue(v.alarm)
        assertTrue(v.offerVerify)
        assertTrue(v.status.contains("changed"))
    }
}
