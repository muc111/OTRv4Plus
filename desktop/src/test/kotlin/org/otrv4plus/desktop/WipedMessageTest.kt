// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import org.otrv4plus.android.bridge.WipeReport
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The WIPED screen never says "Wiped." for a wipe that did not verify. */
class WipedMessageTest {

    @Test
    fun aVerifiedWipeSaysWipedAndWhetherItWasCryptoErase() {
        val erased = wipedMessage(WipeReport(verified = true, cryptoErased = true, keyStore = "secret-service"))
        assertTrue(erased.startsWith("Wiped.") && "secret-service" in erased)
        val plain = wipedMessage(WipeReport(verified = true))
        assertTrue(plain.startsWith("Wiped.") && "overwrite only" in plain)
    }

    @Test
    fun survivorsAreCountedAndNotCalledWiped() {
        val text = wipedMessage(WipeReport(verified = false, survivors = 3))
        assertFalse(text.startsWith("Wiped"))
        assertTrue("3 item(s)" in text)
    }

    @Test
    fun anUnlinkOnlyFileIsNotAWipe() {
        val text = wipedMessage(WipeReport(verified = false, filesUnlinkedOnly = 2))
        assertTrue("could only be deleted" in text)
    }

    @Test
    fun anUnreachableEngineIsNotAWipe() {
        val text = wipedMessage(WipeReport.UNREACHABLE)
        assertTrue("could not be confirmed" in text && "core_unreachable" in text)
        assertFalse(WipeReport.UNREACHABLE.ok)
    }

    @Test
    fun aReportWithoutVerificationIsNotOk() {
        // The engine's report must say it verified; absent means it did not.
        assertFalse(WipeReport().ok)
        assertTrue(WipeReport(verified = true).ok)
    }
}
