// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The current password itself is checked by the engine (test_change_password.py). */
class PasswordChangeTest {

    private val current = "old-password"

    @Test fun aGoodChangeHasNoProblem() {
        assertNull(PasswordChange.problem(current, "new-password-1", "new-password-1"))
    }

    @Test fun theCurrentPasswordIsRequired() {
        assertEquals("Enter your current password.",
                     PasswordChange.problem("", "new-password-1", "new-password-1"))
    }

    @Test fun theNewOneMustBeLongEnoughDifferentAndTypedTwice() {
        assertTrue(PasswordChange.problem(current, "short", "short")!!.contains("at least 8"))
        assertTrue(PasswordChange.problem(current, current, current)!!.contains("same"))
        assertTrue(PasswordChange.problem(current, "new-password-1", "new-password-2")!!
                       .contains("do not match"))
    }

    @Test fun theResultSaysWhetherThisDeviceKeptIt() {
        assertTrue(PasswordChange.result(true, "", saved = true).startsWith("Password changed."))
        assertTrue(PasswordChange.result(true, "", saved = false).contains("could not save"))
        assertEquals("That is not your current password.",
                     PasswordChange.result(false, "That is not your current password.", false))
        assertEquals("The password was not changed.", PasswordChange.result(false, "", false))
    }
}
