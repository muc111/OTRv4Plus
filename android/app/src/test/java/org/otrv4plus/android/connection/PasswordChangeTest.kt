// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordChangeTest {

    private val stored = "old-password"

    @Test fun aGoodChangeHasNoProblem() {
        assertNull(PasswordChange.problem(stored, stored, "new-password-1", "new-password-1"))
    }

    @Test fun theCurrentPasswordIsRequiredAndChecked() {
        assertEquals("Enter your current password.",
                     PasswordChange.problem("", stored, "new-password-1", "new-password-1"))
        assertEquals("That is not your current password.",
                     PasswordChange.problem("guess", stored, "new-password-1", "new-password-1"))
    }

    @Test fun withoutAStoredPasswordTheEngineChecks() {
        assertNull(PasswordChange.problem("anything", null, "new-password-1", "new-password-1"))
        assertEquals("Enter your current password.",
                     PasswordChange.problem("", null, "new-password-1", "new-password-1"))
    }

    @Test fun theNewOneMustBeLongEnoughDifferentAndTypedTwice() {
        assertTrue(PasswordChange.problem(stored, stored, "short", "short")!!.contains("at least 8"))
        assertTrue(PasswordChange.problem(stored, stored, stored, stored)!!.contains("same"))
        assertTrue(PasswordChange.problem(stored, stored, "new-password-1", "new-password-2")!!
                       .contains("do not match"))
    }

    @Test fun theResultSaysWhetherThisDeviceKeptIt() {
        assertTrue(PasswordChange.result(true, "", saved = true).startsWith("Password changed."))
        assertTrue(PasswordChange.result(true, "", saved = false).contains("could not save"))
        assertEquals("The server refused.", PasswordChange.result(false, "The server refused.", false))
        assertEquals("The password was not changed.", PasswordChange.result(false, "", false))
    }
}
