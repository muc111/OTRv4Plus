// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Owner, 2026-10-20: a username alone, like the phone; a full address as typed. */
class SignInFormTest {

    @Test
    fun aUsernameAloneIsOnTheShippedServer() {
        assertEquals("b@otrv4plus.i2p", SignInForm.account("b", ""))
        assertEquals("b@otrv4plus.i2p", SignInForm.account("  b  ", ""))
    }

    @Test
    fun aFullAddressIsUsedAsTyped() {
        assertEquals("b@otrv4plus.i2p", SignInForm.account("b@otrv4plus.i2p", ""))
        assertEquals("b@elsewhere.i2p", SignInForm.account("b@elsewhere.i2p", "otrv4plus.i2p"))
    }

    @Test
    fun aNamedRouteGivesItsDomainButADestinationDoesNot() {
        assertEquals("b@elsewhere.i2p", SignInForm.account("b", "elsewhere.i2p"))
        val b32 = "nquyxk5atgvp5yn3d4czvtb4qavysbxwjormmewhoyrdux5i4ika.b32.i2p"
        assertEquals("b@otrv4plus.i2p", SignInForm.account("b", b32))
    }

    @Test
    fun whatCannotBeAnAccountSaysWhy() {
        for (bad in listOf("", "b c", "@x.i2p", "b@", "a@b@c")) {
            assertNull(SignInForm.account(bad, ""), bad)
            assertNotNull(SignInForm.problem(bad), bad)
        }
    }
}
