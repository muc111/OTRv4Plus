// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals

/** U1: the signed-out navigation rules. Mirrors MainActivity's screens. */
class AuthGateTest {

    private enum class S { CONNECT, CONVERSATIONS, CONVERSATION, ROOMS, PEOPLE, ABOUT, DIAGNOSTICS, PROFILE }
    private val public = setOf(S.CONNECT, S.ABOUT, S.DIAGNOSTICS)

    @Test fun `U1-T1 back from About while signed out is sign-in`() {
        assertEquals(S.CONNECT, AuthGate.back(signedIn = false, home = S.CONVERSATIONS, login = S.CONNECT))
        assertEquals(S.CONVERSATIONS, AuthGate.back(signedIn = true, home = S.CONVERSATIONS, login = S.CONNECT))
    }

    @Test fun `U1-T2 no signed-in screen can be shown while signed out`() {
        for (s in S.entries) {
            val shown = AuthGate.shown(s, signedIn = false, public = public, login = S.CONNECT)
            if (s in public) assertEquals(s, shown) else assertEquals(S.CONNECT, shown, "$s while signed out")
        }
    }

    @Test fun `U1-T5 signed in everything is reachable`() {
        for (s in S.entries) assertEquals(s, AuthGate.shown(s, signedIn = true, public = public, login = S.CONNECT))
    }
}
