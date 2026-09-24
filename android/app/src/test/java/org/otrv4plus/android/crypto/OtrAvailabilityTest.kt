// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.crypto.CallUi.Gate
import org.otrv4plus.android.crypto.OtrAvailability as A
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** OTRv4Plus capability on screen: separate from, and never louder than, security. */
class OtrAvailabilityTest {

    private val bob = "bob@x.i2p"

    @Test
    fun `only a confirmed capability may start OTRv4+`() {
        assertTrue(A.mayStart(A.AVAILABLE))
        for (s in listOf(A.UNKNOWN, A.OFFLINE, A.CHECKING, A.UNAVAILABLE, "garbage"))
            assertFalse(A.mayStart(s), s)
    }

    @Test
    fun `every plaintext line says it is not encrypted and none is a padlock`() {
        for (s in listOf(A.UNKNOWN, A.OFFLINE, A.CHECKING, A.AVAILABLE, A.UNAVAILABLE)) {
            val line = A.plaintextLine(s)
            assertFalse("🔒" in line || "🔐" in line, s)
            if (s != A.AVAILABLE) assertTrue("ot encrypted" in line || "NOT encrypted" in line, "$s: $line")
        }
        assertTrue("establishing secure OTRv4+ session" in A.plaintextLine(A.AVAILABLE))
        assertTrue(A.plaintextLine(A.UNAVAILABLE).startsWith("OTRv4Plus unavailable"))
    }

    @Test
    fun `an incapable contact gets no Start button and a reason`() {
        assertNotNull(A.noStartReason(A.UNAVAILABLE))
        assertTrue("no fallback" in A.noStartReason(A.UNAVAILABLE)!!)
        assertNull(A.noStartReason(A.AVAILABLE))
    }

    @Test
    fun `the call gate says the client does not support OTRv4Plus`() {
        assertEquals(Gate.OTRV4PLUS_UNAVAILABLE,
            CallUi.localGate(true, false, SecurityState.PLAINTEXT, "", A.UNAVAILABLE))
        assertEquals(Gate.NO_SESSION,
            CallUi.localGate(true, false, SecurityState.PLAINTEXT, "", A.AVAILABLE))
        assertFalse(CallUi.control(Gate.OTRV4PLUS_UNAVAILABLE).enabled)
        assertEquals(Gate.OTRV4PLUS_UNAVAILABLE, Gate.of("otrv4plus_unavailable"))
    }

    @Test
    fun `capability arrives by event, is per account, and is not security`() {
        val s = ChatState().apply {
            bindAccount(AccountScope.of("me@x.i2p"))
            applyConnection(ConnectionStatus(stage = "connected", connected = true))
        }
        assertFalse(s.handle(OtrEvent.CapabilityChanged("Bob@X.i2p/phone", A.AVAILABLE)),
            "a capability change buzzed the phone")
        assertEquals(A.AVAILABLE, s.conversation(bob).otrCapability)
        assertEquals(SecurityState.PLAINTEXT, s.conversation(bob).security,
            "capability was taken as encryption")
        s.bindAccount(AccountScope.of("other@x.i2p"))
        assertEquals(A.UNKNOWN, s.capabilityOf(bob))
    }
}
