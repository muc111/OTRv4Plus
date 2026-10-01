// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrBridgeException
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.crypto.Verification
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device report: starting SMP after ordinary chat put a blank message from
 * the contact into the conversation on both phones. The SMP data message has
 * empty text; the bridge now drops it, and this side refuses to store one too.
 */
class SmpCarrierTest {

    private val bob = "bob@otrv4plus.i2p"

    private fun state() = ChatState().also {
        it.bindAccount(AccountScope.of("owner@otrv4plus.i2p"))
        it.applyConnection(ConnectionStatus(stage = "connected", connected = true))
    }

    @Test
    fun `a blank inbound body is never stored or announced`() {
        val s = state()
        s.handle(OtrEvent.MessageReceived(peer = bob, body = "hello", timestamp = 1.0))
        for (blank in listOf("", " ", "\n")) {
            assertFalse(s.handle(OtrEvent.MessageReceived(peer = bob, body = blank, timestamp = 2.0)))
        }
        assertEquals(listOf("hello"), s.messages(bob).map { it.body })
    }

    @Test
    fun `a blank carrier does not bring back a deleted conversation`() {
        val s = state()
        s.handle(OtrEvent.MessageReceived(peer = bob, body = "hello", timestamp = 1.0))
        s.deleteConversation(bob)
        s.handle(OtrEvent.MessageReceived(peer = bob, body = "", timestamp = 2.0))
        assertTrue(s.messages(bob).isEmpty())
        assertTrue(s.conversations().none { it.jid == bob })
    }

    @Test
    fun `an SMP refusal says why`() {
        val s = state()
        s.handle(OtrEvent.Failed(bob, "smp_cooldown"))
        assertTrue(s.notice!!.contains("30 seconds"), s.notice)
        s.dismissNotice()
        s.handle(OtrEvent.Failed(bob, "decrypt_failed"))
        assertNull(s.notice, "unrelated failures are not reworded here")
    }

    @Test
    fun `the bridge code is read from a BridgeError and nothing else`() {
        assertEquals("smp_cooldown",
            OtrBridgeException.codeFromMessage("android_bridge.app.BridgeError: smp_cooldown"))
        assertEquals("smp_cooldown",
            OtrBridgeException.codeFromMessage("BridgeError: smp_cooldown\n  traceback..."))
        assertNull(OtrBridgeException.codeFromMessage("RuntimeError: secret hunter2 rejected"))
        assertNull(OtrBridgeException.codeFromMessage("BridgeError: Has Spaces and text"))
        assertNull(OtrBridgeException.codeFromMessage(null))
        for (code in listOf("smp_cooldown", "smp_attempts_exhausted",
                            "smp_already_verified", "smp_in_progress")) {
            assertTrue(Verification.refusal(code) != null, code)
        }
        assertNull(Verification.refusal("smp_start_failed"))
    }
}
