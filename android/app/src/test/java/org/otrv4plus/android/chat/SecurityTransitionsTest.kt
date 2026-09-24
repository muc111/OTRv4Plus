// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpProgress
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.CallUi.Gate
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.Verification
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Every transition the brief lists, in order, for a peer who is NOT on the
 * roster -- the case the old screen got wrong -- and for one who is:
 * offline, online, OTR connecting, OTR encrypted, fingerprint trusted, SMP
 * running, SMP verified, SMP failed, SMP cancelled, session ended, key
 * changed. A stale "verified" must never survive invalidation, and the call
 * and file controls follow the session, not the roster.
 */
class SecurityTransitionsTest {

    private val termux = "termux@xmpp-elite.i2p"

    private fun state(): ChatState = ChatState().apply {
        applyConnection(ConnectionStatus(stage = "connected", connected = true))
    }

    private fun session(s: ChatState, level: SecurityState) =
        s.handle(OtrEvent.SessionChanged(termux, level))

    private fun smp(s: ChatState, st: SmpState) =
        s.handle(OtrEvent.SmpFinished(termux, st))

    private fun view(s: ChatState) = s.conversation(termux)

    /** The local gate the screen falls back to, with voice available. */
    private fun gate(s: ChatState) =
        CallUi.localGate(s.canSend(), s.isRoom(termux), view(s).security, "")

    @Test
    fun `a peer not on the roster follows the engine's events`() {
        val s = state()
        assertEquals(SecurityState.PLAINTEXT, view(s).security)
        assertEquals(Gate.NO_SESSION, gate(s))

        session(s, SecurityState.ENCRYPTED)                  // OTR encrypted
        assertEquals(SecurityState.ENCRYPTED, view(s).security,
            "the session event was dropped; a non-roster peer stayed plaintext")
        assertEquals(Gate.NOT_VERIFIED, gate(s))
        assertTrue(TransferUi.offer(view(s).security) is TransferUi.Offer.NeedsVerification)

        session(s, SecurityState.FINGERPRINT)                // fingerprint trusted
        assertEquals(Gate.NOT_VERIFIED, gate(s), "a pin is not a verification")

        s.handle(OtrEvent.SmpProgressed(termux, SmpProgress(1, 4, SmpState.IN_PROGRESS)))
        assertEquals(SmpState.IN_PROGRESS, view(s).smp)       // SMP running
        assertEquals(Gate.NOT_VERIFIED, gate(s))

        session(s, SecurityState.SMP_VERIFIED)               // SMP verified
        smp(s, SmpState.VERIFIED)
        assertEquals(SmpState.VERIFIED, view(s).smp)
        assertEquals(Gate.AVAILABLE, gate(s))
        assertTrue(CallUi.control(gate(s)).enabled)
        assertEquals(TransferUi.Offer.Available, TransferUi.offer(view(s).security))
        assertTrue(Verification.callOffered(view(s).security, view(s).smp))
    }

    @Test
    fun `the session ending drops the verification`() {
        val s = state()
        session(s, SecurityState.SMP_VERIFIED); smp(s, SmpState.VERIFIED)
        session(s, SecurityState.PLAINTEXT)                  // session ended
        assertEquals(SmpState.NOT_VERIFIED, view(s).smp, "a stale VERIFIED survived")
        assertEquals(Gate.NO_SESSION, gate(s))
        assertFalse(Verification.callOffered(view(s).security, view(s).smp))
        // And a fresh DAKE starts unverified.
        session(s, SecurityState.ENCRYPTED)
        assertEquals(SmpState.NOT_VERIFIED, view(s).smp)
        assertEquals(Gate.NOT_VERIFIED, gate(s))
    }

    @Test
    fun `a replaced session drops the verification`() {
        val s = state()
        session(s, SecurityState.SMP_VERIFIED); smp(s, SmpState.VERIFIED)
        session(s, SecurityState.ENCRYPTED)                  // re-keyed, new session
        assertEquals(SmpState.NOT_VERIFIED, view(s).smp)
        assertEquals(Gate.NOT_VERIFIED, gate(s))
    }

    @Test
    fun `a changed key drops the verification and closes every gated control`() {
        val s = state()
        session(s, SecurityState.SMP_VERIFIED); smp(s, SmpState.VERIFIED)
        s.handle(OtrEvent.FingerprintChanged(termux, "old", "new"))  // key changed
        assertEquals(SecurityState.FINGERPRINT_MISMATCH, view(s).security)
        assertEquals(SmpState.NOT_VERIFIED, view(s).smp)
        assertEquals(Gate.FINGERPRINT_CHANGED, gate(s))
        assertTrue(TransferUi.offer(view(s).security) is TransferUi.Offer.NeedsEncryption)
    }

    @Test
    fun `failed and cancelled are shown as themselves and unlock nothing`() {
        val s = state()
        session(s, SecurityState.ENCRYPTED)
        smp(s, SmpState.FAILED)
        assertEquals(SmpState.FAILED, view(s).smp)
        assertEquals(Gate.NOT_VERIFIED, gate(s))
        smp(s, SmpState.CANCELLED)
        assertEquals(SmpState.CANCELLED, view(s).smp)
        assertEquals(Gate.NOT_VERIFIED, gate(s))
    }

    @Test
    fun `offline and disconnected say so, and online alone unlocks nothing`() {
        val s = ChatState()
        assertEquals(Gate.NOT_CONNECTED, gate(s))
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        s.applyRoster(listOf(Contact(termux, "T", PeerPresence.ONLINE,
            SecurityState.PLAINTEXT, SmpState.NOT_VERIFIED, false)))
        assertEquals(Gate.NO_SESSION, gate(s), "being online was taken as a session")
    }

    @Test
    fun `a roster poll cannot end a verification it has not caught up with, but can end a session`() {
        val s = state()
        session(s, SecurityState.SMP_VERIFIED); smp(s, SmpState.VERIFIED)
        fun poll(level: SecurityState) = s.applyRoster(listOf(Contact(termux, "T",
            PeerPresence.ONLINE, level, SmpState.NOT_VERIFIED, false)))
        poll(SecurityState.ENCRYPTED)                         // taken before the SMP finished
        assertEquals(SmpState.VERIFIED, view(s).smp)
        assertEquals(Gate.AVAILABLE, gate(s))
        poll(SecurityState.PLAINTEXT)                         // the session really ended
        assertEquals(SmpState.NOT_VERIFIED, view(s).smp)
        assertEquals(Gate.NO_SESSION, gate(s))
    }

    @Test
    fun `every gate has a deterministic control and only AVAILABLE is enabled`() {
        for (g in Gate.entries) {
            val c = CallUi.control(g, "why")
            assertEquals(g == Gate.AVAILABLE, c.enabled, "$g")
            if (g != Gate.ROOM) assertTrue(c.visible && c.label.isNotBlank(), "$g hid itself")
        }
        assertEquals(Gate.UNKNOWN, Gate.of("something new"))
        for (code in listOf("available", "wiped", "room", "not_connected", "no_session",
                            "fingerprint_changed", "not_verified", "voice_unavailable"))
            assertEquals(code, Gate.of(code).code)
    }

    @Test
    fun `a voice-less device is never available`() {
        val s = state()
        session(s, SecurityState.SMP_VERIFIED)
        assertEquals(Gate.VOICE_UNAVAILABLE,
            CallUi.localGate(true, false, view(s).security, "no audio"))
    }
}
