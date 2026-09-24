// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.SecurityState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the call controls may offer, driven rather than read.
 *
 * The two rules that matter are at the top: a call is never offered to an
 * unverified peer, and no phase reads as a working call until the engine
 * says the keys were confirmed. Everything else here exists so those two
 * cannot be weakened by accident.
 */
class CallUiTest {

    private fun offer(
        security: SecurityState,
        reason: String = "",
    ) = CallUi.offer(security, reason)

    // ── the gate, as an affordance ──────────────────────────────────────────

    @Test
    fun `only a verified conversation is offered a call`() {
        assertEquals(CallUi.Offer.Available, offer(SecurityState.SMP_VERIFIED))
        for (state in SecurityState.entries - SecurityState.SMP_VERIFIED) {
            assertTrue(offer(state) !is CallUi.Offer.Available,
                "$state was offered a call without a verified identity")
        }
    }

    @Test
    fun `encryption without verification says what to do instead`() {
        for (state in listOf(SecurityState.ENCRYPTED,
                             SecurityState.FINGERPRINT)) {
            assertEquals(CallUi.Offer.NeedsVerification, offer(state),
                "$state should send the user to verify, not hide the control")
        }
    }

    @Test
    fun `a changed key does not invite the user to verify`() {
        // Offering "verify first" here would invite SMP against whoever
        // holds the new key, which is exactly the wrong next step.
        assertEquals(CallUi.Offer.NeedsEncryption,
            offer(SecurityState.FINGERPRINT_MISMATCH))
    }

    @Test
    fun `a device with no audio says so before mentioning verification`() {
        // Telling a user to verify when the phone cannot do voice sends them
        // to do something that will not help.
        val result = offer(SecurityState.ENCRYPTED, "no audio backend")
        assertTrue(result is CallUi.Offer.Unavailable)
        assertEquals("no audio backend",
            (result as CallUi.Offer.Unavailable).reason)
    }

    @Test
    fun `an unavailable device is not offered a call even when verified`() {
        assertTrue(offer(SecurityState.SMP_VERIFIED, "libopus missing")
                       is CallUi.Offer.Unavailable)
    }

    @Test
    fun `every security state has an answer`() {
        for (state in SecurityState.entries) {
            CallUi.offer(state, "")
            CallUi.offer(state, "some reason")
        }
    }

    // ── nothing claims a call is up before the engine says so ───────────────

    @Test
    fun `only ACTIVE reads as connected`() {
        assertTrue(CallUi.phase(CallState.ACTIVE).connected)
        for (state in CallState.entries - CallState.ACTIVE) {
            assertFalse(CallUi.phase(state).connected,
                "$state rendered as a connected call")
        }
    }

    @Test
    fun `key confirmation is not yet a call`() {
        val phase = CallUi.phase(CallState.KEY_CONFIRMING)
        assertFalse(phase.connected)
        assertFalse(phase.showsDuration,
            "a duration was shown before the keys were confirmed")
    }

    @Test
    fun `only ACTIVE shows a duration`() {
        for (state in CallState.entries - CallState.ACTIVE) {
            assertFalse(CallUi.phase(state).showsDuration,
                "$state showed a call duration")
        }
        assertTrue(CallUi.phase(CallState.ACTIVE).showsDuration)
    }

    @Test
    fun `the long wait says what is happening`() {
        // 30-120 s of tunnel building with a bare spinner reads as stuck.
        assertTrue(CallUi.phase(CallState.INVITING).label.isNotBlank())
        assertTrue("minute" in CallUi.phase(CallState.INVITING).label)
    }

    // ── answering belongs to the side that did not call ─────────────────────

    @Test
    fun `an incoming call may be answered`() {
        val phase = CallUi.phase(CallState.RINGING, CallUi.Direction.INCOMING)
        assertTrue(phase.canAnswer)
        assertTrue(phase.canEnd, "a ringing call must be rejectable")
        assertEquals("Incoming call", phase.label)
    }

    @Test
    fun `an outgoing call is never answerable by the caller`() {
        val phase = CallUi.phase(CallState.RINGING, CallUi.Direction.OUTGOING)
        assertFalse(phase.canAnswer,
            "the caller was offered a button to answer their own call")
        assertEquals("Ringing", phase.label)
    }

    @Test
    fun `nothing but a ringing call may be answered`() {
        for (state in CallState.entries - CallState.RINGING) {
            assertFalse(CallUi.phase(state, CallUi.Direction.INCOMING).canAnswer,
                "$state offered an Answer button")
        }
    }

    @Test
    fun `a live call can always be ended`() {
        for (state in listOf(CallState.INVITING, CallState.RINGING,
                             CallState.CONNECTING, CallState.KEY_CONFIRMING,
                             CallState.MEDIA_CONNECTING, CallState.ACTIVE)) {
            assertTrue(CallUi.phase(state).canEnd,
                "$state could not be ended; the user would be stuck in it")
        }
    }

    @Test
    fun `a finished call offers nothing to end`() {
        for (state in listOf(CallState.IDLE, CallState.ENDED,
                             CallState.ENDING)) {
            assertFalse(CallUi.phase(state).canEnd)
        }
    }

    @Test
    fun `idle shows no call screen at all`() {
        assertFalse(CallUi.phase(CallState.IDLE).active)
        assertEquals("", CallUi.phase(CallState.IDLE).label)
    }

    @Test
    fun `every state and direction has an answer`() {
        for (state in CallState.entries) {
            for (direction in CallUi.Direction.entries) {
                val phase = CallUi.phase(state, direction)
                if (phase.active) {
                    assertTrue(phase.label.isNotBlank(),
                        "$state/$direction shows a screen with no label")
                }
            }
        }
    }

    // ── the small things ────────────────────────────────────────────────────

    @Test
    fun `elapsed reads as a person would say it`() {
        assertEquals("0s", CallUi.elapsed(0))
        assertEquals("59s", CallUi.elapsed(59))
        assertEquals("1:00", CallUi.elapsed(60))
        assertEquals("1:05", CallUi.elapsed(65))
        assertEquals("10:00", CallUi.elapsed(600))
    }

    @Test
    fun `a negative elapsed is not rendered as one`() {
        assertEquals("0s", CallUi.elapsed(-5))
    }

    @Test
    fun `a started call needs nothing said about it`() {
        assertNull(CallUi.refusal("started"))
    }

    @Test
    fun `every refusal code says something`() {
        for (code in org.otrv4plus.android.bridge.CallOutcome.ALL) {
            if (code == "started") continue
            assertTrue(CallUi.refusal(code)?.isNotBlank() == true,
                "$code produced no explanation")
        }
    }

    @Test
    fun `an unknown outcome is still explained`() {
        // A code this build has not been taught is still a refusal. Silence
        // would leave a button that did nothing and said nothing.
        assertTrue(CallUi.refusal("something_new")?.isNotBlank() == true)
    }
}
