// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The verification control, and the one rule underneath all of it:
 *
 *     OTR encrypted  !=  identity verified
 *     SMP verified    =  identity verified
 *
 * No cryptography is tested here and none is performed here — the proof is
 * `Rust/src/smp.rs` and is covered by `tests/test_smp_end_to_end.py` and
 * `tests/test_rust_security.py`. What is tested is the decision table the UI
 * reads, which is the part that can quietly start claiming a peer is verified.
 */
class VerificationTest {

    // ── the button appears only over an encrypted session ────────────────────

    @Test
    fun `nothing is offered before OTR is established`() {
        assertEquals(
            Verification.Offer.HIDDEN,
            Verification.offer(SecurityState.PLAINTEXT, SmpState.NOT_VERIFIED))
    }

    @Test
    fun `the button appears once the session is encrypted`() {
        assertEquals(
            Verification.Offer.VERIFY,
            Verification.offer(SecurityState.ENCRYPTED, SmpState.NOT_VERIFIED))
    }

    @Test
    fun `a pinned fingerprint is still only encrypted, not verified`() {
        // TOFU pins a key; it does not check who holds it. Offering "Verified"
        // here would be the exact conflation this project refuses.
        assertEquals(
            Verification.Offer.VERIFY,
            Verification.offer(SecurityState.FINGERPRINT, SmpState.NOT_VERIFIED))
    }

    @Test
    fun `smp cannot run without an encrypted session`() {
        assertFalse(Verification.available(SecurityState.PLAINTEXT))
    }

    @Test
    fun `a fingerprint mismatch may still be verified`() {
        // That conversation IS encrypted, to somebody. SMP is one of the few
        // things that can say which somebody, so the remedy stays available at
        // the moment it matters most.
        assertTrue(Verification.available(SecurityState.FINGERPRINT_MISMATCH))
        assertEquals(
            Verification.Offer.VERIFY,
            Verification.offer(SecurityState.FINGERPRINT_MISMATCH,
                               SmpState.NOT_VERIFIED))
    }

    // ── success changes the control ──────────────────────────────────────────

    @Test
    fun `a successful run replaces the button with the verified state`() {
        assertEquals(
            Verification.Offer.VERIFIED,
            Verification.offer(SecurityState.ENCRYPTED, SmpState.VERIFIED))
    }

    @Test
    fun `the security level alone is enough to read as verified`() {
        // After an auto-SMP the Rust object is destroyed and its phase moves
        // on, but the level is SMP_VERIFIED. Reading only the phase would put
        // the button back on a conversation that is verified.
        assertEquals(
            Verification.Offer.VERIFIED,
            Verification.offer(SecurityState.SMP_VERIFIED,
                               SmpState.NOT_VERIFIED))
    }

    // ── a run in flight, and an incoming request ─────────────────────────────

    @Test
    fun `a run in flight shows progress rather than another button`() {
        assertEquals(
            Verification.Offer.IN_PROGRESS,
            Verification.offer(SecurityState.ENCRYPTED, SmpState.IN_PROGRESS))
    }

    @Test
    fun `a held request shows that we are answering it`() {
        assertEquals(
            Verification.Offer.ANSWERING,
            Verification.offer(SecurityState.ENCRYPTED,
                               SmpState.SECRET_REQUIRED))
    }

    @Test
    fun `an incoming request opens a prompt with no button pressed`() {
        // THE RECEIVING REQUIREMENT. Bob is prompted because the engine holds
        // Alice's SMP1, not because Bob tapped anything.
        assertEquals(
            Verification.Prompt.INCOMING,
            Verification.prompt(SecurityState.ENCRYPTED,
                                secretRequired = true, requested = false))
    }

    @Test
    fun `tapping verify opens the outgoing prompt`() {
        assertEquals(
            Verification.Prompt.OUTGOING,
            Verification.prompt(SecurityState.ENCRYPTED,
                                secretRequired = false, requested = true))
    }

    @Test
    fun `no prompt opens on its own`() {
        assertNull(
            Verification.prompt(SecurityState.ENCRYPTED,
                                secretRequired = false, requested = false))
    }

    @Test
    fun `an incoming request wins over a simultaneous tap`() {
        // Both true means their SMP1 is already held in the core. Answering it
        // is `smpRespond`, which resumes the held message; `smpStart` would
        // begin a second, competing run.
        assertEquals(
            Verification.Prompt.INCOMING,
            Verification.prompt(SecurityState.ENCRYPTED,
                                secretRequired = true, requested = true))
    }

    @Test
    fun `no prompt opens on a conversation that is not encrypted`() {
        // A peer must not be able to raise a passphrase dialog on a
        // conversation where no session exists to verify.
        assertNull(
            Verification.prompt(SecurityState.PLAINTEXT,
                                secretRequired = true, requested = true))
    }

    // ── either side may initiate ─────────────────────────────────────────────

    @Test
    fun `both sides see the same offer in the same state`() {
        // Symmetry is the requirement: Alice initiating and Bob initiating are
        // the same decision, because nothing here knows which side it is on.
        for (security in listOf(SecurityState.ENCRYPTED,
                                SecurityState.FINGERPRINT)) {
            assertEquals(Verification.Offer.VERIFY,
                         Verification.offer(security, SmpState.NOT_VERIFIED))
        }
    }

    // ── the passphrase bound the engine actually enforces ────────────────────

    @Test
    fun `a short passphrase is refused`() {
        assertFalse(Verification.acceptable("short"))
        assertFalse(Verification.acceptable(""))
        assertFalse(Verification.acceptable("1234567"))
    }

    @Test
    fun `the minimum matches the engine`() {
        // EnhancedOTRSession.set_smp_secret raises below 8. A dialog that
        // accepted 7 would send the user into a round trip to be refused.
        assertEquals(8, Verification.MIN_SECRET)
        assertTrue(Verification.acceptable("12345678"))
    }

    @Test
    fun `an over-long passphrase is refused`() {
        assertEquals(512, Verification.MAX_SECRET)
        assertFalse(Verification.acceptable("x".repeat(513)))
        assertTrue(Verification.acceptable("x".repeat(512)))
    }

    @Test
    fun `a passphrase of spaces is still a passphrase`() {
        // Not trimmed. A space is a character in a shared secret, and
        // silently trimming would make a correct passphrase fail on one side.
        assertTrue(Verification.acceptable("        "))
    }

    // ── what the user is told ────────────────────────────────────────────────

    @Test
    fun `both prompts name the out-of-band agreement`() {
        // A passphrase invented on the spot verifies nothing. The security of
        // SMP is entirely in the secret having been agreed over a channel an
        // attacker does not control, so both prompts have to say so.
        for (prompt in Verification.Prompt.entries) {
            val text = Verification.explanation(prompt, "bob@example.i2p")
            assertTrue(text.contains("agreed"), "$prompt does not say agreed")
            assertTrue(text.contains("another channel"),
                       "$prompt does not name an out-of-band channel")
        }
    }

    @Test
    fun `the incoming prompt names who is asking`() {
        val text = Verification.explanation(
            Verification.Prompt.INCOMING, "bob@example.i2p")
        assertTrue(text.contains("bob@example.i2p"))
    }

    @Test
    fun `a failure says the passphrases did not match and what that may mean`() {
        val text = Verification.outcome(SmpState.FAILED)
        assertNotNull(text)
        assertTrue(text.contains("did not match"))
        assertTrue(text.contains("may not be who you think"))
    }

    @Test
    fun `a cancellation says nothing about the contact`() {
        // The distinction that makes CANCELLED worth having. Showing a cancel
        // as a failure would tell a user their peer may be an impostor because
        // somebody closed a dialog.
        val text = Verification.outcome(SmpState.CANCELLED)
        assertNotNull(text)
        assertFalse(text.contains("did not match"))
        assertTrue(text.contains("says nothing about your contact"))
    }

    @Test
    fun `an in-flight state has no outcome to report`() {
        assertNull(Verification.outcome(SmpState.IN_PROGRESS))
        assertNull(Verification.outcome(SmpState.SECRET_REQUIRED))
        assertNull(Verification.outcome(SmpState.NOT_VERIFIED))
    }

    // ── voice stays gated ────────────────────────────────────────────────────

    @Test
    fun `a call is not offered on an encrypted but unverified session`() {
        // The existing rule, restated rather than relaxed. The real gate is
        // VoiceCallManager._smp_verified in the engine; this only decides
        // whether a button is drawn, and it draws nothing here.
        assertFalse(Verification.callOffered(SecurityState.ENCRYPTED,
                                             SmpState.NOT_VERIFIED))
        assertFalse(Verification.callOffered(SecurityState.FINGERPRINT,
                                             SmpState.NOT_VERIFIED))
        assertFalse(Verification.callOffered(SecurityState.ENCRYPTED,
                                             SmpState.IN_PROGRESS))
    }

    @Test
    fun `a call is offered once SMP has passed`() {
        assertTrue(Verification.callOffered(SecurityState.SMP_VERIFIED,
                                            SmpState.VERIFIED))
    }

    @Test
    fun `a failed or cancelled run does not unlock a call`() {
        assertFalse(Verification.callOffered(SecurityState.ENCRYPTED,
                                             SmpState.FAILED))
        assertFalse(Verification.callOffered(SecurityState.ENCRYPTED,
                                             SmpState.CANCELLED))
    }

    // ── the enum fails safe ──────────────────────────────────────────────────

    @Test
    fun `an unknown state name is never verified`() {
        // A state this build has not been taught must not render as a
        // confirmed identity. NOT_VERIFIED is the safe direction.
        for (bogus in listOf("MADE_UP", "", "verified_maybe", "SMP_VERIFIED")) {
            assertEquals(SmpState.NOT_VERIFIED, SmpState.fromName(bogus))
        }
    }

    @Test
    fun `every state name round-trips`() {
        for (state in SmpState.entries) {
            assertEquals(state, SmpState.fromName(state.name))
            assertEquals(state, SmpState.fromName(state.name.lowercase()))
        }
    }

    @Test
    fun `the states the bridge can report are all present`() {
        // Mirrors android_bridge.events.SmpState. A state added there and not
        // here would arrive over the bridge and be downgraded to NOT_VERIFIED
        // by fromName -- safe, but silent, which is how SECRET_REQUIRED was
        // lost in the first place.
        assertEquals(
            setOf("NOT_VERIFIED", "SECRET_REQUIRED", "IN_PROGRESS",
                  "VERIFIED", "FAILED", "CANCELLED"),
            SmpState.entries.map { it.name }.toSet())
    }

    @Test
    fun `every state produces an offer`() {
        // No state may leave the control undefined: a `when` that fell through
        // would render nothing, which is indistinguishable from HIDDEN and
        // would hide the button on a session that can be verified.
        for (security in SecurityState.entries) {
            for (smp in SmpState.entries) {
                assertNotNull(Verification.offer(security, smp),
                              "$security/$smp produced no offer")
            }
        }
    }
}
