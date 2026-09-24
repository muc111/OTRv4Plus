// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a conversation row may claim, driven rather than eyeballed.
 *
 * [Conversation] has carried `security` and `smp` since it was written and
 * the list rendered neither, so a user scanning their conversations could not
 * tell a verified thread from one going out in the clear without opening it.
 * These are the rules that fixed that, and they are the part that can be
 * wrong: the Composable only maps a [RowSecurity.Tone] onto the theme.
 *
 * The strongest of these is the last class. "Verified" is the one word this
 * application must never say wrongly, and exactly one state earns it.
 */
class RowSecurityTest {

    private fun badge(
        security: SecurityState,
        smp: SmpState = SmpState.NOT_VERIFIED,
        hasHistory: Boolean = true,
    ) = RowSecurity.badge(security, smp, hasHistory)

    // ── only the engine's answer reads as verified ───────────────────────────

    @Test
    fun `exactly one state is described as verified`() {
        assertEquals(setOf(SecurityState.SMP_VERIFIED),
            RowSecurity.statesDescribedAsVerified(),
            "something other than a completed SMP run reads as verified")
    }

    @Test
    fun `a verified conversation says so`() {
        val badge = assertNotNull(badge(SecurityState.SMP_VERIFIED))
        assertEquals("Verified", badge.text)
        assertEquals(RowSecurity.Tone.GOOD, badge.tone)
    }

    @Test
    fun `encryption alone is not verification`() {
        for (state in listOf(SecurityState.ENCRYPTED, SecurityState.FINGERPRINT)) {
            val badge = assertNotNull(badge(state))
            assertEquals(RowSecurity.Tone.NEUTRAL, badge.tone)
            assertTrue("unverified" in badge.text,
                "$state reads as something other than unverified")
        }
    }

    @Test
    fun `a claimed SMP state cannot promote an unverified conversation`() {
        // `smp` and `security` are two answers from the same engine, and if
        // they ever disagreed the row must take the weaker one. A row that
        // said "Verified" because a stale SmpState said VERIFIED, while the
        // session state did not, would be the one lie that matters.
        for (smp in SmpState.entries) {
            val badge = assertNotNull(badge(SecurityState.ENCRYPTED, smp))
            assertTrue(badge.tone != RowSecurity.Tone.GOOD,
                "SmpState.$smp promoted an ENCRYPTED row to verified")
        }
    }

    // ── the loud cases ───────────────────────────────────────────────────────

    @Test
    fun `a changed key is the loudest thing on the row`() {
        val badge = assertNotNull(badge(SecurityState.FINGERPRINT_MISMATCH))
        assertEquals(RowSecurity.Tone.ALARM, badge.tone)
        assertTrue("CHANGED" in badge.text)
    }

    @Test
    fun `a changed key is shown before anything has been said`() {
        // A key that is not the pinned one is a fact about the CONTACT.
        // Waiting for them to speak first is waiting for the moment it is too
        // late to warn about.
        assertNotNull(badge(SecurityState.FINGERPRINT_MISMATCH, hasHistory = false))
    }

    @Test
    fun `a changed key outranks every verification state`() {
        for (smp in SmpState.entries) {
            val badge = assertNotNull(
                badge(SecurityState.FINGERPRINT_MISMATCH, smp))
            assertEquals(RowSecurity.Tone.ALARM, badge.tone,
                "SmpState.$smp softened a fingerprint mismatch")
        }
    }

    @Test
    fun `a plaintext conversation is stated, not left to be inferred`() {
        val badge = assertNotNull(badge(SecurityState.PLAINTEXT))
        assertEquals("Not encrypted", badge.text)
        assertEquals(RowSecurity.Tone.ALARM, badge.tone)
    }

    // ── and the case where silence is the honest answer ──────────────────────

    @Test
    fun `a contact never spoken to gets no badge`() {
        // PLAINTEXT with no history is not a fact about a conversation, it is
        // the absence of one. Stamping "Not encrypted" on every name in a
        // fresh contact list makes the warning mean nothing by the time it
        // matters.
        assertNull(badge(SecurityState.PLAINTEXT, hasHistory = false))
    }

    @Test
    fun `every other state still speaks without history`() {
        for (state in SecurityState.entries - SecurityState.PLAINTEXT) {
            assertNotNull(badge(state, hasHistory = false),
                "$state says nothing until somebody speaks")
        }
    }

    // ── an incoming request is a thing to do ─────────────────────────────────

    @Test
    fun `a held verification request is surfaced in the list`() {
        val badge = assertNotNull(
            badge(SecurityState.ENCRYPTED, SmpState.SECRET_REQUIRED))
        assertEquals("Verification requested", badge.text)
        assertEquals(RowSecurity.Tone.NEUTRAL, badge.tone,
            "an incoming request is a prompt, not a security claim")
    }

    @Test
    fun `a request does not suppress the plaintext warning`() {
        assertEquals("Not encrypted",
            assertNotNull(badge(SecurityState.PLAINTEXT,
                                SmpState.SECRET_REQUIRED)).text)
    }

    // ── nothing may be left undecided ────────────────────────────────────────

    @Test
    fun `every combination of states has an answer`() {
        // The `when` is exhaustive on SecurityState with no `else`, so a new
        // state is a compile error rather than a silent inherit. This covers
        // the other axis: no pair may throw.
        for (security in SecurityState.entries) {
            for (smp in SmpState.entries) {
                for (history in listOf(true, false)) {
                    RowSecurity.badge(security, smp, history)
                }
            }
        }
    }

    @Test
    fun `no badge text is blank`() {
        for (security in SecurityState.entries) {
            for (smp in SmpState.entries) {
                val badge = RowSecurity.badge(security, smp, true) ?: continue
                assertTrue(badge.text.isNotBlank(),
                    "$security/$smp renders an empty badge")
            }
        }
    }
}
