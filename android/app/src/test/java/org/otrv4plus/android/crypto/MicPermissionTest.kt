// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The microphone decision, driven over every combination.
 *
 * THE CASE THIS EXISTS FOR is permanent denial. Android stops showing the
 * system dialog after the second refusal, and the launcher then returns
 * "denied" immediately -- so a UI that keeps calling it is a button that
 * silently does nothing forever. Distinguishing that from "never asked"
 * needs a fact Android does not provide, which is why [MicPermission.State]
 * carries `askedBefore`.
 */
class MicPermissionTest {

    private fun decide(
        granted: Boolean = false,
        rationale: Boolean = false,
        asked: Boolean = false,
    ) = MicPermission.decide(
        MicPermission.State(granted, rationale, asked))

    @Test
    fun `a granted permission just proceeds`() {
        assertEquals(MicPermission.Decision.Proceed, decide(granted = true))
    }

    @Test
    fun `a grant proceeds whatever else is true`() {
        // Granted outranks everything: a user who has just allowed it must
        // not be sent to Settings because of a stale flag.
        assertEquals(MicPermission.Decision.Proceed,
            decide(granted = true, rationale = true, asked = true))
    }

    @Test
    fun `the first ask is made without a lecture`() {
        assertEquals(MicPermission.Decision.Request, decide())
    }

    @Test
    fun `after one refusal the request is explained`() {
        assertEquals(MicPermission.Decision.ExplainThenRequest,
            decide(rationale = true, asked = true))
    }

    @Test
    fun `a permanent denial sends the user to settings`() {
        // The case the whole type exists for: no grant, no rationale, and we
        // have asked -- so the dialog is spent and asking again does nothing.
        assertEquals(MicPermission.Decision.OpenSettings,
            decide(asked = true))
    }

    @Test
    fun `never asked and permanently denied are not confused`() {
        // Android reports both as granted=false, rationale=false. Getting
        // them the wrong way round means either never asking at all, or
        // asking forever into a dialog that no longer appears.
        assertEquals(MicPermission.Decision.Request, decide(asked = false))
        assertEquals(MicPermission.Decision.OpenSettings, decide(asked = true))
    }

    @Test
    fun `a rationale before the first ask is still just a request`() {
        // Android should not report this, but a decision table must not
        // depend on that: it is still a first ask and Settings would be
        // wrong.
        assertEquals(MicPermission.Decision.ExplainThenRequest,
            decide(rationale = true, asked = false))
    }

    @Test
    fun `every combination has a decision`() {
        for (granted in listOf(true, false)) {
            for (rationale in listOf(true, false)) {
                for (asked in listOf(true, false)) {
                    decide(granted, rationale, asked)
                }
            }
        }
    }

    // ── capture is a narrower question ──────────────────────────────────────

    @Test
    fun `capture needs a live grant and nothing else counts`() {
        assertTrue(MicPermission.mayCapture(
            MicPermission.State(true, false, true)))
        for (rationale in listOf(true, false)) {
            for (asked in listOf(true, false)) {
                assertFalse(MicPermission.mayCapture(
                    MicPermission.State(false, rationale, asked)),
                    "capture was allowed without a grant")
            }
        }
    }

    @Test
    fun `the explanations are written for a person`() {
        for (text in listOf(MicPermission.RATIONALE,
                            MicPermission.PERMANENTLY_DENIED,
                            MicPermission.REFUSED)) {
            assertTrue(text.isNotBlank())
            assertTrue(text.length > 20, "not a sentence: $text")
        }
    }

    @Test
    fun `the rationale says where the audio goes`() {
        // A microphone request with no explanation of what happens to the
        // audio is the kind a person refuses.
        assertTrue("encrypted" in MicPermission.RATIONALE)
        assertTrue("never recorded" in MicPermission.RATIONALE)
    }

    @Test
    fun `the permanent denial text names the remedy`() {
        assertTrue("Settings" in MicPermission.PERMANENTLY_DENIED)
    }
}
