// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LinkPhaseTest {

    @Test
    fun `only connected can send`() {
        for (phase in LinkPhase.entries) {
            assertEquals(phase == LinkPhase.CONNECTED, phase.canSend, phase.name)
        }
    }

    @Test
    fun `reconnecting counts as busy`() {
        // Waiting out a backoff IS the app working on it. Showing it as idle
        // invites the user to start a second attempt.
        assertTrue(LinkPhase.RECONNECTING.busy)
    }

    @Test
    fun `stopped and failed are not busy`() {
        assertFalse(LinkPhase.STOPPED.busy)
        assertFalse(LinkPhase.FAILED.busy)
    }

    @Test
    fun `connected is not busy`() {
        assertFalse(LinkPhase.CONNECTED.busy)
    }

    @Test
    fun `an authenticated transport is connected whatever the stage says`() {
        assertEquals(LinkPhase.CONNECTED, LinkPhase.fromStage("anything", true))
    }

    @Test
    fun `the transport's own stages map as expected`() {
        assertEquals(LinkPhase.STOPPED, LinkPhase.fromStage("idle", false))
        assertEquals(LinkPhase.STOPPED, LinkPhase.fromStage("", false))
        assertEquals(LinkPhase.STOPPED, LinkPhase.fromStage("disconnected", false))
        assertEquals(LinkPhase.STOPPED, LinkPhase.fromStage("cancelled", false))
        assertEquals(LinkPhase.FAILED, LinkPhase.fromStage("failed", false))
        assertEquals(
            LinkPhase.CONNECTING, LinkPhase.fromStage("building_tunnels", false))
    }

    @Test
    fun `an unknown stage is progress, not success and not defeat`() {
        val phase = LinkPhase.fromStage("some_new_stage", false)
        assertEquals(LinkPhase.CONNECTING, phase)
        assertFalse(phase.canSend)
    }

    // ── one vocabulary, projected ───────────────────────────────────────────

    @Test
    fun `every declared stage maps to a phase`() {
        // Not a third model: the stages belong to Python's
        // ConnectionController and this is the projection of them onto the
        // four things a screen needs to tell apart. `tests/` binds STAGES
        // against the real tuple; this checks the mapping is total over it.
        for (stage in LinkPhase.STAGES) {
            LinkPhase.fromStage(stage, connected = false)
        }
    }

    @Test
    fun `a created account is not a connection in progress`() {
        // Registration finished and nobody is signed in. CONNECTING would
        // leave a spinner running for work that is over; FAILED would report
        // a success as a failure.
        val phase = LinkPhase.fromStage("registered", connected = false)
        assertEquals(LinkPhase.STOPPED, phase)
        assertFalse(phase.busy)
        assertFalse(phase.canSend)
    }

    @Test
    fun `registered is a stage this build knows about`() {
        assertTrue(LinkPhase.STAGES.contains("registered"))
    }

    @Test
    fun `the tunnel stages are all progress`() {
        for (stage in listOf("checking_router", "building_tunnels",
                             "connecting", "authenticating")) {
            val phase = LinkPhase.fromStage(stage, connected = false)
            assertEquals(LinkPhase.CONNECTING, phase, stage)
            assertTrue(phase.busy, stage)
        }
    }

    @Test
    fun `the resting stages are all stopped`() {
        for (stage in listOf("idle", "disconnected", "cancelled",
                             "registered")) {
            assertEquals(LinkPhase.STOPPED,
                LinkPhase.fromStage(stage, connected = false), stage)
        }
    }

    @Test
    fun `being connected outranks whatever the stage says`() {
        // The stage is a report of the last transition; `connected` is the
        // transport's own answer about now. A stale stage must not make a
        // live session look busy.
        for (stage in LinkPhase.STAGES) {
            assertEquals(LinkPhase.CONNECTED,
                LinkPhase.fromStage(stage, connected = true), stage)
        }
    }
}
