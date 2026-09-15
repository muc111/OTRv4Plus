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
}
