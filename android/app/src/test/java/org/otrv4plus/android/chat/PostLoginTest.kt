// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Whether the post-login sequence has got anywhere.
 *
 * WHY IT MATTERS. An empty conversation list means either "the server says you
 * have no contacts" or "the roster has not arrived yet", and with nothing
 * recording which, the two render identically. That is what made a handset
 * report of "contacts do not appear" unanswerable without a log.
 *
 * It is an OBSERVATION, never a gate: nothing waits on it.
 */
class PostLoginTest {

    @Test
    fun `nothing is claimed before authentication`() {
        val p = PostLogin()
        assertFalse(p.authenticated)
        assertFalse(p.rosterSeen)
        assertFalse(p.ready)
    }

    @Test
    fun `a roster read before authentication is ignored`() {
        val p = PostLogin()
        p.onRoster(3)
        assertFalse(p.rosterSeen, "a stale read counted as initialisation")
    }

    @Test
    fun `an empty roster is a real answer`() {
        // THE DISTINCTION. A new account with nobody on the roster is fully
        // initialised; it is not still loading.
        val p = PostLogin()
        p.onAuthenticated()
        p.onRoster(0)
        assertTrue(p.rosterSeen)
        assertEquals(0, p.rosterSize)
        assertTrue(p.ready)
    }

    @Test
    fun `ready requires the roster to have been seen`() {
        val p = PostLogin()
        p.onAuthenticated()
        assertFalse(p.ready, "ready before any roster read")
        p.onRoster(2)
        assertTrue(p.ready)
    }

    @Test
    fun `an empty list is explained only while still fetching`() {
        val p = PostLogin()
        p.onAuthenticated()
        assertEquals("Fetching your contacts…", p.emptyListExplanation(0))
        p.onRoster(0)
        assertNull(p.emptyListExplanation(0),
                   "still claiming to fetch after the answer arrived")
    }

    @Test
    fun `a non-empty list needs no explanation`() {
        val p = PostLogin()
        p.onAuthenticated()
        assertNull(p.emptyListExplanation(1))
    }

    @Test
    fun `a disconnected screen is not told it is fetching`() {
        // Other lines on that screen already say the connection is down.
        assertNull(PostLogin().emptyListExplanation(0))
    }

    @Test
    fun `discovery is recorded with whatever it found`() {
        val p = PostLogin()
        p.onServices("rooms.xmpp-elite.i2p")
        assertTrue(p.servicesDiscovered)
        assertEquals("rooms.xmpp-elite.i2p", p.roomService)
    }

    @Test
    fun `discovery that found no rooms service says so`() {
        val p = PostLogin()
        p.onServices(null)
        assertTrue(p.servicesDiscovered, "discovery ran and that is a fact")
        assertNull(p.roomService)
        p.onServices("  ")
        assertNull(p.roomService, "a blank service is not a service")
    }

    @Test
    fun `signing out resets everything including the room service`() {
        // The MUC service belongs to the server that was connected to.
        // Carrying it into the next session would build room JIDs against a
        // host this account may never have spoken to.
        val p = PostLogin()
        p.onAuthenticated()
        p.onRoster(4)
        p.onServices("rooms.xmpp-elite.i2p")
        p.onSignedOut()
        assertFalse(p.authenticated)
        assertFalse(p.rosterSeen)
        assertEquals(0, p.rosterSize)
        assertFalse(p.servicesDiscovered)
        assertNull(p.roomService)
    }

    @Test
    fun `re-authenticating starts from nothing known`() {
        val p = PostLogin()
        p.onAuthenticated()
        p.onRoster(4)
        p.onSignedOut()
        p.onAuthenticated()
        assertFalse(p.rosterSeen, "the previous session's roster counted")
        assertFalse(p.ready)
    }
}
