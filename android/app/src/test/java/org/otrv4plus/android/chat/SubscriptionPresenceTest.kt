// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Subscription
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * "Presence unknown" with a reason, where there is one.
 *
 * A contact added but not yet approved reads as unknown for as long as they
 * take to answer -- hours, or days. The roster has always said so and the
 * bridge discarded it, so the only conclusion available to the user was that
 * the app was broken.
 */
class SubscriptionPresenceTest {

    // ── reading the roster's own words ──────────────────────────────────────

    @Test
    fun `both directions is the ordinary working state`() {
        assertEquals(Subscription.BOTH, Subscription.of("both", false))
        assertTrue(Subscription.BOTH.presenceIsKnowable)
    }

    @Test
    fun `to means we can see them`() {
        assertEquals(Subscription.TO, Subscription.of("to", false))
        assertTrue(Subscription.TO.presenceIsKnowable)
    }

    @Test
    fun `from means they see us and we do not see them`() {
        assertEquals(Subscription.FROM, Subscription.of("from", false))
        assertFalse(Subscription.FROM.presenceIsKnowable,
            "the server sends us nothing about them, so any claim is invented")
    }

    @Test
    fun `none is on the roster and subscribed neither way`() {
        assertEquals(Subscription.NONE, Subscription.of("none", false))
        assertFalse(Subscription.NONE.presenceIsKnowable)
    }

    @Test
    fun `a pending request outranks the subscription state`() {
        // This is the whole point. A sent-and-unanswered request leaves the
        // subscription at "none", so reading it alone makes "waiting for
        // them" and "on the roster, not subscribed" identical.
        assertEquals(Subscription.PENDING, Subscription.of("none", true))
        assertEquals(Subscription.PENDING, Subscription.of("", true))
    }

    @Test
    fun `an unrecognised subscription is unknown, not a guess`() {
        assertEquals(Subscription.UNKNOWN, Subscription.of("banana", false))
        assertEquals(Subscription.UNKNOWN, Subscription.of("", false))
    }

    @Test
    fun `case does not matter`() {
        assertEquals(Subscription.BOTH, Subscription.of("BOTH", false))
    }

    // ── what the user is told ───────────────────────────────────────────────

    @Test
    fun `a pending contact is pending rather than merely unknown`() {
        assertEquals(
            Presence.PENDING,
            Presence.of(online = false, known = true,
                        subscription = Subscription.PENDING))
    }

    @Test
    fun `pending survives being connected and hearing nothing`() {
        assertEquals(
            Presence.PENDING,
            Presence.of(online = true, known = true,
                        subscription = Subscription.PENDING),
            "a stray presence must not overwrite the reason it is unknown")
    }

    @Test
    fun `a subscribed contact reports online normally`() {
        assertEquals(
            Presence.ONLINE,
            Presence.of(online = true, known = true,
                        subscription = Subscription.BOTH))
    }

    @Test
    fun `a subscribed contact reports offline normally`() {
        assertEquals(
            Presence.OFFLINE,
            Presence.of(online = false, known = true,
                        subscription = Subscription.BOTH))
    }

    @Test
    fun `a one-way subscription is never reported as offline`() {
        // The server does not send their presence, so "offline" is a claim
        // with nothing behind it.
        assertEquals(
            Presence.UNKNOWN,
            Presence.of(online = false, known = true,
                        subscription = Subscription.FROM))
    }

    @Test
    fun `a disconnected client still knows nothing about anyone`() {
        assertEquals(
            Presence.UNKNOWN,
            Presence.of(online = true, known = false,
                        subscription = Subscription.BOTH))
    }

    @Test
    fun `an unknown subscription falls back to the old behaviour`() {
        // So a server that reports nothing useful behaves exactly as before
        // rather than having every contact silently become UNKNOWN.
        assertEquals(
            Presence.ONLINE,
            Presence.of(online = true, known = true,
                        subscription = Subscription.UNKNOWN))
        assertEquals(
            Presence.OFFLINE,
            Presence.of(online = false, known = true,
                        subscription = Subscription.UNKNOWN))
    }

    @Test
    fun `the two-argument form still works for callers that have no roster`() {
        assertEquals(Presence.ONLINE, Presence.of(online = true, known = true))
        assertEquals(Presence.UNKNOWN, Presence.of(online = true, known = false))
    }
}
