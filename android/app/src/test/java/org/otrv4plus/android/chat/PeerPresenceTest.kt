// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.Subscription
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A contact was added, saved, and read "presence unknown" forever.
 *
 * The Kotlin half of the fix. `Contact.online` was a Boolean, which cannot
 * distinguish "the server has not told us anything about this peer" from
 * "this peer is offline" — so a freshly added contact was inferred OFFLINE,
 * and the only thing standing between that and a wrong label was a flag about
 * OUR OWN link. The peer's state now crosses the bridge as one of three
 * values and the UI reads it directly.
 */
class PeerPresenceTest {

    // ── mapping what Python said ────────────────────────────────────────────

    @Test
    fun `the three states map across the bridge`() {
        assertEquals(PeerPresence.ONLINE, PeerPresence.of("online"))
        assertEquals(PeerPresence.OFFLINE, PeerPresence.of("offline"))
        assertEquals(PeerPresence.UNKNOWN, PeerPresence.of("unknown"))
    }

    @Test
    fun `an unrecognised value is unknown, never a claim`() {
        assertEquals(PeerPresence.UNKNOWN, PeerPresence.of("banana"))
        assertEquals(PeerPresence.UNKNOWN, PeerPresence.of(""))
    }

    @Test
    fun `case does not matter`() {
        assertEquals(PeerPresence.ONLINE, PeerPresence.of("ONLINE"))
    }

    // ── the bug ─────────────────────────────────────────────────────────────

    @Test
    fun `a peer nothing is known about is not reported offline`() {
        assertEquals(
            Presence.UNKNOWN,
            Presence.of(PeerPresence.UNKNOWN, linkKnown = true,
                        subscription = Subscription.BOTH),
            "never-heard was inferred as offline, which is the original bug")
    }

    @Test
    fun `a peer the server said is online is online`() {
        assertEquals(
            Presence.ONLINE,
            Presence.of(PeerPresence.ONLINE, linkKnown = true,
                        subscription = Subscription.BOTH))
    }

    @Test
    fun `a peer the server said is offline is offline`() {
        assertEquals(
            Presence.OFFLINE,
            Presence.of(PeerPresence.OFFLINE, linkKnown = true,
                        subscription = Subscription.BOTH))
    }

    @Test
    fun `offline and never-heard are different answers`() {
        val heard = Presence.of(PeerPresence.OFFLINE, true, Subscription.BOTH)
        val unheard = Presence.of(PeerPresence.UNKNOWN, true, Subscription.BOTH)
        assertTrue(heard != unheard,
            "the two collapsed back into one value")
    }

    // ── precedence, and each step is a different question ───────────────────

    @Test
    fun `a pending request outranks everything`() {
        // The server will not send their presence until they approve, so this
        // is the reason it is unknown and the UI should say so.
        assertEquals(
            Presence.PENDING,
            Presence.of(PeerPresence.ONLINE, linkKnown = true,
                        subscription = Subscription.PENDING))
    }

    @Test
    fun `a disconnected client knows nothing about anyone`() {
        assertEquals(
            Presence.UNKNOWN,
            Presence.of(PeerPresence.ONLINE, linkKnown = false,
                        subscription = Subscription.BOTH),
            "a stale online survived our own link going down")
    }

    @Test
    fun `a subscription that carries no presence stays unknown`() {
        for (sub in listOf(Subscription.FROM, Subscription.NONE)) {
            assertEquals(
                Presence.UNKNOWN,
                Presence.of(PeerPresence.OFFLINE, linkKnown = true,
                            subscription = sub),
                "$sub does not deliver presence, so offline is invented")
        }
    }

    @Test
    fun `an unknown subscription trusts the peer state`() {
        // A server that reports nothing useful about the subscription must not
        // turn every contact grey.
        assertEquals(
            Presence.ONLINE,
            Presence.of(PeerPresence.ONLINE, linkKnown = true,
                        subscription = Subscription.UNKNOWN))
    }

    @Test
    fun `a one-way TO subscription does deliver presence`() {
        assertEquals(
            Presence.ONLINE,
            Presence.of(PeerPresence.ONLINE, linkKnown = true,
                        subscription = Subscription.TO))
    }

    // ── the derived boolean ─────────────────────────────────────────────────

    @Test
    fun `online is derived and cannot drift`() {
        val c = contact(PeerPresence.ONLINE)
        assertTrue(c.online)
        assertFalse(contact(PeerPresence.OFFLINE).online)
        assertFalse(contact(PeerPresence.UNKNOWN).online,
            "unknown reported as online, which is a claim we cannot make")
    }

    private fun contact(p: PeerPresence) =
        org.otrv4plus.android.bridge.Contact(
            jid = "alice@xmpp-elite.i2p", displayName = "alice",
            presence = p,
            security = org.otrv4plus.android.bridge.SecurityState.PLAINTEXT,
            smp = org.otrv4plus.android.bridge.SmpState.NOT_VERIFIED,
            callAvailable = false)
}
