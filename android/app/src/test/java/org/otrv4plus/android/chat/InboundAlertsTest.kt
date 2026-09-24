// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * When the phone may be interrupted, and what it is allowed to say.
 *
 * These run. `InboundAlerts` has no Android import precisely so that the rules
 * about interrupting somebody are executed rather than read, and so that the
 * one thing that must never happen -- a peer's name or words reaching a lock
 * screen -- is pinned by a type that cannot carry them.
 */
class InboundAlertsTest {

    // ── the basic rule ───────────────────────────────────────────────────────

    @Test
    fun `a message arriving in the background raises an alert`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        assertNotNull(alerts.note())
    }

    @Test
    fun `a message arriving while the user is looking does not`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(true)
        assertNull(alerts.note(), "interrupted the user about something on screen")
    }

    @Test
    fun `nothing is visible until something says so`() {
        // The default matters: a service that starts before any Activity must
        // notify, not go silent waiting to be told the UI is gone.
        assertFalse(InboundAlerts().uiVisible)
        assertNotNull(InboundAlerts().note())
    }

    // ── the count ────────────────────────────────────────────────────────────

    @Test
    fun `the count accumulates while the user is away`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        assertEquals(1, alerts.note()?.count)
        assertEquals(2, alerts.note()?.count)
        assertEquals(3, alerts.note()?.count)
    }

    @Test
    fun `opening the app resets it`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        repeat(4) { alerts.note() }
        alerts.setUiVisible(true)
        assertEquals(0, alerts.unseen)
    }

    @Test
    fun `and the next departure starts from nothing`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        repeat(4) { alerts.note() }
        alerts.setUiVisible(true)
        alerts.setUiVisible(false)
        assertEquals(1, alerts.note()?.count, "a stale count carried across a visit")
    }

    @Test
    fun `a message while visible does not accumulate silently`() {
        // The count must not be quietly incrementing behind a suppressed
        // alert, or the first background message would announce five.
        val alerts = InboundAlerts()
        alerts.setUiVisible(true)
        repeat(5) { alerts.note() }
        alerts.setUiVisible(false)
        assertEquals(1, alerts.note()?.count)
    }

    // ── taking the notification down ─────────────────────────────────────────

    @Test
    fun `coming to the front asks for the notification to be cancelled`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        alerts.note()
        assertTrue(alerts.setUiVisible(true))
    }

    @Test
    fun `with nothing posted there is nothing to cancel`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        assertFalse(alerts.setUiVisible(true),
            "cancelled a notification that was never posted")
    }

    @Test
    fun `going away never asks for a cancel`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        alerts.note()
        assertFalse(alerts.setUiVisible(false),
            "backgrounding the app took down the notification it exists for")
    }

    @Test
    fun `a second ON_START does not cancel again`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        alerts.note()
        assertTrue(alerts.setUiVisible(true))
        assertFalse(alerts.setUiVisible(true))
    }

    @Test
    fun `clear forgets the count`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        repeat(3) { alerts.note() }
        alerts.clear()
        assertEquals(0, alerts.unseen)
    }

    // ── the sound ────────────────────────────────────────────────────────────

    @Test
    fun `only the first of a run may make a sound`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        assertTrue(alerts.note()!!.first)
        assertFalse(alerts.note()!!.first, "every message in a burst rang the phone")
        assertFalse(alerts.note()!!.first)
    }

    @Test
    fun `a new run may ring again`() {
        val alerts = InboundAlerts()
        alerts.setUiVisible(false)
        alerts.note()
        alerts.note()
        alerts.setUiVisible(true)
        alerts.setUiVisible(false)
        assertTrue(alerts.note()!!.first, "a fresh arrival was silenced by an old burst")
    }

    // ── what an alert is allowed to carry ────────────────────────────────────

    @Test
    fun `an alert has exactly one field and it is a number`() {
        // Structural, and the load-bearing test in this file. A peer's JID or
        // message body reaching a lock screen would undo the transport
        // underneath it; the defence is that the type CANNOT carry one, so
        // there is no way to build that notification by accident later.
        // Instance fields only: the Compose compiler plugin adds a static
        // `$stable` to classes in this module, which is not state this type
        // carries.
        val fields = InboundAlerts.Alert::class.java.declaredFields
            .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
        assertEquals(listOf("count"), fields.map { it.name })
        assertEquals(Int::class.javaPrimitiveType, fields.single().type)
    }

    @Test
    fun `an empty alert is not constructible`() {
        assertFailsWith<IllegalArgumentException> { InboundAlerts.Alert(0) }
    }
}
