// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.otrv4plus.android.connection.RouterChoice.Use

class RouterChoiceTest {

    @Test
    fun `the router already on the phone is used when it answers`() {
        assertEquals(Use.EXTERNAL, RouterChoice.decide(true, true))
    }

    @Test
    fun `ours starts when nothing answers`() {
        assertEquals(Use.BUILT_IN, RouterChoice.decide(false, true))
    }

    @Test
    fun `an APK without a router never tries to start one`() {
        for (external in listOf(true, false)) {
            assertEquals(Use.EXTERNAL, RouterChoice.decide(external, false))
        }
    }

    @Test
    fun `only I2P sign-ins need a router`() {
        assertTrue(RouterChoice.needsI2p("alice@otrv4plus.i2p", ""))
        assertTrue(RouterChoice.needsI2p("alice@example.org", "abc.b32.i2p"))
        assertTrue(RouterChoice.needsI2p("alice@OTRV4PLUS.I2P/phone", ""))
        assertFalse(RouterChoice.needsI2p("alice@yax.im", ""))
        assertFalse(RouterChoice.needsI2p("alice@x.onion", ""))
        assertFalse(RouterChoice.needsI2p("alice@otrv4plus.i2p", "chat.example.org"))
    }

    @Test
    fun `ours is a random port, never the default one`() {
        // The ends of the range, and a spread in between.
        for (pick in listOf(0, 1, 19_999, 39_999)) {
            val port = RouterChoice.pickSamPort { bound -> minOf(pick, bound - 1) }
            assertTrue(port in RouterChoice.BUILT_IN_SAM_PORT_MIN until
                           RouterChoice.BUILT_IN_SAM_PORT_MAX, "$port")
            // i2pd's datagram port is one below; neither may be 7656/7655.
            assertTrue(port != RouterChoice.EXTERNAL_SAM_PORT &&
                           port - 1 != RouterChoice.EXTERNAL_SAM_PORT &&
                           port - 1 != RouterChoice.EXTERNAL_SAM_PORT - 1, "$port")
        }
        val seen = (1..200).map {
            RouterChoice.pickSamPort { bound -> java.security.SecureRandom().nextInt(bound) }
        }.toSet()
        assertTrue(seen.size > 150, "the port is not predictable: ${seen.size} distinct")
    }

    @Test
    fun `a failed router never falls back to the default port`() {
        assertTrue(RouterChoice.NO_SAM_PORT != 0)
        assertTrue(RouterChoice.NO_SAM_PORT != RouterChoice.EXTERNAL_SAM_PORT)
    }

    @Test
    fun `the configuration listens on loopback only and limits transit`() {
        val conf = RouterChoice.config(23_456)
        val lines = conf.lines().map { it.trim() }
        assertTrue("address = 127.0.0.1" in lines)
        assertTrue("port = 23456" in lines)
        assertTrue("floodfill = false" in lines)
        assertTrue("bandwidth = L" in lines)
        assertTrue("transittunnels = 50" in lines)
        assertTrue("verify = true" in lines)
        // Every listener but SAM is off.
        for (section in listOf("http", "httpproxy", "socksproxy", "bob", "i2cp",
                               "i2pcontrol", "upnp")) {
            val at = lines.indexOf("[$section]")
            assertTrue(at >= 0, section)
            assertEquals("enabled = false", lines[at + 1], section)
        }
        // No other address anywhere.
        assertFalse(lines.any { it.startsWith("address") && it != "address = 127.0.0.1" })
    }

    @Test
    fun `the screen says something only when a router is in use`() {
        assertNull(RouterChoice.label(RouterChoice.State.NOT_USED, 0, false))
        for (state in RouterChoice.State.entries - RouterChoice.State.NOT_USED) {
            assertNotNull(RouterChoice.label(state, 0, false), state.name)
        }
        val first = RouterChoice.label(RouterChoice.State.RUNNING, 125_000, true)!!
        assertTrue("2:05" in first && "first time" in first, first)
        val later = RouterChoice.label(RouterChoice.State.RUNNING, 9_000, false)!!
        assertTrue("0:09" in later, later)
        val joining = RouterChoice.label(RouterChoice.State.JOINING, 61_000, true)!!
        assertTrue("1:01" in joining && "list of I2P routers" in joining, joining)
    }

    @Test
    fun `a stopped router says why`() {
        val why = RouterChoice.label(RouterChoice.State.FAILED, 0, false,
                                     "exited with code 1: bad option")!!
        assertTrue("exited with code 1: bad option" in why, why)
        assertTrue(RouterChoice.label(RouterChoice.State.FAILED, 0, false)!!.endsWith("."))
    }

    @Test
    fun `the certificate directory itself may be unpacked, nothing outside it`() {
        val base = java.io.File("/data/app/i2pd/certificates")
        assertTrue(RouterChoice.isInside(base, base))
        assertTrue(RouterChoice.isInside(base, java.io.File(base, "reseed/a.crt")))
        assertFalse(RouterChoice.isInside(base, java.io.File("/data/app/i2pd/i2pd.conf")))
        assertFalse(RouterChoice.isInside(base, java.io.File("/data/app/i2pd/certificates-x/a")))
    }

    @Test
    fun `a router line shown on screen names no address`() {
        val line = "12:00:01@123/error - SSU2: peer 203.0.113.7:12345 and " +
            "[2001:db8::1]:4567 and fe80::1 failed for " +
            "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p " +
            "ident a2KmX0lP-9qRsTuVwXyZ01234567890abcdefGHIJ~kl"
        val clean = RouterChoice.scrub(line)
        for (leak in listOf("203.0.113.7", "12345", "2001:db8", "fe80::1",
                            "ukeu3k5o", "a2KmX0lP")) {
            assertFalse(leak in clean, "$leak in $clean")
        }
        assertTrue("SSU2" in clean && "failed" in clean, clean)
        assertTrue(RouterChoice.scrub("x".repeat(500)).length <= 200)
        // Ordinary text and times survive.
        assertEquals("exited with code 1: bad option", RouterChoice.scrub(
            "exited with code 1: bad option"))
    }

    // ── a router that has lost its way is restarted, once in a while ────────

    private val min = 60_000L

    @Test
    fun `a long-running router that keeps failing to reach the server is restarted`() {
        assertTrue(RouterChoice.shouldRestart("i2p_destination_unreachable",
            routerUpMs = 40 * min, failuresInARow = 4, sinceLastRestartMs = Long.MAX_VALUE))
    }

    @Test
    fun `a young router is left to settle`() {
        assertFalse(RouterChoice.shouldRestart("i2p_destination_unreachable",
            routerUpMs = 5 * min, failuresInARow = 9, sinceLastRestartMs = Long.MAX_VALUE))
    }

    @Test
    fun `one or two failures are not enough`() {
        assertFalse(RouterChoice.shouldRestart("timeout",
            routerUpMs = 40 * min, failuresInARow = 2, sinceLastRestartMs = Long.MAX_VALUE))
    }

    @Test
    fun `not again within half an hour`() {
        assertFalse(RouterChoice.shouldRestart("timeout",
            routerUpMs = 40 * min, failuresInARow = 6, sinceLastRestartMs = 10 * min))
    }

    @Test
    fun `a wrong password never restarts the router`() {
        assertFalse(RouterChoice.shouldRestart("auth_failed",
            routerUpMs = 40 * min, failuresInARow = 6, sinceLastRestartMs = Long.MAX_VALUE))
    }
}
