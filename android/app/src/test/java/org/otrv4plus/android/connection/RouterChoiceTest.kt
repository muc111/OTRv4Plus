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
        assertTrue(RouterChoice.needsI2p("alice@example.org", "chat.i2p:5222"))
        assertTrue(RouterChoice.needsI2p("alice@chat.i2p.", ""))
        assertFalse(RouterChoice.needsI2p("alice@example.org", "chat.example.org:5223"))
        assertFalse(RouterChoice.needsI2p("alice@example.org", "[2001:db8::1]:5222"))
        assertFalse(RouterChoice.needsI2p("alice@jabber.de", ""))
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
    fun `the configuration listens on loopback only and carries no transit`() {
        val conf = RouterChoice.config(23_456)
        val lines = conf.lines().map { it.trim() }
        assertTrue("address = 127.0.0.1" in lines)
        assertTrue("port = 23456" in lines)
        assertTrue("floodfill = false" in lines)
        assertTrue("bandwidth = L" in lines)
        assertTrue("notransit = true" in lines)
        assertTrue("share = 0" in lines)
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

    // -- is there a router on the phone? A real SAM HELLO, on real sockets --

    private fun serve(reply: String?): java.net.ServerSocket {
        val server = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        Thread {
            runCatching {
                server.accept().use { c ->
                    val hello = c.getInputStream().bufferedReader().readLine()
                    if (reply != null && hello == RouterChoice.SAM_HELLO.trim())
                        c.getOutputStream().apply { write(reply.toByteArray()); flush() }
                    else Thread.sleep(3_000)
                }
            }
        }.apply { isDaemon = true; start() }
        return server
    }

    @Test
    fun `a SAM bridge that answers HELLO is a router on the phone`() {
        serve("HELLO REPLY RESULT=OK VERSION=3.1\n").use {
            assertEquals(RouterChoice.Probe.SAM, RouterChoice.probeSam(it.localPort))
        }
    }

    @Test
    fun `an open port that is not SAM is not a router`() {
        serve("HTTP/1.1 400 Bad Request\n").use {
            assertEquals(RouterChoice.Probe.NOT_SAM, RouterChoice.probeSam(it.localPort))
        }
        serve(null).use {          // accepts, says nothing
            assertEquals(RouterChoice.Probe.NOT_SAM, RouterChoice.probeSam(it.localPort, 300))
        }
        serve("HELLO REPLY RESULT=NOVERSION\n").use {
            assertEquals(RouterChoice.Probe.NOT_SAM, RouterChoice.probeSam(it.localPort))
        }
    }

    @Test
    fun `a closed port is no answer`() {
        val port = java.net.ServerSocket(0).use { it.localPort }
        assertEquals(RouterChoice.Probe.NO_ANSWER, RouterChoice.probeSam(port, 300))
    }

    @Test
    fun `only SAM keeps the built-in router from starting`() {
        for (p in RouterChoice.Probe.values()) {
            val use = RouterChoice.decide(p == RouterChoice.Probe.SAM, bundled = true)
            assertEquals(if (p == RouterChoice.Probe.SAM) Use.EXTERNAL else Use.BUILT_IN, use, p.name)
        }
    }

    @Test
    fun `the phone's router is asked again before giving up on it`() {
        val answers = ArrayDeque(listOf(RouterChoice.Probe.NO_ANSWER, RouterChoice.Probe.SAM))
        val slept = mutableListOf<Long>()
        assertEquals(RouterChoice.Probe.SAM,
            RouterChoice.findExternalSam(probe = { answers.removeFirst() }, sleep = { slept += it }))
        assertEquals(1, slept.size)
        var asked = 0
        assertEquals(RouterChoice.Probe.NO_ANSWER,
            RouterChoice.findExternalSam(tries = 3, probe = { asked++; RouterChoice.Probe.NO_ANSWER },
                                         sleep = {}))
        assertEquals(3, asked)
    }

    @Test
    fun `the HELLO reply is read strictly`() {
        assertTrue(RouterChoice.isSamHello("HELLO REPLY RESULT=OK VERSION=3.1"))
        assertFalse(RouterChoice.isSamHello("HELLO REPLY RESULT=I2P_ERROR"))
        assertFalse(RouterChoice.isSamHello("SSH-2.0-OpenSSH RESULT=OK"))
        assertFalse(RouterChoice.isSamHello(null))
    }
}
