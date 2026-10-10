// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.otrv4plus.android.connection.RouterChoice.Mode
import org.otrv4plus.android.connection.RouterChoice.Use

class RouterChoiceTest {

    @Test
    fun `automatic prefers the router already on the phone`() {
        assertEquals(Use.EXTERNAL, RouterChoice.decide(Mode.AUTOMATIC, true, true))
    }

    @Test
    fun `automatic starts ours when nothing answers`() {
        assertEquals(Use.BUILT_IN, RouterChoice.decide(Mode.AUTOMATIC, false, true))
    }

    @Test
    fun `the user's choice wins`() {
        assertEquals(Use.EXTERNAL, RouterChoice.decide(Mode.EXTERNAL, false, true))
        assertEquals(Use.BUILT_IN, RouterChoice.decide(Mode.BUILT_IN, true, true))
    }

    @Test
    fun `an APK without a router never tries to start one`() {
        for (mode in Mode.entries) {
            for (external in listOf(true, false)) {
                assertEquals(Use.EXTERNAL, RouterChoice.decide(mode, external, false))
            }
        }
    }

    @Test
    fun `an unknown stored value reads as automatic`() {
        assertEquals(Mode.AUTOMATIC, Mode.fromStored(null))
        assertEquals(Mode.AUTOMATIC, Mode.fromStored("something"))
        for (mode in Mode.entries) assertEquals(mode, Mode.fromStored(mode.stored))
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
    fun `ours never takes the default SAM port`() {
        assertTrue(RouterChoice.BUILT_IN_SAM_PORT != RouterChoice.EXTERNAL_SAM_PORT)
        // i2pd's datagram port is one below; it must not land on 7656 either.
        assertTrue(RouterChoice.BUILT_IN_SAM_PORT - 1 != RouterChoice.EXTERNAL_SAM_PORT)
    }

    @Test
    fun `the configuration listens on loopback only and limits transit`() {
        val conf = RouterChoice.config()
        val lines = conf.lines().map { it.trim() }
        assertTrue("address = 127.0.0.1" in lines)
        assertTrue("port = ${RouterChoice.BUILT_IN_SAM_PORT}" in lines)
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
}
