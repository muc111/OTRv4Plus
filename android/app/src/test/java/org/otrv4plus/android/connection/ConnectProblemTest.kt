// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Owner report (2026-10-11): with the built-in router a red "failed" showed
 * while the app was still starting the router and building tunnels. What the
 * Connect screen says, by the failure and whether the app is still trying.
 */
class ConnectProblemTest {

    private fun line(code: String?, retrying: Boolean, n: Int = 0, connected: Boolean = false) =
        ConnectProblem.line(code, connected, retrying, n)

    @Test
    fun `start-up trouble while retrying is quiet, never an error`() {
        for (code in listOf("timeout", "sam_unavailable", "i2p_destination_unreachable",
                            "i2p_session_failed", "stream_failed")) {
            val l = line(code, retrying = true, n = 1)!!
            assertEquals(ConnectProblem.Tone.QUIET, l.tone, code)
            assertTrue(l.text.startsWith("Still setting up"), l.text)
            for (alarming in listOf("failed", "lost", "dropped", "trying again"))
                assertTrue(alarming !in l.text.lowercase(), l.text)
        }
    }

    @Test
    fun `the same trouble three times in a row becomes an error, and says what`() {
        val l = line("i2p_destination_unreachable", retrying = true, n = 3)!!
        assertEquals(ConnectProblem.Tone.ERROR, l.tone)
        assertTrue("offline" in l.text && "Still trying" in l.text, l.text)
        val chat = line("xmpp_stream_failure", retrying = true, n = 3)!!
        assertTrue("chat service" in chat.text, chat.text)
    }

    @Test
    fun `a wrong password is an error at once`() {
        val l = line("auth_failed", retrying = false)!!
        assertEquals(ConnectProblem.Tone.ERROR, l.tone)
        assertTrue("password" in l.text, l.text)
        assertEquals(ConnectProblem.Kind.NEEDS_YOU, ConnectProblem.kind("auth_failed"))
    }

    @Test
    fun `nothing while connected, nothing without a failure`() {
        assertNull(line("timeout", retrying = false, connected = true))
        assertNull(line(null, retrying = true))
        assertNull(line("", retrying = false))
    }

    @Test
    fun `an unknown code is not shown while retrying, and is named once it stops`() {
        assertNull(line("something_new", retrying = true, n = 1))
        assertTrue("something_new" in line("something_new", retrying = false)!!.text)
    }

    @Test
    fun `the reconnect policy stops on exactly the codes the screen calls yours`() {
        assertEquals(ConnectProblem.NEEDS_YOU, ReconnectPolicy.NEEDS_THE_USER)
        for (code in ConnectProblem.NEEDS_YOU) {
            assertTrue(code !in ConnectProblem.TRANSIENT, code)
        }
    }

    @Test
    fun `a session limit says another device holds the account, from the first try`() {
        val line = ConnectProblem.line("session_limit", connected = false,
                                       retrying = true, failuresInARow = 1)!!
        assertEquals(ConnectProblem.Tone.ERROR, line.tone)
        assertTrue("already signed in on another device" in line.text)
        assertTrue("Still setting up" !in line.text)
    }

    @Test
    fun `a young built-in router is named, not the server`() {
        val line = ConnectProblem.line("server_closed_connection", connected = false,
            retrying = true, failuresInARow = 5, bundledRouterUpMs = 125_000L)!!
        assertEquals(ConnectProblem.Tone.QUIET, line.tone)
        assertTrue(line.text.contains("2:05"))
        assertTrue(line.text.contains("Nothing is wrong with the server"))
    }

    @Test
    fun `a settled router or the I2P app gets the usual words`() {
        val settled = ConnectProblem.line("server_closed_connection", false, true, 5,
            bundledRouterUpMs = ConnectProblem.ROUTER_SETTLING_MS + 1)!!
        assertTrue(settled.text.contains("chat service is not responding"))
        val external = ConnectProblem.line("server_closed_connection", false, true, 5)!!
        assertTrue(external.text.contains("chat service is not responding"))
    }

    @Test
    fun `a wrong password is still a wrong password with a young router`() {
        val line = ConnectProblem.line("auth_failed", false, false, 1, bundledRouterUpMs = 1_000L)!!
        assertTrue(line.text.contains("check the address and password"))
    }

    @Test
    fun `a full server says so, quietly while it keeps trying`() {
        val line = ConnectProblem.line(ConnectProblem.SERVER_FULL, false, true, 4)!!
        assertEquals(ConnectProblem.Tone.QUIET, line.tone)
        assertTrue(line.text.startsWith("The server is full"))
    }

    @Test
    fun `a busy server is never an alarm`() {
        for (n in listOf(1, 5, 20)) {
            val line = ConnectProblem.line(ConnectProblem.SERVER_BUSY, false, true, n)!!
            assertEquals(ConnectProblem.Tone.QUIET, line.tone)
        }
    }
}
