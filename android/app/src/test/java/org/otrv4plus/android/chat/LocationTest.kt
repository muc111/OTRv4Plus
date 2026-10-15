// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LocationTest {

    @Test
    fun `plus codes match the reference encoding`() {
        // From the Open Location Code test data (encoding.csv).
        assertEquals("7FG49QCJ+2VX", PlusCode.encode(20.3701125, 2.782234375))
        assertTrue(PlusCode.encode(47.0000625, 8.0000625).startsWith("8FVC2222+22"))
        assertTrue(PlusCode.encode(-41.2730625, 174.7859375).startsWith("4VCPPQGP+Q9"))
    }

    @Test
    fun `decoding lands inside the cell it came from`() {
        for ((lat, lon) in listOf(51.50740 to -0.12780, -33.8688 to 151.2093, 0.0 to 0.0,
                                  89.9999 to 179.9999, -89.9999 to -180.0, 37.4219 to -122.0841)) {
            val code = PlusCode.encode(lat, lon)
            val back = assertNotNull(PlusCode.decode(code), code)
            assertTrue(abs(back.lat - lat) < 0.0001 && abs(back.lon - lon) < 0.0001, "$code $back")
        }
    }

    @Test
    fun `junk and short codes are not codes`() {
        for (bad in listOf("", "hello", "GV4C+XV", "9C3XGV4C", "9C3XGV4C+X+V", "ZZZZZZZZ+ZZ", "9C3XGV4C+XI"))
            assertNull(PlusCode.decode(bad), bad)
    }

    @Test
    fun `a pin survives the message it travels in`() {
        val pin = Location.Pin(51.5074, -0.1278, 12.4)
        val body = Location.body(pin)
        assertTrue(body.startsWith(Location.MARKER))
        assertTrue("geo:51.50740,-0.12780;u=12" in body)
        val back = assertNotNull(Location.parse(body))
        assertEquals(51.5074, back.lat, 1e-9)
        assertEquals(12.0, back.accuracyMeters)
    }

    @Test
    fun `out of range or mangled geo lines are not pins`() {
        for (bad in listOf("geo:91.0,0.0", "geo:0,181", "geo:a,b", "see geo:1,2 there", "x".repeat(2000)))
            assertNull(Location.parse(bad), bad)
    }

    @Test
    fun `what a user may type`() {
        assertNotNull(Location.fromTyped("9C3XGV4C+XV"))
        val c = assertNotNull(Location.fromTyped(" 51.5074, -0.1278 "))
        assertEquals(-0.1278, c.lon, 1e-9)
        assertNotNull(Location.fromTyped("geo:51.5,-0.12"))
        assertNull(Location.fromTyped("GV4C+XV London"))
        assertNull(Location.fromTyped("100, 200"))
        assertNull(Location.typedStatus("", null))
        assertEquals(Location.typedHint, Location.typedStatus("GV4C+XV London", null))
    }

    @Test
    fun `a location goes only where the identity is verified`() {
        assertEquals(Location.NEEDS_ENCRYPTION, Location.shareRefusal(encrypted = false, verified = false, group = false))
        assertTrue(Location.shareRefusal(encrypted = true, verified = false, group = false)!!.contains("SMP"))
        assertTrue(Location.shareRefusal(encrypted = true, verified = false, group = true)!!.contains("verified"))
        assertNull(Location.shareRefusal(encrypted = true, verified = true, group = false))
        assertNull(Location.shareRefusal(encrypted = true, verified = true, group = true))
    }
}
