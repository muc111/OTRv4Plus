// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.theme

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Dark purple by default, persisted by a stable name, and every pair legible. */
class ThemeTokensTest {

    @Test
    fun `dark purple is the default, including for anything unrecognised`() {
        assertEquals(ThemeTokens.Mode.DARK_PURPLE, ThemeTokens.DEFAULT)
        assertEquals(ThemeTokens.DEFAULT, ThemeTokens.Mode.fromStored(null))
        assertEquals(ThemeTokens.DEFAULT, ThemeTokens.Mode.fromStored("neon"))
        for (mode in ThemeTokens.Mode.entries) {
            assertEquals(mode, ThemeTokens.Mode.fromStored(mode.stored), "round trip")
        }
    }

    @Test
    fun `stored names never change`() {
        // Renaming one would silently reset every user's choice.
        assertEquals(listOf("dark_purple", "light", "system"),
                     ThemeTokens.Mode.entries.map { it.stored })
    }

    @Test
    fun `system follows the system, the others do not`() {
        assertTrue(ThemeTokens.isDark(ThemeTokens.Mode.DARK_PURPLE, systemDark = false))
        assertFalse(ThemeTokens.isDark(ThemeTokens.Mode.LIGHT, systemDark = true))
        assertTrue(ThemeTokens.isDark(ThemeTokens.Mode.SYSTEM, systemDark = true))
        assertFalse(ThemeTokens.isDark(ThemeTokens.Mode.SYSTEM, systemDark = false))
    }

    @Test
    fun `every text pair meets WCAG AA in both palettes`() {
        for ((name, palette) in listOf("dark" to ThemeTokens.DARK, "light" to ThemeTokens.LIGHT)) {
            for ((pair, colours) in ThemeTokens.textPairs(palette)) {
                val ratio = ThemeTokens.contrast(colours.first, colours.second)
                assertTrue(ratio >= 4.5, "$name $pair contrast %.2f < 4.5".format(ratio))
            }
        }
    }

    @Test
    fun `the dark palette is dark and purple`() {
        val bg = ThemeTokens.DARK.background
        assertTrue(ThemeTokens.luminance(bg) < 0.02, "not dark")
        val r = (bg shr 16) and 0xFF
        val g = (bg shr 8) and 0xFF
        val b = bg and 0xFF
        assertTrue(b > g && r > g, "not purple")
    }

    @Test
    fun `verified is distinct from error and from primary`() {
        for (p in listOf(ThemeTokens.DARK, ThemeTokens.LIGHT)) {
            assertTrue(p.verified != p.error && p.verified != p.primary)
        }
    }

    @Test
    fun `the contrast formula is right`() {
        assertEquals(21.0, ThemeTokens.contrast(0xFF000000, 0xFFFFFFFF), 0.01)
        assertEquals(1.0, ThemeTokens.contrast(0xFF777777, 0xFF777777), 0.001)
    }
}
