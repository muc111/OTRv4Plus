// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ProfileField
import kotlin.test.Test
import kotlin.test.assertEquals

class ProfileTextTest {

    private val fields = listOf(
        ProfileField("fn", "Full name", 100, false),
        ProfileField("bday", "Birthday (YYYY-MM-DD)", 10, false),
    )

    @Test
    fun `an empty profile is described by whose it is`() {
        assertEquals("Your profile is empty.", ProfileText.empty(""))
        assertEquals("This person has not filled in a profile.", ProfileText.empty("bob@x.i2p"))
    }

    @Test
    fun `a field the bridge refused is named by its label`() {
        val typed = mapOf("fn" to "Alice", "bday" to "soon")
        assertEquals(
            "Saved. Not kept because of their format: Birthday (YYYY-MM-DD)",
            ProfileText.saved(typed, mapOf("fn" to "Alice"), fields))
        assertEquals("Your profile is saved.",
            ProfileText.saved(mapOf("fn" to "Alice", "bday" to ""), mapOf("fn" to "Alice"), fields))
    }
}
