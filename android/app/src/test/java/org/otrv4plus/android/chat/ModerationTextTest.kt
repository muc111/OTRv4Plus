// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.Moderation
import org.otrv4plus.android.bridge.RoomOutcome
import kotlin.test.Test
import kotlin.test.assertEquals

class ModerationTextTest {

    private val ok = RoomOutcome(true, "ok", "")

    @Test
    fun `the state is said plainly`() {
        assertEquals("Not banned.", ModerationText.status(Moderation(ok)))
        assertEquals("Banned permanently.", ModerationText.status(Moderation(ok, true, 0)))
        assertEquals("Banned until 2026-10-24 20:43 UTC.",
                     ModerationText.status(Moderation(ok, true, 1_792_874_580)))
        assertEquals("An admin cannot be banned.", ModerationText.status(
            Moderation(RoomOutcome(false, "moderation_refused", "An admin cannot be banned."))))
    }

    @Test
    fun `a ban is permanent and says so`() {
        // Owner, 2026-10-25: permanent bans only.
        assertEquals("Ban c@x.i2p permanently? They are signed out now and cannot sign in " +
                     "again until you lift the ban.", ModerationText.confirm("c@x.i2p"))
        kotlin.test.assertTrue("permanent" in ModerationText.NOTE)
        kotlin.test.assertFalse("days" in ModerationText.NOTE)
    }

    @Test
    fun `an admin's standing does not survive a change of account`() {
        // Owner, 2026-10-24: ban tools showed on an account that was not an
        // admin. The screen asks ChatState.serverAdmin as well as the server's
        // last answer, and ChatState forgets it with the account.
        val s = ChatState().apply { bindAccount(AccountScope.of("admin@x.i2p")) }
        s.noteServerAdmin(true)
        kotlin.test.assertTrue(s.serverAdmin)
        s.bindAccount(AccountScope.of("bob@x.i2p"))
        kotlin.test.assertFalse(s.serverAdmin)
    }
}

