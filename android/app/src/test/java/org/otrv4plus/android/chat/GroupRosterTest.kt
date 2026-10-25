// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.GroupMember
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GroupRosterTest {

    private fun m(jid: String, me: Boolean = false, verified: Boolean = false, failed: Boolean = false) =
        GroupMember(jid = jid, fingerprint = "", me = me, verified = verified, bound = verified,
                    failed = failed)

    private val hundred: List<GroupMember> =
        listOf(m("alice@x", me = true)) +
            (1..96).map { m("u%02d@x".format(it), verified = true) } +
            listOf(m("eve@x", failed = true), m("mallory@x", failed = true), m("zed@x"))

    @Test fun `a hundred members is one summary line`() {
        assertEquals("100 members · 96 verified · 2 failed · 1 not verified yet",
                     GroupRoster.summary(hundred, emptyMap()))
        assertEquals("Members: asking the group…", GroupRoster.summary(emptyList(), emptyMap()))
    }

    @Test fun `sections put failed first and count each`() {
        val s = GroupRoster.sections(hundred, emptyMap(), isCreator = true)
        assertEquals(listOf("Verification failed (2)", "Not verified yet (1)", "Verified (96)", "You"),
                     s.map { it.title })
        assertEquals(listOf("eve@x", "mallory@x"), s[0].rows.map { it.jid })
        assertEquals("eve", s[0].rows[0].name)
    }

    @Test fun `only the creator sees remove and never on their own row`() {
        val creator = GroupRoster.sections(hundred, emptyMap(), isCreator = true).flatMap { it.rows }
        assertTrue(creator.filter { it.status != GroupRoster.Status.YOU }.all { it.canRemove })
        assertFalse(creator.single { it.status == GroupRoster.Status.YOU }.canRemove)
        val member = GroupRoster.sections(hundred, emptyMap(), isCreator = false).flatMap { it.rows }
        assertTrue(member.none { it.canRemove })
    }

    @Test fun `the running verification wins over a lagging member list`() {
        val verify = mapOf("zed@x" to "running", "eve@x" to "failed", "u01@x" to "failed")
        assertEquals(GroupRoster.Status.CHECKING, GroupRoster.status(m("zed@x"), verify))
        assertEquals(GroupRoster.Status.FAILED, GroupRoster.status(m("u01@x", verified = true), verify))
        assertEquals(GroupRoster.Status.VERIFIED,
                     GroupRoster.status(m("eve@x", failed = true), mapOf("eve@x" to "verified")))
    }

    @Test fun `search narrows by address and keeps the counts honest`() {
        val s = GroupRoster.sections(hundred, emptyMap(), query = "MALL", isCreator = true)
        assertEquals(listOf("Verification failed (1)"), s.map { it.title })
    }

    @Test fun `remove who failed names exactly them`() {
        assertEquals(listOf("eve@x", "mallory@x"), GroupRoster.failed(hundred, emptyMap()))
        assertEquals("Remove 2 who failed verification", GroupRoster.removeFailedButton(2))
        assertTrue("eve@x" in GroupRoster.removeConfirm(listOf("eve@x")))
        assertTrue("2 members" in GroupRoster.removeConfirm(listOf("eve@x", "mallory@x")))
    }

    @Test fun `the finished line is counts not names`() {
        val names = (1..97).joinToString(",") { "u$it@x" }
        val line = GroupText.verifyFinished("team@rooms.x", "verified=$names;excluded=eve@x,mallory@x")
        assertTrue(line.startsWith("Verification of team@rooms.x finished: 97 verified, 2 failed"), line)
        assertFalse("u5@x" in line)
        assertEquals("Verification of r finished: 3 verified.", GroupText.verifyFinished("r", "verified=a,b,c;excluded="))
    }
}
