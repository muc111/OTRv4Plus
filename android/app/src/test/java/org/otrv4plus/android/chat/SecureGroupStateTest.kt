// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.OtrEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Secure groups in the chat model: labels, invitations and room state. */
class SecureGroupStateTest {

    private val room = "sealed@conference.otrv4plus.i2p"

    private fun state() = ChatState().also {
        it.bindAccount(AccountScope.of("owner@otrv4plus.i2p"))
        it.applyConnection(ConnectionStatus(stage = "connected", connected = true))
    }

    @Test
    fun `an MLS-decrypted room message is labelled encrypted, a plain one is not`() {
        val s = state()
        s.handle(OtrEvent.RoomMessageReceived(room, "alice", "secret", 1.0,
                                              encrypted = true, senderIdentity = "alice@x",
                                              verified = true))
        s.handle(OtrEvent.RoomMessageReceived("lobby@conference.x", "bob", "hi", 2.0))
        assertEquals(SecurityLabel.ENCRYPTED, s.messages(room).single().security)
        assertEquals(SecurityLabel.PLAINTEXT,
                     s.messages("lobby@conference.x").single().security)
        assertTrue(s.isSecureRoom(room))
        assertFalse(s.isSecureRoom("lobby@conference.x"))
    }

    @Test
    fun `an invitation waits for an answer and is never a notification`() {
        val s = state()
        assertFalse(s.handle(OtrEvent.GroupInvited("alice@x", room, verified = true)))
        assertEquals(listOf(room), s.pendingGroupInvites.map { it.room })
        s.clearGroupInvite(room)
        assertTrue(s.pendingGroupInvites.isEmpty())
    }

    @Test
    fun `joining makes the room secure and removal undoes it`() {
        val s = state()
        s.handle(OtrEvent.GroupChanged(room, "joined", 1, ""))
        assertTrue(s.isSecureRoom(room))
        assertTrue(s.isRoom(room))
        s.handle(OtrEvent.GroupChanged(room, "removed_us", 2, ""))
        assertFalse(s.isSecureRoom(room))
        assertNotNull(s.notice)
    }

    @Test
    fun `an invitation for a group we are in is shown with what accepting does`() {
        // rc.39 (device test, 2026-10-05): a member invites us back because our
        // copy stopped working. Hiding it left the inviter waiting for nothing.
        val s = state()
        s.handle(OtrEvent.GroupChanged(room, "created", 0, ""))
        s.handle(OtrEvent.GroupChanged(room, "reinvited", 0, "alice@x"))
        s.handle(OtrEvent.GroupInvited("alice@x", room, verified = false))
        assertEquals(listOf(room), s.pendingGroupInvites.map { it.room })
        val note = GroupText.describe(OtrEvent.GroupChanged(room, "reinvited", 0, "alice@x"))
        assertTrue(note != null && "already" in note && "replaced" in note)
    }

    @Test
    fun `a deleted group is no longer secure here`() {
        val s = state()
        s.handle(OtrEvent.GroupChanged(room, "joined", 1, ""))
        s.handle(OtrEvent.GroupChanged(room, "deleted", 0, ""))
        assertFalse(s.isSecureRoom(room))
        assertTrue("deleted" in GroupText.describe(OtrEvent.GroupChanged(room, "deleted", 0, ""))!!)
        assertTrue("creator" in GroupText.outcome("forbidden")!!)
    }

    @Test
    fun `the words say what is and is not protected`() {
        val idle = GroupText.describe(OtrEvent.GroupChanged(room, "idle_removed", 9, "carol@x"))
        assertTrue(idle != null && "carol@x" in idle && "Invite them again" in idle)
        assertTrue("ciphertext" in GroupText.header(true))
        assertTrue("not end-to-end encrypted" in GroupText.header(false))
        assertTrue("verified" in GroupText.memberLine("b@x", false, true, true))
        assertTrue("not verified" in GroupText.memberLine("b@x", false, false, true))
        assertTrue("(you)" in GroupText.memberLine("a@x", true, false, false))
        assertTrue("not SMP-verified" in
            GroupText.invite(OtrEvent.GroupInvited("a@x", room, verified = false)))
        assertTrue("inviter" in GroupText.refusal("inviter_fingerprint_mismatch", room))
        assertEquals(null, GroupText.outcome("ok"))
        assertTrue("OTRv4+" in GroupText.outcome("otr_required")!!)
    }
}
