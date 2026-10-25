// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SmpProgress
import org.otrv4plus.android.bridge.SmpState

class AttentionTest {

    private val bob = "bob@otrv4plus.i2p"
    private val room = "design-team@conference.otrv4plus.i2p"

    @Test fun aVerificationRequestNeedsTheUser() {
        val e = OtrEvent.SmpProgressed(bob, SmpProgress(1, 4, SmpState.SECRET_REQUIRED))
        assertEquals(Attention.Kind.VERIFICATION, Attention.of(e))
    }

    @Test fun ourOwnVerificationGoingAheadDoesNot() {
        val e = OtrEvent.SmpProgressed(bob, SmpProgress(2, 4, SmpState.IN_PROGRESS))
        assertNull(Attention.of(e))
    }

    @Test fun aGroupInvitationNeedsTheUser() {
        assertEquals(Attention.Kind.GROUP_INVITE,
                     Attention.of(OtrEvent.GroupInvited(bob, room, verified = true)))
    }

    // Owner (2026-10-25): the creator starts verifying, and every member is
    // asked -- by a notification too. Our own start ("verify_begun") is not.
    @Test fun theCreatorStartingAVerificationNeedsEveryMember() {
        assertEquals(Attention.Kind.GROUP_VERIFY,
                     Attention.of(OtrEvent.GroupChanged(room, "verify_started", 0, bob)))
        assertNull(Attention.of(OtrEvent.GroupChanged(room, "verify_begun", 0, "me@x.i2p")))
        assertNull(Attention.of(OtrEvent.GroupChanged(room, "verify_progress", 0, "")))
    }

    @Test fun theTextNamesNobodyAndNothing() {
        for (kind in Attention.Kind.values()) {
            for (leak in listOf("bob", "otrv4plus", "design", "@")) {
                assertFalse(kind.text, kind.text.contains(leak, ignoreCase = true))
            }
        }
        assertEquals("Group invitation", Attention.text(listOf(Attention.Kind.GROUP_INVITE)))
        assertEquals("2 things need your attention",
                     Attention.text(listOf(Attention.Kind.VERIFICATION, Attention.Kind.GROUP_INVITE)))
    }

    // -- the chat list: which row pulses --------------------------------------

    private fun chat(jid: String, smp: SmpState = SmpState.NOT_VERIFIED) = Conversation(
        jid = jid, displayName = jid, presence = Presence.UNKNOWN,
        security = org.otrv4plus.android.bridge.SecurityState.ENCRYPTED,
        lastMessage = null, unread = 0, smp = smp)

    @Test fun aChatWhoseVerificationWaitsOnUsPulses() {
        assertEquals(Attention.Kind.VERIFICATION,
                     Attention.forChat(chat(bob, SmpState.SECRET_REQUIRED), emptySet(), emptySet()))
    }

    @Test fun aRoomWithAnInvitationOrAJoinRequestPulses() {
        assertEquals(Attention.Kind.GROUP_INVITE, Attention.forChat(chat(room), setOf(room), emptySet()))
        assertEquals(Attention.Kind.ENTRY_REQUEST, Attention.forChat(chat(room), emptySet(), setOf(room)))
    }

    @Test fun anOrdinaryChatDoesNot() {
        for (state in listOf(SmpState.NOT_VERIFIED, SmpState.IN_PROGRESS, SmpState.VERIFIED, SmpState.FAILED)) {
            assertNull(state.name, Attention.forChat(chat(bob, state), setOf(room), setOf(room)))
        }
    }
}
