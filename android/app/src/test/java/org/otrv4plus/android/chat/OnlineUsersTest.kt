// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Presence and security on the People list, from real events only.
 *
 * These properties used to be tested through a separate "online users"
 * list (`OnlineUsers.rows`), which nothing in the app still drew once People
 * became the one list. They are tested here on that one list, `directory`,
 * so the list the user sees is the list that is held to them.
 */
class OnlineUsersTest {

    private val me = "me@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    private fun contact(jid: String, presence: PeerPresence,
                        security: SecurityState = SecurityState.PLAINTEXT) =
        Contact(jid, jid.substringBefore('@').replaceFirstChar { it.uppercase() },
                presence, security, SmpState.NOT_VERIFIED, false)

    private fun state(vararg roster: Contact) = ChatState().apply {
        bindAccount(AccountScope.of(me))
        applyConnection(ConnectionStatus(stage = "connected", connected = true))
        applyRoster(roster.toList())
    }

    private fun online(s: ChatState) = s.directory()
        .filter { it.relation == OnlineUsers.Relation.ADDED_ONLINE }

    private fun row(s: ChatState, jid: String) = s.directory().single { it.jid == jid }

    @Test
    fun `only people the server says are online are online, and it updates live`() {
        val s = state(contact(alice, PeerPresence.ONLINE), contact(bob, PeerPresence.OFFLINE))
        assertEquals(listOf(alice), online(s).map { it.jid })
        s.applyRoster(listOf(contact(alice, PeerPresence.OFFLINE), contact(bob, PeerPresence.ONLINE)))
        assertEquals(listOf(bob), online(s).map { it.jid })
        s.applyRoster(listOf(contact(alice, PeerPresence.UNKNOWN), contact(bob, PeerPresence.OFFLINE)))
        assertEquals(emptyList(), online(s), "unknown presence was shown as online")
    }

    @Test
    fun `nobody is online while our own stream is down`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        s.applyConnection(ConnectionStatus(stage = "failed", connected = false))
        assertEquals(emptyList(), online(s), "a stale online outlived our connection")
    }

    @Test
    fun `online, encrypted and verified are separate facts`() {
        val s = state(contact(alice, PeerPresence.ONLINE))
        var r = row(s, alice)
        assertFalse(r.encrypted || r.verified, "being online was taken as more than being online")
        assertTrue("not encrypted" in r.facts)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.ENCRYPTED))
        r = row(s, alice)
        assertTrue(r.encrypted); assertFalse(r.verified)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.SMP_VERIFIED))
        s.handle(OtrEvent.SmpFinished(alice, SmpState.VERIFIED))
        r = row(s, alice)
        assertTrue(r.encrypted && r.verified)
        assertEquals(listOf("Online — Added", "OTR encrypted", "SMP verified"), r.facts)

        s.handle(OtrEvent.SessionChanged(alice, SecurityState.PLAINTEXT))
        r = row(s, alice)
        assertFalse(r.encrypted || r.verified, "a stale verified survived")
    }

    @Test
    fun `a person is one row and one conversation, whatever the spelling`() {
        val s = state(contact("Alice@XMPP-Elite.i2p/phone", PeerPresence.ONLINE))
        s.receive(OtrEvent.MessageReceived(alice, "hi", 1.0))
        val r = s.directory().single()
        assertEquals(alice, r.jid)
        s.open(r.jid)
        assertEquals(1, s.conversations().count { it.jid == alice }, "a duplicate conversation")
        assertEquals(listOf("hi"), s.messages(r.jid).map { it.body })
    }

    // -- search ------------------------------------------------------------------

    private fun entry(jid: String, name: String,
                      relation: OnlineUsers.Relation = OnlineUsers.Relation.ADDED_ONLINE) =
        OnlineUsers.Entry(jid, name, relation, encrypted = false, verified = false)

    @Test
    fun `search matches name or address, ignores case, keeps order`() {
        val list = listOf(entry(alice, "Alice"), entry(bob, "Bob"),
                          entry("carol@other.i2p", "Carol"))
        assertEquals(list, OnlineUsers.search(list, "  "))
        assertEquals(listOf(alice), OnlineUsers.search(list, "ALI").map { it.jid })
        assertEquals(listOf(alice, bob), OnlineUsers.search(list, "xmpp-elite").map { it.jid })
        assertEquals(emptyList(), OnlineUsers.search(list, "zed"))
    }

    @Test
    fun `search over a thousand people stays a local filter`() {
        val many = (0 until 1000).map { entry("user$it@xmpp-elite.i2p", "User $it") }
        val hit = OnlineUsers.search(many, "user99")
        assertEquals(listOf("user99", "user990", "user991", "user992", "user993",
                            "user994", "user995", "user996", "user997", "user998",
                            "user999"),
                     hit.map { it.jid.substringBefore('@') })
    }

    // -- details and the button ----------------------------------------------------

    @Test
    fun `details state relation, session and verification in words`() {
        val d = OnlineUsers.details(entry(alice, "Alice", OnlineUsers.Relation.ONLINE_ADD)).toMap()
        assertEquals(alice, d["Address"])
        assertEquals("Online", d["Status"])
        assertEquals("no session (not a contact yet)", d["OTRv4+"])
        assertEquals("not verified with SMP", d["Identity"])
        val v = OnlineUsers.details(OnlineUsers.Entry(bob, "Bob",
            OnlineUsers.Relation.ADDED_ONLINE, encrypted = true, verified = true)).toMap()
        assertEquals("encrypted", v["OTRv4+"])
        assertEquals("SMP verified", v["Identity"])
    }

    @Test
    fun `the people button counts who is online and flags a waiting request`() {
        val list = listOf(entry(alice, "Alice"),
                          entry(bob, "Bob", OnlineUsers.Relation.ONLINE_ADD),
                          entry("c@x.i2p", "C", OnlineUsers.Relation.ADDED_OFFLINE))
        assertEquals("People (2)", OnlineUsers.peopleButton(list))
        val asking = list + entry("d@x.i2p", "D", OnlineUsers.Relation.ACCEPT)
        assertEquals("People (2) •", OnlineUsers.peopleButton(asking))
    }

    @Test
    fun `a welcome room the server will not let us create says so`() {
        for (code in listOf("not_allowed", "forbidden", "registration_required")) {
            val said = OnlineUsers.welcomeCreated(false, code, "You are banned from this room.",
                                                  emptyList())
            assertEquals(OnlineUsers.WELCOME_NOT_PERMITTED, said, code)
            assertFalse("banned" in said)
        }
        assertTrue("timed out" in OnlineUsers.welcomeCreated(false, "timeout", "timed out",
                                                             emptyList()))
    }
}
