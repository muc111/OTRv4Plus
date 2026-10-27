// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.Message
import org.otrv4plus.android.chat.PersistentMessageStore
import org.otrv4plus.android.chat.SecurityLabel
import org.otrv4plus.android.chat.SendState
import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeniableChatTest {

    @Test fun `offered only once a session is established`() {
        assertTrue(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.SMP_VERIFIED, isRoom = false))
        assertTrue(DeniableChat.offered(SecurityState.FINGERPRINT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.PLAINTEXT, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.FINGERPRINT_MISMATCH, isRoom = false))
        assertFalse(DeniableChat.offered(SecurityState.ENCRYPTED, isRoom = true))
    }

    // Audit 2026-10-26 (docs/AUDIT_CLAIM_MATRIX.md §1): L1 is RESOLVED-CODE,
    // so the words describe the mechanism and its residuals and state no
    // deniability property.
    @Test fun `the words describe the mechanism and its residuals and state no property`() {
        val all = listOf(DeniableChat.ACTION, DeniableChat.TITLE, DeniableChat.BODY,
                         DeniableChat.outcome("made_deniable"),
                         DeniableChat.outcome("made_deniable_unconfirmed"),
                         DeniableChat.outcome("no_session"))
        for (word in listOf("deniable messaging", "pending external audit", "no longer proves",
                            "could have forged", "until it does", "unlinked")) {
            assertTrue(all.none { word in it.lowercase() }, word)
        }
        assertTrue("Not independently reviewed." in DeniableChat.BODY)
        // The label names the mechanism, as the dialog does (owner,
        // 2026-10-27: "mechanism is a fact, property is unproven"), and says
        // the chat ends (owner, the same day: "End chat & publish keys").
        assertEquals("End chat & publish keys…", DeniableChat.ACTION)
        assertEquals("Publish keys", DeniableChat.CONFIRM)
        for (label in listOf(DeniableChat.ACTION, DeniableChat.TITLE, DeniableChat.CONFIRM)) {
            assertFalse("deniab" in label.lowercase(), label)
        }
        // The mechanism.
        assertTrue("Publishes the keys used to authenticate this chat's messages" in DeniableChat.BODY)
        assertTrue("stay encrypted" in DeniableChat.BODY)
        assertTrue("asks your server to confirm" in DeniableChat.BODY)
        assertTrue("shares no keys with it" in DeniableChat.BODY)
        // The residuals: having talked (SPEC §10.1); a copy made before the
        // publication; a close that does not finish (TestCrashDuringClose,
        // TestMultiPartClose).
        assertTrue("does not hide that you two talked" in DeniableChat.BODY)
        assertTrue("A copy made before the keys are published, or a close that does not " +
                   "finish, can still be proof." in DeniableChat.BODY)
        // Confirmed only when the server said so; otherwise it says how far
        // the re-sending goes (CLOSING_MAX_TRIES, in memory only).
        assertTrue("confirmed" in DeniableChat.outcome("made_deniable"))
        val unconfirmed = DeniableChat.outcome("made_deniable_unconfirmed")
        assertTrue("not yet confirmed" in unconfirmed)
        assertTrue("up to 40 times, while it keeps running" in unconfirmed)
        assertTrue("can still be proof" in unconfirmed)
    }

    @Test fun `unconfirmed the history still goes because the session is closed either way`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice)
        DeniableChat.apply("made_deniable_unconfirmed", chat, alice)
        assertTrue(store.messages(alice).isEmpty())
    }

    // ── the history goes with the session (owner, 2026-10-26) ───────────────

    private class Disk : Vault {
        val entries = LinkedHashMap<String, ByteArray>()
        override fun put(name: String, bytes: ByteArray) { entries[name] = bytes.copyOf() }
        override fun get(name: String): ByteArray? = entries[name]?.copyOf()
        override fun remove(name: String) { entries.remove(name) }
        override fun clear() { entries.clear() }
    }

    private val owner = "owner@otrv4plus.i2p"
    private val alice = "alice@otrv4plus.i2p"
    private val bob = "bob@otrv4plus.i2p"

    private fun process(disk: Disk): Pair<ChatState, PersistentMessageStore> {
        val store = PersistentMessageStore(disk)
        val chat = ChatState(store).apply { bindVault(disk) }
        chat.bindAccount(AccountScope.of(owner))
        return chat to store
    }

    private fun say(store: PersistentMessageStore, id: String, to: String) =
        store.append(Message(id, to, "hi $id", false, 1_000L, SendState.NONE,
                             SecurityLabel.ENCRYPTED, ""))

    @Test fun `made deniable, the chat's history is deleted here and stays deleted`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice); say(store, "a2", alice); say(store, "b1", bob)
        val said = DeniableChat.apply("made_deniable", chat, alice)
        assertTrue("history was deleted" in said, said)
        assertTrue(store.messages(alice).isEmpty())
        assertFalse(disk.entries.containsKey(AccountScope.of(owner).entryFor(alice)),
            "gone from the vault, not only from the screen")
        assertEquals(1, store.messages(bob).size, "another chat is untouched")
        val (_, restarted) = process(disk)
        assertTrue(restarted.messages(alice).isEmpty(), "a restart does not bring it back")
    }

    @Test fun `the new session's messages are the only ones shown`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "old", alice)
        DeniableChat.apply("made_deniable", chat, alice)
        say(store, "new", alice)
        assertEquals(listOf("new"), store.messages(alice).map { it.id })
    }

    // ── the other side's copy goes too (owner, 2026-10-27) ──────────────────

    private fun at(store: PersistentMessageStore, id: String, to: String, ms: Long) =
        store.append(Message(id, to, "hi $id", false, ms, SendState.NONE,
                             SecurityLabel.ENCRYPTED, ""))

    @Test fun `keys published, what came before goes and the line and what came after stay`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        at(store, "old1", alice, 1_000L); at(store, "old2", alice, 2_000L)
        at(store, "new", alice, 9_000L); at(store, "b", bob, 1_500L)
        chat.handle(org.otrv4plus.android.bridge.OtrEvent.KeysPublished(alice, 5_000L, false, alice))
        val left = store.messages(alice)
        assertEquals(listOf("keys:5000:$alice", "new"), left.map { it.id })
        assertEquals(SecurityLabel.SYSTEM, left[0].security)
        assertTrue("$alice ended this chat and published its keys" in left[0].body, left[0].body)
        assertTrue("Earlier messages were removed from this device." in left[0].body)
        assertEquals(1, store.messages(bob).size, "another chat is untouched")
        val (_, restarted) = process(disk)
        assertEquals(listOf("keys:5000:$alice", "new"), restarted.messages(alice).map { it.id },
                     "the vault holds what the screen shows")
    }

    @Test fun `the same event twice leaves one line`() {
        val (chat, store) = process(Disk())
        at(store, "old", alice, 1_000L)
        val event = org.otrv4plus.android.bridge.OtrEvent.KeysPublished(alice, 5_000L, false, "")
        chat.handle(event); chat.handle(event)
        assertEquals(listOf("keys:5000:"), store.messages(alice).map { it.id })
    }

    @Test fun `the published lines describe what happened and claim nothing more`() {
        val lines = listOf(DeniableChat.published("", false), DeniableChat.published(alice, false),
                           DeniableChat.published("", true), DeniableChat.published(alice, true))
        for (line in lines) {
            assertFalse("deniab" in line.lowercase(), line)
            assertFalse("no longer proves" in line.lowercase(), line)
            assertTrue("removed from this device" in line, line)
        }
        assertTrue("your server confirmed them" in DeniableChat.published("", false))
        assertTrue("group keys" in DeniableChat.published(alice, true))
        assertTrue("your contact's app deletes its copy once its own keys are published" in
                   DeniableChat.BODY)
    }

    @Test fun `no session, nothing deleted`() {
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "a1", alice)
        DeniableChat.apply("no_session", chat, alice)
        assertEquals(1, store.messages(alice).size)
    }

    @Test fun `the dialog says the history goes`() {
        assertTrue("history is deleted from this device" in DeniableChat.BODY)
    }

    // ── groups (F4) ─────────────────────────────────────────────────────────

    @Test fun `the group words describe the mechanism and claim nothing more`() {
        val all = listOf(GroupDeniable.ACTION, GroupDeniable.TITLE, GroupDeniable.BODY,
                         GroupDeniable.outcome(true, "ok"), GroupDeniable.outcome(false, "x"))
        for (word in listOf("deniable messaging", "pending external audit", "no longer proves")) {
            assertTrue(all.none { word in it.lowercase() }, word)
        }
        assertTrue("Not independently reviewed." in GroupDeniable.BODY)
        assertEquals("Publish Group Keys…", GroupDeniable.ACTION)
        for (label in listOf(GroupDeniable.ACTION, GroupDeniable.TITLE, GroupDeniable.CONFIRM)) {
            assertFalse("deniab" in label.lowercase(), label)
        }
        assertTrue("any of them can make signatures under those keys" in GroupDeniable.BODY)
        assertTrue("while the app is running" in GroupDeniable.BODY)
        // MLS_SECURITY_HARDENING §1: release does not reach back, so no copy
        // may say the past is deniable.
        val group = listOf(GroupDeniable.ACTION, GroupDeniable.TITLE, GroupDeniable.BODY,
                           GroupDeniable.outcome(true, "ok"), GroupDeniable.outcome(false, "x"))
        assertTrue(group.none { "past messages are deniable" in it.lowercase() })
        assertTrue(group.none { "past messages" in it.lowercase() && "deniable" in it.lowercase() })
        assertTrue("copied before they are published stays signed" in GroupDeniable.BODY)
        assertTrue("stay encrypted" in GroupDeniable.BODY)
        assertTrue("stays secret" in GroupDeniable.BODY, "says the new key is not published")
        assertTrue("history is deleted from this device" in GroupDeniable.BODY)
    }

    @Test fun `while earlier keys wait for members the button is not offered and says why`() {
        // F4 containment (option A): keys go only once every member's app has
        // confirmed the new key (SecureGroups.keys_waiting).
        assertTrue(GroupDeniable.canPublish(emptyList()))
        assertFalse(GroupDeniable.canPublish(listOf("carol@x.i2p")))
        assertEquals("Publishing keys: waiting for 1 member", GroupDeniable.waiting(1))
        assertEquals("Publishing keys: waiting for 3 members", GroupDeniable.waiting(3))
        assertEquals("", GroupDeniable.waitingLine(emptyList()))
        val seven = (1..7).map { "m$it@x.i2p" }
        val line = GroupDeniable.waitingLine(seven)
        assertTrue("m5@x.i2p" in line && "m6@x.i2p" !in line && "and 2 more" in line, line)
        assertTrue("every member's app has confirmed it has your new key" in GroupDeniable.BODY)
        assertTrue("once every member's app has confirmed it" in GroupDeniable.outcome(true, "ok"))
        for (text in listOf(GroupDeniable.waiting(2), line)) {
            assertFalse("deniab" in text.lowercase(), text)
        }
    }

    @Test fun `made deniable the group's history goes and refused nothing goes`() {
        val room = "team@conference.otrv4plus.i2p"
        val disk = Disk()
        val (chat, store) = process(disk)
        say(store, "r1", room)
        GroupDeniable.apply(false, "commit_pending", chat, room)
        assertEquals(1, store.messages(room).size)
        val said = GroupDeniable.apply(true, "ok", chat, room)
        assertTrue("history was deleted" in said, said)
        assertTrue(store.messages(room).isEmpty())
    }
}
