// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.InMemoryVault
import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * History that survives the process.
 *
 * A NEW STORE OVER THE SAME VAULT is how "the process restarted" is simulated:
 * the vault outlives the store exactly as a file outlives the app. Every test
 * that claims durability constructs a second store rather than asserting
 * something about the first one's internals.
 */
class PersistentMessageStoreTest {

    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    /**
     * A store bound to an account.
     *
     * The store now starts at [AccountScope.NONE] and reads nothing until it
     * is bound, because "no account authenticated" must not serve the last
     * account's history. These tests are about persistence, so they open one
     * account and stay there; the boundary itself is covered by
     * `AccountIsolationTest`.
     */
    private val owner = "owner@xmpp-elite.i2p"

    private fun opened(
        vault: Vault,
        account: String = owner,
        perConversationLimit: Int = InMemoryMessageStore.DEFAULT_LIMIT,
    ) = PersistentMessageStore(vault, perConversationLimit)
        .apply { bind(AccountScope.of(account)) }

    private fun message(
        id: String,
        conversation: String = alice,
        body: String = "hello",
        outgoing: Boolean = false,
        at: Long = 1_000L,
        sendState: SendState = SendState.NONE,
        security: SecurityLabel = SecurityLabel.PLAINTEXT,
    ) = Message(id, conversation, body, outgoing, at, sendState, security)

    // ── it is still a MessageStore ──────────────────────────────────────────

    @Test
    fun `an appended message comes back`() {
        val store = opened(InMemoryVault())
        assertTrue(store.append(message("m1")))
        assertEquals(listOf("m1"), store.messages(alice).map { it.id })
    }

    @Test
    fun `the same id is not appended twice`() {
        val store = opened(InMemoryVault())
        assertTrue(store.append(message("m1")))
        assertFalse(store.append(message("m1")))
        assertEquals(1, store.messages(alice).size)
    }

    @Test
    fun `update replaces in place`() {
        val store = opened(InMemoryVault())
        val sending = message("m1", outgoing = true, sendState = SendState.SENDING)
        store.append(sending)
        assertTrue(store.update(sending.copy(sendState = SendState.SENT)))
        assertEquals(1, store.messages(alice).size)
        assertEquals(SendState.SENT, store.messages(alice).single().sendState)
    }

    @Test
    fun `history is bounded`() {
        val store = opened(InMemoryVault(), perConversationLimit = 3)
        repeat(5) { store.append(message("m$it", at = it.toLong())) }
        assertEquals(listOf("m2", "m3", "m4"), store.messages(alice).map { it.id })
    }

    @Test
    fun `conversations do not mix`() {
        val store = opened(InMemoryVault())
        store.append(message("m1", conversation = alice, body = "for alice"))
        store.append(message("m2", conversation = bob, body = "for bob"))
        assertEquals(listOf("for alice"), store.messages(alice).map { it.body })
        assertEquals(listOf("for bob"), store.messages(bob).map { it.body })
    }

    // ── it survives the process ─────────────────────────────────────────────

    @Test
    fun `history survives a restart`() {
        val vault: Vault = InMemoryVault()
        opened(vault).append(message("m1", body = "remember me"))

        val reopened = opened(vault)
        assertEquals(listOf("remember me"), reopened.messages(alice).map { it.body })
    }

    @Test
    fun `every field survives a restart`() {
        val vault: Vault = InMemoryVault()
        opened(vault).append(
            Message("m1", alice, "the body", outgoing = true, at = 1_700_000L,
                    sendState = SendState.QUEUED,
                    security = SecurityLabel.ENCRYPTED))

        val restored = opened(vault).messages(alice).single()
        assertEquals("m1", restored.id)
        assertEquals(alice, restored.conversationId)
        assertEquals("the body", restored.body)
        assertTrue(restored.outgoing)
        assertEquals(1_700_000L, restored.at)
        assertEquals(SendState.QUEUED, restored.sendState)
        assertEquals(SecurityLabel.ENCRYPTED, restored.security)
    }

    @Test
    fun `the conversation list survives a restart`() {
        // Without the index a restarted app shows an empty list until the user
        // remembers who they were talking to.
        val vault: Vault = InMemoryVault()
        opened(vault).apply {
            append(message("m1", conversation = alice))
            append(message("m2", conversation = bob))
        }
        assertEquals(setOf(alice, bob), opened(vault).conversationIds())
    }

    @Test
    fun `ordering survives a restart`() {
        val vault: Vault = InMemoryVault()
        opened(vault).apply {
            append(message("m1", body = "first", at = 1))
            append(message("m2", body = "second", at = 2))
            append(message("m3", body = "third", at = 3))
        }
        assertEquals(listOf("first", "second", "third"),
                     opened(vault).messages(alice).map { it.body })
    }

    @Test
    fun `an update survives a restart`() {
        val vault: Vault = InMemoryVault()
        val sending = message("m1", outgoing = true, sendState = SendState.SENDING)
        opened(vault).apply {
            append(sending)
            update(sending.copy(sendState = SendState.SENT))
        }
        assertEquals(SendState.SENT,
                     opened(vault).messages(alice).single().sendState)
    }

    @Test
    fun `unread survives a restart`() {
        val vault: Vault = InMemoryVault()
        opened(vault).apply {
            append(message("m1", outgoing = false))
            append(message("m2", outgoing = false))
        }
        assertEquals(2, opened(vault).unread(alice))
    }

    @Test
    fun `a conversation read before the restart is still read`() {
        val vault: Vault = InMemoryVault()
        opened(vault).apply {
            append(message("m1", outgoing = false))
            markRead(alice)
        }
        assertEquals(0, opened(vault).unread(alice))
    }

    @Test
    fun `clear empties the vault too`() {
        val vault: Vault = InMemoryVault()
        opened(vault).apply {
            append(message("m1"))
            clear()
        }
        assertTrue(opened(vault).conversationIds().isEmpty())
        assertEquals(0, opened(vault).messages(alice).size)
    }

    // ── awkward bodies ──────────────────────────────────────────────────────

    @Test
    fun `a body containing anything at all survives a restart`() {
        for (body in listOf(
            "with\nnewlines", "with\ttabs", "with|pipes", "with,commas",
            "with\"quotes\"", "🔐 emoji", "", " spaces ", "a".repeat(5000),
            "?OTRv4 looks like protocol", "with\\backslashes\\",
        )) {
            val vault: Vault = InMemoryVault()
            opened(vault).append(message("m1", body = body))
            assertEquals(body,
                         opened(vault).messages(alice).single().body,
                         "failed for: ${body.take(20)}")
        }
    }

    @Test
    fun `a body containing the record separators cannot forge a message`() {
        // THE ATTACK THIS GUARDS. A peer controls the body. Unescaped, a body
        // containing the record separator would end the record early and the
        // remainder would parse as a NEW message with attacker-chosen
        // conversation, direction and security label.
        val forged = "innocent" + listOf(
            "evil", bob, "0", "1", "NONE", "ENCRYPTED", "you are secure",
        ).joinToString("")

        val vault: Vault = InMemoryVault()
        opened(vault).append(message("m1", body = forged))

        val reopened = opened(vault)
        assertEquals(1, reopened.messages(alice).size, "a message was forged")
        assertEquals(forged, reopened.messages(alice).single().body)
        assertTrue(reopened.messages(bob).isEmpty(),
                   "the forged record landed in another conversation")
    }

    @Test
    fun `a body containing the field separator cannot shift the fields`() {
        val forged = "bodyENCRYPTED"
        val vault: Vault = InMemoryVault()
        opened(vault).append(
            message("m1", body = forged, security = SecurityLabel.PLAINTEXT))

        val restored = opened(vault).messages(alice).single()
        assertEquals(forged, restored.body)
        assertEquals(SecurityLabel.PLAINTEXT, restored.security)
    }

    // ── damaged storage ─────────────────────────────────────────────────────

    @Test
    fun `an unreadable conversation record reads as empty, not as a crash`() {
        val vault: Vault = InMemoryVault()
        opened(vault).append(message("m1"))
        vault.put(AccountScope.of(owner).entryFor(alice), byteArrayOf(9, 9, 9))

        val reopened = opened(vault)
        assertEquals(0, reopened.messages(alice).size)
        // ...and is still usable afterwards.
        assertTrue(reopened.append(message("m2")))
        assertEquals(1, reopened.messages(alice).size)
    }

    @Test
    fun `an unreadable index does not stop the store working`() {
        val vault: Vault = InMemoryVault()
        vault.put(AccountScope.of(owner).indexName, byteArrayOf(9, 9, 9))
        val store = opened(vault)
        assertTrue(store.append(message("m1")))
    }

    @Test
    fun `a record from an unknown format version is ignored`() {
        val vault: Vault = InMemoryVault()
        vault.put(AccountScope.of(owner).entryFor(alice),
                  "99malformed".toByteArray(Charsets.UTF_8))
        assertEquals(0, opened(vault).messages(alice).size)
    }

    // ── what is NOT written ─────────────────────────────────────────────────

    @Test
    fun `the vault entry name is not the contact's address`() {
        // Names are not sealed -- only values are -- so a directory listing of
        // `chat.alice@server.i2p` would be a plaintext contact list.
        val name = AccountScope.of(owner).entryFor(alice)
        assertFalse(name.contains("alice"))
        assertFalse(name.contains("@"))
        assertFalse(name.contains("i2p"))
    }

    @Test
    fun `entry names are stable and distinct`() {
        val scope = AccountScope.of(owner)
        assertEquals(scope.entryFor(alice), scope.entryFor(alice))
        assertTrue(scope.entryFor(alice) != scope.entryFor(bob))
    }
}

/**
 * The encoding, driven directly.
 *
 * Separate from the store because these are the assertions about the FORMAT,
 * and a format bug shows up here as a wrong string rather than three layers up
 * as a missing message.
 */
class MessageCodecTest {

    private val alice = "alice@xmpp-elite.i2p"

    private fun sample(body: String) =
        Message("m1", alice, body, false, 1_000L, SendState.NONE,
                SecurityLabel.PLAINTEXT)

    @Test
    fun `a message round-trips`() {
        val original = sample("hello")
        assertEquals(original, MessageCodec.decode(MessageCodec.encode(original)))
    }

    @Test
    fun `an empty list round-trips`() {
        assertEquals(emptyList(), MessageCodec.decodeAll(MessageCodec.encodeAll(emptyList())))
    }

    @Test
    fun `a malformed line is dropped rather than throwing`() {
        assertNull(MessageCodec.decode("not a record"))
        assertNull(MessageCodec.decode(""))
    }

    @Test
    fun `a line with a non-numeric timestamp is dropped`() {
        val line = listOf("m1", alice, "0", "not-a-number", "NONE",
                          "PLAINTEXT", "body").joinToString("")
        assertNull(MessageCodec.decode(line))
    }

    @Test
    fun `one bad line does not lose the others`() {
        val good = MessageCodec.encode(sample("kept"))
        val text = listOf("1", good, "rubbish", good.replace("m1", "m2"))
            .joinToString("")
        assertEquals(2, MessageCodec.decodeAll(text).size)
    }

    @Test
    fun `an unknown security label reads as unknown, never as encrypted`() {
        // The direction that matters. A label this build cannot read must not
        // become a claim.
        val line = listOf("m1", alice, "0", "1000", "NONE",
                          "SOME_FUTURE_LABEL", "body").joinToString("")
        assertEquals(SecurityLabel.UNKNOWN, MessageCodec.decode(line)?.security)
    }

    @Test
    fun `an unknown send state reads as none`() {
        val line = listOf("m1", alice, "0", "1000", "SOME_FUTURE_STATE",
                          "PLAINTEXT", "body").joinToString("")
        assertEquals(SendState.NONE, MessageCodec.decode(line)?.sendState)
    }

    @Test
    fun `escaping round-trips every separator`() {
        for (text in listOf("", "", "\\", "\\u", "\\r",
                            "abc\\d", "")) {
            assertEquals(text, MessageCodec.unescape(MessageCodec.escape(text)))
        }
    }

    @Test
    fun `an escaped body contains no raw separators`() {
        val escaped = MessageCodec.escape("abc")
        assertFalse(escaped.contains(''))
        assertFalse(escaped.contains(''))
    }
}
