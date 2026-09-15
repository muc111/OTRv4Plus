// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.SecurityState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The model, and the security boundary baked into it.
 *
 * The most important assertions in this file are the ones about what does NOT
 * happen: no amount of connection success promotes a message to ENCRYPTED, and
 * "we have not heard" never collapses into "offline".
 */
class ChatModelsTest {

    private val alice = "alice@xmpp-elite.i2p"

    // -- message identity ----------------------------------------------------

    @Test
    fun `outgoing ids are unique per message`() {
        // Sending the same word twice must produce two messages.
        val a = MessageId.outgoing(alice, 1)
        val b = MessageId.outgoing(alice, 2)
        assertNotEquals(a, b)
    }

    @Test
    fun `outgoing ids are per conversation`() {
        assertNotEquals(
            MessageId.outgoing(alice, 1),
            MessageId.outgoing("bob@xmpp-elite.i2p", 1),
        )
    }

    @Test
    fun `the same inbound event produces the same id`() {
        // So a replayed event collapses instead of showing twice.
        val first = MessageId.inbound(alice, 1_000L, "hello")
        val second = MessageId.inbound(alice, 1_000L, "hello")
        assertEquals(first, second)
    }

    @Test
    fun `inbound ids differ by time`() {
        assertNotEquals(
            MessageId.inbound(alice, 1_000L, "hello"),
            MessageId.inbound(alice, 2_000L, "hello"),
        )
    }

    @Test
    fun `inbound ids differ by body`() {
        assertNotEquals(
            MessageId.inbound(alice, 1_000L, "hello"),
            MessageId.inbound(alice, 1_000L, "goodbye"),
        )
    }

    @Test
    fun `inbound ids differ by sender`() {
        assertNotEquals(
            MessageId.inbound(alice, 1_000L, "hello"),
            MessageId.inbound("carol@xmpp-elite.i2p", 1_000L, "hello"),
        )
    }

    // -- presence ------------------------------------------------------------

    @Test
    fun `presence is unknown before anything is known`() {
        // Not offline. A freshly added contact has not been reported absent;
        // nothing has been reported at all.
        assertEquals(Presence.UNKNOWN, Presence.of(online = false, known = false))
        assertEquals(Presence.UNKNOWN, Presence.of(online = true, known = false))
    }

    @Test
    fun `presence reflects what the server said once it is known`() {
        assertEquals(Presence.ONLINE, Presence.of(online = true, known = true))
        assertEquals(Presence.OFFLINE, Presence.of(online = false, known = true))
    }

    // -- the security boundary ----------------------------------------------

    @Test
    fun `an unencrypted session labels inbound messages plaintext`() {
        assertEquals(
            SecurityLabel.PLAINTEXT,
            SecurityLabel.forInbound(SecurityState.PLAINTEXT),
        )
    }

    @Test
    fun `only a real session labels a message encrypted`() {
        for (state in listOf(
            SecurityState.ENCRYPTED,
            SecurityState.FINGERPRINT,
            SecurityState.SMP_VERIFIED,
        )) {
            assertEquals(SecurityLabel.ENCRYPTED, SecurityLabel.forInbound(state))
        }
    }

    @Test
    fun `a fingerprint mismatch is never labelled encrypted`() {
        // The engine is saying the peer's long-term key is not the one pinned
        // for them. Encrypted-to-somebody is true and is exactly the wrong
        // thing to tell the user, because the somebody is the open question.
        assertEquals(
            SecurityLabel.UNKNOWN,
            SecurityLabel.forInbound(SecurityState.FINGERPRINT_MISMATCH),
        )
    }

    @Test
    fun `every security state has a deliberate label`() {
        // Catches a state added to the engine and never considered here. The
        // `when` is exhaustive so this cannot throw, but the assertion also
        // pins the rule that ONLY the three session states read as encrypted
        // -- a new state defaulting into ENCRYPTED would be a false claim.
        val encrypted = SecurityState.entries.filter {
            SecurityLabel.forInbound(it) == SecurityLabel.ENCRYPTED
        }
        assertEquals(
            listOf(
                SecurityState.ENCRYPTED,
                SecurityState.FINGERPRINT,
                SecurityState.SMP_VERIFIED,
            ),
            encrypted,
        )
    }

    @Test
    fun `send state and security are independent axes`() {
        // A message can be delivered and unencrypted, or encrypted and failed.
        // Folding them into one status is how a UI shows a padlock because a
        // send succeeded.
        val delivered = Message(
            id = "m1", conversationId = alice, body = "hi", outgoing = true,
            at = 1L, sendState = SendState.SENT,
            security = SecurityLabel.PLAINTEXT,
        )
        assertEquals(SendState.SENT, delivered.sendState)
        assertEquals(SecurityLabel.PLAINTEXT, delivered.security)
    }

    @Test
    fun `queued is neither sent nor failed`() {
        // The state the first version of this app got wrong: the engine holds
        // the text until a session exists, which is not a failure.
        assertTrue(SendState.QUEUED != SendState.SENT)
        assertTrue(SendState.QUEUED != SendState.FAILED)
    }

    // -- conversation --------------------------------------------------------

    @Test
    fun `preview collapses newlines and is bounded`() {
        val long = "a".repeat(500)
        val conversation = Conversation(
            jid = alice, displayName = alice, presence = Presence.UNKNOWN,
            security = SecurityState.PLAINTEXT,
            lastMessage = Message("m", alice, "line\nbreak$long", false, 1L,
                                  SendState.NONE, SecurityLabel.PLAINTEXT),
            unread = 0,
        )
        assertTrue(conversation.preview.length <= 120)
        assertTrue(!conversation.preview.contains('\n'))
    }

    @Test
    fun `a conversation with no history has an empty preview`() {
        val conversation = Conversation(
            jid = alice, displayName = alice, presence = Presence.UNKNOWN,
            security = SecurityState.PLAINTEXT, lastMessage = null, unread = 0,
        )
        assertEquals("", conversation.preview)
        assertEquals(0L, conversation.lastAt)
    }
}
