// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.security.InMemoryVault
import org.otrv4plus.android.security.Vault
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The reported defect: Dave signed in and saw Bob's conversation with Alice.
 *
 * THE ROOT CAUSE, so the tests below are read as covering it rather than as
 * covering a screen. The storage schema had no account in it:
 *
 *     Conversations ──► Messages
 *
 * A conversation was identified by the PEER's JID alone. Bob's history with
 * Alice and Dave's history with Alice were one vault entry, under one name, in
 * one global index called `chat.index`. Whoever signed in read it. On top of
 * that, `ChatState` and `PersistentMessageStore` are service singletons and
 * nothing ever told them the account had changed, so the roster, the drafts
 * and the unread badge survived a sign-in as somebody else too.
 *
 * Clearing the screen would have hidden it. What the fix does instead is make
 * the cross-account read unrepresentable: every vault name now carries the
 * account, and a store bound to no account reads nothing at all.
 *
 * THIS FILE MUST NOT BE DELETED. It is the permanent regression cover the
 * milestone asked for, and every test here fails against the old design.
 */
class AccountIsolationTest {

    private val bob = "bob@xmpp-elite.i2p"
    private val dave = "dave@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"

    private fun message(
        id: String,
        conversation: String = alice,
        body: String = "hello",
        outgoing: Boolean = false,
        at: Long = 1_000L,
    ) = Message(id, conversation, body, outgoing, at,
                SendState.NONE, SecurityLabel.PLAINTEXT)

    private fun contact(jid: String) = Contact(
        jid = jid, displayName = jid.substringBefore('@'),
        presence = PeerPresence.ONLINE,
        security = SecurityState.PLAINTEXT, smp = SmpState.NOT_VERIFIED,
        callAvailable = false)

    private fun storeFor(vault: Vault, account: String) =
        PersistentMessageStore(vault).apply { bind(AccountScope.of(account)) }

    // ── Bob → Dave, the reported sequence ───────────────────────────────────

    @Test
    fun `Bob's conversation with Alice is not visible to Dave`() {
        val vault: Vault = InMemoryVault()

        // 1-3. Bob authenticates, talks to Alice, it is persisted.
        storeFor(vault, bob).append(message("m1", body = "bob and alice"))

        // 4-6. Bob goes, Dave authenticates, conversations are loaded.
        val daves = storeFor(vault, dave)

        assertTrue(daves.conversationIds().isEmpty(),
            "Dave can see that a conversation exists")
        assertTrue(daves.messages(alice).isEmpty(),
            "Dave can read Bob's messages")
    }

    @Test
    fun `Dave's conversation with Alice is not visible to Bob`() {
        val vault: Vault = InMemoryVault()
        storeFor(vault, dave).append(message("m1", body = "dave and alice"))
        assertTrue(storeFor(vault, bob).messages(alice).isEmpty())
    }

    @Test
    fun `two accounts talking to the same person keep separate histories`() {
        // The case a peer-keyed schema cannot represent at all, and the
        // reason the fix is structural rather than a filter.
        val vault: Vault = InMemoryVault()
        storeFor(vault, bob).append(message("b1", body = "from bob"))
        storeFor(vault, dave).append(message("d1", body = "from dave"))

        assertEquals(listOf("from bob"),
            storeFor(vault, bob).messages(alice).map { it.body })
        assertEquals(listOf("from dave"),
            storeFor(vault, dave).messages(alice).map { it.body })
    }

    // ── process restart ─────────────────────────────────────────────────────

    @Test
    fun `a restart does not hand Bob's history to Dave`() {
        val vault: Vault = InMemoryVault()
        storeFor(vault, bob).append(message("m1"))

        // A new process: a brand-new store over the same vault.
        val afterRestart = PersistentMessageStore(vault)
        afterRestart.bind(AccountScope.of(dave))

        assertTrue(afterRestart.messages(alice).isEmpty())
        assertTrue(afterRestart.conversationIds().isEmpty())
    }

    @Test
    fun `a restart gives Bob his own history back`() {
        // The boundary must not be achieved by losing everything.
        val vault: Vault = InMemoryVault()
        storeFor(vault, bob).append(message("m1", body = "remember me"))

        val afterRestart = PersistentMessageStore(vault)
        afterRestart.bind(AccountScope.of(bob))

        assertEquals(listOf("remember me"),
            afterRestart.messages(alice).map { it.body })
    }

    // ── nothing is readable before an account is established ────────────────

    @Test
    fun `a store with no account reads nothing`() {
        val vault: Vault = InMemoryVault()
        storeFor(vault, bob).append(message("m1"))

        val unbound = PersistentMessageStore(vault)

        assertTrue(unbound.messages(alice).isEmpty())
        assertTrue(unbound.conversationIds().isEmpty())
        assertNull(unbound.lastMessage(alice))
        assertEquals(0, unbound.unread(alice))
    }

    @Test
    fun `a store with no account writes nothing`() {
        // The window the original defect was visible in: the service exists
        // before anyone has signed in. Nothing may land in it.
        val vault: Vault = InMemoryVault()
        val unbound = PersistentMessageStore(vault)

        assertFalse(unbound.append(message("m1")))
        assertTrue(unbound.messages(alice).isEmpty())
    }

    @Test
    fun `the constructor loads nothing`() {
        // The old version hydrated the global index in `init`, so the service
        // had the previous account's conversations in memory before a single
        // credential had been checked.
        val vault: Vault = InMemoryVault()
        storeFor(vault, bob).append(message("m1"))
        assertTrue(PersistentMessageStore(vault).conversationIds().isEmpty())
    }

    // ── rebinding a live store ──────────────────────────────────────────────

    @Test
    fun `rebinding drops the previous account's messages from memory`() {
        val vault: Vault = InMemoryVault()
        val store = PersistentMessageStore(vault)

        store.bind(AccountScope.of(bob))
        store.append(message("m1"))
        assertEquals(1, store.messages(alice).size)

        store.bind(AccountScope.of(dave))
        assertTrue(store.messages(alice).isEmpty(),
            "Bob's messages survived in memory after Dave signed in")
    }

    @Test
    fun `rebinding back restores the right account's messages`() {
        val vault: Vault = InMemoryVault()
        val store = PersistentMessageStore(vault)
        store.bind(AccountScope.of(bob))
        store.append(message("m1", body = "bob's"))
        store.bind(AccountScope.of(dave))
        store.bind(AccountScope.of(bob))
        assertEquals(listOf("bob's"), store.messages(alice).map { it.body })
    }

    @Test
    fun `rebinding to the same account keeps what is loaded`() {
        // A reconnect, which happens constantly on this transport. It must
        // not cost the user their loaded history.
        val vault: Vault = InMemoryVault()
        val store = storeFor(vault, bob)
        store.append(message("m1"))
        store.bind(AccountScope.of(bob))
        assertEquals(1, store.messages(alice).size)
    }

    @Test
    fun `a resource does not count as a different account`() {
        // `bob@host/phone` and `bob@host/desktop` are one person; the
        // resource is per-session. Treating them as two accounts would split
        // one person's history in half at every reconnect.
        val vault: Vault = InMemoryVault()
        storeFor(vault, "$bob/phone").append(message("m1"))
        assertEquals(1, storeFor(vault, "$bob/desktop").messages(alice).size)
    }

    @Test
    fun `case does not create a second account`() {
        val vault: Vault = InMemoryVault()
        storeFor(vault, "BOB@XMPP-ELITE.I2P").append(message("m1"))
        assertEquals(1, storeFor(vault, bob).messages(alice).size)
    }

    // ── signing out ─────────────────────────────────────────────────────────

    @Test
    fun `forgetting an account removes its history from the vault`() {
        val vault: Vault = InMemoryVault()
        val store = storeFor(vault, bob)
        store.append(message("m1"))
        store.forgetAccount()

        assertTrue(PersistentMessageStore(vault)
            .apply { bind(AccountScope.of(bob)) }
            .messages(alice).isEmpty())
    }

    @Test
    fun `forgetting one account leaves another account's history alone`() {
        // The vault is shared. A sign-out is not a licence to delete somebody
        // else's data off the device.
        val vault: Vault = InMemoryVault()
        storeFor(vault, dave).append(message("d1", body = "dave's"))

        val bobs = storeFor(vault, bob)
        bobs.append(message("b1"))
        bobs.forgetAccount()

        assertEquals(listOf("dave's"),
            storeFor(vault, dave).messages(alice).map { it.body })
    }

    @Test
    fun `forgetting leaves the store bound to nobody`() {
        val vault: Vault = InMemoryVault()
        val store = storeFor(vault, bob)
        store.append(message("m1"))
        store.forgetAccount()
        assertFalse(store.account.isAuthenticated)
        assertFalse(store.append(message("m2")),
            "the store accepted a write after the account was forgotten")
    }

    // ── the state that never reaches a disk ─────────────────────────────────

    @Test
    fun `Bob's contacts do not appear for Dave`() {
        val state = ChatState()
        state.bindAccount(AccountScope.of(bob))
        state.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        state.applyRoster(listOf(contact(alice)))
        assertTrue(state.conversations().any { it.jid == alice })

        state.bindAccount(AccountScope.of(dave))

        assertTrue(state.conversations().isEmpty(),
            "Bob's roster survived into Dave's session")
    }

    @Test
    fun `Bob's drafts do not appear for Dave`() {
        val state = ChatState()
        state.bindAccount(AccountScope.of(bob))
        state.setDraft(alice, "half a sentence Bob was typing")

        state.bindAccount(AccountScope.of(dave))

        assertEquals("", state.draft(alice))
    }

    @Test
    fun `an open conversation does not survive an account change`() {
        val state = ChatState()
        state.bindAccount(AccountScope.of(bob))
        state.open(alice)
        state.bindAccount(AccountScope.of(dave))
        assertNull(state.openConversation)
    }

    @Test
    fun `the connection view is reset rather than inherited`() {
        // A green "connected" carried across a sign-in is a claim about a
        // session that no longer exists.
        val state = ChatState()
        state.bindAccount(AccountScope.of(bob))
        state.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        state.bindAccount(AccountScope.of(dave))
        assertFalse(state.connection.connected)
        assertEquals(ChatState.Link.UNKNOWN, state.link)
    }

    @Test
    fun `rebinding to the same account does not discard a draft`() {
        val state = ChatState()
        state.bindAccount(AccountScope.of(bob))
        state.setDraft(alice, "still typing")
        state.bindAccount(AccountScope.of(bob))
        assertEquals("still typing", state.draft(alice))
    }

    // ── the ingestion guard ─────────────────────────────────────────────────

    @Test
    fun `a message for the old account is rejected`() {
        // A listener held by a replaced session can still deliver: the
        // callback belongs to the old client, not to us.
        val state = ChatState()
        state.bindAccount(AccountScope.of(dave))
        assertFalse(state.accepts(AccountScope.of(bob)))
    }

    @Test
    fun `a message for the current account is accepted`() {
        val state = ChatState()
        state.bindAccount(AccountScope.of(dave))
        assertTrue(state.accepts(AccountScope.of(dave)))
    }

    @Test
    fun `nothing is accepted while no account is bound`() {
        assertFalse(ChatState().accepts(AccountScope.of(bob)))
        assertFalse(ChatState().accepts(AccountScope.NONE))
    }

    @Test
    fun `an unread count does not cross an account boundary`() {
        val vault: Vault = InMemoryVault()
        val state = ChatState(storeFor(vault, bob))
        state.bindAccount(AccountScope.of(bob))
        state.applyConnection(ConnectionStatus(stage = "connected", connected = true))
        state.handle(OtrEvent.MessageReceived(alice, "unread", 1.0))
        assertTrue(state.conversations().first { it.jid == alice }.unread > 0)

        state.bindAccount(AccountScope.of(dave))

        assertTrue(state.conversations().none { it.jid == alice && it.unread > 0 },
            "Bob's unread badge became Dave's")
    }

    // ── the vault names themselves ──────────────────────────────────────────

    @Test
    fun `two accounts produce different entry names for the same peer`() {
        assertTrue(AccountScope.of(bob).entryFor(alice) !=
                   AccountScope.of(dave).entryFor(alice),
            "both accounts write the same vault entry, which is the defect")
    }

    @Test
    fun `two accounts have different indexes`() {
        assertTrue(AccountScope.of(bob).indexName !=
                   AccountScope.of(dave).indexName)
    }

    @Test
    fun `neither the account nor the peer appears in an entry name`() {
        // Names are not sealed, only values are. A directory listing must not
        // be a record of who uses this phone and who they talk to.
        val name = AccountScope.of(bob).entryFor(alice)
        for (fragment in listOf("bob", "alice", "@", "i2p", "xmpp-elite")) {
            assertFalse(name.contains(fragment), fragment)
        }
    }

    @Test
    fun `the index name gives away no more than an entry name does`() {
        val name = AccountScope.of(bob).indexName
        for (fragment in listOf("bob", "@", "i2p")) {
            assertFalse(name.contains(fragment), fragment)
        }
    }
}
