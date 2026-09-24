// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.LatchedVault
import org.otrv4plus.android.security.Vault
import org.otrv4plus.android.security.WipeAndExit
import org.otrv4plus.android.security.WipeAndExit.Step
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The handset report, as a test: "old conversations reappear after Wipe &
 * Exit".
 *
 * [Disk] is the vault's directory: it outlives every "process". A process is
 * a fresh [LatchedVault], message store and [ChatState] over the same disk,
 * wired the way `OtrConnectionService` wires them. The wipe runs the real
 * [WipeAndExit.Runner] in the real order, with each step doing what the
 * service's step does to these objects.
 */
class WipePersistenceTest {

    /** A vault whose contents can be inspected, standing in for the files. */
    private class Disk : Vault {
        val entries = LinkedHashMap<String, ByteArray>()
        override fun put(name: String, bytes: ByteArray) { entries[name] = bytes.copyOf() }
        override fun get(name: String): ByteArray? = entries[name]?.copyOf()
        override fun remove(name: String) { entries.remove(name) }
        override fun clear() { entries.clear() }
    }

    private class Process(disk: Disk) {
        val vault = LatchedVault(disk)
        val store = PersistentMessageStore(vault)
        val chat = ChatState(store).apply { bindVault(vault) }
    }

    private val owner = "owner@xmpp-elite.i2p"
    private val alice = "alice@xmpp-elite.i2p"
    private val bob = "bob@xmpp-elite.i2p"

    private fun signIn(p: Process) = p.chat.bindAccount(AccountScope.of(owner))

    private fun say(p: Process, id: String, to: String) {
        p.store.append(Message(id, to, "hello $id", false, 1_000L,
                               SendState.NONE, SecurityLabel.ENCRYPTED))
    }

    private fun jids(p: Process) = p.chat.conversations().map { it.jid }.toSet()

    /** The service's wipe, step for step, over this process's objects. */
    private fun wipe(p: Process, duringEngine: () -> Unit = {}): WipeAndExit.Report =
        WipeAndExit.Runner(mapOf(
            Step.STOP_BACKGROUND to { p.vault.latch() },
            Step.CLEAR_NOTIFICATIONS to { },
            Step.CLEAR_MEMORY to { p.chat.bindAccount(AccountScope.NONE) },
            Step.DESTROY_VAULT to { p.vault.clear() },
            Step.CLEAR_CACHE to { },
            Step.WIPE_ENGINE to duringEngine,
            Step.EXIT to { },
        )).run()

    @Test
    fun `conversations survive a restart, and do not survive a wipe`() {
        val disk = Disk()

        val first = Process(disk)
        signIn(first)
        say(first, "m1", alice)
        say(first, "m2", bob)
        first.chat.savedContacts.save(alice, "Alice")
        assertEquals(setOf(alice, bob), jids(first))

        // Exit and reopen: still there. This is the behaviour the wipe has to
        // undo, so it is asserted rather than assumed.
        val second = Process(disk)
        signIn(second)
        assertEquals(setOf(alice, bob), jids(second))
        assertEquals(listOf("m1"), second.store.messages(alice).map { it.id })

        assertTrue(wipe(second).ok)

        // Inspected, not inferred: nothing is left in the vault.
        assertEquals(emptyMap(), disk.entries.mapValues { it.value.size })

        // Reopen, sign in to the SAME account: nothing comes back.
        val third = Process(disk)
        signIn(third)
        assertEquals(emptySet(), jids(third))
        assertEquals(emptyList(), third.store.messages(alice))
        assertEquals(emptyList(), third.chat.savedContacts.all())

        // And again.
        val fourth = Process(disk)
        signIn(fourth)
        assertEquals(emptySet(), jids(fourth))
    }

    @Test
    fun `a write that lands while the engine is being torn down does not resurrect anything`() {
        // The drain loop is cancelled, not joined; a message it was already
        // storing, a mark-read from a screen, a send that completes -- each
        // reaches the store AFTER memory and vault are gone, during the
        // seconds the engine step spends closing the tunnel.
        val disk = Disk()
        val p = Process(disk)
        signIn(p)
        say(p, "m1", alice)
        val lateStore = p.store
        val lateContacts = p.chat.savedContacts

        wipe(p, duringEngine = {
            // Re-bound by something that had not caught up, then written to.
            lateStore.bind(AccountScope.of(owner))
            lateStore.append(Message("late", bob, "late", false, 2_000L,
                                     SendState.NONE, SecurityLabel.ENCRYPTED))
            lateStore.markRead(alice)
            lateContacts.bind(AccountScope.of(owner))
            lateContacts.save(bob, "Bob")
        })

        assertEquals(emptySet(), disk.entries.keys)
        val next = Process(disk)
        signIn(next)
        assertEquals(emptySet(), jids(next))
    }

    @Test
    fun `memory and the vault are gone before the engine step starts`() {
        // The engine step is bounded by network timeouts (tens of seconds
        // over I2P). Whatever it is doing, a screen that looks at the chat
        // state during it must find nothing, and the disk must hold nothing.
        val disk = Disk()
        val p = Process(disk)
        signIn(p)
        say(p, "m1", alice)
        var seenDuringEngine: Set<String>? = null
        var diskDuringEngine: Set<String>? = null
        wipe(p, duringEngine = {
            seenDuringEngine = jids(p)
            diskDuringEngine = disk.entries.keys.toSet()
        })
        assertEquals(emptySet(), seenDuringEngine)
        assertEquals(emptySet(), diskDuringEngine)
    }
}
