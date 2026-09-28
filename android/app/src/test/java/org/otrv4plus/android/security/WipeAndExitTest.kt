// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.security

import org.otrv4plus.android.security.WipeAndExit.Category
import org.otrv4plus.android.security.WipeAndExit.Step
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Wipe & Exit's order, coverage and idempotence, executed. */
class WipeAndExitTest {

    private fun recording(
        log: MutableList<Step>,
        failing: Set<Step> = emptySet(),
    ): Map<Step, () -> Unit> =
        Step.entries.associateWith { step ->
            {
                log += step
                if (step in failing) throw IllegalStateException("boom")
            }
        }

    @Test
    fun `the steps run in the documented order`() {
        val log = mutableListOf<Step>()
        val report = WipeAndExit.Runner(recording(log)).run()
        assertEquals(WipeAndExit.ORDER, log)
        assertTrue(report.ok)
    }

    @Test
    fun `background work stops before anything is destroyed`() {
        // Otherwise the drain loop writes a message into the vault after it
        // was destroyed, or the reconnect loop brings a session back.
        assertEquals(Step.STOP_BACKGROUND, WipeAndExit.ORDER.first())
    }

    @Test
    fun `rust secrets are destroyed first, before anything that waits on the network`() {
        // Stage B right after the writers stop: nothing -- not a notification,
        // not a network timeout -- stands between the wipe and the keys.
        val order = WipeAndExit.ORDER
        assertEquals(Step.DESTROY_CRYPTO, order[1])
        assertTrue(order.indexOf(Step.DESTROY_CRYPTO) < order.indexOf(Step.STOP_SUBSYSTEMS))
    }

    @Test
    fun `local state is destroyed before the network-bound step, storage after it, and exit is last`() {
        // STOP_SUBSYSTEMS closes calls, the stream and the I2P tunnel, each
        // bounded by a network timeout. Memory and the vault used to come
        // after it, and that window is where "wiped" conversations were
        // still on screen and on disk (WipePersistenceTest). The storage
        // sweep comes after it so no subsystem can write behind it.
        val order = WipeAndExit.ORDER
        for (local in listOf(Step.CLEAR_NOTIFICATIONS, Step.CLEAR_MEMORY,
                             Step.DESTROY_VAULT)) {
            assertTrue(order.indexOf(local) < order.indexOf(Step.STOP_SUBSYSTEMS), "$local")
        }
        assertTrue(order.indexOf(Step.STOP_SUBSYSTEMS) < order.indexOf(Step.WIPE_APP_DATA))
        assertTrue(order.indexOf(Step.CLEAR_MEMORY) < order.indexOf(Step.DESTROY_VAULT))
        assertTrue(order.indexOf(Step.CLEAR_NOTIFICATIONS) < order.indexOf(Step.DESTROY_VAULT))
        assertEquals(Step.WIPE_APP_DATA, order[order.size - 2])
        assertEquals(Step.EXIT, order.last())
    }

    @Test
    fun `only system-managed state is kept`() {
        for (store in WipeAndExit.STORES.filter { it.step == null }) {
            assertTrue(store.where.startsWith("system") || store.where.startsWith("package manager"),
                       "${store.what} is app data but kept")
        }
    }

    @Test
    fun `a latched vault refuses writes and reads but still erases`() {
        val disk = InMemoryVault()
        val vault = LatchedVault(disk)
        vault.put("a", byteArrayOf(1))
        vault.latch()
        vault.put("b", byteArrayOf(2))
        assertNull(disk.get("b"), "a write after the latch reached the disk")
        assertNull(vault.get("a"), "a read after the latch returned a record")
        vault.clear()
        assertNull(disk.get("a"), "clear stopped working once latched")
        assertTrue(vault.isLatched)
    }

    @Test
    fun `a failing step does not stop the rest, and exit still runs`() {
        val log = mutableListOf<Step>()
        val report = WipeAndExit.Runner(
            recording(log, failing = setOf(Step.DESTROY_CRYPTO, Step.DESTROY_VAULT))).run()
        assertEquals(WipeAndExit.ORDER, log, "a failure skipped later steps")
        assertEquals(WipeAndExit.ORDER.filter { it == Step.DESTROY_CRYPTO || it == Step.DESTROY_VAULT },
                     report.failed)
        assertFalse(report.ok)
        assertTrue(Step.EXIT in report.completed)
    }

    @Test
    fun `running twice runs once`() {
        val log = mutableListOf<Step>()
        val runner = WipeAndExit.Runner(recording(log))
        runner.run()
        val second = runner.run()
        assertEquals(WipeAndExit.ORDER, log, "the teardown ran twice")
        assertFalse(second.ran)
    }

    @Test
    fun `every step must have an action`() {
        val partial = Step.entries.drop(1).associateWith { { } }
        val thrown = runCatching { WipeAndExit.Runner(partial) }.exceptionOrNull()
        assertNotNull(thrown, "a runner with a missing step was accepted")
    }

    @Test
    fun `only configuration is kept`() {
        for (store in WipeAndExit.STORES) {
            if (store.category == Category.CONFIGURATION) {
                assertNull(store.step, "${store.what} is configuration but is destroyed")
            } else {
                assertNotNull(store.step, "${store.what} is sensitive and nothing destroys it")
            }
        }
    }

    @Test
    fun `the stores the app actually writes are all accounted for`() {
        val where = WipeAndExit.STORES.joinToString("\n") { it.where }
        for (needle in listOf("account.credentials", "chat.", "contacts.",
                              "otrv4plus.vault.v1", "~/.otrv4plus", "outbox",
                              "diagnostics", "NotificationManager", "chaquopy",
                              "shared_prefs", "code_cache", "databases", "no_backup",
                              "Android/data")) {
            assertTrue(needle in where, "no policy for $needle")
        }
    }

    @Test
    fun `every step destroys something`() {
        val used = WipeAndExit.STORES.mapNotNull { it.step }.toSet()
        for (step in Step.entries - Step.STOP_BACKGROUND) {
            assertTrue(step in used, "$step is in the order but owns no store")
        }
    }

    @Test
    fun `the confirmation says it cannot be undone and what is lost`() {
        val body = WipeAndExit.CONFIRM_BODY
        for (phrase in listOf("cannot be undone", "message history", "keys",
                              "verify you again")) {
            assertTrue(phrase in body, "the confirmation does not say \"$phrase\"")
        }
    }
}
