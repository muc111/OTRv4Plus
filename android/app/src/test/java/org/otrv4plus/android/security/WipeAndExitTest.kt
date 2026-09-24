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
    fun `local state is destroyed before the network-bound engine step, and exit is last`() {
        // The engine step closes calls, the stream and the I2P tunnel, each
        // bounded by a network timeout. Memory and the vault used to come
        // after it, and that window is where "wiped" conversations were
        // still on screen and on disk (WipePersistenceTest).
        val order = WipeAndExit.ORDER
        for (local in listOf(Step.CLEAR_NOTIFICATIONS, Step.CLEAR_MEMORY,
                             Step.DESTROY_VAULT, Step.CLEAR_CACHE)) {
            assertTrue(order.indexOf(local) < order.indexOf(Step.WIPE_ENGINE), "$local")
        }
        assertTrue(order.indexOf(Step.CLEAR_MEMORY) < order.indexOf(Step.DESTROY_VAULT))
        assertTrue(order.indexOf(Step.CLEAR_NOTIFICATIONS) < order.indexOf(Step.DESTROY_VAULT))
        assertEquals(Step.EXIT, order.last())
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
            recording(log, failing = setOf(Step.WIPE_ENGINE, Step.DESTROY_VAULT))).run()
        assertEquals(WipeAndExit.ORDER, log, "a failure skipped later steps")
        assertEquals(WipeAndExit.ORDER.filter { it == Step.WIPE_ENGINE || it == Step.DESTROY_VAULT },
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
                              "diagnostics", "NotificationManager")) {
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
