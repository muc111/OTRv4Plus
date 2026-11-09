// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Device report 2026-11-09: a ~60 s reconnect wait ran 7 minutes on a Pixel
 * with the screen off (Doze). The wait now ends when the phone wakes, and a
 * wait the phone slept through says so.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RetryWaitTest {

    @Test
    fun aWaitNobodyWakesRunsItsFullLength() = runTest {
        val wait = RetryWait(clock = { testScheduler.currentTime })
        val out = async { wait.await(60_000) }
        advanceTimeBy(59_999); runCurrent()
        assertFalse(out.isCompleted)
        advanceTimeBy(2); runCurrent()
        assertEquals(RetryWait.Outcome(wokenBy = null, lateMs = 0), out.await())
    }

    @Test
    fun thePhoneWakingStartsTheAttemptNow() = runTest {
        val wait = RetryWait(clock = { testScheduler.currentTime })
        val out = async { wait.await(60_000) }
        advanceTimeBy(5_000); runCurrent()
        assertTrue(wait.wake("screen_on"))
        runCurrent()
        assertEquals("screen_on", out.await().wokenBy)
        assertEquals(5_000, testScheduler.currentTime)
        assertFalse(wait.waiting)
    }

    @Test
    fun aWakeWithNothingWaitingIsDroppedAndDoesNotEndTheNextWait() = runTest {
        val wait = RetryWait(clock = { testScheduler.currentTime })
        assertFalse(wait.wake("network"))          // an attempt is running
        val out = async { wait.await(30_000) }
        advanceTimeBy(30_001); runCurrent()
        assertNull(out.await().wokenBy)
    }

    @Test
    fun aWakeTheMomentTheWaitBeganIsIgnoredSoFailuresCannotSpin() = runTest {
        val wait = RetryWait(clock = { testScheduler.currentTime })
        val out = async { wait.await(30_000) }
        runCurrent()
        assertFalse(wait.wake("network"))
        advanceTimeBy(RetryWait.MIN_WAIT_MS); runCurrent()
        assertTrue(wait.wake("network"))
        runCurrent()
        assertEquals("network", out.await().wokenBy)
    }

    @Test
    fun aWaitThePhoneSleptThroughIsReportedLate() = runTest {
        // The CPU slept: the timer fired at 60 s of awake time, but the
        // clock that counts sleep moved on 6 minutes more.
        var slept = 0L
        val wait = RetryWait(clock = { testScheduler.currentTime + slept })
        val out = async { wait.await(60_000) }
        runCurrent()
        slept = 356_000
        advanceTimeBy(60_001); runCurrent()
        val outcome = out.await()
        assertNull(outcome.wokenBy)
        assertTrue(outcome.lateMs >= 356_000)
        assertTrue(outcome.slept)
    }
}
