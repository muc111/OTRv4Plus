package org.otrv4plus.android.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for the application security layer.
 *
 * These classes import nothing from Android on purpose, so this whole file runs
 * on a plain JVM -- which means the lock state machine and the brute-force
 * throttle are verified rather than merely written.
 */

// ── Test doubles ─────────────────────────────────────────────────────────────

private class FakeClock(var now: Long = 0) : () -> Long {
    override fun invoke(): Long = now
    fun advance(millis: Long) { now += millis }
}

private class MemoryThrottleStore : ThrottleStore {
    private var failures = 0
    private var lastFailure = 0L
    override fun failureCount() = failures
    override fun setFailureCount(value: Int) { failures = value }
    override fun lastFailureAtMillis() = lastFailure
    override fun setLastFailureAt(millis: Long) { lastFailure = millis }
}

private class FakeDataKey(override val keyId: Int = 1) : DataKeyHandle {
    var closed = false
        private set
    override fun seal(plaintext: ByteArray, aad: ByteArray) = plaintext
    override fun open(record: ByteArray, aad: ByteArray) = record
    override fun close() { closed = true }
}

/** Closing this one throws, to prove relock still completes. */
private class ExplodingDataKey : DataKeyHandle {
    override val keyId = 9
    override fun seal(plaintext: ByteArray, aad: ByteArray) = plaintext
    override fun open(record: ByteArray, aad: ByteArray) = record
    override fun close() = throw RuntimeException("close failed")
}

// ── Lock state machine ───────────────────────────────────────────────────────

class LockStateTransitionTest {

    @Test
    fun `authenticating is reachable only from locked`() {
        assertTrue(LockState.permits(LockState.LOCKED, LockState.AUTHENTICATING))
        assertFalse(LockState.permits(LockState.UNLOCKED, LockState.AUTHENTICATING))
        assertFalse(
            LockState.permits(LockState.BACKGROUND_LOCK_PENDING, LockState.AUTHENTICATING)
        )
    }

    @Test
    fun `locked cannot jump straight to unlocked`() {
        assertFalse(LockState.permits(LockState.LOCKED, LockState.UNLOCKED))
    }

    @Test
    fun `every state can reach locked except locked itself`() {
        LockState.entries.filter { it != LockState.LOCKED }.forEach {
            assertTrue(LockState.permits(it, LockState.LOCKED), "$it should reach LOCKED")
        }
    }

    @Test
    fun `transition table covers every state`() {
        assertEquals(LockState.entries.toSet(), LockState.ALLOWED.keys)
    }
}

class AppLockManagerTest {

    @Test
    fun `starts locked with no key`() {
        val mgr = AppLockManager(FakeClock())
        assertEquals(LockState.LOCKED, mgr.state)
        assertNull(mgr.dataKey())
    }

    @Test
    fun `full happy path`() {
        val states = mutableListOf<LockState>()
        val mgr = AppLockManager(FakeClock(), onStateChanged = { states += it })
        mgr.beginAuthentication()
        mgr.authenticationSucceeded(FakeDataKey())
        assertEquals(LockState.UNLOCKED, mgr.state)
        assertNotNull(mgr.dataKey())
        assertEquals(listOf(LockState.AUTHENTICATING, LockState.UNLOCKED), states)
    }

    @Test
    fun `failed authentication returns to locked holding no key`() {
        val mgr = AppLockManager(FakeClock())
        mgr.beginAuthentication()
        mgr.authenticationFailed()
        assertEquals(LockState.LOCKED, mgr.state)
        assertNull(mgr.dataKey())
    }

    @Test
    fun `key is released on relock`() {
        val key = FakeDataKey()
        val mgr = AppLockManager(FakeClock())
        mgr.beginAuthentication()
        mgr.authenticationSucceeded(key)
        mgr.lock()
        assertTrue(key.closed, "the data key must be released when relocking")
        assertNull(mgr.dataKey())
    }

    @Test
    fun `backgrounding starts the grace period without locking`() {
        val clock = FakeClock()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 30_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        assertEquals(LockState.BACKGROUND_LOCK_PENDING, mgr.state)
        assertEquals(30_000, mgr.remainingGraceMillis())
    }

    @Test
    fun `returning within the grace period does not require reauthentication`() {
        val clock = FakeClock()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 30_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        clock.advance(5_000)
        mgr.onForegrounded()
        assertEquals(LockState.UNLOCKED, mgr.state)
        assertNotNull(mgr.dataKey())
    }

    @Test
    fun `returning after the grace period relocks`() {
        val clock = FakeClock()
        val key = FakeDataKey()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 30_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(key)
        mgr.onBackgrounded()
        clock.advance(30_001)
        mgr.onForegrounded()
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `relock timer locks while still backgrounded`() {
        val clock = FakeClock()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 10_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        clock.advance(10_000)
        mgr.onRelockTimerFired()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `a late relock timer must not lock an app back in the foreground`() {
        val clock = FakeClock()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 10_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        clock.advance(1_000)
        mgr.onForegrounded()
        clock.advance(60_000)
        mgr.onRelockTimerFired()          // fires long after returning
        assertEquals(LockState.UNLOCKED, mgr.state)
    }

    @Test
    fun `zero grace period locks immediately`() {
        val mgr = AppLockManager(FakeClock(), backgroundGraceMillis = 0)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `clock moving backwards relocks rather than extending the session`() {
        val clock = FakeClock(now = 1_000_000)
        val key = FakeDataKey()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 10_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(key)
        mgr.onBackgrounded()
        clock.now = 0                      // device clock wound back
        mgr.onForegrounded()
        // Fails closed: otherwise anyone holding the device could keep a session
        // unlocked indefinitely by winding the clock back before returning.
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `backwards clock also relocks via the timer path`() {
        val clock = FakeClock(now = 500_000)
        val mgr = AppLockManager(clock, backgroundGraceMillis = 10_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        clock.now = 1
        mgr.onRelockTimerFired()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `remaining grace reports zero when the clock went backwards`() {
        val clock = FakeClock(now = 500_000)
        val mgr = AppLockManager(clock, backgroundGraceMillis = 10_000)
        mgr.beginAuthentication(); mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        clock.now = 0
        assertEquals(0, mgr.remainingGraceMillis())
    }

    @Test
    fun `a stale lifecycle callback cannot unlock a locked app`() {
        val mgr = AppLockManager(FakeClock())
        mgr.onForegrounded()               // stale event while LOCKED
        assertEquals(LockState.LOCKED, mgr.state)
        mgr.onRelockTimerFired()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `illegal transitions are rejected`() {
        val mgr = AppLockManager(FakeClock())
        assertFailsWith<IllegalStateException> {
            mgr.authenticationSucceeded(FakeDataKey())   // never authenticated
        }
    }

    @Test
    fun `relock completes even if releasing the key throws`() {
        val mgr = AppLockManager(FakeClock())
        mgr.beginAuthentication()
        mgr.authenticationSucceeded(ExplodingDataKey())
        mgr.lock()
        assertEquals(LockState.LOCKED, mgr.state)
        assertNull(mgr.dataKey())
    }

    @Test
    fun `lock is idempotent`() {
        val mgr = AppLockManager(FakeClock())
        mgr.lock(); mgr.lock()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `data key is unavailable in every state except unlocked`() {
        val clock = FakeClock()
        val mgr = AppLockManager(clock, backgroundGraceMillis = 30_000)
        mgr.beginAuthentication()
        assertNull(mgr.dataKey())
        mgr.authenticationSucceeded(FakeDataKey())
        mgr.onBackgrounded()
        assertNull(mgr.dataKey(), "key must not be readable while relock is pending")
    }
}

/**
 * Decision 7: no clock condition may leave an authenticated session permanently
 * UNLOCKED.
 *
 * The relock deadline is the one place where a clock the user controls could buy
 * an indefinite unlocked window, so each scenario is checked explicitly rather
 * than assumed to follow from the arithmetic.
 */
class ClockRollbackTest {

    private fun unlocked(clock: FakeClock, grace: Long = 10_000):
            Pair<AppLockManager, FakeDataKey> {
        val key = FakeDataKey()
        val mgr = AppLockManager(clock, backgroundGraceMillis = grace)
        mgr.beginAuthentication()
        mgr.authenticationSucceeded(key)
        return mgr to key
    }

    @Test
    fun `normal timestamp relocks after the grace period`() {
        val clock = FakeClock(now = 1_000)
        val (mgr, key) = unlocked(clock)
        mgr.onBackgrounded()
        clock.advance(10_001)
        mgr.onForegrounded()
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `future timestamp relocks`() {
        // A clock jumped far forward looks like a long absence: relock.
        val clock = FakeClock(now = 1_000)
        val (mgr, key) = unlocked(clock)
        mgr.onBackgrounded()
        clock.now = Long.MAX_VALUE / 2
        mgr.onForegrounded()
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `backwards clock relocks`() {
        val clock = FakeClock(now = 1_000_000)
        val (mgr, key) = unlocked(clock)
        mgr.onBackgrounded()
        clock.now = 0
        mgr.onForegrounded()
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `extreme backwards jump relocks`() {
        val clock = FakeClock(now = 0)
        val (mgr, key) = unlocked(clock)
        mgr.onBackgrounded()
        clock.now = Long.MIN_VALUE / 2
        mgr.onForegrounded()
        assertEquals(LockState.LOCKED, mgr.state)
        assertTrue(key.closed)
    }

    @Test
    fun `large forward jump relocks via the timer path too`() {
        val clock = FakeClock(now = 1_000)
        val (mgr, _) = unlocked(clock)
        mgr.onBackgrounded()
        clock.now = Long.MAX_VALUE / 4
        mgr.onRelockTimerFired()
        assertEquals(LockState.LOCKED, mgr.state)
    }

    @Test
    fun `process restart starts locked regardless of the clock`() {
        // A new AppLockManager is what a restarted process gets. No stored
        // timestamp and no clock value can produce an UNLOCKED start.
        listOf(0L, -1L, 1_000L, Long.MAX_VALUE / 2, Long.MIN_VALUE / 2).forEach { t ->
            val mgr = AppLockManager(FakeClock(now = t))
            assertEquals(LockState.LOCKED, mgr.state, "restart at t=$t must be LOCKED")
            assertNull(mgr.dataKey())
            // And a stray lifecycle event still cannot unlock it.
            mgr.onForegrounded()
            mgr.onRelockTimerFired()
            assertEquals(LockState.LOCKED, mgr.state)
        }
    }

    @Test
    fun `no clock value leaves a backgrounded session unlocked forever`() {
        // Exhaustive over the interesting cases: whatever the clock does, the
        // session either resumes within the grace period or relocks. It never
        // stays BACKGROUND_LOCK_PENDING with the key still reachable.
        val cases = listOf(0L, 1L, 9_999L, 10_000L, 10_001L,
                           Long.MAX_VALUE / 2, -1L, Long.MIN_VALUE / 2)
        cases.forEach { target ->
            val clock = FakeClock(now = 500_000)
            val (mgr, key) = unlocked(clock)
            mgr.onBackgrounded()
            clock.now = target
            mgr.onForegrounded()
            when (mgr.state) {
                LockState.UNLOCKED ->
                    // Only legitimate when time genuinely advanced by less than
                    // the grace period.
                    assertTrue(target - 500_000 in 0 until 10_000,
                               "resumed unlocked at target=$target without a valid elapsed time")
                LockState.LOCKED -> assertTrue(key.closed, "relocked without releasing the key")
                else -> throw AssertionError("stuck in ${mgr.state} at target=$target")
            }
        }
    }

    @Test
    fun `throttle backoff also survives a clock rollback`() {
        val store = MemoryThrottleStore()
        val clock = FakeClock(now = 1_000_000)
        val throttle = AttemptThrottle(store, clock, baseDelayMillis = 1_000,
                                       maxDelayMillis = 60_000, freeAttempts = 3)
        repeat(6) { throttle.recordFailure() }
        listOf(0L, -1L, Long.MIN_VALUE / 2).forEach { t ->
            clock.now = t
            assertTrue(throttle.check() is AttemptThrottle.Decision.Blocked,
                       "rollback to $t granted a free attempt")
        }
    }
}

// ── Throttle ─────────────────────────────────────────────────────────────────

class AttemptThrottleTest {

    private fun throttle(clock: FakeClock, store: MemoryThrottleStore = MemoryThrottleStore()) =
        AttemptThrottle(store, clock, baseDelayMillis = 1_000,
                        maxDelayMillis = 60_000, freeAttempts = 3)

    @Test
    fun `first attempts are allowed without delay`() {
        val t = throttle(FakeClock())
        repeat(3) {
            assertEquals(AttemptThrottle.Decision.Allowed, t.check())
            t.recordFailure()
        }
    }

    @Test
    fun `delay grows after the free allowance`() {
        val t = throttle(FakeClock())
        repeat(4) { t.recordFailure() }
        assertEquals(1_000, t.requiredDelayMillis())
        t.recordFailure()
        assertEquals(2_000, t.requiredDelayMillis())
        t.recordFailure()
        assertEquals(4_000, t.requiredDelayMillis())
    }

    @Test
    fun `delay is capped`() {
        val t = throttle(FakeClock())
        repeat(40) { t.recordFailure() }
        assertEquals(60_000, t.requiredDelayMillis())
    }

    @Test
    fun `blocked until the delay elapses`() {
        val clock = FakeClock()
        val t = throttle(clock)
        repeat(4) { t.recordFailure() }
        val blocked = t.check()
        assertTrue(blocked is AttemptThrottle.Decision.Blocked)
        assertEquals(1_000, (blocked as AttemptThrottle.Decision.Blocked).retryAfterMillis)
        clock.advance(1_000)
        assertEquals(AttemptThrottle.Decision.Allowed, t.check())
    }

    @Test
    fun `success clears the backoff`() {
        val clock = FakeClock()
        val t = throttle(clock)
        repeat(6) { t.recordFailure() }
        t.recordSuccess()
        assertEquals(0, t.consecutiveFailures)
        assertEquals(AttemptThrottle.Decision.Allowed, t.check())
    }

    @Test
    fun `counters survive a restart`() {
        val clock = FakeClock()
        val store = MemoryThrottleStore()
        val first = throttle(clock, store)
        repeat(6) { first.recordFailure() }

        // Process death: a brand new throttle over the same persisted store.
        val second = throttle(clock, store)
        assertEquals(6, second.consecutiveFailures)
        assertTrue(second.check() is AttemptThrottle.Decision.Blocked,
                   "a throttle that forgets on restart is not a throttle")
    }

    @Test
    fun `clock moving backwards does not grant a free attempt`() {
        val clock = FakeClock(now = 1_000_000)
        val t = throttle(clock)
        repeat(4) { t.recordFailure() }
        clock.now = 0
        assertTrue(t.check() is AttemptThrottle.Decision.Blocked)
    }

    @Test
    fun `throttle never receives a credential`() {
        // Structural: none of the public methods takes credential material.
        val methods = AttemptThrottle::class.java.declaredMethods
            .filter { it.name in setOf("check", "recordFailure", "recordSuccess") }
        methods.forEach { m ->
            assertEquals(0, m.parameterCount,
                         "${m.name} must not accept any input, let alone a credential")
        }
    }

    @Test
    fun `there is no data destruction capability`() {
        // The specification forbids destroying user data after N failures
        // without an explicit product decision, so the capability must not exist.
        val names = AttemptThrottle::class.java.declaredMethods.map { it.name.lowercase() }
        listOf("wipe", "destroy", "erase", "reset").forEach { forbidden ->
            assertFalse(names.any { forbidden in it },
                        "AttemptThrottle must not expose a '$forbidden' operation")
        }
    }
}

// ── Argon2id parameters ──────────────────────────────────────────────────────

class Argon2idParamsTest {

    @Test
    fun `shipped defaults are marked uncalibrated`() {
        assertFalse(Argon2idParams.NEEDS_CALIBRATION.calibrated,
                    "defaults must not claim calibration before measurement")
    }

    @Test
    fun `rejects indefensible parameters`() {
        assertFailsWith<IllegalArgumentException> {
            Argon2idParams(timeCost = 0, memoryKib = 64 * 1024, parallelism = 4)
        }
        assertFailsWith<IllegalArgumentException> {
            Argon2idParams(timeCost = 3, memoryKib = 1024, parallelism = 4)
        }
        assertFailsWith<IllegalArgumentException> {
            Argon2idParams(timeCost = 3, memoryKib = 64 * 1024, parallelism = 4,
                           outputLength = 16)
        }
    }
}

// ── Record policy ────────────────────────────────────────────────────────────

class RecordTypeTest {

    @Test
    fun `every record type has a distinct identifier`() {
        val ids = RecordType.entries.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test
    fun `never-persisted categories are not storable record types`() {
        val storable = RecordType.entries.map { it.id }.toSet()
        RecordType.NEVER_PERSISTED.forEach {
            assertFalse(it in storable,
                        "$it must have no RecordType: persisting it would break forward secrecy")
        }
    }
}
