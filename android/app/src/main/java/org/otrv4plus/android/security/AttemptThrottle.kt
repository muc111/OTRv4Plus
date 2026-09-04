package org.otrv4plus.android.security

/**
 * Brute-force resistance for the unlock credential.
 *
 * The specification's requirements, and how each is met:
 *
 *  - *rate limiting, increasing delay after repeated failures* -- exponential
 *    backoff from [baseDelayMillis], capped at [maxDelayMillis].
 *  - *attempt counters* -- [consecutiveFailures], persisted through
 *    [ThrottleStore] so an app restart does not reset them. A throttle that
 *    forgets on restart is not a throttle.
 *  - *secure failure handling* / *no useful error differentiation* -- the only
 *    outcomes are [Decision.Allowed] and [Decision.Blocked]; nothing reports
 *    *why* a credential failed.
 *  - *no logging of attempted credentials* -- this class never receives the
 *    credential at all. It counts outcomes, not inputs.
 *  - *no data destruction* -- deliberately absent. The specification requires an
 *    explicit product decision before destroying user data after N failures, and
 *    no such decision has been made, so the capability does not exist here.
 *
 * The throttle is checked BEFORE any key-derivation work. Running Argon2id first
 * would let an attacker use the unlock screen as a CPU-exhaustion oracle.
 *
 * No Android imports: unit-testable on a plain JVM.
 */
class AttemptThrottle(
    private val store: ThrottleStore,
    private val clock: () -> Long,
    private val baseDelayMillis: Long = 1_000L,
    private val maxDelayMillis: Long = 15 * 60 * 1_000L,
    private val freeAttempts: Int = 3,
) {
    init {
        require(baseDelayMillis > 0) { "baseDelayMillis must be positive" }
        require(maxDelayMillis >= baseDelayMillis) { "maxDelayMillis < baseDelayMillis" }
        require(freeAttempts >= 0) { "freeAttempts must not be negative" }
    }

    sealed interface Decision {
        /** An attempt may proceed. */
        data object Allowed : Decision

        /** Too soon. [retryAfterMillis] is how long remains. */
        data class Blocked(val retryAfterMillis: Long) : Decision
    }

    val consecutiveFailures: Int
        get() = store.failureCount()

    /**
     * May an unlock attempt proceed right now?
     *
     * Call before deriving anything.
     */
    fun check(): Decision {
        val failures = store.failureCount()
        if (failures <= freeAttempts) return Decision.Allowed

        val waited = clock() - store.lastFailureAtMillis()
        val required = requiredDelayMillis(failures)
        // A clock that has gone backwards (user changed the time, or a reboot
        // moved the wall clock) must not hand out a free pass: treat any
        // negative elapsed time as no time having passed.
        val elapsed = if (waited < 0) 0 else waited
        return if (elapsed >= required) Decision.Allowed
        else Decision.Blocked(required - elapsed)
    }

    /** Record a failed attempt. Takes no credential -- only the outcome. */
    fun recordFailure() {
        store.setFailureCount(store.failureCount() + 1)
        store.setLastFailureAt(clock())
    }

    /** Record success and clear the backoff. */
    fun recordSuccess() {
        store.setFailureCount(0)
        store.setLastFailureAt(0)
    }

    /**
     * Delay required after [failures] consecutive failures.
     *
     * Doubles per failure beyond the free allowance, capped at
     * [maxDelayMillis]. The cap matters: without one the delay would reach
     * values indistinguishable from permanent lockout, which is a data-loss
     * outcome the specification says must not happen implicitly.
     */
    fun requiredDelayMillis(failures: Int = store.failureCount()): Long {
        if (failures <= freeAttempts) return 0
        val steps = failures - freeAttempts - 1
        if (steps >= 63) return maxDelayMillis
        val scaled = baseDelayMillis shl steps
        // `shl` can overflow into a negative value for large shifts.
        return if (scaled < 0 || scaled > maxDelayMillis) maxDelayMillis else scaled
    }
}

/**
 * Persistence for throttle counters.
 *
 * Must survive process death and reboot, and must itself be stored encrypted --
 * a counter an attacker can reset by clearing a preferences file is decorative.
 * Phase 4 backs this with the sealed store; Phase 2 defines the contract.
 */
interface ThrottleStore {
    fun failureCount(): Int
    fun setFailureCount(value: Int)
    fun lastFailureAtMillis(): Long
    fun setLastFailureAt(millis: Long)
}
