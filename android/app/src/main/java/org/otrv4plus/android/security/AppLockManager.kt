package org.otrv4plus.android.security

/**
 * Owns the application lock lifecycle.
 *
 * Enforces the [LockState] transition table, runs the background relock timer,
 * and releases the data-key handle whenever the app leaves UNLOCKED.
 *
 * Two properties matter more than the rest:
 *
 *  1. **Relock releases the key.** [DataKeyHandle.close] is called on every
 *     path out of UNLOCKED. The specification is careful not to claim memory
 *     clearing removes anything from RAM -- it does not -- so the goal here is
 *     to minimise the key's lifetime and let the Rust layer's zeroization do
 *     what it can, rather than to pretend the key is gone.
 *  2. **Late callbacks cannot unlock.** Android lifecycle events can arrive out
 *     of order and after teardown. Every transition goes through the table, so
 *     a stale onStart cannot move the app from LOCKED to UNLOCKED.
 *
 * No Android imports: this is driven by the caller's lifecycle observer and is
 * unit-testable on a plain JVM.
 */
class AppLockManager(
    private val clock: () -> Long,
    private val backgroundGraceMillis: Long = 30_000L,
    private val onStateChanged: (LockState) -> Unit = {},
) {
    init {
        require(backgroundGraceMillis >= 0) { "grace period must not be negative" }
    }

    var state: LockState = LockState.LOCKED
        private set

    private var handle: DataKeyHandle? = null
    private var backgroundedAtMillis: Long = 0

    /** The key handle, or null unless UNLOCKED. */
    fun dataKey(): DataKeyHandle? = if (state == LockState.UNLOCKED) handle else null

    /** Begin authenticating. Only legal from LOCKED. */
    fun beginAuthentication() {
        transition(LockState.AUTHENTICATING)
    }

    /** Authentication succeeded; take ownership of the key handle. */
    fun authenticationSucceeded(key: DataKeyHandle) {
        check(state == LockState.AUTHENTICATING) {
            "authenticationSucceeded outside AUTHENTICATING (was $state)"
        }
        handle = key
        transition(LockState.UNLOCKED)
    }

    /** Authentication failed. Returns to LOCKED without holding any key. */
    fun authenticationFailed() {
        releaseKey()
        transition(LockState.LOCKED)
    }

    /**
     * The app was backgrounded.
     *
     * Starts the grace period. Sensitive UI state should already have been
     * cleared by the caller at this point; the key is retained only so a quick
     * return does not force re-authentication.
     *
     * A zero grace period means relock immediately.
     */
    fun onBackgrounded() {
        if (state != LockState.UNLOCKED) return
        backgroundedAtMillis = clock()
        transition(LockState.BACKGROUND_LOCK_PENDING)
        if (backgroundGraceMillis == 0L) lock()
    }

    /**
     * The app returned to the foreground.
     *
     * Relocks if the grace period elapsed, or if the clock moved backwards.
     *
     * The backwards case fails CLOSED. Treating it as "no time passed" would let
     * anyone holding the device keep a session unlocked indefinitely by winding
     * the clock back before returning to the app. Relocking is the safe
     * direction, and the cost of being wrong is one re-authentication.
     */
    fun onForegrounded() {
        if (state != LockState.BACKGROUND_LOCK_PENDING) return
        if (graceExpired()) lock() else transition(LockState.UNLOCKED)
    }

    /**
     * The relock timer fired while still backgrounded.
     *
     * Idempotent, and a no-op if the app already returned to the foreground --
     * a timer that fires late must not lock a session the user is actively
     * using.
     */
    fun onRelockTimerFired() {
        if (state != LockState.BACKGROUND_LOCK_PENDING) return
        if (graceExpired()) lock()
    }

    /** Lock now, from any state. Always safe to call. */
    fun lock() {
        releaseKey()
        if (state != LockState.LOCKED) transition(LockState.LOCKED)
    }

    /** Milliseconds until relock, or 0 if not counting down or already due. */
    fun remainingGraceMillis(): Long {
        if (state != LockState.BACKGROUND_LOCK_PENDING) return 0
        val elapsed = clock() - backgroundedAtMillis
        if (elapsed < 0) return 0
        return (backgroundGraceMillis - elapsed).coerceAtLeast(0)
    }

    /**
     * Has the grace period expired?
     *
     * A negative elapsed time means the clock moved backwards, which counts as
     * expired -- see [onForegrounded].
     *
     * The caller should supply a MONOTONIC source (Android's
     * SystemClock.elapsedRealtime()), not the wall clock. This check is defence
     * for the case where it does not, and for a reboot resetting the reference.
     */
    private fun graceExpired(): Boolean {
        val elapsed = clock() - backgroundedAtMillis
        return elapsed < 0 || elapsed >= backgroundGraceMillis
    }

    private fun releaseKey() {
        val current = handle
        handle = null
        try {
            current?.close()
        } catch (_: Throwable) {
            // Releasing a key must never throw during relock; failing to close
            // is not a reason to leave the app in an unlocked state.
        }
    }

    private fun transition(to: LockState) {
        val from = state
        if (from == to) return
        if (!LockState.permits(from, to)) throw IllegalLockTransition(from, to)
        state = to
        onStateChanged(to)
    }
}
