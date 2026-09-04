package org.otrv4plus.android.security

/**
 * Application lock lifecycle.
 *
 * The specification names these five states explicitly. The transition table is
 * exhaustive and enforced, following the same idiom the voice subsystem already
 * uses for [otrv4plus_voice.CallState] -- where scattered unchecked assignments
 * were replaced by one validated table because a callback firing after teardown
 * could otherwise move a call anywhere at all. The same hazard applies here: a
 * lifecycle callback arriving late must not be able to move the app from LOCKED
 * to UNLOCKED.
 *
 * This file deliberately imports nothing from Android, so the state machine is
 * unit-testable on a plain JVM.
 */
enum class LockState {
    /** No secure key material is available. The only way out is authentication. */
    LOCKED,

    /** A credential is being verified. Entered only from LOCKED. */
    AUTHENTICATING,

    /** Secure key material is available to the application. */
    UNLOCKED,

    /**
     * Backgrounded while unlocked; the relock timer is running.
     *
     * Distinct from UNLOCKED because sensitive UI state should already have been
     * cleared, and distinct from LOCKED because returning quickly must not
     * require re-authentication.
     */
    BACKGROUND_LOCK_PENDING,
    ;

    companion object {
        /**
         * Every legal transition.
         *
         * Notably absent: AUTHENTICATING is reachable only from LOCKED, so an
         * unlocked session cannot be pushed back through authentication by a
         * stray event; and nothing transitions out of LOCKED except by starting
         * authentication.
         */
        val ALLOWED: Map<LockState, Set<LockState>> = mapOf(
            LOCKED to setOf(AUTHENTICATING),
            AUTHENTICATING to setOf(UNLOCKED, LOCKED),
            UNLOCKED to setOf(BACKGROUND_LOCK_PENDING, LOCKED),
            BACKGROUND_LOCK_PENDING to setOf(UNLOCKED, LOCKED),
        )

        fun permits(from: LockState, to: LockState): Boolean =
            ALLOWED[from]?.contains(to) == true
    }
}

/** Raised when something attempts a transition the machine does not permit. */
class IllegalLockTransition(from: LockState, to: LockState) :
    IllegalStateException("illegal lock transition: $from -> $to")
