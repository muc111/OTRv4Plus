package org.otrv4plus.android.security

/**
 * Turns a credential into the key that opens the vault -- via key *unwrapping*,
 * never by using the credential as the key.
 *
 * The flow the specification requires:
 *
 *     credential -> AttemptThrottle.check() -> Argon2id -> KEK
 *                -> unwrap Keystore-held DEK -> authenticated verification
 *                -> secure application key available
 *
 * Consequences of that shape, all of them required properties:
 *
 *  - The credential is an *authentication input*, not the encryption key.
 *  - Changing it re-wraps the same DEK under a new KEK; no user data is
 *    re-encrypted.
 *  - There is no stored plaintext to compare against. Verification is the AEAD
 *    tag on the wrapped key, so a wrong credential and a corrupt record fail
 *    identically.
 *  - Offline guessing additionally requires the non-exportable Keystore key.
 */
interface UnlockCredentialService {

    /**
     * Attempt an unlock.
     *
     * [credential] is consumed and must not be retained, logged, or echoed. It
     * is a CharArray rather than a String so the caller can clear it: a String
     * would sit in the JVM heap until GC with no way to overwrite it.
     */
    fun attempt(credential: CharArray): UnlockOutcome

    /** Change the credential by re-wrapping the same DEK. */
    fun changeCredential(current: CharArray, replacement: CharArray): Boolean

    /** Whether a credential has been established yet (first-run detection). */
    fun isEnrolled(): Boolean
}

/**
 * Result of an unlock attempt.
 *
 * [Failed] carries no reason on purpose -- see "no useful error
 * differentiation" in the specification. [Throttled] is distinguishable only
 * because the UI must be able to say how long to wait; it reveals nothing about
 * the credential.
 */
sealed interface UnlockOutcome {
    data class Success(val handle: DataKeyHandle) : UnlockOutcome
    data object Failed : UnlockOutcome
    data class Throttled(val retryAfterMillis: Long) : UnlockOutcome
    data object NotEnrolled : UnlockOutcome
}

/**
 * Argon2id parameters.
 *
 * The specification is explicit that these must be chosen from measurement on
 * real Android hardware, not picked arbitrarily. They are therefore a value
 * type carried through the code rather than constants baked into it, and
 * [NEEDS_CALIBRATION] is what the code ships with until Phase 11 measures a
 * low-end device.
 *
 * The existing desktop engine uses time=3, memory=64MiB, parallelism=4
 * (`otrv4+.py::_derive_key`). Those are a starting point for calibration, not a
 * validated Android choice: 64 MiB on a low-end phone may be unacceptably slow
 * or may push the app toward an OOM kill during unlock.
 */
data class Argon2idParams(
    val timeCost: Int,
    val memoryKib: Int,
    val parallelism: Int,
    val outputLength: Int = 32,
    /** False until measured on target hardware. Release must not ship false. */
    val calibrated: Boolean = false,
) {
    init {
        require(timeCost >= 1) { "timeCost must be >= 1" }
        require(memoryKib >= 8 * 1024) { "memoryKib below 8 MiB is not defensible" }
        require(parallelism >= 1) { "parallelism must be >= 1" }
        require(outputLength == 32) { "outputLength must be 32 for an AES-256 KEK" }
    }

    companion object {
        /**
         * Placeholder matching the desktop engine, explicitly NOT calibrated.
         *
         * Phase 12's release checklist must assert `calibrated == true`.
         */
        val NEEDS_CALIBRATION = Argon2idParams(
            timeCost = 3,
            memoryKib = 64 * 1024,
            parallelism = 4,
            calibrated = false,
        )
    }
}

/**
 * Where the credential comes from.
 *
 * Phase 3 implements the calculator entry path. This exists now so the
 * development credential has an injection point that is structurally incapable
 * of reaching a release build: the only implementations live in test source
 * sets, and [DEVELOPMENT_ONLY_MARKER] makes any accidental production
 * implementation obvious to a reviewer and to the build-time credential scan.
 *
 * The development sequence ("1337") appears in NO production Kotlin constant,
 * resource, asset, manifest entry or Python/Rust source. A build-time test
 * (`tests/test_release_guard.py`) enforces that.
 */
interface UnlockCredentialSource {
    fun readCredential(): CharArray

    companion object {
        const val DEVELOPMENT_ONLY_MARKER = "development-credential-source"
    }
}
