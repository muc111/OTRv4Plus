package org.otrv4plus.android.security

/**
 * Abstraction over device-bound key protection.
 *
 * Phase 2 defines the contract and the capability model. The Android
 * Keystore/StrongBox implementation is Phase 4 -- there is deliberately no
 * concrete implementation in this package, so an incompletely wired build fails
 * to construct rather than silently protecting nothing.
 *
 * Design rules the specification imposes, encoded here:
 *
 *  - The data-encryption key is generated on-device and wrapped by a
 *    non-exportable Keystore key. It is never embedded in the APK.
 *  - StrongBox is preferred where present but must never be *required*: a device
 *    without it degrades to TEE-backed, and a device without that degrades to
 *    software, each recorded honestly in [SecurityLevel].
 *  - Diagnostics report capability, never key material.
 */
interface KeystoreManager {

    /** What protection this device actually provides. Detected, not assumed. */
    fun securityLevel(): SecurityLevel

    /** Capability and version diagnostics. Contains no key material. */
    fun diagnostics(): KeystoreDiagnostics

    /**
     * Unwrap the data-encryption key using a KEK derived from the credential.
     *
     * Returns an opaque handle. The key bytes are not a return value: on a
     * hardware-backed device they genuinely cannot be read, and the interface is
     * shaped so that the software path cannot be more permissive than the
     * hardware one.
     *
     * Failure is undifferentiated -- a wrong credential and a corrupt wrapped
     * key are indistinguishable to the caller.
     */
    fun unwrapDataKey(kek: ByteArray): DataKeyHandle?

    /**
     * Wrap a freshly generated data-encryption key under a new KEK.
     *
     * This is how the credential changes without re-encrypting user data: the
     * same DEK is re-wrapped under a KEK derived from the new credential.
     */
    fun rewrapDataKey(currentKek: ByteArray, newKek: ByteArray): Boolean

    /** Rotate to a new key generation. Older generations stay readable. */
    fun rotateDataKey(kek: ByteArray): Int
}

/**
 * Where the wrapping key lives. Ordered weakest to strongest; a device reports
 * what it has rather than what the app would prefer.
 */
enum class SecurityLevel {
    /** No Keystore available. The app must warn; it must not pretend otherwise. */
    SOFTWARE_ONLY,

    /** Keystore present but not hardware-backed. */
    KEYSTORE_SOFTWARE,

    /** Trusted Execution Environment. The common case on modern devices. */
    HARDWARE_TEE,

    /** Dedicated secure element. Best available; never assumed present. */
    STRONGBOX,
}

/**
 * Internal diagnostics for development and support.
 *
 * Every field is a capability, a flag or a version number. None is derived from
 * key material, so this is safe to display on the developer diagnostics screen
 * and safe to include in a bug report.
 */
data class KeystoreDiagnostics(
    val keystoreAvailable: Boolean,
    val hardwareBacked: Boolean,
    val strongBoxAvailable: Boolean,
    val userAuthenticationRequired: Boolean,
    val keyVersion: Int,
    val encryptionVersion: Int,
    val securityLevel: SecurityLevel,
)

/**
 * Opaque reference to the unwrapped data-encryption key.
 *
 * Mirrors `android_bridge.secure_store.DekHandle`: operations are performed by
 * the handle rather than the key being surrendered to the caller. [close]
 * releases it on relock.
 */
interface DataKeyHandle : AutoCloseable {
    val keyId: Int
    fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray
    fun open(record: ByteArray, aad: ByteArray): ByteArray?
}
