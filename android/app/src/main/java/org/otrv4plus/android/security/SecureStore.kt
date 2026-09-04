package org.otrv4plus.android.security

/**
 * Authenticated encrypted storage for the application's sensitive records.
 *
 * The Kotlin counterpart of `android_bridge.secure_store.SealedStore`, sharing
 * its record format so a record sealed on either side opens on the other:
 *
 *     version(1) || key_id(4) || nonce(12) || ciphertext || tag(16)
 *     AAD = version || key_id || recordType || 0 || schemaVersion || 0 || recordId
 *
 * A fresh 96-bit CSPRNG nonce is drawn for every operation. Binding recordType,
 * recordId and schemaVersion into the AAD means a sealed record cannot be moved
 * between record types, renamed, or replayed against a different schema.
 *
 * Phase 4 implements this over [DataKeyHandle]. Phase 2 defines the contract.
 */
interface SecureStore {

    /** Seal [plaintext], returning a self-describing record. */
    fun seal(recordType: String, recordId: String, schemaVersion: Int,
             plaintext: ByteArray): ByteArray

    /**
     * Open a record, or return null.
     *
     * Null is undifferentiated: wrong key, tampered record, truncated record and
     * mismatched AAD are indistinguishable to the caller.
     */
    fun open(recordType: String, recordId: String, schemaVersion: Int,
             record: ByteArray): ByteArray?
}

/**
 * Categories of sensitive data, each with an explicit storage policy.
 *
 * The specification requires every category to have one. Naming them in code
 * rather than in a document alone means a new category cannot be added without
 * choosing a policy for it. See ANDROID_STORAGE_AUDIT.md for the current
 * mechanism and the Android replacement for each.
 */
enum class RecordType(val id: String) {
    IDENTITY("otr.identity"),
    TRUST_DATABASE("otr.trust"),
    MESSAGE("otr.message"),
    CONTACT("otr.contact"),
    SMP_SECRET("otr.smp"),
    CALL_METADATA("otr.call"),
    APP_CONFIG("app.config"),
    AUTH_METADATA("auth.metadata"),
    ;

    companion object {
        /**
         * Categories that must never be written to disk at all, in any form.
         *
         * Ratchet and session state live in Rust for the process lifetime and
         * are zeroized on drop. Persisting them would create a file whose theft
         * breaks forward secrecy for the messages it covers -- the property the
         * ratchet exists to provide.
         */
        val NEVER_PERSISTED = setOf("otr.ratchet.state", "otr.session.keys")
    }
}
