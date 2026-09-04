package org.otrv4plus.android.bridge

/**
 * The Kotlin side of the typed bridge.
 *
 * This is deliberately narrow. Kotlin does not get `otrv4+.py`; it gets these
 * operations, which map one-to-one onto `android_bridge.app.OtrApp`. Two rules
 * hold across the whole boundary:
 *
 *  - Nothing here returns key material. Fingerprints are of public keys.
 *  - Nothing here returns a status string for the UI to parse. State is an
 *    enum, mirroring the engine's own values (see android_bridge/events.py for
 *    where each mapping comes from).
 *
 * The terminal client infers state by substring-matching printed English. That
 * pattern must not reach Android, and the types below are what prevents it.
 */
interface OtrCore {

    /** Bring up CPython, load the orchestration layer, construct the engine. */
    fun initialize(): InitResult

    /** Tear down every session. Safe to call repeatedly. */
    fun shutdown()

    fun localFingerprint(): String

    fun securityState(peer: String): SecurityState

    fun smpState(peer: String): SmpState

    fun smpProgress(peer: String): SmpProgress

    fun securityDetails(peer: String): SecurityDetails

    fun contacts(): List<Contact>

    fun startSession(peer: String)

    /**
     * Encrypt and send.
     *
     * Throws rather than downgrading: if there is no encrypted session the
     * message is not transmitted in the clear.
     */
    fun sendMessage(peer: String, body: String)

    /**
     * Begin verification.
     *
     * [secret] is passed straight to the engine and is not retained, logged or
     * echoed back. Verification takes minutes on mobile -- a 50,000-round
     * SHAKE-256 chain plus 3072-bit work -- so callers must drive a real
     * progress UI from [smpProgress] and keep the work in a foreground service.
     */
    fun smpStart(peer: String, secret: String, question: String = "")

    fun smpRespond(peer: String, secret: String)

    fun smpAbort(peer: String)

    fun setEventSink(sink: OtrEventSink?)
}

/** Result of bringing the stack up. Carries no secrets. */
data class InitResult(
    val ok: Boolean,
    val pythonVersion: String,
    val abi: String,
    val rustCoreLoaded: Boolean,
    val engineInitialized: Boolean,
    /** Non-sensitive failure reason, or null. Never engine exception text. */
    val failureCode: String? = null,
)

/** Mirrors `UIConstants.SecurityLevel`; values are numerically identical. */
enum class SecurityState(val level: Int) {
    PLAINTEXT(0),
    ENCRYPTED(1),
    FINGERPRINT(2),
    SMP_VERIFIED(3),
    FINGERPRINT_MISMATCH(4);

    companion object {
        /** Unknown values fail safe: never render as more secure than reality. */
        fun fromLevel(level: Int): SecurityState =
            entries.firstOrNull { it.level == level } ?: PLAINTEXT
    }
}

enum class SmpState { IDLE, IN_PROGRESS, VERIFIED, FAILED;
    companion object {
        fun fromName(name: String): SmpState =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: IDLE
    }
}

enum class ConnectionState { DISCONNECTED, CONNECTING, CONNECTED, FAILED }

enum class CallState {
    IDLE, INVITING, RINGING, CONNECTING, KEY_CONFIRMING,
    MEDIA_CONNECTING, ACTIVE, ENDING, ENDED;

    companion object {
        fun fromName(name: String): CallState =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) } ?: IDLE
    }
}

data class SmpProgress(val step: Int, val total: Int, val state: SmpState)

data class Contact(
    val jid: String,
    val displayName: String,
    val online: Boolean,
    val security: SecurityState,
    val smp: SmpState,
    /**
     * Whether to *enable the call button*. The engine gates calls on its own
     * cryptographic predicate (VoiceCallManager._smp_verified); this flag is a
     * UI affordance and must never be treated as the gate.
     */
    val callAvailable: Boolean,
)

data class SecurityDetails(
    val peer: String,
    val security: SecurityState,
    val smp: SmpState,
    val smpPhase: String,
    val localFingerprint: String,
    val peerFingerprint: String?,
    val trusted: Boolean,
)

/** Structured events pushed from Python. No plaintext reaches any log. */
sealed interface OtrEvent {
    data class ConnectionChanged(val state: ConnectionState) : OtrEvent
    data class SessionChanged(val peer: String, val security: SecurityState) : OtrEvent
    data class MessageReceived(val peer: String, val body: String, val timestamp: Double) : OtrEvent
    data class SmpProgressed(val peer: String, val progress: SmpProgress) : OtrEvent
    data class SmpFinished(val peer: String, val state: SmpState) : OtrEvent

    /** The pinned fingerprint changed. The UI must block, not merely inform. */
    data class FingerprintChanged(
        val peer: String,
        val storedFingerprint: String,
        val receivedFingerprint: String,
    ) : OtrEvent

    data class CallChanged(val peer: String, val state: CallState, val durationSeconds: Int) : OtrEvent

    /** [code] is stable and machine-readable; there is no engine text here. */
    data class Failed(val peer: String?, val code: String) : OtrEvent
}

fun interface OtrEventSink {
    fun onEvent(event: OtrEvent)
}

/** A bridge failure. Carries a code, never engine exception text. */
class OtrBridgeException(val code: String) : RuntimeException(code)
