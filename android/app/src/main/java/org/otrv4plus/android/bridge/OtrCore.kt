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

    /**
     * Wipe & Exit, engine side: destroy every session secret in Rust (on the
     * transport's loop thread), close the transport, and destroy what the
     * Python side wrote to disk. The core is spent afterwards. Idempotent;
     * never throws. See `OtrApp.wipe` and `ANDROID_WIPE_AND_EXIT.md`.
     */
    fun wipe(): WipeReport

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
     * Send one typed line, reporting what actually happened.
     *
     * [sendMessage] throws when there is no session, which is the right
     * guarantee (it never downgrades) but the wrong report: the engine does
     * not discard the text, it holds it and flushes it when the DAKE
     * completes. The terminal client has always shown that as
     * `[queued] will send once OTR is ready`.
     *
     * This returns [SendOutcome] so the UI can distinguish the three states a
     * user cares about. It adds no plaintext path: the engine still decides,
     * and nothing goes on the wire unencrypted.
     */
    fun sendUserText(peer: String, body: String): SendOutcome

    /**
     * Begin verification.
     *
     * [secret] is passed straight to the engine and is not retained, logged or
     * echoed back. Verification takes minutes on mobile -- a 50,000-round
     * SHAKE-256 chain plus 3072-bit work -- so callers must drive a real
     * progress UI from [smpProgress] and keep the work in a foreground service.
     */
    fun smpStart(peer: String, secret: String, question: String = "")

    /**
     * Answer a peer's held verification request.
     *
     * NOT the same call as [smpStart] with the roles swapped. The peer's SMP1
     * is being HELD by the Rust core in `SmpPhase::SecretRequired`; this binds
     * the passphrase AND resumes that held message into SMP2. Calling
     * [smpStart] here would begin a second, competing run.
     */
    fun smpRespond(peer: String, secret: String)

    /**
     * Whether a peer's SMP1 is held, waiting for this side's passphrase.
     *
     * Reads the engine, not a flag kept here: the answer lives in Rust
     * (`get_phase() == "SECRET_REQUIRED"`) and both terminal clients ask the
     * same question the same way.
     */
    fun smpSecretRequired(peer: String): Boolean

    fun smpAbort(peer: String)

    fun setEventSink(sink: OtrEventSink?)
}

/** Result of bringing the stack up. Carries no secrets. */
/**
 * What an engine wipe did. Counts and step names only -- never a key, a JID or
 * engine text.
 */
data class WipeReport(
    val sessions: Int = 0,
    val handshakes: Int = 0,
    val identityKeys: Int = 0,
    val filesDestroyed: Int = 0,
    /** Files that could only be unlinked, not overwritten first. */
    val filesUnlinkedOnly: Int = 0,
    /** Steps that reported a problem, e.g. "engine_off_thread". */
    val errors: List<String> = emptyList(),
) {
    val ok: Boolean get() = errors.isEmpty()

    companion object {
        /** A wipe that could not reach Python at all. */
        val UNREACHABLE = WipeReport(errors = listOf("core_unreachable"))
    }
}

data class InitResult(
    val ok: Boolean,
    val pythonVersion: String,
    val abi: String,
    val rustCoreLoaded: Boolean,
    val engineInitialized: Boolean,
    /** Non-sensitive failure reason, or null. Never engine exception text. */
    val failureCode: String? = null,
    /**
     * A safe, classified description of the failure, or null.
     *
     * Built by `android_bridge.failure.describe()`, which selects the detail
     * by exception TYPE rather than printing the message: our own
     * RuntimeUnsupported text, an ImportError's module name, a SystemExit's
     * code -- and for anything else, the type alone. So this is displayable
     * without a build-type gate.
     */
    val failureDetail: String? = null,
    /** `basename:lineno in function`, innermost last. Carries no values. */
    val failureFrames: String? = null,
    /**
     * The full diagnostic report as text, or null if it could not be built.
     *
     * Rendered by `android_bridge.diagnostics.as_text`, which applies
     * SENSITIVE_KEY_HINTS to the finished string. Kotlin never formats this:
     * one place decides what a diagnostic may contain, and it is the place
     * next to the data.
     */
    val diagnosticsText: String? = null,
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

/**
 * Verification state, mirroring `android_bridge.events.SmpState`.
 *
 * NOT_VERIFIED IS THE RESTING STATE, AND THE NAME IS THE POINT. An OTR
 * session is encrypted TO SOMEBODY; until SMP passes, nobody has checked who.
 * It was called IDLE, which reads as "nothing to do here" for the state that
 * is precisely the one the user still has work to do in.
 *
 * SECRET_REQUIRED is a peer's SMP1 held by the Rust core waiting for this
 * side's passphrase — the state that drives the incoming prompt. It existed
 * in `Rust/src/smp.rs` and reached neither this enum nor the Python map, so
 * "the other person is waiting on you" was reported as "nothing is happening".
 *
 * CANCELLED IS NOT FAILED. FAILED means the proof ran and the secrets did not
 * match, which on this protocol is what an impersonation looks like. Showing
 * a cancel as a failure would tell a user their peer may be an impostor
 * because somebody closed a dialog.
 */
enum class SmpState {
    NOT_VERIFIED, SECRET_REQUIRED, IN_PROGRESS, VERIFIED, FAILED, CANCELLED;

    companion object {
        /**
         * Unknown names fail safe to NOT_VERIFIED.
         *
         * The safe direction, and deliberately not VERIFIED: a state this
         * build has not been taught must never render as a confirmed
         * identity. `SmpStateTest` asserts the arms match the Python enum, so
         * a new state is a test failure rather than a silent downgrade.
         */
        fun fromName(name: String): SmpState =
            entries.firstOrNull { it.name.equals(name, ignoreCase = true) }
                ?: NOT_VERIFIED
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

/**
 * What a call request did, as returned by the Python bridge.
 *
 * Codes, never sentences. `android_bridge.voice.CallOutcome` defines the same
 * five and `tests/test_android_calls.py` asserts the two lists agree, so a
 * screen branching on these cannot drift from what Python answers.
 *
 * THESE ARE NOT CALL STATES. [CallState] is where a call has got to;
 * this is what happened when somebody asked for one. "started" means the
 * request reached the call manager and nothing more -- placing a call builds
 * I2P tunnels, so a call that has started has certainly not connected.
 */
object CallOutcome {
    const val STARTED = "started"
    const val NO_CALL = "no_call"
    const val ALREADY = "already"
    const val UNAVAILABLE = "unavailable"
    const val NOT_CONNECTED = "not_connected"

    /** Every code, so a `when` over them can be checked for completeness. */
    val ALL = listOf(STARTED, NO_CALL, ALREADY, UNAVAILABLE, NOT_CONNECTED)
}

/**
 * What a transfer request did, as returned by the Python bridge.
 *
 * Codes, never sentences, and never engine exception text.
 * `TransferError` messages are written for a person and name the file;
 * `android_bridge.files` reads them and discards them, and what crosses is
 * one of these. `tests/test_android_files.py` asserts the two lists agree.
 */
object FileOutcome {
    const val STARTED = "started"
    const val UNVERIFIED = "unverified"
    const val NO_SESSION = "no_session"
    const val BAD_FILE = "bad_file"
    const val NO_TRANSFER = "no_transfer"
    const val UNAVAILABLE = "unavailable"
    const val NOT_CONNECTED = "not_connected"
    const val CANNOT_SCRUB = "cannot_scrub"

    val ALL = listOf(STARTED, UNVERIFIED, NO_SESSION, BAD_FILE, NO_TRANSFER,
                     UNAVAILABLE, NOT_CONNECTED, CANNOT_SCRUB)
}

/**
 * What `android_bridge.metadata` found in a file before it was sent.
 *
 * [canScrub] false means the app does not understand the format and is
 * promising nothing -- NOT that the file is clean.
 */
data class MetadataFinding(
    val kind: String,
    val carriesMetadata: Boolean,
    val metadataBytes: Int,
    val canScrub: Boolean,
) {
    companion object {
        /** What to assume when the question could not be asked at all. */
        val UNKNOWN = MetadataFinding("unknown", false, 0, false)
    }
}

/**
 * One live transfer, as the engine reports it.
 *
 * [filename] has already been through the engine's `sanitise_filename`. It
 * was chosen by somebody else and is about to be rendered, which is the
 * whole reason that function exists.
 */
data class FileTransferView(
    val id: String,
    val peer: String,
    val filename: String,
    val sizeBytes: Long,
    /** True when this device is the sender. */
    val outgoing: Boolean,
    val accepted: Boolean,
    val cancelled: Boolean,
    /** 0f..1f. Chunks moved, not bytes confirmed by the far end. */
    val progress: Float,
    /** The engine's `TransferState` code; empty from an older bridge. */
    val state: String = "",
    /** The engine's `TransferReason` code, for FAILED/CANCELLED/DECLINED. */
    val reason: String = "",
)

data class SmpProgress(val step: Int, val total: Int, val state: SmpState)

/**
 * The outcome of a roster change, as the controller reported it.
 *
 * `ConnectionController._roster_call` has always returned `{ok, code, detail}`
 * and the Kotlin side used to discard it, which is why adding a contact on a
 * handset looked like a button that did nothing: Python was answering
 * `not_connected`, with a sentence explaining it, to nobody.
 *
 * [detail] is written by the controller for a person to read. Engine exception
 * text never reaches it -- a failure that did not come from the controller
 * carries a [code] and an empty [detail].
 */
data class RosterResult(
    val ok: Boolean,
    val code: String,
    val detail: String,
) {
    /** A sentence to show, or null when there is nothing worth saying. */
    fun message(): String? = when {
        ok -> null
        detail.isNotBlank() -> detail
        code == "not_connected" -> "Connect before changing the contact list."
        code == "not_prepared" -> "The connection is not ready yet."
        else -> "Could not add that contact ($code)."
    }
}

/**
 * What happened to a message the user sent.
 *
 * Three, not two. QUEUED is neither success nor failure and calling it either
 * is a lie: the message has not gone, and it has not been lost.
 */
enum class SendOutcome {
    /** The engine encrypted it and the transport took it. */
    ENCRYPTED,

    /** No session yet. The engine is holding it and will send it after the
     *  DAKE. Nothing is on the wire. */
    QUEUED,

    /** It will not be sent, and nothing is retrying. */
    FAILED,

    /**
     * It went, AS TYPED, readable by the server and by anything between it
     * and the peer.
     *
     * A success, and one that must never be reported in the same words as
     * [ENCRYPTED]. Nobody had asked for OTR on this conversation, so this is
     * ordinary XMPP behaving as ordinary XMPP -- which is what makes talking
     * to a plain client possible at all -- but the user is entitled to know
     * which of the two just happened.
     */
    PLAINTEXT,
    ;

    companion object {
        /**
         * Map Python's answer, failing to [FAILED].
         *
         * FAILED is the right unknown: it never claims a message went, and it
         * never claims one went encrypted. A new outcome name arriving from a
         * newer bridge shows as "not sent" rather than as a false padlock.
         */
        fun fromName(name: String): SendOutcome = when (name.lowercase()) {
            "encrypted" -> ENCRYPTED
            "queued" -> QUEUED
            "plaintext" -> PLAINTEXT
            else -> FAILED
        }
    }
}

/**
 * Where a roster entry has got to, as the XMPP server sees it.
 *
 * This matters to a person rather than only to a protocol. A contact you have
 * added but who has not yet approved you will show as "presence unknown" for
 * as long as they take to answer -- hours, or days -- and without a name for
 * that state the only conclusion available to the user is that the app is
 * broken. It was being read from the roster and then discarded.
 */
enum class Subscription {
    /** Asked, not yet answered. Their presence is genuinely unknowable. */
    PENDING,

    /** We see them; they do not see us. */
    TO,

    /** They see us; we do not see them, so presence stays unknown. */
    FROM,

    /** Both directions. The ordinary working state. */
    BOTH,

    /** On the roster, subscribed neither way. */
    NONE,

    /** The roster did not say, or said something we do not know. */
    UNKNOWN;

    /** Whether presence can be expected to mean anything for this contact. */
    val presenceIsKnowable: Boolean get() = this == BOTH || this == TO

    companion object {
        /**
         * Map the roster's own words, failing to [UNKNOWN].
         *
         * `pending` wins over the subscription state: a request that has been
         * sent and not answered leaves the subscription at "none", so reading
         * the subscription alone makes "waiting for them" and "on the roster,
         * not subscribed" identical.
         */
        fun of(subscription: String, pending: Boolean): Subscription {
            if (pending) return PENDING
            return when (subscription.lowercase()) {
                "both" -> BOTH
                "to" -> TO
                "from" -> FROM
                "none" -> NONE
                else -> UNKNOWN
            }
        }
    }
}

/**
 * What we know about a peer's availability, INCLUDING not knowing.
 *
 * Three states, because the problem has three. This replaced a `Boolean`, and
 * the boolean was the bug: it could not distinguish "the server has not told
 * us anything about this peer" from "this peer is offline", so a contact added
 * a moment ago was reported as offline — and the UI, correctly refusing to
 * claim knowledge it did not have, rendered "presence unknown" indefinitely.
 *
 * Mirrors `otrv4plus_presence.STATES` exactly.
 */
enum class PeerPresence {
    /** No presence stanza has arrived for this peer on this stream. */
    UNKNOWN,

    /** A presence stanza said they are available. */
    ONLINE,

    /** A presence stanza said they are not. */
    OFFLINE;

    companion object {
        /**
         * Map Python's answer, failing to [UNKNOWN].
         *
         * UNKNOWN is the right unknown: a value this layer does not recognise
         * must never be rendered as a claim about the peer.
         */
        fun of(name: String): PeerPresence = when (name.lowercase()) {
            "online" -> ONLINE
            "offline" -> OFFLINE
            else -> UNKNOWN
        }
    }
}

data class Contact(
    val jid: String,
    val displayName: String,
    /** What the server has told us about their availability. */
    val presence: PeerPresence,
    val security: SecurityState,
    val smp: SmpState,
    /**
     * Whether to *enable the call button*. The engine gates calls on its own
     * cryptographic predicate (VoiceCallManager._smp_verified); this flag is a
     * UI affordance and must never be treated as the gate.
     */
    val callAvailable: Boolean,
    /** Where the roster entry has got to. See [Subscription]. */
    val subscription: Subscription = Subscription.UNKNOWN,
    /** RFC 6121 show: "", "away", "chat", "dnd", "xa". Empty unless online. */
    val presenceShow: String = "",
) {
    /**
     * Kept for callers that genuinely want a boolean.
     *
     * Derived, never stored. False covers both OFFLINE and UNKNOWN, which is
     * the collapse this enum exists to undo — anything that must tell those
     * apart reads [presence].
     */
    val online: Boolean get() = presence == PeerPresence.ONLINE
}

/**
 * Where the transport has got to, and what it last said.
 *
 * Note what is NOT here: no security state, no fingerprint, no "encrypted"
 * flag. A connection is a socket to a server; being connected says nothing
 * about whether a session with a peer is encrypted, and a screen that blurred
 * the two would be claiming a property nobody had established. Security state
 * comes from [OtrCore.securityState], which asks the engine.
 *
 * [stage] is one of the Python controller's stages, in order: idle,
 * checking_router, building_tunnels, connecting, authenticating, connected,
 * failed. They are distinct because their remedies are, and because they are
 * three orders of magnitude apart in duration -- a refused SAM port answers in
 * milliseconds, a cold I2P tunnel can take four minutes.
 */
data class ConnectionStatus(
    val stage: String = "idle",
    val connected: Boolean = false,
    val jid: String = "",
    val server: String = "",
    val isDefaultServer: Boolean = false,
    val sam: String = "",
    /** A stable code to branch on: ok, refused, timeout, not_sam, auth_failed... */
    val code: String = "",
    /** A sentence for a person, naming the remedy where one is knowable. */
    val detail: String = "",
    /**
     * What actually crossed from Kotlin into the transport, minus the
     * password — which appears only as present/absent, never as a length.
     *
     * "Did the call fail, or did it get the wrong arguments" are two
     * questions, and from a handset they are indistinguishable without this.
     * Rendered in Python so there is one place deciding what a report may
     * contain.
     */
    val inputs: String = "",
    /**
     * Whether the transport's event-loop thread is still running.
     *
     * The transport works off the calling thread deliberately, so "nothing
     * happened" has two causes: the work failed, or the thread that should
     * have done it is gone. A dead loop under a connected-looking status is a
     * lifecycle bug, invisible unless something asks.
     */
    val workerAlive: Boolean = false,
)

/**
 * Whether a SAM bridge is listening, answered in milliseconds.
 *
 * Run before any tunnel attempt. Without it, "no router running" and "tunnel
 * still building" look identical for four minutes, and the user restarts the
 * app during the one case where waiting was the right thing to do.
 */
data class RouterProbe(
    val reachable: Boolean,
    val code: String,
    val detail: String,
    val version: String,
)

/**
 * What happened when the user pressed Create account.
 *
 * Deliberately NOT a [ConnectionStatus]. Registration ends with nobody signed
 * in, and reusing the connection's shape would put `connected = false` next to
 * a success -- which reads as a failure to anybody who has just been told
 * their account was created.
 *
 * [code] comes from `otrv4plus_registration.CODES`: `ok`, `conflict`,
 * `not_acceptable`, `unsupported`, `timeout`, `network`, `cancelled`,
 * `unknown` and the rest. [detail] is that module's sentence for the code,
 * chosen from a fixed table rather than built from the server's own words --
 * an XMPP error stanza carries the JID being registered, and this string is
 * rendered on screen.
 */
data class RegistrationOutcome(
    val ok: Boolean,
    val code: String,
    val detail: String,
) {
    /**
     * Whether retyping the username is the remedy, so the UI can put the
     * focus back where the fix is rather than making the user guess.
     */
    val isAboutTheUsername: Boolean
        get() = code == "conflict" || code == "not_acceptable"

    /**
     * Whether this server will never accept a registration, however good the
     * details are. Trying again is not the remedy and offering it wastes four
     * minutes of somebody's evening.
     */
    val isPermanent: Boolean
        get() = code == "unsupported" || code == "not_allowed" ||
            code == "service_unavailable" || code == "forbidden"
}

/**
 * Something the server hosts, from XEP-0030 service discovery.
 *
 * [category] and [type] are what make this useful: disco#items gives a name
 * and says nothing about what the thing IS, so finding the rooms service means
 * asking each item and looking for `conference`/`text`. The convention is
 * `conference.<domain>`, and it is a convention, not a rule — guessing it
 * wrong costs an I2P round trip to find out.
 */
data class DiscoveredService(
    val jid: String,
    val name: String,
    val category: String,
    val type: String,
) {
    /** Whether this is a Multi-User Chat service, per XEP-0045's identity. */
    val hostsRooms: Boolean get() = category == "conference" && type == "text"
}

/** A room a service advertises. Hidden rooms are absent by design. */
data class RoomSummary(val jid: String, val name: String) {
    /** The part before the `@`, for a service that advertises no name. */
    val label: String get() = name.ifBlank { jid.substringBefore('@') }
}

/**
 * What we are in a room, and therefore what we may do in it.
 *
 * TWO SEPARATE QUESTIONS, and conflating them is the commonest way to get
 * MUC wrong. [affiliation] is long-term standing with the room and survives
 * leaving; [role] is standing in this visit and is assigned on join. An owner
 * who joined a moderated room as a visitor cannot speak until given voice, and
 * a moderator who owns nothing cannot destroy the room however much of it they
 * run.
 *
 * The booleans are READ, not derived here. `otrv4plus_muc.privileges` works
 * them out from XEP-0045 §5.1 and is tested by being executed; a second
 * derivation on this side would be a second opinion that could disagree, and
 * the disagreement would show up as a button that fails minutes after it is
 * pressed.
 *
 * None of them is a promise. A True means the protocol does not forbid it; the
 * room's own configuration may still refuse, and what the service says is what
 * the app reports.
 */
data class RoomStanding(
    val room: String = "",
    val nick: String = "",
    val affiliation: String = "none",
    val role: String = "none",
    val speak: Boolean = false,
    val changeSubject: Boolean = false,
    val invite: Boolean = false,
    val kick: Boolean = false,
    val ban: Boolean = false,
    val configure: Boolean = false,
    val destroy: Boolean = false,
    val grantMembership: Boolean = false,
) {
    /** Whether any moderation control is worth showing at all. */
    val moderates: Boolean get() = kick || ban || configure || destroy
}

/**
 * What happened when a room operation ran.
 *
 * [code] is from `otrv4plus_muc.CODES` — `conflict`, `forbidden`,
 * `registration_required`, `not_allowed`, `item_not_found`, `timeout` and the
 * rest — and [detail] is that module's sentence for it, chosen from a fixed
 * table. Never the service's own words: a MUC error stanza carries the room,
 * the service and the nickname, and this string is rendered on screen.
 */
/** One person in a room, as the room reports them. */
data class RoomOccupant(val nick: String, val role: String, val affiliation: String)

data class RoomOutcome(
    val ok: Boolean,
    val code: String,
    val detail: String,
) {
    /**
     * Whether trying the same thing again could work. A ban will not stop
     * being a ban, and inviting a retry wastes four minutes of somebody's
     * evening on a network this slow.
     */
    val worthRetrying: Boolean
        get() = code == "timeout" || code == "network" ||
            code == "service_unavailable"

    /** Whether choosing a different nickname is the remedy. */
    val isAboutTheNickname: Boolean get() = code == "conflict"
}

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

    /**
     * Plaintext group chat. [room] is the room's JID; [sender] is the
     * nickname the ROOM assigned, which is not an identity claim. Kept a
     * separate type from [MessageReceived] so nothing can mistake a room's
     * plaintext for a peer's decrypted text.
     */
    data class RoomMessageReceived(
        val room: String, val sender: String, val body: String, val timestamp: Double,
    ) : OtrEvent
    /**
     * A file transfer moved. [state] and [reason] are the engine's
     * `TransferState` / `TransferReason` codes, never its text; [filename]
     * was sanitised by the engine. See `crypto/TransferUi`.
     */
    data class FileTransferChanged(
        val peer: String,
        val transferId: String,
        val filename: String,
        val size: Long,
        val outgoing: Boolean,
        val state: String,
        val reason: String,
    ) : OtrEvent
    data class SmpProgressed(val peer: String, val progress: SmpProgress) : OtrEvent
    data class SmpFinished(val peer: String, val state: SmpState) : OtrEvent

    /** The pinned fingerprint changed. The UI must block, not merely inform. */
    data class FingerprintChanged(
        val peer: String,
        val storedFingerprint: String,
        val receivedFingerprint: String,
    ) : OtrEvent

    data class CallChanged(val peer: String, val state: CallState, val durationSeconds: Int) : OtrEvent

    /**
     * Somebody asked to see this account's presence.
     *
     * [policy] decides what the screen is allowed to offer, and the two cases
     * are genuinely different rather than one being a softer version of the
     * other. Under [SubscriptionPolicy.ASK] nothing has been answered and the
     * user chooses. Under the shipped [SubscriptionPolicy.ACCEPT] the server
     * library already said yes before this event existed, so a prompt offering
     * to decline would be offering to undo something already done — see
     * [isQuestion].
     *
     * Approving is not a cryptographic act. It grants presence, not the
     * ability to read anything: messages stay plaintext until a DAKE runs.
     */
    data class SubscriptionRequested(
        val peer: String,
        val policy: SubscriptionPolicy,
    ) : OtrEvent {
        /** Whether the user still has a decision to make. */
        val isQuestion: Boolean get() = policy == SubscriptionPolicy.ASK
    }

    /** [code] is stable and machine-readable; there is no engine text here. */
    data class Failed(val peer: String?, val code: String) : OtrEvent
}

/**
 * What happens when someone asks to see this account's presence.
 *
 * Mirrors `android_bridge.transport.SubscriptionPolicy` exactly. Presence is
 * metadata: approving tells that account when this device is online, from
 * which resource, and how idle it is, for as long as they keep it.
 *
 * [UNKNOWN] exists because the alternative is worse. Python falls back to
 * ACCEPT for a policy string it does not recognise, and a Kotlin enum that did
 * the same would render "they can now see you" for a state it had not
 * understood — a confident sentence about a privacy grant, derived from a
 * parse failure. An unknown policy is shown as unknown.
 */
enum class SubscriptionPolicy {
    /** Approve, and ask for theirs back. The shipped default. */
    ACCEPT,

    /** Approve, but do not ask for theirs. */
    ACCEPT_ONE_WAY,

    /** Neither approve nor refuse — the user decides. */
    ASK,

    /** Refuse. */
    REJECT,

    /** Python said something this build does not know. */
    UNKNOWN;

    /** Whether a request under this policy is still the user's to answer. */
    val defersToUser: Boolean get() = this == ASK

    companion object {
        /** Map Python's own words, failing to [UNKNOWN] rather than to a default. */
        fun of(name: String): SubscriptionPolicy = when (name.trim().lowercase()) {
            "accept" -> ACCEPT
            "accept_one_way" -> ACCEPT_ONE_WAY
            "ask" -> ASK
            "reject" -> REJECT
            else -> UNKNOWN
        }
    }
}

fun interface OtrEventSink {
    fun onEvent(event: OtrEvent)
}

/** A bridge failure. Carries a code, never engine exception text. */
class OtrBridgeException(val code: String) : RuntimeException(code)
