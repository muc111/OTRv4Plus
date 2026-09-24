// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.SecurityState

/**
 * What the call controls offer, and what the call screen says.
 *
 * DEPENDENCY-FREE ON PURPOSE. No Compose, no Android: the rules below are
 * the part that can be wrong, and this container cannot build Compose, so
 * they live where `CallUiTest` executes them. Same split as [Verification]
 * and `connection/Startup.kt`.
 *
 * TWO THINGS THIS REFUSES TO DO
 * -----------------------------
 * **It never offers a call to an unverified peer.** Encryption alone proves
 * nobody is listening, not who is on the line, and a call to somebody whose
 * identity has not been checked is the one thing this subsystem's gate
 * exists to prevent. The real gate is `VoiceCallManager`'s, read from the
 * engine's own predicate; this is the affordance, and it must not offer what
 * that gate will refuse.
 *
 * **It never claims a call is secure because a button was pressed.** Every
 * phase below is derived from a [CallState] the engine reports. There is no
 * optimistic "connecting…" that outlives the engine's own answer, and
 * nothing here can render ACTIVE unless the state machine reached ACTIVE --
 * which it does only after mutual key confirmation.
 */
object CallUi {

    /** What the call control should be, if anything. */
    sealed interface Offer {
        /** Verified, encrypted, and the device can do voice. Offer the call. */
        data object Available : Offer

        /**
         * Encrypted but not verified. The control is shown DISABLED with
         * this reason rather than hidden: a user who cannot find the call
         * button concludes the app is broken, and one who is told "verify
         * first" knows what to do next.
         */
        data object NeedsVerification : Offer

        /** No encrypted session yet. Nothing to call over. */
        data object NeedsEncryption : Offer

        /** This device cannot do voice at all. [reason] comes from Python. */
        data class Unavailable(val reason: String) : Offer
    }

    /**
     * What to offer for a conversation.
     *
     * [voiceUnavailableReason] is Python's answer from
     * `otrv4plus_voice`'s own host hook -- empty when voice can run. Asked
     * for rather than re-derived, so the button and the engine cannot
     * disagree about whether this device has audio.
     */
    @JvmStatic
    fun offer(security: SecurityState, voiceUnavailableReason: String): Offer {
        // Device capability first: a phone with no audio backend cannot call
        // anybody, verified or not, and saying "verify first" there would
        // send the user to do something that will not help.
        if (voiceUnavailableReason.isNotBlank()) {
            return Offer.Unavailable(voiceUnavailableReason)
        }
        return when (security) {
            SecurityState.SMP_VERIFIED -> Offer.Available
            // Both of these are encrypted without a checked identity. They
            // read the same here on purpose: FINGERPRINT means the key
            // matches a previous pin, which is not somebody confirming who
            // they are.
            SecurityState.ENCRYPTED,
            SecurityState.FINGERPRINT -> Offer.NeedsVerification
            // A changed key is not a "verify first" situation. Offering to
            // verify would invite the user to run SMP against whoever holds
            // the new key, which is exactly the wrong next step.
            SecurityState.FINGERPRINT_MISMATCH -> Offer.NeedsEncryption
            SecurityState.PLAINTEXT -> Offer.NeedsEncryption
        }
    }

    /**
     * Why the call control is, or is not, offered. ONE value per state, in a
     * fixed order, so "why is there no call button" always has an answer and
     * a test can pin it. Mirrors `OtrApp.CALL_GATES`.
     */
    enum class Gate(val code: String) {
        AVAILABLE("available"),
        WIPED("wiped"),
        ROOM("room"),
        NOT_CONNECTED("not_connected"),
        NO_SESSION("no_session"),
        FINGERPRINT_CHANGED("fingerprint_changed"),
        NOT_VERIFIED("not_verified"),
        VOICE_UNAVAILABLE("voice_unavailable"),
        /** The bridge answered with a code this build does not know. */
        UNKNOWN("unknown");

        companion object {
            @JvmStatic
            fun of(code: String): Gate = entries.firstOrNull { it.code == code } ?: UNKNOWN
        }
    }

    /**
     * The gate as this side can see it, for when the bridge cannot be asked.
     * Never more permissive than the engine: AVAILABLE only for an
     * SMP-verified session this app has been told is live.
     */
    @JvmStatic
    fun localGate(
        connected: Boolean,
        isRoom: Boolean,
        security: SecurityState,
        voiceUnavailableReason: String,
    ): Gate = when {
        isRoom -> Gate.ROOM
        !connected -> Gate.NOT_CONNECTED
        security == SecurityState.FINGERPRINT_MISMATCH -> Gate.FINGERPRINT_CHANGED
        security == SecurityState.PLAINTEXT -> Gate.NO_SESSION
        security != SecurityState.SMP_VERIFIED -> Gate.NOT_VERIFIED
        voiceUnavailableReason.isNotBlank() -> Gate.VOICE_UNAVAILABLE
        else -> Gate.AVAILABLE
    }

    /**
     * The control for a [gate]. Only AVAILABLE enables it; every other gate
     * shows it DISABLED with its reason -- nothing is hidden without a word,
     * which is how "the call button did not appear" went unexplained.
     * A room shows nothing: calls are one-to-one and the room header says so.
     */
    @JvmStatic
    fun control(gate: Gate, reason: String = ""): Control = when (gate) {
        Gate.AVAILABLE -> Control(true, true, "Call")
        Gate.ROOM -> Control(false, false, "")
        Gate.WIPED -> Control(true, false, "Call unavailable — the app was wiped")
        Gate.NOT_CONNECTED -> Control(true, false, "Call — connect first")
        Gate.NO_SESSION -> Control(true, false, "Call — start encryption first")
        Gate.FINGERPRINT_CHANGED ->
            Control(true, false, "Call unavailable — their key changed")
        Gate.NOT_VERIFIED -> Control(true, false, "Call — verify this contact first")
        Gate.VOICE_UNAVAILABLE -> Control(true, false,
            "Call unavailable — " + reason.ifBlank { "voice cannot run on this device" })
        Gate.UNKNOWN -> Control(true, false, "Call unavailable")
    }

    data class Control(val visible: Boolean, val enabled: Boolean, val label: String)

    /** Which way a call is going, when one is going at all. */
    enum class Direction { OUTGOING, INCOMING, NONE }

    /** What the call screen shows and which buttons it offers. */
    data class Phase(
        /** One short line describing where the call has got to. */
        val label: String,
        /** True once the engine says media is flowing with confirmed keys. */
        val connected: Boolean,
        /** Whether to offer Answer. Only ever for an inbound call. */
        val canAnswer: Boolean,
        /** Whether to offer End (which is also Reject for a ringing call). */
        val canEnd: Boolean,
        /** Whether a duration should be shown and counted. */
        val showsDuration: Boolean,
        /** Whether the screen should be on at all. */
        val active: Boolean,
    )

    /**
     * What to show for [state].
     *
     * [direction] separates the two sides of the same states. RINGING means
     * "they are calling us"; INVITING means "we are calling them" -- and a
     * screen that showed Answer during an outgoing call would offer to
     * answer a call the user placed.
     *
     * EXHAUSTIVE, with no `else`. A new [CallState] must not be able to
     * arrive and inherit whatever the fallback happened to say; the compiler
     * makes somebody decide what it means.
     */
    @JvmStatic
    fun phase(state: CallState, direction: Direction = Direction.NONE): Phase =
        when (state) {
            CallState.IDLE -> Phase(
                label = "", connected = false, canAnswer = false,
                canEnd = false, showsDuration = false, active = false)

            // The long one. `start_call` builds I2P tunnels, which the call
            // manager itself describes as 30-120 s and longer on a busy
            // phone, so this says what is happening rather than leaving a
            // spinner to imply something is stuck.
            CallState.INVITING -> Phase(
                label = "Calling — building the private route, " +
                        "this can take a minute or two",
                connected = false, canAnswer = false, canEnd = true,
                showsDuration = false, active = true)

            CallState.RINGING -> Phase(
                label = if (direction == Direction.OUTGOING)
                    "Ringing" else "Incoming call",
                connected = false,
                canAnswer = direction != Direction.OUTGOING,
                canEnd = true, showsDuration = false, active = true)

            CallState.CONNECTING -> Phase(
                label = "Connecting", connected = false, canAnswer = false,
                canEnd = true, showsDuration = false, active = true)

            // NOT "secure" yet, and this is the distinction the whole screen
            // turns on: keys are being confirmed, and until they are there
            // is nothing to claim.
            CallState.KEY_CONFIRMING -> Phase(
                label = "Confirming keys", connected = false,
                canAnswer = false, canEnd = true, showsDuration = false,
                active = true)

            CallState.MEDIA_CONNECTING -> Phase(
                label = "Opening the audio path", connected = false,
                canAnswer = false, canEnd = true, showsDuration = false,
                active = true)

            // The only phase that reads as a working call, and the only one
            // the engine reaches after mutual key confirmation.
            CallState.ACTIVE -> Phase(
                label = "Connected", connected = true, canAnswer = false,
                canEnd = true, showsDuration = true, active = true)

            CallState.ENDING -> Phase(
                label = "Ending", connected = false, canAnswer = false,
                canEnd = false, showsDuration = false, active = true)

            CallState.ENDED -> Phase(
                label = "Call ended", connected = false, canAnswer = false,
                canEnd = false, showsDuration = false, active = false)
        }

    /**
     * How long a call has lasted, for a person.
     *
     * Seconds below a minute, `m:ss` above, and never a leading hour that is
     * always zero.
     */
    @JvmStatic
    fun elapsed(seconds: Int): String {
        val total = if (seconds < 0) 0 else seconds
        if (total < 60) return "${total}s"
        return "%d:%02d".format(total / 60, total % 60)
    }

    /**
     * What to tell the user when a call request came back refused.
     *
     * Maps `android_bridge.voice.CallOutcome` codes. Null for "started",
     * which is not a refusal and needs nothing said.
     */
    @JvmStatic
    fun refusal(outcome: String): String? = when (outcome) {
        "started" -> null
        "no_call" -> "There is no call to act on."
        "already" -> "You are already in a call with this contact."
        "not_connected" -> "Connect before placing a call."
        "unavailable" -> "Voice is not available on this device."
        // Deliberately not silent. An outcome this build has not been taught
        // is still a refusal, and saying nothing would leave a button that
        // did nothing with no explanation.
        else -> "The call could not be started."
    }
}
