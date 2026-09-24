// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * The authoritative connection phase, owned by the service.
 *
 * WHY AN EXPLICIT PHASE AND NOT A BOOLEAN
 * ---------------------------------------
 * "Connected" and "not connected" cannot express the three states a user most
 * needs to tell apart on this transport: building an I2P tunnel (slow, normal,
 * nothing is wrong), waiting out a backoff after a drop (nothing is wrong
 * either, but nothing is happening yet), and genuinely stopped. Collapsing
 * them is how an app spends ninety seconds looking broken while it works.
 *
 * These are ANDROID/XMPP TRANSPORT phases. None of them says anything about
 * OTR, about a peer, or about trust -- `SecurityState` is a different axis
 * entirely and the UI must never derive one from the other.
 */
enum class LinkPhase {
    /** Nothing is running and nothing is wanted. */
    STOPPED,

    /** The service is up; Python and the engine are starting. */
    STARTING,

    /** SAM, then the tunnel, then XMPP, then authentication. */
    CONNECTING,

    /** Authenticated. Roster and presence follow. */
    CONNECTED,

    /** A connection was lost and another attempt is scheduled. */
    RECONNECTING,

    /** Tearing down at the user's request. */
    DISCONNECTING,

    /** Stopped after a failure the user has to see. */
    FAILED,
    ;

    /** Whether messages can be sent. Only one phase qualifies. */
    val canSend: Boolean get() = this == CONNECTED

    /**
     * Whether something is in progress.
     *
     * Used for the spinner, and deliberately true for RECONNECTING: waiting
     * out a backoff IS the app working on it, and showing it as idle invites
     * the user to start a second attempt.
     */
    val busy: Boolean
        get() = this == STARTING || this == CONNECTING ||
            this == RECONNECTING || this == DISCONNECTING

    companion object {
        /**
         * Every stage `ConnectionController.STAGES` declares, named here.
         *
         * THIS IS NOT A THIRD MODEL. There is one vocabulary and it belongs
         * to `android_bridge.connection`; this is the projection of it onto
         * the four things a screen needs to distinguish. Listing the stages
         * rather than pattern-matching a few of them is what makes a stage
         * added in Python and forgotten here VISIBLE: `tests/` binds this set
         * against the real `STAGES` tuple, so the two cannot drift apart
         * silently — which is how `disconnected` shipped once as a stage the
         * screen rendered raw because nothing had declared it existed.
         */
        val STAGES: Set<String> = setOf(
            "idle", "checking_router", "building_tunnels", "connecting",
            "authenticating", "connected", "registered", "disconnected",
            "cancelled", "failed",
        )

        /**
         * Map the transport's own stage string onto a phase.
         *
         * A word this build does not know maps to CONNECTING rather than to
         * CONNECTED or FAILED — an unknown stage is progress of some kind,
         * and must not be reported as either success or defeat.
         */
        fun fromStage(stage: String, connected: Boolean): LinkPhase = when {
            connected -> CONNECTED
            stage == "idle" || stage == "" -> STOPPED
            stage == "disconnected" -> STOPPED
            stage == "cancelled" -> STOPPED
            // An account was created and NOBODY IS SIGNED IN. Not CONNECTING:
            // the operation finished, and a spinner left running after it
            // would say the app was still working on something it is not.
            // Not FAILED either — it succeeded.
            stage == "registered" -> STOPPED
            stage == "failed" -> FAILED
            else -> CONNECTING
        }
    }
}
