// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * Whether a login the user asked for is still in progress.
 *
 * THE GAP THIS FILLS
 * ------------------
 * Pressing "Log in" handed the work to [OtrConnectionService] and returned.
 * Nothing on the screen changed until the service had entered a busy phase AND
 * the next poll tick had read it back, so on a cold start the button looked
 * ignored. On I2P the operation that follows takes 30-120+ seconds, which is
 * exactly the situation where a user needs to know the press was accepted --
 * and exactly the situation where they will press it again if it was not.
 *
 * "Create account" never had this problem because it runs in a ViewModel
 * coroutine and sets `busy` on the same line as the call. A login cannot do
 * that: the service owns the attempt, so the answer arrives later and from
 * somewhere else.
 *
 * WHY THE HANDOVER NEEDS A DEADLINE
 * ---------------------------------
 * The obvious version -- a flag set on tap, cleared when the service reports a
 * phase -- can stick. If the service never starts, or starts and reports
 * nothing, the flag stays true, the spinner runs forever and the button stays
 * disabled, and the only way out is killing the app. That is a worse bug than
 * the missing spinner.
 *
 * So the tap is believed only until [HANDOVER_MS]. That window covers the
 * service starting and one poll tick; it is NOT the connection timeout, which
 * is the service's and may be minutes. Past it, the phase is the only thing
 * speaking, and a phase that says "idle" means the buttons come back.
 *
 * Plain Kotlin with no Android import, so the rule is executed by a JVM test
 * rather than reviewed -- this screen cannot be run anywhere else.
 */
class LoginProgress(private val now: () -> Long = { System.currentTimeMillis() }) {

    /** When "Log in" was last tapped, or 0 when no tap is outstanding. */
    private var requestedAt: Long = 0L

    /**
     * Record that the user asked to log in.
     *
     * Takes effect immediately: [inProgress] is true on the next read, before
     * the service has been started, let alone answered.
     */
    fun requested() {
        requestedAt = now()
    }

    /**
     * The user withdrew the request -- Cancel, Back, sign out.
     *
     * Clears the tap unconditionally. A cancelled attempt whose spinner kept
     * running would be the stuck screen this class exists to avoid, and the
     * phase alone cannot be trusted to arrive promptly after a cancel.
     */
    fun cancelled() {
        requestedAt = 0L
    }

    /**
     * Fold in what the service now says.
     *
     * Once the service is speaking, it is the authority and the tap is
     * forgotten. That includes [LinkPhase.FAILED] and [LinkPhase.CONNECTED]:
     * both are answers, and continuing to show "connecting" over either would
     * be the UI contradicting the thing it is reporting.
     */
    fun observe(phase: LinkPhase) {
        if (requestedAt == 0L) return
        if (phase.busy || phase == LinkPhase.CONNECTED ||
            phase == LinkPhase.FAILED) {
            requestedAt = 0L
        }
    }

    /** Whether the tap is still worth believing on its own. */
    private val pending: Boolean
        get() = requestedAt != 0L && (now() - requestedAt) < HANDOVER_MS

    /**
     * Whether to show the in-progress state for [phase].
     *
     * DISCONNECTING is excluded for the same reason the old `connecting`
     * excluded it: tearing down at the user's request is not a login, and
     * showing "logging in" while signing out would be untrue.
     */
    fun inProgress(phase: LinkPhase): Boolean =
        pending || (phase.busy && phase != LinkPhase.DISCONNECTING)

    /**
     * What to put next to the progress bar.
     *
     * The phase's own words once it has any, because they say which of the
     * slow parts is running -- SAM, the tunnel, XMPP, authentication -- and on
     * a two-minute operation that is the difference between waiting and
     * force-quitting. Before the service answers there is nothing truthful to
     * add beyond that the press was taken.
     */
    fun label(phase: LinkPhase): String = when {
        phase == LinkPhase.CONNECTING -> "Connecting over I2P. This can take a minute or two."
        phase == LinkPhase.STARTING -> "Starting the connection service..."
        phase == LinkPhase.RECONNECTING -> "Connection lost. Trying again..."
        pending -> "Connecting..."
        else -> "Connecting..."
    }

    /**
     * The failure to put on screen, or null.
     *
     * THE RULE THE HANDSET BUG BROKE, stated where it can be executed. The
     * latch that caused it lived in `ConnectionViewModel`, which imports
     * Compose and cannot be compiled outside CI; this is the decision it makes,
     * moved somewhere a JVM test can drive it.
     *
     * Three states, three answers:
     *
     *   * **connected** — nothing. A previous attempt's verdict is superseded
     *     by a session that exists. Printing it beside a working connection is
     *     precisely the untruth reported from the handset.
     *   * **in progress** — nothing. An attempt that is still running has not
     *     failed, and last time's code next to a live progress bar reads as
     *     this time having failed.
     *   * **otherwise** — the failure, unchanged. A genuine failure is NOT
     *     masked because something later succeeded; when nothing later has
     *     succeeded, it is still the authoritative answer and it is shown.
     */
    fun problemToShow(
        connected: Boolean,
        phase: LinkPhase,
        failure: String?,
    ): String? = when {
        failure.isNullOrBlank() -> null
        connected -> null
        inProgress(phase) -> null
        else -> failure
    }

    companion object {
        /**
         * How long a tap is believed without corroboration, in ms.
         *
         * Covers starting the service and one poll tick, with room to spare.
         * NOT the connection timeout: an I2P tunnel may take minutes and the
         * phase reports that perfectly well once it exists.
         */
        const val HANDOVER_MS = 10_000L
    }
}
