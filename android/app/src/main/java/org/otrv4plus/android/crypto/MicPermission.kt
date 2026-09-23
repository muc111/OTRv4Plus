// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * What to do about the microphone, decided without touching Android.
 *
 * Android's permission API is three facts -- granted, whether a rationale
 * should be shown, and whether we have asked before -- and one action, the
 * request. The mapping between them is where the mistakes live: asking again
 * after a permanent denial does nothing and looks like a broken button, and
 * proceeding to open the microphone without the grant fails inside AAudio
 * where the user cannot see why.
 *
 * So the mapping is here, as a pure function, and the Composable does the two
 * things only Android can do: read the flags and launch the request.
 *
 * THE PERMANENT-DENIAL CASE IS THE ONE THAT MATTERS. Android stops showing
 * the system dialog after the second refusal and the launcher returns
 * immediately with "denied". A UI that keeps calling it is a button that
 * silently does nothing forever, which is why [Decision.OpenSettings] exists:
 * past that point the only route back is Settings, and the app has to say so.
 */
object MicPermission {

    /** Android's three facts about one runtime permission. */
    data class State(
        val granted: Boolean,
        /**
         * Android's `shouldShowRequestPermissionRationale`. True only
         * between the first refusal and a permanent one -- it is false
         * before the first ask AND after a permanent denial, which is
         * exactly why it cannot be read alone.
         */
        val shouldShowRationale: Boolean,
        /**
         * Whether this app has asked before, remembered by us.
         *
         * ANDROID DOES NOT TELL US THIS, and without it "never asked" and
         * "permanently denied" are indistinguishable: both report
         * granted=false, rationale=false. Getting them confused means either
         * never asking at all, or asking forever into a dialog that no
         * longer appears.
         */
        val askedBefore: Boolean,
    )

    sealed interface Decision {
        /** Nothing to do; open the microphone. */
        data object Proceed : Decision

        /** Launch the system permission request. */
        data object Request : Decision

        /**
         * Explain first, then request. Android asks us to do this after a
         * refusal, and an explanation is the only thing that makes the
         * second dialog more likely to be answered differently.
         */
        data object ExplainThenRequest : Decision

        /**
         * The system dialog will not appear again. Send the user to
         * Settings, and say why -- there is no other route back.
         */
        data object OpenSettings : Decision
    }

    /**
     * What to do next, given what Android says.
     *
     * Exhaustive over the three flags, and deliberately written so the
     * permanently-denied case cannot be reached by accident: it needs BOTH
     * "we have asked" AND "Android will not show a rationale", which
     * together mean the dialog is spent.
     */
    @JvmStatic
    fun decide(state: State): Decision = when {
        state.granted -> Decision.Proceed
        state.shouldShowRationale -> Decision.ExplainThenRequest
        state.askedBefore -> Decision.OpenSettings
        else -> Decision.Request
    }

    /**
     * Whether the microphone may be opened.
     *
     * Separate from [decide] so the audio path can ask the narrow question
     * without reasoning about dialogs. FAIL CLOSED: anything other than a
     * live grant is a no, because attempting capture without one fails
     * inside AAudio where the user cannot see it.
     */
    @JvmStatic
    fun mayCapture(state: State): Boolean = state.granted

    /** What to say when explaining the request. One sentence, no pleading. */
    const val RATIONALE =
        "A call needs the microphone. Audio is encrypted on this device and " +
        "sent over I2P; it is never recorded and never leaves the call."

    /** What to say once the system dialog has stopped appearing. */
    const val PERMANENTLY_DENIED =
        "Android will not ask again. To make calls, turn on the microphone " +
        "for OTRv4+ in Settings."

    /** What to say when a call cannot start because permission was refused. */
    const val REFUSED = "Calls need the microphone. This call was not started."
}
