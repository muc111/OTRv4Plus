// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.CallState

/**
 * When an incoming call should ring the phone, and when it should stop.
 *
 * WHY THIS EXISTS
 * ---------------
 * `ChatState.handle` returns false for every call event, which means "do not
 * notify" -- so a call arriving while the app was in the background produced
 * nothing at all. The user would learn about it by opening the conversation,
 * usually after it had timed out. That is not a phone call.
 *
 * WHY RINGING IS SAFE TO ANNOUNCE
 * -------------------------------
 * The earlier reasoning for staying silent was that "a peer able to trigger a
 * notification is a peer with a way to ring somebody at will". For RINGING
 * specifically that does not hold, and the reason is structural rather than
 * hopeful: `VoiceCallManager._on_invite` refuses a peer whose identity is not
 * SMP-verified BEFORE a session exists, so no RINGING state can be created by
 * an unverified peer at all; `handle_signal` rate-limits every control
 * message per peer before doing any work; and the caller is held to one
 * invite per `VOICE_MIN_INVITE_INTERVAL`. The only people who can make this
 * ring are people the user has verified -- which is the definition of who a
 * phone should ring for.
 *
 * `tests/test_android_calls.py` drives that gate with a real INVITE from an
 * unverified peer and asserts the refusal reason, so this argument is
 * checked rather than assumed.
 *
 * WHAT THE NOTIFICATION MAY SAY
 * -----------------------------
 * The same as the message notification: nothing about who. "Incoming call",
 * hidden entirely on a locked screen. A lock-screen line naming the caller
 * would announce exactly who talks to this device and when.
 */
object CallAlert {

    enum class Change {
        /** A call just started ringing. Ring the phone. */
        START,

        /** Ringing stopped -- answered, rejected, timed out. Take it down. */
        STOP,
    }

    /**
     * What changed between [previous] and [next] for one peer, if anything
     * worth a notification.
     *
     * Only the TRANSITION into RINGING rings. A repeated RINGING (the same
     * state reported again by a later poll) must not ring twice, or a single
     * call would buzz the phone once per drain.
     */
    @JvmStatic
    fun change(previous: CallState, next: CallState): Change? = when {
        next == CallState.RINGING && previous != CallState.RINGING ->
            Change.START
        previous == CallState.RINGING && next != CallState.RINGING ->
            Change.STOP
        else -> null
    }
}
