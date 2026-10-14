// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Which sound something makes. Plain Kotlin, so `SoundPolicyTest` runs it.
 *
 * Owner (2026-10-14): "Notification sounds for incoming messages, calls etc."
 * A messenger that is silent while you look at another app, or that rings a
 * call like a text message, is missed. The rules, each the usual one:
 *
 *  * a NEW message while the app is in the background: the notification,
 *    with the system's message sound (once per run -- InboundAlerts);
 *  * a new message while the app is on screen but in ANOTHER conversation:
 *    a short in-app tone, no notification;
 *  * a new message in the conversation on screen: nothing -- you are
 *    looking at it;
 *  * a 1:1 call ringing: the ringtone, repeating until it is answered,
 *    rejected or ends (only a verified peer can ring -- CallAlert);
 *  * a group call starting: the ringtone once (a group call has no single
 *    "answered" moment to stop a repeating ring on).
 *
 * Nothing here decides WHAT a notification says: it says "New message" or
 * "Incoming call" and never who or what (InboundAlerts).
 */
object SoundPolicy {

    enum class Sound { NONE, IN_APP_TONE, NOTIFICATION, RING_REPEATING, RING_ONCE }

    /** A new message from [from] (bare JID or room) was stored. */
    fun forMessage(appVisible: Boolean, openConversation: String?, from: String): Sound = when {
        !appVisible -> Sound.NOTIFICATION
        openConversation != null && ChatState.bare(openConversation) == ChatState.bare(from) -> Sound.NONE
        else -> Sound.IN_APP_TONE
    }

    fun forCall(group: Boolean): Sound = if (group) Sound.RING_ONCE else Sound.RING_REPEATING
}
