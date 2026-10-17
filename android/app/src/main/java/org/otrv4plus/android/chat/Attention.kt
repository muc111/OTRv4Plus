// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SmpState

/**
 * Things that need the user, other than a message or a call: somebody asked
 * to verify, a group invitation came, a group needs its password. Owner
 * (2026-10-17): "a sound & vibrate when messages are received, SMP
 * verification requested, invited to group, password prompt for group ...
 * all notifications must not leak user or message."
 *
 * WHAT IT MAY SAY. The kind of thing, never who or which: "Verification
 * requested", not "Bob asked to verify"; "Group invitation", not the group's
 * name or the inviter. Like messages (InboundAlerts), one notification for
 * all of them, so the shade's entry count is not a count of people, and it
 * is hidden entirely on a locked screen.
 *
 * Plain Kotlin, so `AttentionTest` runs it.
 */
object Attention {

    enum class Kind(val text: String) {
        VERIFICATION("Verification requested"),
        GROUP_INVITE("Group invitation"),
        PASSWORD_NEEDED("A group needs its password"),
        ENTRY_REQUEST("Someone asks to join a group"),
    }

    /** The kind [event] calls for, or null: most events need nobody. */
    fun of(event: OtrEvent): Kind? = when (event) {
        // Emitted on the transition into SECRET_REQUIRED only, so a peer
        // resending its request cannot stack alerts (android_bridge/app.py).
        is OtrEvent.SmpProgressed ->
            if (event.progress.state == SmpState.SECRET_REQUIRED) Kind.VERIFICATION else null
        is OtrEvent.GroupInvited -> Kind.GROUP_INVITE
        // History replays old requests on every sign-in: banner, no buzz.
        is OtrEvent.GroupEntryRequested -> if (event.live) Kind.ENTRY_REQUEST else null
        else -> null
    }

    /** The notification's text for what is pending: kinds only, oldest first. */
    fun text(pending: List<Kind>): String = when {
        pending.isEmpty() -> ""
        pending.size == 1 -> pending[0].text
        else -> "${pending.size} things need your attention"
    }
}
