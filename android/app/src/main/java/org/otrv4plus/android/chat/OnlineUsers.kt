// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.crypto.SecurityLevel

/**
 * "Online users": who the SERVER says is online right now.
 *
 * Built from [Conversation.presence], which comes from XMPP presence stanzas
 * through the roster -- nothing here invents presence, and a contact whose
 * presence is unknown (not subscribed, not yet heard, or our own stream is
 * down) is NOT listed as online. Plain Kotlin, driven by `OnlineUsersTest`.
 *
 * FOUR SEPARATE FACTS PER ROW, never folded into one:
 *   online      -- the server says they are available;
 *   encrypted   -- an OTR session with them is running;
 *   verified    -- SMP proved who they are in that session;
 *   call        -- all of the above, which is what a call needs (the engine
 *                  still decides; this is a hint on the row).
 * Being online says nothing about the other three, and the row must not
 * imply it does.
 *
 * Tapping a row opens the conversation keyed by the same bare JID as the
 * conversation list, so there is one conversation per person however it
 * was reached.
 */
object OnlineUsers {

    data class Row(
        val jid: String,
        val displayName: String,
        val online: Boolean,
        val encrypted: Boolean,
        val verified: Boolean,
        val callReady: Boolean,
    ) {
        /** The facts as words, in order, for the row and for accessibility. */
        val facts: List<String>
            get() = buildList {
                add("online")
                add(if (encrypted) "OTR encrypted" else "not encrypted")
                if (verified) add("SMP verified")
                if (callReady) add("call available")
            }
    }

    /** Online people only, alphabetical, one row per bare JID. */
    @JvmStatic
    fun rows(conversations: List<Conversation>): List<Row> =
        conversations
            .filter { it.presence == Presence.ONLINE }
            .distinctBy { ChatState.bare(it.jid) }
            .map { c ->
                val level = SecurityLevel.of(c.security)
                val encrypted = SecurityLevel.encrypts(level)
                val verified = c.security == SecurityState.SMP_VERIFIED &&
                    c.smp == SmpState.VERIFIED
                Row(
                    jid = ChatState.bare(c.jid),
                    displayName = c.displayName,
                    online = true,
                    encrypted = encrypted,
                    verified = verified,
                    callReady = verified,
                )
            }
            .sortedBy { it.displayName.lowercase() }

    /** The header: "ONLINE USERS (3)". */
    @JvmStatic
    fun title(count: Int): String = "ONLINE USERS ($count)"
}
