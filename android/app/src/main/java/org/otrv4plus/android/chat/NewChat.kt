// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * "New chat": who is online, to start an OTRv4+ chat with in one tap, and an
 * address for anyone else. Owner (2026-10-25): "when we click on it we should
 * be given a list of users who are online to start a new otrv4+ chat with
 * instead of manually typing names in".
 *
 * The list is [OnlineUsers.directory] -- the roster, the Welcome room and the
 * server's own list -- so nothing here is guessed. Plain Kotlin, driven by
 * `NewChatTest`.
 */
object NewChat {

    const val TITLE = "New OTRv4+ chat"
    const val SEARCH_HINT = "Search, or type an address"
    const val EMPTY = "Nobody else is online right now. Type their address to start a chat anyway."
    const val NO_MATCH = "Nobody online matches. Type their full address to start a chat."
    const val NOTE = "Someone not in your contacts is sent a contact request; " +
        "your messages wait, encrypted, until they accept."

    /** Online people, contacts first, alphabetical inside; [query] narrows. */
    fun online(entries: List<OnlineUsers.Entry>, query: String = ""): List<OnlineUsers.Entry> =
        OnlineUsers.search(entries, query)
            .filter { it.relation == OnlineUsers.Relation.ADDED_ONLINE ||
                      it.relation == OnlineUsers.Relation.ONLINE_ADD }
            .sortedWith(compareBy({ it.relation != OnlineUsers.Relation.ADDED_ONLINE },
                                  { it.displayName.lowercase() }, { it.jid }))

    /**
     * What was typed, as an address to start a chat with, or null: a full
     * address, or a user name completed with our own server ("bob" ->
     * bob@our.server). Never our own address.
     */
    fun address(query: String, self: String): String? {
        val q = query.trim().lowercase()
        if (q.isEmpty() || q.any { it.isWhitespace() } || q.count { it == '@' } > 1) return null
        val me = ChatState.bare(self).lowercase()
        val jid = when {
            '@' in q -> q.takeIf { !it.startsWith("@") && !it.endsWith("@") && '.' in it.substringAfter('@') }
            me.contains('@') -> "$q@${me.substringAfter('@')}"
            else -> null
        } ?: return null
        return jid.takeIf { it != me }
    }

    fun startButton(jid: String): String = "Chat with $jid"

    /** The second line of a row. */
    fun subtitle(e: OnlineUsers.Entry): String =
        if (e.relation == OnlineUsers.Relation.ADDED_ONLINE) "Online · contact" + if (e.verified) " · SMP verified" else ""
        else "Online · not a contact yet"
}
