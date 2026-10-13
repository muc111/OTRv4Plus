// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.Vault

/**
 * Conversations the user deleted, so their rows stay gone.
 *
 * WHY DELETING THE HISTORY IS NOT ENOUGH
 * --------------------------------------
 * The conversation list is the union of the roster, the message store and
 * the saved contacts (`ChatState.conversations`). Deleting a conversation's
 * history removes it from the store, but a contact who is on the server's
 * roster would get their row straight back on the next roster poll -- an
 * empty row, but the one the user just deleted. This remembers the deletion,
 * sealed in the vault with everything else, so the row stays gone across
 * restarts until the conversation has something in it again: a message
 * arrives, the user sends one, or the user opens it from somewhere else.
 *
 * DELETION TIME, AND WHY IT OUTLIVES THE ROW
 * ------------------------------------------
 * A room replays its recent history to everybody who joins, and this app
 * rejoins its rooms on every reconnect. Deleting a room chat removes its
 * records, so that replay would otherwise count as new messages and bring
 * the deleted chat straight back, old messages and all. Each deletion
 * records WHEN ([cutoff]); room history stamped at or before it is ignored
 * (`ChatState.receiveRoom`). The cutoff is kept after the row comes back,
 * so a later rejoin does not pour the pre-deletion history into the
 * restored chat either.
 *
 * It holds addresses and times only. Nothing about what was said.
 *
 * Bound per account, like [SavedContacts], and destroyed by Wipe & Exit with
 * the vault; forgotten by Sign out with the account's other records.
 */
class DeletedConversations(
    private val vault: Vault?,
    private val now: () -> Long = { System.currentTimeMillis() },
) {

    private var scope: AccountScope = AccountScope.NONE
    private val deleted = LinkedHashSet<String>()
    /** jid -> when it was last deleted (ms). Survives [restore]. */
    private val cutoffs = LinkedHashMap<String, Long>()

    fun bind(next: AccountScope) {
        if (next == scope) return
        scope = next
        deleted.clear()
        cutoffs.clear()
        if (!next.isAuthenticated) return
        val bytes = vault?.get(recordName()) ?: return
        try {
            val loaded = now()
            for (line in String(bytes, Charsets.UTF_8).split("\n")) {
                val parts = line.split("\t")
                val jid = ChatState.bare(parts[0])
                if (jid.isEmpty()) continue
                // Format: jid \t cutoff \t d|c (deleted, or cutoff only).
                // A bare "jid" line is the format before cutoffs existed: it
                // was deleted at some time before now, so everything already
                // said in it -- which is all a rejoin can replay -- predates
                // this load.
                val at = parts.getOrNull(1)?.toLongOrNull() ?: loaded
                cutoffs[jid] = at
                if (parts.getOrNull(2) != "c") deleted.add(jid)
            }
        } finally {
            bytes.fill(0)
        }
    }

    fun contains(jid: String): Boolean = ChatState.bare(jid) in deleted

    fun all(): Set<String> = deleted.toSet()

    /** When [jid] was last deleted, or null if it never was. */
    fun cutoff(jid: String): Long? = cutoffs[ChatState.bare(jid)]

    /** Whether a message stamped [at] (ms) was said before [jid] was deleted. */
    fun predatesDeletion(jid: String, at: Long): Boolean =
        cutoff(jid)?.let { at <= it } ?: false

    /** Remember that [jid] was deleted, now. Returns whether anything changed. */
    fun add(jid: String): Boolean {
        if (!scope.isAuthenticated) return false
        val bare = ChatState.bare(jid)
        if (bare.isEmpty()) return false
        val wasDeleted = !deleted.add(bare)
        cutoffs[bare] = maxOf(cutoffs[bare] ?: 0L, now())
        persist()
        return !wasDeleted
    }

    /** [jid] has something in it again; show it. The cutoff stays. */
    fun restore(jid: String): Boolean {
        if (!scope.isAuthenticated) return false
        if (!deleted.remove(ChatState.bare(jid))) return false
        persist()
        return true
    }

    /** Drop this account's record entirely, on sign-out. */
    fun forgetAccount() {
        if (scope.isAuthenticated) vault?.remove(recordName())
        deleted.clear()
        cutoffs.clear()
        scope = AccountScope.NONE
    }

    private fun recordName(): String = RECORD_PREFIX + scope.key

    private fun persist() {
        if (!scope.isAuthenticated) return
        if (cutoffs.isEmpty()) {
            vault?.remove(recordName())
        } else {
            val text = cutoffs.entries.joinToString("\n") { (jid, at) ->
                "$jid\t$at\t" + (if (jid in deleted) "d" else "c")
            }
            vault?.put(recordName(), text.toByteArray(Charsets.UTF_8))
        }
    }

    companion object {
        const val RECORD_PREFIX = "deleted."
    }
}
