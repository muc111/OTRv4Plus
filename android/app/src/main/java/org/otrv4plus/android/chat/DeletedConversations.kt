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
 * It holds addresses only. Nothing about what was said.
 *
 * Bound per account, like [SavedContacts], and destroyed by Wipe & Exit with
 * the vault; forgotten by Sign out with the account's other records.
 */
class DeletedConversations(private val vault: Vault?) {

    private var scope: AccountScope = AccountScope.NONE
    private val deleted = LinkedHashSet<String>()

    fun bind(next: AccountScope) {
        if (next == scope) return
        scope = next
        deleted.clear()
        if (!next.isAuthenticated) return
        val bytes = vault?.get(recordName()) ?: return
        try {
            String(bytes, Charsets.UTF_8).split("\n")
                .map { ChatState.bare(it) }
                .filter { it.isNotEmpty() }
                .forEach { deleted.add(it) }
        } finally {
            bytes.fill(0)
        }
    }

    fun contains(jid: String): Boolean = ChatState.bare(jid) in deleted

    fun all(): Set<String> = deleted.toSet()

    /** Remember that [jid] was deleted. Returns whether anything changed. */
    fun add(jid: String): Boolean {
        if (!scope.isAuthenticated) return false
        val bare = ChatState.bare(jid)
        if (bare.isEmpty() || !deleted.add(bare)) return false
        persist()
        return true
    }

    /** [jid] has something in it again; show it. */
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
        scope = AccountScope.NONE
    }

    private fun recordName(): String = RECORD_PREFIX + scope.key

    private fun persist() {
        if (!scope.isAuthenticated) return
        if (deleted.isEmpty()) {
            vault?.remove(recordName())
        } else {
            vault?.put(recordName(), deleted.joinToString("\n").toByteArray(Charsets.UTF_8))
        }
    }

    companion object {
        const val RECORD_PREFIX = "deleted."
    }
}
