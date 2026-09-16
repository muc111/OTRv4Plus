// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.Vault

/**
 * History that survives the process.
 *
 * WHAT CHANGED, AND WHY IT IS NOW SAFE TO DO
 * ------------------------------------------
 * The first version of this layer was `InMemoryMessageStore` and a comment
 * explaining why it had to be: message bodies are the most sensitive thing the
 * application handles, `RecordType.MESSAGE` says they must be sealed, and the
 * key for that was to come from an app unlock that did not exist. A plaintext
 * Room database or JSON file in the meantime would have been exactly the
 * artefact the sealed design exists to prevent.
 *
 * The unlock still does not exist. What does exist now is [Vault] -- on a
 * device, an AES-256-GCM key generated in the AndroidKeyStore that never
 * leaves it. That is enough to close the gap honestly:
 *
 *   * it protects against the FILE being read -- a pulled backup, a recovered
 *     flash chip, another app that finds a path to the data directory;
 *   * it does NOT protect against code running as this app on an unlocked
 *     phone, because the key is available to this app by construction.
 *
 * A passphrase-derived key would cover the second case too, and when the
 * unlock lands this class does not change -- only the [Vault] behind it does.
 * `ANDROID_STORAGE_AUDIT.md` records the distinction rather than letting the
 * word "encrypted" imply more than it buys.
 *
 * WHAT IS PERSISTED
 * -----------------
 * Conversation, direction, body, timestamp, delivery state and security label.
 * Nothing else, and in particular NO cryptographic material: the security
 * label is the word `ENCRYPTED`, not a key, and a ratchet state has never been
 * anywhere near this class. `RecordType.NEVER_PERSISTED` names the categories
 * that must not reach a disk at all and none of them are here.
 *
 * HOW IT IS LAID OUT
 * ------------------
 * One vault entry per conversation, not one per message. A message arriving
 * rewrites that conversation's entry, which is O(history) per message and
 * completely adequate at a 500-message cap and human typing speeds -- and it
 * means a torn write costs one conversation rather than the database. The
 * simplest thing that is safe.
 */
class PersistentMessageStore(
    private val vault: Vault,
    private val perConversationLimit: Int = InMemoryMessageStore.DEFAULT_LIMIT,
) : MessageStore {

    private val lock = Any()
    private val memory = InMemoryMessageStore(perConversationLimit)

    /** Conversations already read back from the vault this session. */
    private val loaded = HashSet<String>()

    /**
     * Whose history this store is currently holding.
     *
     * Starts at [AccountScope.NONE], which reads nothing and writes nothing.
     * Nothing is hydrated in the constructor any more: the old version read
     * the global index at construction time, which meant the service had the
     * previous account's conversations in memory before anyone had signed in.
     */
    private var scope: AccountScope = AccountScope.NONE

    /** The account this store is bound to. */
    val account: AccountScope get() = synchronized(lock) { scope }

    /**
     * Bind to an account, replacing whatever was loaded.
     *
     * THE ACCOUNT BOUNDARY, and the reason it is one call. Every in-memory
     * structure is dropped before the new account's index is read, so there is
     * no window in which one account's conversations and another's are both
     * present — not even briefly, and not even if the read fails.
     *
     * Binding to the SAME account is a no-op rather than a reload: a reconnect
     * must not throw away unsent state or re-hydrate history that is already
     * correct.
     */
    fun bind(next: AccountScope) = synchronized(lock) {
        if (next == scope) return@synchronized
        memory.clear()
        loaded.clear()
        scope = next
        if (!next.isAuthenticated) return@synchronized
        // The index, so `conversationIds()` is right before anything is
        // opened. Without it a restarted app shows an empty list until the
        // user remembers who they were talking to.
        for (jid in readIndex()) hydrate(jid)
    }

    /**
     * Forget this account's history, in memory and on disk.
     *
     * Only this account's: the vault holds other accounts' entries under
     * other prefixes and they are not ours to delete. `clear()` remains the
     * blunt instrument for a full sign-out.
     */
    fun forgetAccount() = synchronized(lock) {
        val current = scope
        if (current.isAuthenticated) {
            for (jid in memory.conversationIds()) {
                vault.remove(current.entryFor(jid))
            }
            vault.remove(current.indexName)
        }
        memory.clear()
        loaded.clear()
        scope = AccountScope.NONE
    }

    // -- MessageStore ---------------------------------------------------------

    override fun append(message: Message): Boolean = synchronized(lock) {
        // No account, no write. A message arriving on a listener that outlived
        // its session has nowhere to go, which is the point: it must not land
        // in the next account's history.
        if (!scope.isAuthenticated) return@synchronized false
        hydrate(message.conversationId)
        val added = memory.append(message)
        if (added) persist(message.conversationId)
        added
    }

    override fun update(message: Message): Boolean = synchronized(lock) {
        if (!scope.isAuthenticated) return@synchronized false
        hydrate(message.conversationId)
        val changed = memory.update(message)
        if (changed) persist(message.conversationId)
        changed
    }

    override fun messages(conversationId: String): List<Message> =
        synchronized(lock) {
            if (!scope.isAuthenticated) return@synchronized emptyList()
            hydrate(conversationId)
            memory.messages(conversationId)
        }

    override fun lastMessage(conversationId: String): Message? =
        synchronized(lock) {
            if (!scope.isAuthenticated) return@synchronized null
            hydrate(conversationId)
            memory.lastMessage(conversationId)
        }

    override fun conversationIds(): Set<String> = synchronized(lock) {
        if (!scope.isAuthenticated) return@synchronized emptySet()
        memory.conversationIds()
    }

    override fun unread(conversationId: String): Int = synchronized(lock) {
        if (!scope.isAuthenticated) return@synchronized 0
        hydrate(conversationId)
        memory.unread(conversationId)
    }

    override fun markRead(conversationId: String) = synchronized(lock) {
        if (!scope.isAuthenticated) return@synchronized
        hydrate(conversationId)
        memory.markRead(conversationId)
        persist(conversationId)
    }

    override fun clear() = synchronized(lock) {
        memory.clear()
        loaded.clear()
        vault.clear()
    }

    // -- durability -----------------------------------------------------------

    private fun hydrate(conversationId: String) {
        if (!scope.isAuthenticated) return
        if (!loaded.add(conversationId)) return
        val bytes = vault.get(scope.entryFor(conversationId)) ?: return
        var unread: Int? = null
        val stored = try {
            val text = String(bytes, Charsets.UTF_8)
            unread = MessageCodec.decodeUnread(text)
            MessageCodec.decodeAll(text)
        } catch (e: Exception) {
            // Unreadable history is history we do not have. Dropped rather
            // than retried forever, and never allowed to take the app down:
            // this runs on the path that delivers every message.
            vault.remove(scope.entryFor(conversationId))
            emptyList()
        } finally {
            bytes.fill(0)
        }
        for (message in stored) memory.append(message)
        // The count the user actually had, not the one replaying the messages
        // produces. Without this a conversation read before the restart comes
        // back wearing a badge.
        unread?.let { memory.restoreUnread(conversationId, it) }
    }

    private fun persist(conversationId: String) {
        if (!scope.isAuthenticated) return
        val text = MessageCodec.encodeAll(
            memory.messages(conversationId), memory.unread(conversationId))
        vault.put(scope.entryFor(conversationId),
                  text.toByteArray(Charsets.UTF_8))
        writeIndex(memory.conversationIds())
    }

    private fun readIndex(): Set<String> {
        val bytes = vault.get(scope.indexName) ?: return emptySet()
        return try {
            String(bytes, Charsets.UTF_8).split("\n")
                .filter { it.isNotBlank() }.toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    private fun writeIndex(ids: Set<String>) {
        vault.put(scope.indexName,
                  ids.joinToString("\n").toByteArray(Charsets.UTF_8))
    }

    companion object {
        /**
         * The unscoped index the FIRST version of this class wrote.
         *
         * Kept only so [purgeLegacy] can find it. Nothing writes here any
         * more: every name now carries the account, via
         * [AccountScope.entryFor].
         */
        const val LEGACY_INDEX = "chat.index"

        /**
         * Delete history written before histories had owners.
         *
         * NOT a migration, and it cannot be one. The old scheme recorded no
         * account at all, so there is nothing in the data that says whose it
         * is — attributing it to whoever signs in next is precisely the defect
         * this change removes, and attributing it to nobody would leave
         * unreadable entries sitting in the vault forever.
         *
         * So it goes. The cost is that an existing installation loses its
         * history once, on the upgrade that makes history private. That is the
         * right way round: the alternative is handing Bob's conversations to
         * whoever opens the app next.
         *
         * Safe to call at any time and idempotent; it only ever removes names
         * in the old flat format, which no account scope can produce.
         */
        fun purgeLegacy(vault: Vault) {
            val index = vault.get(LEGACY_INDEX) ?: run {
                vault.remove(LEGACY_INDEX)
                return
            }
            try {
                String(index, Charsets.UTF_8).split("\n")
                    .filter { it.isNotBlank() }
                    .forEach { vault.remove(legacyEntryFor(it)) }
            } catch (e: Exception) {
                // An index we cannot read is an index we cannot use to find
                // the entries. The index itself still goes.
            } finally {
                index.fill(0)
                vault.remove(LEGACY_INDEX)
            }
        }

        /** The old flat name, for [purgeLegacy] only. */
        internal fun legacyEntryFor(conversationId: String): String =
            "chat." + java.lang.Long.toHexString(
                stableHash(conversationId).toLong() and 0xffffffffL)

        /**
         * FNV-1a. Not a security boundary -- an attacker with the file can
         * confirm a guessed JID -- but it stops the names being a plaintext
         * contact list, which is what they would otherwise be. A cryptographic
         * hash here would imply a protection the design does not have.
         */
        internal fun stableHash(text: String): Int {
            var hash = -0x7ee3623b
            for (byte in text.toByteArray(Charsets.UTF_8)) {
                hash = hash xor (byte.toInt() and 0xff)
                hash *= 0x01000193
            }
            return hash
        }
    }
}
