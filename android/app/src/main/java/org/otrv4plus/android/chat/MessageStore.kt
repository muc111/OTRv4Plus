// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Where conversation history lives.
 *
 * WHY THIS IS AN INTERFACE AND NOT A DATABASE
 * -------------------------------------------
 * Message bodies are the most sensitive thing this application handles, and
 * the project has a deliberate position on storing them:
 * `security/SecureStore.kt` declares `RecordType.MESSAGE = "otr.message"` as a
 * category that must be sealed, and `android_bridge/secure_store.py` has the
 * AES-256-GCM implementation with record-bound AAD.
 *
 * That implementation needs a data-encryption key, and on Android the key
 * comes from the app unlock (password or keyfile) that is scheduled for the
 * final build. There is no user-derived key on the device yet. So sealing is
 * not available, and the alternative -- an ordinary Room database or a JSON
 * file of plaintext message bodies -- is precisely the thing a privacy
 * application must not add casually. A plaintext history file is a permanent
 * artefact that outlives the process, survives an uninstall on some devices,
 * and is readable by anything that gets the app's data directory.
 *
 * So: the seam exists now, the in-memory implementation is what ships now, and
 * a `SealedMessageStore` drops in behind this interface when the unlock work
 * lands, with no change above it. Nothing in the UI or the ViewModel knows
 * which implementation it has.
 *
 * WHAT "PERSIST" MEANS TODAY
 * --------------------------
 * [InMemoryMessageStore] is held by the ViewModel, so history survives leaving
 * a conversation, navigating anywhere in the app, Activity recreation
 * (rotation, theme change, locale change) and reconnecting. It does NOT
 * survive the process being killed. That limit is stated rather than hidden;
 * see ANDROID_CHAT_DEVICE_TEST.md.
 *
 * KEPT AWAY FROM COMPOSE AND FROM THE TRANSPORT.
 * This interface mentions neither. A store is a place to put messages; it does
 * not know what draws them or what carries them.
 */
interface MessageStore {

    /** Every message in a conversation, oldest first. */
    fun messages(conversationId: String): List<Message>

    /**
     * Add a message, or return false if its id is already present.
     *
     * Idempotent on [Message.id], which is what makes appends safe from a
     * recomposition, a replayed event or a restarted poll. See [MessageId].
     */
    fun append(message: Message): Boolean

    /**
     * Replace a message in place, by id. Returns false if it is not there.
     *
     * Used to move an optimistic outgoing message from SENDING to its real
     * outcome without appending a second copy of it.
     */
    fun update(message: Message): Boolean

    /** The most recent message in a conversation, or null. */
    fun lastMessage(conversationId: String): Message?

    /** Every conversation id that has at least one message. */
    fun conversationIds(): Set<String>

    /** Unread count for a conversation. */
    fun unread(conversationId: String): Int

    /** Mark everything in a conversation as read. */
    fun markRead(conversationId: String)

    /** Forget everything. Used when the account changes. */
    fun clear()
}

/**
 * History in memory, bounded per conversation.
 *
 * BOUNDED ON PURPOSE. An unbounded list is a memory leak with a polite name:
 * a long-running session on a phone would grow until Android killed the
 * process, taking the conversation with it. When the cap is reached the oldest
 * messages go, because the recent end is what the user is reading.
 *
 * Not thread-safe by accident -- every method synchronises. Inbound messages
 * arrive on the transport's poll and outbound ones on a ViewModel coroutine,
 * and those are different threads.
 */
class InMemoryMessageStore(
    private val perConversationLimit: Int = DEFAULT_LIMIT,
) : MessageStore {

    private val lock = Any()
    private val byConversation = linkedMapOf<String, MutableList<Message>>()
    private val ids = linkedMapOf<String, MutableSet<String>>()
    private val unreadCounts = linkedMapOf<String, Int>()

    override fun messages(conversationId: String): List<Message> =
        synchronized(lock) {
            byConversation[conversationId]?.toList() ?: emptyList()
        }

    override fun append(message: Message): Boolean = synchronized(lock) {
        val seen = ids.getOrPut(message.conversationId) { linkedSetOf() }
        if (!seen.add(message.id)) return false
        val list = byConversation.getOrPut(message.conversationId) { mutableListOf() }
        list.add(message)
        while (list.size > perConversationLimit) {
            val dropped = list.removeAt(0)
            seen.remove(dropped.id)
        }
        if (!message.outgoing && message.security != SecurityLabel.SYSTEM) {
            unreadCounts[message.conversationId] =
                (unreadCounts[message.conversationId] ?: 0) + 1
        }
        true
    }

    override fun update(message: Message): Boolean = synchronized(lock) {
        val list = byConversation[message.conversationId] ?: return false
        val index = list.indexOfFirst { it.id == message.id }
        if (index < 0) return false
        list[index] = message
        true
    }

    override fun lastMessage(conversationId: String): Message? =
        synchronized(lock) { byConversation[conversationId]?.lastOrNull() }

    override fun conversationIds(): Set<String> =
        synchronized(lock) { byConversation.keys.toSet() }

    override fun unread(conversationId: String): Int =
        synchronized(lock) { unreadCounts[conversationId] ?: 0 }

    override fun markRead(conversationId: String) {
        synchronized(lock) { unreadCounts[conversationId] = 0 }
    }

    override fun clear() {
        synchronized(lock) {
            byConversation.clear()
            ids.clear()
            unreadCounts.clear()
        }
    }

    companion object {
        /**
         * Messages kept per conversation.
         *
         * Enough that scrolling back through a day's conversation works;
         * small enough that a hundred conversations cannot exhaust a phone.
         */
        const val DEFAULT_LIMIT = 500
    }
}
