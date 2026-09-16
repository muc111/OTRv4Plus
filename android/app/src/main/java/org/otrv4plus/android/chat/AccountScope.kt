// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Which account a piece of private state belongs to.
 *
 * THE DEFECT THIS EXISTS TO MAKE IMPOSSIBLE
 * -----------------------------------------
 * Bob was signed in and had a conversation with Alice. Dave signed in on the
 * same handset, and Alice ↔ Bob was still on screen.
 *
 * It was not a UI bug and clearing the screen would not have fixed it. The
 * storage schema had no account in it at all:
 *
 *     Conversations ──► Messages
 *
 * A conversation was identified by the PEER's JID alone, so Bob's history with
 * Alice and Dave's history with Alice were the same vault entry, under the
 * same name, in the same global index. Whoever signed in read it. The shape
 * the data has to have is:
 *
 *     Account ──► Conversations ──► Messages
 *
 * and that is what this type supplies: the account half of every key, applied
 * at the data layer, so a cross-account read is not something the UI has to
 * remember to avoid — it is something the storage cannot express.
 *
 * WHY THE BARE JID
 * ----------------
 * The resource is per-session: `alice@host/phone` and `alice@host/desktop` are
 * the same person and must share history. The domain is part of the identity —
 * `alice@one.i2p` and `alice@two.i2p` are two accounts — so the localpart
 * alone will not do. Case is folded, because a server that accepts `Alice`
 * and `alice` as one account must not give them two histories here.
 *
 * WHY THE KEY IS HASHED
 * ---------------------
 * Vault entry NAMES are not sealed; only values are. A directory listing of
 * `chat.alice@server.i2p.<peer>` would be a plaintext record of who uses this
 * phone and who they talk to — precisely what an anonymity-oriented client is
 * protecting. [PersistentMessageStore] already hashed the peer for that
 * reason; the account gets the same treatment.
 *
 * This is NOT a security boundary and is not claimed as one. Anybody holding
 * the file can confirm a guessed JID by hashing it. What it buys is that the
 * names are not a contact list, which is what they would otherwise be.
 *
 * [NONE] IS A REAL VALUE
 * ----------------------
 * Not null, and not "the last account". Before anyone has authenticated there
 * is no account, and a store bound to [NONE] reads nothing and writes nothing.
 * That is what stops cached history being served in the window between the
 * process starting and an identity being established — the window in which the
 * original defect was visible.
 */
class AccountScope private constructor(
    /** The bare, case-folded JID, or "" for [NONE]. Never written to disk. */
    val bareJid: String,
) {

    /** Whether this scope may touch stored private state at all. */
    val isAuthenticated: Boolean get() = bareJid.isNotEmpty()

    /**
     * The account's half of every vault entry name.
     *
     * "" for [NONE], which is never used to build a name because nothing
     * bound to [NONE] reads or writes.
     */
    val key: String
        get() = if (bareJid.isEmpty()) "" else hashOf(bareJid)

    /** The vault entry holding this account's list of conversations. */
    val indexName: String get() = "chat.$key.index"

    /** The vault entry holding one conversation's history, for this account. */
    fun entryFor(conversationId: String): String =
        "chat.$key." + hashOf(normalise(conversationId))

    /**
     * The prefix every entry of this account shares.
     *
     * So a sign-out can remove one account's data without touching another's,
     * and without needing the list of conversations to still be readable.
     */
    val prefix: String get() = "chat.$key."

    override fun equals(other: Any?): Boolean =
        other is AccountScope && other.bareJid == bareJid

    override fun hashCode(): Int = bareJid.hashCode()

    /**
     * Counts and a truncated key only. A repr naming the account would undo
     * the reason the key is hashed in the first place.
     */
    override fun toString(): String =
        if (isAuthenticated) "AccountScope(${key.take(6)}…)" else "AccountScope(none)"

    companion object {
        /**
         * Nobody is authenticated.
         *
         * A store bound to this reads nothing and writes nothing. It is the
         * starting state and the state after a sign-out, and it is deliberately
         * not the same as "the previous account" — which is what the defect
         * amounted to.
         */
        val NONE = AccountScope("")

        /**
         * The scope for a JID. Blank or malformed input gives [NONE].
         *
         * Malformed rather than accepted: a scope built from rubbish would
         * still be a scope, and two different pieces of rubbish could collide
         * into one namespace. Refusing means the store stays shut instead.
         */
        fun of(jid: String?): AccountScope {
            val bare = normalise(jid ?: "")
            // A JID without a domain is not an account. `alice` alone would
            // share a namespace with `alice` on every other server.
            if (bare.isEmpty() || !bare.contains('@')) return NONE
            if (bare.startsWith("@") || bare.endsWith("@")) return NONE
            return AccountScope(bare)
        }

        /** Bare and case-folded: the resource is per-session, not per-account. */
        internal fun normalise(jid: String): String =
            jid.trim().substringBefore('/').lowercase()

        /**
         * FNV-1a, as [PersistentMessageStore] already uses for peers.
         *
         * Deliberately the same function, so there is one answer in this
         * codebase to "how is an identity turned into an entry name" rather
         * than two that could drift. A cryptographic hash here would imply a
         * protection the design does not have — see the class docs.
         */
        internal fun hashOf(text: String): String {
            var hash = -0x7ee3623b
            for (byte in text.toByteArray(Charsets.UTF_8)) {
                hash = hash xor (byte.toInt() and 0xff)
                hash *= 0x01000193
            }
            return java.lang.Long.toHexString(hash.toLong() and 0xffffffffL)
        }
    }
}
