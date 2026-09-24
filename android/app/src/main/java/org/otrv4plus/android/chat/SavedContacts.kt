// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.security.Vault

/**
 * People this device has chosen to remember, sealed in the existing vault.
 *
 * WHAT THIS IS NOT
 * ----------------
 * **It is not a roster, and it must never be read as one.** The XMPP server
 * owns the roster, the subscription state and whether the other person has
 * accepted. This file owns exactly one local fact: *this account asked to keep
 * this JID*.
 *
 * Keeping them apart is the point. A local record saying "saved" is a
 * statement about a tap on this phone; a subscription is a statement about a
 * server and another human being. Merging them would let the app say somebody
 * is a confirmed contact because a button was pressed, which is the class of
 * lie this project refuses everywhere else. So:
 *
 *   * [Saved.jid] and [Saved.displayName] — what was typed or offered here.
 *   * subscription, presence, pending — NOT HERE. They come from
 *     `OtrApp.contacts()` on every poll and are the server's answer.
 *
 * [ChatState.conversations] already merges the two, and a conversation is
 * `saved = true` only when the ROSTER has it. This store adds the other half:
 * somebody saved on a previous run is remembered before the roster has been
 * fetched, and is not silently dropped if the server has not confirmed yet.
 *
 * WHAT IS PERSISTED, AND WHERE
 * ----------------------------
 * No new database. The same [Vault] `PersistentMessageStore` uses --
 * `KeystoreVault`, AES-GCM under AndroidKeyStore, with the record name bound
 * into the authenticated data so a record sealed under one name cannot be
 * opened under another.
 *
 * Account-scoped by [AccountScope], under `contacts.<accountHash>`, for the
 * same reason conversations are: two accounts on one handset must not be able
 * to read each other's contact list, and the schema is what enforces that
 * rather than the UI remembering to filter.
 *
 * NOTHING CRYPTOGRAPHIC IS STORED HERE. No keys, no fingerprints, no SMP
 * state, no passwords. Those belong to the engine and to `CredentialStore`,
 * and duplicating a fingerprint into a second place is how two sources of
 * truth disagree about identity.
 */
class SavedContacts(private val vault: Vault?) {

    /** One remembered person. Local facts only. */
    data class Saved(
        val jid: String,
        val displayName: String = "",
        /** When this device saved them, epoch millis; 0 when unknown. */
        val savedAt: Long = 0L,
    )

    private var scope: AccountScope = AccountScope.NONE
    private val saved = LinkedHashMap<String, Saved>()

    /** Everything remembered for the bound account, in the order saved. */
    fun all(): List<Saved> = saved.values.toList()

    fun isSaved(jid: String): Boolean = ChatState.bare(jid) in saved

    /**
     * Bind to an account and load its list.
     *
     * Binding to [AccountScope.NONE] — or to an account that has nothing
     * stored — leaves an EMPTY list rather than the previous account's, and
     * reads and writes both no-op while unauthenticated. Same rule as
     * `PersistentMessageStore`: the window between the process starting and
     * an identity being established belongs to nobody.
     */
    fun bind(next: AccountScope) {
        if (next == scope) return
        scope = next
        saved.clear()
        if (!next.isAuthenticated) return
        val bytes = vault?.get(recordName()) ?: return
        for (entry in decode(bytes)) saved[entry.jid] = entry
    }

    /**
     * Remember [jid]. Returns whether anything changed.
     *
     * CALLED ONLY AFTER THE SERVER HAS CONFIRMED THE ROSTER OPERATION — see
     * `ChatViewModel.addContact`. Writing on the tap would make the list a
     * record of intentions, and the whole reason this is separate from the
     * roster is that it must not claim anything the server has not done.
     */
    fun save(jid: String, displayName: String = "", at: Long = 0L): Boolean {
        if (!scope.isAuthenticated) return false
        val bare = ChatState.bare(jid)
        if (bare.isEmpty() || !bare.contains('@')) return false
        val existing = saved[bare]
        val entry = Saved(
            jid = bare,
            displayName = displayName.ifBlank { existing?.displayName ?: "" },
            savedAt = if (existing != null && existing.savedAt != 0L)
                existing.savedAt else at,
        )
        if (existing == entry) return false
        saved[bare] = entry
        persist()
        return true
    }

    /** Forget [jid] locally. Says nothing about the server's roster. */
    fun forget(jid: String): Boolean {
        if (!scope.isAuthenticated) return false
        val bare = ChatState.bare(jid)
        if (saved.remove(bare) == null) return false
        persist()
        return true
    }

    /** Drop this account's record entirely, on sign-out. */
    fun forgetAccount() {
        if (scope.isAuthenticated) vault?.remove(recordName())
        saved.clear()
        scope = AccountScope.NONE
    }

    private fun recordName(): String = "contacts." + scope.key

    private fun persist() {
        if (!scope.isAuthenticated) return
        vault?.put(recordName(), encode(saved.values))
    }

    // -- encoding --------------------------------------------------------
    //
    // A line per contact, tab-separated, because the fields are three short
    // strings and a number. JSON would need a parser on a path that already
    // has one place to get a null wrong, and the vault seals the bytes either
    // way. A tab and a newline cannot appear in a JID, and the display name
    // is stripped of both on the way in.

    private fun encode(entries: Collection<Saved>): ByteArray =
        entries.joinToString("\n") { entry ->
            listOf(
                entry.jid,
                entry.displayName.replace('\t', ' ').replace('\n', ' '),
                entry.savedAt.toString(),
            ).joinToString("\t")
        }.toByteArray(Charsets.UTF_8)

    private fun decode(bytes: ByteArray): List<Saved> =
        String(bytes, Charsets.UTF_8)
            .split("\n")
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val parts = line.split("\t")
                // FOLDED ON THE WAY IN, not only on the way out. `save`,
                // `forget` and `isSaved` all key through `ChatState.bare`, so
                // a stored record that was not folded would be a key none of
                // them can reach -- present in the list, impossible to remove.
                // The invariant belongs where records ENTER the map.
                val jid = ChatState.bare(parts.getOrNull(0).orEmpty())
                // A record that cannot be read is skipped, not guessed at.
                // A truncated vault entry must not become a contact with a
                // blank JID sitting in the list.
                if (jid.isEmpty() || !jid.contains('@')) null
                else Saved(
                    jid = jid,
                    displayName = parts.getOrNull(1).orEmpty(),
                    savedAt = parts.getOrNull(2)?.toLongOrNull() ?: 0L,
                )
            }
}
