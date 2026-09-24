// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.SubscriptionPolicy
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

    // -- the one list ----------------------------------------------------------
    //
    // Roster contacts, people asking to add us, and people the SERVER says
    // are online, merged into one row per bare JID. Where each comes from:
    //
    //   * roster + presence   -> Added (online / offline / unknown), Pending
    //   * subscription request-> Accept
    //   * server discovery    -> Online — Add (XEP-0133; empty for ordinary
    //                            Prosody accounts, and then nobody is shown
    //                            who is not already on the roster)
    //
    // Nothing here is guessed: a JID appears only because the roster, a
    // stanza from that JID, or the server's own list named it.

    /** Where this person stands with this account. One per row. */
    enum class Relation(val label: String, val action: String?) {
        /** They asked to see our presence; the user has a decision to make. */
        ACCEPT("Wants to add you", "Accept"),
        /** On the roster, and the server says they are online. */
        ADDED_ONLINE("Online — Added", null),
        /** The server says they are online; not on our roster. */
        ONLINE_ADD("Online", "Add"),
        /** We asked; they have not answered. */
        PENDING("Pending — waiting for them to accept", null),
        /** On the roster, offline. */
        ADDED_OFFLINE("Offline — Added", null),
        /** On the roster; the server does not tell us their presence. */
        ADDED_UNKNOWN("Added — presence not shared", null),
    }

    data class Entry(
        val jid: String,
        val displayName: String,
        val relation: Relation,
        val encrypted: Boolean,
        val verified: Boolean,
    ) {
        /** Row subtitle: the relation, then security facts, never merged. */
        val facts: List<String>
            get() = buildList {
                add(relation.label)
                if (relation != Relation.ONLINE_ADD && relation != Relation.ACCEPT) {
                    add(if (encrypted) "OTR encrypted" else "not encrypted")
                }
                if (verified) add("SMP verified")
            }
    }

    /**
     * One row per bare JID, never our own. Order: decisions first, then
     * who is online, then pending, then the rest; alphabetical within.
     */
    @JvmStatic
    fun directory(
        conversations: List<Conversation>,
        requests: List<OtrEvent.SubscriptionRequested>,
        discovered: Set<String>,
        self: String,
    ): List<Entry> {
        val me = ChatState.bare(self)
        val byJid = LinkedHashMap<String, Entry>()
        val known = conversations.associateBy { ChatState.bare(it.jid) }
        fun security(jid: String): Pair<Boolean, Boolean> {
            val c = known[jid] ?: return false to false
            val enc = SecurityLevel.encrypts(SecurityLevel.of(c.security))
            val ver = c.security == SecurityState.SMP_VERIFIED &&
                c.smp == SmpState.VERIFIED
            return enc to ver
        }
        fun name(jid: String): String =
            known[jid]?.displayName?.takeIf { it.isNotBlank() } ?: jid

        for (r in requests) {
            val jid = ChatState.bare(r.peer)
            if (jid.isEmpty() || jid == me) continue
            // Under ACCEPT the server was answered already; nothing to decide.
            if (r.policy != SubscriptionPolicy.ASK) continue
            val (enc, ver) = security(jid)
            byJid[jid] = Entry(jid, name(jid), Relation.ACCEPT, enc, ver)
        }
        for (c in conversations) {
            val jid = ChatState.bare(c.jid)
            if (!c.saved || jid == me || jid in byJid || !jid.contains('@')) continue
            val relation = when (c.presence) {
                Presence.PENDING -> Relation.PENDING
                Presence.ONLINE -> Relation.ADDED_ONLINE
                Presence.OFFLINE -> Relation.ADDED_OFFLINE
                // The server says they are online though presence is not
                // shared with us: that is its answer, so it is shown.
                Presence.UNKNOWN -> if (jid in discovered) Relation.ADDED_ONLINE
                                    else Relation.ADDED_UNKNOWN
            }
            val (enc, ver) = security(jid)
            byJid[jid] = Entry(jid, name(jid), relation, enc, ver)
        }
        for (raw in discovered) {
            val jid = ChatState.bare(raw)
            if (jid.isEmpty() || jid == me || jid in byJid || !jid.contains('@')) continue
            val (enc, ver) = security(jid)
            byJid[jid] = Entry(jid, name(jid), Relation.ONLINE_ADD, enc, ver)
        }
        return byJid.values.sortedWith(
            compareBy<Entry> { it.relation.ordinal }
                .thenBy { it.displayName.lowercase() })
    }

    /** The header: "PEOPLE (5 · 2 online)". */
    @JvmStatic
    fun directoryTitle(entries: List<Entry>): String {
        val online = entries.count {
            it.relation == Relation.ADDED_ONLINE || it.relation == Relation.ONLINE_ADD
        }
        return "PEOPLE (${entries.size} · $online online)"
    }

    /**
     * What the screen says about discovery itself. Null when the server
     * listed who is online; otherwise why only contacts are shown.
     */
    @JvmStatic
    fun discoveryNote(discovery: org.otrv4plus.android.bridge.OnlineDiscovery?,
                      connected: Boolean): String? = when {
        !connected -> "Not connected: nobody's presence is known."
        discovery == null -> "Asking the server who is online…"
        discovery.available -> null
        else -> "This server does not list its online users to this account " +
            "(XEP-0133 is admin-only on Prosody). Showing your contacts and " +
            "requests; add someone by address to see them here."
    }

    /** The header: "ONLINE USERS (3)". */
    @JvmStatic
    fun title(count: Int): String = "ONLINE USERS ($count)"
}
