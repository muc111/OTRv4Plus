// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.SubscriptionPolicy
import org.otrv4plus.android.crypto.SecurityLevel

/**
 * People: roster contacts, requests and discovered users, one row each.
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

    /** The chat list's button beside the connection state: "People (2)",
     *  counting who is online. */
    @JvmStatic
    fun peopleButton(entries: List<Entry>): String {
        val online = entries.count {
            it.relation == Relation.ADDED_ONLINE || it.relation == Relation.ONLINE_ADD
        }
        val asking = entries.count { it.relation == Relation.ACCEPT }
        return when {
            asking > 0 -> "People ($online) \u2022"
            else -> "People ($online)"
        }
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
     * What the screen says about discovery itself, or null when there is
     * nothing to add. The Welcome room is the primary source; the server's
     * admin-only list is an extra where it exists.
     */
    @JvmStatic
    fun discoveryNote(welcome: org.otrv4plus.android.bridge.WelcomeView,
                      discovery: org.otrv4plus.android.bridge.OnlineDiscovery?,
                      connected: Boolean): String? {
        val W = org.otrv4plus.android.bridge.WelcomeView
        if (!connected) return "Not connected: nobody's presence is known."
        return when (welcome.state) {
            W.JOINED ->
                if (welcome.hidden > 0)
                    "${welcome.hidden} people in the OTRv4Plus Welcome room " +
                        "have hidden addresses (the room does not show " +
                        "members' addresses), so they cannot be added from here."
                else null
            W.SEARCHING, W.JOINING, W.NOT_CONNECTED ->
                "Joining the OTRv4Plus Welcome room…"
            W.NOT_FOUND ->
                if (discovery?.available == true) null
                else "This server has no public room named \u201cOTRv4Plus " +
                    "Welcome\u201d, so only your contacts and requests are " +
                    "shown. You can create it below, or add someone by address."
            W.AMBIGUOUS -> "More than one room is named \u201cOTRv4Plus " +
                "Welcome\u201d on this server; none was joined."
            W.LEFT -> "You are no longer in the OTRv4Plus Welcome room."
            else -> "Could not join the OTRv4Plus Welcome room."
        }
    }

    /** Shown before creating the Welcome room: what it will reveal. */
    const val WELCOME_CREATE_WARNING =
        "This creates a public room named \u201cOTRv4Plus Welcome\u201d on " +
            "your server so OTRv4Plus users can find each other. Everyone " +
            "in it sees everyone else's address and when they are online. " +
            "It is not end-to-end encrypted: the server can read it. Private " +
            "chats stay OTRv4+ as before."

    /**
     * Refusals that mean the SERVER'S SETTINGS stop this account creating
     * rooms (Prosody's restrict_room_creation answers not-allowed or, on some
     * versions, forbidden). Said as such -- not as the generic room sentence,
     * which for `forbidden` is "you are banned from this room".
     */
    private val PERMISSION_CODES = setOf(
        "not_allowed", "forbidden", "registration_required", "not_authorized")

    const val WELCOME_NOT_PERMITTED =
        "The Welcome room was not created: this server's settings do not let " +
            "your account create rooms. Ask the server admin to create a " +
            "public, persistent room named \u201cOTRv4Plus Welcome\u201d, or " +
            "to allow room creation. You can still add people by address."

    /** The result of creating it, in words. */
    @JvmStatic
    fun welcomeCreated(ok: Boolean, code: String, detail: String,
                       missing: List<String>): String =
        if (!ok && code in PERMISSION_CODES) WELCOME_NOT_PERMITTED
        else welcomeCreated(ok, detail, missing)

    /** The result of creating it, in words. */
    @JvmStatic
    fun welcomeCreated(ok: Boolean, detail: String, missing: List<String>): String = when {
        !ok -> "The Welcome room was not created: " +
            detail.ifBlank { "the server refused." }
        missing.isEmpty() -> "The OTRv4Plus Welcome room is ready. Other users " +
            "join it automatically when they sign in."
        else -> "The Welcome room was created, but the server did not allow: " +
            missing.joinToString("; ") + ". Ask the server admin to change it."
    }

    // -- search and details ----------------------------------------------------

    /**
     * The rows matching [query]: case-insensitive, on the name or the address,
     * order kept. Blank matches everyone. Local filtering only -- a search
     * never asks the server anything, so it cannot enumerate accounts.
     */
    @JvmStatic
    fun search(entries: List<Entry>, query: String): List<Entry> {
        val q = query.trim().lowercase()
        if (q.isEmpty()) return entries
        return entries.filter {
            q in it.displayName.lowercase() || q in it.jid.lowercase()
        }
    }

    /** What the details sheet says about one person, label to value. */
    @JvmStatic
    fun details(entry: Entry): List<Pair<String, String>> = buildList {
        add("Address" to entry.jid)
        add("Status" to entry.relation.label)
        val discoveredOnly = entry.relation == Relation.ONLINE_ADD ||
            entry.relation == Relation.ACCEPT
        add("OTRv4+" to when {
            discoveredOnly && !entry.encrypted -> "no session (not a contact yet)"
            entry.encrypted -> "encrypted"
            else -> "not encrypted"
        })
        add("Identity" to if (entry.verified) "SMP verified"
                         else "not verified with SMP")
    }
}
