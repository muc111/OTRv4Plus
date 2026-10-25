// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.GroupMember

/**
 * A secure group's members list: one summary line, search, sections by
 * verification with counts, one short row each, and Remove for the creator.
 * Owner (2026-10-25): "these groups could have 100 users so clean display is
 * needed" -- the old list was every member inline under the chat, each with
 * a sentence and a Remove button, and a "not verified: a, b, c ..." line.
 *
 * Plain Kotlin, shared by the phone and the desktop, driven by
 * `GroupRosterTest`.
 */
object GroupRoster {

    /** A search box from this many members up. */
    const val SEARCH_FROM = 8

    /** Failed first: that is the section the creator acts on. */
    enum class Status(val label: String) {
        FAILED("Verification failed"),
        CHECKING("Checking…"),
        NOT_VERIFIED("Not verified yet"),
        VERIFIED("Verified"),
        YOU("You"),
    }

    data class Row(val jid: String, val name: String, val status: Status, val canRemove: Boolean)
    data class Section(val title: String, val rows: List<Row>)

    /** The verification's word (verified / failed / running / waiting /
     *  not_verified) wins over the member list's, which can lag it. */
    fun status(m: GroupMember, verify: Map<String, String>): Status = when {
        m.me -> Status.YOU
        verify[m.jid] == "verified" || (m.verified && verify[m.jid] == null) -> Status.VERIFIED
        verify[m.jid] == "failed" || m.failed -> Status.FAILED
        verify[m.jid] == "running" -> Status.CHECKING
        else -> Status.NOT_VERIFIED
    }

    /** "alice" for alice@server: the address is the second line. */
    fun name(jid: String): String = jid.substringBefore('@').ifBlank { jid }

    fun matches(m: GroupMember, query: String): Boolean {
        val q = query.trim()
        return q.isEmpty() || m.jid.contains(q, ignoreCase = true)
    }

    /** "100 members · 97 verified · 2 failed · 1 not verified yet". */
    fun summary(members: List<GroupMember>, verify: Map<String, String>): String {
        if (members.isEmpty()) return "Members: asking the group…"
        val counts = members.groupingBy { status(it, verify) }.eachCount()
        val parts = mutableListOf("${members.size} member" + if (members.size == 1) "" else "s")
        counts[Status.VERIFIED]?.let { parts += "$it verified" }
        counts[Status.FAILED]?.let { parts += "$it failed" }
        counts[Status.CHECKING]?.let { parts += "$it checking" }
        counts[Status.NOT_VERIFIED]?.let { parts += "$it not verified yet" }
        return parts.joinToString(" · ")
    }

    /** Failed, checking, not verified, verified, then you; "Title (n)" each,
     *  alphabetical inside, empty sections left out. Remove only on the
     *  creator's screen and never on our own row. */
    fun sections(members: List<GroupMember>, verify: Map<String, String>,
                 query: String = "", isCreator: Boolean): List<Section> {
        val rows = members.filter { matches(it, query) }.map {
            val s = status(it, verify)
            Row(it.jid, name(it.jid), s, canRemove = isCreator && s != Status.YOU)
        }
        return Status.entries.mapNotNull { s ->
            val group = rows.filter { it.status == s }.sortedBy { it.jid.lowercase() }
            if (group.isEmpty()) null
            else Section(if (s == Status.YOU) s.label else "${s.label} (${group.size})", group)
        }
    }

    /** Who the creator's "Remove N who failed" removes. */
    fun failed(members: List<GroupMember>, verify: Map<String, String>): List<String> =
        members.filter { status(it, verify) == Status.FAILED }.map { it.jid }.sorted()

    fun removeFailedButton(n: Int): String =
        "Remove $n who failed verification"

    fun removeConfirm(jids: List<String>): String =
        if (jids.size == 1) "Remove ${jids[0]} from the group? They can no longer read it; " +
            "you can invite them again (with a new key, so a new attempt)."
        else "Remove ${jids.size} members whose verification failed? One change for all " +
            "of them; you can invite any of them again."
}
