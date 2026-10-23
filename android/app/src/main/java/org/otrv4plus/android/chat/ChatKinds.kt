// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * What kind of chat a row is, how it is tinted, and the filter chips over
 * the chat list. Owner (2026-10-23): "distinguish between public channels,
 * groups, 1:1 chats and maybe 50% tint colour for each type so users can
 * switch into chats quicker".
 *
 * Plain Kotlin, shared by the phone and the desktop, driven by
 * `ChatKindsTest`.
 *
 * COLOUR IS NEVER THE ONLY SIGNAL. Every row also carries the kind's [label]
 * (and the screens an icon), so someone who cannot tell the tints apart --
 * or a screen reader -- loses nothing. The tint says what kind of chat it
 * is; whether it is encrypted is still said in words by `RowSecurity`.
 */
object ChatKinds {

    /** How strongly a row is tinted with its kind's colour (owner: "50%"). */
    const val TINT = 0.5f

    enum class Kind(val label: String, val hue: Long) {
        /** A one-to-one conversation (OTRv4+). Blue. */
        PERSON("Chat", 0xFF3B82F6),
        /** A secure group (MLS+): end-to-end encrypted. Green. */
        GROUP("Encrypted group", 0xFF16A34A),
        /** An ordinary room such as Welcome: readable by the server. Amber. */
        PUBLIC("Public room · not encrypted", 0xFFF59E0B),
    }

    enum class Filter(val label: String) {
        ALL("All"), PEOPLE("People"), GROUPS("Groups"), PUBLIC("Public");

        fun admits(kind: Kind): Boolean = when (this) {
            ALL -> true
            PEOPLE -> kind == Kind.PERSON
            GROUPS -> kind == Kind.GROUP
            PUBLIC -> kind == Kind.PUBLIC
        }
    }

    /** A room is a group when it is (or is becoming) a secure group. */
    fun kind(isRoom: Boolean, isSecureRoom: Boolean): Kind = when {
        isSecureRoom -> Kind.GROUP
        isRoom -> Kind.PUBLIC
        else -> Kind.PERSON
    }

    /** "Groups (3)": how many chats each chip would show. */
    fun chipLabel(filter: Filter, kinds: List<Kind>): String =
        if (filter == Filter.ALL) filter.label
        else "${filter.label} (${kinds.count { filter.admits(it) }})"

    /** The chips worth showing: All, plus each kind that has a chat. A list
     *  of only 1:1 chats needs no chips at all. */
    fun chips(kinds: List<Kind>): List<Filter> {
        val present = Filter.entries.filter { it != Filter.ALL && kinds.any(it::admits) }
        return if (present.size < 2) emptyList() else listOf(Filter.ALL) + present
    }
}
