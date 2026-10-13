// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.ProfileField

/**
 * What the Profile screen says. Plain Kotlin, so each sentence is decided
 * where a JVM test can reach it (see ProfileTextTest), not in the ViewModel.
 */
object ProfileText {

    fun isOwn(jid: String): Boolean = jid.isBlank()

    fun empty(jid: String): String =
        if (isOwn(jid)) "Your profile is empty."
        else "This person has not filled in a profile."

    /**
     * After a save: which typed fields the bridge did not keep (wrong shape,
     * e.g. a birthday not in YYYY-MM-DD), named by their labels.
     */
    fun saved(
        typed: Map<String, String>,
        kept: Map<String, String>,
        fields: List<ProfileField>,
    ): String {
        val dropped = typed.filterValues { it.isNotBlank() }.keys - kept.keys
        if (dropped.isEmpty()) return "Your profile is saved."
        return "Saved. Not kept because of their format: " +
            dropped.joinToString { key -> fields.firstOrNull { it.key == key }?.label ?: key }
    }
}
