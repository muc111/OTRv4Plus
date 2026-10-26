// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState

/**
 * "Make Chat Deniable" (L1, SPEC §5.8): what the action is offered for and
 * what it says. Shared by the phone and the desktop; `DeniableChatTest`.
 *
 * The words describe the mechanism and nothing more. They do NOT claim
 * "deniable messaging": that claim waits for the formal review of the
 * retirement rule (docs/SECURITY_ISSUES.md, L1).
 */
object DeniableChat {

    const val ACTION = "Make Chat Deniable…"
    const val TITLE = "Make this chat deniable?"
    const val CONFIRM = "Make deniable"

    const val BODY =
        "Publishes the keys that authenticated this chat's messages, so anyone " +
            "who has a copy of them could have forged them. Then this encrypted " +
            "session ends and a new one starts, unlinked to the old one. Your " +
            "messages stay encrypted: only their authentication keys are published. " +
            "This mechanism has not been independently reviewed yet."

    /** Offered only in an established OTRv4+ session -- not plaintext, and
     *  not a session whose key does not match the one pinned. */
    fun offered(security: SecurityState, isRoom: Boolean): Boolean =
        !isRoom && security in setOf(SecurityState.ENCRYPTED, SecurityState.FINGERPRINT,
                                     SecurityState.SMP_VERIFIED)

    fun outcome(result: String): String = when (result) {
        "made_deniable" -> "The keys were published and a new encrypted session is starting."
        else -> "There is no encrypted session with this contact to end."
    }
}
