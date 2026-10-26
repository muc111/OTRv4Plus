// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState

/**
 * "Make Chat Deniable" (L1, SPEC §5.8): what the action is offered for and
 * what it says. Shared by the phone and the desktop; `DeniableChatTest`.
 *
 * The words say what the tests show and no more (owner, 2026-10-26: "we
 * want to be able to say we have deniability pending external audit"):
 *   * deniability of WHAT WAS SAID -- every line's MAC key is on the wire
 *     once both closing messages are out (tests/test_deniability_wire_audit.py),
 *     and a message is authenticated only by keys both sides hold;
 *   * NOT of having talked: the handshake's ML-DSA-87 signatures are
 *     attributable (SPEC §10.1), so the text says so;
 *   * pending the external audit (docs/SECURITY_ISSUES.md, L1).
 */
object DeniableChat {

    const val ACTION = "Make Chat Deniable…"
    const val TITLE = "Make this chat deniable?"
    const val CONFIRM = "Make deniable"

    const val BODY =
        "Publishes the keys that authenticated this chat's messages, so a copy " +
            "of the chat -- your contact's, or a recording of the traffic -- no " +
            "longer proves who wrote what: anyone holding it could have forged " +
            "it. Your server confirms it received them first. Then this " +
            "encrypted session ends and a new one starts, unlinked to the old one. " +
            "Your messages stay encrypted: only their authentication keys are " +
            "published. It does not hide that you two talked: starting a session " +
            "is signed. This chat's history is deleted from this device, so only " +
            "the new session's messages are shown. Deniability pending external audit."

    /** Offered only in an established OTRv4+ session -- not plaintext, and
     *  not a session whose key does not match the one pinned. */
    fun offered(security: SecurityState, isRoom: Boolean): Boolean =
        !isRoom && security in setOf(SecurityState.ENCRYPTED, SecurityState.FINGERPRINT,
                                     SecurityState.SMP_VERIFIED)

    fun outcome(result: String): String = when (result) {
        "made_deniable" -> "Your server confirmed it received the published keys. This " +
            "chat's history was deleted from this device, and a new encrypted session " +
            "is starting."
        "made_deniable_unconfirmed" -> "The session was closed and its keys retired, but " +
            "your server has not yet confirmed the message that publishes them; the app " +
            "keeps sending it until it does. This chat's history was deleted from this " +
            "device, and a new encrypted session is starting."
        else -> "There is no encrypted session with this contact to end."
    }

    /**
     * What the phone and the desktop do with the engine's answer. Owner
     * (2026-10-26): "wipe the chat history and only show new chat session
     * following the make deniability". On "made_deniable" this chat's
     * messages go, from memory and from the vault ([ChatState.clearHistory]);
     * the chat itself stays open for the new session. Anything else deletes
     * nothing. Returns the line to show.
     */
    fun apply(result: String, chat: org.otrv4plus.android.chat.ChatState, jid: String): String {
        if (result.startsWith("made_deniable")) chat.clearHistory(jid)
        return outcome(result)
    }
}

/**
 * "Make Group Deniable" (F4, docs/MLS_SECURITY_HARDENING.md §1) for a secure group: a new signing key
 * for us in the group, then our earlier ones published to its members
 * (epochal signatures). Shared by the phone and the desktop;
 * `DeniableChatTest`. Like [DeniableChat], it describes the mechanism and
 * claims nothing more.
 */
object GroupDeniable {

    const val ACTION = "Make Group Deniable…"
    const val TITLE = "Make this group deniable?"
    const val CONFIRM = "Make deniable"

    const val BODY =
        "Gives you a new signing key in this group, then publishes your earlier " +
            "ones to its members, so any member could have signed what they " +
            "signed. New messages are signed with the new key, which stays " +
            "secret. Messages stay encrypted. Earlier keys are also published " +
            "by themselves some minutes after each automatic key change. " +
            "Anything copied before they are published stays signed. This " +
            "group's history is deleted from this device. Pending external audit."

    fun outcome(ok: Boolean, code: String): String =
        if (ok) "A new signing key is being set up; your earlier ones are published " +
            "as soon as it is in place, and this group's history was deleted from " +
            "this device."
        else org.otrv4plus.android.chat.GroupText.outcome(code)
            ?: "The group could not be made deniable ($code)."

    /** What both apps do with the answer: on success the group's history goes. */
    fun apply(ok: Boolean, code: String, chat: org.otrv4plus.android.chat.ChatState,
              room: String): String {
        if (ok) chat.clearHistory(room)
        return outcome(ok, code)
    }
}
