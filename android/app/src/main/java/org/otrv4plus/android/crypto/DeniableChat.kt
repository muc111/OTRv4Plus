// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState

/**
 * "Publish Chat Keys" (L1, SPEC §5.8; "Make Chat Deniable" before
 * 2026-10-27): what the action is offered for and what it says. Shared by
 * the phone and the desktop; `DeniableChatTest`. The label names the
 * mechanism, like the dialog: a property the code does not demonstrate is
 * named nowhere (docs/AUDIT_CLAIM_MATRIX.md 1.10).
 *
 * The words describe the mechanism and its residuals; they state no
 * deniability property (docs/SECURITY_ISSUES.md L1 is RESOLVED-CODE; audit
 * of 2026-10-26, docs/AUDIT_CLAIM_MATRIX.md §1):
 *   * what it does: every line's MAC key goes on the wire in the closing
 *     messages (tests/test_deniability_wire_audit.py), messages stay
 *     encrypted, the server is asked to confirm, a new session starts;
 *   * what it does not: hide that you talked (the handshake's ML-DSA-87
 *     signatures, SPEC §10.1); help a copy made before the keys are
 *     published, or a close that does not finish;
 *   * that it has not been independently reviewed.
 */
object DeniableChat {

    /** "End chat & publish keys" from 2026-10-27 (owner): it says the chat
     *  ends, which is true, and names what happens. */
    const val ACTION = "End chat & publish keys…"
    const val TITLE = "End this chat and publish its keys?"
    const val CONFIRM = "Publish keys"

    const val BODY =
        "Publishes the keys used to authenticate this chat's messages, so anyone " +
            "holding them can make a message pass that check. Your messages stay encrypted: " +
            "only their authentication keys are published. The app asks your server " +
            "to confirm it received them, then ends this encrypted session and " +
            "starts a new one that shares no keys with it. It does not hide that you " +
            "two talked: starting a session is signed. This chat's history is " +
            "deleted from this device, so only the new session's messages are shown, " +
            "and your contact's app deletes its copy once its own keys are published. " +
            "Not independently reviewed. A copy made before the keys are published, " +
            "or a close that does not finish, can still be proof."

    /**
     * The line left in a conversation whose keys were published on purpose
     * (ChatState): who did it, and that the earlier messages were removed
     * here. For a chat it is said once our own keys are confirmed by our
     * server; for a group, once the publisher's keys are out.
     */
    fun published(by: String, group: Boolean): String = when {
        group && by.isEmpty() -> "You published your group keys. Earlier messages " +
            "were removed from this device."
        group -> "$by published their group keys. Earlier messages were removed " +
            "from this device."
        by.isEmpty() -> "You ended this chat and published its keys; your server " +
            "confirmed them. Earlier messages were removed from this device."
        else -> "$by ended this chat and published its keys, and this app published " +
            "its own; your server confirmed them. Earlier messages were removed from " +
            "this device."
    }

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
            "your server has not yet confirmed the message that publishes them. The app " +
            "sends it again, up to 40 times, while it keeps running; if it closes first, " +
            "this close can still be proof. This chat's history was deleted from this " +
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
 * "Publish Group Keys" ("Make Group Deniable" before 2026-10-27; F4,
 * docs/MLS_SECURITY_HARDENING.md §1) for a secure group: a new signing key
 * for us in the group, then our earlier ones published to its members
 * (epochal signatures). Shared by the phone and the desktop;
 * `DeniableChatTest`. Like [DeniableChat], it describes the mechanism and
 * claims nothing more.
 */
object GroupDeniable {

    const val ACTION = "Publish Group Keys…"
    const val TITLE = "Publish your earlier keys in this group?"
    const val CONFIRM = "Publish keys"

    const val BODY =
        "Gives you a new signing key in this group, then publishes your earlier " +
            "ones to its members, so any of them can make signatures under those " +
            "keys too. They are published only once every member's app has " +
            "confirmed it has your new key, so each member must come online first. " +
            "New messages are signed with the new key, which stays " +
            "secret. Messages stay encrypted. Earlier keys are also published " +
            "by themselves some minutes after each automatic key change, while " +
            "the app is running. Anything copied before they are published stays " +
            "signed. This group's history is deleted from this device. Not " +
            "independently reviewed."

    fun outcome(ok: Boolean, code: String): String =
        if (ok) "A new signing key is being set up; your earlier ones are published " +
            "once every member's app has confirmed it, and this group's history was " +
            "deleted from this device."
        else org.otrv4plus.android.chat.GroupText.outcome(code)
            ?: "The group could not be made deniable ($code)."

    /**
     * F4: earlier keys wait until every other member's app has confirmed the
     * new one (SecureGroups.keys_waiting), because a member still on the old
     * one would accept a message signed with a published key. While they
     * wait the button is not offered and says for how many.
     */
    fun canPublish(waitingFor: List<String>): Boolean = waitingFor.isEmpty()

    fun waiting(count: Int): String =
        "Publishing keys: waiting for $count member" + (if (count == 1) "" else "s")

    fun waitingLine(who: List<String>): String =
        if (who.isEmpty()) ""
        else "Your earlier keys are published when these members' apps confirm your " +
            "new key: " + who.take(5).joinToString(", ") +
            (if (who.size > 5) " and ${who.size - 5} more" else "") + "."

    /** What both apps do with the answer: on success the group's history goes. */
    fun apply(ok: Boolean, code: String, chat: org.otrv4plus.android.chat.ChatState,
              room: String): String {
        if (ok) chat.clearHistory(room)
        return outcome(ok, code)
    }
}
