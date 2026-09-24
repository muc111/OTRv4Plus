// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * "Delete chat": what it does, what it offers, and what it may claim.
 *
 * Plain Kotlin, driven by `ChatDeletionTest`. The screen renders these
 * strings and nothing else, so what the user is told is fixed here.
 *
 * WHAT IT DOES
 * ------------
 * One-to-one: deletes the history on this device (records and index), the
 * draft and the unread count, and keeps the row gone ([DeletedConversations]).
 * It does NOT remove the contact from the server roster (that is "Remove
 * contact", a separate action) and it does not touch OTR or verification
 * state, which are about the peer rather than about what was said.
 *
 * Room (XEP-0045 multi-user chat): the same locally, and optionally LEAVE the
 * room. It NEVER destroys the room. Destroying is an owner action on a room
 * other people are in, and it is only on the Rooms screen, behind its own
 * confirmation. Deleting a chat is about this device.
 *
 * WHAT IT MAY CLAIM
 * -----------------
 * No XEP lets a client delete a server's message archive, so this app never
 * deletes server-side history and never says it did. When the server was
 * asked (disco#info) the answer is reported: it keeps an archive, or it
 * advertised none. When it could not be asked, that is said instead.
 */
object ChatDeletion {

    enum class Kind { DIRECT, ROOM }

    /** What the server said about keeping history, if it was asked. */
    enum class ServerArchive {
        /** Advertises XEP-0313. Its copy, if any, is still there. */
        ADVERTISED,
        /** Answered, and advertised no archive. */
        NOT_ADVERTISED,
        /** Not asked or did not answer: offline, timeout, error. */
        UNKNOWN,
    }

    data class Outcome(
        val kind: Kind,
        val deletedLocally: Boolean,
        /** Null when leaving was not asked for. */
        val left: Boolean?,
        val server: ServerArchive,
    ) {
        /** One sentence for the notice banner. Never says the server deleted anything. */
        val notice: String
            get() = buildString {
                append(if (deletedLocally) "Deleted from this device." else "Nothing to delete on this device.")
                when (left) {
                    true -> append(" You left the room; it still exists for everyone else.")
                    false -> append(" Leaving the room failed; you are still in it.")
                    null -> {}
                }
                append(" ")
                append(when (server) {
                    ServerArchive.ADVERTISED ->
                        "Server-side deletion is not supported: the server keeps a " +
                            "message archive and its copy was not deleted" +
                            (if (kind == Kind.DIRECT) " (for encrypted messages, " +
                                "that copy is OTR ciphertext)." else ".")
                    ServerArchive.NOT_ADVERTISED ->
                        "Server-side deletion is not supported; the server " +
                            "advertises no message archive."
                    ServerArchive.UNKNOWN ->
                        "Server-side deletion is not supported, and whether the " +
                            "server keeps a copy could not be checked."
                })
            }
    }

    fun confirmTitle(kind: Kind, name: String): String = when (kind) {
        Kind.DIRECT -> "Delete chat with $name?"
        Kind.ROOM -> "Delete room chat $name?"
    }

    fun confirmBody(kind: Kind): String = when (kind) {
        Kind.DIRECT ->
            "Deletes the messages with this contact from this device. It " +
                "cannot be undone. They stay in your contacts, and a new " +
                "message brings the conversation back. Anything the server " +
                "or the other person kept is not deleted."
        Kind.ROOM ->
            "Deletes this room's messages from this device. It cannot be " +
                "undone. The room is not destroyed and nobody else loses " +
                "anything; what the server kept is not deleted. If you stay " +
                "in the room, new messages bring it back."
    }

    const val CONFIRM = "Delete"
    const val CONFIRM_AND_LEAVE = "Delete and leave room"
    const val CANCEL = "Cancel"

    /** Map the bridge's probe onto what may be said. `null` = not answered. */
    fun serverArchive(answered: Boolean, mam: Boolean): ServerArchive = when {
        !answered -> ServerArchive.UNKNOWN
        mam -> ServerArchive.ADVERTISED
        else -> ServerArchive.NOT_ADVERTISED
    }
}
