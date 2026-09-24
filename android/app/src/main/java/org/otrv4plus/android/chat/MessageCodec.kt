// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Messages to bytes and back.
 *
 * DELIBERATELY NOT JSON, AND NOT A DATABASE
 * -----------------------------------------
 * A JSON library is a dependency and a parser surface; a database is a schema,
 * a migration story and a file this project would then have to keep sealed.
 * What is actually needed is "turn 500 small records into a byte array and
 * back", and a line-oriented format does that in fifty lines with no
 * dependency and no parser to be surprised by.
 *
 * THE FORMAT
 * ----------
 * One message per line. Fields separated by `` (UNIT SEPARATOR), lines by
 * `` (RECORD SEPARATOR):
 *
 *     id US conversationId US outgoing US at US sendState US security US body
 *
 * The control characters are the point. A message body may contain anything a
 * person can type -- tabs, newlines, pipes, commas, quotes -- and every one of
 * those is a separator somebody has regretted choosing. `` and ``
 * cannot appear in text typed at a keyboard, and the ones that could still
 * arrive from a hostile peer are escaped rather than trusted: see [escape].
 *
 * The BODY IS LAST and is split with a limit, so even if an escape were missed
 * a body containing a separator cannot shift the other fields -- the failure
 * mode is a body with a stray character in it, not a message attributed to the
 * wrong conversation or relabelled as encrypted.
 */
internal object MessageCodec {

    private const val FIELD = ''
    private const val RECORD = ''

    /**
     * The version marker. "2" added the room SENDER as a field before the
     * body; "1" records (seven fields, no sender) still decode, so history
     * written by an older build survives the upgrade.
     */
    private const val VERSION = "2"
    private const val LEGACY_VERSION = "1"

    /**
     * The header carries the UNREAD COUNT as well as the version.
     *
     * It has to be persisted rather than recomputed: rehydrating replays every
     * message through `append`, which counts each inbound one as unread, so a
     * conversation the user had already read came back wearing a badge after
     * every restart.
     */
    fun encodeAll(messages: List<Message>, unread: Int = 0): String =
        (listOf(VERSION + FIELD + unread) + messages.map { encode(it) })
            .joinToString(RECORD.toString())

    fun decodeAll(text: String): List<Message> {
        if (text.isEmpty()) return emptyList()
        val parts = text.split(RECORD)
        val header = parts.firstOrNull()
        if (!isHeader(header)) return emptyList()
        val legacy = header?.split(FIELD)?.firstOrNull() == LEGACY_VERSION
        return parts.drop(1).mapNotNull { decode(it, legacy) }
    }

    /** The persisted unread count, or null when the record is unreadable. */
    fun decodeUnread(text: String): Int? {
        val header = text.split(RECORD).firstOrNull() ?: return null
        if (!isHeader(header)) return null
        return header.split(FIELD).getOrNull(1)?.toIntOrNull() ?: 0
    }

    private fun isHeader(header: String?): Boolean =
        header != null && header.split(FIELD).firstOrNull()
            .let { it == VERSION || it == LEGACY_VERSION }

    fun encode(message: Message): String = listOf(
        escape(message.id),
        escape(message.conversationId),
        if (message.outgoing) "1" else "0",
        message.at.toString(),
        message.sendState.name,
        message.security.name,
        escape(message.sender),
        escape(message.body),
    ).joinToString(FIELD.toString())

    /**
     * One record, or null.
     *
     * Null rather than an exception for anything malformed: this is read back
     * from a file, and one bad line must cost that line rather than the
     * conversation. An unknown enum name resolves to the SAFE value -- a
     * security label this build does not recognise becomes UNKNOWN, never
     * ENCRYPTED.
     */
    fun decode(line: String, legacy: Boolean = false): Message? {
        if (line.isBlank()) return null
        val count = if (legacy) 7 else 8
        val parts = line.split(FIELD, limit = count)
        if (parts.size != count) return null
        val at = parts[3].toLongOrNull() ?: return null
        val id = unescape(parts[0])
        val conversationId = unescape(parts[1])
        if (id.isEmpty() || conversationId.isEmpty()) return null
        return Message(
            id = id,
            conversationId = conversationId,
            body = unescape(parts[count - 1]),
            sender = if (legacy) "" else unescape(parts[6]),
            outgoing = parts[2] == "1",
            at = at,
            sendState = SendState.entries.firstOrNull { it.name == parts[4] }
                ?: SendState.NONE,
            // UNKNOWN, not PLAINTEXT and certainly not ENCRYPTED. A label this
            // build cannot read must not be rendered as a claim.
            security = SecurityLabel.entries.firstOrNull { it.name == parts[5] }
                ?: SecurityLabel.UNKNOWN,
        )
    }

    /**
     * Make the separators unrepresentable in a field.
     *
     * A peer controls the body, so this is not a tidiness measure: without it a
     * body containing `` would end the record early and the remainder
     * would be parsed as a NEW message, with attacker-chosen conversation id,
     * direction and security label. That is a forged chat entry, written by
     * whoever can send this device a message.
     */
    internal fun escape(text: String): String = buildString(text.length) {
        for (ch in text) when (ch) {
            '\\' -> append("\\\\")
            FIELD -> append("\\u")
            RECORD -> append("\\r")
            else -> append(ch)
        }
    }

    internal fun unescape(text: String): String = buildString(text.length) {
        var i = 0
        while (i < text.length) {
            val ch = text[i]
            if (ch != '\\' || i == text.length - 1) {
                append(ch)
                i++
                continue
            }
            when (text[i + 1]) {
                '\\' -> append('\\')
                'u' -> append(FIELD)
                'r' -> append(RECORD)
                else -> append(text[i + 1])
            }
            i += 2
        }
    }
}
