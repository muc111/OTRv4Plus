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
 *     id US conversationId US outgoing US at US sendState US security US
 *     sender US wireId US flags US replyTo US replyPreview US reactions US body
 *
 * (version 3; "2" records stop after the sender, "1" records before it).
 * [reactions] is `who GS emoji GS emoji RS2 who GS emoji ...` with GS = U+0002
 * and RS2 = U+0003, both escaped inside every field like the separators.
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
    private const val VERSION = "3"
    private const val V2 = "2"
    private const val LEGACY_VERSION = "1"
    private const val SUB = '\u0002'
    private const val SUBREC = '\u0003'

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
        val version = header?.split(FIELD)?.firstOrNull()
        val count = when (version) { LEGACY_VERSION -> 7; V2 -> 8; else -> 13 }
        return parts.drop(1).mapNotNull { decode(it, count) }
    }

    /** The persisted unread count, or null when the record is unreadable. */
    fun decodeUnread(text: String): Int? {
        val header = text.split(RECORD).firstOrNull() ?: return null
        if (!isHeader(header)) return null
        return header.split(FIELD).getOrNull(1)?.toIntOrNull() ?: 0
    }

    private fun isHeader(header: String?): Boolean =
        header != null && header.split(FIELD).firstOrNull()
            .let { it == VERSION || it == V2 || it == LEGACY_VERSION }

    fun encode(message: Message): String = listOf(
        escape(message.id),
        escape(message.conversationId),
        if (message.outgoing) "1" else "0",
        message.at.toString(),
        message.sendState.name,
        message.security.name,
        escape(message.sender),
        escape(message.wireId),
        (if (message.edited) "e" else "") + (if (message.retracted) "r" else ""),
        escape(message.replyTo),
        escape(message.replyPreview),
        escape(message.reactions.entries.joinToString(SUBREC.toString()) { (who, emoji) ->
            (listOf(who) + emoji).joinToString(SUB.toString()) { escape(it) }
        }),
        escape(message.body),
    ).joinToString(FIELD.toString())

    private fun decodeReactions(text: String): Map<String, List<String>> {
        if (text.isEmpty()) return emptyMap()
        val out = linkedMapOf<String, List<String>>()
        for (record in text.split(SUBREC)) {
            val bits = record.split(SUB).map { unescape(it) }
            if (bits.size >= 2 && bits[0].isNotEmpty()) out[bits[0]] = bits.drop(1).take(16)
        }
        return out
    }

    /**
     * One record, or null.
     *
     * Null rather than an exception for anything malformed: this is read back
     * from a file, and one bad line must cost that line rather than the
     * conversation. An unknown enum name resolves to the SAFE value -- a
     * security label this build does not recognise becomes UNKNOWN, never
     * ENCRYPTED.
     */
    fun decode(line: String, legacy: Boolean = false): Message? =
        // Every field is escaped, so the raw separators count the fields
        // exactly: 13 for a v3 record, 8 for v2 (7 when told it is v1).
        decode(line, if (legacy) 7 else if (line.count { it == FIELD } >= 12) 13 else 8)

    fun decode(line: String, count: Int): Message? {
        if (line.isBlank()) return null
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
            sender = if (count < 8) "" else unescape(parts[6]),
            wireId = if (count < 13) "" else unescape(parts[7]),
            edited = count >= 13 && 'e' in parts[8],
            retracted = count >= 13 && 'r' in parts[8],
            replyTo = if (count < 13) "" else unescape(parts[9]),
            replyPreview = if (count < 13) "" else unescape(parts[10]),
            reactions = if (count < 13) emptyMap() else decodeReactions(unescape(parts[11])),
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
            SUB -> append("\\a")
            SUBREC -> append("\\b")
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
                'a' -> append(SUB)
                'b' -> append(SUBREC)
                else -> append(text[i + 1])
            }
            i += 2
        }
    }
}
