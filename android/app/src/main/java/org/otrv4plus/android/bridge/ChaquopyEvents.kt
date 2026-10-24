// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import com.chaquo.python.PyObject

/**
 * One event from the bridge's queue (a dict, `android_bridge.events`), as an
 * [OtrEvent]. Reads only the dict it is given. An unknown type is null:
 * skipped, never guessed. tests/test_android_event_mapping.py checks every
 * branch against the Python event classes.
 */
internal object ChaquopyEvents {

    fun from(item: PyObject): OtrEvent? {
        fun str(k: String) = item.callAttr("get", k)?.toString() ?: ""
        fun num(k: String) = item.callAttr("get", k)?.toDouble() ?: 0.0
        fun int(k: String) = item.callAttr("get", k)?.toInt() ?: 0
        fun flag(k: String) = item.callAttr("get", k)?.toBoolean() ?: false
        return when (str("type")) {
            "ConnectionStateChanged" ->
                OtrEvent.ConnectionChanged(
                    ConnectionState.entries.firstOrNull {
                        it.name == str("state")
                    } ?: ConnectionState.DISCONNECTED)

            "SessionStateChanged" ->
                OtrEvent.SessionChanged(
                    str("peer"), SecurityState.fromLevel(int("security_level")))

            "MessageReceived" ->
                OtrEvent.MessageReceived(
                    str("peer"), str("body"), num("timestamp"),
                    messageId = item.callAttr("get", "message_id")?.toString()
                        ?.takeIf { it != "None" } ?: "",
                    source = str("source").ifBlank { "live" },
                    replyTo = str("reply_to").takeIf { it != "None" } ?: "")

            "MessageChanged" ->
                OtrEvent.MessageChanged(
                    str("peer"), str("action"), str("target_id"), str("body"),
                    runCatching {
                        item.callAttr("get", "emojis")?.asList()?.map { it.toString() }
                    }.getOrNull() ?: emptyList(),
                    flag("outgoing"), str("source"), str("sender"), str("sender_identity"))

            "RoomMessageAcked" ->
                OtrEvent.RoomMessageAcked(str("peer"), str("message_id"), str("stanza_id"))

            "MessageSentElsewhere" ->
                OtrEvent.MessageSentElsewhere(
                    str("peer"), str("body"), num("timestamp"),
                    str("message_id"), str("source"))

            "MessageDisplayed" ->
                OtrEvent.MessageDisplayed(str("peer"), str("message_id"))

            "ChatStateChanged" ->
                OtrEvent.ChatStateChanged(str("peer"), str("state"))

            "HistorySynced" -> OtrEvent.HistorySynced(int("count"))

            "RoomMessageReceived" ->
                OtrEvent.RoomMessageReceived(
                    str("peer"), str("sender"), str("body"), num("timestamp"),
                    encrypted = flag("encrypted"),
                    senderIdentity = str("sender_identity"),
                    verified = flag("verified"),
                    messageId = str("message_id"),
                    replyTo = str("reply_to"),
                    source = str("source").ifBlank { "live" },
                    own = flag("own"))

            "GroupInvite" ->
                OtrEvent.GroupInvited(str("peer"), str("room"), flag("verified"))

            "GroupEntryRequested" ->
                OtrEvent.GroupEntryRequested(str("peer"), str("requester"), flag("live"))

            "GroupChanged" ->
                OtrEvent.GroupChanged(
                    str("peer"), str("change"), num("epoch").toLong(), str("detail"))

            // The Python class is SmpProgress, the Kotlin event is
            // SmpProgressed. The names differ and that is a trap: these
            // branches are checked against android_bridge.events by
            // tests/test_android_event_mapping.py, because three of them were
            // wrong when first written and nothing would have noticed.
            "SmpProgress" ->
                OtrEvent.SmpProgressed(
                    str("peer"),
                    SmpProgress(int("step"), int("total"),
                        SmpState.fromName(str("state"))))

            "SmpResult" ->
                OtrEvent.SmpFinished(str("peer"), SmpState.fromName(str("state")))

            "FingerprintChanged" ->
                OtrEvent.FingerprintChanged(
                    str("peer"), str("stored_fingerprint"),
                    str("received_fingerprint"))

            // A delivery receipt (XEP-0184) for one of our messages.
            "MessageDelivered" ->
                OtrEvent.MessageDelivered(str("peer"), str("message_id"))

            "CallStateChanged" ->
                OtrEvent.CallChanged(
                    str("peer"), CallState.fromName(str("state")),
                    int("duration_seconds"))

            // Was dropped here for a real reason that has since been fixed:
            // the controller used to log this and never queue it, because a
            // plain dict arrives from `EventQueue._describe` as
            // `{"type": "dict"}` with no fields. It is a dataclass now, so
            // there is something to map.
            "SubscriptionRequested" ->
                OtrEvent.SubscriptionRequested(
                    str("peer"), SubscriptionPolicy.of(str("policy")))

            "OtrCapabilityChanged" ->
                OtrEvent.CapabilityChanged(str("peer"), str("state"))

            "QueuedSent" ->
                OtrEvent.QueuedSent(
                    str("peer"), int("count"),
                    item.callAttr("get", "encrypted")?.toBoolean() ?: false)

            "FileTransferChanged" ->
                OtrEvent.FileTransferChanged(
                    str("peer"), str("transfer_id"), str("filename"),
                    item.callAttr("get", "size")?.toLong() ?: 0L,
                    item.callAttr("get", "outgoing")?.toBoolean() ?: false,
                    str("state"), str("reason"), str("path"))

            "VoiceNoteReceived" ->
                OtrEvent.VoiceNoteReceived(
                    str("peer"), str("transfer_id"), str("path"), str("sender"))

            "ErrorOccurred" ->
                OtrEvent.Failed(str("peer").ifBlank { null }, str("code"))

            // An event type this build does not know about is skipped rather
            // than guessed at. A wrong mapping is worse than a missing one:
            // the screen would show something confident and untrue.
            else -> null
        }
    }
}
