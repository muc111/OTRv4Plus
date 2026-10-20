// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.engine

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.otrv4plus.android.bridge.AvatarImage
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.GroupCallState
import org.otrv4plus.android.bridge.GroupMember
import org.otrv4plus.android.bridge.GroupVerifyState
import org.otrv4plus.android.bridge.ProfileField
import org.otrv4plus.android.chat.AvatarPixels
import org.otrv4plus.android.bridge.ConnectionState
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.InitResult
import org.otrv4plus.android.bridge.OtrBridgeException
import org.otrv4plus.android.bridge.OtrCore
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.OtrEventSink
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.RegistrationOutcome
import org.otrv4plus.android.bridge.SecurityDetails
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.bridge.SmpProgress
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription
import org.otrv4plus.android.bridge.SubscriptionPolicy
import org.otrv4plus.android.bridge.WipeReport
import org.otrv4plus.android.crypto.HandshakeUi

/**
 * [OtrCore] over the engine process: the desktop's ChaquopyOtrCore.
 *
 * Same operations, same result shapes, same rules: every method is one
 * call into `android_bridge` (through `desktop_bridge.host`), nothing here
 * decides anything about security, and a failure surfaces as a code.
 * Blocking: call from Dispatchers.IO.
 *
 * Events are pushed by the host rather than polled; they are parsed here
 * with the same mapping as `ChaquopyOtrCore.eventFrom` (and checked against
 * `android_bridge.events` by tests/test_desktop_event_mapping.py).
 */
class DesktopCore(private val engine: Engine) : OtrCore {

    @Volatile private var sink: OtrEventSink? = null

    /** Called by the engine's reader thread for every pushed event. */
    fun deliver(raw: JsonObject) {
        val event = eventFrom(raw) ?: return
        sink?.let { runCatching { it.onEvent(event) } }
    }

    override fun setEventSink(sink: OtrEventSink?) { this.sink = sink }

    override fun initialize(): InitResult = try {
        val ready = engine.awaitReady()
        InitResult(ok = true, pythonVersion = ready.str("python"), abi = "desktop",
                   rustCoreLoaded = true, engineInitialized = true)
    } catch (e: OtrBridgeException) {
        InitResult(ok = false, pythonVersion = "", abi = "desktop",
                   rustCoreLoaded = false, engineInitialized = false, failureCode = e.code)
    }

    override fun shutdown() = engine.shutdown()

    private fun call(op: String, vararg args: Pair<String, Any?>): JsonElement =
        engine.call(op, mapOf(*args))

    // -- connection ------------------------------------------------------------

    fun prepare(jid: String, server: String = "", samHost: String = "", samPort: Int = 0): ConnectionStatus =
        statusFrom(call("prepare", "jid" to jid, "server" to server,
                        "sam_host" to samHost, "sam_port" to samPort))

    fun connect(password: String): ConnectionStatus =
        statusFrom(call("connect", "password" to password))

    fun connectionStatus(): ConnectionStatus = statusFrom(call("status"))

    /** Create the account [prepare] named (in-band registration). Does not
     *  sign in: the caller connects next. [password] is not kept. */
    fun register(password: String): RegistrationOutcome {
        val r = call("register", "password" to password) as? JsonObject ?: JsonObject(emptyMap())
        return RegistrationOutcome(ok = r["ok"].asBool(), code = r.str("code").ifBlank { "unknown" },
                                   detail = r.str("detail"))
    }

    fun disconnect() { call("disconnect") }
    fun cancel() { call("cancel") }

    // -- engine state ------------------------------------------------------------

    override fun localFingerprint(): String = call("local_fingerprint").asStr()

    override fun securityState(peer: String): SecurityState =
        SecurityState.fromLevel(call("security_state", "peer" to peer).asInt())

    override fun smpState(peer: String): SmpState =
        SmpState.fromName(call("smp_state", "peer" to peer).asStr().ifBlank { "NOT_VERIFIED" })

    override fun smpProgress(peer: String): SmpProgress {
        val p = call("smp_progress", "peer" to peer) as? JsonObject ?: JsonObject(emptyMap())
        return SmpProgress(p["step"].asInt(), p["total"].asInt().takeIf { it > 0 } ?: 4,
                           SmpState.fromName(p.str("state").ifBlank { "NOT_VERIFIED" }))
    }

    /** "Fingerprints match": the engine checks [fingerprint] is the session's
     *  key (constant time) and records it as confirmed. */
    fun trustPeer(peer: String, fingerprint: String): Boolean = runCatching {
        call("trust_peer", "peer" to peer, "fingerprint" to fingerprint).asBool()
    }.getOrDefault(false)

    override fun securityDetails(peer: String): SecurityDetails {
        val d = call("security_details", "peer" to peer) as? JsonObject ?: JsonObject(emptyMap())
        return SecurityDetails(
            peer = peer,
            security = SecurityState.fromLevel(d["security"].asInt()),
            smp = SmpState.fromName(d.str("smp").ifBlank { "NOT_VERIFIED" }),
            smpPhase = d.str("smp_phase"),
            localFingerprint = d.str("local_fingerprint"),
            peerFingerprint = d.str("peer_fingerprint").ifBlank { null },
            trusted = d["trusted"].asBool(),
        )
    }

    override fun contacts(): List<Contact> =
        (call("contacts") as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }.map { c ->
            Contact(
                jid = c.str("jid"),
                displayName = c.str("display_name"),
                presence = PeerPresence.of(c.str("presence")),
                presenceShow = c.str("presence_show"),
                security = SecurityState.fromLevel(c["security"].asInt()),
                smp = SmpState.fromName(c.str("smp").ifBlank { "NOT_VERIFIED" }),
                callAvailable = c["call_available"].asBool(),
                subscription = Subscription.of(c.str("subscription"), c["pending"].asBool()),
            )
        }

    fun otrCapability(peer: String): String =
        runCatching { call("otr_capability", "peer" to peer).asStr() }.getOrDefault("unknown")

    fun ensureOtr(peer: String): String =
        runCatching { call("ensure_otr", "peer" to peer).asStr() }.getOrDefault("unknown")

    fun handshakeStatus(peer: String): HandshakeUi.Status = runCatching {
        val v = call("handshake_status", "peer" to peer) as JsonObject
        HandshakeUi.Status(
            stage = v.str("stage").ifBlank { "idle" },
            step = v["step"].asInt(), steps = v["steps"].asInt().takeIf { it > 0 } ?: 3,
            have = v["have"].asInt(), of = v["of"].asInt(), elapsed = v["elapsed"].asInt(),
            eta = v["eta"].asInt(), queued = v["queued"].asInt(),
        )
    }.getOrDefault(HandshakeUi.Status.IDLE)

    // -- messages and SMP ----------------------------------------------------------

    override fun startSession(peer: String) { call("start_session", "peer" to peer) }

    override fun sendMessage(peer: String, body: String) {
        sendUserText(peer, body)
    }

    override fun sendUserText(peer: String, body: String): SendOutcome =
        SendOutcome.fromName(call("send_user_text", "peer" to peer, "body" to body).asStr())

    override fun sendUserText(peer: String, body: String, messageId: String): SendOutcome =
        SendOutcome.fromName(call("send_user_text", "peer" to peer, "body" to body,
                                  "message_id" to messageId).asStr())

    override fun sendReply(peer: String, body: String, messageId: String, replyTo: String): SendOutcome =
        SendOutcome.fromName(call("send_user_text", "peer" to peer, "body" to body,
                                  "message_id" to messageId, "reply_to" to replyTo).asStr())

    override fun sendAction(peer: String, action: String, targetId: String, body: String,
                            emojis: List<String>, messageId: String): SendOutcome =
        runCatching {
            SendOutcome.fromName(call("send_action", "peer" to peer, "action" to action,
                                      "target_id" to targetId, "body" to body,
                                      "emojis" to emojis, "message_id" to messageId).asStr())
        }.getOrDefault(SendOutcome.FAILED)

    override fun markDisplayed(peer: String) {
        runCatching { call("mark_displayed", "peer" to peer) }
    }

    override fun sendChatStateTo(peer: String, state: String) {
        runCatching { call("set_chat_state", "peer" to peer, "state" to state) }
    }

    override fun setPrivacy(chatStates: Boolean, readMarkers: Boolean) {
        runCatching { call("set_privacy", "chat_states" to chatStates, "read_markers" to readMarkers) }
    }

    override fun setClientActive(active: Boolean) {
        runCatching { call("set_client_active", "active" to active) }
    }

    override fun smpStart(peer: String, secret: String, question: String) {
        call("smp_start", "peer" to peer, "secret" to secret, "question" to question)
    }

    override fun smpRespond(peer: String, secret: String) {
        call("smp_respond", "peer" to peer, "secret" to secret)
    }

    override fun smpSecretRequired(peer: String): Boolean =
        runCatching { call("smp_secret_required", "peer" to peer).asBool() }.getOrDefault(false)

    override fun smpAbort(peer: String) { call("smp_abort", "peer" to peer) }

    // -- calls (the gate is the engine's; nothing here decides) ------------------------

    fun startCall(peer: String): String =
        runCatching { call("start_call", "peer" to peer).asStr() }.getOrDefault("unavailable")
    fun answerCall(peer: String): String =
        runCatching { call("answer_call", "peer" to peer).asStr() }.getOrDefault("unavailable")
    fun endCall(peer: String): String =
        runCatching { call("end_call", "peer" to peer).asStr() }.getOrDefault("unavailable")
    fun callState(peer: String): CallState =
        runCatching { CallState.fromName(call("call_state", "peer" to peer).asStr().ifBlank { "IDLE" }) }
            .getOrDefault(CallState.IDLE)
    fun callDurationSeconds(peer: String): Int =
        runCatching { call("call_duration_seconds", "peer" to peer).asInt() }.getOrDefault(0)
    fun callGate(peer: String): Pair<String, String>? = runCatching {
        val d = call("call_gate", "peer" to peer) as JsonObject
        d.str("gate").ifBlank { return@runCatching null } to d.str("reason")
    }.getOrNull()
    fun voiceUnavailableReason(): String =
        runCatching { call("voice_unavailable_reason").asStr() }.getOrDefault("")
    /** The next call's I2P path (see the app's ChaquopyOtrCore.callPath). */
    fun callPath(build: Boolean): Pair<String, Int> = runCatching {
        val d = call(if (build) "warm_call_path" else "call_path_state") as JsonObject
        d.str("state").ifBlank { "cold" } to (d.str("seconds_left").toIntOrNull() ?: 0)
    }.getOrDefault("cold" to 0)

    // -- files ---------------------------------------------------------------------------

    fun sendFile(peer: String, path: String, stripMetadata: Boolean): String =
        runCatching {
            call("send_file", "peer" to peer, "path" to path, "strip_metadata" to stripMetadata).asStr()
        }.getOrElse { (it as? OtrBridgeException)?.code ?: "failed" }
    // -- voice notes (otrv4plus_voicenote; the recording stays in Python) ---------------

    fun voiceNoteStart(): String = runCatching { call("voice_note_start").asStr() }.getOrDefault("no_microphone")
    fun voiceNoteStatus(): org.otrv4plus.android.chat.VoiceRecording = runCatching {
        val d = call("voice_note_status") as JsonObject
        org.otrv4plus.android.chat.VoiceRecording(d["recording"].asBool(), d["seconds"].asDouble(),
                                                  d["level"].asDouble(), d.str("error"))
    }.getOrDefault(org.otrv4plus.android.chat.VoiceRecording(false, 0.0, 0.0, ""))
    fun voiceNoteStop(mode: String, directory: String): org.otrv4plus.android.chat.VoiceNoteFile = runCatching {
        val d = call("voice_note_stop", "mode" to mode, "directory" to directory) as JsonObject
        org.otrv4plus.android.chat.VoiceNoteFile(d.str("path"), d["seconds"].asDouble(),
                                                 d.str("mode").ifBlank { mode }, d.str("error"))
    }.getOrDefault(org.otrv4plus.android.chat.VoiceNoteFile("", 0.0, mode, "failed"))
    /** The [sendFile] outcome, and the sealed copy kept for playback ("" when none). */
    fun sendVoiceNote(peer: String, path: String): Pair<String, String> = runCatching {
        val d = call("send_voice_note", "peer" to peer, "path" to path) as JsonObject
        d.str("outcome").ifBlank { "failed" } to d.str("path")
    }.getOrElse { ((it as? OtrBridgeException)?.code ?: "failed") to "" }
    fun voiceNoteCancel() { runCatching { call("voice_note_cancel") } }
    fun voiceNoteDiscard(path: String) { runCatching { call("voice_note_discard", "path" to path) } }
    /** Play a note (preview or received) through the engine's audio output. */
    fun voiceNotePlay(path: String): String = runCatching {
        (call("voice_note_play", "path" to path) as JsonObject).str("error")
    }.getOrDefault("bad_file")
    fun voiceNotePlayStop() { runCatching { call("voice_note_play_stop") } }

    fun acceptFile(id: String): String = runCatching { call("accept_file", "transfer_id" to id).asStr() }.getOrDefault("failed")
    fun declineFile(id: String): String = runCatching { call("decline_file", "transfer_id" to id).asStr() }.getOrDefault("failed")
    fun cancelFile(id: String): String = runCatching { call("cancel_file", "transfer_id" to id).asStr() }.getOrDefault("failed")
    fun saveReceived(path: String, destination: String): String =
        runCatching { call("save_received", "path" to path, "destination" to destination).asStr() }.getOrDefault("")

    fun transfers(): List<FileTransferView> = runCatching {
        (call("transfers") as JsonArray).mapNotNull { it as? JsonObject }.map { r ->
            FileTransferView(
                id = r.str("id"), peer = r.str("peer"), filename = r.str("filename"),
                sizeBytes = r["size"].asLong(), outgoing = r["outgoing"].asBool(),
                accepted = r["accepted"].asBool(), cancelled = r["cancelled"].asBool(),
                progress = r["progress"].asDouble().toFloat(), state = r.str("state"),
                reason = r.str("reason"), path = r.str("path"), group = r["group"].asBool(),
                sender = r.str("from"), deliveredTo = r["delivered_to"].asInt(),
            )
        }
    }.getOrDefault(emptyList())

    // -- contacts and rooms ---------------------------------------------------------------

    /** `{ok, code, detail, value}` from the controller, flattened. */
    data class Outcome(val ok: Boolean, val code: String, val detail: String, val value: JsonElement?)

    fun controller(op: String, vararg args: Pair<String, Any?>): Outcome = try {
        val r = call(op, *args) as? JsonObject ?: JsonObject(emptyMap())
        Outcome(r["ok"].asBool(), r.str("code"), r.str("detail"), r["value"])
    } catch (e: OtrBridgeException) {
        Outcome(false, e.code, "", null)
    }

    fun addContact(jid: String, name: String = "") = controller("add_contact", "jid" to jid, "name" to name)
    fun removeContact(jid: String) = controller("remove_contact", "jid" to jid)
    fun answerSubscription(jid: String, approve: Boolean) =
        controller("answer_subscription", "jid" to jid, "approve" to approve)
    fun joinRoom(room: String, nick: String, password: String = "") =
        controller("join_room", "room" to room, "nick" to nick, "password" to password)
    fun leaveRoom(room: String, nick: String) = controller("leave_room", "room" to room, "nick" to nick)
    fun blockContact(jid: String, report: String) = controller("block_contact", "jid" to jid, "report" to report)
    fun unblockContact(jid: String) = controller("unblock_contact", "jid" to jid)
    /** The server's block list, and whether it can block at all. */
    fun blockedContacts(): Pair<List<String>, Boolean> {
        val r = runCatching { call("blocked_contacts") as? JsonObject }.getOrNull() ?: return emptyList<String>() to false
        return names(r["value"]) to r["supported"].asBool()
    }
    fun createSecureGroup(room: String) = controller("create_secure_group", "room" to room, "password" to "")
    fun acceptGroupInvite(room: String, password: String = "") =
        controller("accept_group_invite", "room" to room, "password" to password)
    fun declineGroupInvite(room: String) = controller("decline_group_invite", "room" to room)
    fun inviteToGroup(room: String, peer: String) = controller("invite_to_group", "room" to room, "peer" to peer)
    fun requestGroupEntry(room: String) = controller("request_group_entry", "room" to room)
    fun startGroupVerify(room: String, passphrase: String) =
        controller("start_group_verify", "room" to room, "passphrase" to passphrase)
    fun startGroupCall(room: String) = controller("start_group_call", "room" to room)
    fun joinGroupCall(room: String) = controller("join_group_call", "room" to room)
    fun hangupGroupCall() = controller("hangup_group_call")

    fun leaveSecureGroup(room: String) = controller("leave_secure_group", "room" to room)
    fun deleteSecureGroup(room: String) = controller("delete_secure_group", "room" to room)
    fun removeGroupMember(room: String, member: String) =
        controller("remove_group_member", "room" to room, "member" to member)
    fun verifyGroupMembers(room: String) = controller("verify_group_members", "room" to room)
    fun pauseGroupCall() = controller("pause_group_call")
    fun setGroupCallAutoJoin(allowed: Boolean) =
        controller("set_group_call_auto_join", "allowed" to allowed)

    /** Who is verified in [room], and a verification someone started. */
    fun groupVerifyState(room: String): GroupVerifyState {
        val v = controller("group_verify_state", "room" to room).value as? JsonObject
            ?: return GroupVerifyState()
        return GroupVerifyState(
            members = (v["members"] as? JsonObject).orEmpty().mapValues { it.value.asStr() },
            allVerified = v["all_verified"].flag(), startedBy = v.str("started_by"),
            active = v["active"].flag(), done = v["done"].asInt(), total = v["total"].asInt(),
            etaSeconds = v["eta"].asInt(),
            excluded = (v["excluded"] as? JsonArray).orEmpty().map { it.asStr() },
        )
    }

    fun groupCallState(room: String): GroupCallState {
        val v = controller("group_call_state", "room" to room).value as? JsonObject
            ?: return GroupCallState()
        return GroupCallState(
            inCall = v["in_call"].flag(), paused = v["paused"].flag(),
            participants = (v["participants"] as? JsonArray).orEmpty().map { it.asStr() },
            ringingFrom = v.str("ringing_from"),
        )
    }

    fun groupMembers(room: String): Pair<Outcome, List<GroupMember>> {
        val r = controller("group_members", "room" to room)
        val members = (r.value as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }.map { m ->
            GroupMember(jid = m.str("jid"), fingerprint = m.str("fingerprint"),
                        me = m["me"].flag(), verified = m["verified"].flag(), bound = m["bound"].flag())
        }
        return r to members
    }

    // -- avatars: pixels, decoded by the engine's bounded decoder ------------------------

    /** Bare JID -> avatar id. No network. */
    fun avatarIndex(): Map<String, String> = runCatching {
        AvatarPixels.index((call("avatar_index") as JsonArray).map { it.asStr() })
    }.getOrDefault(emptyMap())

    /**
     * A contact's avatar as RGBA PIXELS. Base64 here is text decoding, not
     * image decoding: no image decoder in this process reads a peer's file.
     */
    fun avatarImage(jid: String): AvatarImage? = runCatching {
        val v = call("avatar_pixels", "jid" to jid) as? JsonObject ?: return null
        AvatarImage(id = v.str("id"), width = v["width"].asInt(), height = v["height"].asInt(),
                    rgba = java.util.Base64.getDecoder().decode(v.str("rgba_b64")))
    }.getOrNull()

    /** Publish our avatar: PNG this app made from the user's own picture. */
    fun setAvatar(png: ByteArray) =
        controller("set_avatar_b64", "text" to java.util.Base64.getEncoder().encodeToString(png))

    fun removeAvatar() = controller("remove_avatar")

    // -- the XMPP profile (vcard-temp) ---------------------------------------------------

    fun profileFields(): List<ProfileField> = runCatching {
        (call("profile_fields") as JsonArray).mapNotNull { item ->
            val p = item.asStr().split('\t')
            if (p.size != 4) null else ProfileField(p[0], p[1], p[2].toIntOrNull() ?: 0, p[3] == "1")
        }
    }.getOrDefault(emptyList())

    /** A profile (ours when [jid] is blank), sanitised by the engine. */
    fun profileGet(jid: String = ""): Pair<Outcome, Map<String, String>> {
        val r = controller("profile_get_json", "jid" to jid)
        return r to jsonMap(r.value.asStr())
    }

    fun profileSet(values: Map<String, String>): Pair<Outcome, Map<String, String>> {
        val text = kotlinx.serialization.json.JsonObject(
            values.mapValues { kotlinx.serialization.json.JsonPrimitive(it.value) }).toString()
        val r = controller("profile_set_json", "text" to text)
        return r to jsonMap(r.value.asStr())
    }

    private fun jsonMap(text: String): Map<String, String> = runCatching {
        if (text.isBlank()) return emptyMap()
        (kotlinx.serialization.json.Json.parseToJsonElement(text) as JsonObject)
            .mapValues { it.value.asStr() }
    }.getOrDefault(emptyMap())

    fun joinedRooms(): List<String> = names(controller("joined_rooms").value)
    fun secureGroups(): List<String> = names(controller("secure_groups").value)
    fun ownedRooms(): List<String> = names(controller("owned_rooms").value)
    fun serverAdmin(): Boolean? = runCatching {
        val r = controller("server_admin")
        if (r.ok) r.value.asBool() else null
    }.getOrNull()

    /** Other sessions of our own account; null when unknown. */
    fun otherSessions(): Int? = runCatching {
        val r = controller("other_sessions")
        if (r.ok) (r.value as? JsonArray)?.size ?: 0 else null
    }.getOrNull()

    /** Sign out our other sessions (server admins only): outcome and count. */
    fun endOtherSessions(): Pair<Outcome, Int> {
        val r = controller("end_other_sessions")
        val n = runCatching { r.value.asInt() }.getOrDefault(0)
        return r to n
    }

    /** Change the account's password on the server; the engine checks [current]. */
    fun changePassword(current: String, new: String): Outcome =
        controller("change_password", "current_password" to current, "new_password" to new)

    private fun names(value: JsonElement?): List<String> =
        (value as? JsonArray).orEmpty().mapNotNull { item ->
            when (item) {
                is JsonObject -> item.str("room").ifBlank { item.str("jid") }.ifBlank { null }
                else -> item.asStr().ifBlank { null }
            }
        }

    // -- wipe ---------------------------------------------------------------------------------

    override fun wipeCrypto(): Boolean = runCatching {
        val r = call("wipe_crypto") as? JsonObject
        (r?.get("errors") as? JsonArray).isNullOrEmpty()
    }.getOrDefault(false)

    override fun wipe(): WipeReport = wipe(deleteAccount = false)

    /** [deleteAccount]: also ask the server to delete the account (XEP-0077),
     *  after the keys are destroyed (opt-in, see WipeAndExit). */
    fun wipe(deleteAccount: Boolean): WipeReport = runCatching {
        val r = call("wipe", "delete_account" to deleteAccount) as JsonObject
        WipeReport(
            sessions = r["sessions"].asInt(), handshakes = r["handshakes"].asInt(),
            identityKeys = r["identity_keys"].asInt(), filesDestroyed = r["files_destroyed"].asInt(),
            filesUnlinkedOnly = r["files_unlinked_only"].asInt(),
            errors = (r["errors"] as? JsonArray).orEmpty().map { it.asStr() },
        )
    }.getOrDefault(WipeReport.UNREACHABLE)

    companion object {
        fun statusFrom(v: JsonElement): ConnectionStatus {
            val s = v as? JsonObject ?: return ConnectionStatus()
            val last = s["last"] as? JsonObject
            return ConnectionStatus(
                stage = s.str("stage").ifBlank { "idle" },
                connected = s["connected"].asBool(),
                jid = s.str("jid"), server = s.str("server"),
                isDefaultServer = s["is_default_server"].asBool(),
                sam = s.str("sam"),
                code = last?.str("code").orEmpty(), detail = last?.str("detail").orEmpty(),
                inputs = s.str("inputs_text"), workerAlive = s["worker_alive"].asBool(),
            )
        }

        /** The mapping of ChaquopyOtrCore.eventFrom, from JSON. */
        fun eventFrom(e: JsonObject): OtrEvent? {
            fun str(k: String) = e.str(k)
            fun int(k: String) = e[k].asInt()
            fun num(k: String) = e[k].asDouble()
            fun flag(k: String) = e[k].asBool()
            return when (str("type")) {
                "ConnectionStateChanged" -> OtrEvent.ConnectionChanged(
                    ConnectionState.entries.firstOrNull { it.name == str("state") }
                        ?: ConnectionState.DISCONNECTED)
                "SessionStateChanged" -> OtrEvent.SessionChanged(
                    str("peer"), SecurityState.fromLevel(int("security_level")))
                "MessageReceived" -> OtrEvent.MessageReceived(
                    str("peer"), str("body"), num("timestamp"),
                    messageId = str("message_id"), source = str("source").ifBlank { "live" },
                    replyTo = str("reply_to"))
                "MessageChanged" -> OtrEvent.MessageChanged(
                    str("peer"), str("action"), str("target_id"), str("body"),
                    (e["emojis"] as? kotlinx.serialization.json.JsonArray).orEmpty().map { it.asStr() },
                    flag("outgoing"), str("source"), str("sender"), str("sender_identity"))
                "RoomMessageAcked" -> OtrEvent.RoomMessageAcked(
                    str("peer"), str("message_id"), str("stanza_id"))
                "MessageSentElsewhere" -> OtrEvent.MessageSentElsewhere(
                    str("peer"), str("body"), num("timestamp"), str("message_id"), str("source"))
                "MessageDisplayed" -> OtrEvent.MessageDisplayed(str("peer"), str("message_id"))
                "ChatStateChanged" -> OtrEvent.ChatStateChanged(str("peer"), str("state"))
                "HistorySynced" -> OtrEvent.HistorySynced(int("count"))
                "RoomMessageReceived" -> OtrEvent.RoomMessageReceived(
                    str("peer"), str("sender"), str("body"), num("timestamp"),
                    encrypted = flag("encrypted"), senderIdentity = str("sender_identity"),
                    verified = flag("verified"), messageId = str("message_id"),
                    replyTo = str("reply_to"), source = str("source").ifBlank { "live" },
                    own = flag("own"))
                "GroupInvite" -> OtrEvent.GroupInvited(str("peer"), str("room"), flag("verified"))
                "GroupEntryRequested" ->
                    OtrEvent.GroupEntryRequested(str("peer"), str("requester"), flag("live"))
                "GroupChanged" -> OtrEvent.GroupChanged(
                    str("peer"), str("change"), e["epoch"].asLong(), str("detail"))
                "SmpProgress" -> OtrEvent.SmpProgressed(
                    str("peer"), SmpProgress(int("step"), int("total"), SmpState.fromName(str("state"))))
                "SmpResult" -> OtrEvent.SmpFinished(str("peer"), SmpState.fromName(str("state")))
                "FingerprintChanged" -> OtrEvent.FingerprintChanged(
                    str("peer"), str("stored_fingerprint"), str("received_fingerprint"))
                "MessageDelivered" -> OtrEvent.MessageDelivered(str("peer"), str("message_id"))
                "CallStateChanged" -> OtrEvent.CallChanged(
                    str("peer"), CallState.fromName(str("state")), int("duration_seconds"))
                "SubscriptionRequested" -> OtrEvent.SubscriptionRequested(
                    str("peer"), SubscriptionPolicy.of(str("policy")))
                "OtrCapabilityChanged" -> OtrEvent.CapabilityChanged(str("peer"), str("state"))
                "QueuedSent" -> OtrEvent.QueuedSent(str("peer"), int("count"), flag("encrypted"))
                "FileTransferChanged" -> OtrEvent.FileTransferChanged(
                    str("peer"), str("transfer_id"), str("filename"), e["size"].asLong(),
                    flag("outgoing"), str("state"), str("reason"))
                "VoiceNoteReceived" -> OtrEvent.VoiceNoteReceived(
                    str("peer"), str("transfer_id"), str("path"), str("sender"))
                "ErrorOccurred" -> OtrEvent.Failed(str("peer").ifBlank { null }, str("code"))
                else -> null
            }
        }
    }
}
