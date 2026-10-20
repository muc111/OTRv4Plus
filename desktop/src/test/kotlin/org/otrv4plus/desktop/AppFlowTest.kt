// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.jetbrains.skia.EncodedImageFormat
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.chat.SendState
import java.io.File
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The desktop app against a scripted engine: sign in, receive, send, and the
 * boundary rules -- the password crosses once, inside "connect", and nothing
 * the GUI sends is a key. Also renders the screens to PNG (build/screens/)
 * so the design can be looked at without a display.
 */
class AppFlowTest {

    private val me = "alice@otrv4plus.i2p"
    private val bob = "bob@otrv4plus.i2p"
    @Volatile private var connected = false
    private val sent = mutableListOf<String>()

    private fun status(): JsonElement = Json.parseToJsonElement(
        """{"stage":"${if (connected) "connected" else "idle"}","connected":$connected,
            "jid":"$me","server":"otrv4plus.i2p","sam":"127.0.0.1:7656",
            "last":{"code":"${if (connected) "ok" else ""}","detail":""},"worker_alive":$connected}""")

    private val contacts = Json.parseToJsonElement("""[
        {"jid":"$bob","display_name":"Bob","presence":"online","security":3,"smp":"VERIFIED",
         "call_available":true,"subscription":"both","pending":false},
        {"jid":"carol@otrv4plus.i2p","display_name":"Carol","presence":"online","security":1,
         "smp":"NOT_VERIFIED","call_available":false,"subscription":"both","pending":false},
        {"jid":"dave@otrv4plus.i2p","display_name":"Dave","presence":"offline","security":0,
         "smp":"NOT_VERIFIED","call_available":false,"subscription":"both","pending":false}]""")

    private fun answers(op: String, args: JsonObject): JsonElement? = when (op) {
        "prepare", "status" -> status()
        "connect" -> { connected = true; status() }
        "discover_services" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":[
            {"jid":"upload.otrv4plus.i2p","name":"","category":"store","type":"file"},
            {"jid":"conference.otrv4plus.i2p","name":"Rooms","category":"conference","type":"text"}]}""")
        "create_secure_group" -> { createdGroups += args["room"]!!.jsonPrimitive.content
            Json.parseToJsonElement("""{"ok":true,"code":"ok","detail":""}""") }
        "register" -> Json.parseToJsonElement("""{"ok":true,"stage":"idle","code":"ok","detail":"Account created."}""")
        "contacts" -> contacts
        "local_fingerprint" -> JsonPrimitive("6338F2F9 F00A1ED0")
        "handshake_status" -> Json.parseToJsonElement("""{"stage":"idle"}""")
        "call_state" -> JsonPrimitive("IDLE")
        "call_gate" -> Json.parseToJsonElement("""{"gate":"available","reason":""}""")
        "transfers" -> Json.parseToJsonElement("[]")
        "secure_groups" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":["team@conference.otrv4plus.i2p"]}""")
        "otr_capability", "ensure_otr" -> JsonPrimitive("available")
        "send_user_text" -> { sent += args["body"]!!.jsonPrimitive.content; JsonPrimitive("encrypted") }
        "avatar_index" -> Json.parseToJsonElement("""["$bob\t4f2a9c0e1b7d3a5f6e8c9b0a1d2e3f4a5b6c7d8e"]""")
        "avatar_pixels" -> if (args["jid"]!!.jsonPrimitive.content == bob) Json.parseToJsonElement(
            """{"id":"4f2a9c0e1b7d3a5f6e8c9b0a1d2e3f4a5b6c7d8e","width":48,"height":48,"rgba_b64":"${pixels()}"}""") else JsonNull
        "profile_fields" -> Json.parseToJsonElement(
            """["FN\tName\t80\t0","NICKNAME\tNickname\t40\t0","NOTE\tAbout\t500\t1","URL\tWebsite\t200\t0"]""")
        "profile_get_json" -> {
            val who = args["jid"]?.jsonPrimitive?.content.orEmpty()
            val v = if (who.isBlank()) """{\"FN\":\"Alice\",\"NOTE\":\"Qubes, otr-chat\"}"""
                    else """{\"FN\":\"Bob\",\"NICKNAME\":\"bob\",\"NOTE\":\"Pixel 7, verified in person\"}"""
            Json.parseToJsonElement("""{"ok":true,"code":"ok","detail":"","value":"$v"}""")
        }
        "group_verify_state" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":
            {"members":{"$bob":"verified","carol@otrv4plus.i2p":"running"},"all_verified":false,
             "started_by":"","active":true,"done":1,"total":2,"eta":42,"excluded":[]}}""")
        "group_call_state" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":
            {"in_call":false,"paused":false,"participants":[],"ringing_from":""}}""")
        "group_members" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":[
            {"jid":"$me","fingerprint":"AA","me":true,"verified":true,"bound":true},
            {"jid":"$bob","fingerprint":"BB","me":false,"verified":true,"bound":true},
            {"jid":"carol@otrv4plus.i2p","fingerprint":"CC","me":false,"verified":false,"bound":true}]}""")
        "answer_call" -> { answered += args["peer"]!!.jsonPrimitive.content; JsonPrimitive("started") }
        "voice_note_play_status" -> Json.parseToJsonElement("""{"playing":true,"position":0.8,"seconds":2.0}""")
        "voice_note_waveform" -> Json.parseToJsonElement(
            """{"bars":[${(0 until 48).joinToString(",") { "%.2f".format(java.util.Locale.ROOT, 0.2 + 0.8 * Math.abs(Math.sin(it / 4.0))) }}],"seconds":2.0}""")
        "voice_note_play" -> { played += args["path"]!!.jsonPrimitive.content
            Json.parseToJsonElement("""{"seconds":2.0}""") }
        "start_group_verify" -> { verifyPassphrases += args["passphrase"]!!.jsonPrimitive.content
            Json.parseToJsonElement("""{"ok":true,"code":"ok","detail":""}""") }
        else -> null
    }

    private val verifyPassphrases = mutableListOf<String>()
    private val played = java.util.concurrent.CopyOnWriteArrayList<String>()
    private val answered = java.util.concurrent.CopyOnWriteArrayList<String>()

    /** Owner, 2026-10-20: a call from the phone "not going through" -- the
     *  desktop rang only inside the caller's own chat. It now shows on any
     *  screen, and Answer opens that chat and answers. */
    @Test
    fun anIncomingCallCanBeAnsweredFromAnyScreen() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui),
                             Notifier({ "7" }, available = false, play = {}))
        model.jid = me
        host.ready()
        model.start()
        waitFor("connect screen") { model.screen == AppModel.Screen.CONNECT }
        model.connect("pw")
        waitFor("main screen") { model.screen == AppModel.Screen.MAIN }
        model.open("carol@otrv4plus.i2p")              // another chat is open
        host.event("""{"type":"CallStateChanged","peer":"$bob/phone","state":"RINGING","duration_seconds":0}""")
        waitFor("ringing") { model.chat.ringingPeers() == listOf(bob) }
        Thread.sleep(400)
        render(model, "10-incoming-call")
        model.answerFromPrompt(bob)
        waitFor("answered") { answered.isNotEmpty() }
        assertEquals(listOf(bob), answered)
        assertEquals(bob, model.openConversation)
    }

    /** Owner, 2026-10-20: a voice note is taken without asking and is a
     *  message that plays, not a file to accept. */
    @Test
    fun aReceivedVoiceNoteIsABubbleThatPlays() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui),
                             Notifier({ "7" }, available = false, play = {}))
        model.jid = me
        host.ready()
        model.start()
        waitFor("connect screen") { model.screen == AppModel.Screen.CONNECT }
        model.connect("pw")
        waitFor("main screen") { model.screen == AppModel.Screen.MAIN }
        host.event("""{"type":"FileTransferChanged","peer":"$bob/desk","transfer_id":"t9","filename":"voice-note-ab.ogg","size":9000,"outgoing":false,"state":"offered","reason":""}""")
        host.event("""{"type":"VoiceNoteReceived","peer":"$bob/desk","transfer_id":"t9","path":"/state/voice-note-ab.ogg.otrv","sender":""}""")
        waitFor("voice note") { model.messages(bob).any { it.voicePath.isNotEmpty() } }
        assertTrue(model.chat.pendingFileOffers.isEmpty(), "a voice note was offered as a file")
        val note = model.messages(bob).single { it.voicePath.isNotEmpty() }
        model.open(bob)
        Thread.sleep(500)
        render(model, "8-voice-note")
        waitFor("waveform") { model.waveforms[note.voicePath]?.bars?.size == 48 }
        model.playVoiceNote(note.voicePath)
        waitFor("played") { played.isNotEmpty() }
        assertEquals(listOf("/state/voice-note-ab.ogg.otrv"), played)
        assertEquals(note.voicePath, model.playingNote)
        // The bubble follows the engine's player: 0.8 s of 2 s is 19 of 48 bars.
        waitFor("position") { model.playPosition > 0.0 }
        assertEquals(19, org.otrv4plus.android.chat.VoiceNotes.playedBars(model.playPosition, 2.0, 48))
        render(model, "9-voice-note-playing")
        model.stopPlaying()
        assertEquals(null, model.playingNote)
    }
    private val createdGroups = java.util.concurrent.CopyOnWriteArrayList<String>()

    /** Owner, 2026-10-20: a group's name alone, not room@conference.server. */
    @Test
    fun aGroupNameAloneGetsTheServersRoomsService() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui),
                             Notifier({ "7" }, available = false, play = {}))
        model.jid = "alice"
        host.ready()
        model.start()
        waitFor("connect screen") { model.screen == AppModel.Screen.CONNECT }
        model.connect("pw")
        waitFor("main screen") { model.screen == AppModel.Screen.MAIN }
        model.createSecureGroup("Team2")
        waitFor("group created") { createdGroups.isNotEmpty() }
        assertEquals(listOf("team2@conference.otrv4plus.i2p"), createdGroups)
        assertEquals("conference.otrv4plus.i2p", model.roomService)
        // A full address is used as typed.
        model.createSecureGroup("other@rooms.elsewhere.i2p")
        waitFor("second group") { createdGroups.size == 2 }
        assertEquals("other@rooms.elsewhere.i2p", createdGroups[1])
    }

    /** A 48x48 purple gradient as RGBA, base64: what the engine's decoder hands over. */
    private fun pixels(): String {
        val b = ByteArray(48 * 48 * 4)
        for (y in 0 until 48) for (x in 0 until 48) {
            val i = (y * 48 + x) * 4
            b[i] = (90 + x * 2).toByte(); b[i + 1] = (50 + y).toByte(); b[i + 2] = (180 + y).toByte(); b[i + 3] = 255.toByte()
        }
        return java.util.Base64.getEncoder().encodeToString(b)
    }

    private fun waitFor(what: String, timeoutMs: Long = 10_000, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + timeoutMs
        while (!cond()) {
            check(System.currentTimeMillis() < end) { "timed out waiting for $what" }
            Thread.sleep(25)
        }
    }

    private fun render(model: AppModel, name: String, w: Int = 1180, h: Int = 760) {
        val scene = ImageComposeScene(w, h, Density(1f)) { App(model, onWipe = {}) }
        try {
            scene.render(0)
            val image = scene.render(500_000_000)
            val data = image.encodeToData(EncodedImageFormat.PNG) ?: return
            val dir = File("build/screens").apply { mkdirs() }
            File(dir, "$name.png").writeBytes(data.bytes)
            image.encodeToData(EncodedImageFormat.JPEG, 55)?.let { File(dir, "$name.jpg").writeBytes(it.bytes) }
        } finally {
            scene.close()
        }
    }

    /** Owner, 2026-10-20: create an account from the start screen with a
     *  username alone, and be signed in once it is made. */
    @Test
    fun createAccountWithAUsernameThenSignInStraightAway() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui),
                             Notifier({ "7" }, available = false, play = {}))
        host.ready()
        model.start()
        waitFor("connect screen") { model.screen == AppModel.Screen.CONNECT }
        model.jid = "carol"
        assertEquals("carol@otrv4plus.i2p", model.account)

        model.register("a new password")
        waitFor("signed in") { model.screen == AppModel.Screen.MAIN }
        assertEquals(true, model.registration?.ok)

        val ops = host.requests.map { it["op"]!!.jsonPrimitive.content }
        assertTrue(ops.indexOf("register") in 0 until ops.indexOf("connect"), ops.toString())
        // The account the engine was given is the full address.
        val prepare = host.requests.first { it["op"]!!.jsonPrimitive.content == "prepare" }
        assertTrue(prepare.toString().contains("carol@otrv4plus.i2p"), prepare.toString())
        // The password crossed for register and for connect, and nowhere else.
        val withPassword = host.requests.filter { it.toString().contains("a new password") }
        assertEquals(listOf("register", "connect"), withPassword.map { it["op"]!!.jsonPrimitive.content })
    }

    @Test
    fun signInReceiveAndSend() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val notes = mutableListOf<String>()
        val notifier = Notifier({ args -> notes += args.last(); "7" }, available = true, play = {})
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui), notifier)
        model.jid = me
        host.ready()
        model.start()
        waitFor("connect screen") { model.screen == AppModel.Screen.CONNECT }
        render(model, "1-connect")

        model.connect("correct horse battery staple")
        waitFor("main screen") { model.screen == AppModel.Screen.MAIN }
        waitFor("roster") { model.conversations().any { it.jid == bob } }

        host.event("""{"type":"MessageReceived","peer":"$bob/desk","body":"Hi Alice — call later? Verified both ends.","timestamp":${System.currentTimeMillis() / 1000.0}}""")
        waitFor("message") { model.messages(bob).isNotEmpty() }
        // The window was not in front: one notification, with no sender and no text.
        waitFor("notification") { notes.isNotEmpty() }
        assertEquals(listOf("New message"), notes)
        waitFor("avatar") { model.avatar(bob) != null }
        model.open(bob)
        model.setDraft(bob, "Yes, after 6. The new build runs in a qube with no network.")
        model.send(bob)
        waitFor("sent") { model.messages(bob).any { it.outgoing && it.sendState != SendState.SENDING } }
        assertEquals(listOf("Yes, after 6. The new build runs in a qube with no network."), sent)
        assertEquals(SecurityState.SMP_VERIFIED, model.conversation(bob).security)
        Thread.sleep(700)
        render(model, "2-chat")

        model.open("carol@otrv4plus.i2p")
        Thread.sleep(700)
        render(model, "3-unverified")
        model.tab = AppModel.Tab.PEOPLE
        render(model, "4-people")
        model.tab = AppModel.Tab.SETTINGS
        model.loadProfile()   // the Settings screen does this when first drawn
        waitFor("own profile") { model.profile["FN"] == "Alice" }
        Thread.sleep(300)
        render(model, "5-settings", h = 1100)

        // A contact's profile, read-only.
        model.tab = AppModel.Tab.CHATS
        model.open(bob)
        model.viewProfile(bob)
        waitFor("bob's profile") { model.viewing?.first == bob }
        render(model, "7-profile")
        model.closeProfile()

        // A secure group: verification in progress, members, Call offered.
        val team = "team@conference.otrv4plus.i2p"
        model.chat.noteRoom(team)
        waitFor("secure group known") { model.chat.isSecureRoom(team) }
        model.open(team)
        model.refreshGroupNow(team)
        waitFor("group state") { model.groupVerify(team).total == 2 && model.groupMembers[team]?.size == 3 }
        Thread.sleep(400)
        render(model, "6-group")
        model.startGroupVerify(team, "our group phrase")
        waitFor("verify sent") { verifyPassphrases.isNotEmpty() }
        assertEquals(listOf("our group phrase"), verifyPassphrases)

        // A group call rings: notified whatever the focus, with nothing but the word.
        host.event("""{"type":"GroupChanged","peer":"$team","change":"call_ringing","epoch":3,"detail":"$bob"}""")
        waitFor("call notification") { notes.size == 2 }
        assertEquals("Incoming call", notes.last())
        assertTrue(notes.none { it.contains("bob") || it.contains("Hi Alice") }, notes.toString())

        // The boundary: the password crossed exactly once, in "connect", and
        // was the only argument there; "prepare" carried no secret.
        val withPassword = host.requests.filter { it.toString().contains("correct horse") }
        assertEquals(listOf("connect"), withPassword.map { it["op"]!!.jsonPrimitive.content })
        val ops = host.requests.map { it["op"]!!.jsonPrimitive.content }
        assertTrue(ops.indexOf("prepare") < ops.indexOf("connect"), "prepare must precede connect")
        // Nothing the GUI asks for is key material: every op is one the host
        // lists (desktop_bridge/host.py) -- checked from Python too.
        assertTrue(ops.none { it.contains("key") || it.contains("secret") }, ops.toString())
        ui.close()
    }
}
