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
        "contacts" -> contacts
        "local_fingerprint" -> JsonPrimitive("6338F2F9 F00A1ED0")
        "handshake_status" -> Json.parseToJsonElement("""{"stage":"idle"}""")
        "call_state" -> JsonPrimitive("IDLE")
        "call_gate" -> Json.parseToJsonElement("""{"gate":"available","reason":""}""")
        "transfers" -> Json.parseToJsonElement("[]")
        "secure_groups" -> Json.parseToJsonElement("""{"ok":true,"code":"ok","value":["team@conference.otrv4plus.i2p"]}""")
        "otr_capability", "ensure_otr" -> JsonPrimitive("available")
        "send_user_text" -> { sent += args["body"]!!.jsonPrimitive.content; JsonPrimitive("encrypted") }
        else -> null
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
            image.encodeToData(EncodedImageFormat.JPEG, 82)?.let { File(dir, "$name.jpg").writeBytes(it.bytes) }
        } finally {
            scene.close()
        }
    }

    @Test
    fun signInReceiveAndSend() {
        val host = FakeHost(::answers)
        val ui = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val model = AppModel(host.core, CoroutineScope(SupervisorJob() + ui))
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
        render(model, "5-settings")

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
