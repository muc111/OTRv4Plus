// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.otrv4plus.desktop.engine.DesktopCore
import org.otrv4plus.desktop.engine.Engine
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A stand-in for `desktop_bridge/host.py`: speaks the same JSON lines and
 * answers each op from [answers]. Records every request, so a test can see
 * exactly what crossed the boundary (and what did not).
 */
class FakeHost(private val answers: (String, JsonObject) -> JsonElement?) {
    val requests = CopyOnWriteArrayList<JsonObject>()
    private val toEngine = PipedOutputStream()
    private val engineIn = PipedInputStream(toEngine, 1 shl 20)
    private val fromEngine = PipedInputStream(1 shl 20)
    private val engineOut = PipedOutputStream(fromEngine)
    lateinit var core: DesktopCore
    val engine: Engine = Engine(engineIn, engineOut, onEvent = { core.deliver(it) })

    init {
        core = DesktopCore(engine)
        Thread({
            val reader = fromEngine.bufferedReader()
            while (true) {
                val line = runCatching { reader.readLine() }.getOrNull() ?: break
                val req = Json.parseToJsonElement(line).jsonObject
                requests += req
                val id = req["id"]!!.jsonPrimitive.content.toLong()
                val op = req["op"]!!.jsonPrimitive.content
                val args = req["args"]?.jsonObject ?: JsonObject(emptyMap())
                val result = runCatching { answers(op, args) }
                send(if (result.isSuccess && result.getOrNull() != null)
                    buildJsonObject { put("id", id); put("ok", true); put("result", result.getOrNull()!!) }
                else buildJsonObject { put("id", id); put("ok", false); put("error", "unknown_op") })
            }
        }, "fake-host").apply { isDaemon = true }.start()
    }

    fun send(obj: JsonObject) = synchronized(toEngine) {
        toEngine.write((obj.toString() + "\n").toByteArray())
        toEngine.flush()
    }

    fun ready(fingerprint: String = "6338F2F9 F00A1ED0 F1E396A8 ABF95191 DF652508 F14A2FF8 8C53530C 2067E7DB") =
        send(buildJsonObject { put("ready", buildJsonObject { put("fingerprint", fingerprint); put("python", "3.13") }) })

    fun event(json: String) = send(buildJsonObject { put("event", Json.parseToJsonElement(json)) })
}
