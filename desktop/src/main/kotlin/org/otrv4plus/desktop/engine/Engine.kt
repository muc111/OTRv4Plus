// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop.engine

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import org.otrv4plus.android.bridge.OtrBridgeException
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.io.Writer
import java.nio.charset.StandardCharsets
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

/**
 * The engine process: `desktop_bridge/host.py`, the same Python and Rust the
 * Android app embeds, run as a child of this JVM and spoken to in JSON lines.
 *
 * THE SECURITY BOUNDARY IS THE PROCESS. This side never holds a key, a
 * ratchet, a session secret or a fingerprint it computed: it sends commands
 * and renders what comes back. The only secrets that cross are the ones a
 * person types -- the account password and an SMP secret -- and they go
 * straight out on the pipe; nothing here stores or logs them.
 *
 * Blocking by design ([call] waits for the answer), like ChaquopyOtrCore:
 * callers run it on Dispatchers.IO. Requests are answered out of order --
 * the host runs them on a pool, because a tunnel build takes minutes and
 * must not hold up a message -- so every request carries an id.
 */
class Engine(
    input: InputStream,
    output: OutputStream,
    private val onEvent: (JsonObject) -> Unit,
    private val onExit: (String) -> Unit = {},
) {
    private val writer: Writer = OutputStreamWriter(output, StandardCharsets.UTF_8)
    private val pending = ConcurrentHashMap<Long, CompletableFuture<JsonElement>>()
    private val ids = AtomicLong(0)
    private val ready = CompletableFuture<JsonObject>()
    @Volatile private var closed = false

    init {
        val reader = BufferedReader(InputStreamReader(input, StandardCharsets.UTF_8))
        Thread({ readLoop(reader) }, "otr-engine-reader").apply { isDaemon = true }.start()
    }

    private fun readLoop(reader: BufferedReader) {
        try {
            while (true) {
                val line = reader.readLine() ?: break
                if (line.length > MAX_LINE) continue
                val obj = runCatching { Json.parseToJsonElement(line) as JsonObject }
                    .getOrNull() ?: continue
                when {
                    "event" in obj -> (obj["event"] as? JsonObject)?.let { e ->
                        runCatching { onEvent(e) }
                    }
                    "ready" in obj -> ready.complete(obj["ready"] as? JsonObject ?: JsonObject(emptyMap()))
                    "fatal" in obj -> ready.completeExceptionally(
                        OtrBridgeException(obj.str("fatal").ifBlank { "engine_failed" }))
                    "id" in obj -> {
                        val id = (obj["id"] as? JsonPrimitive)?.longOrNull ?: continue
                        val future = pending.remove(id) ?: continue
                        if ((obj["ok"] as? JsonPrimitive)?.booleanOrNull == true) {
                            future.complete(obj["result"] ?: JsonNull)
                        } else {
                            future.completeExceptionally(
                                OtrBridgeException(obj.str("error").ifBlank { "bridge_error" }))
                        }
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            closed = true
            val gone = OtrBridgeException("engine_stopped")
            ready.completeExceptionally(gone)
            pending.values.forEach { it.completeExceptionally(gone) }
            pending.clear()
            onExit("engine_stopped")
        }
    }

    /** The engine's start-up report, once it has one. */
    fun awaitReady(timeoutSeconds: Long = 120): JsonObject = try {
        ready.get(timeoutSeconds, TimeUnit.SECONDS)
    } catch (e: java.util.concurrent.ExecutionException) {
        throw e.cause as? OtrBridgeException ?: OtrBridgeException("engine_failed")
    } catch (_: TimeoutException) {
        throw OtrBridgeException("engine_timeout")
    }

    /**
     * Run [op] with [args] and wait for the result. Throws
     * [OtrBridgeException] with the engine's CODE -- never a message.
     */
    fun call(op: String, args: Map<String, Any?> = emptyMap(),
             timeoutSeconds: Long = DEFAULT_TIMEOUT): JsonElement {
        if (closed) throw OtrBridgeException("engine_stopped")
        val id = ids.incrementAndGet()
        val future = CompletableFuture<JsonElement>()
        pending[id] = future
        val line = buildJsonObject {
            put("id", id)
            put("op", op)
            put("args", buildJsonObject {
                for ((k, v) in args) when (v) {
                    null -> put(k, JsonNull)
                    is String -> put(k, v)
                    is Boolean -> put(k, v)
                    is Number -> put(k, v)
                    is List<*> -> put(k, kotlinx.serialization.json.JsonArray(
                        v.map { kotlinx.serialization.json.JsonPrimitive(it?.toString() ?: "") }))
                    else -> put(k, v.toString())
                }
            })
        }.toString()
        try {
            synchronized(writer) {
                writer.write(line)
                writer.write("\n")
                writer.flush()
            }
        } catch (_: Exception) {
            pending.remove(id)
            throw OtrBridgeException("engine_stopped")
        }
        return try {
            future.get(timeoutSeconds, TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.ExecutionException) {
            throw e.cause as? OtrBridgeException ?: OtrBridgeException("bridge_error")
        } catch (_: TimeoutException) {
            pending.remove(id)
            throw OtrBridgeException("timeout")
        }
    }

    fun shutdown() {
        runCatching { call("shutdown", timeoutSeconds = 5) }
    }

    companion object {
        /** Long enough for a cold I2P tunnel; the host never takes longer. */
        const val DEFAULT_TIMEOUT = 600L
        const val MAX_LINE = 4 shl 20

        /**
         * Start the engine as a child process.
         *
         * [command] defaults to the packaged launcher, or `OTRV4PLUS_ENGINE`
         * (a whitespace-separated command) for development. stderr is
         * inherited: the engine's own diagnostics go to the terminal or the
         * journal, never into the protocol.
         */
        fun launch(
            onEvent: (JsonObject) -> Unit,
            onExit: (String) -> Unit = {},
            command: List<String> = defaultCommand(),
            workDir: java.io.File? = null,
        ): Pair<Engine, Process> {
            val process = ProcessBuilder(command)
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .apply { if (workDir != null) directory(workDir) }
                .start()
            return Engine(process.inputStream, process.outputStream, onEvent, onExit) to process
        }

        fun defaultCommand(): List<String> =
            System.getenv("OTRV4PLUS_ENGINE")?.trim()?.takeIf { it.isNotEmpty() }
                ?.split(Regex("\\s+"))
                ?: listOf("/usr/lib/otrv4plus/otrv4plus-engine")
    }
}

internal fun JsonObject.str(key: String): String =
    (this[key] as? JsonPrimitive)?.contentOrNull ?: ""

internal fun JsonElement?.asStr(): String =
    (this as? JsonPrimitive)?.contentOrNull ?: ""

internal fun JsonElement?.asBool(): Boolean =
    (this as? JsonPrimitive)?.booleanOrNull ?: false

internal fun JsonElement?.asLong(): Long =
    (this as? JsonPrimitive)?.let { it.longOrNull ?: it.contentOrNull?.toDoubleOrNull()?.toLong() } ?: 0L

internal fun JsonElement?.asDouble(): Double =
    (this as? JsonPrimitive)?.contentOrNull?.toDoubleOrNull() ?: 0.0

internal fun JsonElement?.asInt(): Int = asLong().toInt()

/** A Python bool: JSON true/false, or the string "True" from an older shape. */
internal fun JsonElement?.flag(): Boolean =
    asBool() || (this as? JsonPrimitive)?.contentOrNull == "True"

internal fun JsonElement?.jsonPrimitiveOrNull(): JsonPrimitive? =
    runCatching { this?.jsonPrimitive }.getOrNull()
