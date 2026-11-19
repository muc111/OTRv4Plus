// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import com.chaquo.python.PyObject

// Reading the dictionaries the Python bridge answers with, and the handles
// every Chaquopy* part shares. Split out of ChaquopyOtrCore.

/**
 * The engine's `OtrApp` and the connection controller, owned by
 * [ChaquopyOtrCore] and shared with the parts it delegates to
 * ([ChaquopyGroups], [ChaquopyAccountAdmin], [ChaquopyMedia]).
 */
internal class BridgeHandles {
    /** The engine's `OtrApp`; null before initialisation and after shutdown. */
    @Volatile
    var app: PyObject? = null

    /** The connection controller; null until a connection is prepared. */
    @Volatile
    var controller: PyObject? = null

    fun requireApp(): PyObject =
        app ?: throw OtrBridgeException("not_initialized")

    /**
     * A controller call that answers rather than throws.
     *
     * WRAPPED, and it was not. This returned `controller?.callAttr(...)` bare,
     * so anything the Python side raised -- a `TransportError` from a room
     * join, a malformed JID, a timeout -- crossed Chaquopy as a PyException
     * and propagated out of `createRoom` into `RoomsViewModel`'s coroutine.
     * That coroutine had no `finally`, so `busy` was never cleared and the
     * Rooms screen sat on "Creating the room..." for good.
     *
     * The roster calls have answered this way since `addContact` was fixed
     * for the same reason; the room calls were the ones still throwing.
     * Returning null means "no answer", which every caller here already
     * handles as `notPrepared()`.
     *
     * The exception TYPE is not propagated and its message is never read: a
     * PyException carries the engine's own text, which can quote what it was
     * handling. The caller's own `RoomOutcome` carries the reportable code,
     * which Python wrote for a person.
     */
    fun call(name: String, vararg args: Any): PyObject? =
        try {
            controller?.callAttr(name, *args)
        } catch (t: Throwable) {
            null
        }

    fun roomWithStanding(name: String, vararg args: Any):
        Pair<RoomOutcome, RoomStanding> {
        val result = call(name, *args) ?: return notPrepared() to RoomStanding()
        val value = result.callAttr("get", "value")
        val standing = if (value == null) RoomStanding() else RoomStanding(
            room = entry(value, "room"),
            nick = entry(value, "nick"),
            affiliation = entry(value, "affiliation").ifBlank { "none" },
            role = entry(value, "role").ifBlank { "none" },
            speak = flag(value, "speak"),
            changeSubject = flag(value, "change_subject"),
            invite = flag(value, "invite"),
            kick = flag(value, "kick"),
            ban = flag(value, "ban"),
            configure = flag(value, "configure"),
            destroy = flag(value, "destroy"),
            grantMembership = flag(value, "grant_membership"),
        )
        return outcomeOf(result) to standing
    }
}

internal fun outcomeOf(result: PyObject): RoomOutcome = RoomOutcome(
    ok = result.callAttr("get", "ok")?.toBoolean() ?: false,
    code = result.callAttr("get", "code")?.toString()?.ifBlank { "unknown" }
        ?: "unknown",
    detail = result.callAttr("get", "detail")?.toString() ?: "",
)

internal fun listValue(result: PyObject): PyObject? =
    result.callAttr("get", "value")

internal fun entry(item: PyObject, key: String): String =
    runCatching { item.callAttr("get", key)?.toString() }.getOrNull()
        ?: ""

internal fun flag(item: PyObject, key: String): Boolean =
    runCatching { item.callAttr("get", key)?.toBoolean() }.getOrNull()
        ?: false

/**
 * No controller yet, which is not the same as a failure to do the thing.
 *
 * Reported as `network` because from the user's side it is the same
 * situation — nothing has connected — and it is the code the rooms screen
 * already knows how to render.
 */
internal fun notPrepared(): RoomOutcome = RoomOutcome(
    ok = false, code = "network",
    detail = "Connect before using rooms.")

internal fun jsonMap(text: String): Map<String, String> = runCatching {
    if (text.isBlank() || text == "None") return emptyMap()
    val obj = org.json.JSONObject(text)
    obj.keys().asSequence().associateWith { obj.optString(it, "") }
}.getOrDefault(emptyMap())
