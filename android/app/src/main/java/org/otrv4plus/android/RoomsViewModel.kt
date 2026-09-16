// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.DiscoveredService
import org.otrv4plus.android.bridge.RoomOutcome
import org.otrv4plus.android.bridge.RoomStanding
import org.otrv4plus.android.bridge.RoomSummary

/**
 * Rooms: finding the service, listing what it advertises, and being in one.
 *
 * WHY THE SERVICE IS DISCOVERED RATHER THAN ASSUMED. A MUC service is
 * conventionally `conference.<domain>`, and conventionally it is not —
 * `rooms.`, `muc.` and `chat.` are all in use. Guessing costs an I2P round
 * trip to find out you guessed wrong, so the app asks: XEP-0030 disco#items on
 * the server, then disco#info on each result, looking for the `conference`/
 * `text` identity XEP-0045 defines.
 *
 * WHAT THIS DOES NOT CLAIM. A room is not encrypted and nothing here should be
 * read as suggesting otherwise. OTRv4+ is a two-party protocol; a MUC message
 * is fanned out by the service to everybody present, so a room is plaintext to
 * the server hosting it. The screen says so, once, plainly, rather than
 * leaving it to be inferred from the absence of a padlock.
 *
 * Every call blocks on an I2P round trip and runs on [Dispatchers.IO]. A
 * blocking Chaquopy call on the main thread is an ANR, not a slow screen.
 */
class RoomsViewModel : ViewModel() {

    /**
     * The core, handed over by the Activity once the service has bound.
     *
     * Snapshot state, not a plain `var`. There is a window between this screen
     * being composed and the service binding, and a plain field would not
     * recompose when it closed — so a screen opened during that window would
     * call [discover] against a null core, give up silently, and never try
     * again. The screen keys its one-shot effect on this.
     */
    var core by mutableStateOf<ChaquopyOtrCore?>(null)

    /** Everything the server hosts, once discovery has run. */
    val services = mutableStateListOf<DiscoveredService>()

    /** The MUC service, once one has been identified. Null until then. */
    var roomService by mutableStateOf<String?>(null)
        private set

    /** What [roomService] advertises. Public rooms only, by design. */
    val rooms = mutableStateListOf<RoomSummary>()

    /** The rooms this session is in, and what we are in each. */
    val joined = mutableStateMapOf<String, RoomStanding>()

    /** Non-null while something long-running is in flight; the UI's label. */
    var busy by mutableStateOf<String?>(null)
        private set

    /** The last thing that happened, for the screen to render. */
    var last by mutableStateOf<RoomOutcome?>(null)
        private set

    /**
     * True once discovery has run, whatever it found.
     *
     * Distinct from `services.isEmpty()`: "we have not asked" and "we asked
     * and this server hosts nothing" are different things to put on a screen,
     * and the second one is a finding.
     */
    var discovered by mutableStateOf(false)
        private set

    /** Find the rooms service. Safe to call more than once. */
    fun discover() {
        val c = core ?: return
        if (busy != null) return
        busy = "Looking for a rooms service..."
        last = null
        viewModelScope.launch {
            val (outcome, found) = withContext(Dispatchers.IO) {
                c.discoverServices()
            }
            services.clear()
            services.addAll(found)
            // The FIRST conference/text identity. A server with two is
            // unusual; picking one and saying which beats refusing to choose
            // and showing a list of components nobody can interpret.
            roomService = found.firstOrNull { it.hostsRooms }?.jid
            discovered = true
            last = outcome
            busy = null
            roomService?.let { refreshRooms(it) }
        }
    }

    /** List what a service advertises. */
    fun refreshRooms(service: String) {
        val c = core ?: return
        if (busy != null) return
        busy = "Listing rooms..."
        viewModelScope.launch {
            val (outcome, found) = withContext(Dispatchers.IO) {
                c.discoverRooms(service)
            }
            rooms.clear()
            rooms.addAll(found)
            last = outcome
            busy = null
        }
    }

    fun join(room: String, nick: String, password: String = "") =
        enter("Joining...", room) { c -> c.joinRoom(room, nick, password) }

    fun create(room: String, nick: String) =
        enter("Creating the room...", room) { c -> c.createRoom(room, nick) }

    private fun enter(
        label: String,
        room: String,
        call: (ChaquopyOtrCore) -> Pair<RoomOutcome, RoomStanding>,
    ) {
        val c = core ?: return
        if (busy != null) return
        busy = label
        last = null
        viewModelScope.launch {
            val (outcome, standing) = withContext(Dispatchers.IO) { call(c) }
            // Recorded ONLY on success. A failed join leaves the user outside
            // the room, and an entry here would put it in the "you are in
            // these" list with no privileges — which reads as a room that is
            // broken rather than one that was refused.
            if (outcome.ok) joined[room] = standing
            last = outcome
            busy = null
        }
    }

    fun leave(room: String, nick: String) {
        val c = core ?: return
        if (busy != null) return
        busy = "Leaving..."
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) { c.leaveRoom(room, nick) }
            // Removed whatever the service said. Leaving is unavailable
            // presence, not a request that can be refused, and a room left in
            // the list after a failed leave is one the user cannot get out of.
            joined.remove(room)
            last = outcome
            busy = null
        }
    }

    /**
     * Delete a room for everybody in it.
     *
     * OWNERS ONLY, and the service is what enforces that. The screen offers
     * this only when [RoomStanding.destroy] says so, which comes from
     * `otrv4plus_muc.privileges`; this does not check again, because a
     * client-side permission check that disagreed with the service would be a
     * second opinion in a place with no way to be right.
     */
    fun destroy(room: String, reason: String = "") {
        val c = core ?: return
        if (busy != null) return
        busy = "Deleting the room..."
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                c.destroyRoom(room, reason)
            }
            if (outcome.ok) joined.remove(room)
            last = outcome
            busy = null
        }
    }

    /** Dismiss the last result. */
    fun clearLast() {
        last = null
    }
}
