// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.CallState
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.FileOutcome
import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.MetadataFinding
import org.otrv4plus.android.bridge.OtrBridgeException
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.crypto.CallUi
import org.otrv4plus.android.crypto.ConversationRef
import org.otrv4plus.android.crypto.EncryptionKind
import org.otrv4plus.android.crypto.EncryptionLauncher
import org.otrv4plus.android.crypto.MetadataChoice
import org.otrv4plus.android.crypto.MicPermission
import org.otrv4plus.android.crypto.MlsProvider
import org.otrv4plus.android.crypto.Omemo2Provider
import org.otrv4plus.android.crypto.OtrAvailability
import org.otrv4plus.android.crypto.OtrV4PlusProvider
import org.otrv4plus.android.crypto.SafeView
import org.otrv4plus.android.crypto.TransferUi
import org.otrv4plus.android.crypto.Verification

/**
 * The UI's window onto the conversation. It owns none of it.
 *
 * `OtrConnectionService` owns the [ChatState] and drains the engine's event
 * queue, because a drain is destructive and must keep running while no screen
 * exists. This class holds a reference, re-reads it on a timer so Compose
 * recomposes, and sends what the user types; clearing it changes nothing in
 * the conversation.
 *
 * No routing, presence, history or rules live here -- those are in
 * [ChatState], plain Kotlin with JVM tests.
 */
class ChatViewModel : ViewModel() {

    private var core: ChaquopyOtrCore? = null
    private var state: ChatState? = null
    private var pollJob: Job? = null

    /**
     * Redraw ticket.
     *
     * [ChatState] is deliberately not a Compose-observable type -- it must work
     * without Compose, in a service, and be unit-testable -- so the ViewModel
     * tells Compose when to look again.
     */
    private var revision by mutableStateOf(0)

    private fun observe() {
        @Suppress("UNUSED_EXPRESSION") revision
    }

    /** Whether the service has handed its state over yet. */
    val attached: Boolean get() { observe(); return state != null }

    // -- what the UI reads ----------------------------------------------------

    val connection: ConnectionStatus
        get() { observe(); return state?.connection ?: ConnectionStatus() }

    val droppedEvents: Int get() { observe(); return state?.droppedEvents ?: 0 }

    val link: ChatState.Link
        get() { observe(); return state?.link ?: ChatState.Link.UNKNOWN }

    val readFailure: String? get() { observe(); return state?.readFailure }

    val notice: String? get() { observe(); return state?.notice }

    val openConversation: String? get() { observe(); return state?.openConversation }

    val fingerprintAlert: OtrEvent.FingerprintChanged?
        get() { observe(); return state?.fingerprintAlert }

    fun conversations(): List<Conversation> {
        observe()
        return state?.conversations() ?: emptyList()
    }

    fun conversation(jid: String): Conversation {
        observe()
        return state?.conversation(jid) ?: Conversation(
            jid = jid, displayName = jid, presence = Presence.UNKNOWN,
            security = org.otrv4plus.android.bridge.SecurityState.PLAINTEXT,
            lastMessage = null, unread = 0,
        )
    }

    fun messages(jid: String): List<Message> {
        observe()
        return state?.messages(jid) ?: emptyList()
    }

    fun draft(jid: String): String { observe(); return state?.draft(jid) ?: "" }

    fun canSend(): Boolean { observe(); return state?.canSend() == true }

    // -- rooms ------------------------------------------------------------------

    /** Whether [jid] is a room: plaintext group chat, no OTR. See [ChatState.isRoom]. */
    fun isRoom(jid: String): Boolean { observe(); return state?.isRoom(jid) == true }

    /** Called when the Rooms screen opens [jid]: it is a room from now on. */
    fun noteRoom(jid: String) {
        state?.noteRoom(jid)
        revision++
    }

    /** Who is in each room, as last fetched. Empty until [refreshOccupants]. */
    private val occupants = mutableMapOf<String, List<org.otrv4plus.android.bridge.RoomOccupant>>()

    /** Whether the last occupant fetch failed, per room; shown, not hidden. */
    private val occupantsFailed = mutableSetOf<String>()

    fun occupants(jid: String): List<org.otrv4plus.android.bridge.RoomOccupant> {
        observe()
        return occupants[jid].orEmpty()
    }

    fun occupantsUnavailable(jid: String): Boolean { observe(); return jid in occupantsFailed }

    /** Whether the participant list is open, per room. Survives recreation. */
    private val occupantsShown = mutableSetOf<String>()

    fun occupantsShown(jid: String): Boolean { observe(); return jid in occupantsShown }

    fun toggleOccupants(jid: String) {
        if (!occupantsShown.remove(jid)) occupantsShown.add(jid)
        revision++
    }

    /** Ask the room who is in it. Over I2P this can take tens of seconds. */
    fun refreshOccupants(jid: String) {
        val c = core ?: return
        viewModelScope.launch {
            val (outcome, people) = withContext(Dispatchers.IO) {
                runCatching { c.roomOccupants(jid) }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "network", "") to emptyList())
            }
            if (outcome.ok) {
                occupants[jid] = people
                occupantsFailed.remove(jid)
            } else {
                occupantsFailed.add(jid)
            }
            revision++
        }
    }

    // -- secure groups (MLS) ----------------------------------------------------

    /** Whether [jid] is an OTRv4Plus secure group, as the engine reported. */
    fun isSecureRoom(jid: String): Boolean { observe(); return state?.isSecureRoom(jid) == true }
    fun isSyncingRoom(jid: String): Boolean { observe(); return state?.isSyncingRoom(jid) == true }
    fun isJoiningRoom(jid: String): Boolean { observe(); return state?.isJoiningRoom(jid) == true }

    /** A secure group's row badge (MLS), or null for any other row. */
    fun groupBadge(jid: String): RowSecurity.Badge? {
        if (!isSecureRoom(jid)) return null
        val (verified, total) = GroupText.verifiedCount(groupMembers(jid))
        return RowSecurity.group(isSyncingRoom(jid), verified, total)
    }

    /** "Encrypted Chat | 5/6 users verified". */
    fun groupSecurityLine(jid: String): String {
        val (verified, total) = GroupText.verifiedCount(groupMembers(jid))
        return GroupText.securityLine(verified, total)
    }

    /** Whether this group is small enough to call (see GroupText.MAX_CALL_MEMBERS). */
    fun groupCallAllowed(jid: String): Boolean = GroupText.callAllowed(groupMembers(jid).size)

    fun groupInvites(): List<OtrEvent.GroupInvited> {
        observe()
        return state?.pendingGroupInvites.orEmpty()
    }

    private val groupMembers = mutableMapOf<String, List<org.otrv4plus.android.bridge.GroupMember>>()

    fun groupMembers(jid: String): List<org.otrv4plus.android.bridge.GroupMember> {
        observe()
        return groupMembers[jid].orEmpty()
    }

    /** room -> who our earlier keys there wait for (F4). */
    private val groupKeysWaiting = mutableMapOf<String, List<String>>()

    fun groupKeysWaiting(jid: String): List<String> {
        observe()
        return groupKeysWaiting[jid].orEmpty()
    }

    private fun groupCall(label: String,
                          onOk: (org.otrv4plus.android.bridge.RoomOutcome) -> Unit = {},
                          onFail: (org.otrv4plus.android.bridge.RoomOutcome) -> Unit = {},
                          op: (ChaquopyOtrCore) -> org.otrv4plus.android.bridge.RoomOutcome) {
        val c = core ?: return
        val state = this.state ?: return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { op(c) }.getOrElse {
                    org.otrv4plus.android.bridge.RoomOutcome(false, "group_failed", "")
                }
            }
            if (outcome.ok) onOk(outcome) else onFail(outcome)
            GroupText.outcome(outcome.code)?.let { state.note("$label: $it") }
            revision++
        }
    }

    private var secureRoomsAt = 0L

    /** Which rooms are secure groups, from the engine; at most every 10 s. */
    private fun refreshSecureRooms() {
        val c = core ?: return
        val state = this.state ?: return
        val now = System.currentTimeMillis()
        if (now - secureRoomsAt < 10_000L) return
        secureRoomsAt = now
        viewModelScope.launch {
            val rooms = withContext(Dispatchers.IO) {
                runCatching { c.secureGroups() }.getOrNull()
            } ?: return@launch
            state.noteSecureRooms(rooms)
            // Each group's members: the "n/m users verified" in its line.
            rooms.forEach { refreshGroupMembers(it) }
            withContext(Dispatchers.IO) { runCatching { c.ownedRooms() }.getOrNull() }
                ?.let { state.noteOwnedRooms(it) }
            // An unanswered or failed question is "not an admin", never the
            // previous answer.
            val admin = withContext(Dispatchers.IO) {
                runCatching { c.serverAdmin() }.getOrNull()
            } == true
            state.noteServerAdmin(admin)
            serverAdminAnswer = admin
            otherSessions = withContext(Dispatchers.IO) {
                runCatching { c.otherSessions() }.getOrNull()
            } ?: 0
        }
        viewModelScope.launch {
            val (list, supported) = withContext(Dispatchers.IO) {
                runCatching { c.blockedContacts() }.getOrDefault(emptyList<String>() to false)
            }
            blocked = list.map { ChatState.bare(it) }.toSet()
            blockingSupported = supported
        }
    }

    // -- our account signed in elsewhere ---------------------------------------

    /** Other sessions of our own account, as the server reports them. */
    var otherSessions by mutableStateOf(0)
        private set

    /** The server's last answer to "is this account an admin?". */
    private var serverAdminAnswer by mutableStateOf(false)

    /**
     * Whether we administer the server: only then are moderation (bans) and
     * other people's sessions offered. Both the last answer AND the current
     * account's state must say so: the state is cleared whenever the account
     * changes, so an admin's answer cannot outlive their sign-in (owner,
     * 2026-10-24: ban tools showed on an account that was not an admin).
     */
    val isServerAdmin: Boolean
        get() = serverAdminAnswer && state?.serverAdmin == true

    var sessionsStatus by mutableStateOf<String?>(null)

    /** XEP-0133 end-user-session for every other session of ours. */
    fun endOtherSessions() {
        val c = core ?: return
        viewModelScope.launch {
            val (outcome, ended) = withContext(Dispatchers.IO) {
                runCatching { c.endOtherSessions() }.getOrElse {
                    org.otrv4plus.android.bridge.RoomOutcome(false, "failed", "") to 0
                }
            }
            sessionsStatus = AccountSessions.outcome(outcome.ok, outcome.code, ended)
            if (outcome.ok) otherSessions = 0
        }
    }

    // -- blocking (XEP-0191) and spam reports (XEP-0377) ------------------------

    /** Blocked on the server: nothing from them reaches any of our devices. */
    var blocked by mutableStateOf(emptySet<String>())
        private set
    var blockingSupported by mutableStateOf(false)
        private set
    var blockStatus by mutableStateOf<String?>(null)
        private set

    /** The conversation's ⋮ menu, and the block question (with its "also
     *  report as spam" box) while it is asked. Screen state, kept here with
     *  the rest so the screen holds nothing but passphrases. */
    var conversationMenu by mutableStateOf(false)
    var askBlock by mutableStateOf<String?>(null)
    var blockReport by mutableStateOf(false)

    fun isBlocked(jid: String): Boolean = ChatState.bare(jid) in blocked

    /** [report]: "spam", "abuse" or "" (block only). */
    fun block(jid: String, report: String = "") {
        val c = core ?: return
        viewModelScope.launch {
            val out = withContext(Dispatchers.IO) { runCatching { c.blockContact(jid, report) }.getOrNull() }
            if (out?.ok == true) {
                blocked = blocked + ChatState.bare(jid)
                blockStatus = if (report.isEmpty()) "Blocked." else "Blocked and reported."
            } else {
                blockStatus = out?.detail?.ifBlank { null } ?: "Could not block."
            }
        }
    }

    fun unblock(jid: String) {
        val c = core ?: return
        viewModelScope.launch {
            val out = withContext(Dispatchers.IO) { runCatching { c.unblockContact(jid) }.getOrNull() }
            if (out?.ok == true) {
                blocked = blocked - ChatState.bare(jid)
                blockStatus = "Unblocked."
            } else {
                blockStatus = out?.detail?.ifBlank { null } ?: "Could not unblock."
            }
        }
    }

    /** A password-protected group's room whose password the user must type
     *  (the inviter's did not come, or was refused). Null: no prompt. */
    var groupRoomPasswordFor by mutableStateOf<String?>(null)

    fun acceptGroupInvite(room: String, roomPassword: String = "") {
        state?.clearGroupInvite(room)
        groupRoomPasswordFor = null
        // A secure group being set up from this moment, never an ordinary room.
        groupCall("Joining $room", onOk = { state?.noteJoiningSecure(room) },
                  onFail = { if (it.code == "group_password_needed") groupRoomPasswordFor = room }) {
            it.acceptGroupInvite(room, roomPassword)
        }
    }

    fun declineGroupInvite(room: String) {
        state?.clearGroupInvite(room)
        groupCall("Declining") { it.declineGroupInvite(room) }
    }

    /** Each chat that needs the user, and what for (Attention.forChat). */
    fun attentionByChat(): Map<String, Attention.Kind> {
        val invited = groupInvites().mapTo(HashSet()) { it.room }
        val entries = entryRequests().mapTo(HashSet()) { it.room }
        return conversations().mapNotNull { c ->
            Attention.forChat(c, invited, entries)?.let { c.jid to it }
        }.toMap()
    }

    /** Somebody asked to join one of our groups ("X asks to join"). */
    fun entryRequests(): List<OtrEvent.GroupEntryRequested> {
        observe()
        return state?.pendingEntryRequests { room -> groupMembers(room).map { it.jid } }.orEmpty()
    }

    /** The creator's answer (owner, 2026-10-25). Accept: the ordinary
     *  OTRv4+ invitation to the address they gave. Deny: they wait 15
     *  minutes before asking again, doubling each time (the engine keeps
     *  the count). Later: hidden until the next sign-in. */
    fun answerEntryRequest(room: String, requester: String, invite: Boolean) {
        state?.clearEntryRequest(room, requester)
        revision++
        val c = core ?: return
        viewModelScope.launch {
            val (outcome, wait) = withContext(Dispatchers.IO) {
                runCatching { c.answerEntryRequest(room, requester, invite) }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "group_failed", "") to 0)
            }
            state?.note(when {
                !outcome.ok -> GroupText.outcome(outcome.code) ?: outcome.detail
                invite -> GroupText.outcome(outcome.code) ?: "Invitation sent to $requester over OTRv4+."
                else -> GroupText.entryDenied(requester, wait)
            })
            revision++
        }
    }

    /** The chat a "Make Chat Deniable?" question is open for, or null. */
    var askDeniable by mutableStateOf<String?>(null)

    /** L1: publish this session's MAC keys, end it, start a fresh one. */
    fun makeChatDeniable(jid: String) {
        askDeniable = null
        val c = core ?: return
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { c.makeChatDeniable(jid) }.getOrDefault("no_session")
            }
            state?.let { it.note(org.otrv4plus.android.crypto.DeniableChat.apply(result, it, jid)) }
            revision++
        }
    }

    fun laterEntryRequest(room: String, requester: String) {
        state?.clearEntryRequest(room, requester)
        revision++
    }

    fun inviteToGroup(room: String, peer: String) {
        // A user name alone ("bob") means a user on our own server.
        val typed = peer.trim()
        val domain = state?.account?.bareJid.orEmpty().substringAfter('@', "")
        val full = if ('@' !in typed && domain.isNotEmpty() && typed.isNotEmpty()) "$typed@$domain" else typed
        val jid = ChatState.bare(full)
        if (state?.validContact(jid) != true) {
            state?.note("Enter the address of a contact to invite.")
            revision++
            return
        }
        groupCall("Inviting $jid", onOk = {
            if (it.code == "ok") state?.note("Invitation sent to $jid over OTRv4+.")
        }) {
            it.inviteToGroup(room, jid)
        }
    }

    /** Online people who could be invited to [room] (see GroupInvitePicker). */
    fun groupInviteCandidates(room: String): List<GroupInvitePicker.Candidate> =
        GroupInvitePicker.candidates(directory, groupMembers(room).map { it.jid },
                                     state?.account?.bareJid.orEmpty())

    /** Invite every ticked person: one OTRv4+ invitation each, sent in turn. */
    fun inviteManyToGroup(room: String, jids: Collection<String>) {
        val c = core ?: return
        val list = jids.map { ChatState.bare(it) }.distinct()
        if (list.isEmpty()) return
        viewModelScope.launch {
            var sent = 0
            for (jid in list) {
                val outcome = withContext(Dispatchers.IO) {
                    runCatching { c.inviteToGroup(room, jid) }.getOrNull()
                }
                // Only "ok" was sent. "waiting_for_otr" / "waiting_for_contact"
                // are ok too, but nothing has gone yet: they used to be
                // counted as sent, so a stuck invitation read as delivered.
                val code = outcome?.code ?: "group_failed"
                if (outcome?.ok == true && code == "ok") sent++
                else GroupText.outcome(code)?.let { state?.note("Inviting $jid: $it") }
            }
            if (sent > 0) state?.note(GroupInvitePicker.sent(sent))
            revision++
        }
    }

    // ── group verification (the group passphrase) and group calls ───────────

    fun groupVerifyState(room: String): org.otrv4plus.android.bridge.GroupVerifyState {
        observe(); return state?.groupVerifyState(room) ?: org.otrv4plus.android.bridge.GroupVerifyState()
    }

    fun groupCallState(room: String): org.otrv4plus.android.bridge.GroupCallState {
        observe(); return state?.groupCallState(room) ?: org.otrv4plus.android.bridge.GroupCallState()
    }

    /** Re-read verification and call state for [room] (cheap: no network). */
    fun refreshGroupState(room: String) {
        val c = core ?: return
        viewModelScope.launch {
            val (v, k) = withContext(Dispatchers.IO) {
                runCatching { c.groupVerifyState(room) to c.groupCallState(room) }
                    .getOrNull()
            } ?: return@launch
            if (state?.noteGroupState(room, v, k) == true) revision++
        }
    }

    /** Verify every member with the group passphrase ("" = the one set at creation). */
    fun startGroupVerify(room: String, passphrase: String) {
        groupCall("Verifying $room", onOk = {
            state?.note("Verifying every member of $room with the group passphrase. " +
                "Each member is asked to type it.")
            refreshGroupState(room)
        }) { it.startGroupVerify(room, passphrase) }
    }

    fun setGroupCallAutoJoin(allowed: Boolean) {
        val c = core ?: return
        viewModelScope.launch(Dispatchers.IO) { runCatching { c.setGroupCallAutoJoin(allowed) } }
    }

    fun startGroupCall(room: String) {
        groupCall("Calling $room", onOk = { refreshGroupState(room) }) { it.startGroupCall(room) }
    }

    fun joinGroupCall(room: String) {
        groupCall("Joining the call in $room", onOk = { refreshGroupState(room) }) {
            it.joinGroupCall(room)
        }
    }

    fun pauseGroupCall(room: String) {
        groupCall("Pausing", onOk = { refreshGroupState(room) }) { it.pauseGroupCall() }
    }

    fun hangupGroupCall(room: String) {
        groupCall("Hanging up", onOk = { refreshGroupState(room) }) { it.hangupGroupCall() }
    }

    /** Group calls need verified members: send our key to each, say who needs SMP. */
    fun verifyGroupMembers(room: String) {
        val c = core ?: return
        val state = this.state ?: return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { c.verifyGroupMembers(room) }.getOrNull()
            } ?: return@launch
            state.note(if (outcome.ok) outcome.detail
                       else GroupText.outcome(outcome.code) ?: outcome.detail)
            refreshGroupMembers(room)
        }
    }

    /** F4: a new signing key here, and our earlier ones published. */
    fun makeGroupDeniable(room: String) {
        val c = core ?: return
        val state = this.state ?: return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { c.makeGroupDeniable(room) }.getOrElse {
                    org.otrv4plus.android.bridge.RoomOutcome(false, "group_failed", "")
                }
            }
            state.note(org.otrv4plus.android.crypto.GroupDeniable.apply(
                outcome.ok, outcome.code, state, room))
            refreshGroupMembers(room)
            revision++
        }
    }

    /** Forget the group's keys on this phone and leave its room. */
    fun leaveSecureGroup(room: String) {
        groupCall("Leaving $room") { it.leaveSecureGroup(room) }
    }

    /** Whether to offer "Delete group for everyone": we own its room. */
    fun canDeleteGroup(room: String): Boolean = state?.canDeleteRoom(room) == true

    /** Delete the group for everyone: its room goes, and every member's copy. */
    fun deleteSecureGroup(room: String) {
        groupCall("Deleting $room") { it.deleteSecureGroup(room) }
    }

    fun removeGroupMember(room: String, member: String) {
        groupCall("Removing $member", onOk = { refreshGroupMembers(room) }) {
            it.removeGroupMember(room, member)
        }
    }

    /** The creator removes everyone whose one verification attempt failed. */
    fun removeFailedGroupMembers(room: String) {
        groupCall("Removing who failed verification", onOk = { refreshGroupMembers(room) }) {
            it.removeFailedGroupMembers(room)
        }
    }

    fun refreshGroupMembers(room: String) {
        val c = core ?: return
        viewModelScope.launch {
            val (outcome, members) = withContext(Dispatchers.IO) {
                runCatching { c.groupMembers(room) }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "group_failed", "") to emptyList())
            }
            if (outcome.ok) groupMembers[room] = members
            groupKeysWaiting[room] = withContext(Dispatchers.IO) {
                runCatching { c.groupKeysWaiting(room) }.getOrDefault(emptyList())
            }
            revision++
        }
    }

    // -- wiring ---------------------------------------------------------------

    /**
     * Take the service's core and its conversation.
     *
     * Idempotent, and NOT a handover of ownership: the service keeps both. A
     * recomposition can call this and a recreated Activity will, so calling it
     * again with the same pair must do nothing beyond ensuring the redraw
     * timer is running.
     */
    fun attach(core: ChaquopyOtrCore, state: ChatState) {
        val same = this.core === core && this.state === state
        this.core = core
        this.state = state
        if (same && pollJob?.isActive == true) return
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (isActive) {
                // No work, just a redraw: the SERVICE reads Python. Doing it
                // here as well would be two drainers on one destructive queue.
                revision++
                autoSecure()
                markOpenDisplayed()
                refreshDiscovery()
                refreshWelcome()
                refreshHandshake()
                refreshSecureRooms()
                refreshAvatars()
                delay(REDRAW_INTERVAL_MS)
            }
        }
    }

    /**
     * For the release page's screenshots only: show [state] with no engine
     * behind it. CI draws the real screens from made-up conversations
     * (src/screens, built with -Pscreens) because the app sets FLAG_SECURE
     * and a phone cannot screenshot it. Without a core every action is a
     * no-op, so nothing can be sent from here.
     */
    fun attachForScreenshots(state: ChatState,
                             members: Map<String, List<org.otrv4plus.android.bridge.GroupMember>> = emptyMap()) {
        this.state = state
        groupMembers.putAll(members)
        revision++
    }

    // -- actions --------------------------------------------------------------

    fun setDraft(jid: String, text: String) {
        state?.setDraft(jid, text)
        revision++
        typing(jid, text.isNotBlank())
    }

    // -- typing, read markers (XEP-0085, XEP-0333) -----------------------------
    //
    // The bridge decides whether anything goes (only to a contact who already
    // sees our presence, only when switched on, at most every ten seconds);
    // this only says what the user is doing.

    private var pausedJob: kotlinx.coroutines.Job? = null

    private fun typing(jid: String, active: Boolean) {
        val core = this.core ?: return
        pausedJob?.cancel()
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { core.sendChatStateTo(jid, if (active) "composing" else "active") }
        }
        if (active) {
            pausedJob = viewModelScope.launch {
                delay(TYPING_PAUSE_MS)
                withContext(Dispatchers.IO) { runCatching { core.sendChatStateTo(jid, "paused") } }
            }
        }
    }

    /** Whether [jid] is typing ("typing..." under the name). */
    fun isTyping(jid: String): Boolean { observe(); return state?.isTyping(jid) ?: false }

    /** Settings: send "typing..." and read receipts. */
    var sendTyping by mutableStateOf(true)
        private set
    var sendReadReceipts by mutableStateOf(true)
        private set

    fun setPrivacy(typing: Boolean, readReceipts: Boolean) {
        sendTyping = typing
        sendReadReceipts = readReceipts
        val core = this.core ?: return
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { core.setPrivacy(typing, readReceipts) }
        }
    }

    /** The open conversation is on screen: a read marker for what arrived. */
    private fun markOpenDisplayed() {
        val core = this.core ?: return
        val state = this.state ?: return
        val open = state.openConversation ?: return
        if (!state.uiVisible) return
        viewModelScope.launch(Dispatchers.IO) { runCatching { core.markDisplayed(open) } }
    }

    fun open(jid: String) {
        state?.open(jid)
        revision++
        lastAutoAttempt.remove(ChatState.bare(jid))
        autoSecure()
    }

    // -- automatic OTRv4+ -------------------------------------------------------
    //
    // Contact -> resource -> capability -> OTRv4+. Only for the conversation
    // on screen, only when the transport has confirmed an OTRv4Plus-capable
    // resource (`OtrAvailability.mayStart`), and the bridge re-checks that
    // itself -- this merely asks. Throttled per peer so a DAKE that takes
    // twenty seconds over I2P is not restarted every redraw.

    private val lastAutoAttempt = HashMap<String, Long>()

    private fun autoSecure() {
        val state = this.state ?: return
        val core = this.core ?: return
        val jid = state.openConversation ?: return
        if (!state.canSend() || state.isRoom(jid)) return
        val c = state.conversation(jid)
        if (c.security != org.otrv4plus.android.bridge.SecurityState.PLAINTEXT) return
        if (!OtrAvailability.mayStart(c.otrCapability)) return
        val now = System.currentTimeMillis()
        if (now - (lastAutoAttempt[jid] ?: 0L) < AUTO_RETRY_MS) return
        lastAutoAttempt[jid] = now
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { core.ensureOtr(jid) }
        }
    }

    // -- the one list of people ------------------------------------------------

    /** Roster, requests and server-listed online users, one row each. */
    val directory: List<OnlineUsers.Entry>
        get() { observe(); return state?.directory() ?: emptyList() }

    /** Why the list shows only contacts, or null when the server listed users. */
    val discoveryNote: String?
        get() {
            observe()
            val s = state ?: return null
            return OnlineUsers.discoveryNote(s.welcome, s.discovery, s.canSend())
        }

    /** The open conversation's handshake, as last read. */
    private var handshake by mutableStateOf(
        org.otrv4plus.android.crypto.HandshakeUi.Status.IDLE)
    private var handshakeFor: String? = null
    private var lastHandshake = 0L

    /** The handshake status for [jid], or IDLE when it is not the one open. */
    fun handshake(jid: String): org.otrv4plus.android.crypto.HandshakeUi.Status {
        observe()
        return if (handshakeFor == ChatState.bare(jid)) handshake
               else org.otrv4plus.android.crypto.HandshakeUi.Status.IDLE
    }

    /**
     * Re-read the open conversation's handshake about once a second while it
     * is not encrypted. A local read of engine state; nothing is sent.
     */
    private fun refreshHandshake() {
        val state = this.state ?: return
        val core = this.core ?: return
        val jid = state.openConversation ?: run { handshakeFor = null; return }
        if (state.isRoom(jid)) return
        val now = System.currentTimeMillis()
        if (now - lastHandshake < HANDSHAKE_INTERVAL_MS) return
        lastHandshake = now
        viewModelScope.launch {
            val s = withContext(Dispatchers.IO) {
                runCatching { core.handshakeStatus(jid) }.getOrNull()
            } ?: return@launch
            handshake = s
            handshakeFor = ChatState.bare(jid)
            revision++
        }
    }

    /** Whether the server has no Welcome room, so creating one is offered. */
    val welcomeMissing: Boolean
        get() {
            observe()
            val s = state ?: return false
            return s.canSend() &&
                s.welcome.state == org.otrv4plus.android.bridge.WelcomeView.NOT_FOUND
        }

    /** Busy creating the Welcome room; the button is disabled meanwhile. */
    var creatingWelcome by mutableStateOf(false)
        private set

    /**
     * Create the OTRv4Plus Welcome room, after the user confirmed the
     * warning. Reports what the server would not apply, in words.
     */
    fun createWelcomeRoom() {
        val state = this.state ?: return
        val core = this.core ?: return
        if (creatingWelcome) return
        creatingWelcome = true
        viewModelScope.launch {
            val (outcome, missing) = withContext(Dispatchers.IO) {
                runCatching { core.createWelcomeRoom() }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "network", "") to emptyList())
            }
            creatingWelcome = false
            state.note(OnlineUsers.welcomeCreated(outcome.ok, outcome.code, outcome.detail, missing))
            lastWelcome = 0L
            refreshWelcome()
            revision++
        }
    }

    // ── avatars ──────────────────────────────────────────────────────────

    /**
     * Bare JID -> picture, built from PIXELS the bridge decoded
     * ([AvatarPixels]); no Android image decoder reads a peer's file.
     */
    // An immutable map swapped whole on a change: a display cache, not
    // conversation state (which ChatState owns).
    private var avatarBitmaps by mutableStateOf<Map<String, ImageBitmap>>(emptyMap())
    private val avatarShown = HashMap<String, String>()     // jid -> id drawn
    private var lastAvatars = 0L

    fun avatar(jid: String): ImageBitmap? =
        avatarBitmaps[ChatState.bare(jid)]

    /** What happened to the last "set profile picture", for the screen. */
    var avatarStatus: String? by mutableStateOf(null)

    private fun refreshAvatars() {
        val core = this.core ?: return
        val now = System.currentTimeMillis()
        if (now - lastAvatars < AVATAR_INTERVAL_MS) return
        lastAvatars = now
        viewModelScope.launch {
            val index = withContext(Dispatchers.IO) {
                runCatching { core.avatarIndex() }.getOrDefault(emptyMap())
            }
            // Gone from the bridge (removed, wiped, signed out): gone here.
            for (jid in avatarShown.keys.toList()) {
                if (jid !in index) {
                    avatarShown.remove(jid)
                    avatarBitmaps = avatarBitmaps - jid
                }
            }
            for ((jid, id) in index) {
                if (avatarShown[jid] == id) continue
                val bitmap = withContext(Dispatchers.Default) {
                    val image = runCatching { core.avatarImage(jid) }.getOrNull()
                        ?: return@withContext null
                    val argb = AvatarPixels.argb(image.rgba, image.width, image.height)
                        ?: return@withContext null
                    runCatching {
                        android.graphics.Bitmap.createBitmap(
                            argb, image.width, image.height,
                            android.graphics.Bitmap.Config.ARGB_8888,
                        ).asImageBitmap()
                    }.getOrNull()
                } ?: continue
                avatarShown[jid] = id
                avatarBitmaps = avatarBitmaps + (jid to bitmap)
            }
        }
    }

    /** Publish [png] (already scaled and re-encoded by the screen). */
    fun setOwnAvatar(png: ByteArray?) {
        val core = this.core ?: run { avatarStatus = "Connect first."; return }
        if (png == null) {
            avatarStatus = "That picture could not be used."
            return
        }
        avatarStatus = "Uploading your picture over I2P… this can take a minute or two."
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.setAvatar(png) }.getOrNull()
            }
            avatarStatus = when {
                outcome == null -> "Your picture could not be published."
                outcome.ok -> outcome.detail.ifBlank {
                    "Your picture is updated. Contacts see it when they next connect." }
                else -> outcome.detail.ifBlank { "Your picture could not be published." }
            }
            lastAvatars = 0L
        }
    }

    /** As [setOwnAvatar], with the picture made by [make] on a background
     *  thread: the PNG, or our own sentence saying why not (never an
     *  exception's text). */
    fun setOwnAvatarFrom(make: () -> Pair<ByteArray?, String>) {
        if (this.core == null) { avatarStatus = "Connect first."; return }
        avatarStatus = "Preparing your picture…"
        viewModelScope.launch {
            val (png, refusal) = withContext(Dispatchers.Default) {
                runCatching { make() }.getOrDefault(null to "That picture could not be used.")
            }
            if (png != null) setOwnAvatar(png)
            else avatarStatus = refusal.ifBlank { "That picture could not be used." }
        }
    }

    fun removeOwnAvatar() {
        val core = this.core ?: return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.removeAvatar() }.getOrNull()
            }
            avatarStatus = if (outcome?.ok == true) "Your picture is removed."
                           else "Your picture could not be removed."
            lastAvatars = 0L
        }
    }

    // ── the XMPP profile ─────────────────────────────────────────────────

    /** The fields the bridge defines; loaded with the first profile. */
    var profileFields: List<org.otrv4plus.android.bridge.ProfileField> by mutableStateOf(emptyList())
        private set

    /** The profile on screen: ours, or a contact's (read-only). */
    var profileValues: Map<String, String> by mutableStateOf(emptyMap())
        private set
    var profileJid: String by mutableStateOf("")
        private set
    var profileBusy by mutableStateOf(false)
        private set
    var profileStatus: String? by mutableStateOf(null)

    /** Load [jid]'s profile; blank means our own. */
    /** The identity shown on a contact's profile: the key from the OTRv4+
     *  session with them (ProfileIdentity), never from their vCard. */
    var profileIdentity by mutableStateOf<org.otrv4plus.android.bridge.SecurityDetails?>(null)
        private set
    /** Our own fingerprint, for our profile and for comparing side by side. */
    var ownFingerprint by mutableStateOf("")
        private set

    /** U1: signed out -- the identity shown on a profile goes with it. */
    fun forgetIdentity() {
        profileIdentity = null
        ownFingerprint = ""
    }

    fun loadIdentity(jid: String = "") {
        val c = core ?: return
        profileIdentity = null
        viewModelScope.launch {
            val (details, own) = withContext(Dispatchers.IO) {
                (if (jid.isEmpty()) null
                 else runCatching { c.securityDetails(jid) }.getOrNull()) to
                    runCatching { c.localFingerprint() }.getOrDefault("")
            }
            profileIdentity = details
            ownFingerprint = own
        }
    }

    /** Forget the contact's pinned keys; the next handshake pins afresh. */
    fun resetTrust(jid: String) {
        val c = core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { c.resetTrust(jid) } }
            loadIdentity(jid)
        }
    }

    /** "They match": record the session's key as confirmed by the user. */
    fun confirmFingerprint(jid: String) {
        val c = core ?: return
        val fp = profileIdentity?.peerFingerprint ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { c.trustPeer(jid, fp) } }
            loadIdentity(jid)
        }
    }

    // ── moderation (server admins only; the SERVER decides every use) ──────

    /** The shown profile's ban state, for a server admin; null otherwise. */
    var moderation by mutableStateOf<org.otrv4plus.android.bridge.Moderation?>(null)
        private set
    var moderationBusy by mutableStateOf(false)
        private set

    /** Read [jid]'s ban state. Asked only when this account is a server admin. */
    fun loadModeration(jid: String) {
        moderation = null
        val c = core ?: return
        if (!isServerAdmin || jid.isEmpty()) return
        moderationOp(c, "status", jid)
    }

    /** "ban" ([days] 0 = permanent) or "unban", then the state is read again. */
    fun moderate(jid: String, op: String, days: Int = 0) {
        val c = core ?: return
        if (!isServerAdmin || moderationBusy) return
        moderationOp(c, op, jid, days)
    }

    private fun moderationOp(c: org.otrv4plus.android.bridge.ChaquopyOtrCore,
                             op: String, jid: String, days: Int = 0) {
        moderationBusy = true
        viewModelScope.launch {
            try {
                val done = withContext(Dispatchers.IO) {
                    runCatching { c.moderate(op, jid, days) }.getOrNull()
                }
                moderation = if (done != null && done.outcome.ok && op != "status") {
                    val now = withContext(Dispatchers.IO) {
                        runCatching { c.moderate("status", jid) }.getOrNull()
                    }
                    now?.copy(said = done.said) ?: done
                } else done
            } finally {
                moderationBusy = false
            }
        }
    }

    fun loadProfile(jid: String = "") {
        val core = this.core ?: run { profileStatus = "Connect first."; return }
        profileJid = jid
        profileValues = emptyMap()
        profileBusy = true
        profileStatus = null
        viewModelScope.launch {
            val (fields, result) = withContext(Dispatchers.IO) {
                val f = if (profileFields.isEmpty())
                    runCatching { core.profileFields() }.getOrDefault(emptyList())
                    else profileFields
                f to runCatching { core.profileGet(jid) }.getOrNull()
            }
            if (fields.isNotEmpty()) profileFields = fields
            profileBusy = false
            if (profileJid != jid) return@launch       // another profile was opened
            if (result == null || !result.first.ok) {
                profileStatus = "The profile could not be read. " +
                    (result?.first?.code?.let { "($it)" } ?: "")
                return@launch
            }
            profileValues = result.second
            if (result.second.isEmpty()) profileStatus = ProfileText.empty(jid)
        }
    }

    /** Publish our profile. The bridge sanitises it and says what it kept. */
    fun saveProfile(values: Map<String, String>) {
        val core = this.core ?: run { profileStatus = "Connect first."; return }
        profileBusy = true
        profileStatus = "Saving…"
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { core.profileSet(values) }.getOrNull()
            }
            profileBusy = false
            if (result == null || !result.first.ok) {
                profileStatus = "Your profile could not be saved."
                return@launch
            }
            profileValues = result.second
            profileStatus = ProfileText.saved(values, result.second, profileFields)
        }
    }

    private var lastWelcome = 0L

    /**
     * Re-read the Welcome room's state from the bridge, at most every
     * [WELCOME_INTERVAL_MS]. Local state only -- the bridge keeps it current
     * from room presence -- so this is cheap and sends nothing.
     */
    private fun refreshWelcome() {
        val state = this.state ?: return
        val core = this.core ?: return
        val now = System.currentTimeMillis()
        if (now - lastWelcome < WELCOME_INTERVAL_MS) return
        lastWelcome = now
        viewModelScope.launch {
            val view = withContext(Dispatchers.IO) {
                runCatching { core.welcomeDirectory() }.getOrNull()
            } ?: return@launch
            state.applyWelcome(view)
            revision++
        }
    }

    private var lastDiscovery = 0L
    private var discovering = false

    /**
     * Ask the server who is online (XEP-0133), at most every
     * [DISCOVERY_INTERVAL_MS]. One round trip to our own server; nothing is
     * sent to any user. A server that does not offer it answers "none" and
     * is asked again only on the same slow interval.
     */
    fun refreshDiscovery(force: Boolean = false) {
        val state = this.state ?: return
        val core = this.core ?: return
        if (!state.canSend()) { lastDiscovery = 0L; return }
        val now = System.currentTimeMillis()
        if (discovering || (!force && now - lastDiscovery < DISCOVERY_INTERVAL_MS)) return
        lastDiscovery = now
        discovering = true
        viewModelScope.launch {
            val (outcome, found) = withContext(Dispatchers.IO) {
                runCatching { core.discoverOnlineUsers() }.getOrNull()
                    ?: (org.otrv4plus.android.bridge.RoomOutcome(false, "network", "") to null)
            }
            discovering = false
            // A failed ask leaves the last answer alone rather than claiming
            // that nobody is online.
            if (outcome.ok) state.applyDiscovery(found)
            revision++
        }
    }

    fun closeConversation() {
        state?.closeConversation()
        revision++
    }

    fun dismissFingerprintAlert() {
        state?.dismissFingerprintAlert()
        revision++
    }

    fun dismissNotice() {
        state?.dismissNotice()
        revision++
    }

    /** People who have asked to see this account's presence. */
    val pendingSubscriptions: List<OtrEvent.SubscriptionRequested>
        get() { observe(); return state?.pendingSubscriptions ?: emptyList() }

    /**
     * Answer a pending subscription request.
     *
     * The request is cleared FIRST and unconditionally, before the blocking
     * call is even scheduled. Two reasons, and the second is the important
     * one: the answer is an I2P round trip and a banner that lingered for it
     * reads as the button not working; and a banner that stayed up on failure
     * would invite a second tap, which under ASK sends a second `subscribed`
     * stanza for a request that may already have been answered.
     *
     * Only sent when the policy actually left the decision open. Under ACCEPT
     * slixmpp answered before the event was raised, so the stanza would have
     * nothing to do — the screen offers revoking instead, via
     * [removeContact].
     */
    fun answerSubscription(jid: String, approve: Boolean) {
        val state = this.state ?: return
        val bare = ChatState.bare(jid.trim())
        val pending = state.pendingSubscriptions
            .firstOrNull { ChatState.bare(it.peer) == bare }
        state.clearSubscription(bare)
        revision++
        if (pending?.isQuestion != true) return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                core.answerSubscription(bare, approve)
            }
            state.note(result.message())
            revision++
        }
    }

    /**
     * Dismiss a request without answering it.
     *
     * Distinct from declining. Under ASK, saying nothing leaves the asker
     * pending on the server rather than telling them no, and that is a
     * legitimate thing to want — a decline is itself a signal that this
     * account exists and is being used.
     */
    fun dismissSubscription(jid: String) {
        state?.clearSubscription(ChatState.bare(jid.trim()))
        revision++
    }

    /**
     * Drop a contact and revoke both directions of subscription.
     *
     * The remedy the banner offers under ACCEPT, where presence was granted
     * before anybody was asked. Without it, automatic approval was a one-way
     * door from the handset.
     */
    fun removeContact(jid: String) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        val bare = ChatState.bare(jid.trim())
        state.clearSubscription(bare)
        revision++
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { core.removeContact(bare) }
            // FORGOTTEN LOCALLY TOO, and only once the server confirmed it --
            // the mirror image of `addContact`, which saves only on `ok`.
            //
            // Otherwise the local record would bring the row straight back,
            // since `conversations()` unions the roster, the message store and
            // the saved list.
            //
            // The HISTORY is deliberately untouched. A conversation outlives
            // the roster entry, so somebody the user has actually talked to
            // keeps their row and their messages; what goes is the local
            // record that was keeping an empty row alive on its own.
            if (result.ok) state.savedContacts.forget(bare)
            state.note(result.message())
            revision++
        }
    }

    /** What kind of chat [jid] is, for the delete dialog. */
    fun deletionKind(jid: String): ChatDeletion.Kind =
        if (isRoom(jid)) ChatDeletion.Kind.ROOM else ChatDeletion.Kind.DIRECT

    /** Whether [jid] is a room this session is in, so leaving means something. */
    fun inRoom(jid: String): Boolean { observe(); return state?.inRoomThisSession(jid) == true }

    /**
     * "Delete chat". Local deletion first and unconditionally -- it does not
     * wait on the network, and it is the part the user asked for. Then, if
     * asked, leave the room (never destroy it); then ask the server what it
     * keeps, and say exactly that. See [ChatDeletion].
     */
    fun deleteChat(jid: String, leaveRoom: Boolean = false) {
        val state = this.state ?: return
        val bare = ChatState.bare(jid.trim())
        val kind = deletionKind(bare)
        val deleted = state.deleteConversation(bare)
        revision++
        val core = this.core
        viewModelScope.launch {
            var left: Boolean? = null
            if (kind == ChatDeletion.Kind.ROOM && leaveRoom) {
                left = core != null && withContext(Dispatchers.IO) {
                    core.leaveRoom(bare, "").ok
                }
                if (left == true) state.forgetRoom(bare)
            }
            val (probe, mam) = if (core == null || !state.canSend()) null to null
                else withContext(Dispatchers.IO) {
                    core.archiveSupport(if (kind == ChatDeletion.Kind.ROOM) bare else "")
                }
            state.note(ChatDeletion.Outcome(
                kind = kind,
                deletedLocally = deleted,
                left = left,
                server = ChatDeletion.serverArchive(
                    answered = probe?.ok == true && mam != null, mam = mam == true),
            ).notice)
            revision++
        }
    }

    /** Add a contact to the roster, and say what happened. */
    fun addContact(jid: String) {
        val state = this.state ?: return
        if (!state.validContact(jid)) {
            state.note("That does not look like an address (name@server).")
            revision++
            return
        }
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        val bare = ChatState.bare(jid.trim())
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) { core.addContact(bare) }
            // SAVED ONLY AFTER THE CONTROLLER CONFIRMED IT.
            //
            // `RosterResult.ok` is the answer to the roster operation, not to
            // the tap. Writing on the tap would make the local list a record
            // of intentions, and the entire reason it is kept apart from the
            // roster is that it must never assert something the server has
            // not done.
            //
            // What this records is still only local: "this account asked to
            // keep this JID". Whether they accept the subscription, and
            // whether their presence ever becomes visible, stays the server's
            // to say and arrives through the roster poll.
            if (result.ok) {
                state.savedContacts.save(bare, at = System.currentTimeMillis())
            }
            state.note(result.message())
            revision++
        }
    }

    /** People this device remembers. NOT a statement about the roster. */
    fun savedContacts(): List<SavedContacts.Saved> {
        observe()
        return state?.savedContacts?.all() ?: emptyList()
    }

    /**
     * What has finished since authentication, for the screen to explain an
     * empty list with. Never gates anything.
     */
    fun initialising(): Boolean {
        observe()
        val s = state ?: return false
        return s.canSend() && !s.postLogin.rosterSeen
    }

    /**
     * Send the draft for [jid].
     *
     * [ChatState.beginSend] decides what is sent and records it; this schedules
     * the blocking call and hands the outcome back. No rule about duplication,
     * ordering or labelling is repeated here.
     */
    fun send(jid: String) {
        val core = this.core ?: return
        val state = this.state ?: return
        editing?.let { target ->
            if (ChatState.bare(target.conversationId) == ChatState.bare(jid)) {
                sendEdit(jid, target)
                return
            }
        }
        val replyTo = replyingTo?.takeIf {
            ChatState.bare(it.conversationId) == ChatState.bare(jid) && it.wireId.isNotEmpty()
        }
        val message = state.beginSend(jid, replyTo) ?: return
        replyingTo = null
        revision++
        // The message itself carries <active/>: no "paused" after it.
        pausedJob?.cancel()

        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                // getOrDefault, not a rethrow: a bridge failure is a failed
                // send, and the exception's text may name what it was handling.
                runCatching {
                    if (message.replyTo.isNotEmpty())
                        core.sendReply(jid, message.body, message.wireId, message.replyTo)
                    else core.sendUserText(jid, message.body, message.wireId)
                }.getOrDefault(SendOutcome.FAILED)
            }
            state.completeSend(message, outcome)
            revision++
        }
    }

    // -- reply, correct, delete for everyone, react (otrv4plus_actions) --------

    /** The message the next send replies to, shown above the composer. */
    var replyingTo by mutableStateOf<Message?>(null)
    /** The message of ours being corrected: the composer holds its text. */
    var editing by mutableStateOf<Message?>(null)
        private set
    /** The message whose action menu is open (its local id). */
    var actionsFor by mutableStateOf<String?>(null)
    /** Why the last action did not go, for a line under the composer. */
    var actionStatus by mutableStateOf<String?>(null)
        private set

    /** Actions need a wire id: one-to-one conversations, plain rooms
     *  (standard XEPs) and secure groups (inside MLS). */
    /** See [ChatState.memberOf]. */
    fun memberOf(m: Message): String? = state?.memberOf(m)

    fun isContact(jid: String): Boolean = state?.isContact(jid) ?: false

    /** This account's bare JID, or "" before sign-in. */
    fun ownJid(): String = state?.account?.bareJid.orEmpty()

    fun canAct(m: Message): Boolean {
        this.state ?: return false
        return m.wireId.isNotEmpty() && !m.retracted && m.security != SecurityLabel.SYSTEM
    }

    fun startReply(m: Message) { editing = null; replyingTo = m; actionsFor = null }

    fun startEdit(m: Message) {
        if (!m.outgoing || !canAct(m)) return
        replyingTo = null
        editing = m
        actionsFor = null
        setDraft(m.conversationId, m.body)
    }

    fun cancelCompose(jid: String) {
        if (editing != null) setDraft(jid, "")
        editing = null
        replyingTo = null
    }

    private fun sendEdit(jid: String, target: Message) {
        val core = this.core ?: return
        val state = this.state ?: return
        val text = state.draft(jid).trim()
        if (text.isEmpty() || text == target.body) { cancelCompose(jid); return }
        state.setDraft(jid, "")
        editing = null
        revision++
        act(core, jid, "edit", target, text, emptyList())
    }

    fun retract(m: Message) {
        val core = this.core ?: return
        if (!m.outgoing || !canAct(m)) return
        actionsFor = null
        act(core, m.conversationId, "retract", m, "", emptyList())
    }

    fun react(m: Message, emoji: String) {
        val core = this.core ?: return
        val state = this.state ?: return
        if (!canAct(m)) return
        actionsFor = null
        act(core, m.conversationId, "react", m, "", state.toggledReaction(m, emoji))
    }

    private fun act(core: ChaquopyOtrCore, jid: String, action: String, target: Message,
                    body: String, emojis: List<String>) {
        val state = this.state ?: return
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    core.sendAction(jid, action, target.wireId, body, emojis, MessageId.newWireId())
                }.getOrDefault(SendOutcome.FAILED)
            }
            if (outcome == SendOutcome.ENCRYPTED || outcome == SendOutcome.PLAINTEXT ||
                (outcome == SendOutcome.QUEUED && state.isSecureRoom(jid))) {
                state.applyChange(jid, action, target.wireId, body, emojis, outgoing = true)
                actionStatus = null
            } else {
                // A plain room never has a secure session: saying it lacked
                // one there read as the room having lost its encryption.
                val plainRoom = state.isRoom(jid) && !state.isSecureRoom(jid)
                actionStatus = when (action) {
                    "edit" -> if (plainRoom) "Could not correct the message: the room did not " +
                                  "take it. Check you are connected and try again."
                              else "Could not correct the message: no secure session yet."
                    "retract" -> "Could not delete the message for everyone."
                    else -> "Could not send the reaction."
                }
            }
            revision++
        }
    }

    // No `startSession` here on purpose: encryption starts through
    // [startEncryption] and [EncryptionLauncher], which report failures. A
    // convenience wrapper that swallowed `OtrApp.start_session`'s exceptions
    // would hide a handshake that was never sent.

    // -- encryption ----------------------------------------------------------
    //
    // The user's request for encryption (the Encrypt button) goes through
    // [EncryptionLauncher]; once asked, `OtrApp.send_user_text` never sends
    // that conversation in the clear.

    /**
     * Built lazily, and only once a core exists.
     *
     * The providers need the engine: `OtrV4PlusProvider` reads the security
     * state and starts the DAKE through it, so a launcher built before the
     * service bound would hold a dead lambda.
     */
    private var launcher: EncryptionLauncher? = null

    private fun encryption(): EncryptionLauncher? {
        val core = this.core ?: return null
        launcher?.let { return it }
        val made = EncryptionLauncher(listOf(
            OtrV4PlusProvider(
                securityOf = { jid -> conversation(jid).security },
                startSession = { jid -> core.startSession(jid) },
            ),
            // Named rather than omitted. A provider that reports
            // NOT_IMPLEMENTED is checkable; a missing one is indistinguishable
            // from one nobody wrote.
            Omemo2Provider(backend = null),
            // Its transport parameter is not nullable and defaults to
            // MlsTransport.Unavailable, which is the honest value here.
            MlsProvider(),
        ))
        launcher = made
        return made
    }

    private fun refFor(jid: String): ConversationRef {
        val account = state?.account?.bareJid.orEmpty()
        return ConversationRef(account = account, target = jid, isGroup = false)
    }

    /**
     * What this conversation may be encrypted with, in order.
     *
     * Empty is a real answer and the screen must say so with
     * [encryptionUnavailableReason] rather than showing an empty menu.
     */
    fun encryptionOffered(jid: String): List<EncryptionKind> {
        observe()
        // No Start button for a contact whose client has not been confirmed
        // to speak OTRv4Plus: a DAKE is never how that is found out.
        if (OtrAvailability.noStartReason(capability(jid)) != null) return emptyList()
        return encryption()?.offered(refFor(jid)) ?: emptyList()
    }

    fun encryptionUnavailableReason(jid: String): String =
        OtrAvailability.noStartReason(capability(jid))
            ?: encryption()?.unavailableReason(refFor(jid))
            ?: "The connection is not ready yet."

    private fun capability(jid: String): String =
        state?.capabilityOf(jid) ?: OtrAvailability.UNKNOWN

    /**
     * Ask for encryption on this conversation.
     *
     * Goes through [EncryptionLauncher], which re-derives what is on offer, so
     * a stale screen cannot start a protocol that is no longer usable. The
     * outcome is reported as a notice either way: a control that silently does
     * nothing is what this whole trace found.
     */
    fun startEncryption(jid: String) {
        val state = this.state ?: return
        val launcher = encryption() ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                launcher.startDefault(refFor(jid))
            }
            if (!outcome.ok) {
                state.note(outcome.detail.ifBlank {
                    "Encryption could not be started." })
            }
            revision++
        }
    }

    // -- identity verification (SMP) -----------------------------------------
    //
    // No cryptography here. The proof is `Rust/src/smp.rs` -- X448 with
    // hybrid ML-KEM-1024 / ML-DSA-87 and the zero-knowledge proofs -- reached
    // through `OtrApp.smp_start` / `smp_respond`. What is here is which dialog
    // is open and what the user typed, and the typed text is handed to the
    // core and dropped on the same line.

    /** Whose prompt the user has asked for, or null. Never a passphrase. */
    private var verifyRequested: String? = null

    /**
     * Which prompt should be open for [jid], or null for none.
     *
     * Derived on every read from [Verification.prompt] rather than latched,
     * so an incoming request that arrives while the outgoing prompt is open
     * flips it to the one that will actually work — `smpRespond` resumes the
     * peer's held SMP1, `smpStart` would begin a competing run.
     */
    fun verificationPrompt(jid: String): Verification.Prompt? {
        observe()
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val core = this.core ?: return null
        return Verification.prompt(
            security = conversation(jid).security,
            secretRequired = runCatching { core.smpSecretRequired(jid) }
                .getOrDefault(false),
            requested = verifyRequested == jid,
        )
    }

    /** What the one verification control should be for [jid]. */
    fun verificationOffer(jid: String): Verification.Offer {
        observe()
        val conversation = conversation(jid)
        return Verification.offer(conversation.security, conversation.smp)
    }

    /** (step, total) of the verification running with [jid]; (0, 4) when
     *  it runs and nothing has come back yet. */
    fun verificationSteps(jid: String): Pair<Int, Int> {
        observe()
        return state?.smpSteps(jid) ?: (0 to 4)
    }

    /** The user tapped Verify Identity. Opens the outgoing prompt only. */
    fun requestVerification(jid: String) {
        // Folded, because this is compared against the jid every later read
        // passes in. Two spellings here would mean the prompt is "open" for a
        // key nothing asks about, so the dialog never appears.
        verifyRequested = ChatState.bare(jid)
        revision++
    }

    /**
     * The user dismissed a prompt.
     *
     * An OUTGOING prompt closes and nothing else happens: no run had started.
     *
     * An INCOMING prompt means the peer's SMP1 is held in the core, and
     * closing the dialog without telling the engine would leave it held
     * forever while the initiator waited. So that case aborts, which is how
     * the state becomes CANCELLED rather than staying SECRET_REQUIRED.
     */
    fun dismissVerification(jid: String) {
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val incoming = verificationPrompt(jid) == Verification.Prompt.INCOMING
        verifyRequested = null
        revision++
        if (!incoming) return
        val core = this.core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.smpAbort(jid) } }
            revision++
        }
    }

    /**
     * Submit the passphrase for [jid].
     *
     * WHICH CALL IS NOT A DETAIL. An incoming prompt must go to `smpRespond`,
     * which binds the secret AND resumes the peer's held SMP1 into SMP2;
     * `smpStart` there would begin a second, competing run against a core that
     * is already holding one.
     *
     * [secret] is passed to the bridge and not retained: it is not assigned to
     * a field, not put in a notice, and not logged. The bridge hands it to the
     * engine, which copies it into Rust-owned zeroizing memory.
     */
    fun submitVerification(jid: String, secret: String) {
        @Suppress("NAME_SHADOWING") val jid = ChatState.bare(jid)
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        if (!Verification.acceptable(secret)) {
            state.note("The passphrase must be at least " +
                       "${Verification.MIN_SECRET} characters.")
            revision++
            return
        }
        val incoming = verificationPrompt(jid) == Verification.Prompt.INCOMING
        verifyRequested = null
        revision++
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                // getOrElse, not a rethrow: the exception's text comes from
                // the bridge and a PyException carries the engine's own
                // message. The CODE is what reaches the screen.
                runCatching {
                    if (incoming) core.smpRespond(jid, secret)
                    else core.smpStart(jid, secret)
                }
            }
            outcome.onFailure {
                val code = (it as? OtrBridgeException)?.code.orEmpty()
                state.note(
                    Verification.refusal(code)
                        ?: if (incoming) "The verification could not be answered."
                        else "The verification could not be started.")
            }
            revision++
        }
    }

    /** What to say about a finished run, or null while one is in flight. */
    fun verificationOutcome(jid: String): String? {
        observe()
        return Verification.outcome(conversation(jid).smp)
    }

    // ── calls ───────────────────────────────────────────────────────────────
    //
    // Every decision here is somebody else's: what to offer is `CallUi`, what
    // may happen is `otrv4plus_voice.VoiceCallManager` through the bridge.
    // This holds which direction a call is going -- a fact only the UI knows,
    // because RINGING means "they are calling us" and "we are calling them"
    // depending on who pressed the button.

    /** Which peer this device placed a call to, or null. Not a call state. */
    private var callingOut: String? = null

    /** Why voice cannot run here, cached: it is a fact about the device. */
    private var voiceReason: String? = null

    /**
     * Why the call control is or is not offered for [jid]. The ENGINE's
     * answer (`call_gate`) when it can be asked; otherwise what this side
     * knows, which is never more permissive. Deterministic: one gate per
     * state, rendered by [CallUi.control].
     */
    fun callGate(jid: String): Pair<CallUi.Gate, String> {
        observe()
        val core = this.core
        val bare = ChatState.bare(jid)
        val fromEngine = core?.let { c -> runCatching { c.callGate(bare) }.getOrNull() }
        if (fromEngine != null) return CallUi.Gate.of(fromEngine.first) to fromEngine.second
        return CallUi.localGate(
            connected = canSend(),
            isRoom = isRoom(bare),
            security = conversation(bare).security,
            // Not asked yet is not "voice works": the fallback never offers
            // what it has not checked.
            voiceUnavailableReason = voiceReason ?: "voice has not been checked yet",
            capability = capability(bare),
        ) to (voiceReason ?: "voice has not been checked yet")
    }

    /** The phone icon: whether the next call's I2P path is already built. */
    var callPath by mutableStateOf(CallUi.Readiness.COLD)
        private set
    var callPathSecondsLeft by mutableStateOf(0)
        private set

    /**
     * Keep the next call's path built while a conversation that can call is
     * on screen (asked every few seconds by the screen; each ask renews the
     * 10-minute window). [callable] is false where no call could be made --
     * nothing is built for those, the state is only read.
     */
    fun refreshCallPath(callable: Boolean) {
        val core = this.core ?: return
        viewModelScope.launch {
            val (code, left) = withContext(Dispatchers.IO) {
                runCatching { core.callPath(build = callable) }.getOrDefault("cold" to 0)
            }
            callPath = CallUi.Readiness.of(code)
            callPathSecondsLeft = left
        }
    }

    /** What the call control should be for [jid]. Never a security claim. */
    fun callOffer(jid: String): CallUi.Offer {
        observe()
        val core = this.core
            ?: return CallUi.Offer.Unavailable("The connection is not ready yet.")
        if (voiceReason == null) {
            voiceReason = runCatching { core.voiceUnavailableReason() }
                .getOrDefault("Voice is not available on this device.")
        }
        return CallUi.offer(conversation(jid).security, voiceReason.orEmpty())
    }

    /** Where this peer's call has got to, and what the screen may offer. */
    fun callPhase(jid: String): CallUi.Phase {
        observe()
        val bare = ChatState.bare(jid)
        val state = state?.callState(bare) ?: CallState.IDLE
        return CallUi.phase(
            state,
            if (callingOut == bare) CallUi.Direction.OUTGOING
            else if (state == CallState.IDLE) CallUi.Direction.NONE
            else CallUi.Direction.INCOMING,
        )
    }

    /** How long the call has been up, formatted. Empty when none is. */
    fun callElapsed(jid: String): String {
        observe()
        val core = this.core ?: return ""
        if (!callPhase(jid).showsDuration) return ""
        return CallUi.elapsed(
            runCatching { core.callDurationSeconds(ChatState.bare(jid)) }
                .getOrDefault(0))
    }

    /**
     * Place a call, once the microphone is ours to use.
     *
     * [micGranted] is passed in rather than read here: this class cannot
     * touch Android, and a call placed without the permission fails inside
     * AAudio where the user cannot see why.
     */
    fun startCall(jid: String, micGranted: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        if (!micGranted) {
            state.note(MicPermission.REFUSED)
            revision++
            return
        }
        val bare = ChatState.bare(jid)
        // Held BEFORE the request, so the first poll after it already knows
        // which way the call is going. Set after, a RINGING state arriving
        // quickly would read as somebody calling us.
        callingOut = bare
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.startCall(bare) }.getOrDefault("unavailable")
            }
            if (outcome != "started") {
                callingOut = null
                CallUi.refusal(outcome)?.let { state.note(it) }
            }
            revision++
        }
    }

    /** Answer the call that is ringing. */
    fun answerCall(jid: String, micGranted: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: return
        if (!micGranted) {
            state.note(MicPermission.REFUSED)
            revision++
            return
        }
        val bare = ChatState.bare(jid)
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.answerCall(bare) }.getOrDefault("unavailable")
            }
            if (outcome != "started") CallUi.refusal(outcome)?.let(state::note)
            revision++
        }
    }

    /** End an active call, or reject a ringing one. */
    fun endCall(jid: String) {
        val core = this.core ?: return
        val bare = ChatState.bare(jid)
        // Cleared here rather than on the outcome: whatever the engine
        // answers, this device is no longer placing a call, and leaving the
        // flag set would render the next inbound ring as outgoing.
        callingOut = null
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.endCall(bare) } }
            revision++
        }
    }

    // ── files ───────────────────────────────────────────────────────────────
    //
    // Every decision is somebody else's: what to offer is `TransferUi`, what
    // may happen is `otrv4plus_filetransfer` through the bridge, which
    // enforces the SMP gate on both sides. This only carries the request.

    /** What the attach control should be for [jid]. Never a security claim. */
    fun transferOffer(jid: String): TransferUi.Offer {
        observe()
        // A secure group: every other member verified (the bridge decides;
        // this only mirrors it). An ordinary room has no files at all.
        if (isRoom(jid)) {
            return if (isSecureRoom(jid))
                // Members not listed yet: still encrypted, still to be verified.
                TransferUi.groupOffer(groupMembers(jid)) ?: TransferUi.Offer.NeedsVerification
            else TransferUi.Offer.NeedsEncryption
        }
        return TransferUi.offer(conversation(jid).security)
    }

    /** Live transfers with [jid], newest state first read. */
    fun transfers(jid: String): List<FileTransferView> {
        observe()
        val core = this.core ?: return emptyList()
        val bare = ChatState.bare(jid)
        return runCatching { core.transfers() }.getOrDefault(emptyList())
            .filter { ChatState.bare(it.peer) == bare }
            // Voice notes are bubbles in the chat, not files.
            .filterNot { VoiceNotes.looksLikeNote(it.filename) }
    }

    /** A received file being viewed: its sealed container and its name. */
    data class ViewedFile(val path: String, val filename: String)

    /** A verified received file the user asked to view, or null. */
    var viewing: ViewedFile? by mutableStateOf(null)
        private set

    private var receivedDir: String? = null

    private fun receivedDirOrNull(): String? = receivedDir ?: core?.let { c ->
        runCatching { c.receivedFileDir() }.getOrDefault("").also {
            if (it.isNotBlank()) receivedDir = it
        }.ifBlank { null }
    }

    /**
     * Whether [transfer] may be opened in the viewer: received, verified by
     * the engine, and inside the private received directory.
     */
    fun canOpen(transfer: FileTransferView): Boolean {
        if (transfer.outgoing || transfer.state != TransferUi.State.RECEIVED) return false
        val dir = receivedDirOrNull() ?: return false
        return SafeView.openable(transfer.path, dir)
    }

    /** Explicit tap only; nothing is ever opened on arrival. */
    fun openReceived(transfer: FileTransferView) {
        if (canOpen(transfer)) viewing = ViewedFile(transfer.path, transfer.filename)
    }

    /**
     * Whether a conversation line can open its file: a file we received and
     * the engine verified ([Message.filePath]), still in the private received
     * directory (deleted chats and Wipe remove it).
     */
    fun canOpenLine(message: Message): Boolean {
        if (message.filePath.isEmpty()) return false
        val dir = receivedDirOrNull() ?: return false
        return SafeView.openable(message.filePath, dir) && java.io.File(message.filePath).isFile
    }

    /** Open a conversation line's file in the viewer. Explicit tap only. */
    fun openLine(message: Message) {
        if (canOpenLine(message)) viewing = ViewedFile(message.filePath, receivedName(message.filePath))
    }

    /** The name a container was stored under, without the `.otrv` suffix. */
    private fun receivedName(path: String): String =
        java.io.File(path).name.removeSuffix(".otrv")

    /**
     * What metadata [plainPath] (the viewer's decrypted copy) still carries,
     * so the viewer can show that a picture's was stripped. Null if the
     * question could not be asked.
     */
    fun inspectViewed(plainPath: String): MetadataFinding? {
        val c = core ?: return null
        return runCatching { c.inspectFile(plainPath) }.getOrNull()
    }

    fun closeViewer() { viewing = null }

    /**
     * Decrypt a received container into [directory] for the viewer. Blocking;
     * the viewer calls it off the main thread. Null when it does not open.
     */
    fun openReceivedTo(container: String, directory: String): String? {
        val c = core ?: return null
        val file = viewing ?: return null
        val dir = receivedDirOrNull() ?: return null
        if (file.path != container || !SafeView.openable(container, dir)) return null
        return c.openReceivedTo(container, directory)
    }

    private val rates = TransferUi.RateMeter()

    /**
     * The row for [transfer], with speed and ETA while bytes are moving.
     * The rate is sampled here, on each redraw, from the engine's own
     * progress; nothing is estimated for a transfer that is not moving.
     */
    fun transferRow(transfer: FileTransferView): TransferUi.Row {
        val moving = transfer.state == TransferUi.State.ACCEPTED &&
            transfer.progress > 0f && transfer.progress < 1f
        val rate = if (moving) rates.sample(
            transfer.id, (transfer.sizeBytes * transfer.progress).toLong(),
            transfer.sizeBytes, System.currentTimeMillis()) else null
        return TransferUi.row(transfer, rate)
    }

    /**
     * A picked file waiting on the user's metadata choice, or null.
     *
     * Held here rather than in the Composable so a rotation mid-dialog does
     * not lose the question -- and with it the path of a staged copy that
     * would then never be sent or deleted.
     */
    var pendingMetadata: PendingMetadata? by mutableStateOf(null)
        private set

    data class PendingMetadata(val jid: String, val path: String,
                               val question: String)

    /**
     * A file has been picked and staged. Look at it before anything is sent.
     *
     * [path] has been resolved by Android through the Storage Access
     * Framework and copied into this app's cache. Examined on the IO
     * dispatcher: it reads the file, and this is reached from a picker
     * callback on the main thread.
     */
    fun prepareFile(jid: String, path: String) {
        val state = this.state ?: return
        val core = this.core ?: run {
            state.note("The connection is not ready yet.")
            revision++
            return
        }
        viewModelScope.launch {
            val finding = withContext(Dispatchers.IO) {
                runCatching { core.inspectFile(path) }
                    .getOrDefault(MetadataFinding.UNKNOWN)
            }
            when (val next = MetadataChoice.next(finding)) {
                is MetadataChoice.Next.Send -> sendFile(jid, path, false)
                is MetadataChoice.Next.SendUnchecked -> {
                    sendFile(jid, path, false)
                    state.note(next.notice)
                }
                is MetadataChoice.Next.Ask ->
                    pendingMetadata = PendingMetadata(jid, path, next.question)
            }
            revision++
        }
    }

    /** The user answered the metadata question. */
    fun answerMetadata(strip: Boolean) {
        val pending = pendingMetadata ?: return
        pendingMetadata = null
        sendFile(pending.jid, pending.path, strip)
    }

    /**
     * The user dismissed the question without answering.
     *
     * NOTHING IS SENT. Dismissing is not consent to either option, and the
     * staged copy is deleted rather than left in the cache.
     */
    fun cancelMetadata() {
        val pending = pendingMetadata ?: return
        pendingMetadata = null
        discardStaged(pending.path)
        revision++
    }

    /**
     * Offer a file, having settled the metadata question.
     *
     * The staged copy is deleted once the offer is made: the engine seals the
     * whole file into memory in `offer_file` and never reads the path again,
     * so the copy in the cache would only be a second plaintext of the
     * user's file left behind.
     */
    private fun sendFile(jid: String, path: String, strip: Boolean) {
        val state = this.state ?: return
        val core = this.core ?: return
        val bare = ChatState.bare(jid)
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                val result = runCatching { core.sendFile(bare, path, strip) }
                    .getOrDefault(FileOutcome.UNAVAILABLE)
                discardStaged(path)
                result
            }
            val refusal = if (isRoom(jid)) TransferUi.groupRefusal(outcome)
                          else TransferUi.refusal(outcome)
            refusal?.let(state::note)
            revision++
        }
    }

    private fun discardStaged(path: String) {
        runCatching { java.io.File(path).delete() }
    }

    // -- location pins (Location.kt) --------------------------------------------
    //
    // A pin is a chat message (a geo: URI and a Plus Code), so it is encrypted
    // like any other line; it is only offered where the conversation IS
    // encrypted. Screen state lives here like the rest.

    /** The conversation the pin sheet is open for, or null. */
    var locationFor by mutableStateOf<String?>(null)
        private set
    var locationText by mutableStateOf("")
        private set
    var locationPin by mutableStateOf<Location.Pin?>(null)
        private set
    var locationStatus by mutableStateOf<String?>(null)
        private set
    var gpsBusy by mutableStateOf(false)
        private set

    /** Encrypted 1:1 conversation, or a secure group. Never a plain room. */
    /** Null when a location may go to [jid]; otherwise why not (see
     *  [Location.shareRefusal]: verified, not merely encrypted). */
    fun locationRefusal(jid: String): String? {
        observe()
        val offer = transferOffer(jid)
        return Location.shareRefusal(
            encrypted = offer !is TransferUi.Offer.NeedsEncryption,
            verified = offer is TransferUi.Offer.Available,
            group = isRoom(jid),
        )
    }

    fun canShareLocation(jid: String): Boolean = locationRefusal(jid) == null

    /** 📍: the sheet where sharing is allowed; elsewhere only the reason.
     *  The sheet -- and with it the GPS -- is never opened before. */
    fun openLocation(jid: String) {
        val refusal = locationRefusal(jid)
        if (refusal != null) {
            actionStatus = refusal
            return
        }
        actionStatus = null
        locationFor = ChatState.bare(jid)
        locationText = ""
        locationPin = null
        locationStatus = null
        gpsBusy = false
    }

    fun closeLocation() {
        locationFor = null
        locationPin = null
        locationText = ""
        locationStatus = null
        gpsBusy = false
    }

    fun typeLocation(text: String) {
        locationText = text.take(200)
        locationPin = Location.fromTyped(locationText)
        locationStatus = Location.typedStatus(locationText, locationPin)
    }

    fun gpsStarted() { gpsBusy = true; locationStatus = "Waiting for satellites… (outdoors works best)" }

    /** A GPS fix, or [failure] in our own words. */
    fun gpsFinished(pin: Location.Pin?, failure: String?) {
        gpsBusy = false
        if (pin != null) {
            locationPin = pin
            locationText = pin.code
            locationStatus = null
        } else {
            locationStatus = failure ?: "No GPS fix."
        }
    }

    /** Send the pin as an ordinary (encrypted) message, through [send]. */
    fun sendLocation() {
        val state = this.state ?: return
        val jid = locationFor ?: return
        val pin = locationPin ?: return
        locationRefusal(jid)?.let { locationStatus = it; return }
        val previous = state.draft(jid)
        val keepEditing = editing
        val keepReply = replyingTo
        editing = null
        replyingTo = null
        state.setDraft(jid, Location.body(pin))
        send(jid)
        state.setDraft(jid, previous)
        editing = keepEditing
        replyingTo = keepReply
        closeLocation()
    }

    // -- voice notes ------------------------------------------------------------
    //
    // The sheet's state lives here, like every other piece of screen state.
    // The recording itself never comes to Kotlin: see [VoiceNotes].

    /** The open voice-note sheet, or null. */
    var voiceSheet by mutableStateOf<VoiceSheet?>(null)
        private set
    private var voiceMode = VoiceNotes.DEFAULT
    private var voicePoll: Job? = null

    /** The conversation whose file picker the composer's 📎 asked for. */
    var pickFileFor by mutableStateOf<String?>(null)

    /** 📎 in the composer: the picker if allowed here, otherwise why not. */
    fun requestFile(jid: String) {
        val hint = TransferUi.lockedHint(transferOffer(jid), isRoom(jid))
        if (hint == null) { actionStatus = null; pickFileFor = ChatState.bare(jid) }
        else actionStatus = hint
    }

    fun filePickerOpened() { pickFileFor = null }

    /** 🎤 in the composer: the voice-note sheet if allowed, otherwise why not. */
    fun requestVoice(jid: String) {
        val hint = TransferUi.lockedHint(transferOffer(jid), isRoom(jid))
        if (hint == null) { actionStatus = null; openVoiceSheet() }
        else actionStatus = hint
    }

    fun openVoiceSheet() {
        if (voiceSheet == null) voiceSheet = VoiceSheet.Choosing(voiceMode)
    }

    fun chooseVoice(mode: String) {
        if (mode !in VoiceNotes.MODES) return
        voiceMode = mode
        when (val s = voiceSheet) {
            is VoiceSheet.Choosing -> voiceSheet = s.copy(mode = mode)
            is VoiceSheet.Failed -> voiceSheet = VoiceSheet.Choosing(mode)
            else -> {}
        }
    }

    /** Start recording, once the microphone is ours to use. */
    fun startVoiceNote(micGranted: Boolean) {
        val core = this.core ?: return
        val mode = voiceSheet?.mode ?: voiceMode
        if (!micGranted) {
            voiceSheet = VoiceSheet.Failed(mode, MicPermission.REFUSED)
            return
        }
        viewModelScope.launch {
            val started = withContext(Dispatchers.IO) { core.voiceNoteStart() }
            if (started != "ok") {
                voiceSheet = VoiceSheet.Failed(mode, VoiceNotes.errorText(started))
                return@launch
            }
            voiceSheet = VoiceSheet.Recording(mode)
            voicePoll?.cancel()
            voicePoll = viewModelScope.launch {
                while (voiceSheet is VoiceSheet.Recording) {
                    val st = withContext(Dispatchers.IO) { core.voiceNoteStatus() }
                    if (voiceSheet !is VoiceSheet.Recording) break
                    if (!st.recording) {
                        // The limit was reached, or the microphone failed.
                        if (st.error.isNotEmpty()) {
                            voiceSheet = VoiceSheet.Failed(mode, VoiceNotes.errorText("no_microphone"))
                            core.voiceNoteCancel()
                        } else {
                            stopVoiceNote()
                        }
                        break
                    }
                    voiceSheet = VoiceSheet.Recording(mode, st.seconds, st.level)
                    delay(200)
                }
            }
        }
    }

    /** Stop and disguise. The note goes into the app's private cache. */
    fun stopVoiceNote(cacheDir: java.io.File? = voiceDir) {
        val core = this.core ?: return
        val sheet = voiceSheet as? VoiceSheet.Recording ?: return
        val dir = cacheDir ?: return
        voicePoll?.cancel()
        voiceSheet = VoiceSheet.Making(sheet.mode)
        viewModelScope.launch {
            val note = withContext(Dispatchers.IO) {
                core.voiceNoteStop(sheet.mode, java.io.File(dir, "outbox").also { it.mkdirs() }.absolutePath)
            }
            voiceSheet = if (note.error.isEmpty() && note.path.isNotEmpty()) {
                VoiceSheet.Ready(note.mode, note.path, note.seconds)
            } else {
                VoiceSheet.Failed(sheet.mode, VoiceNotes.errorText(note.error))
            }
        }
    }

    /** Where notes are written; set by the screen (it has the Context). */
    var voiceDir: java.io.File? = null

    /**
     * Send the ready note. It travels as an encrypted file, but shows in the
     * chat as a voice-note bubble that plays, from a sealed copy the engine
     * keeps. The plaintext in the cache goes either way.
     */
    fun sendVoiceNote(jid: String) {
        val ready = voiceSheet as? VoiceSheet.Ready ?: return
        val state = this.state ?: return
        val core = this.core ?: return
        voiceSheet = null
        val bare = ChatState.bare(jid)
        viewModelScope.launch {
            val (outcome, kept) = withContext(Dispatchers.IO) {
                val result = runCatching { core.sendVoiceNote(bare, ready.path) }
                    .getOrDefault(FileOutcome.UNAVAILABLE to "")
                discardStaged(ready.path)
                result
            }
            if (outcome == FileOutcome.STARTED) {
                if (kept.isNotEmpty()) state.addOutgoingVoiceNote(bare, kept)
            } else {
                val refusal = if (isRoom(jid)) TransferUi.groupRefusal(outcome)
                              else TransferUi.refusal(outcome)
                refusal?.let(state::note)
            }
            revision++
        }
    }

    /**
     * Decrypt a voice note's sealed copy into [directory] for the player, which
     * deletes it when done. Only a path a voice-note message in this chat
     * names; the engine checks again that it is a received container.
     * Blocking; null when it does not open.
     */
    /** The waveform for a voice-note bubble, read once per note and kept
     *  in memory for this screen. Blocking; null when it cannot be read. */
    fun voiceWaveform(message: Message): VoiceWaveform? {
        val c = core ?: return null
        val s = state ?: return null
        if (message.voicePath.isEmpty() ||
            s.messages(message.conversationId).none { it.id == message.id && it.voicePath == message.voicePath })
            return null
        waveforms[message.voicePath]?.let { return it }
        return c.voiceNoteWaveform(message.voicePath)?.also { waveforms[message.voicePath] = it }
    }

    private val waveforms = java.util.concurrent.ConcurrentHashMap<String, VoiceWaveform>()

    fun openVoiceNote(message: Message, directory: String): String? {
        val c = core ?: return null
        val s = state ?: return null
        if (message.voicePath.isEmpty() ||
            s.messages(message.conversationId).none { it.id == message.id && it.voicePath == message.voicePath })
            return null
        return c.openReceivedTo(message.voicePath, directory)
    }

    /** Close the sheet: stop any recording and delete any unsent note. */
    fun closeVoiceSheet() {
        val core = this.core
        val sheet = voiceSheet
        voiceSheet = null
        voicePoll?.cancel()
        viewModelScope.launch(Dispatchers.IO) {
            when (sheet) {
                is VoiceSheet.Recording -> core?.voiceNoteCancel()
                is VoiceSheet.Ready -> {
                    core?.voiceNoteDiscard(sheet.path)
                    discardStaged(sheet.path)
                }
                else -> {}
            }
        }
    }

    /** Incoming offers waiting for Accept or Decline. See [ChatState.pendingFileOffers]. */
    fun fileOffers(): List<OtrEvent.FileTransferChanged> {
        observe()
        return state?.pendingFileOffers ?: emptyList()
    }

    /** "Not now": the prompt goes; the offer stays in its conversation. */
    fun putAsideFileOffer(transferId: String) {
        state?.dismissFileOffer(transferId)
        revision++
    }

    /** Accept an offered transfer. */
    fun acceptTransfer(transferId: String) {
        val state = this.state ?: return
        val core = this.core ?: return
        state.dismissFileOffer(transferId)
        revision++
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching { core.acceptFile(transferId) }
                    .getOrDefault(FileOutcome.UNAVAILABLE)
            }
            TransferUi.refusal(outcome)?.let(state::note)
            revision++
        }
    }

    /** Decline an offered transfer. */
    fun declineTransfer(transferId: String) {
        val core = this.core ?: return
        state?.dismissFileOffer(transferId)
        revision++
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { core.declineFile(transferId) }
            }
            revision++
        }
    }

    /**
     * Stop a transfer under way -- one of ours, or one we accepted. Not
     * [declineTransfer]: that answers an offer, and routing a cancel through
     * it found no offer and did nothing.
     */
    fun cancelTransfer(transferId: String) {
        val core = this.core ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { core.cancelFile(transferId) }
            }
            revision++
        }
    }

    /** Where a finished file lands, for the screen to tell the user. */
    fun receivedFileDir(): String {
        observe()
        val core = this.core ?: return ""
        return runCatching { core.receivedFileDir() }.getOrDefault("")
    }

    override fun onCleared() {
        super.onCleared()
        // The redraw timer, and nothing else. The conversation and the
        // connection belong to the service and outlive this.
        pollJob?.cancel()
        // A voice note is the exception: the microphone is not left open,
        // and an unsent note is not left in the cache, for a screen that is
        // gone. (viewModelScope is already cancelled, so a plain thread.)
        val core = this.core
        val sheet = voiceSheet
        if (sheet is VoiceSheet.Recording || sheet is VoiceSheet.Ready) {
            Thread {
                core?.voiceNoteCancel()
                if (sheet is VoiceSheet.Ready) core?.voiceNoteDiscard(sheet.path)
            }.start()
        }
    }

    companion object {
        /**
         * How often to redraw.
         *
         * Not a poll of Python -- the service does that. This only decides how
         * quickly a message the service has already received appears on screen.
         */
        const val REDRAW_INTERVAL_MS = 400L
        /** No keystroke for this long: "paused" (XEP-0085). */
        const val TYPING_PAUSE_MS = 6_000L

        /** How long an automatic OTRv4+ start gets before it is retried. */
        const val AUTO_RETRY_MS = 45_000L
        const val DISCOVERY_INTERVAL_MS = 120_000L
        const val WELCOME_INTERVAL_MS = 3_000L

        /** How often the avatar index is re-read (local, no network). */
        const val AVATAR_INTERVAL_MS = 5_000L
        const val HANDSHAKE_INTERVAL_MS = 1_000L
    }
}
