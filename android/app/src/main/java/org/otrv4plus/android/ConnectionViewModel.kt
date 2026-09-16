// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.InitResult
import org.otrv4plus.android.bridge.RegistrationOutcome
import org.otrv4plus.android.bridge.RouterProbe
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.connection.LinkPhase
import org.otrv4plus.android.connection.OtrConnectionService

/**
 * The UI's view of the connection. It does NOT own it.
 *
 * WHAT CHANGED, AND WHY
 * ---------------------
 * This class used to hold `ChaquopyOtrCore` itself. A ViewModel survives
 * Activity recreation, so that fixed the rotation bug it was written for -- but
 * it does not survive the process, and Android kills a backgrounded process
 * that nothing is holding up. The connection died whenever the user looked at
 * something else, and every message sent to them in between was lost.
 *
 * [OtrConnectionService] owns the core now. This binds to it, reads its state,
 * and asks it to start and stop. The distinction that matters: when this
 * ViewModel is cleared the connection is UNTOUCHED, because the Activity going
 * away is not a reason to hang up.
 *
 * `core` is therefore nullable: there is a window between the ViewModel being
 * created and the service binding, and pretending otherwise would put a
 * not-yet-there object into every caller's hands.
 */
class ConnectionViewModel(app: Application) : AndroidViewModel(app) {

    /** The service's core, once bound. Never constructed here. */
    var core by mutableStateOf<ChaquopyOtrCore?>(null)
        private set

    /**
     * The service's conversation, once bound.
     *
     * Handed straight to `ChatViewModel`. This object does not read it, does
     * not copy it and does not replace it -- it exists here only because the
     * Activity binds once and both ViewModels need what the binding produced.
     */
    var chat by mutableStateOf<ChatState?>(null)
        private set

    var init by mutableStateOf<InitResult?>(null)
        private set
    var status by mutableStateOf(ConnectionStatus())
        private set
    var probe by mutableStateOf<RouterProbe?>(null)
        private set

    /**
     * The last Create account result, or null if nobody has tried.
     *
     * Kept separate from [status] because registration ends with nobody
     * signed in: folding it into the connection status would put
     * `connected = false` next to a success, which reads as a failure to
     * somebody who has just been told their account was created.
     */
    var registration by mutableStateOf<RegistrationOutcome?>(null)
        private set

    /** The service's authoritative phase. */
    var phase by mutableStateOf(LinkPhase.STOPPED)
        private set

    /** Non-null while something long-running is in flight; the UI's label. */
    var busy by mutableStateOf<String?>("Starting...")
        private set

    /** A Kotlin-side throw, as opposed to a reported Python failure. */
    var error by mutableStateOf<String?>(null)
        private set

    /** True once the core is up and the connect path is worth offering. */
    val ready: Boolean get() = init?.ok == true

    /** True while a connect attempt is running, including a reconnect. */
    val connecting: Boolean get() = phase.busy && phase != LinkPhase.DISCONNECTING

    private var service: OtrConnectionService? = null
    private var poll: Job? = null

    /**
     * Whether a screen is in front of the user, remembered across a rebind.
     *
     * Not UI state -- nothing renders it. It is held here because the service
     * can go away and come back, and the answer has to be re-delivered when it
     * does.
     */
    private var uiVisible: Boolean = false

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val bound = (binder as? OtrConnectionService.LocalBinder)?.service
            service = bound
            core = bound?.core
            chat = bound?.chat
            // The UI may already have been on screen for a moment before the
            // binding landed. Without this the service would still believe
            // nobody was looking and would notify for a message the user is
            // watching arrive.
            bound?.setUiVisible(uiVisible)
            startPolling()
            viewModelScope.launch {
                // The engine starts once, in the service. Asking here is what
                // gives the connect screen something to show while it does.
                init = withContext(Dispatchers.IO) {
                    runCatching { bound?.core?.initialize() }.getOrNull()
                }
                busy = null
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            // The service process went away. Say so rather than leaving a
            // stale handle that will throw on the next call.
            service = null
            core = null
            chat = null
            phase = LinkPhase.STOPPED
        }
    }

    init {
        // BIND_AUTO_CREATE creates the service without making it foreground:
        // the core exists for the router probe before anyone has asked to
        // connect, and the notification appears only when a connection does.
        getApplication<Application>().bindService(
            Intent(getApplication(), OtrConnectionService::class.java),
            connection,
            Context.BIND_AUTO_CREATE,
        )
    }

    private fun startPolling() {
        if (poll?.isActive == true) return
        poll = viewModelScope.launch {
            while (isActive) {
                service?.let {
                    phase = it.phase
                    status = it.status
                    it.failure?.let { code -> error = code }
                }
                delay(POLL_MS)
            }
        }
    }

    /**
     * A screen came to the front, or went away.
     *
     * Forwarded to the service, which uses it to decide whether an arriving
     * message is worth a notification. Held here as well so a rebind can
     * re-deliver it: a service that has just been reconnected to knows nothing
     * about what the user can see.
     */
    fun setUiVisible(visible: Boolean) {
        uiVisible = visible
        service?.setUiVisible(visible)
    }

    fun checkRouter(jid: String) {
        val c = core ?: return
        if (busy != null) return
        error = null
        busy = "Checking for a router..."
        viewModelScope.launch {
            val got = withContext(Dispatchers.IO) {
                runCatching {
                    c.prepareConnection(jid.trim())
                    c.probeRouter()
                }
            }
            got.onSuccess { probe = it }
                .onFailure { error = it.javaClass.simpleName }
            busy = null
        }
    }

    /**
     * Create an account, and do not sign in.
     *
     * Unlike [connect] this does NOT go through the service. There is no
     * session at the end of it, so there is nothing for a foreground service
     * to hold up: the stream is opened, the account is created, and the stream
     * is given back. The user then presses Log in like anybody else.
     *
     * Refused while connected. [ChaquopyOtrCore.prepareConnection] replaces
     * the core's controller, and doing that under a live session would leave
     * the service holding a connection nothing could any longer disconnect.
     */
    fun register(jid: String, password: String, server: String = "") {
        val c = core ?: return
        if (busy != null) return
        if (status.connected) {
            registration = RegistrationOutcome(
                ok = false, code = "already_connected",
                detail = "Sign out before creating another account.")
            return
        }
        error = null
        registration = null
        busy = "Creating the account..."
        viewModelScope.launch {
            val got = withContext(Dispatchers.IO) {
                runCatching {
                    c.prepareConnection(jid.trim(), server.trim())
                    c.register(password)
                }
            }
            got.onSuccess { registration = it }
                .onFailure { error = it.javaClass.simpleName }
            busy = null
        }
    }

    /** Dismiss the last registration result. */
    fun clearRegistration() {
        registration = null
    }

    /**
     * Connect, for real.
     *
     * Handed to the service, which owns the attempt, the backoff and the
     * teardown. [password] goes into an explicit Intent to a non-exported
     * service and is removed from that Intent as soon as the service reads it;
     * it is not stored on this object, not logged, and not placed in any state
     * the UI renders.
     */
    fun connect(jid: String, password: String, server: String = "") {
        error = null
        OtrConnectionService.start(getApplication(), jid.trim(), password,
                                   server.trim())
    }

    /** Stop an attempt that is still running. */
    fun cancelConnect() {
        OtrConnectionService.stop(getApplication())
    }

    /** The user asked to disconnect, which also stops reconnecting. */
    fun disconnect() {
        OtrConnectionService.stop(getApplication())
    }

    /** Sign out: stop, and forget the account and its history. */
    fun logout() {
        OtrConnectionService.logout(getApplication())
    }

    /**
     * Resume with stored credentials, if there are any.
     *
     * Called once on launch. A user who has signed in before should not be
     * shown a login screen again just because the process restarted.
     */
    fun resumeIfRemembered() {
        OtrConnectionService.resume(getApplication())
    }

    /**
     * The Activity is finishing, or rotating. EITHER WAY THE CONNECTION STAYS.
     *
     * This used to tear down the transport and the engine here, which was
     * correct when this object owned them and is exactly wrong now: hanging up
     * because a screen went away is the bug the service exists to fix. Only
     * the binding is released.
     */
    override fun onCleared() {
        super.onCleared()
        poll?.cancel()
        runCatching { getApplication<Application>().unbindService(connection) }
    }

    companion object {
        /** How often to read the service's state. Cheap: it is in-process. */
        const val POLL_MS = 500L
    }
}
