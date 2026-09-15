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
import org.otrv4plus.android.bridge.RouterProbe
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

    var init by mutableStateOf<InitResult?>(null)
        private set
    var status by mutableStateOf(ConnectionStatus())
        private set
    var probe by mutableStateOf<RouterProbe?>(null)
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

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val bound = (binder as? OtrConnectionService.LocalBinder)?.service
            service = bound
            core = bound?.core
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
     * Connect, for real.
     *
     * Handed to the service, which owns the attempt, the backoff and the
     * teardown. [password] goes into an explicit Intent to a non-exported
     * service and is removed from that Intent as soon as the service reads it;
     * it is not stored on this object, not logged, and not placed in any state
     * the UI renders.
     */
    fun connect(jid: String, password: String) {
        error = null
        OtrConnectionService.start(getApplication(), jid.trim(), password)
    }

    /** Stop an attempt that is still running. */
    fun cancelConnect() {
        OtrConnectionService.stop(getApplication())
    }

    /** The user asked to disconnect, which also stops reconnecting. */
    fun disconnect() {
        OtrConnectionService.stop(getApplication())
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
