// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.InitResult
import org.otrv4plus.android.bridge.RouterProbe

/**
 * Owns the connection, and outlives the screen that starts it.
 *
 * WHY THIS EXISTS
 * ---------------
 * The connect screen used to hold the core in `remember { ChaquopyOtrCore(…) }`.
 * `remember` survives recomposition and nothing else — in particular it does
 * not survive Activity recreation, which Android does for a rotation, a theme
 * change, a font-size change, or a locale change. So the sequence was:
 *
 *   1. user starts a connect; a cold I2P tunnel takes 30-90s
 *   2. the phone rotates
 *   3. the Activity is destroyed and rebuilt; the composition is discarded
 *   4. `remember` runs again and builds a SECOND ChaquopyOtrCore
 *
 * and the first one is still there: its worker thread, its half-built tunnel,
 * its engine holding the same identity and trust files. Two
 * EnhancedSessionManagers over one set of files is not a leak, it is a
 * correctness problem.
 *
 * A ViewModel is scoped to the Activity's *retained* instance, so it survives
 * step 3 and is cleared only when the Activity is finishing for real.
 * `lifecycle-viewmodel-compose` was already a dependency; this uses it rather
 * than inventing a holder.
 *
 * WHY THE CONNECT RUNS HERE
 * -------------------------
 * In [viewModelScope], not in the screen's `rememberCoroutineScope()`. A
 * screen-scoped coroutine is cancelled when the composition goes away, which
 * is exactly the rotation above — so the Kotlin side would stop waiting while
 * the Python side carried on connecting, and nothing would ever collect the
 * result.
 *
 * Cancelling the coroutine is not enough by itself either: the call into
 * Python is a blocking JNI call and cancellation does not interrupt it. That
 * is what [cancelConnect] is for — it asks the transport to stop, which is the
 * only thing that actually unwinds the attempt.
 */
class ConnectionViewModel(app: Application) : AndroidViewModel(app) {

    /** One core for the life of the ViewModel. It owns the interpreter. */
    val core: ChaquopyOtrCore = ChaquopyOtrCore(app.applicationContext)

    var init by mutableStateOf<InitResult?>(null)
        private set
    var status by mutableStateOf(ConnectionStatus())
        private set
    var probe by mutableStateOf<RouterProbe?>(null)
        private set

    /** Non-null while something long-running is in flight; the UI's label. */
    var busy by mutableStateOf<String?>("Starting Python...")
        private set

    /** A Kotlin-side throw, as opposed to a reported Python failure. */
    var error by mutableStateOf<String?>(null)
        private set

    /** True once the core is up and the connect path is worth offering. */
    val ready: Boolean get() = init?.ok == true

    /**
     * True only while a real connect attempt is running.
     *
     * Distinct from [busy], which is also set by the router probe and by
     * start-up. Cancel is offered on this and not on `busy`, because cancel
     * does nothing during a probe -- a SAM HELLO answers in milliseconds --
     * and a button that does nothing when pressed teaches people that buttons
     * do nothing.
     */
    var connecting by mutableStateOf(false)
        private set

    private var connectJob: Job? = null

    init {
        viewModelScope.launch {
            init = withContext(Dispatchers.IO) { core.initialize() }
            busy = null
        }
    }

    fun checkRouter(jid: String) {
        if (busy != null) return
        error = null
        busy = "Checking for a router..."
        viewModelScope.launch {
            val got = withContext(Dispatchers.IO) {
                runCatching {
                    core.prepareConnection(jid.trim())
                    core.probeRouter()
                }
            }
            got.onSuccess { probe = it }
                .onFailure { error = it.javaClass.simpleName }
            refreshStatus()
            busy = null
        }
    }

    /**
     * Connect, for real.
     *
     * [password] is passed straight through to Python and is not stored on
     * this object, not logged, and not placed in any state the UI renders.
     * The caller clears its own copy as soon as this returns.
     */
    fun connect(jid: String, password: String) {
        if (busy != null) return
        error = null
        busy = "Connecting. A cold I2P tunnel can take minutes."
        connecting = true
        connectJob = viewModelScope.launch {
            val got = withContext(Dispatchers.IO) {
                runCatching {
                    core.prepareConnection(jid.trim())
                    core.connect(password)
                }
            }
            got.onSuccess { status = it }
                .onFailure { error = it.javaClass.simpleName }
            busy = null
            connecting = false
            connectJob = null
        }
    }

    /**
     * Stop an attempt that is still running.
     *
     * Two steps, and both are needed. The Python call tells the transport to
     * abandon the tunnel — that is what actually ends it, because the JNI call
     * the connect is blocked in cannot be interrupted from Kotlin. Cancelling
     * the job afterwards only tidies up the coroutine that was waiting.
     */
    fun cancelConnect() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { runCatching { core.cancelConnect() } }
        }
    }

    fun disconnect() {
        if (busy != null) return
        busy = "Disconnecting..."
        viewModelScope.launch {
            val got = withContext(Dispatchers.IO) { runCatching { core.disconnect() } }
            got.onSuccess { status = it }
                .onFailure { error = it.javaClass.simpleName }
            busy = null
        }
    }

    private suspend fun refreshStatus() {
        status = withContext(Dispatchers.IO) {
            runCatching { core.connectionStatus() }.getOrDefault(status)
        }
    }

    /**
     * The Activity is finishing for real — not rotating.
     *
     * Everything the connection owns goes here: the transport's worker thread,
     * its I2P tunnel and its local listening socket, then the engine. On a
     * best-effort basis and off the main thread, because this is a lifecycle
     * callback that has to return promptly and a socket close can block.
     *
     * `viewModelScope` is already cancelled by the time this runs, so the work
     * goes on a plain thread. A daemon thread: if the process is going away
     * anyway, teardown must not be the thing that keeps it alive.
     */
    override fun onCleared() {
        super.onCleared()
        val c = core
        Thread({
            runCatching { c.disconnect() }
            runCatching { c.shutdown() }
        }, "otrv4plus-shutdown").apply { isDaemon = true }.start()
    }
}
