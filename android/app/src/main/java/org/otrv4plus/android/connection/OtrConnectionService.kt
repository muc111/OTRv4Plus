// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.otrv4plus.android.MainActivity
import org.otrv4plus.android.R
import org.otrv4plus.android.bridge.ChaquopyOtrCore
import org.otrv4plus.android.bridge.ConnectionStatus

/**
 * The one owner of the connection, and it outlives every screen.
 *
 * WHY A SERVICE AND NOT A VIEWMODEL
 * ---------------------------------
 * `ConnectionViewModel` survives Activity recreation, which covers a rotation
 * and a theme change. It does not survive the process, and Android kills a
 * backgrounded process with nothing holding it up -- so a conversation that
 * was working stopped working the moment the user looked at something else,
 * and every message sent to them in the meantime was gone.
 *
 * A foreground service is the platform's answer to "this app is doing
 * something the user asked for and can see", and an XMPP connection over an
 * I2P tunnel is exactly that. It is also the honest answer: the notification
 * says the connection is up, because it is, and the user can stop it.
 *
 * WHAT IT OWNS
 * ------------
 * [ChaquopyOtrCore], and therefore the Python interpreter, the engine, the
 * SAM tunnel, the XMPP stream, the keepalive and the inbound path. ONE of
 * each, for the life of the service. Nothing else in the application may
 * construct a core -- two would be two engines over one identity file and one
 * set of trust records.
 *
 * WHAT IT DOES NOT DO
 * -------------------
 * It holds no chat state. Messages are drained from the core by
 * `ChatViewModel` exactly as before; the service's job is to make sure there
 * is still a core to drain from. A service that also owned the conversation
 * would be a second place for history to live and a second thing to keep in
 * step.
 */
class OtrConnectionService : Service() {

    /**
     * The handle a bound client gets.
     *
     * Deliberately NOT a copy of anything: the caller reads live state from
     * the service. A snapshot handed out at bind time is a snapshot that is
     * wrong by the time it is read.
     */
    inner class LocalBinder : Binder() {
        val service: OtrConnectionService get() = this@OtrConnectionService
    }

    private val binder = LocalBinder()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val reconnect = ReconnectPolicy()

    /** The one core. Built on first use, never rebuilt. */
    val core: ChaquopyOtrCore by lazy { ChaquopyOtrCore(applicationContext) }

    @Volatile
    var phase: LinkPhase = LinkPhase.STOPPED
        private set

    /** The last status the transport reported. */
    @Volatile
    var status: ConnectionStatus = ConnectionStatus()
        private set

    /** A stable code for the last failure, or null. Never exception text. */
    @Volatile
    var failure: String? = null
        private set

    private var worker: Job? = null
    private var watcher: Job? = null

    /** Python and the engine start once, not once per reconnect. */
    @Volatile
    private var initialised: Boolean = false

    /**
     * Credentials for THIS run, held in memory only.
     *
     * Never written here. Durable storage is `security/CredentialStore`, which
     * seals them under the Keystore; this is the working copy the reconnect
     * loop needs so a transient drop does not stop to ask the user to type
     * their password again.
     */
    private var jid: String = ""
    private var password: String = ""

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopConnection(explicit = true)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                goForeground()
                val account = intent.getStringExtra(EXTRA_JID).orEmpty()
                val secret = intent.getStringExtra(EXTRA_PASSWORD).orEmpty()
                if (account.isNotBlank()) {
                    jid = account
                    password = secret
                }
                // The Intent is done with the password the moment it is read.
                // Intents can be logged by the system, so it does not sit in
                // one any longer than it must.
                intent.removeExtra(EXTRA_PASSWORD)
                startConnection()
            }
            else -> goForeground()
        }
        // START_STICKY would have Android restart the service with a null
        // Intent after a kill, and we would have no credentials -- so it would
        // come back as a notification attached to nothing. The UI restarts it
        // deliberately instead.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopConnection(explicit = true)
        scope.cancel()
        super.onDestroy()
    }

    // ── connection ──────────────────────────────────────────────────────────

    /** Begin, or do nothing if an attempt is already running. */
    fun startConnection() {
        reconnect.onUserConnect()
        if (worker?.isActive == true) return
        worker = scope.launch { connectLoop() }
    }

    /**
     * Stop, and mean it.
     *
     * `explicit` latches the reconnect policy, which is what separates "the
     * user pressed Disconnect" from "the stream dropped". Only the first
     * should stop the app coming back.
     */
    fun stopConnection(explicit: Boolean) {
        if (explicit) reconnect.onUserDisconnect()
        worker?.cancel()
        worker = null
        watcher?.cancel()
        watcher = null
        phase = LinkPhase.DISCONNECTING
        // Off the main thread: this crosses into Python and blocks.
        scope.launch {
            withContext(Dispatchers.IO) {
                runCatching { core.cancelConnect() }
                runCatching { core.disconnect() }
            }
            phase = LinkPhase.STOPPED
            updateNotification()
        }
    }

    private suspend fun connectLoop() {
        while (scope.isActive) {
            if (!reconnect.beginAttempt()) return
            phase = if (reconnect.attempts == 0) LinkPhase.CONNECTING
                    else LinkPhase.RECONNECTING
            updateNotification()

            // initialize -> prepareConnection -> connect, in that order and
            // all on the IO dispatcher: every one of them is a blocking call
            // into Python and Chaquopy's JNI calls are not interruptible by
            // coroutine cancellation.
            //
            // `prepareConnection` is repeated on each attempt on purpose. A
            // reconnect needs a controller whose transport is not the dead
            // one, and building it is cheap next to a tunnel.
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    if (!initialised) {
                        val init = core.initialize()
                        if (!init.ok) throw IllegalStateException("init_failed")
                        initialised = true
                    }
                    core.prepareConnection(jid.trim())
                    core.connect(password)
                }
            }
            reconnect.endAttempt()

            val ok = result.getOrNull()?.connected == true
            if (ok) {
                reconnect.onConnected()
                status = result.getOrNull() ?: ConnectionStatus()
                failure = null
                phase = LinkPhase.CONNECTED
                updateNotification()
                watchUntilDropped()
                // watchUntilDropped returns when the stream is gone. Fall
                // through to the backoff rather than returning: a drop we did
                // not ask for is exactly what reconnect exists for.
                if (reconnect.suppressed) return
            } else {
                failure = result.exceptionOrNull()?.let { codeOf(it) }
                    ?: result.getOrNull()?.code.orEmpty().ifBlank { "connect_failed" }
                status = result.getOrNull() ?: status
            }

            val wait = reconnect.nextDelayMs() ?: return
            phase = LinkPhase.RECONNECTING
            updateNotification()
            delay(wait)
        }
    }

    /**
     * Poll the transport's own view until it stops being connected.
     *
     * The transport's `connected`, not ours: the keepalive clears it when a
     * round trip stops being answered, which over I2P is the only reliable
     * evidence that a stream that still accepts writes is actually dead.
     */
    private suspend fun watchUntilDropped() {
        while (scope.isActive) {
            delay(WATCH_INTERVAL_MS)
            val current = withContext(Dispatchers.IO) {
                runCatching { core.connectionStatus() }.getOrNull()
            } ?: continue
            status = current
            if (!current.connected) {
                phase = LinkPhase.RECONNECTING
                updateNotification()
                return
            }
        }
    }

    private fun codeOf(t: Throwable): String =
        t::class.simpleName ?: "error"

    // ── the notification ────────────────────────────────────────────────────

    private fun goForeground() {
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID, buildNotification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC else 0,
        )
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.connection_channel_name),
            // LOW: the connection notification is a persistent fact, not an
            // event. It must not make a sound every time a tunnel rebuilds.
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.connection_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java)
            ?.createNotificationChannel(channel)
    }

    /**
     * What the notification says.
     *
     * The PHASE and nothing else. No JID, no server, no contact name, no
     * message: a notification is visible on a locked screen and over the
     * user's shoulder, and "who this person talks to" is the thing an
     * anonymity-oriented client is protecting.
     */
    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java)
                .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, OtrConnectionService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(phaseText()))
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentIntent(open)
            .addAction(0, getString(R.string.connection_stop), stop)
            .setOngoing(true)
            .setShowWhen(false)
            // Nothing about this notification may appear on a lock screen
            // beyond the app's own name.
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun phaseText(): Int = when (phase) {
        LinkPhase.STOPPED -> R.string.connection_stopped
        LinkPhase.STARTING -> R.string.connection_starting
        LinkPhase.CONNECTING -> R.string.connection_connecting
        LinkPhase.CONNECTED -> R.string.connection_connected
        LinkPhase.RECONNECTING -> R.string.connection_reconnecting
        LinkPhase.DISCONNECTING -> R.string.connection_disconnecting
        LinkPhase.FAILED -> R.string.connection_failed
    }

    private fun updateNotification() {
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIFICATION_ID, buildNotification())
        }
    }

    companion object {
        private const val CHANNEL_ID = "otrv4plus.connection"
        private const val NOTIFICATION_ID = 1

        const val ACTION_START = "org.otrv4plus.android.START"
        const val ACTION_STOP = "org.otrv4plus.android.STOP"
        const val EXTRA_JID = "jid"
        const val EXTRA_PASSWORD = "password"

        /** How often to ask the transport whether it is still up. */
        const val WATCH_INTERVAL_MS = 5_000L

        /** Start the service and ask it to connect. */
        fun start(context: Context, jid: String, password: String) {
            val intent = Intent(context, OtrConnectionService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_JID, jid)
                .putExtra(EXTRA_PASSWORD, password)
            ContextCompat.startForegroundService(context, intent)
        }

        /** Stop it, and latch the reconnect policy so it stays stopped. */
        fun stop(context: Context) {
            val intent = Intent(context, OtrConnectionService::class.java)
                .setAction(ACTION_STOP)
            ContextCompat.startForegroundService(context, intent)
        }
    }
}
