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
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.InboundAlerts
import org.otrv4plus.android.chat.PersistentMessageStore
import org.otrv4plus.android.crypto.CallAlert
import org.otrv4plus.android.security.Credentials
import org.otrv4plus.android.security.CredentialStore
import org.otrv4plus.android.security.KeystoreVault
import org.otrv4plus.android.security.LatchedVault
import org.otrv4plus.android.security.Vault
import org.otrv4plus.android.security.VaultCredentialStore
import org.otrv4plus.android.security.WipeAndExit
import java.util.concurrent.atomic.AtomicBoolean

// Telling the user something arrived, and the foreground notification:
// split out of OtrConnectionService (audit tidy 4). Extension functions
// on the service, so `this` is the service and its Context, exactly as
// when they were members; the service calls them unchanged.

private const val CHANNEL_ID = "otrv4plus.connection"
private const val NOTIFICATION_ID = 1

/** With sound and vibration (rc.102); the old id had neither set. */
private const val MESSAGE_CHANNEL_ID = "otrv4plus.messages.alert"
private const val OLD_MESSAGE_CHANNEL_ID = "otrv4plus.messages"

private const val ATTENTION_CHANNEL_ID = "otrv4plus.attention"
/** One id for every verification request and invitation. */
private const val ATTENTION_NOTIFICATION_ID = 6

/**
 * ONE id for every arrival.
 *
 * Not one per conversation: the shade would then have one entry per
 * person who messaged, which is a contact graph by cardinality even
 * with every name stripped out.
 */
private const val MESSAGE_NOTIFICATION_ID = 2

private const val CALL_CHANNEL_ID = "otrv4plus.calls.ringtone"
/** The call channel before it had the ringtone; deleted on start. */
private const val OLD_CALL_CHANNEL_ID = "otrv4plus.calls"

/** One id for a ringing call. Only one call can ring at a time. */
private const val CALL_NOTIFICATION_ID = 3

/** A group call's ring, separate so it never cancels a 1:1 ring. */
private const val GROUP_CALL_NOTIFICATION_ID = 4
private const val GROUP_RING_MS = 30_000L

/**
 * The sound for a newly stored message (SoundPolicy): the notification in
 * the background, a short tone when the app is on screen in another
 * conversation, nothing in the conversation being read.
 */
internal fun OtrConnectionService.soundForMessage(event: org.otrv4plus.android.bridge.OtrEvent) {
    val from = when (event) {
        is org.otrv4plus.android.bridge.OtrEvent.MessageReceived -> event.peer
        is org.otrv4plus.android.bridge.OtrEvent.RoomMessageReceived -> event.room
        else -> return
    }
    when (org.otrv4plus.android.chat.SoundPolicy.forMessage(
            alerts.uiVisible, chat.openConversation, from)) {
        org.otrv4plus.android.chat.SoundPolicy.Sound.NOTIFICATION -> announceArrival(from)
        org.otrv4plus.android.chat.SoundPolicy.Sound.IN_APP_TONE -> playInAppTone()
        else -> {}
    }
}

/** Tone and buzz, as the ring mode allows, without a notification. */
internal fun OtrConnectionService.playInAppTone() = AlertFeedback.inApp(this)

/**
 * Post, or update, the "something arrived" notification.
 *
 * Silent when [InboundAlerts] says the user is already looking. One
 * notification for everything, replaced in place as more arrive -- a
 * notification per conversation would make the shade a contact list even
 * with every name removed, because the number of entries is the number of
 * people who messaged.
 */
internal fun OtrConnectionService.announceArrival(from: String) {
    val alert = alerts.note() ?: return
    arrivals.arrived(from)
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.notify(MESSAGE_NOTIFICATION_ID, buildArrivalNotification(alert))
    }
}


/**
 * Something needs the user (Attention): on screen, a tone and a buzz --
 * the app shows the request itself; otherwise one notification that
 * says the kind and nothing more, hidden on a locked screen.
 */
internal fun OtrConnectionService.needAttention(kind: org.otrv4plus.android.chat.Attention.Kind) {
    if (alerts.uiVisible) {
        playInAppTone()
        return
    }
    synchronized(pendingAttention) { pendingAttention.add(kind) }
    val text = synchronized(pendingAttention) {
        org.otrv4plus.android.chat.Attention.text(pendingAttention.toList())
    }
    val open = PendingIntent.getActivity(
        this, 5,
        Intent(this, MainActivity::class.java)
            .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )
    val notification = NotificationCompat.Builder(this, ATTENTION_CHANNEL_ID)
        .setContentTitle(getString(R.string.app_name))
        .setContentText(text)
        .setSmallIcon(android.R.drawable.stat_notify_more)
        .setContentIntent(open)
        .setAutoCancel(true)
        .setShowWhen(false)
        .setVisibility(NotificationCompat.VISIBILITY_SECRET)
        .build()
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.notify(ATTENTION_NOTIFICATION_ID, notification)
    }
}

internal fun OtrConnectionService.cancelAttentionNotification() {
    synchronized(pendingAttention) { pendingAttention.clear() }
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.cancel(ATTENTION_NOTIFICATION_ID)
    }
}

/**
 * Ring for an incoming call. Says "incoming call" and not one word more.
 *
 * The same rules as [buildArrivalNotification]: no caller, no name, and
 * hidden entirely on a locked screen, because a lock-screen line naming
 * the caller announces exactly who talks to this device. Posted whether
 * or not the app is on screen: unlike a message, a call that is missed
 * because the phone stayed silent cannot be read later.
 *
 * Heads-up through a HIGH-importance channel, NOT a full-screen intent.
 * A full-screen intent needs USE_FULL_SCREEN_INTENT, which Play restricts
 * to calling and alarm apps and which the user has to grant separately
 * on Android 14+; that is a later decision, not one to make silently.
 */
internal fun OtrConnectionService.announceCall(group: Boolean = false) {
    val open = PendingIntent.getActivity(
        this, 3,
        Intent(this, MainActivity::class.java)
            .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )
    val notification = NotificationCompat.Builder(this, CALL_CHANNEL_ID)
        .setContentTitle(getString(R.string.app_name))
        .setContentText(getString(R.string.call_incoming))
        .setSmallIcon(android.R.drawable.stat_sys_phone_call)
        .setContentIntent(open)
        .setAutoCancel(true)
        .setShowWhen(false)
        .setCategory(NotificationCompat.CATEGORY_CALL)
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .setVisibility(NotificationCompat.VISIBILITY_SECRET)
        // A group call rings once and clears itself; nothing marks the
        // moment it is "answered" (SoundPolicy.forCall).
        .apply { if (group) setTimeoutAfter(GROUP_RING_MS) }
        .build()
    // A 1:1 call rings until answered, rejected or over: FLAG_INSISTENT
    // repeats the channel's ringtone until the notification is cancelled
    // (CallAlert.Change.STOP cancels it).
    if (org.otrv4plus.android.chat.SoundPolicy.forCall(group) ==
        org.otrv4plus.android.chat.SoundPolicy.Sound.RING_REPEATING) {
        notification.flags = notification.flags or Notification.FLAG_INSISTENT
    }
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.notify(if (group) GROUP_CALL_NOTIFICATION_ID else CALL_NOTIFICATION_ID, notification)
    }
}

internal fun OtrConnectionService.cancelCallNotification() {
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.apply {
                cancel(CALL_NOTIFICATION_ID)
                cancel(GROUP_CALL_NOTIFICATION_ID)
            }
    }
}

internal fun OtrConnectionService.cancelArrivalNotification() {
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.cancel(MESSAGE_NOTIFICATION_ID)
    }
}

/**
 * How many, and not one word more.
 *
 * No peer, no display name, no body, no preview, and no big-text style to
 * expand into one. See [InboundAlerts] for why: a lock-screen line naming
 * who just messaged this device defeats the anonymity the transport under
 * it exists to provide.
 */
internal fun OtrConnectionService.buildArrivalNotification(alert: InboundAlerts.Alert): Notification {
    // The action alone says "a message notification was tapped"; the
    // intent carries no sender. MainActivity then opens the chat list
    // and asks before showing anyone ([ArrivalPrompt]).
    val open = PendingIntent.getActivity(
        this, 2,
        Intent(this, MainActivity::class.java)
            .setAction(MainActivity.ACTION_OPEN_ARRIVAL)
            .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )
    val text = if (alert.count == 1) getString(R.string.message_arrived_one)
               else getString(R.string.message_arrived_many, alert.count)
    return NotificationCompat.Builder(this, MESSAGE_CHANNEL_ID)
        .setContentTitle(getString(R.string.app_name))
        .setContentText(text)
        .setSmallIcon(android.R.drawable.stat_notify_chat)
        .setContentIntent(open)
        .setAutoCancel(true)
        .setShowWhen(false)
        // Hidden entirely on a locked screen -- not "hidden contents",
        // which still shows the app's name and therefore that this device
        // is running this app and just received something.
        .setVisibility(NotificationCompat.VISIBILITY_SECRET)
        // Only the first of a run makes a sound. A conversation arriving
        // message by message must not become a burst of alerts.
        .setOnlyAlertOnce(!alert.first)
        .build()
}

// ── the notification ────────────────────────────────────────────────────

internal fun OtrConnectionService.goForeground() {
    ServiceCompat.startForeground(
        this, NOTIFICATION_ID, buildNotification(), foregroundTypes(micClaimed),
    )
}

/** The foreground-service types to claim: always dataSync (the XMPP
 *  session), plus microphone while a call holds it. */
private fun foregroundTypes(microphone: Boolean): Int = when {
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && microphone ->
        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or
            ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
    else -> 0
}

/**
 * Claim the microphone foreground type for the length of a call, and give it
 * back after. Called on every drain tick with [ChatState.usingMicrophone].
 *
 * WHY. Since Android 11 an app in the background may use the microphone only
 * from a foreground service of type microphone; under any other type the
 * capture reads silence. The service was dataSync only, so a call with the
 * screen locked could go silent on our side (audit 2026-11-14; the app's
 * "your microphone is sending silence" warning is the symptom).
 *
 * Android allows claiming it only while the app may start a microphone
 * service -- on screen, as when the user taps Call or Answer. A refusal
 * (SecurityException, or no RECORD_AUDIO yet) leaves dataSync, which is what
 * every call had before, and is not retried until the next call.
 */
internal fun OtrConnectionService.claimMicrophone(inCall: Boolean) {
    if (inCall) {
        if (micClaimed || micTried) return
        micTried = true
        micClaimed = runCatching {
            ServiceCompat.startForeground(
                this, NOTIFICATION_ID, buildNotification(), foregroundTypes(true))
        }.isSuccess
        runCatching {
            core.note("calls", if (micClaimed) "microphone_claimed" else "microphone_not_claimed",
                      if (micClaimed) "info" else "warning", "")
        }
    } else if (micClaimed || micTried) {
        val held = micClaimed
        micClaimed = false
        micTried = false
        if (held) runCatching {
            ServiceCompat.startForeground(
                this, NOTIFICATION_ID, buildNotification(), foregroundTypes(false))
        }
    }
}

/**
 * Started, but with no account to be. Stand down without claiming a fault.
 *
 * The foreground notification goes: a persistent "OTRv4+ — stopped" in
 * the shade of somebody who has not signed in yet is a statement about
 * work that is not happening.
 *
 * The phase is set to [LinkPhase.STOPPED] rather than [LinkPhase.FAILED].
 * Nothing failed. A first launch with no stored account is the ordinary
 * case, and FAILED would put an error above an empty login form and feed
 * `LoginProgress.problemToShow` a failure the user never caused.
 *
 * `stopSelf` is deliberately NOT called. The UI is bound to this service
 * and is about to send a real ACTION_START; tearing it down between the
 * two would run [onDestroy], which reports a teardown it did not ask for.
 */
internal fun OtrConnectionService.idle() {
    if (phase != LinkPhase.STOPPED) enter(LinkPhase.STOPPED, "no account yet")
    ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
}

internal fun OtrConnectionService.createChannel() {
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
    // A SEPARATE channel for arrivals, so the user can silence one without
    // silencing the other. Silencing the connection channel must not also
    // silence the only signal that somebody is trying to reach them, and
    // silencing arrivals must not stop the foreground notification that
    // keeps the connection alive at all.
    val messages = NotificationChannel(
        MESSAGE_CHANNEL_ID,
        getString(R.string.message_channel_name),
        // DEFAULT: an arrival IS an event, and is the one thing in this app
        // worth interrupting somebody for.
        NotificationManager.IMPORTANCE_DEFAULT,
    ).apply {
        description = getString(R.string.message_channel_description)
        // No badge and no preview on the lock screen. The count alone is
        // already the most this may say.
        setShowBadge(false)
        lockscreenVisibility = Notification.VISIBILITY_SECRET
        // Sound AND vibration, set here because a channel's are fixed
        // once it exists (owner, 2026-10-17: "a sound & vibrate"); the
        // channel without them is deleted below.
        setSound(
            android.media.RingtoneManager.getDefaultUri(android.media.RingtoneManager.TYPE_NOTIFICATION),
            android.media.AudioAttributes.Builder()
                .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION_COMMUNICATION_INSTANT)
                .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build(),
        )
        enableVibration(true)
        vibrationPattern = AlertFeedback.PATTERN
    }
    // Verification requests, group invitations: the kind, never who.
    // HIGH, so it shows over what is on screen -- a verification request
    // waits for an answer.
    val attention = NotificationChannel(
        ATTENTION_CHANNEL_ID,
        getString(R.string.attention_channel_name),
        NotificationManager.IMPORTANCE_HIGH,
    ).apply {
        description = getString(R.string.attention_channel_description)
        setShowBadge(false)
        lockscreenVisibility = Notification.VISIBILITY_SECRET
        setSound(
            android.media.RingtoneManager.getDefaultUri(android.media.RingtoneManager.TYPE_NOTIFICATION),
            android.media.AudioAttributes.Builder()
                .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION_EVENT)
                .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build(),
        )
        enableVibration(true)
        vibrationPattern = AlertFeedback.PATTERN
    }
    // A THIRD channel, for calls, and HIGH so it can appear heads-up: a
    // call that waits in the shade for somebody to look is a missed call.
    // Separate so the user can silence messages without silencing calls,
    // or the other way round.
    //
    // THE RINGTONE, not the notification sound: a call that sounds like
    // a text message is a missed call. A channel's sound is fixed when
    // the channel is created, so the old channel (notification sound) is
    // deleted and this one has a new id.
    val calls = NotificationChannel(
        CALL_CHANNEL_ID,
        getString(R.string.call_channel_name),
        NotificationManager.IMPORTANCE_HIGH,
    ).apply {
        description = getString(R.string.call_channel_description)
        setShowBadge(false)
        lockscreenVisibility = Notification.VISIBILITY_SECRET
        setSound(
            android.media.RingtoneManager.getDefaultUri(android.media.RingtoneManager.TYPE_RINGTONE),
            android.media.AudioAttributes.Builder()
                .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                .setContentType(android.media.AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build(),
        )
        enableVibration(true)
        vibrationPattern = longArrayOf(0, 800, 600, 800, 600)
    }
    runCatching {
        getSystemService(NotificationManager::class.java)?.apply {
            deleteNotificationChannel(OLD_CALL_CHANNEL_ID)
            deleteNotificationChannel(OLD_MESSAGE_CHANNEL_ID)
        }
    }
    getSystemService(NotificationManager::class.java)
        ?.createNotificationChannels(listOf(channel, messages, attention, calls))
}

/**
 * What the notification says.
 *
 * The PHASE and nothing else. No JID, no server, no contact name, no
 * message: a notification is visible on a locked screen and over the
 * user's shoulder, and "who this person talks to" is the thing an
 * anonymity-oriented client is protecting.
 */
internal fun OtrConnectionService.buildNotification(): Notification {
    val open = PendingIntent.getActivity(
        this, 0,
        Intent(this, MainActivity::class.java)
            .setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE,
    )
    val stop = PendingIntent.getService(
        this, 1,
        Intent(this, OtrConnectionService::class.java).setAction(OtrConnectionService.ACTION_STOP),
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

internal fun OtrConnectionService.phaseText(): Int = when (phase) {
    LinkPhase.STOPPED -> R.string.connection_stopped
    LinkPhase.STARTING -> R.string.connection_starting
    LinkPhase.CONNECTING -> R.string.connection_connecting
    LinkPhase.CONNECTED -> R.string.connection_connected
    LinkPhase.RECONNECTING -> R.string.connection_reconnecting
    LinkPhase.DISCONNECTING -> R.string.connection_disconnecting
    LinkPhase.FAILED -> R.string.connection_failed
}

internal fun OtrConnectionService.updateNotification() {
    runCatching {
        getSystemService(NotificationManager::class.java)
            ?.notify(NOTIFICATION_ID, buildNotification())
    }
}
