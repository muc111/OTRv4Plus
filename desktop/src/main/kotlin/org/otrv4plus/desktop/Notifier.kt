// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import org.otrv4plus.android.chat.InboundAlerts
import org.otrv4plus.android.chat.SoundPolicy
import java.io.File

/**
 * Desktop notifications, with the Android app's rules.
 *
 * WHAT THEY SAY: "New message", "3 new messages", "Incoming call" -- never
 * who, never what. A notification leaves this window: on Qubes the qube's
 * notification goes to dom0's notification daemon (drawn in the qube's
 * label colour, shown over every other qube), on a plain desktop to the
 * session's daemon, and either can log it. A sender or a line of text in
 * it would put who talks to whom, and what they said, outside the
 * encrypted conversation. The Android app hides them on the lock screen for
 * the same reason.
 *
 * WHEN: a message only while the window is not focused (counted by the
 * shared [InboundAlerts]); a call always, because a missed call cannot be
 * read later. One message notification is replaced, not stacked.
 *
 * HOW: `notify-send` (libnotify), which both Qubes and ordinary desktops
 * provide. Without it, nothing -- the app works the same, just silently.
 *
 * SOUNDS (owner, 2026-10-14: "Notification sounds for incoming messages,
 * calls"): the shared [SoundPolicy], as on Android -- the message sound with
 * the notification while the window is behind, a short tone while it is in
 * front on another conversation, nothing for the conversation being read;
 * a 1:1 call rings until it is answered, rejected or over, a group call
 * rings once. Played from the desktop's own sound theme
 * (`canberra-gtk-play`, else `paplay` on the freedesktop sound file, else
 * the system beep). Settings can turn the sounds off; a notification still
 * appears.
 */
class Notifier(
    private val send: (List<String>) -> String? = ::run,
    private val available: Boolean = findNotifySend() != null,
    private val play: (String) -> Unit = Sounds::play,
    private val ringEveryMs: Long = 3_000,
    private val ringForMs: Long = 60_000,
) {
    val alerts = InboundAlerts()
    @Volatile private var messageId: String? = null
    @Volatile private var attentionId: String? = null
    @Volatile private var visible = false
    /** Sounds on or off (Settings). Notifications are not affected. */
    @Volatile var sounds: Boolean = true
    @Volatile private var ringing: Thread? = null

    /** The window gained or lost focus. Focus clears the count. */
    fun setUiVisible(visible: Boolean) {
        this.visible = visible
        alerts.setUiVisible(visible)
    }

    /**
     * A new message was stored, from [from] (a bare JID or a room), while
     * [openConversation] is on screen. Announced only when the window is
     * not in front; a tone when it is but another conversation is open.
     */
    fun message(from: String = "", openConversation: String? = null) {
        when (SoundPolicy.forMessage(visible, openConversation, from)) {
            SoundPolicy.Sound.NOTIFICATION -> {
                val alert = alerts.note() ?: return
                val text = if (alert.first) "New message" else "${alert.count} new messages"
                val id = post(text, urgency = "normal", replace = messageId)
                if (id != null) messageId = id
                sound(MESSAGE_SOUND)
            }
            SoundPolicy.Sound.IN_APP_TONE -> sound(TONE_SOUND)
            else -> {}
        }
    }

    /**
     * Something waits on the user: a group invitation, a verification request,
     * someone asking to join ([org.otrv4plus.android.chat.Attention], the
     * Android rules). The kind's words only, never who. Posted when the window
     * is not in front; a tone when it is (the app shows the request itself).
     */
    fun attention(kind: org.otrv4plus.android.chat.Attention.Kind) {
        if (visible) { sound(TONE_SOUND); return }
        val id = post(kind.text, urgency = "normal", replace = attentionId)
        if (id != null) attentionId = id
        sound(MESSAGE_SOUND)
    }

    /** A call is ringing, 1:1 or group. Announced whatever the focus. */
    fun call(group: Boolean = false) {
        post("Incoming call", urgency = "critical", replace = null)
        if (SoundPolicy.forCall(group) == SoundPolicy.Sound.RING_REPEATING) startRinging()
        else sound(RING_SOUND)
    }

    /** The 1:1 call was answered, rejected or ended: stop the ring. */
    fun stopRinging() {
        ringing?.interrupt()
        ringing = null
    }

    private fun startRinging() {
        stopRinging()
        if (!sounds) return
        val t = Thread({
            val until = System.currentTimeMillis() + ringForMs
            try {
                while (!Thread.currentThread().isInterrupted && System.currentTimeMillis() < until) {
                    sound(RING_SOUND)
                    Thread.sleep(ringEveryMs)
                }
            } catch (_: InterruptedException) {}
        }, "otrv4plus-ring").apply { isDaemon = true }
        ringing = t
        t.start()
    }

    private fun sound(name: String) {
        if (sounds) runCatching { play(name) }
    }

    private fun post(text: String, urgency: String, replace: String?): String? {
        if (!available) return null
        val args = mutableListOf("notify-send", "--app-name=$APP_NAME", "--icon=otrv4plus",
                                 "--urgency=$urgency", "--print-id")
        if (replace != null) args += "--replace-id=$replace"
        args += listOf(APP_NAME, text)
        return send(args)?.trim()?.takeIf { it.isNotEmpty() && it.all(Char::isDigit) }
    }

    companion object {
        const val APP_NAME = "Off The Record v4 Plus"
        // freedesktop sound-naming names, present in every sound theme.
        const val MESSAGE_SOUND = "message-new-instant"
        const val TONE_SOUND = "message"
        const val RING_SOUND = "phone-incoming-call"

        fun findNotifySend(): File? = findTool("notify-send")

        fun findTool(name: String): File? =
            (System.getenv("PATH") ?: "/usr/bin:/bin").split(':')
                .map { File(it, name) }.firstOrNull { it.canExecute() }

        private fun run(args: List<String>): String? = runCatching {
            val p = ProcessBuilder(args).redirectErrorStream(true).start()
            p.outputStream.close()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) p.destroy()
            out
        }.getOrNull()
    }
}

/** Plays a freedesktop sound by name, with whatever the desktop has. */
object Sounds {
    private val canberra by lazy { Notifier.findTool("canberra-gtk-play") }
    private val paplay by lazy { Notifier.findTool("paplay") }

    fun play(name: String) {
        // Fixed names only (Notifier's constants): nothing a peer sent.
        canberra?.let { spawn(listOf(it.path, "-i", name)); return }
        val file = listOf("oga", "ogg", "wav")
            .map { File("/usr/share/sounds/freedesktop/stereo/$name.$it") }
            .firstOrNull { it.canRead() }
        val player = paplay
        if (player != null && file != null) { spawn(listOf(player.path, file.path)); return }
        runCatching { java.awt.Toolkit.getDefaultToolkit().beep() }
    }

    private fun spawn(args: List<String>) {
        runCatching {
            ProcessBuilder(args).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start().outputStream.close()
        }
    }
}
