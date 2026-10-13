// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import org.otrv4plus.android.chat.InboundAlerts
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
 */
class Notifier(
    private val send: (List<String>) -> String? = ::run,
    private val available: Boolean = findNotifySend() != null,
) {
    val alerts = InboundAlerts()
    @Volatile private var messageId: String? = null

    /** The window gained or lost focus. Focus clears the count. */
    fun setUiVisible(visible: Boolean) {
        alerts.setUiVisible(visible)
    }

    /** A new message was stored. Announced only when the window is not in front. */
    fun message() {
        val alert = alerts.note() ?: return
        val text = if (alert.first) "New message" else "${alert.count} new messages"
        val id = post(text, urgency = "normal", replace = messageId)
        if (id != null) messageId = id
    }

    /** A call is ringing, 1:1 or group. Announced whatever the focus. */
    fun call() {
        post("Incoming call", urgency = "critical", replace = null)
    }

    private fun post(text: String, urgency: String, replace: String?): String? {
        if (!available) return null
        val args = mutableListOf("notify-send", "--app-name=OTRv4Plus", "--icon=otrv4plus",
                                 "--urgency=$urgency", "--print-id")
        if (replace != null) args += "--replace-id=$replace"
        args += listOf("OTRv4Plus", text)
        return send(args)?.trim()?.takeIf { it.isNotEmpty() && it.all(Char::isDigit) }
    }

    companion object {
        fun findNotifySend(): File? =
            (System.getenv("PATH") ?: "/usr/bin:/bin").split(':')
                .map { File(it, "notify-send") }.firstOrNull { it.canExecute() }

        private fun run(args: List<String>): String? = runCatching {
            val p = ProcessBuilder(args).redirectErrorStream(true).start()
            p.outputStream.close()
            val out = p.inputStream.bufferedReader().readText()
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) p.destroy()
            out
        }.getOrNull()
    }
}
