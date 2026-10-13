// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

/**
 * What the screen shows while an OTRv4+ handshake runs.
 *
 * Reported from two handsets: starting OTR looked like it did nothing. It
 * worked, but over I2P the three handshake messages (two of them ~11 KB and
 * sent in parts) take a minute or more, and nothing on screen moved. The
 * bridge (`OtrApp.handshake_status`) reports the step from the engine's own
 * DAKE state and, while a message is arriving in parts, how many have come.
 * This turns that into words and a bar. Nothing here is estimated.
 *
 * Plain Kotlin, driven by `HandshakeUiTest`.
 */
object HandshakeUi {

    data class Status(
        val stage: String,
        val step: Int,
        val steps: Int = 3,
        val have: Int = 0,
        val of: Int = 0,
        val elapsed: Int = 0,
        /** Seconds still expected (the bridge's estimate from past
         *  handshakes); 0 when unknown. */
        val eta: Int = 0,
        /** Lines waiting to go once encrypted. */
        val queued: Int = 0,
    ) {
        companion object {
            val IDLE = Status("idle", 0)
        }
    }

    data class View(
        val title: String,
        val detail: String,
        /** 0f..1f: completed steps plus the share of parts received. */
        val progress: Float,
        val elapsed: String,
    )

    const val IDLE = "idle"
    const val ESTABLISHED = "established"
    const val FAILED = "failed"

    /** Whether a card should be shown at all. */
    @JvmStatic
    fun active(s: Status): Boolean = s.stage != IDLE && s.stage != ESTABLISHED

    @JvmStatic
    fun view(s: Status): View? {
        if (!active(s)) return null
        val parts = if (s.of > 0) " (${s.have} of ${s.of} parts)" else ""
        val detail = when (s.stage) {
            "receiving_request" -> "Receiving their handshake request$parts"
            "waiting_reply" -> "Handshake request sent. Waiting for their reply"
            "receiving_reply" -> "Receiving their reply$parts"
            "replying" -> "Sending our reply"
            "waiting_confirm" -> "Reply sent. Waiting for their confirmation"
            "receiving_confirm" -> "Receiving their confirmation$parts"
            FAILED -> "The handshake did not complete. Messages here are not encrypted."
            else -> "Working"
        }
        val done = (s.step - 1).coerceAtLeast(0).toFloat()
        val share = if (s.of > 0) s.have.toFloat() / s.of else 0f
        val progress = if (s.stage == FAILED) 0f
                       else ((done + share) / s.steps).coerceIn(0.05f, 0.95f)
        val title = if (s.stage == FAILED) "OTRv4+ handshake failed"
                    else "Establishing secure OTRv4+ session: step ${s.step} of ${s.steps}"
        val waiting = if (s.queued > 0)
            " ${s.queued} message${if (s.queued == 1) "" else "s"} will be sent when it is ready." else ""
        val time = if (s.stage == FAILED) elapsedText(s.elapsed)
                   else etaText(s.elapsed, s.eta)
        return View(title, detail + waiting, progress, time)
    }

    /** "20 s so far, about 40 s left", or "taking longer than usual". */
    @JvmStatic
    fun etaText(elapsed: Int, eta: Int): String {
        if (eta <= 0) return elapsedText(elapsed)
        val so = if (elapsed < 60) "$elapsed s" else "${elapsed / 60} min ${elapsed % 60} s"
        val left = if (eta < 60) "$eta s" else "${eta / 60} min ${eta % 60} s"
        return if (eta <= 5 && elapsed > 120)
            "$so so far. Taking longer than usual: I2P routes vary."
        else "$so so far, about $left left (from your past handshakes over I2P)."
    }

    /** "45 s" / "2 min 10 s", plus why it can take this long. */
    @JvmStatic
    fun elapsedText(seconds: Int): String {
        val t = if (seconds < 60) "$seconds s" else "${seconds / 60} min ${seconds % 60} s"
        return "$t so far. Over I2P this usually takes one to three minutes."
    }
}
