// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.FileTransferView
import org.otrv4plus.android.bridge.SecurityState

/**
 * What the file control offers, and what a transfer row says.
 *
 * DEPENDENCY-FREE, for the same reason as [CallUi] and [MicPermission]: the
 * rules are the part that can be wrong, this container cannot build Compose,
 * so they live where `TransferUiTest` executes them.
 *
 * THE GATE IS THE SAME ONE. A file may only be sent to, or accepted from, a
 * peer whose identity has been checked -- `otrv4plus_filetransfer` enforces
 * it on both sides and this must not offer what that will refuse. Encryption
 * alone proves nobody is reading it in transit, not who is at the other end,
 * and a file is a thing you cannot take back.
 */
object TransferUi {

    /** What the attach control should be, if anything. */
    sealed interface Offer {
        /** Verified and encrypted. Offer the picker. */
        data object Available : Offer

        /**
         * Encrypted but not verified. Shown DISABLED with the reason: a
         * hidden control reads as a broken app, a disabled one with a
         * sentence reads as a next step.
         */
        data object NeedsVerification : Offer

        /** No encrypted session. Nothing to send a file over. */
        data object NeedsEncryption : Offer
    }

    @JvmStatic
    fun offer(security: SecurityState): Offer = when (security) {
        SecurityState.SMP_VERIFIED -> Offer.Available
        // Both are encrypted without a checked identity, and they read the
        // same here on purpose: a matching pin is not somebody confirming
        // who they are.
        SecurityState.ENCRYPTED,
        SecurityState.FINGERPRINT -> Offer.NeedsVerification
        // A changed key must not invite "verify first" -- that would be
        // inviting SMP against whoever holds the new key.
        SecurityState.FINGERPRINT_MISMATCH,
        SecurityState.PLAINTEXT -> Offer.NeedsEncryption
    }

    /** The engine's `TransferState` codes (otrv4plus_filetransfer). */
    object State {
        const val OFFERED = "offered"
        const val WAITING = "waiting"
        const val ACCEPTED = "accepted"
        const val SENT = "sent"
        const val DELIVERED = "delivered"
        const val RECEIVED = "received"
        const val DECLINED = "declined"
        const val CANCELLED = "cancelled"
        const val FAILED = "failed"

        val TERMINAL = setOf(DELIVERED, RECEIVED, DECLINED, CANCELLED, FAILED)
    }

    /** What a transfer row shows and which buttons it carries. */
    data class Row(
        val label: String,
        /** Offer Accept. Only for an INCOMING offer nobody has answered. */
        val canAccept: Boolean,
        /** Offer Decline, which is also how an incoming offer is refused. */
        val canDecline: Boolean,
        /** 0f..1f, shown only once something is actually moving. */
        val progress: Float,
        val showsProgress: Boolean,
        /** "12 KB of 40 KB · 31%" while moving; the size otherwise. */
        val detail: String = "",
        /** Ended, one way or the other: no buttons, no bar. */
        val finished: Boolean = false,
        /** Ended badly. Rendered in the error colour. */
        val failed: Boolean = false,
        /** One of [Phase]: the state in a single word, for the badge. */
        val phase: String = "",
    )

    /**
     * The transfer phases the screen names, one word each. Derived from the
     * engine's state and progress; never from a timer.
     */
    object Phase {
        const val WAITING = "Waiting"
        const val ACCEPTED = "Accepted"
        const val PREPARING = "Preparing"
        const val SENDING = "Sending"
        const val RECEIVING = "Receiving"
        const val VERIFYING = "Verifying"
        const val COMPLETED = "Completed"
        const val FAILED = "Failed"
        const val CANCELLED = "Cancelled"
        const val DECLINED = "Declined"
    }

    /** The phase for [transfer]. */
    @JvmStatic
    fun phase(transfer: FileTransferView): String {
        val state = transfer.state.ifBlank {
            when {
                transfer.cancelled -> State.CANCELLED
                transfer.accepted -> State.ACCEPTED
                transfer.outgoing -> State.WAITING
                else -> State.OFFERED
            }
        }
        val p = transfer.progress
        return when (state) {
            State.OFFERED, State.WAITING -> Phase.WAITING
            State.ACCEPTED -> when {
                // Accepted, nothing moved yet: the sealed file is being set up.
                p <= 0f -> if (transfer.outgoing) Phase.PREPARING else Phase.ACCEPTED
                // Every chunk is here; the hashes are being checked.
                p >= 1f && !transfer.outgoing -> Phase.VERIFYING
                transfer.outgoing -> Phase.SENDING
                else -> Phase.RECEIVING
            }
            // Ours is out; theirs is checking it against the hashes.
            State.SENT -> Phase.VERIFYING
            State.DELIVERED, State.RECEIVED -> Phase.COMPLETED
            State.DECLINED -> Phase.DECLINED
            State.FAILED -> Phase.FAILED
            else -> Phase.CANCELLED
        }
    }

    /**
     * What to show for one transfer. DRIVEN BY THE ENGINE'S STATE, never by a
     * timer and never by a row having vanished: those are how a transfer
     * came to sit at "transferring" after it had ended.
     *
     * An OUTGOING transfer is never acceptable by the sender, and an
     * incoming one stops being acceptable the moment it has been accepted --
     * a second Accept would be a button that does nothing.
     */
    @JvmStatic
    fun row(transfer: FileTransferView, rate: Rate? = null): Row =
        baseRow(transfer, rate).copy(phase = phase(transfer))

    private fun baseRow(transfer: FileTransferView, rate: Rate?): Row {
        val name = transfer.filename.ifBlank { "a file" }
        val size = humanBytes(transfer.sizeBytes)
        val moving = progressDetail(transfer.progress, transfer.sizeBytes) +
            (rate?.let { " · " + it.text() } ?: "")
        fun ended(label: String, failed: Boolean = false) =
            Row(label, false, false, 0f, false, size, finished = true, failed = failed)
        val state = transfer.state.ifBlank {
            // An older bridge with no state: what the flags can say.
            when {
                transfer.cancelled -> State.CANCELLED
                transfer.accepted -> State.ACCEPTED
                transfer.outgoing -> State.WAITING
                else -> State.OFFERED
            }
        }
        return when (state) {
            State.OFFERED -> Row("$name — $size", canAccept = !transfer.outgoing,
                                 canDecline = true, progress = 0f,
                                 showsProgress = false, detail = size)
            State.WAITING -> Row("Offered $name — waiting for them to accept",
                                 false, true, 0f, false, size)
            State.ACCEPTED -> Row(
                if (transfer.outgoing) "Sending $name" else "Receiving $name",
                false, true, transfer.progress, true, moving)
            State.SENT -> Row(
                "Sent $name — waiting for them to confirm it arrived intact",
                false, false, 1f, true, moving, finished = false)
            State.DELIVERED -> ended("Sent $name — they received it and verified it")
            State.RECEIVED -> ended("Received $name — hashes verified")
            State.DECLINED -> ended(
                if (transfer.outgoing) "$name — they declined it" else "$name — declined")
            State.CANCELLED -> ended("$name — cancelled", failed = false)
            State.FAILED -> ended("$name — failed: ${reasonText(transfer.reason)}", failed = true)
            else -> ended("$name — cancelled")
        }
    }

    /** "12 KB of 40 KB · 31%". Bytes are chunks moved, not bytes confirmed. */
    @JvmStatic
    fun progressDetail(progress: Float, sizeBytes: Long): String {
        val p = progress.coerceIn(0f, 1f)
        val done = (sizeBytes * p).toLong()
        return "${humanBytes(done)} of ${humanBytes(sizeBytes)} · ${(p * 100).toInt()}%"
    }

    // -- speed and ETA ---------------------------------------------------------

    /**
     * Speed and time remaining, as far as they can honestly be said.
     *
     * [bytesPerSecond] is null until two samples a real interval apart have
     * been seen ("Calculating ETA…"); [stalled] means nothing has moved for
     * [RateMeter.STALL_MS] and any ETA would be invented ("ETA unavailable").
     */
    data class Rate(
        val bytesPerSecond: Double?,
        val etaSeconds: Long?,
        val stalled: Boolean = false,
    ) {
        fun text(): String = when {
            stalled -> "ETA unavailable"
            bytesPerSecond == null || etaSeconds == null -> "Calculating ETA…"
            else -> "${humanBytes(bytesPerSecond.toLong())}/s · ETA ${duration(etaSeconds)}"
        }
    }

    /**
     * A rolling, exponentially weighted transfer rate per transfer id.
     *
     * Fed the engine's progress on every redraw; an EWMA rather than
     * "bytes so far / time so far" so a transfer that slows down over I2P
     * shows its CURRENT speed, and rather than the last interval alone so
     * one bursty chunk does not swing the ETA by minutes.
     */
    class RateMeter(private val alpha: Double = 0.3) {
        private class Track(var bytes: Long, var at: Long, var movedAt: Long,
                            var ewma: Double? = null)

        private val tracks = HashMap<String, Track>()

        fun sample(id: String, bytesDone: Long, total: Long, nowMs: Long): Rate {
            val t = tracks[id] ?: Track(bytesDone, nowMs, nowMs).also { tracks[id] = it }
            val dt = nowMs - t.at
            if (bytesDone > t.bytes && dt >= MIN_INTERVAL_MS) {
                val instant = (bytesDone - t.bytes) * 1000.0 / dt
                t.ewma = t.ewma?.let { alpha * instant + (1 - alpha) * it } ?: instant
                t.bytes = bytesDone
                t.at = nowMs
                t.movedAt = nowMs
            } else if (bytesDone < t.bytes) {
                // Restarted from the start: forget the old rate.
                tracks[id] = Track(bytesDone, nowMs, nowMs)
                return Rate(null, null)
            }
            if (nowMs - t.movedAt >= STALL_MS) return Rate(t.ewma, null, stalled = true)
            val rate = t.ewma ?: return Rate(null, null)
            if (rate <= 0.0) return Rate(null, null)
            val remaining = (total - bytesDone).coerceAtLeast(0L)
            return Rate(rate, kotlin.math.ceil(remaining / rate).toLong())
        }

        /** Stop tracking anything not in [live]. */
        fun retain(live: Set<String>) { tracks.keys.retainAll(live) }

        companion object {
            const val MIN_INTERVAL_MS = 250L
            const val STALL_MS = 15_000L
        }
    }

    /** "45 s", "3 min 20 s", "1 h 05 min". */
    @JvmStatic
    fun duration(seconds: Long): String = when {
        seconds < 60 -> "$seconds s"
        seconds < 3600 -> "${seconds / 60} min ${seconds % 60} s"
        else -> "${seconds / 3600} h %02d min".format((seconds % 3600) / 60)
    }

    /** Why a transfer ended badly, for a person. From a fixed set of codes. */
    @JvmStatic
    fun reasonText(reason: String): String = when (reason) {
        "lost_chunk" -> "part of it was lost in transit; ask them to send it again"
        "auth_failed" -> "part of it failed authentication and was discarded"
        "verify_failed" -> "it did not match its hashes and was discarded"
        "transport" -> "the connection failed while sending"
        "by_peer" -> "cancelled by the other side"
        "by_us" -> "cancelled"
        else -> "it did not complete"
    }

    /**
     * The line kept in the conversation when a transfer ends, or null for a
     * state that is not an ending. Persisted with the history, so it
     * survives a restart -- unlike the live row, which is gone with the
     * process that was moving the bytes.
     *
     * SENT gets a line of its own because a peer on an older build never
     * confirms, and "waiting for confirmation" is then the last true thing.
     */
    @JvmStatic
    fun statusLine(state: String, outgoing: Boolean, filename: String, reason: String): String? {
        val name = filename.ifBlank { "a file" }
        return when (state) {
            State.RECEIVED -> "File received successfully — $name (hashes verified)"
            State.DELIVERED -> "File sent successfully — $name (they received it and verified it)"
            State.SENT -> "File sent — $name. Waiting for them to confirm it arrived intact."
            State.DECLINED ->
                if (outgoing) "File declined by the other side — $name"
                else "File declined — $name"
            State.CANCELLED -> "File transfer cancelled — $name" +
                (if (reason == "by_peer") " (by the other side)" else "")
            State.FAILED -> "File transfer failed — $name: ${reasonText(reason)}"
            else -> null
        }
    }

    /** The incoming-file prompt. Name and size, always; nothing auto-accepted. */
    @JvmStatic
    fun promptTitle(): String = "Incoming file"

    @JvmStatic
    fun promptBody(peer: String, filename: String, sizeBytes: Long): String =
        "$peer wants to send you ${filename.ifBlank { "a file" }} " +
            "(${humanBytes(sizeBytes)}). It is encrypted end to end and " +
            "checked against its hashes when it arrives."

    /** A size for a person. Never more precision than it deserves. */
    @JvmStatic
    fun humanBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return "%.0f KB".format(kb)
        val mb = kb / 1024.0
        return "%.1f MB".format(mb)
    }

    /**
     * What to tell the user when a transfer request came back refused.
     *
     * Maps `android_bridge.files.FileOutcome`. Null for "started", which is
     * not a refusal.
     */
    @JvmStatic
    fun refusal(outcome: String): String? = when (outcome) {
        "started" -> null
        "unverified" ->
            "Verify this contact before sending them a file."
        "no_session" ->
            "Start an encrypted session before sending a file."
        "bad_file" ->
            "That file could not be read, or is too large to send."
        "no_transfer" -> "That transfer is no longer available."
        "not_connected" -> "Connect before sending a file."
        "unavailable" -> "File transfer is not available on this device."
        // An outcome this build has not been taught is still a refusal.
        else -> "The file could not be sent."
    }
}
