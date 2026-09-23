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
    )

    /**
     * What to show for one transfer.
     *
     * An OUTGOING transfer is never acceptable by the sender, and an
     * incoming one stops being acceptable the moment it has been accepted --
     * a second Accept would be a button that does nothing.
     */
    @JvmStatic
    fun row(transfer: FileTransferView): Row {
        val name = transfer.filename.ifBlank { "a file" }
        if (transfer.cancelled) {
            return Row("$name — cancelled", false, false, 0f, false)
        }
        if (transfer.outgoing) {
            return Row(
                label = if (transfer.accepted) "Sending $name"
                        else "Offered $name — waiting for them to accept",
                canAccept = false,
                canDecline = true,
                progress = transfer.progress,
                showsProgress = transfer.accepted,
            )
        }
        return Row(
            label = if (transfer.accepted) "Receiving $name"
                    else "$name — ${humanBytes(transfer.sizeBytes)}",
            canAccept = !transfer.accepted,
            canDecline = true,
            progress = transfer.progress,
            showsProgress = transfer.accepted,
        )
    }

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
