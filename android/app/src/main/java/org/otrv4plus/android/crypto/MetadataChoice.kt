// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.MetadataFinding

/**
 * Whether to ask about a file's metadata, and what to say.
 *
 * The scrubbing is in Python (`android_bridge.metadata`), where it is driven
 * against real photographs. This decides only the conversation with the
 * user, and is dependency-free so `MetadataChoiceTest` executes it.
 *
 * ASK ONLY WHEN THERE IS A REAL CHOICE. A question about an image with
 * nothing to remove teaches people to dismiss the question, and then the
 * one that matters gets dismissed too. So: a scrubbable file that carries
 * metadata is asked about; one that carries none is sent; one the app cannot
 * check is sent with a plain statement that it could not check -- never
 * with an implication that it is clean.
 */
object MetadataChoice {

    sealed interface Next {
        /** Nothing to decide. Send as it is. */
        data object Send : Next

        /** Ask: remove the metadata, or send as it is. */
        data class Ask(val question: String) : Next

        /**
         * The app cannot check this kind of file. Send, and say so plainly
         * rather than let silence read as "checked and clean".
         */
        data class SendUnchecked(val notice: String) : Next
    }

    @JvmStatic
    fun next(finding: MetadataFinding): Next = when {
        !finding.canScrub -> Next.SendUnchecked(UNCHECKED)
        finding.carriesMetadata -> Next.Ask(
            "This image carries ${finding.metadataBytes} bytes of " +
            "metadata — typically where and when it was taken, and on " +
            "what device. Remove it before sending?")
        else -> Next.Send
    }

    /** The button that removes it. Listed first: it is the private choice. */
    const val STRIP = "Remove and send"

    /** The button that keeps it. The user's call, and honoured exactly. */
    const val KEEP = "Send as it is"

    const val UNCHECKED =
        "The app cannot check this kind of file for hidden information. " +
        "It was sent exactly as it is."
}
