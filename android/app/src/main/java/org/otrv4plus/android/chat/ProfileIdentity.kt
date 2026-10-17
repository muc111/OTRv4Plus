// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.SecurityDetails
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState

/**
 * The identity section of a profile: whose key, and whether anyone checked.
 * Owner (2026-10-17): "Should the user's fingerprint be on their profile with
 * a button to perform some sort of check?"
 *
 * THE FINGERPRINT IS THE ONE THE SESSION SAW, never one the person
 * publishes. A profile (vCard) is stored on the server and the server can
 * change it; a fingerprint shown from there would let a compromised server
 * vouch for itself. This reads the key from the OTRv4+ session with them
 * (SecurityDetails.peerFingerprint), the same one the key-change alarm and
 * SMP use, and shows nothing at all where there has been no session.
 *
 * Plain Kotlin, so `ProfileIdentityTest` runs it.
 */
object ProfileIdentity {

    data class View(
        /** One sentence: verified, unverified, changed, or no session. */
        val status: String,
        /** Their fingerprint in groups of four, or "" when there is none. */
        val theirs: String,
        /** Ours, in the same groups, for reading aloud side by side. */
        val ours: String,
        /** Whether to offer Verify (a session exists and it is not verified). */
        val offerVerify: Boolean,
        /** Whether the status is a warning. */
        val alarm: Boolean,
    )

    const val COMPARE =
        "To check without a shared secret, read your fingerprints to each " +
            "other in person or on a call. If every group matches, it is them."

    const val OWN_NOTE =
        "Your fingerprint is made on this phone. Signing in again after Wipe & " +
            "Exit, or on a new install, makes a new one, and your contacts are " +
            "warned and asked to verify you again."

    fun of(details: SecurityDetails?): View {
        val theirs = group(details?.peerFingerprint.orEmpty())
        val ours = group(details?.localFingerprint.orEmpty())
        if (details == null || theirs.isEmpty()) {
            return View(
                "No encrypted chat with them yet, so there is no key to show. " +
                    "Open a chat: once it is encrypted, their fingerprint " +
                    "appears here.", "", ours, offerVerify = false, alarm = false)
        }
        return when {
            details.security == SecurityState.FINGERPRINT_MISMATCH -> View(
                "Their key has changed since you last spoke. They may have " +
                    "reinstalled -- or it may not be them. Verify again before " +
                    "trusting anything they send.",
                theirs, ours, offerVerify = true, alarm = true)
            details.smp == SmpState.VERIFIED || details.security == SecurityState.SMP_VERIFIED ->
                View("Verified: you checked that this key is theirs.",
                     theirs, ours, offerVerify = false, alarm = false)
            details.security == SecurityState.PLAINTEXT -> View(
                "Not encrypted right now. This is the key from your last " +
                    "encrypted chat; it has not been verified.",
                theirs, ours, offerVerify = false, alarm = false)
            else -> View(
                "Encrypted, not verified yet: nobody has checked that this key " +
                    "is theirs.", theirs, ours, offerVerify = true, alarm = false)
        }
    }

    /** "ab12cd34..." -> "AB12 CD34 ...": groups of four, for reading aloud. */
    fun group(fingerprint: String): String =
        fingerprint.filter { it.isLetterOrDigit() }.uppercase().chunked(4).joinToString(" ")
}
