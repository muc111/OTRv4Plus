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
        /** One sentence: what has been checked, and how. */
        val status: String,
        /** Their fingerprint in groups of four, or "" when there is none. */
        val theirs: String,
        /** Ours, in the same groups, for reading aloud side by side. */
        val ours: String,
        /** Whether to offer the shared-secret check (SMP). */
        val offerVerify: Boolean,
        /** Whether to offer "They match" after comparing fingerprints. */
        val offerConfirm: Boolean,
        /** Whether the status is a warning. */
        val alarm: Boolean,
    )

    /**
     * TWO CHECKS, TWO NAMES (owner, 2026-10-17: "It should not be confused
     * with SMP verified"). Comparing fingerprints is "Fingerprint
     * confirmed": the person says the groups matched. The shared-secret
     * check is "Verified (shared secret)": SMP, run by the app, and the only
     * one that unlocks calls and files. Neither is ever called by the
     * other's name.
     */
    const val CONFIRMED = "Fingerprint confirmed"
    const val VERIFIED = "Verified (shared secret)"

    const val COMPARE =
        "To check without a shared secret, read your fingerprints to each " +
            "other in person or on a call. If every group matches, tap " +
            "\u201cThey match\u201d."

    const val CONFIRM_TITLE = "Do the fingerprints match?"
    const val CONFIRM_BODY =
        "Only if you compared every group with them, in person or on a call " +
            "where you know their voice. A message from the account itself " +
            "proves nothing: whoever holds the key could send it. This records " +
            "the key as confirmed by you; calls and files still need the " +
            "shared-secret check."
    const val CONFIRM_BUTTON = "They match"

    const val OWN_NOTE =
        "Your fingerprint is made on this phone. Signing in again after Wipe & " +
            "Exit, or on a new install, makes a new one, and your contacts are " +
            "warned and asked to check you again."

    fun of(details: SecurityDetails?): View {
        val theirs = group(details?.peerFingerprint.orEmpty())
        val ours = group(details?.localFingerprint.orEmpty())
        if (details == null || theirs.isEmpty()) {
            return View(
                "No encrypted chat with them yet, so there is no key to show. " +
                    "Open a chat: once it is encrypted, their fingerprint " +
                    "appears here.", "", ours,
                offerVerify = false, offerConfirm = false, alarm = false)
        }
        val smp = details.smp == SmpState.VERIFIED || details.security == SecurityState.SMP_VERIFIED
        return when {
            details.security == SecurityState.FINGERPRINT_MISMATCH -> View(
                "Their key has changed since you last spoke. They may have " +
                    "reinstalled -- or it may not be them. Check again before " +
                    "trusting anything they send.",
                theirs, ours, offerVerify = true, offerConfirm = true, alarm = true)
            smp && details.trusted -> View(
                "$VERIFIED, and $CONFIRMED: both checks say this key is theirs.",
                theirs, ours, offerVerify = false, offerConfirm = false, alarm = false)
            smp -> View(
                "$VERIFIED: you and they proved the same secret, so this key is theirs.",
                theirs, ours, offerVerify = false, offerConfirm = true, alarm = false)
            details.trusted -> View(
                "$CONFIRMED by you: you compared fingerprints and they matched. " +
                    "Calls and files also need the shared-secret check.",
                theirs, ours, offerVerify = true, offerConfirm = false, alarm = false)
            details.security == SecurityState.PLAINTEXT -> View(
                "Not encrypted right now. This is the key from your last " +
                    "encrypted chat; nobody has checked it.",
                theirs, ours, offerVerify = false, offerConfirm = false, alarm = false)
            else -> View(
                "Encrypted, not checked yet: nobody has confirmed that this key " +
                    "is theirs.", theirs, ours,
                offerVerify = true, offerConfirm = true, alarm = false)
        }
    }

    /** "ab12cd34..." -> "AB12 CD34 ...": groups of four, for reading aloud. */
    fun group(fingerprint: String): String =
        fingerprint.filter { it.isLetterOrDigit() }.uppercase().chunked(4).joinToString(" ")
}
