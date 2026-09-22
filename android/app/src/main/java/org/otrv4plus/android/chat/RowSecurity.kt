// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState

/**
 * What one row of the conversation list says about its security.
 *
 * WHY THE LIST NEEDED THIS AT ALL
 * -------------------------------
 * [Conversation] has carried `security` and `smp` since it was written and
 * the list rendered neither. A user scanning their conversations could not
 * tell an encrypted-and-verified thread from one going out in the clear
 * without opening it, which is the one comparison this application exists to
 * make easy.
 *
 * STILL NOT A PADLOCK
 * -------------------
 * `ConversationScreen` states the rule and it holds here: "Being connected to
 * XMPP says nothing about whether this conversation is encrypted, and the two
 * are easy to blur into a reassuring icon that means the network is up. A
 * padlock next to a plaintext message would be the one claim this project
 * cannot afford to get wrong." So a row gets a WORD, in the same three tones
 * the conversation screen already uses, and the plaintext case is stated
 * rather than left to be inferred from the absence of a badge.
 *
 * DEPENDENCY-FREE ON PURPOSE
 * --------------------------
 * No Compose, no Android. The rules below are the part that can be wrong, and
 * this container cannot build Compose -- so they live where `RowSecurityTest`
 * can execute them and the Composable does nothing but map [Tone] onto the
 * theme. Same split as `crypto/Verification.kt` and `connection/Startup.kt`.
 */
object RowSecurity {

    /** How loudly to say it. Mapped onto the theme by the caller. */
    enum class Tone {
        /** Something is wrong, or nothing is protecting this. */
        ALARM,

        /** True and unremarkable. Encryption without a verified identity. */
        NEUTRAL,

        /** The only state this application will describe as verified. */
        GOOD,
    }

    data class Badge(val text: String, val tone: Tone)

    /**
     * The badge for a row, or null when there is nothing honest to say.
     *
     * Null for the row of somebody never spoken to: `PLAINTEXT` there is not
     * a fact about a conversation, it is the absence of one, and stamping
     * "Not encrypted" on every name in a fresh contact list would make the
     * warning mean nothing by the time it mattered.
     *
     * [hasHistory] is what tells those apart -- a conversation that exists.
     */
    @JvmStatic
    fun badge(
        security: SecurityState,
        smp: SmpState,
        hasHistory: Boolean,
    ): Badge? = when (security) {
        // The loudest state in the application, and it is shown whether or
        // not anything has been said: a key that is not the pinned one is a
        // fact about the CONTACT, and waiting for them to speak first is
        // waiting for the moment it is too late to warn about.
        SecurityState.FINGERPRINT_MISMATCH ->
            Badge("KEY CHANGED", Tone.ALARM)

        SecurityState.PLAINTEXT ->
            if (hasHistory) Badge("Not encrypted", Tone.ALARM) else null

        // ENCRYPTED and FINGERPRINT are deliberately ONE word here.
        //
        // They differ in whether the key matches a previous pin, which is
        // worth a sentence on the conversation screen and is not a
        // distinction a list row can carry without implying it is the same
        // kind of thing as verification. What matters in a list is the line
        // between "somebody checked who this is" and "nobody did", and both
        // of these are on the same side of it.
        SecurityState.ENCRYPTED, SecurityState.FINGERPRINT ->
            if (smp == SmpState.SECRET_REQUIRED)
                // An incoming verification request is a thing to DO, and the
                // list is where the user will see it first.
                Badge("Verification requested", Tone.NEUTRAL)
            else
                Badge("Encrypted, unverified", Tone.NEUTRAL)

        // Reached only when the engine says so. `SmpState` is not consulted
        // for this arm: SMP_VERIFIED is the engine's own answer and a second
        // opinion here could only disagree with it.
        SecurityState.SMP_VERIFIED ->
            Badge("Verified", Tone.GOOD)
    }

    /**
     * Whether [badge] may ever describe a conversation as verified.
     *
     * Exists so the rule is a value a test can assert on rather than a shape
     * a reader has to infer: exactly one [SecurityState] earns [Tone.GOOD],
     * and it is the one the engine derives from a completed SMP run.
     */
    @JvmStatic
    fun statesDescribedAsVerified(): Set<SecurityState> =
        SecurityState.entries
            .filter { state ->
                SmpState.entries.any { smp ->
                    badge(state, smp, hasHistory = true)?.tone == Tone.GOOD
                }
            }
            .toSet()
}
