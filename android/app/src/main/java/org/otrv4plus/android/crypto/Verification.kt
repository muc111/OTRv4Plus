// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SmpState

/**
 * What the conversation screen may offer for identity verification, and when.
 *
 * WHAT SMP IS FOR, RESTATED BECAUSE EVERY RULE HERE FOLLOWS FROM IT
 * -----------------------------------------------------------------
 * A completed DAKE means the conversation is encrypted **to somebody**.
 * Nobody has checked who. SMP is the check: both sides prove they know a
 * passphrase agreed out of band, without transmitting it, and a pass is the
 * only thing in this application that means *identity verified*.
 *
 *     OTR encrypted  !=  identity verified
 *     SMP verified    =  identity verified
 *
 * That distinction is why [SecurityState] has four rungs rather than a
 * boolean, and it is why this file exists as its own tested unit: the UI must
 * never collapse them.
 *
 * NO CRYPTOGRAPHY HAPPENS HERE, OR ANYWHERE ELSE IN KOTLIN
 * --------------------------------------------------------
 * The proof is `Rust/src/smp.rs` — X448 with hybrid ML-KEM-1024 / ML-DSA-87
 * and the zero-knowledge proofs, over secrets held in `SecretVec` with
 * `ZeroizeOnDrop`. Python's `OtrApp` is a facade over it and this is a
 * decision table over that facade's reported state. There is exactly one SMP
 * implementation in this project and it is not in this language.
 *
 * WHY A PLAIN-KOTLIN LEAF
 * -----------------------
 * No Android import, so every rule below is EXECUTED by `VerificationTest` on
 * the JVM rather than reviewed in a Composable that CI can only compile. The
 * same reason [EncryptionSelector] and `ChatState` are shaped this way.
 */
object Verification {

    /** What the one control on the conversation screen should currently be. */
    enum class Offer {
        /** Nothing to show. There is no encrypted session to verify. */
        HIDDEN,

        /** "Verify Identity" — this side may start a run. */
        VERIFY,

        /** A run is under way; show progress, offer only cancel. */
        IN_PROGRESS,

        /** The peer is waiting on our passphrase. The prompt is already up. */
        ANSWERING,

        /** "Identity Verified ✓". Done, and not a button. */
        VERIFIED,
    }

    /** Why a prompt is open, which decides which words it uses. */
    enum class Prompt {
        /** We tapped Verify. "Enter the shared passphrase agreed…" */
        OUTGOING,

        /** Their SMP1 is held. "<peer> wants to verify your identity." */
        INCOMING,
    }

    /**
     * The passphrase length the engine will actually accept.
     *
     * `EnhancedOTRSession.set_smp_secret` raises below 8 and `otrv4+.py`
     * defines both bounds. Restated here so the dialog can disable its own
     * Verify button rather than letting a user type seven characters, wait for
     * a round trip, and be told no — but the engine remains the authority and
     * still enforces it.
     */
    const val MIN_SECRET = 8
    const val MAX_SECRET = 512

    /**
     * Whether SMP may run at all on this conversation.
     *
     * PLAINTEXT is the only refusal. A proof needs a session to bind to;
     * without one it would prove nothing about anybody.
     *
     * FINGERPRINT_MISMATCH is deliberately ALLOWED. That conversation is
     * encrypted, to somebody, and SMP is one of the few things that can tell
     * the user which somebody — refusing it there would withdraw the remedy at
     * the moment it is most needed.
     */
    fun available(security: SecurityState): Boolean =
        security != SecurityState.PLAINTEXT

    /**
     * What to show, from the two states the UI already has.
     *
     * [smp] wins over [security] for the in-flight states because it is the
     * finer reading: a run can be under way while the level is still
     * ENCRYPTED, which is the normal case and not a contradiction.
     */
    fun offer(security: SecurityState, smp: SmpState): Offer = when {
        !available(security) -> Offer.HIDDEN
        smp == SmpState.VERIFIED -> Offer.VERIFIED
        // The level is authoritative for a COMPLETED verification even when
        // the SMP object has been destroyed and its phase has moved on --
        // which is exactly what happens after an auto-SMP.
        security == SecurityState.SMP_VERIFIED -> Offer.VERIFIED
        smp == SmpState.SECRET_REQUIRED -> Offer.ANSWERING
        smp == SmpState.IN_PROGRESS -> Offer.IN_PROGRESS
        // FAILED and CANCELLED both offer another attempt. Neither is a dead
        // end: a failure may be a typo on either side, and a cancel is not a
        // statement about the peer at all.
        else -> Offer.VERIFY
    }

    /**
     * Whether a prompt should be open, and which one.
     *
     * [requested] is the user having tapped Verify. [secretRequired] is the
     * engine reporting a peer's SMP1 is held.
     *
     * INCOMING WINS. If both are true, the peer's request is already in the
     * core waiting to be answered, and starting a competing run would be the
     * wrong operation — `smpRespond` resumes the held message, `smpStart`
     * would begin a second one.
     */
    fun prompt(
        security: SecurityState,
        secretRequired: Boolean,
        requested: Boolean,
    ): Prompt? = when {
        !available(security) -> null
        secretRequired -> Prompt.INCOMING
        requested -> Prompt.OUTGOING
        else -> null
    }

    /**
     * Whether a typed passphrase may be submitted.
     *
     * Not a security control — the engine enforces the bound and would refuse
     * — but it stops the UI presenting an action that is certain to fail.
     */
    fun acceptable(secret: String): Boolean =
        secret.length in MIN_SECRET..MAX_SECRET

    /**
     * The sentence shown beneath the passphrase field.
     *
     * Names the out-of-band agreement in both directions, because a user who
     * invents a passphrase on the spot has verified nothing — the security of
     * SMP is entirely in the secret having been agreed over a channel an
     * attacker does not control.
     */
    /**
     * How long an identity -- and so a verification -- lasts on this device.
     *
     * Decision B1: the engine is built with `OTRConfig()`, whose
     * `persist_identity` is false, so every launch generates a new Ed448
     * identity and nothing about the old one survives. That is deliberate and
     * is not changed here; what was missing is that nothing told the user.
     * A verification is a proof about a key, so it ends with the key, and
     * every contact who pinned the old one will see a key-change warning for
     * the new one. Saying so up front is what stops that warning being
     * learned as noise.
     */
    const val IDENTITY_LIFETIME: String =
        "Your identity on this device is new each time the app starts. " +
            "Nothing about it is kept after you close the app. Contacts who " +
            "saved your previous key will be warned that it changed, and any " +
            "verification has to be done again."

    /** Appended to a successful verification: it is not permanent. */
    const val VERIFIED_UNTIL: String =
        "This lasts until the app closes: your identity is new each launch."

    fun explanation(prompt: Prompt, peer: String): String = when (prompt) {
        Prompt.OUTGOING ->
            "Enter the passphrase you agreed with this contact in person or " +
                "over another channel. They must enter the same text."
        Prompt.INCOMING ->
            "$peer wants to verify your identity. Enter the passphrase you " +
                "agreed with them in person or over another channel."
    }

    /**
     * What to say about an outcome.
     *
     * FAILED and CANCELLED say different things, and the difference is the
     * whole reason they are separate states. A failed proof means the two
     * passphrases did not match — which is either a typo or somebody is not
     * who they claim — and the user must be told the second possibility
     * exists. A cancel means nobody proved anything and says nothing at all
     * about the peer.
     */
    fun outcome(state: SmpState): String? = when (state) {
        SmpState.VERIFIED ->
            "Identity verified. You are talking to the person who knows the " +
                "shared passphrase. $VERIFIED_UNTIL"
        SmpState.FAILED ->
            "Verification failed. The passphrases did not match — check you " +
                "both entered the same text. If they did, this may not be " +
                "who you think it is."
        SmpState.CANCELLED ->
            "Verification cancelled. Nothing was verified, and this says " +
                "nothing about your contact."
        else -> null
    }

    /**
     * Whether a call may be offered.
     *
     * NOT THE GATE ITSELF, and this must never be mistaken for it. The gate is
     * `VoiceCallManager._smp_verified`, a cryptographic predicate in the
     * engine; this only decides whether a button is drawn. The rule is
     * restated rather than relaxed: voice stays unavailable until SMP has
     * passed, so an unverified peer is never offered a call.
     */
    fun callOffered(security: SecurityState, smp: SmpState): Boolean =
        security == SecurityState.SMP_VERIFIED || smp == SmpState.VERIFIED
}
