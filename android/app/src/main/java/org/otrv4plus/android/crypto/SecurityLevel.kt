// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.crypto

import org.otrv4plus.android.bridge.SecurityState

/**
 * The three security levels a conversation can be at, and how every screen
 * marks them.
 *
 * THE MODEL
 * ---------
 *   1. NOT_ENCRYPTED        no OTR session. The server can read it.
 *   2. ENCRYPTED_UNVERIFIED OTR is running; nobody has checked who answered.
 *   3. VERIFIED             OTR is running AND SMP proved who is at the end.
 * plus KEY_CHANGED, which is not a fourth level but the alarm that the key is
 * not the one pinned for this contact -- louder than NOT_ENCRYPTED, because it
 * is the state an attacker produces.
 *
 * Messaging follows the OTR state (levels 2 and 3 encrypt). Calls, files and
 * media are offered only at level 3 -- and REFUSED by the engine below it,
 * whatever the screen shows: this model describes the gate, it is not the
 * gate.
 *
 * A PADLOCK FOR OTR, AND A DIFFERENT ONE FOR VERIFIED
 * ---------------------------------------------------
 * Decided by the project owner for 0.7.0-experimental.rc.2, and chosen to
 * match what the Termux client already shows (`otrv4plus_xmpp._otr_prefix`):
 * an encrypted session IS encrypted, so a padlock on it is not a lie, but
 * the SAME padlock on verified and unverified would give one reassurance for
 * two different facts. So:
 *
 *   NOT_ENCRYPTED         "!"    open alarm. Never a padlock.
 *   ENCRYPTED_UNVERIFIED  "🔒"   OTR is running; nobody checked who answered
 *   VERIFIED              "🔐✓"  lock with key, and the only tick in the app,
 *                               in the verified blue (Termux's 🔵 SMP colour)
 *   KEY_CHANGED           "⚠"    the warning sign. Never a padlock.
 *
 * The WORD stays the primary indication and the shapes differ by level, so
 * the levels remain distinguishable without colour. The padlock is derived
 * from the engine's security state only -- never from connection state.
 *
 * Plain Kotlin, executed by `SecurityLevelTest`; both the conversation list
 * (`RowSecurity`) and the conversation screen take their level from here, so
 * the two surfaces cannot describe one conversation two ways.
 */
object SecurityLevel {

    enum class Level(val mark: String, val label: String) {
        NOT_ENCRYPTED("!", "Not encrypted"),
        ENCRYPTED_UNVERIFIED("\uD83D\uDD12", "Encrypted, unverified"),
        VERIFIED("\uD83D\uDD10\u2713", "Verified"),
        KEY_CHANGED("⚠", "KEY CHANGED"),
    }

    /**
     * The level for an engine state. Exhaustive: a new [SecurityState] must be
     * placed by somebody, not inherit a default.
     *
     * FINGERPRINT (the key matches a previous pin) is level 2, not 3. A pin is
     * a memory of a key, not a check of a person; only SMP is verification.
     */
    @JvmStatic
    fun of(state: SecurityState): Level = when (state) {
        SecurityState.PLAINTEXT -> Level.NOT_ENCRYPTED
        SecurityState.ENCRYPTED, SecurityState.FINGERPRINT -> Level.ENCRYPTED_UNVERIFIED
        SecurityState.SMP_VERIFIED -> Level.VERIFIED
        SecurityState.FINGERPRINT_MISMATCH -> Level.KEY_CHANGED
    }

    /** Whether messages at this level are end-to-end encrypted. */
    @JvmStatic
    fun encrypts(level: Level): Boolean =
        level == Level.ENCRYPTED_UNVERIFIED || level == Level.VERIFIED

    /**
     * Whether calls, files and media are OFFERED at this level. The engine
     * refuses them below it independently; this only decides what is shown.
     */
    @JvmStatic
    fun offersGatedFeatures(level: Level): Boolean = level == Level.VERIFIED

    /** "✓ Verified", and so on: mark first, so it survives truncation. */
    @JvmStatic
    fun marked(level: Level): String = "${level.mark} ${level.label}"
}
