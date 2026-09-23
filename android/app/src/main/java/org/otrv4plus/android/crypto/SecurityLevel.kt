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
 * WHY A MARK AND A WORD, NOT A PADLOCK
 * ------------------------------------
 * The padlock decision was left open; this is the decision, and why. A
 * padlock is the icon users have been taught means "safe", and it reads the
 * same whether the other end was verified or not -- which is exactly the
 * distinction levels 2 and 3 exist to draw. So each level gets a WORD, which
 * is the primary indication, and a MARK whose SHAPE differs by level, so the
 * three are distinguishable without colour (colour-blind users, monochrome
 * displays, a screenshot described over the phone). Colour is applied by the
 * caller as a supplement and never carries the meaning alone.
 *
 *   NOT_ENCRYPTED         "!"  open alarm
 *   ENCRYPTED_UNVERIFIED  "○"  an empty circle: encrypted, identity unfilled
 *   VERIFIED              "✓"  the only tick in the application
 *   KEY_CHANGED           "⚠"  the warning sign
 *
 * Plain Kotlin, executed by `SecurityLevelTest`; both the conversation list
 * (`RowSecurity`) and the conversation screen take their level from here, so
 * the two surfaces cannot describe one conversation two ways.
 */
object SecurityLevel {

    enum class Level(val mark: String, val label: String) {
        NOT_ENCRYPTED("!", "Not encrypted"),
        ENCRYPTED_UNVERIFIED("○", "Encrypted, unverified"),
        VERIFIED("✓", "Verified"),
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
