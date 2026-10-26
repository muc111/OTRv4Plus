// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * U1: what can be on screen while signed out, and where back goes.
 *
 * Device report (2026-10-26): signed out (not wiped), Sign in -> About ->
 * back landed on the empty chat list, and from there the device's identity
 * fingerprint could be read -- device-binding material that a server's
 * login record could later be matched against. Only the public screens may
 * show while signed out, and their back always goes to sign-in.
 *
 * Generic over the screen type so the app's private enum stays private and
 * this stays plain Kotlin (`AuthGateTest`).
 */
object AuthGate {

    /** The screen to show: [wanted] if allowed, else [login]. */
    fun <S> shown(wanted: S, signedIn: Boolean, public: Set<S>, login: S): S =
        if (signedIn || wanted in public) wanted else login

    /** Back from a public screen (About, Debug): home only when signed in. */
    fun <S> back(signedIn: Boolean, home: S, login: S): S = if (signedIn) home else login
}
