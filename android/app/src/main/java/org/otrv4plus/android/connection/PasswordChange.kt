// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * Changing the account's password: the checks made before anything is sent,
 * and what the result says.
 *
 * The current password is asked for even though the app already holds it,
 * so that someone holding an unlocked device cannot lock its owner out. The
 * ENGINE compares it, in constant time, with the one the stream signed in
 * with (transport.change_password), and never sends it to the server:
 * XEP-0077 §3.3 trusts the signed-in stream. Not here: the vault is
 * Kotlin's only cryptography (CRYPTO_SOURCE_OF_TRUTH.md).
 *
 * Plain Kotlin, so a JVM test drives it (PasswordChangeTest).
 */
object PasswordChange {

    /** The same floor as account creation (otrv4plus_registration.MIN_PASSWORD). */
    const val MIN_LENGTH = 8

    const val TITLE = "Change password"

    const val NOT_CONNECTED = "Connect first: the password is changed on the server."

    const val EXPLAINED =
        "Changes the password on your server. Do this if the app warned that " +
            "your account is signed in on another device: signing that device " +
            "out does not stop it signing in again, a new password does. Your " +
            "messages stay encrypted with your keys either way."

    /** Why the change cannot be sent, or null when it can. */
    fun problem(current: String, new: String, confirm: String): String? = when {
        current.isEmpty() -> "Enter your current password."
        new.length < MIN_LENGTH -> "The new password must be at least $MIN_LENGTH characters."
        new == current -> "The new password is the same as the current one."
        new != confirm -> "The two new passwords do not match."
        else -> null
    }

    /** What to say once the server has answered. */
    fun result(ok: Boolean, detail: String, saved: Boolean): String = when {
        ok && saved ->
            "Password changed. This device stays signed in; anyone using the " +
                "old password can no longer sign in."
        ok -> "Password changed on the server, but this device could not save " +
            "it: you will be asked for it the next time you sign in."
        else -> detail.ifBlank { "The password was not changed." }
    }
}
