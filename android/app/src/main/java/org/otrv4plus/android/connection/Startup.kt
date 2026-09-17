// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * Whether a start command should become a connection attempt.
 *
 * THE BUG THIS EXISTS FOR
 * -----------------------
 * The app tried to connect the instant it was opened, before anybody had
 * typed anything. On a fresh install the only way to reach the login form was
 * to wait for the attempt, press Cancel, and then sign in.
 *
 * `OtrConnectionService.onStartCommand` handled ACTION_START like this:
 *
 *     if (account.isNotBlank()) { ...use the Intent's credentials... }
 *     else { credentials.load()?.let { ...use the stored ones... } }
 *     startConnection()
 *
 * `startConnection()` is outside the `else`, and `load()` returns null when
 * nothing has been stored. So a first launch fell through the `let`, left
 * `jid` as `""`, and connected anyway: `enterAccount(NONE)`,
 * `reconnect.onUserConnect()` clearing the suppression latch, and
 * `connectLoop` entering CONNECTING and calling `prepareConnection("", "")`.
 * That builds I2P tunnels, fails, and BACKS OFF AND RETRIES, which is why it
 * could not simply be waited out.
 *
 * It is a state-machine fault and it is fixed here rather than by a guard on
 * the screen. A UI guard would leave the service's own resume path -- and a
 * restart of the service by anything other than the Activity -- still able to
 * connect as nobody, and the condition would be stated in two places that
 * could disagree.
 *
 * WHAT MUST STILL WORK
 * --------------------
 * Resuming a remembered session. Somebody who signed in yesterday should not
 * be shown a login form because the process restarted, and [Decision.CONNECT]
 * for a stored account is the whole reason `resume()` exists. The rule is not
 * "only connect when the user just typed it" -- it is "only connect when
 * there is an account to connect AS".
 *
 * Plain Kotlin, no Android import, so the rule is executed by a JVM test
 * rather than reviewed.
 */
object Startup {

    /** What to do with a start command. */
    enum class Decision {
        /** There is an account. Go. */
        CONNECT,

        /**
         * There is not. Do nothing and let the user sign in.
         *
         * Not an error and not a failure: nothing is wrong on a first launch,
         * and reporting one would put a red line above an empty login form.
         */
        WAIT,
    }

    /**
     * The account a start command should connect as, or null for none.
     *
     * [intentJid]/[intentPassword] are what the Intent carried -- an explicit
     * Connect. [storedJid]/[storedPassword] are what the vault holds. The
     * Intent wins when it has a JID: somebody who just typed an account is
     * asking for that one, not for the one that happens to be remembered.
     */
    fun accountFor(
        intentJid: String?,
        intentPassword: String?,
        storedJid: String?,
        storedPassword: String?,
    ): Account? {
        usable(intentJid, intentPassword)?.let { return it }
        return usable(storedJid, storedPassword)
    }

    /**
     * [Decision.CONNECT] only when [accountFor] found an account.
     *
     * Deliberately derived from the same call rather than re-tested, so
     * "should we connect" and "who as" cannot answer differently.
     */
    fun decide(
        intentJid: String?,
        intentPassword: String?,
        storedJid: String?,
        storedPassword: String?,
    ): Decision =
        if (accountFor(intentJid, intentPassword, storedJid, storedPassword)
            != null) Decision.CONNECT else Decision.WAIT

    /** An account to connect as. The password is not printed. */
    class Account(val jid: String, val password: String) {
        override fun toString(): String = "Account(jid=$jid, password=<redacted>)"
    }

    /**
     * A pair that can actually be connected with, or null.
     *
     * A JID with no `@` is not an account -- `alice` alone would share a
     * namespace with `alice` on every other server, which is the same rule
     * `AccountScope.of` applies. A BLANK PASSWORD is refused too: a truncated
     * or half-written vault record would otherwise become an attempt that
     * fails authentication over and over, which looks to the user exactly
     * like the bug this file is about.
     */
    private fun usable(jid: String?, password: String?): Account? {
        val account = jid.orEmpty().trim()
        val secret = password.orEmpty()
        if (account.isEmpty() || !account.contains('@')) return null
        if (account.startsWith("@") || account.endsWith("@")) return null
        if (secret.isEmpty()) return null
        return Account(account, secret)
    }
}
