// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * What the Connect screen says about a connection that has not come up yet.
 *
 * Owner report (2026-10-11): with the built-in router a red "failed" appeared
 * at the bottom while the app was still doing what it should -- starting the
 * router, building tunnels, retrying by itself. Every messaging app gets this
 * right: while it is still trying it says so quietly, and it only shows an
 * error for something that is actually wrong.
 *
 * Three kinds of failure, by the stable code the transport reports:
 *
 *   * [Kind.NEEDS_YOU] -- a retry would only repeat it: a wrong password, the
 *     server's I2P key changed, no safe sign-in method, an address that cannot
 *     be right. Retrying stops ([ReconnectPolicy.NEEDS_THE_USER]); shown as an
 *     error with what to do.
 *   * [Kind.TRANSIENT] -- what I2P does while a router integrates, a tunnel
 *     builds or a lease is looked up: timeouts, an unreachable destination, a
 *     stream that closed. Shown as a quiet "still trying" line, and only as an
 *     error once it has repeated [PERSISTENT_AFTER] times in a row.
 *   * anything else -- reported as it is, as before.
 *
 * Plain Kotlin, so a JVM test drives it (ConnectProblemTest).
 */
object ConnectProblem {

    enum class Kind { NEEDS_YOU, TRANSIENT, OTHER }

    /** How a line is shown: not at all, quietly, or as an error. */
    enum class Tone { QUIET, ERROR }

    data class Line(val text: String, val tone: Tone)

    /** The server allows one session per account and another holds it
     *  (Prosody mod_c2s_limit_sessions; docs/SECURITY_SESSIONS.md). */
    const val SESSION_LIMIT = "session_limit"

    const val SESSION_LIMIT_TEXT =
        "This account is already signed in on another device, and the " +
            "server allows one at a time. Sign out there, or wait a few " +
            "minutes if it just lost its connection. If it isn't you, " +
            "change your password."

    /** The server has as many people online as it allows
     *  (prosody/mod_otrv4plus_capacity.lua). Retried: people leave. */
    const val SERVER_FULL = "server_full"

    const val SERVER_FULL_TEXT =
        "The server is full: it has as many people online as it allows. " +
            "The app keeps trying and gets in when someone leaves."

    /** The server is pacing sign-ins (mod_otrv4plus_capacity login_rate).
     *  Retried after a randomised delay; never an alarm. */
    const val SERVER_BUSY = "server_busy"

    const val SERVER_BUSY_TEXT =
        "The server is busy letting people in, a few at a time. The app " +
            "tries again in a moment."

    /** The server closed this session for a newer sign-in of the account
     *  (transport.REPLACED_CODE). Never retried by itself: a retry would sign
     *  the other device out, and that one would do the same back. */
    const val SIGNED_IN_ELSEWHERE = "signed_in_elsewhere"

    /** A server admin banned this account (transport.BANNED_CODE,
     *  prosody/mod_otrv4plus_moderation.lua). Never retried: it would only
     *  be refused again. The detail says until when. */
    const val ACCOUNT_BANNED = "account_banned"

    const val ACCOUNT_BANNED_TEXT =
        "This account is banned from this server by its administrator. " +
            "Sign-in will not work until the ban ends."

    const val SIGNED_IN_ELSEWHERE_TEXT =
        "Signed out: this account signed in on another device, and the " +
            "server keeps only the newest sign-in. Connect again to use it " +
            "here (that signs the other device out). If it wasn't you, " +
            "change your password."

    /**
     * How long the built-in router counts as settling in. A router started
     * minutes ago can send into I2P before other routers can reach it, so
     * the server's replies are lost and its silence looks like a server
     * fault (owner report, 2026-10-16: the i2pd app worked, the built-in
     * router did not).
     */
    const val ROUTER_SETTLING_MS = 15 * 60_000L

    /** Failures that a settling router's lost replies look like. */
    private val SILENT_SERVER: Set<String> = setOf(
        "xmpp_stream_failure", "server_closed_connection", "closed",
        "stream_failed", "timeout",
    )

    /** Failures a young built-in router produces while it settles in. */
    private val SETTLING_FAILURES: Set<String> = SILENT_SERVER + setOf(
        "i2p_destination_unreachable", "i2p_name_not_found", "i2p_session_failed",
    )

    /**
     * Whether [code] is most likely the built-in router still settling in
     * (up less than [ROUTER_SETTLING_MS]). The service then retries every
     * few seconds instead of backing off (ReconnectPolicy.settlingDelayMs):
     * owner's rc.110 timing, "I2P router 0:08, sign-in 5:08, 4 attempts",
     * was 3½ minutes of backoff waiting on a router that was ready.
     */
    fun settling(code: String?, bundledRouterUpMs: Long?): Boolean =
        code != null && bundledRouterUpMs != null &&
            bundledRouterUpMs < ROUTER_SETTLING_MS && code in SETTLING_FAILURES

    fun routerSettling(upMs: Long): String {
        val s = upMs.coerceAtLeast(0) / 1000
        return "The built-in I2P router has been running %d:%02d and other routers cannot ".format(s / 60, s % 60) +
            "reach it yet, so the server's replies are not arriving. Nothing is wrong " +
            "with the server; this clears by itself, usually within 5 to 10 minutes. " +
            "The I2P app, if you have it running, is ready sooner."
    }

    /** Transient failures in a row before one is shown as an error. */
    const val PERSISTENT_AFTER = 3

    /** Codes no retry can fix. Kept equal to ReconnectPolicy.NEEDS_THE_USER. */
    val NEEDS_YOU: Set<String> = setOf(
        "auth_failed", "password_not_applied", "profile_incomplete",
        "i2p_destination_changed", "i2p_name_invalid",
        "tls_required", "certificate_failure", "no_safe_auth_mechanism",
        "route_refused", "malformed_server", "bad_transport", "no_server",
        SIGNED_IN_ELSEWHERE, ACCOUNT_BANNED,
    )

    /** Codes I2P produces on its way up; retrying is the remedy. */
    val TRANSIENT: Set<String> = setOf(
        "timeout", "sam_unavailable", "i2p_session_failed",
        "i2p_destination_unreachable", "i2p_name_not_found", "stream_failed",
        "xmpp_stream_failure", "server_closed_connection", "closed",
        "tls_failed", "connect_failed", "not_connected", "unexpected_error",
    )

    fun kind(code: String?): Kind = when (code) {
        null, "" -> Kind.OTHER
        in NEEDS_YOU -> Kind.NEEDS_YOU
        in TRANSIENT -> Kind.TRANSIENT
        else -> Kind.OTHER
    }

    /**
     * The line for the last failure ([failure], a code), or null to show
     * nothing.
     *
     * [connected]: a session exists, so no earlier verdict applies.
     * [retrying]: the app will try again by itself (an attempt is running or
     * scheduled). [failuresInARow]: consecutive failed attempts.
     */
    fun line(failure: String?, connected: Boolean, retrying: Boolean,
             failuresInARow: Int,
             /** How long the built-in router has run, when it is the one in use. */
             bundledRouterUpMs: Long? = null): Line? {
        if (connected) return null
        val code: String = failure?.takeIf { it.isNotBlank() } ?: return null
        // Our own router is new: the server's silence is most likely its
        // replies failing to reach us, not the server. Said quietly while
        // it retries, as an explanation rather than an alarm.
        if (bundledRouterUpMs != null && bundledRouterUpMs < ROUTER_SETTLING_MS &&
            code in SILENT_SERVER) {
            return Line(routerSettling(bundledRouterUpMs) +
                            if (retrying) " Still trying." else "",
                        if (retrying) Tone.QUIET else Tone.ERROR)
        }
        // The rest of a young router's failures (name not found yet, peer
        // unreachable, session not built). rc.111 retries these every ~10 s,
        // so the three-in-a-row that used to take minutes of backoff came
        // within half a minute, and the first sign-in showed "Can't reach
        // the server" while it was only setting up (rc.82's promise:
        // "setting up", never an alarm). Quiet while it retries.
        if (retrying && settling(code, bundledRouterUpMs)) {
            return Line(stillSettingUp(code, failuresInARow), Tone.QUIET)
        }
        // Not "still setting up": the server refused this sign-in because
        // another session of the account holds its only slot. Said every
        // time; retrying is still right (a session that lost its network is
        // timed out by the server).
        if (code == SERVER_BUSY) return Line(SERVER_BUSY_TEXT, Tone.QUIET)
        if (code == SERVER_FULL) {
            return Line(SERVER_FULL_TEXT, if (retrying) Tone.QUIET else Tone.ERROR)
        }
        if (code == SESSION_LIMIT) {
            return Line(SESSION_LIMIT_TEXT + if (retrying) " Trying again." else "", Tone.ERROR)
        }
        return when (kind(code)) {
            Kind.NEEDS_YOU -> Line(needsYou(code), Tone.ERROR)
            Kind.TRANSIENT -> when {
                failuresInARow >= PERSISTENT_AFTER ->
                    Line(persistent(code) + if (retrying) " Still trying." else "",
                         Tone.ERROR)
                retrying -> Line(stillSettingUp(code, failuresInARow), Tone.QUIET)
                else -> Line(persistent(code), Tone.ERROR)
            }
            Kind.OTHER -> if (retrying) null
                          else Line("The connection did not come up ($code).", Tone.ERROR)
        }
    }

    private fun stillSettingUp(code: String, failuresInARow: Int): String =
        "Still setting up: ${transient(code)} Nothing is wrong; it carries on by itself" +
            (if (failuresInARow > 0) " (try ${failuresInARow + 1})." else ".")

    private fun needsYou(code: String): String = when (code) {
        "auth_failed", "password_not_applied" ->
            "The server refused the sign-in: check the address and password."
        "i2p_destination_changed" ->
            "The server's I2P address now points at a different key. Nothing " +
                "was sent. Check it with the server's owner before trusting it."
        "i2p_name_invalid", "malformed_server", "no_server" ->
            "The server address is not valid. Check it."
        "no_safe_auth_mechanism" ->
            "The server offered no safe sign-in method over I2P (SCRAM), so " +
                "the password was not sent."
        "tls_required", "certificate_failure" ->
            "The server's encryption could not be verified, so nothing was sent."
        "profile_incomplete" -> "Fill in the address and password."
        SIGNED_IN_ELSEWHERE -> SIGNED_IN_ELSEWHERE_TEXT
        ACCOUNT_BANNED -> ACCOUNT_BANNED_TEXT
        else -> "The connection needs your attention ($code)."
    }

    private fun transient(code: String): String = when (code) {
        "timeout" -> "the I2P network is still building the tunnels (a new " +
            "router can need several minutes)."
        "sam_unavailable", "i2p_session_failed" -> "the I2P router is still starting."
        "i2p_destination_unreachable", "i2p_name_not_found" ->
            "the server's I2P address has not been found yet."
        "xmpp_stream_failure", "server_closed_connection", "closed",
        "stream_failed", "tls_failed" -> "the route to the server is still settling."
        else -> "the connection is not up yet."
    }

    private fun persistent(code: String): String = when (code) {
        "i2p_destination_unreachable", "i2p_name_not_found" ->
            "Can't reach the server: its I2P service seems to be offline."
        "timeout" -> "The I2P tunnels to the server keep timing out."
        "sam_unavailable", "i2p_session_failed" -> "The I2P router is not answering."
        "xmpp_stream_failure", "server_closed_connection", "closed",
        "stream_failed", "tls_failed" ->
            "The server answers over I2P, but its chat service is not responding."
        else -> "The connection keeps failing ($code)."
    }
}
