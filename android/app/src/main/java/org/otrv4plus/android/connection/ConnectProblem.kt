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

    /** Transient failures in a row before one is shown as an error. */
    const val PERSISTENT_AFTER = 3

    /** Codes no retry can fix. Kept equal to ReconnectPolicy.NEEDS_THE_USER. */
    val NEEDS_YOU: Set<String> = setOf(
        "auth_failed", "password_not_applied", "profile_incomplete",
        "i2p_destination_changed", "i2p_name_invalid",
        "tls_required", "certificate_failure", "no_safe_auth_mechanism",
        "route_refused", "malformed_server", "bad_transport", "no_server",
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
             failuresInARow: Int): Line? {
        if (connected) return null
        val code: String = failure?.takeIf { it.isNotBlank() } ?: return null
        return when (kind(code)) {
            Kind.NEEDS_YOU -> Line(needsYou(code), Tone.ERROR)
            Kind.TRANSIENT -> when {
                failuresInARow >= PERSISTENT_AFTER ->
                    Line(persistent(code) + if (retrying) " Still trying." else "",
                         Tone.ERROR)
                retrying -> Line("Still setting up: ${transient(code)} " +
                                 "Nothing is wrong; it carries on by itself" +
                                 (if (failuresInARow > 0) " (try ${failuresInARow + 1})."
                                  else "."), Tone.QUIET)
                else -> Line(persistent(code), Tone.ERROR)
            }
            Kind.OTHER -> if (retrying) null
                          else Line("The connection did not come up ($code).", Tone.ERROR)
        }
    }

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
