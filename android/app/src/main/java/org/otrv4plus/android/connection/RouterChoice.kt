// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

/**
 * Which I2P router the app talks to, decided in one place.
 *
 * The APK carries i2pd ([BundledRouter]), so a phone with no I2P app still
 * connects. A phone that already runs one (the I2P app, i2pd, Termux) keeps
 * using it: two routers on one phone double the battery and bandwidth for
 * nothing, and the user's own router is already integrated into the network.
 *
 * Plain Kotlin with no Android import, so every rule here is executed by a
 * JVM test (`RouterChoiceTest`).
 */
object RouterChoice {

    enum class Use { EXTERNAL, BUILT_IN }

    /** The SAM bridge of a router already on the phone (the I2P default). */
    const val EXTERNAL_SAM_PORT = 7656

    /**
     * Our router's SAM bridge port: random, from this range, chosen at each
     * start (see [BundledRouter.samPort]). Never 7656, so an I2P app the user
     * starts later finds its own port free. i2pd puts the SAM datagram port
     * one below it, which is what voice uses.
     */
    const val BUILT_IN_SAM_PORT_MIN = 20000
    const val BUILT_IN_SAM_PORT_MAX = 60000      // exclusive

    /** A port for our SAM bridge; [nextInt] is a CSPRNG's nextInt(bound). */
    fun pickSamPort(nextInt: (Int) -> Int): Int =
        BUILT_IN_SAM_PORT_MIN + nextInt(BUILT_IN_SAM_PORT_MAX - BUILT_IN_SAM_PORT_MIN)

    /**
     * A port nothing listens on: what a connection attempt gets when our
     * router did not start, so it fails ("refused") rather than reaching
     * whatever happens to be on the default 7656.
     */
    const val NO_SAM_PORT = 1

    /**
     * The rule, and there is no setting (owner, 2026-10-14: "it should just
     * be automatically handled"). An I2P app already running on the phone
     * whose SAM bridge answers is used; otherwise ours starts. A choice the
     * user had to make was a choice they could get wrong -- "My I2P app" with
     * none running failed every connection -- and nobody needs to know which
     * router carried their traffic. [bundled] is whether this APK carries a
     * router at all.
     */
    /** What a router that cannot find its way round I2P makes a connection fail with. */
    private val UNREACHABLE = setOf(
        "i2p_destination_unreachable", "i2p_name_not_found", "i2p_session_failed",
        "server_closed_connection", "timeout",
    )

    /** The built-in router has been up at least this long... */
    const val RESTART_AFTER_UP_MS = 15 * 60_000L
    /** ...and this many attempts in a row have failed reaching the server... */
    const val RESTART_AFTER_FAILURES = 4
    /** ...and it was not itself restarted in this long. */
    const val RESTART_COOLDOWN_MS = 30 * 60_000L

    /**
     * Whether to restart the built-in router. Since rc.100 it runs from one
     * sign-in to the next instead of starting fresh each time; a router that
     * has lost its way round the network (a long sleep, a network change)
     * then fails to reach the server again and again where a fresh one would
     * not (owner, 2026-10-17: "the built-in router worked better around
     * rc.87"). Never for a young router -- that is still settling (rc.98) --
     * and at most once per [RESTART_COOLDOWN_MS], since a restart costs its
     * own 5-10 minutes.
     */
    fun shouldRestart(code: String?, routerUpMs: Long, failuresInARow: Int,
                      sinceLastRestartMs: Long): Boolean =
        code in UNREACHABLE && routerUpMs >= RESTART_AFTER_UP_MS &&
            failuresInARow >= RESTART_AFTER_FAILURES &&
            sinceLastRestartMs >= RESTART_COOLDOWN_MS

    fun decide(externalAnswers: Boolean, bundled: Boolean): Use =
        if (externalAnswers || !bundled) Use.EXTERNAL else Use.BUILT_IN

    /**
     * Whether a sign-in goes over I2P at all. Clearnet (TLS) and Tor accounts
     * need no router, and starting one for them would be traffic the user did
     * not ask for. The route is the explicit server when given, else the
     * account's own domain -- the same rule the bridge's router applies.
     */
    fun needsI2p(jid: String, server: String): Boolean {
        val host = server.trim().ifBlank { jid.substringAfter('@', "").substringBefore('/') }
        return host.lowercase().trimEnd('.').endsWith(".i2p")
    }

    /**
     * i2pd.conf for the bundled router.
     *
     * Owner's choices (2026-10-10): limited transit, so the phone helps the
     * network a little without becoming a relay that drains the battery.
     *
     *  - SAM on loopback only, on a random port. Nothing else listens:
     *    no web console, no HTTP or SOCKS proxy, no BOB, I2CP or I2PControl.
     *  - Transit allowed but small: bandwidth class L (32 KB/s), half of it
     *    for others, at most 50 transit tunnels. Never floodfill.
     *  - No UPnP: the app does not open ports on the user's router.
     *  - Reseed downloads checked against the bundled certificates.
     *  - The address book stays on, so names like otrv4plus.i2p resolve.
     *  - Logs only errors, to a file in the router's private directory.
     */
    fun config(samPort: Int): String = """
        |# Written by OTRv4+ on every start; edits are overwritten.
        |log = file
        |loglevel = error
        |ipv4 = true
        |ipv6 = true
        |floodfill = false
        |notransit = false
        |bandwidth = L
        |share = 50
        |
        |[limits]
        |transittunnels = 50
        |
        |[http]
        |enabled = false
        |
        |[httpproxy]
        |enabled = false
        |
        |[socksproxy]
        |enabled = false
        |
        |[sam]
        |enabled = true
        |address = 127.0.0.1
        |port = $samPort
        |
        |[bob]
        |enabled = false
        |
        |[i2cp]
        |enabled = false
        |
        |[i2pcontrol]
        |enabled = false
        |
        |[upnp]
        |enabled = false
        |
        |[reseed]
        |verify = true
        |
        |[addressbook]
        |enabled = true
        |""".trimMargin()

    /**
     * Whether [path] is [base] or below it (both canonical). Guards the
     * unpacking of i2pd's certificate archive. [base] itself counts: the
     * archive's first entry is the `certificates/` directory, and rc.46
     * refused it, so the router never started (IllegalArgumentException).
     */
    fun isInside(base: java.io.File, path: java.io.File): Boolean =
        path == base || path.path.startsWith(base.path + java.io.File.separator)

    /**
     * A line i2pd printed, made safe to show and record: IPv4 and IPv6
     * addresses, I2P addresses (.b32.i2p, base32/base64 identities) and
     * ports after an address become placeholders, and it is cut to 200
     * characters. The line goes on screen and into diagnostics when the
     * router stops, and i2pd's errors can name peers (security audit,
     * 2026-10-11).
     */
    fun scrub(line: String): String = line
        .replace(Regex("""[A-Za-z0-9]{52}\.b32\.i2p"""), "<i2p-address>")
        .replace(Regex("""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"""), "<ip>")
        .replace(Regex("""\[?(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\]?(?::\d{1,5})?"""), "<ip>")
        .replace(Regex("""[A-Za-z0-9~+/=-]{32,}"""), "<id>")
        .take(200)

    /** What the router is doing, for the connection screen. */
    enum class State {
        NOT_USED, EXTERNAL, STARTING,
        /** Running, SAM not open yet: fetching the router list (reseed). */
        JOINING,
        /** SAM open: the connection is building its tunnels. */
        RUNNING,
        UNAVAILABLE, FAILED,
    }

    /**
     * One line for the connection screen, or null when there is nothing to
     * say. [elapsedMs] is how long the built-in router has been up; [fresh]
     * is whether it has never joined the network on this phone before;
     * [reason] is why it stopped, when it has.
     */
    fun label(state: State, elapsedMs: Long, fresh: Boolean,
              reason: String? = null): String? {
        val elapsed = elapsedMs.coerceAtLeast(0) / 1000
        val clock = "%d:%02d".format(elapsed / 60, elapsed % 60)
        return when (state) {
            State.NOT_USED -> null
            State.EXTERNAL -> "Using the I2P router already on this phone."
            State.STARTING -> "Starting the built-in I2P router..."
            State.JOINING -> if (fresh)
                "Built-in I2P router: downloading the list of I2P routers for its " +
                    "first start ($clock, usually 1 to 5 minutes)."
            else
                "Built-in I2P router: starting up ($clock)."
            State.RUNNING -> if (fresh)
                "Built-in I2P router: joining the I2P network for the first time " +
                    "($clock, usually 2 to 5 minutes)."
            else
                "Built-in I2P router: building tunnels ($clock, usually under a minute)."
            State.UNAVAILABLE -> "No I2P router answered. Start your I2P app with " +
                "its SAM bridge on, or set the I2P router to Automatic."
            State.FAILED -> "The built-in I2P router stopped" +
                (reason?.let { ": $it" } ?: ".")
        }
    }
}
