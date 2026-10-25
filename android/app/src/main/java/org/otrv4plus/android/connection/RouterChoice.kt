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
     * [decide] from the probe, remembering whether the phone's router has
     * answered SAM before in this run ([externalSeen]).
     *
     * Owner report (2026-10-25): the account was created through i2pd running
     * on the phone, then the sign-in that followed started the built-in router
     * -- minutes of warm-up -- although i2pd was still there. A SAM bridge busy
     * with the session just closed can accept the connection and answer the
     * HELLO late. [Probe.SLOW] from a router that already answered in this run
     * is that router being busy, not gone: it is used again. A router never
     * seen to answer gets no such benefit (an I2P app still starting accepts
     * and then fails every sign-in, and the built-in router must get its turn),
     * and a closed port ([Probe.NO_ANSWER]) is never sticky.
     */
    fun decide(probe: Probe, bundled: Boolean, externalSeen: Boolean): Use = when {
        probe == Probe.SAM -> Use.EXTERNAL
        !bundled -> Use.EXTERNAL
        probe == Probe.SLOW && externalSeen -> Use.EXTERNAL
        else -> Use.BUILT_IN
    }

    /**
     * What is on [EXTERNAL_SAM_PORT]. Only [SAM] counts as a router on the
     * phone. [SLOW]: it accepted the connection but sent no reply in time;
     * [NOT_SAM]: it replied, and not as a SAM bridge agreeing to talk.
     */
    enum class Probe { SAM, NOT_SAM, SLOW, NO_ANSWER }

    /** The HELLO the probe sends: the one our tunnels send (otrv4plus_tunnels). */
    const val SAM_HELLO = "HELLO VERSION MIN=3.1 MAX=3.1\n"

    /** Whether [reply] is a SAM bridge agreeing to talk. */
    fun isSamHello(reply: String?): Boolean =
        reply != null && reply.startsWith("HELLO REPLY") && " RESULT=OK" in reply

    /**
     * Ask whatever listens on loopback [port] for a SAM HELLO. An open port
     * is not enough: an I2P app still starting, or another program on 7656,
     * accepts the connection and then fails every sign-in, and the built-in
     * router -- which would have worked -- never got a turn.
     */
    fun probeSam(port: Int, timeoutMs: Int = 1_500): Probe {
        var connected = false
        return try {
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress("127.0.0.1", port), timeoutMs)
                connected = true
                s.soTimeout = timeoutMs
                s.getOutputStream().apply {
                    write(SAM_HELLO.toByteArray(Charsets.US_ASCII)); flush()
                }
                val input = s.getInputStream()
                val line = StringBuilder()
                while (line.length < 256) {
                    val b = input.read()
                    if (b < 0 || b == '\n'.code) break
                    line.append(b.toChar())
                }
                when {
                    isSamHello(line.toString()) -> Probe.SAM
                    line.isEmpty() -> Probe.SLOW
                    else -> Probe.NOT_SAM
                }
            }
        } catch (_: java.net.SocketTimeoutException) {
            if (connected) Probe.SLOW else Probe.NO_ANSWER
        } catch (_: Exception) {
            if (connected) Probe.NOT_SAM else Probe.NO_ANSWER
        }
    }

    /**
     * [probeSam], asked [tries] times [gapMs] apart until a router answers:
     * an I2P app opened a moment ago may take a second to open its bridge.
     */
    fun findExternalSam(port: Int = EXTERNAL_SAM_PORT, tries: Int = 3, gapMs: Long = 400,
                        probe: (port: Int, timeoutMs: Int) -> Probe = { p, t -> probeSam(p, t) },
                        sleep: (Long) -> Unit = { Thread.sleep(it) }): Probe {
        var last = Probe.NO_ANSWER
        repeat(tries) { i ->
            last = probe(port, PROBE_TIMEOUTS_MS[minOf(i, PROBE_TIMEOUTS_MS.size - 1)])
            if (last == Probe.SAM) return last
            if (i < tries - 1) sleep(gapMs)
        }
        return last
    }

    /**
     * Each try's wait for the HELLO reply, longer each time. A closed port
     * fails at once whatever this is, so a phone with no I2P app still starts
     * the built-in router without delay; only a bridge that accepted and is
     * slow to answer is waited for -- seconds, against the built-in router's
     * minutes of warm-up if it were started for nothing.
     */
    val PROBE_TIMEOUTS_MS = intArrayOf(1_500, 3_000, 6_000)

    /**
     * Whether a sign-in goes over I2P at all. Clearnet (TLS) and Tor accounts
     * need no router, and starting one for them would be traffic the user did
     * not ask for. The route is the explicit server when given, else the
     * account's own domain -- the same rule the bridge's router applies.
     */
    fun needsI2p(jid: String, server: String): Boolean {
        val typed = server.trim().ifBlank { jid.substringAfter('@', "").substringBefore('/') }
        // The port is not part of the name (route.py's _split_port): without
        // this, "chat.i2p:5222" started no router while the bridge sent the
        // connection to I2P. tests/test_route_parity.py holds the two together.
        val host = when {
            typed.startsWith("[") -> typed.substringAfter('[').substringBefore(']')
            typed.count { it == ':' } == 1 -> typed.substringBefore(':')
            else -> typed
        }
        return host.lowercase().trimEnd('.').endsWith(".i2p")
    }

    /**
     * i2pd.conf for the bundled router.
     *
     * Owner's choices: no transit (2026-10-17, replacing the "limited
     * transit" of 2026-10-10). The router now stays up between connections
     * (rc.100), and relaying other people's tunnels was the largest battery
     * cost the user gets nothing from. Our own tunnels, and so sign-in and
     * call speed, are unaffected.
     *
     *  - SAM on loopback only, on a random port. Nothing else listens:
     *    no web console, no HTTP or SOCKS proxy, no BOB, I2CP or I2PControl.
     *  - No transit: other people's tunnels are refused (notransit), and
     *    the limit below stays as a backstop. Bandwidth class L
     *    (32 KB/s). Never floodfill.
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
        |notransit = true
        |bandwidth = L
        |share = 0
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
                "its SAM bridge on (port 7656)."
            State.FAILED -> "The built-in I2P router stopped" +
                (reason?.let { ": $it" } ?: ".")
        }
    }
}
