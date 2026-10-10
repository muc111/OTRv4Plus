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

    /** What the user picked. Stored by name; unknown names read as AUTOMATIC. */
    enum class Mode(val stored: String) {
        /** A router already on the phone if its SAM bridge answers, else ours. */
        AUTOMATIC("auto"),
        /** Only the phone's own I2P app; never start ours. */
        EXTERNAL("external"),
        /** Always ours, even when another router is running. */
        BUILT_IN("builtin");

        companion object {
            fun fromStored(value: String?): Mode =
                entries.firstOrNull { it.stored == value } ?: AUTOMATIC
        }
    }

    /** Which router a connection attempt uses. */
    enum class Use { EXTERNAL, BUILT_IN }

    /** The SAM bridge of a router already on the phone (the I2P default). */
    const val EXTERNAL_SAM_PORT = 7656

    /**
     * Our router's SAM bridge. Not 7656, so an I2P app the user starts later
     * finds its own port free and the two are never confused. i2pd puts the
     * SAM datagram port one below this (17655), which is what voice uses.
     */
    const val BUILT_IN_SAM_PORT = 17656

    /** The rule. [bundled] is whether this APK carries a router at all. */
    fun decide(mode: Mode, externalAnswers: Boolean, bundled: Boolean): Use = when {
        !bundled -> Use.EXTERNAL
        mode == Mode.EXTERNAL -> Use.EXTERNAL
        mode == Mode.BUILT_IN -> Use.BUILT_IN
        externalAnswers -> Use.EXTERNAL
        else -> Use.BUILT_IN
    }

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
     *  - SAM on loopback only, on [BUILT_IN_SAM_PORT]. Nothing else listens:
     *    no web console, no HTTP or SOCKS proxy, no BOB, I2CP or I2PControl.
     *  - Transit allowed but small: bandwidth class L (32 KB/s), half of it
     *    for others, at most 50 transit tunnels. Never floodfill.
     *  - No UPnP: the app does not open ports on the user's router.
     *  - Reseed downloads checked against the bundled certificates.
     *  - The address book stays on, so names like otrv4plus.i2p resolve.
     *  - Logs only errors, to a file in the router's private directory.
     */
    fun config(samPort: Int = BUILT_IN_SAM_PORT): String = """
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
