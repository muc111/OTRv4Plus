// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertNotNull

/**
 * Whether opening the app should connect.
 *
 * THE DEFECT. It always did. `OtrConnectionService.onStartCommand` called
 * `startConnection()` outside the `else` that loaded stored credentials, so a
 * first launch -- where `credentials.load()` returns null -- connected with
 * `jid` still `""`. That is not a no-op: it cleared the reconnect
 * suppression latch, entered CONNECTING, built I2P tunnels for an empty
 * account, failed, and BACKED OFF AND RETRIED. The only way to reach the
 * login form was to press Cancel first.
 *
 * Three cases, and all three are here because fixing the first by breaking
 * the third would be the obvious wrong answer:
 *
 *   1. first launch, nothing stored        -> no attempt
 *   2. the user pressed Connect            -> attempt, with what they typed
 *   3. a remembered account, process restarted -> attempt, with the stored one
 */
class StartupTest {

    private fun decide(
        intentJid: String? = null, intentPassword: String? = null,
        storedJid: String? = null, storedPassword: String? = null,
    ) = Startup.decide(intentJid, intentPassword, storedJid, storedPassword)

    private fun accountFor(
        intentJid: String? = null, intentPassword: String? = null,
        storedJid: String? = null, storedPassword: String? = null,
    ) = Startup.accountFor(intentJid, intentPassword, storedJid, storedPassword)

    // ── 1. first launch ──────────────────────────────────────────────────────

    @Test
    fun `a first launch with nothing stored does not connect`() {
        // THE BUG, stated as one line. Everything else in this file exists to
        // stop the fix for it breaking something.
        assertEquals(Startup.Decision.WAIT, decide())
    }

    @Test
    fun `a first launch has no account to connect as`() {
        assertNull(accountFor())
    }

    @Test
    fun `an empty stored record does not become an attempt`() {
        assertEquals(Startup.Decision.WAIT,
                     decide(storedJid = "", storedPassword = ""))
    }

    // ── 2. the user pressed Connect ──────────────────────────────────────────

    @Test
    fun `an explicit connect starts`() {
        assertEquals(Startup.Decision.CONNECT,
                     decide(intentJid = "alice@xmpp-elite.i2p",
                            intentPassword = "pw"))
    }

    @Test
    fun `an explicit connect uses what was typed`() {
        val account = accountFor(intentJid = "alice@xmpp-elite.i2p",
                                 intentPassword = "pw")
        assertEquals("alice@xmpp-elite.i2p", account?.jid)
        assertEquals("pw", account?.password)
    }

    @Test
    fun `what was typed wins over what was remembered`() {
        // Signing in as somebody else must not silently reconnect as the
        // previous account.
        val account = accountFor(
            intentJid = "bob@xmpp-elite.i2p", intentPassword = "bobs",
            storedJid = "alice@xmpp-elite.i2p", storedPassword = "alices")
        assertEquals("bob@xmpp-elite.i2p", account?.jid)
        assertEquals("bobs", account?.password)
    }

    @Test
    fun `surrounding space in a typed account is trimmed`() {
        assertEquals("alice@xmpp-elite.i2p",
                     accountFor(intentJid = "  alice@xmpp-elite.i2p  ",
                                intentPassword = "pw")?.jid)
    }

    @Test
    fun `a password is never trimmed`() {
        // A space is a character in a password. Trimming one would make a
        // correct password fail, silently, only for some users.
        assertEquals(" pw ",
                     accountFor(intentJid = "alice@xmpp-elite.i2p",
                                intentPassword = " pw ")?.password)
    }

    // ── 3. the remembered session still resumes ──────────────────────────────

    @Test
    fun `a remembered account still connects on launch`() {
        // THE CASE THE FIX MUST NOT BREAK. Somebody who signed in yesterday
        // is not shown a login form because the process restarted.
        assertEquals(Startup.Decision.CONNECT,
                     decide(storedJid = "alice@xmpp-elite.i2p",
                            storedPassword = "pw"))
    }

    @Test
    fun `a remembered account is the one connected as`() {
        val account = accountFor(storedJid = "alice@xmpp-elite.i2p",
                                 storedPassword = "pw")
        assertEquals("alice@xmpp-elite.i2p", account?.jid)
        assertEquals("pw", account?.password)
    }

    @Test
    fun `an empty intent alongside a stored account still resumes`() {
        // `resume()` sends ACTION_START with no extras at all, and
        // `getStringExtra` returns null rather than "".
        assertNotNull(accountFor(intentJid = null, intentPassword = null,
                                 storedJid = "alice@xmpp-elite.i2p",
                                 storedPassword = "pw"))
    }

    // ── a record that cannot be connected with ───────────────────────────────

    @Test
    fun `a stored account with no password does not connect`() {
        // A truncated or half-written vault record. Connecting would fail
        // authentication over and over and look exactly like the bug above.
        assertEquals(Startup.Decision.WAIT,
                     decide(storedJid = "alice@xmpp-elite.i2p",
                            storedPassword = ""))
    }

    @Test
    fun `a bare local part is not an account`() {
        // The same rule AccountScope.of applies: `alice` alone would share a
        // namespace with `alice` on every other server.
        assertEquals(Startup.Decision.WAIT,
                     decide(storedJid = "alice", storedPassword = "pw"))
    }

    @Test
    fun `a jid that is only a domain is not an account`() {
        assertEquals(Startup.Decision.WAIT,
                     decide(storedJid = "@xmpp-elite.i2p", storedPassword = "pw"))
    }

    @Test
    fun `a jid with no domain is not an account`() {
        assertEquals(Startup.Decision.WAIT,
                     decide(storedJid = "alice@", storedPassword = "pw"))
    }

    @Test
    fun `whitespace alone is not an account`() {
        assertEquals(Startup.Decision.WAIT,
                     decide(intentJid = "   ", intentPassword = "pw"))
    }

    @Test
    fun `an unusable typed account falls back to the remembered one`() {
        // Not a rule anybody should rely on, but it must be DECIDED rather
        // than accidental: a malformed Intent is not a reason to drop a
        // working session on a restart.
        assertEquals("alice@xmpp-elite.i2p",
                     accountFor(intentJid = "nonsense", intentPassword = "pw",
                                storedJid = "alice@xmpp-elite.i2p",
                                storedPassword = "stored")?.jid)
    }

    // ── the two answers cannot disagree ──────────────────────────────────────

    @Test
    fun `connect is returned exactly when there is an account`() {
        val cases = listOf(
            listOf(null, null, null, null),
            listOf("a@b", "p", null, null),
            listOf(null, null, "a@b", "p"),
            listOf("a@b", "", null, null),
            listOf("", "", "", ""),
            listOf("nope", "p", "a@b", "p"),
        )
        for (case in cases) {
            val account = accountFor(case[0], case[1], case[2], case[3])
            val decision = decide(case[0], case[1], case[2], case[3])
            assertEquals(
                if (account == null) Startup.Decision.WAIT
                else Startup.Decision.CONNECT,
                decision,
                "decide and accountFor disagree for $case")
        }
    }

    @Test
    fun `the account does not print its password`() {
        val account = accountFor(intentJid = "alice@xmpp-elite.i2p",
                                 intentPassword = "hunter2")
        assertEquals(false, account.toString().contains("hunter2"))
    }
}
