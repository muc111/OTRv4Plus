// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A sign-in screen that does not ask anybody about b32 addresses.
 *
 * These run. The rules are in plain Kotlin precisely so that "what happens
 * when somebody types a full address into the username field" is answered by
 * executing it rather than by reading it.
 */
class SignInTest {

    private val default = SignIn.Choice.DEFAULT
    private val custom = SignIn.Choice.CUSTOM

    // ── the ordinary case ───────────────────────────────────────────────────

    @Test
    fun `a bare username takes the selected server's domain`() {
        val target = SignIn.resolve("alice", default, "")
        assertEquals("alice@xmpp-elite.i2p", target?.jid)
    }

    @Test
    fun `the default route is left to the bridge`() {
        // Blank means "use the compiled-in b32", which is how the profile
        // already spells it. The user never sees or types the destination.
        val target = SignIn.resolve("alice", default, "")
        assertEquals("", target?.server)
        assertTrue(target!!.usesDefaultRoute)
    }

    @Test
    fun `no b32 address appears anywhere in this layer`() {
        // The mapping lives in Python. If it were duplicated here it would be
        // two places to change when the server moves.
        val source = SignIn.DEFAULT_DOMAIN
        assertTrue(!source.contains(".b32."), "a b32 route leaked into the UI layer")
    }

    @Test
    fun `whitespace around the username is forgiven`() {
        assertEquals("alice@xmpp-elite.i2p",
            SignIn.resolve("  alice  ", default, "")?.jid)
    }

    // ── somebody who types the whole thing ──────────────────────────────────

    @Test
    fun `a full address is respected as typed`() {
        val target = SignIn.resolve("alice@elsewhere.i2p", default, "")
        assertEquals("alice@elsewhere.i2p", target?.jid,
            "the domain the user typed was silently replaced, which would " +
            "connect them somewhere they did not ask for")
    }

    @Test
    fun `a full address on the default server is unchanged`() {
        assertEquals("alice@xmpp-elite.i2p",
            SignIn.resolve("alice@xmpp-elite.i2p", default, "")?.jid)
    }

    @Test
    fun `a full address still routes through the chosen server`() {
        """A virtual host and a destination are different things; one server
           can front several hosts."""
        val target = SignIn.resolve("alice@vhost.i2p", custom, "server.i2p")
        assertEquals("alice@vhost.i2p", target?.jid)
        assertEquals("server.i2p", target?.server)
    }

    // ── a custom server ─────────────────────────────────────────────────────

    @Test
    fun `a custom server supplies the domain and the route`() {
        val target = SignIn.resolve("bob", custom, "chat.example.i2p")
        assertEquals("bob@chat.example.i2p", target?.jid)
        assertEquals("chat.example.i2p", target?.server)
        assertTrue(!target!!.usesDefaultRoute)
    }

    @Test
    fun `a custom server is trimmed`() {
        assertEquals("bob@chat.i2p",
            SignIn.resolve("bob", custom, "  chat.i2p  ")?.jid)
    }

    @Test
    fun `a custom b32 is still accepted for anyone who wants one`() {
        // The architecture must still allow explicit routing. The point is
        // that nobody NEEDS it, not that it is forbidden.
        val b32 = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
        val target = SignIn.resolve("bob@vhost.i2p", custom, b32)
        assertEquals(b32, target?.server)
    }

    // ── what stops a sign-in ────────────────────────────────────────────────

    @Test
    fun `an empty username is refused with a sentence`() {
        assertEquals("Enter your username.", SignIn.problem("", default, ""))
    }

    @Test
    fun `a blank username is refused`() {
        assertNotNull(SignIn.problem("   ", default, ""))
    }

    @Test
    fun `a username with spaces is refused`() {
        assertNotNull(SignIn.problem("al ice", default, ""))
    }

    @Test
    fun `a half address is refused`() {
        assertNotNull(SignIn.problem("@server.i2p", default, ""))
        assertNotNull(SignIn.problem("alice@", default, ""))
    }

    @Test
    fun `two at signs are refused`() {
        assertNotNull(SignIn.problem("a@b@c", default, ""))
    }

    @Test
    fun `a custom server with nothing in it is refused`() {
        assertEquals("Enter your server's address.",
            SignIn.problem("alice", custom, ""))
    }

    @Test
    fun `a custom server with no dot is refused`() {
        assertNotNull(SignIn.problem("alice", custom, "localhost"))
    }

    @Test
    fun `the default server needs no custom value`() {
        assertNull(SignIn.problem("alice", default, ""))
    }

    @Test
    fun `resolve refuses exactly what problem refuses`() {
        val cases = listOf(
            Triple("", default, ""),
            Triple("  ", default, ""),
            Triple("a@b@c", default, ""),
            Triple("al ice", default, ""),
            Triple("alice", custom, ""),
            Triple("alice", custom, "nodot"),
        )
        for ((account, choice, server) in cases) {
            assertNotNull(SignIn.problem(account, choice, server), account)
            assertNull(SignIn.resolve(account, choice, server), account)
        }
    }

    // ── coming back ─────────────────────────────────────────────────────────

    @Test
    fun `a remembered default account restores the default choice`() {
        assertEquals(default, SignIn.choiceFor("alice@xmpp-elite.i2p"))
    }

    @Test
    fun `a remembered custom account restores the custom choice`() {
        assertEquals(custom, SignIn.choiceFor("alice@elsewhere.i2p"),
            "a custom server silently reverted to the default on relaunch")
    }

    @Test
    fun `the domain match ignores case`() {
        assertEquals(default, SignIn.choiceFor("alice@XMPP-Elite.i2p"))
    }

    @Test
    fun `the username is recovered for the field`() {
        assertEquals("alice", SignIn.usernameOf("alice@xmpp-elite.i2p"))
        assertEquals("alice", SignIn.usernameOf("alice"))
    }

    @Test
    fun `the domain is recovered and a resource is dropped`() {
        assertEquals("xmpp-elite.i2p",
            SignIn.domainOf("alice@xmpp-elite.i2p/phone"))
        assertEquals("", SignIn.domainOf("alice"))
    }
}
