// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.screens

import android.graphics.Bitmap
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.otrv4plus.android.bridge.ConnectionStatus
import org.otrv4plus.android.bridge.Contact
import org.otrv4plus.android.bridge.GroupMember
import org.otrv4plus.android.bridge.OtrEvent
import org.otrv4plus.android.bridge.PeerPresence
import org.otrv4plus.android.bridge.SecurityState
import org.otrv4plus.android.bridge.SendOutcome
import org.otrv4plus.android.bridge.SmpState
import org.otrv4plus.android.bridge.Subscription
import org.otrv4plus.android.chat.AccountScope
import org.otrv4plus.android.chat.ChatState
import org.otrv4plus.android.chat.ChatViewModel
import org.otrv4plus.android.theme.ThemeTokens
import org.otrv4plus.android.ui.ConversationScreen
import org.otrv4plus.android.ui.ConversationsScreen
import org.otrv4plus.android.ui.OtrTheme
import org.otrv4plus.android.ui.PeopleScreen
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/**
 * The release page's Android screenshots: the real screens, drawn by
 * Robolectric from MADE-UP conversations (nobody's data). A phone cannot take
 * them -- the app sets FLAG_SECURE -- so CI renders them instead.
 *
 * Built and run only with `-Pscreens` (the `screens` job in android.yml); the
 * ordinary unit tests and the APKs never include this.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
// A plain Application: OtrApplication starts the embedded CPython, whose
// native library does not exist on the JVM (UnsatisfiedLinkError).
@Config(sdk = [34], qualifiers = "w400dp-h860dp-xhdpi", application = android.app.Application::class)
class AndroidScreensTest {

    @get:Rule val compose = createComposeRule()

    private val me = "alice@otrv4plus.i2p"
    private val bob = "bob@otrv4plus.i2p"
    private val carol = "carol@otrv4plus.i2p"
    private val dave = "dave@otrv4plus.i2p"
    private val erin = "erin@otrv4plus.i2p"
    private val room = "design-team@conference.otrv4plus.i2p"
    private val t0 = 1_760_640_000.0

    private fun contact(jid: String, name: String, presence: PeerPresence,
                        security: SecurityState, smp: SmpState) = Contact(
        jid = jid, displayName = name, presence = presence, security = security,
        smp = smp, callAvailable = smp == SmpState.VERIFIED, subscription = Subscription.BOTH)

    private fun model(): ChatViewModel {
        val s = ChatState()
        s.now = { ((t0 + 3_600) * 1000).toLong() }
        s.bindAccount(AccountScope.of(me))
        s.applyConnection(ConnectionStatus(stage = "connected", connected = true, jid = me,
                                           server = "otrv4plus.i2p"))
        s.applyRoster(listOf(
            contact(bob, "Bob", PeerPresence.ONLINE, SecurityState.SMP_VERIFIED, SmpState.VERIFIED),
            contact(carol, "Carol", PeerPresence.ONLINE, SecurityState.ENCRYPTED, SmpState.NOT_VERIFIED),
            contact(dave, "Dave", PeerPresence.OFFLINE, SecurityState.PLAINTEXT, SmpState.NOT_VERIFIED),
            contact(erin, "Erin", PeerPresence.ONLINE, SecurityState.SMP_VERIFIED, SmpState.VERIFIED),
        ))
        s.handle(OtrEvent.SessionChanged(bob, SecurityState.SMP_VERIFIED))
        s.handle(OtrEvent.SmpFinished(bob, SmpState.VERIFIED))
        s.handle(OtrEvent.SessionChanged(carol, SecurityState.ENCRYPTED))
        s.handle(OtrEvent.SessionChanged(erin, SecurityState.SMP_VERIFIED))
        s.handle(OtrEvent.SmpFinished(erin, SmpState.VERIFIED))

        fun inbound(peer: String, body: String, at: Double) =
            s.receive(OtrEvent.MessageReceived(peer = peer, body = body, timestamp = t0 + at))
        fun outbound(peer: String, body: String) {
            s.setDraft(peer, body)
            val m = s.beginSend(peer) ?: return
            s.completeSend(m, SendOutcome.ENCRYPTED)
        }
        inbound(bob, "Are we still on for the review tomorrow?", 60.0)
        outbound(bob, "Yes, 10:00. I'll bring the new layouts.")
        inbound(bob, "Great. Verified you just now, the padlock is blue.", 300.0)
        outbound(bob, "Same here. Call later?")
        inbound(carol, "Sent you the photos (metadata stripped).", 900.0)
        inbound(erin, "On my way.", 1_500.0)

        s.noteRoom(room)
        s.noteSecureRooms(listOf(room))
        for ((i, line) in listOf(
            bob to "Draft is in the shared folder.",
            erin to "Looks good. Two small notes on page 3.",
            bob to "Fixed. Call at 4?",
        ).withIndex()) {
            s.receiveRoom(OtrEvent.RoomMessageReceived(
                room = room, sender = line.first.substringBefore('@'), body = line.second,
                timestamp = t0 + 2_000 + i * 120, encrypted = true,
                senderIdentity = line.first, verified = true))
        }
        val members = listOf(
            GroupMember(me, "", me = true, verified = true, bound = true),
            GroupMember(bob, "", me = false, verified = true, bound = true),
            GroupMember(erin, "", me = false, verified = true, bound = true),
            GroupMember(carol, "", me = false, verified = false, bound = true),
            GroupMember(dave, "", me = false, verified = false, bound = true),
        )
        return ChatViewModel().apply { attachForScreenshots(s, mapOf(room to members)) }
    }

    private fun shoot(name: String, screen: @Composable (ChatViewModel) -> Unit) {
        val model = model()
        compose.setContent { OtrTheme(ThemeTokens.Mode.DARK_PURPLE) { screen(model) } }
        compose.waitForIdle()
        val bitmap = compose.onRoot().captureToImage().asAndroidBitmap()
        val dir = File("build/screens").apply { mkdirs() }
        File(dir, "$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test fun chats() = shoot("android-1-chats") { ConversationsScreen(it, onOpen = {}) }

    @Test fun verifiedChat() = shoot("android-2-chat") { ConversationScreen(it, bob, onBack = {}) }

    @Test fun secureGroup() = shoot("android-3-group") { ConversationScreen(it, room, onBack = {}) }

    @Test fun people() = shoot("android-4-people") {
        PeopleScreen(it, onBack = {}, onOpenChat = {}, showBack = false)
    }
}
