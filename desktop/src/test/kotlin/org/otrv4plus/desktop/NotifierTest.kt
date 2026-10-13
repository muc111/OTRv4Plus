// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.desktop

import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NotifierTest {

    private class Sent : (List<String>) -> String? {
        val calls = mutableListOf<List<String>>()
        override fun invoke(args: List<String>): String? { calls += args; return "${calls.size}\n" }
    }

    @Test
    fun messagesOnlyWhenTheWindowIsNotInFront() {
        val sent = Sent()
        val n = Notifier(sent, available = true)
        n.setUiVisible(true)
        n.message()
        assertEquals(0, sent.calls.size, "a visible window was notified")
        n.setUiVisible(false)
        n.message(); n.message()
        assertEquals(listOf("New message", "2 new messages"), sent.calls.map { it.last() })
        // The second replaces the first rather than stacking.
        assertTrue(sent.calls[1].contains("--replace-id=1"), sent.calls[1].toString())
        n.setUiVisible(true); n.setUiVisible(false); n.message()
        assertEquals("New message", sent.calls.last().last(), "focus did not reset the count")
    }

    @Test
    fun callsAlwaysAndNothingButTheWord() {
        val sent = Sent()
        val n = Notifier(sent, available = true)
        n.setUiVisible(true)
        n.call()
        assertEquals(listOf("notify-send", "--app-name=OTRv4Plus", "--icon=otrv4plus",
                            "--urgency=critical", "--print-id", "OTRv4Plus", "Incoming call"),
                     sent.calls.single())
    }

    @Test
    fun withoutNotifySendNothingRuns() {
        val sent = Sent()
        val n = Notifier(sent, available = false)
        n.message(); n.call()
        assertEquals(0, sent.calls.size)
    }

    @Test
    fun ownPictureIsSquaredScaledAndReEncoded() {
        val src = File.createTempFile("pic", ".png").apply { deleteOnExit() }
        val img = BufferedImage(400, 300, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until 400) for (y in 0 until 300) img.setRGB(x, y, (x shl 16) or (y shl 8))
        ImageIO.write(img, "png", src)
        val png = assertNotNull(Avatars.ownPng(src))
        val out = ImageIO.read(png.inputStream())
        assertEquals(96, out.width); assertEquals(96, out.height)
        assertTrue(png.size < 64 * 1024, "over the engine's 64 KiB limit")
        val notAPicture = File.createTempFile("notpic", ".png").apply { writeText("not a picture"); deleteOnExit() }
        assertEquals(null, Avatars.ownPng(notAPicture))
    }
}
