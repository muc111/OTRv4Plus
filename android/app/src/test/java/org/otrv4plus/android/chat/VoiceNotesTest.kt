// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VoiceNotesTest {

    @Test
    fun `the strongest disguise is the first choice and the default`() {
        assertEquals(VoiceNotes.SYNTHETIC, VoiceNotes.MODES.first())
        assertEquals(VoiceNotes.SYNTHETIC, VoiceNotes.DEFAULT)
        for (mode in VoiceNotes.MODES) {
            assertTrue(VoiceNotes.label(mode).isNotBlank())
            assertTrue(VoiceNotes.detail(mode).isNotBlank())
        }
    }

    @Test
    fun `disguised is gone, synthetic and my voice remain`() {
        assertEquals(listOf(VoiceNotes.SYNTHETIC, VoiceNotes.NATURAL), VoiceNotes.MODES)
        assertTrue("disguise" !in VoiceNotes.MODES)
        // Nor does any word the user reads mention it.
        val shown = VoiceNotes.MODES.flatMap { listOf(VoiceNotes.label(it), VoiceNotes.detail(it),
                                                      VoiceNotes.whileRecording(it, "phone"),
                                                      VoiceNotes.making(it)) } +
            VoiceNotes.CAVEAT + VoiceNotes.errorText("unavailable")
        for (text in shown) assertTrue("disguis" !in text.lowercase(), text)
    }

    @Test
    fun `the caveat does not promise what no disguise can`() {
        val c = VoiceNotes.CAVEAT.lowercase()
        assertTrue("not impossible" in c)
        assertTrue("what you say" in c)
        assertTrue("never stored" in c)
    }

    @Test
    fun `every bridge error has words and a missing mask says nothing was recorded`() {
        for (code in listOf("too_short", "no_speech", "too_long", "unavailable",
                            "no_microphone", "bad_mode", "something_new")) {
            assertTrue(VoiceNotes.errorText(code).isNotBlank(), code)
        }
        assertTrue("nothing was recorded" in VoiceNotes.errorText("unavailable"))
    }

    @Test
    fun `the clock`() {
        assertEquals("0:00", VoiceNotes.clock(0.0))
        assertEquals("0:07", VoiceNotes.clock(7.9))
        assertEquals("1:30", VoiceNotes.clock(90.0))
        assertEquals("0:00", VoiceNotes.clock(-3.0))
    }

    @Test
    fun `the sheet keeps its mode through every state`() {
        val states = listOf<VoiceSheet>(
            VoiceSheet.Choosing("synthetic"), VoiceSheet.Recording("synthetic", 1.0, 0.2),
            VoiceSheet.Making("synthetic"), VoiceSheet.Ready("synthetic", "/c/voice-note-1.ogg", 2.0),
            VoiceSheet.Failed("synthetic", "x"),
        )
        assertTrue(states.all { it.mode == "synthetic" })
    }
}
