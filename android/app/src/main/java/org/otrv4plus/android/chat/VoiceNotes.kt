// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.chat

/**
 * Voice notes in a synthetic voice (or your own): the words and the states of the sheet.
 *
 * The recording, the mask and the file are in Python and Rust
 * (`otrv4plus_voicenote`, `Rust/src/voice_mask.rs`). The recording never
 * reaches Kotlin: it stays in Python's memory, is masked there, and only the
 * finished note is written -- to the app's cache, from where it
 * is sent as an ordinary encrypted file and then deleted.
 *
 * Plain Kotlin, driven by `VoiceNotesTest`.
 */
object VoiceNotes {

    const val SYNTHETIC = "synthetic"
    const val NATURAL = "natural"

    /** Synthetic, the default, and My voice. "Disguised" was removed on
     *  2026-10-16 (owner: hard to understand; synthetic only) -- it was also
     *  the weaker of the two masks (VOICE_NOTES.md). */
    val MODES = listOf(SYNTHETIC, NATURAL)
    const val DEFAULT = SYNTHETIC

    fun label(mode: String): String = when (mode) {
        SYNTHETIC -> "Synthetic"
        NATURAL -> "My voice"
        else -> mode
    }

    fun detail(mode: String): String = when (mode) {
        SYNTHETIC -> "A generated, robot-like voice. The hardest for AI to match."
        NATURAL -> "Your own voice, unchanged."
        else -> ""
    }

    /** Said once, under the choice, because it is what matters most. */
    const val CAVEAT =
        "The synthetic voice is made on this device before anything is saved or " +
        "sent, and your real voice is never stored. It makes recognising " +
        "or linking your notes by voice much harder, not impossible -- and " +
        "what you say can still identify you."

    fun errorText(code: String): String = when (code) {
        "too_short" -> "Too short to send."
        "no_speech" -> "No speech was heard."
        "too_long" -> "Too long: notes are at most five minutes."
        "unavailable" -> "The synthetic voice is not available in this build, so nothing was recorded."
        "no_microphone" -> "The microphone could not be opened."
        "bad_mode" -> "Unknown voice setting."
        else -> "The voice note could not be made."
    }

    /** A received file that looks like one of our notes, for a Play
     *  button. The NAME only offers the button: what is played is parsed
     *  as audio, and anything else is refused there. */
    fun looksLikeNote(filename: String): Boolean =
        filename.startsWith("voice-note-") &&
            (filename.endsWith(".ogg") || filename.endsWith(".wav"))

    /** Under the level bar while recording. */
    fun whileRecording(mode: String, device: String): String =
        if (mode == NATURAL) "Your own voice is kept, as recorded."
        else "Your voice is replaced by a synthetic one when you stop, on this $device."

    /** While the note is being made. */
    fun making(mode: String): String =
        if (mode == NATURAL) "Preparing your note…" else "Making the synthetic voice…"

    /** "0:07", "1:30". */
    fun clock(seconds: Double): String {
        val s = seconds.toInt().coerceAtLeast(0)
        return "%d:%02d".format(s / 60, s % 60)
    }
}

/** What the voice-note sheet shows. */
sealed interface VoiceSheet {
    val mode: String

    /** Choosing a voice, not yet recording. */
    data class Choosing(override val mode: String) : VoiceSheet

    data class Recording(override val mode: String, val seconds: Double = 0.0,
                         val level: Double = 0.0) : VoiceSheet

    /** Masking and encoding: a moment, on another thread. */
    data class Making(override val mode: String) : VoiceSheet

    /** A finished note, ready to hear, send or throw away. */
    data class Ready(override val mode: String, val path: String,
                     val seconds: Double) : VoiceSheet

    data class Failed(override val mode: String, val message: String) : VoiceSheet
}

/** The bridge's answers, as plain values. */
data class VoiceRecording(val recording: Boolean, val seconds: Double,
                          val level: Double, val error: String)

data class VoiceNoteFile(val path: String, val seconds: Double, val mode: String,
                         val error: String)
