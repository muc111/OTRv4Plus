// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
package org.otrv4plus.android.bridge

import com.chaquo.python.PyObject

/** [MediaApi] over the engine's `OtrApp`. */
internal class ChaquopyMedia(private val handles: BridgeHandles) : MediaApi {

    private fun requireApp(): PyObject = handles.requireApp()

    private fun call(name: String, vararg args: Any): PyObject? =
        handles.call(name, *args)

    // ── Calls ─────────────────────────────────────────────────────────────
    //
    // Thin, like everything else here: each of these is one `callAttr` onto
    // `OtrApp`, which delegates to `android_bridge.voice.CallBridge`, which
    // delegates to `otrv4plus_voice.VoiceCallManager` -- the same state
    // machine, signalling and SMP gate the terminal client has always used.
    //
    // NOTHING ON THIS SIDE DECIDES WHETHER A CALL MAY HAPPEN. The gate is
    // `VoiceCallManager`'s, read from the engine's own verification
    // predicate. A second check in Kotlin would be a second answer that
    // could disagree with the one that actually refuses, and the UI would
    // be showing the wrong one.
    //
    // BLOCKING, so every one of these belongs on a worker thread -- the same
    // rule as the rest of this class. None of them waits for a call to
    // connect, though: placing a call builds I2P tunnels, and the Python
    // side returns as soon as the request is handed over.

    /**
     * Place a call to [peer]. Returns a `CallOutcome` code, never a sentence.
     *
     * "started" means the request reached the call manager, NOT that anything
     * is ringing. Building the tunnels takes 30-120 s, so the screen follows
     * [callState] and the events that arrive through [drainEvents].
     */
    override fun startCall(peer: String): String =
        runCatching {
            requireApp().callAttr("start_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /** Answer a ringing call. Returns a `CallOutcome` code. */
    override fun answerCall(peer: String): String =
        runCatching {
            requireApp().callAttr("answer_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /**
     * End an active call, or reject a ringing one.
     *
     * One verb for both because the state machine has one: rejecting and
     * hanging up are the same transition, and splitting them here would
     * invent a distinction the protocol does not have.
     */
    override fun endCall(peer: String): String =
        runCatching {
            requireApp().callAttr("end_call", peer).toString()
        }.getOrDefault(CallOutcome.UNAVAILABLE)

    /**
     * "Mask my voice" for live calls, 1:1 and group, at once (Rust
     * live_mask.rs through otrv4plus_audio). Returns whether this build can
     * mask at all.
     */
    override fun setVoiceMask(on: Boolean): Boolean = runCatching {
        val state = requireApp().callAttr("set_voice_mask", on)
        state.callAttr("get", "available")?.toBoolean() == true
    }.getOrDefault(false)

    /** This peer's call state, read from the live session. */
    override fun callState(peer: String): CallState =
        runCatching {
            CallState.fromName(
                requireApp().callAttr("call_state", peer)
                    .get("name")?.toString() ?: "IDLE")
        }.getOrDefault(CallState.IDLE)

    /**
     * Seconds since the call became ACTIVE, or 0.
     *
     * Never counts the tunnel build. A timer that started when the user
     * pressed Call would show a minute and a half of conversation that had
     * not happened yet.
     */
    override fun callDurationSeconds(peer: String): Int =
        runCatching {
            requireApp().callAttr("call_duration_seconds", peer).toInt()
        }.getOrDefault(0)

    /**
     * Why voice cannot run on this device, or "" when it can.
     *
     * Asked of Python, which asks `otrv4plus_voice`'s own host hook -- the
     * same question the call manager asks before doing anything. A separate
     * answer here could tell the user something the engine would contradict.
     */
    /**
     * Whether a call may be offered to [peer], from the engine: the code and,
     * for "voice_unavailable", the host hook's reason. Null when the bridge
     * could not be asked -- the caller then decides from what it has, and
     * never towards "available". See `OtrApp.call_gate`.
     */
    override fun callGate(peer: String): Pair<String, String>? =
        runCatching {
            val d = requireApp().callAttr("call_gate", peer)
            (d.callAttr("get", "gate")?.toString() ?: return@runCatching null) to
                (d.callAttr("get", "reason")?.toString() ?: "")
        }.getOrNull()

    /**
     * The next call's I2P path (`OtrApp.warm_call_path`): built in advance
     * when [build] is true, otherwise only read. Returns the state code
     * ("cold", "warming", "ready") and the seconds it is still kept for.
     */
    override fun callPath(build: Boolean): Pair<String, Int> =
        runCatching {
            val d = requireApp().callAttr(if (build) "warm_call_path" else "call_path_state")
            (d.callAttr("get", "state")?.toString() ?: "cold") to
                (d.callAttr("get", "seconds_left")?.toInt() ?: 0)
        }.getOrDefault("cold" to 0)

    override fun voiceUnavailableReason(): String =
        runCatching {
            requireApp().callAttr("voice_unavailable_reason").toString()
        }.getOrDefault("Voice is not available on this device.")

    // ── File transfer ─────────────────────────────────────────────────────
    //
    // Thin, like the calls. `otrv4plus_filetransfer` owns the FileKey, the
    // AEAD, the chunk format, the hashes, the offer semantics, the filename
    // rules, the size limit and the atomic commit -- and the SMP gate on
    // BOTH sides. None of that is restated here.
    //
    // THE PATH COMES FROM SAF. Android picks through the Storage Access
    // Framework and hands down a path it has already resolved; the Termux
    // picker `otrv4plus_filetransfer.pick_file` shells out to is never
    // reached from an APK.

    /**
     * Offer a file to [peer]. Returns a `FileOutcome` code, never a sentence.
     *
     * "started" means the engine accepted the offer and it is on its way,
     * NOT that the peer has it -- the peer has to accept, and then every
     * chunk crosses I2P.
     */
    override fun sendFile(peer: String, path: String,
                 stripMetadata: Boolean): String =
        runCatching {
            requireApp().callAttr("send_file", peer, path, stripMetadata)
                .toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /**
     * What [path] carries before it is sent, so the user can choose.
     *
     * Examined in Python, where `android_bridge.metadata` is driven against
     * real files in the test suite. A failure to ask is reported as UNKNOWN
     * -- "the app cannot check" -- never as clean.
     */
    override fun inspectFile(path: String): MetadataFinding =
        runCatching {
            val d = requireApp().callAttr("inspect_file", path)
            MetadataFinding(
                kind = d.callAttr("get", "kind")?.toString() ?: "unknown",
                carriesMetadata = d.callAttr("get", "carries_metadata")?.toBoolean() ?: false,
                metadataBytes = d.callAttr("get", "metadata_bytes")?.toInt() ?: 0,
                canScrub = d.callAttr("get", "can_scrub")?.toBoolean() ?: false,
            )
        }.getOrDefault(MetadataFinding.UNKNOWN)

    // -- voice notes (otrv4plus_voicenote; the recording stays in Python) ------

    /** Start recording. "ok", or an error code for [VoiceNotes.errorText]. */
    override fun voiceNoteStart(): String =
        runCatching { requireApp().callAttr("voice_note_start").toString() }
            .getOrDefault("no_microphone")

    override fun voiceNoteStatus(): org.otrv4plus.android.chat.VoiceRecording =
        runCatching {
            val d = requireApp().callAttr("voice_note_status")
            org.otrv4plus.android.chat.VoiceRecording(
                recording = d.callAttr("get", "recording")?.toBoolean() ?: false,
                seconds = d.callAttr("get", "seconds")?.toDouble() ?: 0.0,
                level = d.callAttr("get", "level")?.toDouble() ?: 0.0,
                error = d.callAttr("get", "error")?.toString() ?: "",
            )
        }.getOrDefault(org.otrv4plus.android.chat.VoiceRecording(false, 0.0, 0.0, ""))

    /** Stop, disguise and write the note under [directory]. */
    override fun voiceNoteStop(mode: String, directory: String): org.otrv4plus.android.chat.VoiceNoteFile =
        runCatching {
            val d = requireApp().callAttr("voice_note_stop", mode, directory)
            org.otrv4plus.android.chat.VoiceNoteFile(
                path = d.callAttr("get", "path")?.toString() ?: "",
                seconds = d.callAttr("get", "seconds")?.toDouble() ?: 0.0,
                mode = d.callAttr("get", "mode")?.toString() ?: mode,
                error = d.callAttr("get", "error")?.toString() ?: "",
            )
        }.getOrDefault(org.otrv4plus.android.chat.VoiceNoteFile("", 0.0, mode, "failed"))

    /** Send a note made by [voiceNoteStop]: the [sendFile] outcome, and the
     *  sealed copy kept so the sender can play it back ("" when none). */
    override fun sendVoiceNote(peer: String, path: String): Pair<String, String> =
        runCatching {
            val d = requireApp().callAttr("send_voice_note", peer, path)
            (d.callAttr("get", "outcome")?.toString() ?: FileOutcome.UNAVAILABLE) to
                (d.callAttr("get", "path")?.toString() ?: "")
        }.getOrDefault(FileOutcome.UNAVAILABLE to "")

    override fun voiceNoteCancel() {
        runCatching { requireApp().callAttr("voice_note_cancel") }
    }

    override fun voiceNoteDiscard(path: String) {
        runCatching { requireApp().callAttr("voice_note_discard", path) }
    }

    /** A note's waveform for its bubble, or null when it cannot be read. */
    override fun voiceNoteWaveform(path: String): org.otrv4plus.android.chat.VoiceWaveform? =
        runCatching {
            val d = requireApp().callAttr("voice_note_waveform", path, 0)
            val bars = d.callAttr("get", "bars") ?: return@runCatching null
            org.otrv4plus.android.chat.VoiceWaveform(
                bars.asList().map { it.toFloat().coerceIn(0f, 1f) },
                d.callAttr("get", "seconds")?.toDouble() ?: 0.0)
        }.getOrNull()

    /** Accept an offered transfer, by the id [transfers] reported. */
    override fun acceptFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("accept_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /** Stop a transfer under way: ours, or one we accepted. */
    override fun cancelFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("cancel_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /** Decline an offered transfer. */
    override fun declineFile(transferId: String): String =
        runCatching {
            requireApp().callAttr("decline_file", transferId).toString()
        }.getOrDefault(FileOutcome.UNAVAILABLE)

    /**
     * Every live transfer, structured.
     *
     * Structured rather than the engine's own progress lines: those are
     * written for a terminal, name files and embed transfer ids. The
     * filename here has already been through the engine's
     * `sanitise_filename`, which matters because it was chosen by somebody
     * else and is about to be rendered.
     */
    // `callAttr("get", key)`, NOT `row.get(key)`. Chaquopy's PyObject is a
    // Map over the object's ATTRIBUTES, so on a Python dict `get("path")`
    // looked up an attribute called `path` and returned null. Every field of
    // every row decoded as empty: `state` was never RECEIVED and `path` was
    // blank, so `canOpen` was false and a received file could never be
    // opened -- the Android-to-Android "cannot open" report. The Python side
    // was right all along (tests/test_android_files.py), which is why no
    // Python test saw it; tests/test_chaquopy_dict_access.py now pins it.
    override fun transfers(): List<FileTransferView> =
        runCatching {
            requireApp().callAttr("transfers").asList().map { row ->
                FileTransferView(
                    id = row.callAttr("get", "id")?.toString().orEmpty(),
                    peer = row.callAttr("get", "peer")?.toString().orEmpty(),
                    filename = row.callAttr("get", "filename")?.toString().orEmpty(),
                    sizeBytes = row.callAttr("get", "size")?.toLong() ?: 0L,
                    outgoing = row.callAttr("get", "outgoing")?.toBoolean() ?: false,
                    accepted = row.callAttr("get", "accepted")?.toBoolean() ?: false,
                    cancelled = row.callAttr("get", "cancelled")?.toBoolean() ?: false,
                    progress = row.callAttr("get", "progress")?.toFloat() ?: 0f,
                    state = row.callAttr("get", "state")?.toString().orEmpty(),
                    reason = row.callAttr("get", "reason")?.toString().orEmpty(),
                    path = row.callAttr("get", "path")?.toString().orEmpty(),
                    group = row.callAttr("get", "group")?.toBoolean() ?: false,
                    sender = row.callAttr("get", "from")?.toString().orEmpty(),
                    deliveredTo = row.callAttr("get", "delivered_to")?.toInt() ?: 0,
                )
            }
        }.getOrDefault(emptyList())

    /**
     * Where a FINISHED file lands.
     *
     * Not the partial-work directory: the engine keeps the two apart so a
     * partial file can never be mistaken for a complete one, and pointing
     * the user at that one would point them at the files that are not
     * theirs yet.
     */
    /**
     * Decrypt a received `.otrv` container into [directory] (the viewer's
     * transient copy). Null when it does not open; the reason stays in
     * Python, as a code.
     */
    override fun openReceivedTo(container: String, directory: String): String? =
        runCatching {
            requireApp().callAttr("open_received_to", container, directory).toString()
        }.getOrNull()

    /** Explicit Save of a received file's plaintext to [destination]. */
    override fun saveReceived(container: String, destination: String): String =
        runCatching {
            requireApp().callAttr("save_received", container, destination).toString()
        }.getOrDefault("save_failed")

    override fun receivedFileDir(): String =
        runCatching {
            requireApp().callAttr("received_file_dir").toString()
        }.getOrDefault("")
}

/**
 * Calls, file transfer and voice notes: thin calls onto `OtrApp`, whose
 * Python owns the state machines, the keys and the SMP gate. Split out of
 * [ChaquopyOtrCore], which implements it by delegation.
 */
interface MediaApi {
    fun startCall(peer: String): String
    fun answerCall(peer: String): String
    fun endCall(peer: String): String
    fun setVoiceMask(on: Boolean): Boolean
    fun callState(peer: String): CallState
    fun callDurationSeconds(peer: String): Int
    fun callGate(peer: String): Pair<String, String>?
    fun callPath(build: Boolean): Pair<String, Int>
    fun voiceUnavailableReason(): String
    fun sendFile(peer: String, path: String,
                 stripMetadata: Boolean = false): String
    fun inspectFile(path: String): MetadataFinding
    fun voiceNoteStart(): String
    fun voiceNoteStatus(): org.otrv4plus.android.chat.VoiceRecording
    fun voiceNoteStop(mode: String, directory: String): org.otrv4plus.android.chat.VoiceNoteFile
    fun sendVoiceNote(peer: String, path: String): Pair<String, String>
    fun voiceNoteCancel()
    fun voiceNoteDiscard(path: String)
    fun voiceNoteWaveform(path: String): org.otrv4plus.android.chat.VoiceWaveform?
    fun acceptFile(transferId: String): String
    fun cancelFile(transferId: String): String
    fun declineFile(transferId: String): String
    fun transfers(): List<FileTransferView>
    fun openReceivedTo(container: String, directory: String): String?
    fun saveReceived(container: String, destination: String): String
    fun receivedFileDir(): String
}
