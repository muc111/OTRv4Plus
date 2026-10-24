# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's files and voice notes: sending, receiving, the transfer list and
where received files go.

A mixin of OtrApp (app.py). Thin, like the calls: every decision belongs
to otrv4plus_filetransfer (through files.py)."""
from __future__ import annotations

import os
from typing import Any, Dict, List

from .app_base import BridgeError, _log
from .files import FileBridge, FileOutcome


class FilesMixin:
    """Files and voice notes. Mixed into OtrApp."""

    # -- files -----------------------------------------------------------------
    #
    # Thin, like the calls. Every decision -- the SMP gate on both sides, the
    # size limit, the filename rules, the chunk format, the atomic commit --
    # belongs to `otrv4plus_filetransfer`, which already makes them for the
    # terminal client.

    @property
    def files(self) -> "FileBridge":
        """The transfer bridge, built once per app. See android_bridge.files."""
        if self._wiped:
            raise BridgeError("wiped", "this app has been wiped")
        if self._files_bridge is None:
            self._files_bridge = FileBridge(self)
        return self._files_bridge

    def send_file(self, peer: str, path: str,
                  strip_metadata: bool = False) -> str:
        """Offer a file. Returns a `FileOutcome` code, never a sentence.

        THE VERIFICATION GATE IS NOT HERE. `offer_file` refuses an unverified
        peer before it reads a byte of the file, using the same predicate the
        call gate uses. Restating it would create a second answer that could
        disagree with the one that actually refuses.

        [path] is resolved by Android through the Storage Access Framework
        before it arrives. The engine takes a path and does not care who
        chose it, which is why the Termux picker is never reached here.
        """
        if self._wiped:
            return FileOutcome.UNAVAILABLE
        if self.is_room(peer):
            # A secure group's file goes to the whole group, over MLS
            # (android_bridge.group_files); an ordinary room has none.
            room = self.canonical_peer(peer)
            if self._group_files is None or not self.groups.is_secure(room):
                return FileOutcome.UNAVAILABLE
            return self._group_files.send(room, path, bool(strip_metadata))
        return self.files.send_file(self.canonical_peer(peer), path,
                                    bool(strip_metadata))

    def inspect_file(self, path: str) -> Dict[str, Any]:
        """Whether [path] carries metadata the app can remove.

        Asked BEFORE sending, so the user can choose. See
        `android_bridge.metadata` for exactly what counts and what is kept.
        """
        return self.files.inspect(path)

    # -- voice notes -----------------------------------------------------------
    #
    # A voice note is recorded into memory, put through the voice mask
    # (otrv4plus_voicenote, Rust/src/voice_mask.rs), written as a small
    # metadata-free audio file, and then sent with `send_file` like any other
    # file -- so the session and verification gates are the file gates.

    def _voice(self):
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            import otrv4plus_voicenote as vn
            rec = self._voice_recorder = vn.Recorder()
        return rec

    def voice_note_modes(self) -> Dict[str, Any]:
        """The choices, and whether the mask is in this build."""
        import otrv4plus_voicenote as vn
        return {"modes": list(vn.MODES), "default": vn.DEFAULT_MODE,
                "labels": {m: vn.describe_mode(m) for m in vn.MODES},
                "mask_available": vn.mask_available(),
                "max_seconds": vn.MAX_SECONDS}

    def voice_note_start(self) -> str:
        """Start recording. "ok", or why not."""
        if self._wiped:
            return "unavailable"
        import otrv4plus_voicenote as vn
        try:
            self._voice().start()
        except vn.VoiceNoteError as exc:
            # Which backend refused and why ("parec not found"): no content.
            _log.warning("voice note: %s (%s)", exc.code, exc)
            return exc.code
        except Exception:
            return "no_microphone"
        return "ok"

    def voice_note_status(self) -> Dict[str, Any]:
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            return {"recording": False, "seconds": 0.0, "level": 0.0, "error": ""}
        return {"recording": rec.recording, "seconds": round(rec.seconds, 1),
                "level": round(rec.level, 3), "error": rec.error}

    def voice_note_stop(self, mode: str, directory: str) -> Dict[str, Any]:
        """Stop, mask and write the note under [directory]. {"path", "seconds",
        "mode", "format", "bytes"} or {"error": code}. The raw recording is
        wiped either way; a masked note is never replaced by an unmasked one."""
        import otrv4plus_voicenote as vn
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            return {"error": "too_short"}
        pcm, rate = rec.stop(vn.TAIL_SECONDS)
        try:
            if not directory:
                import otrv4plus_filetransfer as _ft
                directory = _ft.staging_dir()
            return vn.make_note(pcm, rate, mode, directory)
        except vn.VoiceNoteError as exc:
            return {"error": exc.code}
        except Exception:
            _log.warning("voice note could not be made")
            return {"error": "bad_file"}

    def send_voice_note(self, peer: str, path: str) -> Dict[str, Any]:
        """Send a note made by `voice_note_stop`, keeping a sealed copy so it
        can be played back from the chat like a received one.

        {"outcome": FileOutcome, "path": the kept copy, or ""}. The gates are
        `send_file`'s; a refused note keeps nothing."""
        from .files import keep_sent_note
        kept = keep_sent_note(path)
        outcome = self.send_file(peer, path, False)
        if outcome != FileOutcome.STARTED and kept:
            try:
                os.unlink(kept)
            except OSError:
                pass
            kept = ""
        return {"outcome": outcome, "path": kept}

    def voice_note_cancel(self) -> None:
        rec = getattr(self, "_voice_recorder", None)
        if rec is not None:
            rec.cancel()

    def voice_note_play(self, path: str) -> Dict[str, Any]:
        """Play a note (a preview, or a received one) through the call audio
        path. For hosts without a media player of their own (desktop)."""
        import otrv4plus_voicenote as vn
        try:
            data = self._note_bytes(path)
            player = getattr(self, "_voice_player", None)
            if player is None:
                player = self._voice_player = vn.Player()
            return {"seconds": round(player.play(data), 1)}
        except vn.VoiceNoteError as exc:
            _log.warning("voice note playback: %s (%s)", exc.code, exc)
            return {"error": exc.code}
        except Exception as exc:
            _log.warning("voice note playback: %s", type(exc).__name__)
            return {"error": "bad_file"}

    def _note_bytes(self, path: str) -> bytes:
        """A note's file, decrypted in memory when it is a sealed container
        (`files.open_received` checks it is one, in the received directory);
        otherwise only an unsent note of ours (voice-note-*)."""
        import otrv4plus_voicenote as vn
        if path.endswith(".otrv"):
            return self.files.open_received(path)
        if not os.path.basename(path or "").startswith("voice-note-"):
            raise ValueError("not a voice note")
        with open(path, "rb") as f:
            return f.read(vn.MAX_NOTE_BYTES + 1)

    def voice_note_waveform(self, path: str, bars: int = 0) -> Dict[str, Any]:
        """{"bars": [0..1, ...], "seconds"} for a note's bubble, or
        {"error": code}. Decoded by the same bounded decoder as playback;
        nothing is written anywhere."""
        import otrv4plus_voicenote as vn
        try:
            pcm, rate = vn.decode(self._note_bytes(path))
            return {"bars": vn.waveform(pcm, rate, int(bars or vn.WAVEFORM_BARS)),
                    "seconds": round(len(pcm) / 2 / max(rate, 1), 1)}
        except vn.VoiceNoteError as exc:
            return {"error": exc.code}
        except Exception:
            return {"error": "bad_file"}

    def voice_note_play_status(self) -> Dict[str, Any]:
        """Where playback is, for the waveform: {"playing", "position", "seconds"}."""
        player = getattr(self, "_voice_player", None)
        if player is None or not player.playing:
            return {"playing": False, "position": 0.0, "seconds": 0.0}
        return {"playing": True, "position": round(player.position, 2),
                "seconds": round(player.seconds, 2)}

    def voice_note_play_stop(self) -> None:
        player = getattr(self, "_voice_player", None)
        if player is not None:
            player.stop()

    def voice_note_discard(self, path: str) -> None:
        """Delete a note that was not sent."""
        name = os.path.basename(path or "")
        if name.startswith("voice-note-"):
            try:
                os.unlink(path)
            except OSError:
                pass

    def accept_file(self, transfer_id: str) -> str:
        """Accept an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.UNAVAILABLE
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.accept(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.accept(transfer_id)

    def decline_file(self, transfer_id: str) -> str:
        """Decline an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.NO_TRANSFER
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.decline(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.decline(transfer_id)

    def cancel_file(self, transfer_id: str) -> str:
        """Stop a transfer that is under way, either direction. A `FileOutcome`."""
        if self._wiped:
            return FileOutcome.NO_TRANSFER
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.cancel(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.cancel(transfer_id)

    def transfers(self) -> List[Dict[str, Any]]:
        """Every live transfer, structured. Never the engine's own sentences."""
        if self._wiped:
            return []
        group = self._group_files.transfers() if self._group_files is not None else []
        return self.files.transfers() + group

    def received_file_dir(self) -> str:
        """Where a FINISHED file lands, as the engine decides it.

        Not the partial-work directory, which the engine keeps separate so a
        partial file can never be mistaken for a complete one.
        """
        return self.files.received_dir()

    # A received file rests as a `.otrv` container (Rust-sealed). These open
    # it without leaving plaintext behind, or save it on an explicit request.
    # Failures are codes: a container that does not open says so, and never
    # why in engine words.

    def open_received(self, path: str) -> bytes:
        """Decrypt into memory for the in-app viewer."""
        try:
            return self.files.open_received(path)
        except Exception:
            raise BridgeError("open_failed", "the file could not be opened")

    def open_received_to(self, path: str, directory: str) -> str:
        """Decrypt to a transient file for a viewer that needs one (PDF,
        video). The caller deletes it when the viewer closes."""
        try:
            return self.files.open_received_to(path, directory)
        except Exception:
            raise BridgeError("open_failed", "the file could not be opened")

    def save_received(self, path: str, destination: str) -> str:
        """Explicit Save to `destination`, replacing a file already there."""
        try:
            self.files.save_received(path, destination)
            return "ok"
        except Exception:
            return "save_failed"

    def export_received(self, path: str, destination: str, passphrase: str) -> str:
        """A passphrase-sealed `.otrv` any OTRv4Plus build can import."""
        if len(passphrase or "") < 8:
            return "passphrase_too_short"
        try:
            self.files.export_received(path, destination, passphrase)
            return "ok"
        except Exception:
            return "export_failed"
