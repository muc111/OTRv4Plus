# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice notes whose voice is not yours.

Owner (2026-10-15): "add a voice note feature but with a security mind
twist ... morph voice notes advanced enough where ai detection cannot
identify or link voice note to specific user".

THE PATH OF A NOTE
==================
    microphone -> memory -> voice mask (Rust) -> Opus/WAV file -> the
    ordinary encrypted file transfer -> the other side's verified-file viewer

  * The microphone's PCM is held in memory only. It is never written to
    disk, and is overwritten as soon as the mask has run (or the note is
    cancelled).
  * The mask (`otrv4_core.voice_mask`, Rust/src/voice_mask.rs) draws new,
    secret settings for every note: formant warp, pitch, speaking rate and,
    in SYNTHETIC mode, a generated voice source. Nothing about them is
    returned, stored or sent; see that file for what each step removes and
    what no voice changer can promise.
  * If the mask is unavailable, a masked note is REFUSED; it is never sent
    in the speaker's own voice instead. "natural" is a separate choice the
    user makes explicitly.
  * The note file has no metadata: an Ogg Opus stream whose tags hold only a
    fixed vendor string, or a bare WAV. Its name is random.
  * It is sent as a file, so everything about files applies: OTR session and
    SMP verification required, sealed in Rust, accepted with a y/n prompt.

Shared by the app bridge (Android, desktop) and the terminal client.
"""
from __future__ import annotations

import io
import os
import secrets
import struct
import threading
import time
import wave
from typing import Callable, List, Optional, Tuple

__all__ = ["MODES", "DEFAULT_MODE", "RATE", "MAX_SECONDS", "MIN_SECONDS",
           "VoiceNoteError", "mask", "encode", "decode", "write_note",
           "Recorder", "Player", "mask_available", "describe_mode"]

MODES = ("disguise", "synthetic", "natural")
DEFAULT_MODE = "disguise"
RATE = 16000
MAX_SECONDS = 300
MIN_SECONDS = 0.5
FRAME = 320                       # 20 ms Opus frames at 16 kHz
BITRATE = 24000
VENDOR = b"OTRv4Plus"
#: Received files are untrusted: decoding stops here.
MAX_NOTE_BYTES = 16 * 1024 * 1024

_DESCRIPTIONS = {
    "disguise": "Disguised: a different voice for every note",
    "synthetic": "Synthetic: robot-like, strongest disguise",
    "natural": "Natural: your own voice",
}


def describe_mode(mode: str) -> str:
    return _DESCRIPTIONS.get(mode, mode)


class VoiceNoteError(RuntimeError):
    """`code` is for the UI: unavailable, too_short, too_long, no_speech,
    bad_mode, no_microphone, bad_file."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def _wipe(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# -- the mask ---------------------------------------------------------------------

def _core():
    try:
        import otrv4_core
    except Exception:
        return None
    return otrv4_core if hasattr(otrv4_core, "voice_mask") else None


def mask_available() -> bool:
    return _core() is not None


def mask(pcm: bytes, rate: int, mode: str) -> bytes:
    """[pcm] (s16le mono at [rate]) through the voice mask: 16 kHz s16le."""
    if mode not in MODES:
        raise VoiceNoteError("bad_mode")
    core = _core()
    if core is None:
        raise VoiceNoteError("unavailable", "the voice mask is not in this build")
    seconds = len(pcm) / 2 / max(rate, 1)
    if seconds > MAX_SECONDS:
        raise VoiceNoteError("too_long")
    if seconds < MIN_SECONDS:
        raise VoiceNoteError("too_short")
    try:
        out = bytes(core.voice_mask(bytes(pcm), int(rate), mode))
    except ValueError as exc:
        raise VoiceNoteError("bad_file", str(exc))
    if len(out) / 2 / RATE < MIN_SECONDS:
        raise VoiceNoteError("no_speech")
    return out


# -- the file -------------------------------------------------------------------------

def _opus_encoder():
    try:
        import otrv4_core
        if hasattr(otrv4_core, "OpusEncoder"):
            enc = otrv4_core.OpusEncoder(RATE, 1, otrv4_core.OPUS_APPLICATION_VOIP)
            enc.bitrate = BITRATE
            return enc
    except Exception:
        pass
    try:
        import opuslib
        enc = opuslib.Encoder(RATE, 1, "voip")
        enc.bitrate = BITRATE
        return enc
    except Exception:
        return None


def _opus_decoder():
    try:
        import otrv4_core
        if hasattr(otrv4_core, "OpusDecoder"):
            return otrv4_core.OpusDecoder(RATE, 1)
    except Exception:
        pass
    try:
        import opuslib
        return opuslib.Decoder(RATE, 1)
    except Exception:
        return None


def _crc_table() -> List[int]:
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) if r & 0x80000000 else (r << 1)
        table.append(r & 0xFFFFFFFF)
    return table


_CRC = _crc_table()


def _ogg_crc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC[((crc >> 24) & 0xFF) ^ b]
    return crc


def _page(serial: int, seq: int, granule: int, packets: List[bytes], flags: int) -> bytes:
    lacing = bytearray()
    for p in packets:
        n = len(p)
        while n >= 255:
            lacing.append(255)
            n -= 255
        lacing.append(n)
    header = struct.pack("<4sBBqIIIB", b"OggS", 0, flags, granule, serial, seq, 0, len(lacing))
    page = bytearray(header + bytes(lacing) + b"".join(packets))
    struct.pack_into("<I", page, 22, _ogg_crc(bytes(page)))
    return bytes(page)


def _ogg_opus(packets: List[bytes], samples: int, pre_skip: int = 312) -> bytes:
    serial = secrets.randbits(32)
    head = b"OpusHead" + struct.pack("<BBHIhB", 1, 1, pre_skip, RATE, 0, 0)
    tags = b"OpusTags" + struct.pack("<I", len(VENDOR)) + VENDOR + struct.pack("<I", 0)
    out = [_page(serial, 0, 0, [head], 0x02), _page(serial, 1, 0, [tags], 0)]
    seq, granule, i = 2, 0, 0
    per_page = 50                                  # one second a page
    total_48k = samples * 3 + pre_skip
    while i < len(packets):
        chunk = packets[i:i + per_page]
        i += len(chunk)
        granule = min(granule + len(chunk) * FRAME * 3, total_48k)
        last = i >= len(packets)
        out.append(_page(serial, seq, total_48k if last else granule, chunk,
                         0x04 if last else 0))
        seq += 1
    return b"".join(out)


def _wav(pcm: bytes) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(pcm)
    return buf.getvalue()


def encode(pcm16k: bytes, prefer_opus: bool = True) -> Tuple[bytes, str]:
    """(file bytes, extension). Ogg Opus when this build has an encoder,
    else WAV. Neither carries anything but the audio."""
    enc = _opus_encoder() if prefer_opus else None
    if enc is not None:
        packets = []
        step = FRAME * 2
        for off in range(0, len(pcm16k), step):
            frame = pcm16k[off:off + step]
            if len(frame) < step:
                frame = frame + b"\x00" * (step - len(frame))
            packets.append(bytes(enc.encode(frame, FRAME)))
        return _ogg_opus(packets, len(pcm16k) // 2), "ogg"
    return _wav(pcm16k), "wav"


def _ogg_packets(data: bytes) -> List[bytes]:
    packets, partial, pos = [], b"", 0
    while pos + 27 <= len(data):
        if data[pos:pos + 4] != b"OggS":
            raise VoiceNoteError("bad_file", "not an Ogg stream")
        nseg = data[pos + 26]
        seg_end = pos + 27 + nseg
        if seg_end > len(data):
            raise VoiceNoteError("bad_file", "truncated page")
        body = seg_end
        for lace in data[pos + 27:seg_end]:
            if body + lace > len(data):
                raise VoiceNoteError("bad_file", "truncated packet")
            partial += data[body:body + lace]
            body += lace
            if lace < 255:
                packets.append(partial)
                partial = b""
                if len(packets) > MAX_SECONDS * 60:
                    raise VoiceNoteError("too_long")
        pos = body
    return packets


def decode(data: bytes) -> Tuple[bytes, int]:
    """(s16le mono PCM, rate) from a note -- ours or anyone's. Received
    notes are untrusted: everything is bounds-checked and capped."""
    if len(data) > MAX_NOTE_BYTES:
        raise VoiceNoteError("too_long")
    if data[:4] == b"RIFF":
        try:
            with wave.open(io.BytesIO(data), "rb") as w:
                if w.getnchannels() != 1 or w.getsampwidth() != 2:
                    raise VoiceNoteError("bad_file", "not 16-bit mono")
                rate = w.getframerate()
                if not 8000 <= rate <= 48000 or w.getnframes() > rate * MAX_SECONDS:
                    raise VoiceNoteError("bad_file", "unsupported WAV")
                return w.readframes(w.getnframes()), rate
        except (wave.Error, EOFError) as exc:
            raise VoiceNoteError("bad_file", str(exc))
    if data[:4] != b"OggS":
        raise VoiceNoteError("bad_file", "not a voice note")
    packets = _ogg_packets(data)
    if len(packets) < 2 or not packets[0].startswith(b"OpusHead") or len(packets[0]) < 19:
        raise VoiceNoteError("bad_file", "not Ogg Opus")
    if packets[0][9] != 1:
        raise VoiceNoteError("bad_file", "not mono")
    pre_skip = struct.unpack_from("<H", packets[0], 10)[0]
    dec = _opus_decoder()
    if dec is None:
        raise VoiceNoteError("unavailable", "no Opus decoder in this build")
    out = bytearray()
    for p in packets[2:]:
        if not p:
            continue
        try:
            out += bytes(dec.decode(p, 1920))
        except Exception as exc:
            raise VoiceNoteError("bad_file", str(exc))
        if len(out) > RATE * 2 * MAX_SECONDS:
            raise VoiceNoteError("too_long")
    skip = min(len(out), (pre_skip // 3) * 2)
    return bytes(out[skip:]), RATE


def write_note(data: bytes, extension: str, directory: str) -> str:
    """Write a finished note under [directory] with a random name, 0600."""
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, "voice-note-%s.%s" % (secrets.token_hex(6), extension))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def make_note(pcm: bytearray, rate: int, mode: str, directory: str) -> dict:
    """Mask, encode and write one note; [pcm] is wiped whatever happens."""
    try:
        masked = mask(bytes(pcm), rate, mode)
    finally:
        _wipe(pcm)
    data, ext = encode(masked)
    path = write_note(data, ext, directory)
    return {"path": path, "seconds": round(len(masked) / 2 / RATE, 1),
            "mode": mode, "format": ext, "bytes": len(data)}


# -- recording and playing ------------------------------------------------------------

class Recorder:
    """Microphone to memory, on a thread, until stop() or MAX_SECONDS."""

    def __init__(self, open_capture: Optional[Callable] = None):
        self._open = open_capture
        self._buf = bytearray()
        self._stream = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.level = 0.0
        self.rate = 0
        self.error = ""
        self._started = 0.0

    @property
    def recording(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def seconds(self) -> float:
        with self._lock:
            return len(self._buf) / 2 / self.rate if self.rate else 0.0

    def start(self) -> None:
        if self.recording:
            return
        opener = self._open
        if opener is None:
            import otrv4plus_audio
            opener = otrv4plus_audio.open_capture
            self.rate = otrv4plus_audio.SAMPLE_RATE
        try:
            stream = opener()
        except Exception as exc:
            raise VoiceNoteError("no_microphone", str(exc))
        if isinstance(stream, tuple):
            stream = stream[0]
        self.rate = getattr(stream, "rate", 0) or self.rate or 24000
        self._stream = stream
        self._discard()
        self._stop.clear()
        self.error = ""
        self._started = time.monotonic()
        self._thread = threading.Thread(target=self._run, name="voice-note", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        limit = self.rate * 2 * MAX_SECONDS
        try:
            while not self._stop.is_set():
                frame = self._stream.read_frame(200)
                if not frame:
                    continue
                peak = 0
                for (s,) in struct.iter_unpack("<h", bytes(frame[: len(frame) // 2 * 2])):
                    if abs(s) > peak:
                        peak = abs(s)
                self.level = min(1.0, peak / 32768.0)
                with self._lock:
                    room = limit - len(self._buf)
                    self._buf += bytes(frame[:max(room, 0)])
                    if len(self._buf) >= limit:
                        break
        except Exception as exc:
            self.error = str(exc) or "microphone failed"
        finally:
            try:
                self._stream.stop()
            except Exception:
                pass

    def stop(self) -> Tuple[bytearray, int]:
        """Stop and hand over the PCM (the caller wipes it)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._thread = None
        with self._lock:
            pcm, self._buf = self._buf, bytearray()
        return pcm, self.rate

    def _discard(self) -> None:
        with self._lock:
            _wipe(self._buf)
            self._buf = bytearray()

    def cancel(self) -> None:
        pcm, _ = self.stop()
        _wipe(pcm)


class Player:
    """Play a note through the same audio backends calls use."""

    def __init__(self, open_playback: Optional[Callable] = None):
        self._open = open_playback
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def playing(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def play(self, data: bytes) -> float:
        """Start playing; returns the length in seconds."""
        pcm, rate = decode(data)
        self.stop()
        import otrv4plus_audio as audio
        opener = self._open or audio.open_playback
        stream = opener()
        if isinstance(stream, tuple):
            stream = stream[0]
        out_rate = getattr(stream, "rate", 0) or audio.SAMPLE_RATE
        if rate != out_rate:
            pcm = audio.Resampler(rate, out_rate).process(pcm)
        frame_bytes = getattr(stream, "frame_bytes", 0) or audio.FRAME_BYTES
        self._stop.clear()

        def run():
            try:
                for off in range(0, len(pcm), frame_bytes):
                    if self._stop.is_set():
                        break
                    chunk = pcm[off:off + frame_bytes]
                    if len(chunk) < frame_bytes:
                        chunk += b"\x00" * (frame_bytes - len(chunk))
                    stream.write_frame(chunk)
            finally:
                try:
                    stream.stop()
                except Exception:
                    pass

        self._thread = threading.Thread(target=run, name="voice-note-play", daemon=True)
        self._thread.start()
        return len(pcm) / 2 / out_rate

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._thread = None
