# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group voice calls for the terminal client: the media side of
`android_bridge.group_call.GroupCalls` (MLS_SECURITY_HARDENING.md §5, M5).

  * One SAM STYLE=DATAGRAM session per call, with a TRANSIENT destination
    and the same tunnel options as 1:1 voice (`otrv4plus_mediapath`). Its
    public destination is what we announce to the group -- inside an MLS
    message, so only group members learn it.
  * Inbound datagrams are forwarded by the router to a local UDP socket;
    each is handed to `GroupCalls.on_datagram`, which decrypts in Rust and
    drops anything not from a verified participant.
  * Audio: the 1:1 backends (`otrv4plus_audio`), Opus via the host's
    loader, the 1:1 padding (`pad_opus`: every frame the same size, so
    length says nothing about speech). One Opus decoder per sender, a small
    per-sender queue, mixed and played every frame.

Nothing here touches a key. Keys, nonces and the replay window are in
`RustGroupVoice`.
"""
from __future__ import annotations

import asyncio
import collections
import secrets
import socket
import threading
import time
from typing import Any, Callable, Deque, Dict, Optional

import otrv4plus_voice as _voice
import otrv4plus_audio as _audio
import otrv4plus_mediapath as _mediapath
from android_bridge.group_call import mix

__all__ = ["GroupCallMedia", "PER_SENDER_QUEUE"]

#: Frames buffered per sender before the oldest is dropped (~300 ms).
PER_SENDER_QUEUE = 5
#: Senders whose decoders are kept (one per participant).
MAX_DECODERS = 8


class Playout:
    """Per-sender queues of decoded PCM, mixed one frame at a time."""

    def __init__(self, frame_bytes: int):
        self.frame_bytes = frame_bytes
        self._queues: Dict[str, Deque[bytes]] = {}
        self._lock = threading.Lock()

    def push(self, who: str, pcm: bytes) -> None:
        with self._lock:
            q = self._queues.get(who)
            if q is None:
                if len(self._queues) >= MAX_DECODERS:
                    return
                q = self._queues[who] = collections.deque(maxlen=PER_SENDER_QUEUE)
            q.append(pcm)

    def next_frame(self) -> bytes:
        with self._lock:
            frames = [q.popleft() for q in self._queues.values() if q]
        if not frames:
            return b"\x00" * self.frame_bytes
        return mix(frames)[: self.frame_bytes].ljust(self.frame_bytes, b"\x00")

    def forget(self, who: str) -> None:
        with self._lock:
            self._queues.pop(who, None)


class GroupCallMedia:
    """The SAM datagram session and the audio for one group call."""

    def __init__(self, *, loop: asyncio.AbstractEventLoop, sam_host: str,
                 sam_port: int, printer: Callable[..., None] = print):
        self._loop = loop
        self._sam_host = sam_host
        self._sam_port = sam_port
        self._print = printer
        self._control = None
        self._session_id = ""
        self._dest = ""
        self._sock: Optional[socket.socket] = None
        self._transport = None
        self._calls = None
        self._running = False
        self._threads = []
        self._capture = None
        self._playback = None
        self._encoder = None
        self._decoders: Dict[str, Any] = {}
        self._playout = Playout(_voice.VOICE_FRAME_BYTES)
        self.stats = {"tx": 0, "rx": 0, "rx_bad": 0}

    @property
    def destination(self) -> str:
        return self._dest

    # -- the I2P datagram session --------------------------------------------

    async def open(self) -> str:
        """Create the SAM datagram session. Returns our public destination."""
        host = _voice._HOST
        sam_open, read_line, parse = host["sam_open"], host["sam_read_line"], host["sam_parse"]
        if not all((sam_open, read_line, parse)):
            raise RuntimeError("SAM helpers not bound")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.setblocking(False)
        port = self._sock.getsockname()[1]

        def create():
            ctrl = sam_open(self._sam_host, self._sam_port, _voice.SAM_HELLO_TIMEOUT)
            sid = "otrv4gcall_%s" % secrets.token_hex(6)
            ctrl.sendall(("SESSION CREATE STYLE=DATAGRAM ID=%s DESTINATION=TRANSIENT "
                          "SIGNATURE_TYPE=7 PORT=%d HOST=127.0.0.1 %s\n"
                          % (sid, port, _mediapath.tunnel_options())).encode("ascii"))
            fields = parse(read_line(ctrl, _voice.SAM_SESSION_TIMEOUT), "SESSION STATUS ")
            blob = fields.get("DESTINATION")
            if not blob:
                ctrl.close()
                raise RuntimeError("SESSION STATUS carried no DESTINATION")
            ctrl.settimeout(None)
            return ctrl, sid, blob

        self._control, self._session_id, blob = await self._loop.run_in_executor(None, create)
        # Only the public half is ever announced.
        self._dest = _voice.i2p_public_destination(blob)
        media = self

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                media._on_datagram(data)

        self._transport, _ = await self._loop.create_datagram_endpoint(
            _Proto, sock=self._sock)
        return self._dest

    def send_datagram(self, dest: str, packet: bytes) -> None:
        if self._transport is None:
            return
        header = _voice.build_datagram_send_header(self._session_id, dest)
        self._transport.sendto(header + packet, (self._sam_host, _voice.sam_udp_port()))
        self.stats["tx"] += 1

    def _on_datagram(self, data: bytes) -> None:
        _source, payload = _voice.split_datagram_receive(data)
        if not payload or self._calls is None:
            return
        if self._calls.on_datagram(payload):
            self.stats["rx"] += 1
        else:
            self.stats["rx_bad"] += 1

    # -- audio ------------------------------------------------------------------

    def start_audio(self, calls) -> None:
        """Open microphone and speaker and start moving frames."""
        self._calls = calls
        if not _voice._HOST["load_opus"]():
            raise RuntimeError("opuslib unavailable")
        opus = _voice._HOST["opus"]
        self._opus = opus
        self._encoder = opus.Encoder(_voice.VOICE_SAMPLE_RATE, _voice.VOICE_CHANNELS,
                                     opus.APPLICATION_VOIP)
        self._capture, notes = _audio.open_capture()
        for n in notes:
            self._print("[group call] %s" % n)
        self._playback, notes = _audio.open_playback(preferred=self._capture.name)
        for n in notes:
            self._print("[group call] %s" % n)
        self._running = True
        self._started = time.monotonic()
        for target in (self._capture_loop, self._playback_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def on_audio(self, room: str, who: str, frame: bytes) -> None:
        """A decrypted frame from `who` (called by GroupCalls)."""
        try:
            opus_frame = _voice.unpad_opus(frame)
        except Exception:
            return
        dec = self._decoders.get(who)
        if dec is None:
            if len(self._decoders) >= MAX_DECODERS or self._encoder is None:
                return
            dec = self._decoders[who] = self._opus.Decoder(
                _voice.VOICE_SAMPLE_RATE, _voice.VOICE_CHANNELS)
        try:
            pcm = dec.decode(opus_frame, _voice.VOICE_FRAME_SAMPLES)
        except Exception:
            return
        self._playout.push(who, bytes(pcm))

    def _capture_loop(self) -> None:
        while self._running:
            try:
                pcm = self._capture.read_frame(200)
            except Exception:
                break
            if not pcm or self._calls is None:
                continue
            try:
                encoded = self._encoder.encode(bytes(pcm), _voice.VOICE_FRAME_SAMPLES)
            except Exception:
                continue
            padded = _voice.pad_opus(encoded, int((time.monotonic() - self._started) * 1000))
            if padded is None:
                continue
            try:
                self._loop.call_soon_threadsafe(self._calls.send_audio, padded)
            except RuntimeError:
                break

    def _playback_loop(self) -> None:
        while self._running:
            try:
                self._playback.write_frame(self._playout.next_frame())
            except Exception:
                break

    # -- the end ------------------------------------------------------------------

    def close(self) -> None:
        self._running = False
        for stream in (self._capture, self._playback):
            if stream is not None:
                try:
                    stream.stop()
                except Exception:
                    pass
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._control is not None:
            try:
                self._control.close()
            except Exception:
                pass
            self._control = None
        self._decoders.clear()
        self._calls = None
