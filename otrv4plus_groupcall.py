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
  * Audio: the SAME chain as a 1:1 call (rc.62; group calls had a bare
    one -- no jitter buffer, no loss repair, no levelling):
      - send: microphone compressor and gain, Opus at the 1:1 settings
        (`configure_encoder`), the 1:1 padding (every frame the same size);
        the padded frame carries our frame number (as `send_ts_ms`, a
        multiple of the frame length) so receivers can order it;
      - receive, per member: the 1:1 adaptive JitterBuffer (reorders, sizes
        itself to the path's measured jitter, sheds latency after a burst),
        their own Opus decoder, in-band FEC for one lost frame and packet
        loss concealment for longer gaps;
      - mix, then the 1:1 speech clarity, speaker compressor and gain, and
        the device (paced by it).

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

__all__ = ["GroupCallMedia", "Playout", "frame_number"]

#: Senders whose decoders and buffers are kept (one per participant).
MAX_DECODERS = 8
#: A sender's frame number jumping BACK this far means their stream started
#: again (they hung up and rejoined): their buffer and decoder start afresh.
RESTART_FRAMES = 100
#: Concealment for a gap: at most this many synthesised frames (as 1:1).
MAX_CONCEAL = 3


def frame_number(send_ts_ms: int) -> int:
    """The sender's frame number. Ours send exactly n * FRAME_MS; a sender
    before rc.62 sent milliseconds since it started, which rounds to the same
    thing within a frame of capture jitter."""
    return int(round(int(send_ts_ms) / float(_voice.VOICE_FRAME_MS)))


class _Sender:
    """One member's receive side: their buffer and their decoder. The
    decoder is touched only by the playback thread (Opus state is not
    thread-safe); the buffer is locked internally."""

    __slots__ = ("jitter", "decoder", "pending", "highest")

    def __init__(self, decoder):
        self.jitter = _voice.JitterBuffer()
        self.decoder = decoder
        self.pending: Deque[bytes] = collections.deque()
        self.highest = -1


class Playout:
    """Per-sender jitter buffers and decoders, mixed one frame at a time."""

    def __init__(self, frame_bytes: int, make_decoder: Optional[Callable[[], Any]] = None):
        self.frame_bytes = frame_bytes
        self._make_decoder = make_decoder
        self._senders: Dict[str, _Sender] = {}
        self._lock = threading.Lock()
        self.stats = {"queued": 0, "late": 0, "fec": 0, "concealed": 0,
                      "decoded": 0, "restarts": 0, "dropped_senders": 0}

    def push(self, who: str, opus_frame: bytes, number: int) -> bool:
        """An Opus frame from `who` (network thread). False if refused."""
        with self._lock:
            st = self._senders.get(who)
            if st is not None and st.highest - number > RESTART_FRAMES:
                st = None                       # their stream restarted
                self.stats["restarts"] += 1
            if st is None:
                if who not in self._senders and len(self._senders) >= MAX_DECODERS:
                    self.stats["dropped_senders"] += 1
                    return False
                if self._make_decoder is None:
                    return False
                try:
                    st = _Sender(self._make_decoder())
                except Exception:
                    return False
                self._senders[who] = st
            st.highest = max(st.highest, number)
        ok = st.jitter.push(0, number, bytes(opus_frame))
        self.stats["queued" if ok else "late"] += 1
        return ok

    def _decode(self, st: _Sender, opus_frame, fec: bool = False):
        try:
            if opus_frame is None:
                pcm = st.decoder.decode(None, _voice.VOICE_FRAME_SAMPLES)
            elif fec:
                pcm = st.decoder.decode(bytes(opus_frame), _voice.VOICE_FRAME_SAMPLES,
                                        decode_fec=True)
            else:
                pcm = st.decoder.decode(bytes(opus_frame), _voice.VOICE_FRAME_SAMPLES)
        except Exception:
            return None
        return bytes(pcm)

    def _refill(self, st: _Sender) -> None:
        """Next frame(s) for one sender, as the 1:1 playback worker does: a
        single lost frame is rebuilt from the next frame's FEC copy, a longer
        gap is concealed (bounded)."""
        item = st.jitter.pop()
        if item is None:
            return
        opus_frame, gap = item
        if gap == 1:
            pcm = self._decode(st, opus_frame, fec=True)
            if pcm is not None:
                st.pending.append(pcm)
                self.stats["fec"] += 1
                gap = 0
        for _ in range(min(gap, MAX_CONCEAL)):
            pcm = self._decode(st, None)
            if pcm is None:
                break
            st.pending.append(pcm)
            self.stats["concealed"] += 1
        pcm = self._decode(st, opus_frame)
        if pcm is not None:
            st.pending.append(pcm)
            self.stats["decoded"] += 1

    def next_frame(self) -> bytes:
        """One frame of the mix (playback thread). Silence when idle."""
        with self._lock:
            senders = list(self._senders.values())
        frames = []
        for st in senders:
            if not st.pending:
                self._refill(st)
            if st.pending:
                frames.append(st.pending.popleft())
        if not frames:
            return b"\x00" * self.frame_bytes
        return mix(frames)[: self.frame_bytes].ljust(self.frame_bytes, b"\x00")

    def forget(self, who: str) -> None:
        with self._lock:
            st = self._senders.pop(who, None)
        if st is not None:
            st.jitter.clear()

    def describe(self) -> Dict[str, Any]:
        """Jitter-buffer state per sender, summed (diagnostics)."""
        with self._lock:
            senders = list(self._senders.values())
        out = dict(self.stats)
        out["senders"] = len(senders)
        out["depth"] = sum(st.jitter.depth() for st in senders)
        out["gaps"] = sum(st.jitter.stats.get("gaps", 0) for st in senders)
        out["underrun"] = sum(st.jitter.stats.get("underrun", 0) for st in senders)
        return out


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
        self._playout = Playout(_voice.VOICE_FRAME_BYTES, self._new_decoder)
        #: Our frame number: sent in place of a timestamp so receivers can
        #: order our frames exactly (see `frame_number`).
        self._seq = 0
        # The 1:1 levelling, both ways (otrv4plus_audio): compression and
        # gain on the microphone before Opus; speech clarity, compression
        # and gain on the mix before the speaker.
        self._mic_comp = _audio.make_mic_compressor()
        self._mic_gain = _audio.make_mic_gain()
        self._clarity = _audio.make_speech_clarity()
        self._speaker_comp = _audio.make_speaker_compressor()
        self._speaker_gain = _audio.make_speaker_gain()
        #: tx/rx: datagrams sent and accepted; rx_bad: received but refused
        #: (not a participant, failed authentication, replay); decoded: Opus
        #: frames decoded; heard: frames played that had someone's audio in
        #: them; play_err/cap_err: the speaker or microphone failing. Read by
        #: the app's diagnostics to tell which leg of a call is silent.
        self.stats = {"tx": 0, "rx": 0, "rx_bad": 0, "decoded": 0, "heard": 0,
                      "captured": 0, "play_err": 0, "cap_err": 0, "oversize": 0,
                      "reopened": 0}
        #: member -> monotonic time their last frame arrived (the watchdog's
        #: evidence that a leg of the call is alive; see GroupCallBridge).
        self._heard_at: Dict[str, float] = {}

    def describe(self) -> Dict[str, Any]:
        """Counters and the audio devices, for diagnostics (no addresses)."""
        out = dict(self.stats)
        out["decoded"] = self._playout.stats.get("decoded", 0)
        try:
            for key, value in self._playout.describe().items():
                out["jb_" + key] = value
        except Exception:
            pass
        out["playback"] = getattr(self._playback, "name", "") or ""
        out["capture"] = getattr(self._capture, "name", "") or ""
        out["usage"] = getattr(self._playback, "usage", "")
        return out

    @property
    def destination(self) -> str:
        return self._dest

    def last_heard(self, who: str) -> float:
        """When a frame from `who` last arrived (monotonic), 0 if never."""
        return self._heard_at.get(who, 0.0)

    # -- the I2P datagram session --------------------------------------------

    async def open(self) -> str:
        """Create the SAM datagram session. Returns our public destination."""
        (self._sock, self._transport, self._control, self._session_id,
         self._dest) = await self._create()
        return self._dest

    async def reopen(self) -> str:
        """A NEW datagram session (new tunnels, new destination) in place of
        the current one, which is closed once the new one is up -- we keep
        sending on the old one meanwhile. For a call where audio stopped
        arriving: our inbound tunnels, or the peer's cached route to them,
        are what a fresh destination replaces. Returns the new destination,
        which the caller announces to the group."""
        made = await self._create()
        old_transport, old_control = self._transport, self._control
        (self._sock, self._transport, self._control, self._session_id,
         self._dest) = made
        self.stats["reopened"] += 1
        for thing in (old_transport, old_control):
            if thing is not None:
                try:
                    thing.close()
                except Exception:
                    pass
        return self._dest

    async def _create(self):
        host = _voice._HOST
        sam_open, read_line, parse = host["sam_open"], host["sam_read_line"], host["sam_parse"]
        if not all((sam_open, read_line, parse)):
            raise RuntimeError("SAM helpers not bound")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        port = sock.getsockname()[1]

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

        try:
            control, session_id, blob = await self._loop.run_in_executor(None, create)
        except BaseException:
            sock.close()
            raise
        # Only the public half is ever announced.
        dest = _voice.i2p_public_destination(blob)
        media = self

        class _Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                media._on_datagram(data)

        transport, _ = await self._loop.create_datagram_endpoint(_Proto, sock=sock)
        return sock, transport, control, session_id, dest

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
        # The 1:1 settings: constant 24 kbit/s (frame sizes no longer follow
        # speech), voice tuning, the band the sample rate carries. It used to
        # be left at libopus defaults (variable rate).
        _voice.configure_encoder(self._encoder, opus)
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

    def _new_decoder(self):
        opus = getattr(self, "_opus", None) or _voice._HOST["opus"]
        return opus.Decoder(_voice.VOICE_SAMPLE_RATE, _voice.VOICE_CHANNELS)

    def on_audio(self, room: str, who: str, frame: bytes) -> None:
        """A decrypted frame from `who` (called by GroupCalls, network
        thread): into their jitter buffer. Decoded on the playback thread."""
        try:
            opus_frame, ts = _voice.unpad_frame(frame)
        except Exception:
            return
        if not opus_frame:
            return
        self._heard_at[who] = time.monotonic()
        self._playout.push(who, opus_frame, frame_number(ts))

    def _capture_loop(self) -> None:
        while self._running:
            try:
                raw = self._capture.read_frame(200)
            except Exception:
                self.stats["cap_err"] += 1
                break
            if not raw or self._calls is None:
                continue
            self.stats["captured"] += 1
            # Levelled before Opus, as in a 1:1 call: the encoder spends its
            # bits on what it is given, so a quiet microphone amplified at
            # the far end amplifies the coding noise with it.
            try:
                pcm = self._mic_gain.process(self._mic_comp.process(raw))
            except Exception:
                pcm = raw
            try:
                encoded = self._encoder.encode(bytes(pcm), _voice.VOICE_FRAME_SAMPLES)
            except Exception:
                continue
            seq, self._seq = self._seq, self._seq + 1
            padded = _voice.pad_opus(encoded, seq * _voice.VOICE_FRAME_MS)
            if padded is None:
                self.stats["oversize"] = self.stats.get("oversize", 0) + 1
                continue
            try:
                self._loop.call_soon_threadsafe(self._calls.send_audio, padded)
            except RuntimeError:
                break

    def _playback_loop(self) -> None:
        silence = b"\x00" * _voice.VOICE_FRAME_BYTES
        while self._running:
            frame = self._playout.next_frame()
            if frame != silence:
                self.stats["heard"] += 1
                try:
                    frame = bytes(self._speaker_gain.process(
                        self._speaker_comp.process(self._clarity.process(frame))))
                except Exception:
                    pass
            try:
                self._playback.write_frame(frame)
            except Exception:
                self.stats["play_err"] += 1
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
        for who in list(getattr(self._playout, "_senders", {})):
            self._playout.forget(who)
        self._calls = None
