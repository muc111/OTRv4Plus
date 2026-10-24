"""OTRv4+ encrypted voice subsystem — protocol v3 (hybrid X448 + ML-KEM-1024).

This module replaces the v2 voice code that lived inline in
``otrv4plus_xmpp.py``.  It is a separate module for one reason: the v2 code
could not be tested.  It was reachable only by importing a 6 200-line file
that pulls in slixmpp, opuslib and PulseAudio at import time, so the key
agreement, the rekey state machine and the replay window had no test
coverage at all.  Everything security-relevant in here imports nothing
beyond the standard library and the Rust core, and is exercised by
``tests/test_voice_security.py``.

The audio/SAM host helpers are injected by ``bind_host()`` rather than
duplicated.


WHAT CHANGED FROM v2, AND WHY
=============================

v2 derived the media root from X448 alone.  ML-KEM-1024 existed in the Rust
core and was bound into Python, but the voice path never called it: the OTR
*session* had post-quantum components while the *voice payload* did not.  A
recorded call was recoverable by an adversary with a CRQC.  v3 derives the
voice root from X448 **and** ML-KEM-1024, both mandatory.

v2 also:
  * identified calls solely by bare JID — ACCEPT/REKEY/END carried no
    call_id, so a message from a previous call terminated or rekeyed the
    current one;
  * used a constant AEAD AAD (b"OTRv4+voice"), leaving the wire header
    (generation, length) unauthenticated;
  * used an 8-bit wrapping generation with no ordering check, so a replayed
    REKEY was accepted and installed;
  * destroyed the current root *before* the rekey was confirmed, so a failed
    rekey killed a working call;
  * confirmed keys in one direction only — the callee started sending audio
    before it had any evidence the caller held the same key;
  * gated calls on a set populated by substring-matching printed log lines.

All of the above are fixed here.  See the engineering report for the full
list with file/function references.


PROTOCOL v3
===========

Roles are fixed by who sent the INVITE.  INITIATOR == caller == the side that
publishes a SAM destination and parks in STREAM ACCEPT.  RESPONDER == callee.

Control messages travel inside the established, DAKE-authenticated,
SMP-verified OTR channel.  Every one of them carries the call_id.

    INVITE      call_id | dest_b64 | x448_pub | mlkem_ek
    ACCEPT      call_id | x448_pub | mlkem_ct | confirm_responder
    CONFIRM     call_id | confirm_initiator
    REJECT      call_id | reason
    REKEY       call_id | epoch | x448_pub | mlkem_ek
    REKEYACK    call_id | epoch | x448_pub | mlkem_ct | confirm_responder
    REKEYCOMMIT call_id | epoch | confirm_initiator
    END         call_id

The initiator generates the ephemeral ML-KEM keypair and is the
decapsulator; the responder encapsulates.  That direction is chosen so the
1568-byte encapsulation key rides the INVITE, which the initiator is sending
anyway, and the 1568-byte ciphertext rides the ACCEPT.  Neither side has to
send both.

Key confirmation is two-way and role-labelled.  The responder proves
possession first (ACCEPT), the initiator second (CONFIRM).  Neither side
starts audio before the exchange completes, so a key mismatch never results
in a frame being emitted under a key the peer does not hold.


HYBRID KEY DERIVATION
=====================

    transcript = LP("OTRv4+Voice/v3")
              || LP(call_id)
              || LP(otr_binding)
              || LP(fp_low) || LP(fp_high)          # sorted, symmetric
              || LP(initiator_x448_pub)
              || LP(responder_x448_pub)
              || LP(mlkem_ek) || LP(mlkem_ct)
              || u64(epoch)

    ikm  = LP(x448_shared) || LP(mlkem_shared)      # BOTH mandatory
    salt = SHA-512("OTRv4+Voice/Salt/v3" || transcript)
    root = HKDF-SHA512(ikm, salt, info="OTRv4+Voice/Initial/v1" || transcript)

LP(x) is a 4-byte big-endian length prefix followed by x.  Every field is
length-prefixed, so no two distinct field sets can serialise to the same
byte string.  The hybrid is a concatenation KDF: an adversary must break
X448 *and* ML-KEM-1024 to recover the root, and is not weakened if either
primitive is later broken.

Directional media keys:

    K_dir = HKDF-SHA512(root, salt=call_id,
                        info="OTRv4+Voice/Media/v1" || LP(call_id)
                             || u64(epoch) || dir_byte)

dir_byte is 0x01 for initiator->responder and 0x02 for responder->initiator,
so the two endpoints never share an encryption key and their counters can
both start at zero.


MEDIA FRAME
===========

    off  0  sync        u8    0xA7
    off  1  version     u8    0x03
    off  2  frame_type  u8    0x01 (AUDIO — the only value ever sent)
    off  3  epoch       u64 BE
    off 11  counter     u64 BE
    off 19  length      u16 BE   (sealed length; constant for the call)
    off 21  ciphertext || GCM tag

    AAD   = "OTRv4+Voice/AAD/v3" || LP(call_id) || dir_byte || header[0:21]
    nonce = u32BE(epoch mod 2^32) || u64BE(counter)          # not transmitted

The nonce is derived from authenticated header fields rather than sent, so
it costs no bytes and cannot be tampered with independently of the header.
dir_byte is not on the wire — the receiver supplies the peer's direction
locally, so a frame reflected back at its own sender fails authentication.

Every security-relevant header field is inside the AAD.  Flipping the epoch,
the counter, the length or the frame type causes a tag failure.


SECURITY CLAIMS
===============

Claimed:
  * Confidentiality and integrity of media against a classical adversary,
    contingent on X448.
  * Confidentiality against a store-now-decrypt-later quantum adversary,
    contingent on ML-KEM-1024.  Both are required; neither alone suffices.
  * Forward secrecy within a call from the symmetric media ratchet, and
    across rekeys from the ephemeral hybrid exchange.
  * Post-compromise recovery at each successful hybrid rekey (not from the
    symmetric ratchet, which cannot provide it).
  * Media is bound to the call, epoch, direction and counter by the AEAD.

Not claimed:
  * Post-quantum *authentication* of the voice exchange.  The public keys
    are authenticated by the surrounding OTR channel; whether that channel's
    authentication is post-quantum depends on the DAKE, which this module
    does not audit.  A quantum adversary able to forge OTR authentication in
    real time could MITM a call.  Recorded calls remain protected.
  * Metadata protection beyond application-layer constant-rate traffic
    shaping.  Call timing, duration, tunnel behaviour, loss and congestion
    remain observable to a network adversary.  The XMPP server still sees
    that two parties exchanged encrypted stanzas.
  * Anything about the security of the OTR session itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import socket as _socket
import struct
import threading
import time

import otrv4plus_audio as _audio
import otrv4plus_mediapath as _mediapath

# Split out of this file; every name is re-exported here.
from otrv4plus_voice_params import G114_GOOD_MS, G114_WARN_MS  # noqa: F401
from otrv4plus_voice_params import (  # noqa: F401
    _env_int, _env_ms, M2E_GOOD_MS, M2E_WARN_MS, _ANSI_GREEN, _ANSI_YELLOW,
    _ANSI_RED, _ANSI_RESET, _colour_state, _colour_enabled, latency_band,
    colour_latency, latency_legend, _HOST, _default_cleanse, bind_host, _wipe,
    VOICE_PROTOCOL_VERSION, VOICE_SAMPLE_RATE, VOICE_FRAME_MS,
    VOICE_FRAME_SAMPLES, VOICE_CHANNELS, VOICE_FRAME_BYTES, FRAME_INTERVAL_S,
    VOICE_BITRATE, VOICE_COMPLEXITY, VOICE_LOSS_PCT, VOICE_TS_LEN,
    _derive_opus_slot, VOICE_OPUS_SLOT, VOICE_PLAIN_LEN, _OPUS_VALID_FRAME_MS,
    VOICE_OPUS_PEAK_BYTES, _OPUS_BANDWIDTH, opus_bandwidth, configure_encoder,
    VOICE_SYNC, FRAME_TYPE_AUDIO, FRAME_TYPE_PING, FRAME_TYPE_PONG,
    _FRAME_TYPES, VOICE_HDR_LEN, VOICE_HDR_FMT, VOICE_SEALED_LEN,
    VOICE_PACKET_LEN, SAM_REPLIABLE_OVERHEAD, I2P_TUNNEL_MESSAGE_PAYLOAD,
    VOICE_DATAGRAM_LEN, VOICE_MIN_FRAME, VOICE_MAX_FRAME, DIR_INITIATOR,
    DIR_RESPONDER, VOICE_JITTER_PREFILL_MS, VOICE_JITTER_DRIFT_HIGH_MS,
    VOICE_JITTER_MAX_MS, VOICE_JITTER_DRAIN_MS, VOICE_JITTER_SHED_MARGIN_MS,
    VOICE_JITTER_SAFETY_FACTOR, VOICE_JITTER_TAIL_PCT,
    VOICE_JITTER_TAIL_WINDOW, VOICE_JITTER_UNDERRUN_STEP,
    VOICE_JITTER_UNDERRUN_DECAY, VOICE_JITTER_PREFILL, VOICE_JITTER_MAX,
    VOICE_JITTER_SHED_MARGIN, VOICE_JITTER_DRIFT_HIGH,
    VOICE_JITTER_LATE_TOLERANCE, VOICE_SEND_BUFFER_BYTES,
    limit_media_send_buffer, _I2P_B64_TO_STD, _I2P_B64_FROM_STD,
    _KEYS_AND_CERT_PREFIX, i2p_b64decode, i2p_b64encode,
    i2p_public_destination, VOICE_TRANSPORT_DATAGRAM, VOICE_TRANSPORT_STREAM,
    SAM_UDP_PORT, SAM_DATAGRAM_MAX, voice_transport_mode, sam_udp_port,
    build_datagram_send_header, split_datagram_receive, VOICE_REKEY_SECONDS,
    VOICE_REKEY_TIMEOUT, VOICE_REKEY_MAX_CATCHUP, VOICE_RX_CHECK_S,
    VOICE_RX_WARN_S, VOICE_RX_DEAD_S, VOICE_RX_START_GRACE_S,
    VOICE_RX_SESSION_HOLD_S, VOICE_RECOVER_ATTEMPTS, VOICE_RECOVER_TIMEOUT_S,
    VOICE_MAX_MEDIAPATH_PER_MIN, VOICE_MAX_CONCURRENT_CALLS,
    VOICE_MIN_INVITE_INTERVAL, VOICE_MAX_CONTROL_PER_MIN,
    VOICE_MAX_REKEY_PER_MIN, SAM_HELLO_TIMEOUT, SAM_SESSION_TIMEOUT,
    SAM_ACCEPT_TIMEOUT, SAM_CONNECT_TIMEOUT,
)
from otrv4plus_voice_crypto import (  # noqa: F401
    MLKEM_EK_LEN, MLKEM_CT_LEN, MLKEM_SS_LEN, MLKEM_DK_LEN, KemUnavailable,
    _RustKem, _kem_self_test, _resolve_kem, kem_provider,
    set_kem_provider_for_testing, _lp, _u64, normalise_fingerprint,
    sorted_fingerprints, _LABEL_SALT, _LABEL_INITIAL, _LABEL_REKEY,
    _as_root_handle, _require_rust_voice, _LABEL_MEDIA, _LABEL_CONFIRM,
    _LABEL_RATCHET, _LABEL_ENDPOINT, _LABEL_AAD, _LABEL_VERSION, ROOT_LEN,
    MEDIA_KEY_LEN, CONFIRM_LEN, build_transcript, _salt_for,
    derive_voice_root, derive_rekey_root, derive_confirmations,
    derive_endpoint_tag, VoiceKeyExchange, ReplayWindow, FrameError,
    pack_media_header, parse_media_header, media_aad, media_nonce,
    VoiceFrameCrypto, CallState, IllegalTransition, VoiceKeySchedule,
)
from otrv4plus_voice_jitter import (  # noqa: F401
    JitterBuffer, pad_opus, unpad_frame, unpad_opus, Percentiles, StageTimers,
    LatencyTracker,
)


def _print(*args):
    _HOST["print"](*args)


#: What protects a call, in the words a user needs rather than the words the
#: code uses.  Named once so the terminal, the README and the tests cannot
#: drift apart, and derived from what this module actually does: the media
#: root is hybrid X448 + ML-KEM-1024 (both mandatory, neither alone
#: sufficient) and each frame is sealed with AES-256-GCM by a Rust-held key.
VOICE_SUITE_NAME = "X448 + ML-KEM-1024 → AES-256-GCM"

#: Whether the per-call setup detail is printed.
#:
#: Bringing a call up used to emit fourteen lines: codec, mic and speaker
#: gains, transport, shaping, audio backend, playout geometry, three loudness
#: lines and two about which Android stream the volume keys control.  All of
#: it is true and almost none of it is what a person wants at the moment they
#: start talking, and on a phone it pushed the one line that matters -- that
#: the call is up -- off the top of the screen.
#:
#: It is not deleted, because every one of those lines was added to answer a
#: real question during a real failure.  It is behind a flag: `--debug`, or
#: OTRV4PLUS_VOICE_VERBOSE=1 without one.
VOICE_VERBOSE = bool(os.environ.get("OTRV4PLUS_VOICE_VERBOSE"))


def set_voice_verbose(on: bool) -> None:
    """Turn the setup detail on, from the host's --debug flag."""
    global VOICE_VERBOSE
    VOICE_VERBOSE = bool(on) or bool(os.environ.get("OTRV4PLUS_VOICE_VERBOSE"))


def _vprint(*args):
    """Print only when the setup detail was asked for."""
    if VOICE_VERBOSE:
        _print(*args)


def _san(text, max_len=1024):
    return _HOST["sanitise"](text, max_len)


# ---------------------------------------------------------------------------
# Jitter buffer
# ---------------------------------------------------------------------------


class RateLimiter:
    """Per-peer token bucket for control messages.

    An INVITE costs an I2P tunnel build on both sides.  Without a limit a
    peer inside an established OTR session can force unbounded tunnel
    construction, which is a cheap remote resource-exhaustion attack against
    a phone.
    """

    MAX_TRACKED = 512          # distinct peers held before pruning kicks in

    def __init__(self, per_minute: int):
        self._per_minute = max(1, int(per_minute))
        self._events = {}
        self._last_prune = 0.0

    def _prune(self, now: float) -> None:
        """Bound the tracking table.

        Without this the dict grows one list per peer that has ever sent a
        call signal and never shrinks. handle_signal() rate-limits BEFORE the
        OTR and SMP gates — deliberately, so the gates cannot themselves be
        used as a workload — so the key set is driven by whoever talks to us,
        not by whoever we accept.

        Two stages. Expiry first: anything with nothing inside the window is
        free to drop and costs an attacker nothing to avoid. Then a hard cap,
        evicting least-recently-seen, because a flood of distinct JIDs inside
        a single window is all current and expiry alone would keep every one.

        The cap is a deliberate trade. Eviction resets a peer's budget, so a
        sufficiently wide flood can push a real peer out and buy itself a
        fresh allowance. That is acceptable: reaching this function at all
        requires an established OTR session, which costs the attacker an
        ML-KEM exchange, an ML-DSA signature and a ring signature per JID —
        far more than it costs us. Unbounded memory is the worse failure.
        """
        cutoff = now - 60.0
        for key in [k for k, w in self._events.items()
                    if not w or w[-1] < cutoff]:
            self._events.pop(key, None)
        if len(self._events) > self.MAX_TRACKED:
            ordered = sorted(self._events.items(),
                             key=lambda kv: kv[1][-1] if kv[1] else 0.0)
            for key, _w in ordered[:len(self._events) - self.MAX_TRACKED]:
                self._events.pop(key, None)
        self._last_prune = now

    def allow(self, key: str, now=None) -> bool:
        now = time.monotonic() if now is None else now
        if now - self._last_prune > 60.0 or len(self._events) > self.MAX_TRACKED:
            self._prune(now)
        window = self._events.setdefault(key, [])
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.pop(0)
        if len(window) >= self._per_minute:
            return False
        window.append(now)
        return True

    def forget(self, key: str) -> None:
        self._events.pop(key, None)


# ---------------------------------------------------------------------------
# Call session
# ---------------------------------------------------------------------------

#: Every media counter, in one place. Test doubles build their stats from
#: here rather than restating the keys, so adding a counter cannot leave a
#: fake behind with a KeyError.
MEDIA_STAT_KEYS = (
    "sent", "recv", "dropped", "late", "oversize", "backpressure",
    # `dropped` is the total of these two, kept for the diagnostics that
    # read it. It counts LOCAL failures only -- a frame we could not encode,
    # seal or hand to the transport (tx), or bytes that arrived and did not
    # form an authentic frame (rx). It is not loss in transit ("missing")
    # and not frames discarded to cut latency ("shed"), which is why a call
    # can end with dropped=0 and still have lost audio. See
    # otrv4plus_mediapath.COUNTER_DEFINITIONS.
    "tx_dropped", "rx_dropped",
    "auth_fail", "replay", "resync", "fec_recovered", "stale", "foreign",
    # Rejection causes, split out at v10.13.1.  `auth_fail` used to absorb
    # all of these, so "authfail=87" could equally mean a forged frame or a
    # peer that had rekeyed ahead of us.  Only `auth_fail` is now an
    # authentication failure; the others are state, not attack.
    "rej_no_key", "rej_retired", "rej_malformed",
    # Raw arrivals, counted before every filter. Without this, recv=0 with
    # every rejection counter also at 0 is ambiguous: nothing arrived, or
    # things arrived and were discarded on a path that counts nothing. The
    # live failure produced exactly that reading and could not be classified
    # from it.
    "dgram_in", "dgram_empty", "dgram_closed",
)


def new_media_stats() -> dict:
    return {name: 0 for name in MEDIA_STAT_KEYS}


class VoiceCallSession:
    """One encrypted call carried over a single bidirectional SAM stream.

    TRANSPORT
    ---------
    Exactly one SAM stream, used full-duplex.  Both peers opening an outbound
    stream deadlocks, because each only begins listening after its own
    connect returns.  Roles are therefore fixed by who initiated: the
    initiator publishes a TRANSIENT destination and parks in STREAM ACCEPT
    before the INVITE is sent, so the responder's connect always finds a
    listener.

    THREADING
    ---------
    capture thread : AAudio/parec -> Opus -> AEAD -> event loop
    asyncio reader : socket -> AEAD -> Opus -> jitter buffer
    playback thread: jitter buffer -> AAudio/pacat

    Blocking device I/O never touches the event loop.  The key schedule is
    read from the capture thread and mutated from the loop, so it is guarded
    by a lock — v2 read `self._crypto` and `self._send_gen` unsynchronised
    and could label a frame with one epoch while sealing it under another.
    """

    ROLE_INITIATOR = "initiator"
    ROLE_RESPONDER = "responder"

    def __init__(self, peer, loop, call_id, is_initiator,
                 sam_host="127.0.0.1", sam_port=7656):
        if not call_id or len(call_id) != 16:
            raise ValueError("call_id must be exactly 16 bytes")

        self.peer = peer
        self.loop = loop
        self.call_id = bytes(call_id)
        self.is_initiator = bool(is_initiator)
        self.role = (self.ROLE_INITIATOR if is_initiator
                     else self.ROLE_RESPONDER)
        self.sam_host = sam_host
        self.sam_port = sam_port

        self.state = CallState.IDLE
        self._state_lock = threading.Lock()
        self._key_lock = threading.Lock()

        self.kex = VoiceKeyExchange(self.is_initiator)
        self.schedule = VoiceKeySchedule(self.call_id, self.is_initiator)
        self.our_confirm = None            # tag we send
        self.peer_confirm_expected = None  # tag the peer must send
        self.keys_confirmed = asyncio.Event()

        self.otr_material = None           # (otr_binding, local_fp, remote_fp)
        self._peer_dest = None
        self._peer_x448 = None
        self._peer_mlkem_ek = None
        self._mlkem_ct = None              # responder's ciphertext (transcript)
        self._rekey_kex = None
        self._rekey_waiter = None          # (epoch, Future) while in flight
        # (epoch, confirm_hex) of the last REKEYCOMMIT we sent.  Initiator
        # only; retransmitted with the next REKEY so a lost commit cannot
        # strand the responder an epoch behind for the rest of the call.
        # The tag is a public MAC output that already travelled the wire.
        self._last_rekey_commit = None

        self._sam_control = None
        #: Control sockets whose SESSION CREATE is still in flight. The
        #: create runs in an executor, so cancelling the coroutine that
        #: awaits it does NOT stop the thread: it finishes, returns a live
        #: socket to a caller that has gone, and the router-side session
        #: stays open for the life of the process. Publishing the socket the
        #: moment it exists is what makes it reclaimable.
        self._sam_pending = []
        self._sam_session_id = None
        self._transport_mode = voice_transport_mode()
        self._dgram_sock = None          # our bound UDP receive socket
        self._dgram_transport = None     # asyncio datagram transport
        self._dgram_send_addr = None     # (host, port) of the SAM UDP bridge
        self._dgram_send_header = None   # cached "3.0 <session> <dest>\n"
        self._foreign_warned = False
        #: Pipeline stage timings. See StageTimers -- this is what separates
        #: "I2P is slow" from "we are slow" inside the one-way figure.
        self.stages = StageTimers()
        # Level control. Two devices on one call measured 4090 and 31226 for
        # the same microphone self-test, so the far end heard one of them as
        # a quiet, thin call regardless of the codec settings.
        self._mic_gain = _audio.make_mic_gain()
        self._speaker_gain = _audio.make_speaker_gain()
        # Compression before gain. Peak gain cannot make a call loud: speech
        # has a 12-18 dB crest factor, so playback measured 24422 of 32767 --
        # 2.5 dB from full scale -- and was still described as barely
        # audible. There was no headroom left to turn up because the peaks
        # were never the problem; the quiet parts were.
        self._mic_comp = _audio.make_mic_compressor()
        self._speaker_comp = _audio.make_speaker_compressor()
        # Ahead of the compressor, not after it. Measured on speech with a
        # 60 Hz rumble: the high-pass takes level the compressor was turning
        # the whole frame down for, and the presence lift puts the consonant
        # band back that a loudness compressor flattens. Speech RMS goes
        # -16.0 -> -13.9 dBFS at an unchanged -1.0 dBFS peak, and the 1-4 kHz
        # share of energy 0.348 -> 0.421. Louder voice, same headroom.
        self._speech_clarity = _audio.make_speech_clarity()
        self._our_dest = None
        self._media_sock = None
        self._accept_sock = None
        self._writer = None
        self._reader = None

        self._capture = None      # otrv4plus_audio capture stream
        self._playback = None     # otrv4plus_audio playback stream
        self.audio_backend = None
        self._audio_env = None
        self._opus_enc = None
        self._opus_dec = None
        self._silence_frame = None
        self.constant_rate = False

        self._capture_thread = None
        self._playback_thread = None
        self._reader_task = None
        self._rx_watchdog_task = None
        self._rx_last_datagram = None   # monotonic: anything at the socket
        self._rx_last_frame = None      # monotonic: anything that authenticated
        self._rx_degraded = False       # a warning is outstanding
        #: Media-endpoint announcements. Both counters are per call, so they
        #: cannot be carried into the call that replaces this one.
        self._endpoint_seq_sent = 0     # last sequence we announced
        self._endpoint_seq_seen = 0     # highest we have accepted
        #: Authenticated inbound frames, and the reading taken when the media
        #: path was last rebuilt. A rebuild resets the liveness clock so the
        #: new path gets a fair chance, which means the clock alone cannot
        #: distinguish "media resumed" from "we just reset the clock" -- only
        #: this counter moving past the mark proves anything arrived.
        self._rx_authenticated = 0
        self._rx_mark = 0
        self._recover_task = None
        self._recover_attempts = 0
        self._recovering = False        # a rebuild is genuinely in flight
        #: The endpoint was replaced but the peer was never told, because the
        #: control plane was down when the announcement went out. Rebuilding
        #: again would destroy a second endpoint for nothing; what is missing
        #: is the announcement, so that is what gets retried.
        self._endpoint_announce_pending = False
        self.on_media_stalled = None    # set by the manager, call_id-bound
        self._accept_task = None
        self._prewarm = None

        self.jitter = JitterBuffer()
        self.latency = LatencyTracker()
        self._call_t0 = time.monotonic()   # frame-timestamp origin
        self._muted = False
        self._running = False
        self._closing = False
        self.on_stream_lost = None
        self._loss_signalled = False
        self.debug_binding = False

        self.stats = new_media_stats()

    # -- state machine ----------------------------------------------------

    def transition(self, new_state: str) -> None:
        """Move to a new state or raise.  ENDED is absorbing."""
        with self._state_lock:
            current = self.state
            if new_state == current:
                return
            if new_state not in CallState.ALLOWED.get(current, set()):
                raise IllegalTransition(
                    "illegal call transition %s -> %s" % (current, new_state))
            self.state = new_state

    def try_transition(self, new_state: str) -> bool:
        """Transition if legal.  For async callbacks that may race teardown."""
        try:
            self.transition(new_state)
            return True
        except IllegalTransition:
            return False

    @property
    def is_live(self) -> bool:
        return self.state in CallState.LIVE

    @property
    def is_ended(self) -> bool:
        return self.state in (CallState.ENDING, CallState.ENDED)

    # -- key agreement ----------------------------------------------------

    def _transcript(self, epoch: int, initiator_pub: bytes,
                    responder_pub: bytes, mlkem_ek: bytes,
                    mlkem_ct: bytes) -> bytes:
        otr_binding, local_fp, remote_fp = self.otr_material
        return build_transcript(self.call_id, otr_binding, local_fp, remote_fp,
                                initiator_pub, responder_pub, mlkem_ek,
                                mlkem_ct, epoch)

    def responder_derive(self, peer_x448_pub: bytes, peer_mlkem_ek: bytes):
        """Responder: complete the hybrid exchange for epoch 0.

        Returns (our_confirm, peer_confirm_expected, mlkem_ct).
        """
        if self.is_initiator:
            raise RuntimeError("responder_derive called on the initiator")
        if self.schedule.ready:
            raise RuntimeError("media keys already derived")

        agreement, mlkem_ct = self.kex.responder_agree(
            peer_x448_pub, peer_mlkem_ek)
        try:
            transcript = self._transcript(0, peer_x448_pub, self.kex.public,
                                          peer_mlkem_ek, mlkem_ct)
            self._debug_transcript(agreement, transcript)
            root = agreement.into_root(transcript)
        finally:
            agreement.zeroize()
            self.kex.destroy()

        # The schedule owns the handle from here; zeroize() on teardown is
        # what destroys it, so there is nothing to wipe locally.
        confirm_i, confirm_r = self.schedule.install_initial(root)

        self._mlkem_ct = mlkem_ct
        self._peer_x448 = peer_x448_pub
        self._peer_mlkem_ek = peer_mlkem_ek
        self.our_confirm = confirm_r
        self.peer_confirm_expected = confirm_i
        return confirm_r, confirm_i, mlkem_ct

    def initiator_derive(self, peer_x448_pub: bytes, mlkem_ct: bytes):
        """Initiator: complete the hybrid exchange for epoch 0.

        Returns (our_confirm, peer_confirm_expected).
        """
        if not self.is_initiator:
            raise RuntimeError("initiator_derive called on the responder")
        if self.schedule.ready:
            raise RuntimeError("media keys already derived")

        agreement = self.kex.initiator_agree(peer_x448_pub, mlkem_ct)
        try:
            transcript = self._transcript(0, self.kex.public, peer_x448_pub,
                                          self.kex.mlkem_ek, mlkem_ct)
            self._debug_transcript(agreement, transcript)
            root = agreement.into_root(transcript)
        finally:
            agreement.zeroize()
            self.kex.destroy()

        # The schedule owns the handle from here; zeroize() on teardown is
        # what destroys it, so there is nothing to wipe locally.
        confirm_i, confirm_r = self.schedule.install_initial(root)

        self._mlkem_ct = mlkem_ct
        self._peer_x448 = peer_x448_pub
        self.our_confirm = confirm_i
        self.peer_confirm_expected = confirm_r
        return confirm_i, confirm_r

    def verify_peer_confirm(self, peer_confirm: bytes) -> bool:
        """Constant-time check of the peer's epoch-0 confirmation tag."""
        if self.peer_confirm_expected is None:
            return False
        return hmac.compare_digest(bytes(peer_confirm or b""),
                                   self.peer_confirm_expected)

    def mark_keys_confirmed(self) -> None:
        try:
            self.loop.call_soon_threadsafe(self.keys_confirmed.set)
        except Exception:
            self.keys_confirmed.set()

    def _debug_transcript(self, agreement, transcript) -> None:
        """Digests only, never raw secrets -- and the secret digests are
        computed inside Rust (`RustVoiceAgreement.digests`), so the secrets
        themselves are not in reach of this function.

        Comparing these five lines across the two devices names precisely
        which input differs when a confirmation mismatch occurs — that is the
        whole diagnosis, and it costs nothing.
        """
        if not self.debug_binding:
            return

        def d(label, value):
            raw = value if isinstance(value, (bytes, bytearray)) \
                else str(value).encode()
            return "%s=%s" % (label, hashlib.sha256(bytes(raw)).hexdigest()[:12])

        x_digest, k_digest = agreement.digests()
        _print("[voice-bind] role=%s x448=%s mlkem=%s %s %s"
               % (self.role, x_digest, k_digest,
                  d("transcript", transcript), d("callid", self.call_id)))

    # -- rekey ------------------------------------------------------------

    def begin_rekey_initiator(self):
        """Initiator: fresh ephemerals for epoch+1.  Returns (epoch, kex)."""
        epoch = self.schedule.epoch + 1
        kex = VoiceKeyExchange(True)
        self._rekey_kex = kex
        return epoch, kex

    def rekey_responder(self, epoch: int, peer_x448_pub: bytes,
                        peer_mlkem_ek: bytes):
        """Responder: derive the pending epoch and return (our_confirm, ct).

        Nothing is committed here.  The current epoch keeps encrypting and
        decrypting until REKEYCOMMIT verifies.
        """
        kex = VoiceKeyExchange(False)
        try:
            agreement, mlkem_ct = kex.responder_agree(peer_x448_pub,
                                                      peer_mlkem_ek)
        finally:
            kex.destroy()
        try:
            transcript = self._transcript(epoch, peer_x448_pub, kex.public,
                                          peer_mlkem_ek, mlkem_ct)
            with self._key_lock:
                # derive_rekey chains inside Rust: neither the old root nor
                # the new one is ever a Python object.  The schedule takes
                # ownership of the handle, so there is nothing left here to
                # wipe -- abort_rekey and commit_rekey zeroize it.
                new_root = agreement.into_rekey_root(
                    self.schedule.current_root(), transcript)
                self.schedule.begin_rekey(epoch, new_root)
                our_confirm = self.schedule.our_confirm()
        finally:
            agreement.zeroize()
        return our_confirm, mlkem_ct, kex.public

    def rekey_initiator_finish(self, epoch: int, peer_x448_pub: bytes,
                               mlkem_ct: bytes):
        """Initiator: derive the pending epoch from the REKEYACK.

        Returns (our_confirm, peer_confirm_expected).
        """
        kex = self._rekey_kex
        if kex is None:
            raise RuntimeError("no rekey in progress")
        try:
            agreement = kex.initiator_agree(peer_x448_pub, mlkem_ct)
        finally:
            kex.destroy()
            self._rekey_kex = None
        try:
            transcript = self._transcript(epoch, kex.public, peer_x448_pub,
                                          kex.mlkem_ek, mlkem_ct)
            with self._key_lock:
                new_root = agreement.into_rekey_root(
                    self.schedule.current_root(), transcript)
                self.schedule.begin_rekey(epoch, new_root)
                return (self.schedule.our_confirm(),
                        self.schedule.expected_peer_confirm())
        finally:
            agreement.zeroize()

    def commit_rekey(self, epoch: int, peer_confirm: bytes) -> bool:
        with self._key_lock:
            return self.schedule.commit_rekey(epoch, peer_confirm)

    def abort_rekey(self, discard_receive: bool = False) -> None:
        with self._key_lock:
            self.schedule.abort_rekey(discard_receive=discard_receive)

    # -- SAM transport ----------------------------------------------------

    async def create_session(self, session_timeout=None) -> str:
        """Create a TRANSIENT SAM session.  Returns our base64 destination.

        ``session_timeout`` bounds the blocking SESSION STATUS read. Recovery
        passes its own budget so the executor thread cannot outlive the
        deadline its caller is held to.
        """
        if session_timeout is None:
            session_timeout = SAM_SESSION_TIMEOUT
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            # A path built before the call (otrv4plus_warmpath: the green
            # phone) skips the 30-120 s tunnel build. A fresh transient
            # destination like any other, used for this call only.
            try:
                import otrv4plus_warmpath as _warmpath
                spare = _warmpath.WARM.take((self.sam_host, self.sam_port))
            except Exception:
                spare = None
            if spare is not None:
                self._dgram_sock = spare.sock
                self._sam_control, self._sam_session_id = spare.control, spare.session_id
                self._our_dest = spare.dest
                try:
                    self.stats["warm_path"] = 1
                except Exception:
                    pass
                return self._our_dest
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]
        if not all((sam_open, sam_read_line, sam_parse)):
            raise RuntimeError("SAM helpers not bound — call bind_host()")

        # In datagram mode the router forwards inbound datagrams to a UDP
        # port of our choosing, so the socket has to exist -- and its port be
        # known -- before SESSION CREATE is sent.
        forward_port = 0
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            try:
                forward_port = self._bind_datagram_socket()
            except Exception as exc:
                _print("[voice] datagram transport unavailable (%s); "
                       "falling back to the stream transport"
                       % _san(str(exc), 120))
                self._transport_mode = VOICE_TRANSPORT_STREAM

        def _create():
            ctrl = sam_open(self.sam_host, self.sam_port, SAM_HELLO_TIMEOUT)
            # Reachable from the session before the blocking read starts, so
            # a cancelled await cannot strand it.
            self._sam_pending.append(ctrl)
            try:
                session_id = "otrv4voice_%s" % secrets.token_hex(6)
                if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
                    # STYLE=DATAGRAM is repliable: the sender's destination
                    # arrives with every packet, which gives a cheap pre-AEAD
                    # filter and lets the initiator learn the callee's
                    # destination without extra signalling. PORT/HOST ask the
                    # router to forward inbound datagrams straight to us
                    # rather than multiplexing them onto the control socket.
                    #
                    # The tunnel options are the 3-hop requirement, asked for
                    # rather than assumed. This client used to send no tunnel
                    # length at all and print "6 I2P hops" anyway, so a router
                    # configured with inbound.length=1 -- a common latency
                    # tweak -- would have been given a 1-hop path with nothing
                    # noticing. See otrv4plus_mediapath.TUNNEL_OPTIONS for why
                    # the variance is pinned too (length alone is a midpoint,
                    # not a floor) and hops_are_confirmed() for why this is
                    # still only a request: SAM's SESSION STATUS reply carries
                    # RESULT and DESTINATION and never says what it built.
                    create = ("SESSION CREATE STYLE=DATAGRAM ID=%s "
                              "DESTINATION=TRANSIENT SIGNATURE_TYPE=7 "
                              "PORT=%d HOST=127.0.0.1 %s\n"
                              % (session_id, forward_port,
                                 _mediapath.tunnel_options()))
                else:
                    create = ("SESSION CREATE STYLE=STREAM ID=%s "
                              "DESTINATION=TRANSIENT SIGNATURE_TYPE=7 %s\n"
                              % (session_id, _mediapath.tunnel_options()))
                ctrl.sendall(create.encode("ascii"))
                # i2pd builds a full tunnel set before answering, so this is
                # minutes rather than seconds on a busy phone.
                fields = sam_parse(sam_read_line(ctrl, session_timeout),
                                   "SESSION STATUS ")
                dest = fields.get("DESTINATION")
                if not dest:
                    raise RuntimeError("SESSION STATUS carried no DESTINATION")
                ctrl.settimeout(None)
                return ctrl, session_id, dest
            except Exception:
                self._discard_pending_sam(ctrl)
                raise

        control, session_id, blob = await self.loop.run_in_executor(
            None, _create)
        # Handed over: it is the live session now, not a pending one.
        try:
            self._sam_pending.remove(control)
        except ValueError:
            pass
        self._sam_control, self._sam_session_id = control, session_id
        # SESSION STATUS hands back the private key blob. Nothing after this
        # point needs it -- the session is bound to the control socket, not to
        # the key -- so derive the destination and let the blob go.
        try:
            self._our_dest = i2p_public_destination(blob)
        except ValueError as exc:
            raise RuntimeError("SAM returned an unparseable DESTINATION: %s"
                               % exc)
        return self._our_dest

    # -- datagram transport ------------------------------------------------

    def _bind_datagram_socket(self) -> int:
        """Bind the UDP socket the router will forward our media to.

        Returns the port, which SESSION CREATE has to carry.  Bound to
        loopback only: this socket accepts anything the host can send it, and
        the AEAD is the only thing standing behind it, so it must not be
        reachable off the device.
        """
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", 0))
            sock.setblocking(False)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise
        self._dgram_sock = sock
        return sock.getsockname()[1]

    def _datagram_ready(self) -> bool:
        return (self._transport_mode == VOICE_TRANSPORT_DATAGRAM
                and self._dgram_transport is not None)

    async def open_datagram_endpoint(self) -> None:
        """Attach the bound UDP socket to the event loop and arm sending."""
        if self._transport_mode != VOICE_TRANSPORT_DATAGRAM:
            return
        if self._dgram_sock is None:
            raise RuntimeError("datagram socket was never bound")

        session = self

        class _MediaDatagramProtocol(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                session._on_datagram(data)

            def error_received(self, exc):
                # ICMP port-unreachable from the SAM bridge arrives here.  It
                # is per-packet and recoverable, so it must not tear the call
                # down; the stats already show the result as silence.
                session.stats["dropped"] += 1
                session.stats["tx_dropped"] = session.stats.get("tx_dropped", 0) + 1

        transport, _proto = await self.loop.create_datagram_endpoint(
            _MediaDatagramProtocol, sock=self._dgram_sock)
        self._dgram_transport = transport
        self._dgram_send_addr = (self.sam_host, sam_udp_port())
        self._refresh_datagram_header()

    def _refresh_datagram_header(self) -> None:
        """Cache the SAM send header once the peer destination is known."""
        if self._sam_session_id and self._peer_dest:
            self._dgram_send_header = build_datagram_send_header(
                self._sam_session_id, self._peer_dest)
        else:
            self._dgram_send_header = None

    def _on_datagram(self, data: bytes) -> None:
        """One forwarded SAM datagram -> AEAD -> jitter buffer.

        A datagram boundary is a frame boundary, so unlike the stream path
        there is no reassembly and no resynchronisation across packets: a
        corrupt datagram costs exactly itself.
        """
        # Counted first, before every filter, and stamped before every
        # possible return. This is what separates "the router stopped
        # forwarding" from "datagrams are arriving and being discarded" --
        # a distinction the previous telemetry could not make, because both
        # read as rx=0 with every rejection counter at 0.
        self.stats["dgram_in"] += 1
        self._rx_last_datagram = time.monotonic()
        if not self._running:
            self.stats["dgram_closed"] += 1
            return
        source, payload = split_datagram_receive(data)
        if not payload:
            self.stats["dgram_empty"] += 1
            return
        # Cheap pre-AEAD filter.  Not a security boundary -- the AEAD is --
        # but it keeps an unrelated sender from reaching the cipher at all.
        #
        # Counted separately from "dropped". When this filter was comparing a
        # destination against a private key blob it discarded every packet of
        # the call, and folded into the general drop counter that was
        # indistinguishable from a path losing frames.
        if (source is not None and self._peer_dest
                and source != self._peer_dest):
            self.stats["foreign"] += 1
            if not self._foreign_warned:
                self._foreign_warned = True
                _print("[voice] media datagrams are arriving from a "
                       "destination other than the peer's and are being "
                       "discarded — if the call is silent, the two sides "
                       "disagree about the peer's destination")
            return
        before = self.stats["recv"]
        buf = bytearray(payload)
        try:
            self._drain_buffer(buf)
        except Exception:
            self.stats["dropped"] += 1
            self.stats["rx_dropped"] = self.stats.get("rx_dropped", 0) + 1
        finally:
            _wipe(buf)
        # The initiator never learns the callee's destination from signalling:
        # it published one and waited to be connected to.  Latching it from
        # the first datagram that actually authenticates is safe -- an
        # attacker cannot produce one -- and saves a signalling round trip.
        if (source is not None and self._peer_dest is None
                and self.stats["recv"] > before):
            self._peer_dest = source
            self._refresh_datagram_header()

    def _send_datagram(self, packet: bytes) -> bool:
        """Send one media packet through the SAM UDP bridge."""
        header = self._dgram_send_header
        if header is None or self._dgram_transport is None:
            return False
        try:
            self._dgram_transport.sendto(header + packet,
                                         self._dgram_send_addr)
            return True
        except Exception:
            return False

    async def accept_media_stream(self) -> None:
        """Park in STREAM ACCEPT until the peer connects (initiator role)."""
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            # Nothing to accept: datagrams need no connection.  The initiator
            # cannot send until the callee's first packet arrives and
            # _on_datagram latches its destination, which happens within one
            # frame of the callee starting audio.
            await self.open_datagram_endpoint()
            return
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]

        def _accept():
            sock = sam_open(self.sam_host, self.sam_port, SAM_HELLO_TIMEOUT)
            # Published before blocking: cancelling the future does NOT
            # interrupt an executor thread parked in recv().  Closing the
            # socket from outside is the only thing that releases it, so the
            # handle must be reachable while the thread is blocked.
            self._accept_sock = sock
            try:
                sock.sendall(("STREAM ACCEPT ID=%s SILENT=false\n"
                              % self._sam_session_id).encode("ascii"))
                # Line 1: accept registered.
                sam_parse(sam_read_line(sock, SAM_SESSION_TIMEOUT),
                          "STREAM STATUS ")
                # Line 2: blocks until a peer connects, then carries their
                # destination.  Consuming it exactly is essential — one
                # over-read here is misparsed as audio and every subsequent
                # frame boundary is wrong.
                sam_read_line(sock, SAM_ACCEPT_TIMEOUT)
                sock.settimeout(None)
                limit_media_send_buffer(sock)
                sock.setblocking(False)
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                self._accept_sock = None
                raise

        try:
            self._media_sock = await self.loop.run_in_executor(None, _accept)
        finally:
            self._accept_sock = None
        self._reader, self._writer = await asyncio.open_connection(
            sock=self._media_sock)

    async def connect_media_stream(self, peer_dest: str) -> None:
        """STREAM CONNECT to the initiator's destination (responder role)."""
        if not peer_dest or len(peer_dest) < 64:
            raise RuntimeError("peer destination missing or implausibly short")
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            self._peer_dest = peer_dest
            await self.open_datagram_endpoint()
            return
        sam_open = _HOST["sam_open"]
        sam_read_line = _HOST["sam_read_line"]
        sam_parse = _HOST["sam_parse"]

        def _connect():
            sock = sam_open(self.sam_host, self.sam_port, SAM_CONNECT_TIMEOUT)
            try:
                sock.sendall(
                    ("STREAM CONNECT ID=%s DESTINATION=%s SILENT=false\n"
                     % (self._sam_session_id, peer_dest)).encode("ascii"))
                sam_parse(sam_read_line(sock, SAM_CONNECT_TIMEOUT),
                          "STREAM STATUS ")
                sock.settimeout(None)
                limit_media_send_buffer(sock)
                sock.setblocking(False)
                return sock
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                raise

        self._media_sock = await self.loop.run_in_executor(None, _connect)
        self._reader, self._writer = await asyncio.open_connection(
            sock=self._media_sock)

    # -- codec and audio processes ----------------------------------------

    def _build_codec(self) -> None:
        """Instantiate and tune the Opus encoder/decoder.

        Each CTL is applied individually: a libopus build lacking one must not
        prevent the others from being applied.
        """
        if not _HOST["load_opus"]():
            raise RuntimeError("opuslib unavailable")
        opus = _HOST["opus"]
        if opus is None:
            raise RuntimeError("opus module not bound")

        self._opus_enc = opus.Encoder(VOICE_SAMPLE_RATE, VOICE_CHANNELS,
                                      opus.APPLICATION_VOIP)
        self._opus_dec = opus.Decoder(VOICE_SAMPLE_RATE, VOICE_CHANNELS)

        applied, failed = configure_encoder(self._opus_enc, opus)

        # VBR and DTX are the two settings that leak conversation rhythm.  If
        # either could not be disabled the constant-rate property does not
        # hold and the user is told plainly rather than left believing in
        # protection they do not have.
        self.constant_rate = ("vbr" in applied) and ("dtx" in applied)

        _vprint("[voice] codec: Opus %d Hz mono, %d ms frames, %d kbit/s %s"
                % (VOICE_SAMPLE_RATE, VOICE_FRAME_MS, VOICE_BITRATE // 1000,
                  "CBR" if self.constant_rate else "VBR"))
        _vprint("[voice] levels: mic gain %.2f%s, speaker gain %.2f, "
                "playback compressor %s (%.0f dB makeup) — output is limited "
                "so nothing here can clip"
                % (self._mic_gain.gain,
                  " + auto" if self._mic_gain.auto else "",
                  self._speaker_gain.gain,
                  "on" if self._speaker_comp.enabled else "off",
                  self._speaker_comp.makeup_db))
        if self._playback_usage_is_voice():
            _vprint("[voice] playback is declared as VOICE_COMMUNICATION, "
                    "which some phones route to the EARPIECE rather than the "
                    "speaker. If the level readings below look healthy but "
                    "the call is still faint, that is routing, not gain: set "
                    "OTRV4PLUS_AUDIO_USAGE=media.")
        if self._transport_mode == VOICE_TRANSPORT_DATAGRAM:
            _vprint("[voice] transport: I2P datagrams — no retransmission, so "
                    "congestion arrives as loss (concealed) rather than as "
                    "delay that accumulates.")
        else:
            _vprint("[voice] transport: I2P streams — reliable and ordered, so "
                    "a lost segment stalls everything behind it for one 9 s "
                    "retransmit timeout. Unset OTRV4PLUS_VOICE_TRANSPORT for "
                    "datagrams.")
        # The shaping line stays at normal volume when it is BAD news.  A
        # user who has been told the call is constant-rate is entitled to be
        # told when it is not, and burying that with the codec settings would
        # hide the one setup line that changes what the call protects.
        if self.constant_rate:
            _vprint("[voice] application-layer constant-rate shaping active — "
                    "packet size and timing carry no speech information. Call "
                    "timing, duration and tunnel behaviour remain observable.")
        else:
            _print("[voice] ⚠ WARNING: could not disable VBR/DTX (%s); packet "
                   "size and timing may leak conversation rhythm"
                   % ", ".join(failed))

        try:
            self._silence_frame = bytes(self._opus_enc.encode(
                b"\x00" * VOICE_FRAME_BYTES, VOICE_FRAME_SAMPLES))
        except Exception:
            self._silence_frame = None

    def security_line(self) -> str:
        """One line naming what actually protects the call.

        Asked for from a handset: the setup output said a great deal about
        gains and buffers and nothing about the cryptography, so a user had
        no way to know what the call was protected by.  Every value here is
        read from the session rather than written down twice -- a hard-coded
        cipher name is a lie waiting for the day somebody changes one.

        The shaping claim is the reason this is built rather than printed as
        a constant: if VBR or DTX could not be disabled the call is NOT
        constant-rate, and a fixed string would tell the user it was.
        """
        shaped = ("constant-rate" if self.constant_rate
                  else "NOT constant-rate")
        return ("[voice] 🔒 %s over %s, %s — keys are per call, held in Rust, "
                "and zeroized on hangup"
                % (VOICE_SUITE_NAME,
                   "I2P datagrams"
                   if self._transport_mode == VOICE_TRANSPORT_DATAGRAM
                   else "I2P streams",
                   shaped))

    def _open_audio_devices(self) -> None:
        """Open the microphone and speaker through otrv4plus_audio.

        Replaces the parec/pacat pair.  On Android this is AAudio talking
        straight to the platform audio framework: no PulseAudio, no
        module-sles-source, no ALSA, no /dev/snd, no root, and nothing
        written to disk.  PulseAudio remains selectable via
        OTRV4PLUS_AUDIO_BACKEND=pulseaudio.

        A fallback from AAudio to PulseAudio is reported, never silent.  On
        this hardware PulseAudio exposes only auto_null, so a call placed
        through it would establish keys, encrypt and transmit pure silence
        while every indicator showed a healthy call.  The user is told which
        device is actually open.
        """
        env = dict(os.environ)
        libdir = os.path.join(_HOST["termux_prefix"], "lib")
        if _HOST["is_termux"] and libdir not in env.get("LD_LIBRARY_PATH", ""):
            env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get(
                "LD_LIBRARY_PATH", "")

        self._audio_env = env
        self._capture, cap_notes = _audio.open_capture(
            which=_HOST["which"], read_exact=_HOST["pipe_read_exact"], env=env)
        try:
            # Pinned to whichever backend capture actually opened.  Letting
            # playback fall back on its own gives a one-way call: AAudio
            # capture with PulseAudio playback means the peer hears us and we
            # hear auto_null, with nothing anywhere reporting a fault.
            self._playback, play_notes = _audio.open_playback(
                preferred=self._capture.name,
                which=_HOST["which"], write_all=_HOST["pipe_write_all"],
                env=env)
        except Exception:
            self._capture.stop()
            self._capture = None
            raise

        for note in list(cap_notes) + list(play_notes):
            _print("[voice] %s" % _san(note, 200))

        self.audio_backend = self._capture.name
        cap = self._capture.diagnostics()
        _vprint("[voice] audio: %s capture %s Hz / %s ch, playback %s — "
                "PCM_16BIT%s"
                % (self.audio_backend, cap.get("device_rate"),
                  cap.get("device_channels"), self._playback.name,
                  ", resampling to %d Hz" % VOICE_SAMPLE_RATE
                  if cap.get("resampling") else ""))

        # The playback side, spelled out, on every call rather than only when
        # someone thinks to run /audioprobe.  A playout deficit is invisible in
        # the frame counters -- the buffer sheds the surplus and the call reads
        # as healthy -- so the device parameters that decide how long a write
        # blocks belong in the same log as the symptom.
        try:
            play = self._playback.diagnostics()
            cap_frames = play.get("buffer_capacity_frames") or 0
            rate = play.get("device_rate") or VOICE_SAMPLE_RATE
            held_ms = (1000.0 * cap_frames / float(rate)) if cap_frames and rate else 0.0
            _vprint("[voice] playout: %s Hz / %s ch%s, burst %s frames, "
                    "capacity %s frames (%.0f ms) vs %d ms per packet"
                    % (play.get("device_rate"), play.get("device_channels"),
                      " (resampling)" if play.get("resampling") else "",
                      play.get("frames_per_burst"), cap_frames or "?",
                      held_ms, VOICE_FRAME_MS))
            # The CONCLUSION stays at normal volume; the parameters above do
            # not.  This is the one playout condition that ruins a call while
            # every counter reads healthy: the write blocks, the pop rate
            # falls below the arrival rate, and the jitter buffer sheds the
            # difference -- deliberately, so it is not counted as loss.  A
            # 1960 s call destroyed a third of its own audio this way and
            # nothing in the frame counters said so.  Four numbers of device
            # geometry are a diagnostic; "every write waits on the device" is
            # a finding, and findings are not put behind a flag.
            if held_ms and held_ms < VOICE_FRAME_MS:
                _print("[voice] ⚠ playout: the device buffer holds less than "
                       "one packet (%.0f ms vs %d ms), so every write waits "
                       "on the device — audio will be dropped locally to keep "
                       "up. --voice-debug for the device parameters."
                       % (held_ms, VOICE_FRAME_MS))
        except Exception:
            pass

        # Loudness, spelled out, because "it is too quiet" has one digital
        # answer and two Android ones and they are not interchangeable. The
        # compressor is already worth about +7 dB of RMS and leaves only a few
        # dB of headroom, so when a call is still quiet the cause is usually
        # the stream it is routed to rather than anything measured here.
        try:
            comp = self._speaker_comp
            gain = self._speaker_gain
            usage = _audio.playback_usage()
            on_call_stream = (usage == getattr(
                _audio, "AAUDIO_USAGE_VOICE_COMMUNICATION", None))
            clarity = self._speech_clarity
            _vprint("[voice] loudness: clarity %s (high-pass %.0f Hz, "
                    "presence +%.1f dB at %.0f Hz)"
                    % ("on" if getattr(clarity, "enabled", False) else "OFF",
                      getattr(clarity, "hpf_hz", 0.0),
                      getattr(clarity, "presence_db", 0.0),
                      getattr(clarity, "presence_hz", 0.0)))
            _vprint("[voice] loudness: compressor %s (makeup %.1f dB, %.0f:1 "
                    "above %.0f dBFS), speaker gain x%.2f"
                    % ("on" if getattr(comp, "enabled", False) else "OFF",
                      getattr(comp, "makeup_db", 0.0),
                      getattr(comp, "ratio", 1.0),
                      getattr(comp, "threshold", 0.0),
                      getattr(gain, "gain", 1.0)))
            if on_call_stream:
                _vprint("[voice] loudness: routed to the CALL stream — the "
                        "volume keys during a call")
                _vprint("[voice]   change this, not the media volume. For the "
                        "louder media route:")
                _vprint("[voice]   OTRV4PLUS_AUDIO_USAGE=media  (costs the "
                        "platform echo canceller)")
        except Exception:
            pass

    async def start_audio(self) -> None:
        """Bring the media path up.

        Refuses unless the keys have been mutually confirmed.  This is the
        single check that makes "no audio before confirmation" structural
        rather than a property of the call ordering.
        """
        if self._writer is None and not self._datagram_ready():
            raise RuntimeError("media stream not established")
        if not self.schedule.ready:
            raise RuntimeError("refusing to start audio: no media keys")
        if not self.keys_confirmed.is_set():
            raise RuntimeError("refusing to start audio: keys not confirmed "
                               "by the peer")
        if self.state != CallState.MEDIA_CONNECTING:
            raise IllegalTransition(
                "start_audio requires MEDIA_CONNECTING, state is %s"
                % self.state)

        self._build_codec()
        self._open_audio_devices()

        self._running = True
        self.transition(CallState.ACTIVE)

        self._capture_thread = threading.Thread(
            target=self._capture_worker, name="voice-capture", daemon=True)
        self._capture_thread.start()
        self._playback_thread = threading.Thread(
            target=self._playback_worker, name="voice-playback", daemon=True)
        self._playback_thread.start()
        if self._writer is not None:
            self._reader_task = asyncio.ensure_future(self._network_reader())
        # Both transports. The stream reader only reports a path the peer
        # CLOSED; a path that simply stops delivering produces no EOF on
        # either transport, so neither has been covered until now.
        now = time.monotonic()
        self._rx_last_datagram = now
        self._rx_last_frame = now
        self._rx_mark = self._rx_authenticated
        self._rx_degraded = False
        self._rx_watchdog_task = asyncio.ensure_future(self._rx_watchdog())

    # -- capture ----------------------------------------------------------

    def _seal_frame(self, padded: bytes):
        """Seal under the committed epoch, holding the key lock.

        The lock is what stops a rekey commit landing between choosing the
        epoch and sealing under it.  v2 read the cipher and the generation
        byte separately and could label a frame with one epoch while sealing
        it under another, which the peer then dropped.
        """
        with self._key_lock:
            cipher = self.schedule.cipher_for_send()
            if cipher is None:
                return None
            return cipher.seal(padded)

    def _capture_worker(self) -> None:
        """Mic -> Opus -> AEAD -> event loop.  Runs on its own thread.

        Muting RELEASES the capture device rather than reading and discarding.
        A soft mute leaves the microphone open: Android's recording indicator
        stays lit, the OS still routes audio into this process, and anything
        that compromised the process could read it. Closing the stream makes
        the mute observable at the OS level, which is the only place a mute is
        worth anything.

        Constant-rate output is preserved regardless. While muted we transmit
        the cached silence frame on the same 40 ms cadence, so packet size and
        timing are identical to speech and the mute is invisible on the wire.
        """
        capture = self._capture
        if capture is None:
            return

        next_frame = time.monotonic()
        while self._running:
            if self._muted:
                if capture is not None:
                    try:
                        capture.stop()
                    except Exception:
                        pass
                    capture = None
                    self._capture = None
                    _print("[voice] microphone RELEASED — the OS recording "
                           "indicator should go out")
                # Keep the wire cadence with the cached silence frame.
                next_frame += VOICE_FRAME_MS / 1000.0
                delay = next_frame - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    next_frame = time.monotonic()
                if self._silence_frame is not None:
                    self._emit(pad_opus(self._silence_frame))
                continue

            if capture is None:
                # Unmuted: take the device back.
                try:
                    # Pinned to the backend the call started on. Letting the
                    # reopen fall through to PulseAudio would put the second
                    # half of the call on auto_null — transmitting silence
                    # with every indicator healthy, which is the failure mode
                    # this whole path is built to avoid.
                    capture, _notes = _audio.open_capture(
                        preferred=self.audio_backend,
                        which=_HOST["which"],
                        read_exact=_HOST["pipe_read_exact"],
                        env=self._audio_env)
                    self._capture = capture
                    next_frame = time.monotonic()
                    _print("[voice] microphone live")
                except Exception as exc:
                    self._muted = True
                    _print("[voice] could not reopen the microphone (%s) — "
                           "staying muted" % _san(str(exc), 120))
                    continue

            try:
                raw = capture.read_frame(timeout_ms=200)
            except _audio.AudioError as exc:
                if exc.code == _audio.AUDIO_DEVICE_DISCONNECTED:
                    # AAudio's ERROR_DEAD_OBJECT: route change, headset
                    # unplug, or audioserver restart.  The stream is dead and
                    # must never be re-read; end the call rather than spin.
                    self._signal_stream_lost("audio device disconnected")
                else:
                    self._signal_stream_lost("microphone error: %s" % exc.code)
                break
            except Exception:
                self._signal_stream_lost("microphone stopped")
                break

            if raw is None:
                # A timeout, not end-of-stream.  read_frame already blocked
                # inside the device for up to timeout_ms, so this loop cannot
                # busy-spin.
                continue
            if not self._running:
                break

            # Gain before Opus, not after: the encoder allocates bits by
            # what it is given, so encoding a -18 dBFS signal and amplifying
            # at the far end amplifies the coding noise with it.
            _t_stage = time.monotonic()
            pcm = self._mic_gain.process(self._mic_comp.process(raw))
            opus_frame = None
            try:
                opus_frame = bytearray(
                    self._opus_enc.encode(bytes(pcm), VOICE_FRAME_SAMPLES))
                self.stages.record_since("encode", _t_stage)
                _wipe(pcm)
                padded = pad_opus(bytes(opus_frame),
                                  self.latency.call_ms(self._call_t0))
                _wipe(opus_frame)
                opus_frame = None
                if padded is None:
                    # Encoder exceeded the fixed slot.  Substitute silence
                    # rather than emit an odd-sized packet: a lost 40 ms is
                    # inaudible, a size leak is permanent.
                    self.stats["oversize"] += 1
                    if self._silence_frame is None:
                        continue
                    padded = pad_opus(
                        self._silence_frame,
                        self.latency.call_ms(self._call_t0))
                self._emit(padded)
            except Exception:
                self.stats["dropped"] += 1
                self.stats["tx_dropped"] = self.stats.get("tx_dropped", 0) + 1
            finally:
                _wipe(pcm)
                if opus_frame is not None:
                    _wipe(opus_frame)

            # Outside the try: a probe must still go out on a frame that
            # failed to encode, or a codec hiccup would also stop latency
            # measurement.
            self._maybe_ping()

    def _playback_usage_is_voice(self) -> bool:
        """True when playback asked for the voice-communication usage."""
        try:
            return (getattr(self._playback, "usage", None)
                    == _audio.AAUDIO_USAGE_VOICE_COMMUNICATION)
        except Exception:
            return False

    def _emit_probe(self, frame_type: int, payload: bytes) -> None:
        """Send a PING or PONG as a full-size frame.

        Padded to VOICE_PLAIN_LEN so a probe is indistinguishable from audio
        by length; only the authenticated frame_type byte differs.
        """
        if len(payload) > VOICE_PLAIN_LEN:
            return
        plain = payload + b"\x00" * (VOICE_PLAIN_LEN - len(payload))
        try:
            with self._key_lock:
                cipher = self.schedule.cipher_for_send()
                if cipher is None:
                    return
                packet = cipher.seal(plain, frame_type=frame_type)
        except Exception:
            return
        try:
            # Probes are exempt from the staleness deadline below: they are
            # rare, and a probe that waited in the queue is measuring exactly
            # the delay we want reported.
            self.loop.call_soon_threadsafe(self._write_packet, packet, None)
        except Exception:
            pass

    def _maybe_ping(self) -> None:
        """Emit a latency probe if one is due."""
        if not self.latency.due():
            return
        try:
            _pid, payload = self.latency.build_ping()
            self._emit_probe(FRAME_TYPE_PING, payload)
        except Exception:
            pass

    def _emit(self, padded) -> None:
        """Seal one padded frame and hand it to the event loop."""
        if padded is None:
            return
        _t_seal = time.monotonic()
        try:
            packet = self._seal_frame(padded)
            self.stages.record_since("seal", _t_seal)
        except FrameError as exc:
            # Counter exhaustion is unreachable in practice (2^62 frames) but
            # it is permanent when it happens: every later frame fails the
            # same way. Counting it as a drop would present as a call that
            # silently stopped transmitting.
            if "exhausted" in str(exc):
                self._signal_stream_lost("frame counter exhausted")
                self._running = False
            else:
                self.stats["dropped"] += 1
                self.stats["tx_dropped"] = self.stats.get("tx_dropped", 0) + 1
            return
        except Exception:
            self.stats["dropped"] += 1
            self.stats["tx_dropped"] = self.stats.get("tx_dropped", 0) + 1
            return
        if packet is None:
            return
        self.loop.call_soon_threadsafe(self._write_packet, packet,
                                       time.monotonic())

    # Every queue between here and the peer's speaker has to be bounded in
    # TIME, because audio that arrives late is not late audio, it is noise.
    #
    # This one is asyncio's write buffer.  50 packets is 3 s at 60 ms — long
    # enough that a call could sound three seconds behind purely on our own
    # backlog.  8 packets is ~480 ms, which is the same order as the jitter
    # buffer's own ceiling and therefore the most that can be useful.
    _MAX_WRITE_BACKLOG = VOICE_PACKET_LEN * 8

    #: A frame still unwritten this long after capture is discarded rather
    #: than transmitted.  It bounds the queue that call_soon_threadsafe builds
    #: when the event loop is busy, independently of any socket buffer.
    _SEND_DEADLINE_S = 0.25

    def _signal_stream_lost(self, why: str) -> None:
        """Report a media failure exactly once, on the loop."""
        if self._loss_signalled or self._closing:
            return
        self._loss_signalled = True
        callback = self.on_stream_lost
        if callback is None:
            return
        try:
            self.loop.call_soon_threadsafe(callback, self.peer, self.call_id,
                                           why)
        except Exception:
            pass

    def _write_packet(self, packet: bytes, queued_at=None) -> None:
        """Write one framed packet.  Event-loop thread only.

        ``queued_at`` is the ``time.monotonic()`` reading taken when the
        capture thread handed this frame over.  A frame that has been waiting
        longer than ``_SEND_DEADLINE_S`` is dropped: transmitting it would
        push a fresher frame further behind, and it is already too late to be
        played in sequence.  Pass ``None`` to exempt a frame (probes).
        """
        if not self._running:
            return
        if self._writer is None and not self._datagram_ready():
            return
        if queued_at is not None:
            # How long the frame waited between the capture thread handing it
            # over and this callback running. This is event-loop scheduling
            # delay, and it counts inside the reported one-way figure -- so a
            # large value here means the one-way number is measuring us, not
            # I2P.
            self.stages.record_since("queue", queued_at)
            if (time.monotonic() - queued_at) > self._SEND_DEADLINE_S:
                self.stats["stale"] += 1
                return
        if self._datagram_ready():
            if self._dgram_send_header is None:
                # Initiator, still waiting to learn the callee's destination.
                # Counted rather than silently discarded so a peer that never
                # sends is visible in the stats rather than looking like loss.
                self.stats["backpressure"] += 1
                return
            if self._send_datagram(packet):
                self.stats["sent"] += 1
            else:
                self.stats["dropped"] += 1
                self.stats["tx_dropped"] = self.stats.get("tx_dropped", 0) + 1
            return
        try:
            if self._writer.is_closing():
                return
            transport = self._writer.transport
            if transport is not None:
                try:
                    if transport.get_write_buffer_size() > self._MAX_WRITE_BACKLOG:
                        self.stats["backpressure"] += 1
                        return
                except Exception:
                    pass
            self._writer.write(packet)
            self.stats["sent"] += 1
        except Exception:
            self.stats["dropped"] += 1
            self.stats["tx_dropped"] = self.stats.get("tx_dropped", 0) + 1

    # -- network ----------------------------------------------------------

    def open_packet(self, header: bytes, sealed: bytes) -> tuple:
        """Authenticate one packet against a live epoch.

        Returns (epoch, counter, plaintext).  Raises FrameError otherwise.
        Only epochs the schedule still holds are tried, and each is tried by
        its own cipher, so a frame claiming an epoch we never committed —
        or one already retired — is rejected without touching any key.
        """
        epoch, counter, length, ftype = parse_media_header(header)
        with self._key_lock:
            cipher = self.schedule.cipher_for_epoch(epoch)
            if cipher is None:
                raise FrameError("no live key for epoch %d" % epoch, FrameError.NO_KEY)
            # A tag that does not verify comes back from the Rust cipher as
            # FrameError(AUTH) -- `VoiceFrameCrypto.open` classifies it -- and
            # is the ONLY rejection that is an authentication failure.
            plaintext = cipher.open(header, sealed)
        return epoch, counter, plaintext, ftype

    async def _network_reader(self) -> None:
        """Stream -> AEAD -> Opus -> jitter buffer."""
        buf = bytearray()
        try:
            while self._running:
                try:
                    chunk = await asyncio.wait_for(self._reader.read(8192),
                                                   timeout=2.0)
                except asyncio.TimeoutError:
                    continue
                except (asyncio.CancelledError, GeneratorExit):
                    raise
                except Exception:
                    break
                if not chunk:
                    break
                buf += chunk

                # Drain BEFORE bounding.  read(8192) returns up to 41 packets
                # in one go and I2P delivers in bursts, so trimming first
                # discarded every complete frame in the burst and cut the
                # survivor at an arbitrary offset — destroying byte alignment
                # and forcing the parser to hunt for sync afterwards.  That
                # showed up on a live call as dropped and resync climbing in
                # lockstep with authfail=0: nothing was failing to decrypt,
                # the frames were being shredded before they could be read.
                self._drain_buffer(buf)

                # Only unparseable residue can reach here: a drained buffer
                # holds at most one partial frame.  Anything larger is a peer
                # sending bytes that never form a frame, so this is the DoS
                # guard it was meant to be rather than a data shredder.
                if len(buf) > VOICE_PACKET_LEN * 8:
                    del buf[:]
                    self.stats["dropped"] += 1
                    self.stats["rx_dropped"] = self.stats.get("rx_dropped", 0) + 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _print("[voice] media stream error: %s" % _san(str(exc), 200))
        finally:
            _wipe(buf)
        if self._running:
            self._signal_stream_lost("peer closed the media stream")

    # -- media endpoint announcements --------------------------------------

    def _endpoint_tag(self, epoch: int, seq: int, destination: str,
                      from_initiator: bool) -> bytes:
        """Tag an announcement under the committed epoch root."""
        with self._key_lock:
            if self.schedule.epoch != epoch:
                raise FrameError("endpoint epoch %d is not the committed one"
                                 % epoch)
            return self.schedule.current_root().endpoint_tag(
                self.call_id, epoch, seq, destination, from_initiator)

    def build_endpoint_announcement(self):
        """Describe our current media endpoint.  Returns (epoch, seq, dest, tag).

        The sequence advances on every announcement and is inside the tag, so
        the peer can order two announcements that overtake each other on the
        control channel and refuse the older one.
        """
        destination = self._our_dest
        if not destination:
            raise FrameError("no local media destination to announce")
        with self._key_lock:
            epoch = self.schedule.epoch
        self._endpoint_seq_sent += 1
        seq = self._endpoint_seq_sent
        return epoch, seq, destination, self._endpoint_tag(
            epoch, seq, destination, self.is_initiator)

    def accept_endpoint(self, epoch: int, seq: int, destination: str,
                        tag: bytes) -> str:
        """Validate a peer announcement and adopt it.  Returns a reason string.

        "ok" means the peer destination was replaced. Everything else names
        why it was refused, so a refusal is diagnosable rather than silent.

        The order is deliberate: everything cheap and non-cryptographic first,
        the tag last, and no state moves until the tag verifies. A forged or
        replayed announcement therefore costs nothing and changes nothing.
        """
        if self.state != CallState.ACTIVE:
            return "call is not active"
        if seq <= self._endpoint_seq_seen:
            # Covers replays, reordering on the control channel, and a
            # deliberate attempt to reinstate an endpoint we have moved past.
            return "stale sequence %d (already at %d)" % (
                seq, self._endpoint_seq_seen)
        try:
            destination = i2p_public_destination(destination)
        except ValueError:
            return "unparseable destination"
        if destination == self._peer_dest:
            return "endpoint unchanged"
        try:
            expected = self._endpoint_tag(epoch, seq, destination,
                                          not self.is_initiator)
        except FrameError as exc:
            return str(exc)
        except Exception:
            return "no committed media key"
        if not hmac.compare_digest(bytes(tag or b""), expected):
            return "authentication failed"

        self._peer_dest = destination
        self._endpoint_seq_seen = seq
        self._refresh_datagram_header()
        return "ok"

    async def rebuild_media_endpoint(self) -> str:
        """Replace the local SAM datagram session.  Returns the new destination.

        The old session is closed first and unconditionally. Leaving it open
        would hold a router-side session and a bound UDP socket for the rest
        of the call, and create_session() overwrites both handles, so anything
        not closed here is leaked rather than merely idle.

        Nothing cryptographic changes: the media keys, the epoch, the replay
        windows and the call identity all survive. Only where our packets
        arrive changes, which is why this needs an announcement rather than a
        rekey.
        """
        if self._transport_mode != VOICE_TRANSPORT_DATAGRAM:
            raise RuntimeError("only the datagram transport has an endpoint "
                               "that can be replaced")
        self._close_datagram_transport()
        self._our_dest = None
        destination = await self.create_session(
            session_timeout=VOICE_RECOVER_TIMEOUT_S)
        if not self._running:
            # Teardown ran while the router was building tunnels. Do not leave
            # the replacement behind.
            self._close_datagram_transport()
            raise RuntimeError("call ended while the media path was rebuilding")
        await self.open_datagram_endpoint()
        now = time.monotonic()
        # The new path has had no chance to deliver anything yet; judging it
        # by the old clock would declare it dead the moment it opened. That
        # reset is also why the clock cannot be used to decide whether the
        # rebuild worked -- the mark is what the watchdog compares against.
        self._rx_last_datagram = now
        self._rx_last_frame = now
        self._rx_mark = self._rx_authenticated
        return destination

    def _discard_pending_sam(self, control) -> None:
        """Close and forget one in-flight control socket.  Never raises."""
        try:
            self._sam_pending.remove(control)
        except ValueError:
            pass
        release = _HOST.get("sam_release")
        try:
            if release is not None:
                release(control)
            else:
                control.close()
        except Exception:
            pass

    def _close_datagram_transport(self) -> None:
        """Release the datagram endpoint and its SAM session.  Idempotent."""
        if self._dgram_transport is not None:
            try:
                self._dgram_transport.close()
            except Exception:
                pass
            self._dgram_transport = None
            self._dgram_sock = None       # closed with the transport
        elif self._dgram_sock is not None:
            try:
                self._dgram_sock.close()
            except Exception:
                pass
            self._dgram_sock = None
        self._dgram_send_header = None
        release = _HOST.get("sam_release")
        control, self._sam_control = self._sam_control, None
        if control is not None:
            try:
                if release is not None:
                    release(control)
                else:
                    control.close()
            except Exception:
                pass
        self._sam_session_id = None
        # A create whose await was cancelled leaves its socket here. Draining
        # is the only thing that can reclaim it, because nothing else still
        # holds a reference.
        while self._sam_pending:
            self._discard_pending_sam(self._sam_pending[-1])

    # -- inbound liveness --------------------------------------------------

    def _sam_control_state(self) -> str:
        """Whether the SAM session that owns this transport still exists.

        A SAM v3 session lives exactly as long as its control socket. If the
        router tears the session down, inbound forwarding to our UDP port
        stops, while sendto() to the local bridge keeps succeeding -- so the
        call looks healthy from the transmit side and receives nothing
        forever. This code never read that socket after SESSION STATUS, so
        the condition was undetectable. Reading it costs one non-blocking
        select and turns a hypothesis into a diagnosis.

        Returns "closed", "open", or "unknown". Never raises, never blocks,
        and never consumes bytes: MSG_PEEK leaves the stream untouched.
        """
        sock = self._sam_control
        if sock is None:
            return "unknown"
        try:
            import select
            readable, _w, _x = select.select([sock], [], [], 0)
            if not readable:
                return "open"          # nothing pending: session still held
            return "closed" if sock.recv(1, _socket.MSG_PEEK) == b"" else "open"
        except Exception:
            return "unknown"

    def _rx_thresholds(self):
        """(warn, rebuild, dead) for this call, in seconds.

        Three points, not two, because telling the user and replacing the
        endpoint are different decisions and want different timing.

        `warn` is when to say something. It stays early: silence with no
        explanation is the worst of the three states to be in.

        `rebuild` is when to actually replace the endpoint, and it is held
        back while the SAM session that owns our destination is still alive
        -- the router is rebuilding tunnels under an address that is still
        ours, and replacing it throws away a working session, stops our own
        transmission for the duration, and makes the peer adopt an address it
        did not need.

        `dead` moves with the rebuild point, so holding can never mean the
        call sits dead for longer than the hold it earned.

        Everything widens until media has ever flowed: a cold I2P path taking
        its time to deliver the first frame is not a broken path, and
        treating it as one rebuilt a working endpoint and cost a live call
        ~70 s of silence.
        """
        if self._rx_authenticated == 0:
            warn = VOICE_RX_START_GRACE_S
            dead = VOICE_RX_START_GRACE_S + VOICE_RX_DEAD_S
        else:
            warn, dead = VOICE_RX_WARN_S, VOICE_RX_DEAD_S
        rebuild = warn
        if VOICE_RX_SESSION_HOLD_S and self._sam_control_state() == "open":
            rebuild += VOICE_RX_SESSION_HOLD_S
            dead += VOICE_RX_SESSION_HOLD_S
        return warn, rebuild, dead

    def _rx_idle_seconds(self, now=None):
        """Seconds since anything authenticated, or None before audio starts."""
        if self._rx_last_frame is None:
            return None
        return max(0.0, (now or time.monotonic()) - self._rx_last_frame)

    def _rx_diagnosis(self) -> str:
        """Name the first stage that stopped, from counters rather than guess."""
        if self._rx_last_datagram is None:
            arrived = False
        else:
            arrived = (self._rx_last_frame is None
                       or self._rx_last_datagram > self._rx_last_frame)
        if arrived:
            # Datagrams are reaching the socket but none authenticate: the
            # transport is fine and the fault is above it.
            # Split by cause, because the causes need different actions.
            # nokey dominating means the peers disagree about the epoch --
            # a rekey problem.  authfail dominating means frames are being
            # forged or corrupted.  They used to be the same number.
            return ("datagrams are arriving but none authenticate "
                    "(foreign=%d empty=%d nokey=%d retired=%d malformed=%d "
                    "authfail=%d replay=%d)"
                    % (self.stats["foreign"], self.stats["dgram_empty"],
                       self.stats["rej_no_key"], self.stats["rej_retired"],
                       self.stats["rej_malformed"],
                       self.stats["auth_fail"], self.stats["replay"]))
        state = self._sam_control_state()
        if state == "closed":
            return ("no media datagrams are arriving and the SAM session is "
                    "gone — the router stopped forwarding to us")
        return ("no media datagrams are arriving at all "
                "(SAM control socket %s)" % state)

    async def _rx_watchdog(self) -> None:
        """Notice an inbound media path that has stopped, and act on it.

        The transmit side cannot detect this: a datagram handed to the local
        SAM bridge is accepted whether or not the session behind it still
        exists, so `sent` keeps climbing over a dead path. Only the absence of
        inbound traffic shows it, and before this nothing was watching.

        Three bounded stages. A warning names the failing stage once -- not
        once per tick, which is how the old debug-only message printed 116
        times. Recovery is then attempted, and only if that is impossible or
        exhausted is the call declared lost through the existing
        _signal_stream_lost path, which ends it and tells the peer.

        Recovery can extend the deadline, never remove it: the dead check is
        suspended only while a rebuild is genuinely in flight, and the rebuild
        itself is bounded by VOICE_RECOVER_TIMEOUT_S and by a fixed number of
        attempts.
        """
        try:
            while self._running:
                await asyncio.sleep(VOICE_RX_CHECK_S)
                if not self._running:
                    return
                idle = self._rx_idle_seconds()
                if idle is None:
                    continue
                warn_after, rebuild_after, dead_after = self._rx_thresholds()
                if idle < warn_after:
                    # Recovery is confirmed by a frame that authenticated
                    # AFTER the rebuild, never by the clock: rebuilding resets
                    # the clock, so treating a small idle as success declared
                    # victory over a path that had delivered nothing and
                    # handed back the attempt budget, which made the rebuild
                    # loop unbounded.
                    if self._rx_degraded:
                        if self._rx_authenticated > self._rx_mark:
                            self._rx_degraded = False
                            self._recover_attempts = 0
                            _print("[voice] inbound audio recovered")
                    continue
                if self._recovering:
                    # A rebuild owns the deadline while it runs. It cannot run
                    # forever -- it is wrapped in wait_for -- and when it ends
                    # this check resumes on the next tick.
                    continue
                if not self._rx_degraded:
                    self._rx_degraded = True
                    held = rebuild_after > warn_after
                    _print("[voice] %s for %ds — %s%s"
                           % ("no audio yet on a new call"
                              if self._rx_authenticated == 0
                              else "no inbound audio",
                              int(idle), self._rx_diagnosis(),
                              ("; the router still holds our session, giving "
                               "it %ds to rebuild its tunnels before we "
                               "replace the endpoint"
                               % int(rebuild_after - warn_after))
                              if held else ""))
                if idle >= rebuild_after and self._request_recovery():
                    continue
                if idle >= dead_after:
                    self._signal_stream_lost(
                        "no media received for %ds — %s"
                        % (int(idle), self._rx_diagnosis()))
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The watchdog failing must not take the call with it, but it
            # must not fail silently either: a dead watchdog means the very
            # condition it exists to catch would go unnoticed again.
            _print("[voice] media watchdog stopped: %s" % _san(str(exc), 120))

    def _recovery_possible(self) -> bool:
        """Whether replacing our endpoint could plausibly help.

        Only the datagram transport has an endpoint to replace, and only a
        path delivering nothing at all is one a new endpoint could fix. If
        datagrams are arriving and failing to authenticate, the transport is
        working and rebuilding it would discard a healthy path for nothing.
        """
        if self._transport_mode != VOICE_TRANSPORT_DATAGRAM:
            return False
        if self._recover_attempts >= VOICE_RECOVER_ATTEMPTS:
            return False
        if self._rx_last_datagram is not None and self._rx_last_frame is not None \
                and self._rx_last_datagram > self._rx_last_frame:
            return False
        return self.state == CallState.ACTIVE

    def _request_recovery(self) -> bool:
        """Ask the manager to rebuild the media path.  True if it was asked."""
        if not self._recovery_possible():
            return False
        callback = self.on_media_stalled
        if callback is None:
            return False
        self._recovering = True
        self._recover_attempts += 1
        try:
            started = callback(self.peer, self.call_id)
        except Exception as exc:
            self._recovering = False
            self._recover_attempts -= 1
            self._vlog("media recovery could not start: %s"
                       % _san(str(exc), 120))
            return False
        if not started:
            # Declined -- the control plane cannot carry the announcement
            # yet. Refund the attempt: nothing was rebuilt, so nothing was
            # spent, and the budget exists to bound rebuilds rather than
            # to bound asking.
            self._recovering = False
            self._recover_attempts -= 1
            return False
        return True

    def _vlog(self, message: str) -> None:
        _print("[voice] %s" % message)

    def _drain_buffer(self, buf: bytearray) -> None:
        """Parse, authenticate and enqueue every complete frame in buf.

        Resynchronisation is authenticated, not structural: a candidate whose
        tag fails is treated as a false sync and the parser advances exactly
        one byte.  Because every genuine frame is authenticated, a false sync
        can never be mistaken for real audio, and a stray byte cannot make
        the parser swallow a plausible-looking length of valid frames.
        """
        while len(buf) >= VOICE_HDR_LEN:
            if buf[0] != VOICE_SYNC:
                idx = buf.find(bytes([VOICE_SYNC]), 1)
                if idx == -1:
                    self.stats["dropped"] += 1
                    self.stats["rx_dropped"] = self.stats.get("rx_dropped", 0) + 1
                    buf.clear()
                    return
                del buf[:idx]
                self.stats["resync"] += 1
                continue

            header = bytes(buf[:VOICE_HDR_LEN])
            try:
                _, _, length, _ = parse_media_header(header)
            except FrameError:
                del buf[:1]
                self.stats["resync"] += 1
                continue
            if len(buf) < VOICE_HDR_LEN + length:
                return                       # genuine partial frame

            sealed = bytes(buf[VOICE_HDR_LEN:VOICE_HDR_LEN + length])
            opus_frame = None
            pcm = None
            _t_open = time.monotonic()
            try:
                epoch, counter, plaintext, ftype = self.open_packet(
                    header, sealed)
                self.stages.record_since("decrypt", _t_open)
                # Stamped for every authenticated frame, not only audio: a
                # PING or PONG proves the receive path just as well, and
                # during the live failure the probe replies died in the same
                # instant as the audio.
                self._rx_last_frame = time.monotonic()
                self._rx_authenticated += 1
                del buf[:VOICE_HDR_LEN + length]

                if ftype == FRAME_TYPE_PING:
                    # Authenticated before we answer, so a forged PING cannot
                    # make us transmit.
                    try:
                        self._emit_probe(FRAME_TYPE_PONG,
                                         self.latency.build_pong_stamped(plaintext))
                    except Exception:
                        pass
                    continue
                if ftype == FRAME_TYPE_PONG:
                    try:
                        self.latency.handle_pong(plaintext)
                    except Exception:
                        pass
                    continue
                # Queue the Opus payload, not decoded PCM. Decoding at
                # playout is what makes Opus in-band FEC usable: recovering a
                # lost frame requires the NEXT packet, which does not exist
                # yet at receive time. It also cuts the buffer's memory by
                # 12x, since 152 bytes of Opus replaces 1920 of PCM.
                _opus, _send_ms = unpad_frame(plaintext)
                self.latency.observe_frame(_send_ms, self._call_t0)
                opus_frame = bytearray(_opus)
                if self.jitter.push(epoch, counter, opus_frame):
                    self.stats["recv"] += 1
                    opus_frame = None        # ownership passed to playback
                else:
                    # Refused by the jitter buffer, which says why: `late`
                    # (its slot was already played) or `duplicate`. This
                    # counter used to take both, so a duplicate read as a
                    # late frame. Kept as their sum for the diagnostics
                    # that print it; the split is in jitter.stats.
                    self.stats["late"] += 1
            except FrameError as exc:
                # Classified by the raise site.  This used to read
                # `if "replay" in str(exc)` and count everything else as an
                # authentication failure, which meant a rekey the peer had
                # moved ahead of was indistinguishable from a forged frame.
                self.stats[FrameError.STAT_FOR_REASON.get(
                    getattr(exc, "reason", FrameError.MALFORMED),
                    "rej_malformed")] += 1
                self.stats["dropped"] += 1
                self.stats["rx_dropped"] = self.stats.get("rx_dropped", 0) + 1
                del buf[:1]
                self.stats["resync"] += 1
            except Exception:
                self.stats["dropped"] += 1
                self.stats["rx_dropped"] = self.stats.get("rx_dropped", 0) + 1
                del buf[:1]
            finally:
                if opus_frame is not None:
                    _wipe(opus_frame)
                if pcm is not None:
                    _wipe(pcm)

    # -- playback ---------------------------------------------------------

    def _decode(self, opus_frame, fec: bool = False):
        """Decode one Opus frame.  Returns PCM or None.

        fec=True asks Opus to extract the redundant copy of the PREVIOUS
        frame carried inside this one. That is what in-band FEC is: the
        encoder spends a few bits describing the frame before, so a single
        lost packet can be reconstructed once its successor arrives.
        """
        if self._opus_dec is None:
            return None
        try:
            if fec:
                return bytearray(self._opus_dec.decode(
                    bytes(opus_frame), VOICE_FRAME_SAMPLES, decode_fec=True))
            return bytearray(self._opus_dec.decode(bytes(opus_frame),
                                                   VOICE_FRAME_SAMPLES))
        except Exception:
            return None

    def _conceal(self, gap: int):
        """Synthesise PCM for a detected gap.

        Bounded: a large gap means the far end went away, and synthesising
        seconds of concealment audio helps nobody.
        """
        out = []
        for _ in range(min(gap, 3)):
            try:
                plc = self._opus_dec.decode(None, VOICE_FRAME_SAMPLES)
            except Exception:
                return out
            out.append(bytearray(plc))
        return out

    def _playback_worker(self) -> None:
        """Jitter buffer -> decode -> the playback device.

        A one-frame gap is repaired from the next packet's FEC copy, which is
        the common case on a lossy path and is genuinely recovered audio
        rather than synthesised. Longer gaps fall back to packet-loss
        concealment.
        """
        while self._running:
            item = self.jitter.pop()
            if item is None:
                time.sleep(VOICE_FRAME_MS / 2000.0)
                continue
            opus_frame, gap = item
            playback = self._playback
            recovered = []
            try:
                if gap == 1:
                    pcm_fec = self._decode(opus_frame, fec=True)
                    if pcm_fec is not None:
                        recovered.append(pcm_fec)
                        self.stats["fec_recovered"] += 1
                    else:
                        recovered.extend(self._conceal(gap))
                elif gap > 1:
                    recovered.extend(self._conceal(gap))

                _t_dec = time.monotonic()
                pcm = self._decode(opus_frame)
                self.stages.record_since("decode", _t_dec)
                if pcm is not None:
                    recovered.append(pcm)

                for chunk in recovered:
                    loud = None
                    try:
                        if playback is not None:
                            loud = self._speaker_gain.process(
                                self._speaker_comp.process(
                                    self._speech_clarity.process(chunk)))
                            _t_play = time.monotonic()
                            playback.write_frame(bytes(loud))
                            # write_frame blocks against the device ring. A
                            # p95 near the frame duration means playout is
                            # device-paced and healthy; well above it means
                            # the device is the bottleneck, not the network.
                            self.stages.record_since("play", _t_play)
                            # Split it, because "play is slow" has two very
                            # different causes and opposite fixes: `conv` is
                            # CPU we are burning on resample/upmix before the
                            # device is involved at all, `write` is the device
                            # declining to accept audio faster than it plays
                            # it. Reading only the total led an analysis to
                            # blame sender clock drift for what turned out to
                            # be a playout deficit.
                            self.stages.record(
                                "conv", getattr(playback, "last_convert_s", 0.0))
                            self.stages.record(
                                "write", getattr(playback, "last_device_s", 0.0))
                    except _audio.AudioError as exc:
                        if exc.code == _audio.AUDIO_DEVICE_DISCONNECTED:
                            self._signal_stream_lost(
                                "audio device disconnected")
                            return
                    except Exception:
                        pass
                    finally:
                        if loud is not None:
                            _wipe(loud)
                        _wipe(chunk)
                recovered = []
            except Exception:
                pass
            finally:
                for chunk in recovered:
                    _wipe(chunk)
                _wipe(opus_frame)

    # -- control ----------------------------------------------------------

    def toggle_mute(self) -> bool:
        """Toggle the microphone.

        Muting closes the capture stream; the device is genuinely released,
        not merely ignored. Unmuting reopens it, which takes a moment on
        AAudio, so the first frame or two after unmute may be silence.
        """
        self._muted = not self._muted
        return self._muted

    def describe(self) -> str:
        with self._key_lock:
            epoch = self.schedule.epoch
            pending = self.schedule.pending_epoch
            rekeys = self.schedule.rekeys_committed
            failed = self.schedule.rekeys_failed
            cipher = self.schedule.cipher_for_send()
            ratchets = getattr(cipher, "ratchet_steps", 0)
        rate = "constant-rate" if self.constant_rate else "VARIABLE-RATE"
        transport = self._transport_mode
        audio = self.audio_backend or "-"
        return ("state=%s role=%s audio=%s %s transport=%s keys=%s epoch=%d "
                "pending=%s sent=%d dgram_in=%d "
                "recv=%d dropped=%d late=%d nokey=%d retired=%d "
                "malformed=%d authfail=%d replay=%d resync=%d "
                "backpressure=%d stale=%d foreign=%d oversize=%d fec=%d "
                "jitter=%d/%d (%.0fms) %s ratchets=%d rekeys=%d/%d"
                % (self.state, self.role, audio, rate, transport,
                   "confirmed" if self.keys_confirmed.is_set() else "pending",
                   epoch, "-" if pending is None else pending,
                   self.stats["sent"], self.stats["dgram_in"],
                   self.stats["recv"],
                   self.stats["dropped"], self.stats["late"],
                   self.stats["rej_no_key"], self.stats["rej_retired"],
                   self.stats["rej_malformed"],
                   self.stats["auth_fail"], self.stats["replay"],
                   self.stats["resync"],
                   self.stats["backpressure"], self.stats["stale"],
                   self.stats["foreign"], self.stats["oversize"],
                   self.stats["fec_recovered"],
                   self.jitter.depth(), self.jitter.target_depth,
                   self.jitter.jitter_ms, self.latency.summary(),
                   ratchets, rekeys, failed))

    # -- teardown ---------------------------------------------------------

    def force_close_sync(self) -> None:
        """Loop-independent emergency teardown.

        Runs on interpreter-shutdown paths where the loop may already be
        closed, so it awaits nothing and must survive a partially constructed
        session — if __init__ raised part-way, an AttributeError here would
        abort teardown and leave the microphone recording.
        """
        self._running = False
        self._closing = True
        self.state = CallState.ENDED       # bypasses the table by design

        for name in ("_capture", "_playback"):
            stream = getattr(self, name, None)
            if stream is None:
                continue
            try:
                stream.stop()
            except Exception:
                pass
            setattr(self, name, None)

        dgram = getattr(self, "_dgram_transport", None)
        if dgram is not None:
            try:
                dgram.close()
            except Exception:
                pass
        self._dgram_transport = None
        self._dgram_send_header = None
        # create_datagram_endpoint takes ownership of the socket and closes it
        # with the transport; closing it again here would hit an unrelated fd.
        if getattr(self, "_dgram_sock", None) is not None and dgram is None:
            try:
                self._dgram_sock.close()
            except Exception:
                pass
        self._dgram_sock = None

        release = _HOST["sam_release"]
        for name in ("_accept_sock", "_media_sock", "_sam_control"):
            sock = getattr(self, name, None)
            if sock is not None and release is not None:
                try:
                    release(sock)
                except Exception:
                    pass
            setattr(self, name, None)
        self._writer = None
        self._reader = None

        jitter = getattr(self, "jitter", None)
        if jitter is not None:
            try:
                jitter.clear()
            except Exception:
                pass

        schedule = getattr(self, "schedule", None)
        if schedule is not None:
            try:
                schedule.zeroize()
            except Exception:
                pass
        for name in ("kex", "_rekey_kex"):
            kex = getattr(self, name, None)
            if kex is not None:
                try:
                    kex.destroy()
                except Exception:
                    pass
                setattr(self, name, None)
        self.our_confirm = None
        self.peer_confirm_expected = None

    async def end(self) -> dict:
        """Tear the call down completely.  Idempotent and exception-safe.

        Order matters: the microphone is released first, then the network,
        then the keys, so nothing can still need a key that has been wiped
        and no callback can resurrect a call that has ended.
        """
        if self._closing:
            return self.stats
        self._closing = True
        self._running = False
        try:
            self.transition(CallState.ENDING)
        except IllegalTransition:
            pass

        # 1. Release the microphone before anything else.  stop() is
        #    idempotent on every backend, and for AAudio it issues
        #    requestStop + close so the AudioRecord-equivalent handle is
        #    returned to the platform rather than left held by a dead call.
        for name in ("_capture", "_playback"):
            stream = getattr(self, name, None)
            if stream is None:
                continue
            try:
                stream.stop()
            except Exception:
                pass
            setattr(self, name, None)

        # 2. Join the audio threads.
        for thread in (self._capture_thread, self._playback_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=2.0)
        self._capture_thread = None
        self._playback_thread = None

        # 3. A parked STREAM ACCEPT is blocked inside an executor thread that
        #    cancellation cannot reach; closing its socket is what releases it.
        release = _HOST["sam_release"]
        if release is not None and self._accept_sock is not None:
            try:
                release(self._accept_sock)
            except Exception:
                pass
        self._accept_sock = None

        # 4. Cancel every asyncio task this session owns.
        for name in ("_prewarm", "_reader_task", "_accept_task",
                     "_rx_watchdog_task", "_recover_task"):
            task = getattr(self, name, None)
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass
            setattr(self, name, None)

        # 5. Wipe queued PCM.
        try:
            self.jitter.clear()
        except Exception:
            pass

        # 6. Close the media transport, then the SAM session.
        self._close_datagram_transport()
        if self._writer is not None:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=3)
            except Exception:
                pass
        self._writer = None
        self._reader = None
        if release is not None:
            for sock in (self._media_sock, self._sam_control):
                if sock is not None:
                    try:
                        release(sock)
                    except Exception:
                        pass
        self._media_sock = None
        self._sam_control = None       # _close_datagram_transport cleared it

        # 7. Destroy every key last.
        try:
            self.schedule.zeroize()
        except Exception:
            pass
        for name in ("kex", "_rekey_kex"):
            kex = getattr(self, name, None)
            if kex is not None:
                try:
                    kex.destroy()
                except Exception:
                    pass
                setattr(self, name, None)
        self.our_confirm = None
        self.peer_confirm_expected = None
        self._opus_enc = None
        self._opus_dec = None

        self.state = CallState.ENDED
        return self.stats


# ---------------------------------------------------------------------------
# Signalling
# ---------------------------------------------------------------------------

CALL_PREFIX = "?OTRv4-CALL:"

# Bound so a peer cannot force megabyte allocations through the OTR channel.
# INVITE is the largest: destination (~520) + call_id (32) + X448 (112) +
# ML-KEM ek (3136) hex characters, plus separators.
MAX_SIGNAL_LEN = 8192
MAX_FIELDS = 6


class SignalError(ValueError):
    """A control message was malformed, or not for the call it claims."""


def parse_signal(body: str):
    """Split one control message into (verb, fields).

    Structural only.  Nothing here decides anything; the caller matches the
    call_id and the state before acting on any of it.
    """
    if not isinstance(body, str) or not body.startswith(CALL_PREFIX):
        raise SignalError("not a call signal")
    if len(body) > MAX_SIGNAL_LEN:
        raise SignalError("control message too long")
    remainder = body[len(CALL_PREFIX):]
    verb, _, payload = remainder.partition(":")
    verb = verb.strip().upper()
    if not verb or not verb.isalpha():
        raise SignalError("malformed verb")
    fields = [f.strip() for f in payload.split("|")] if payload else []
    if len(fields) > MAX_FIELDS:
        raise SignalError("too many fields")
    return verb, fields


def _hex_field(text: str, expect_len=None) -> bytes:
    # bytes.fromhex("") returns b"" rather than raising, so an empty
    # field would otherwise pass as valid hex.  Every call site here
    # passes expect_len, but a future one might not.
    if not text:
        raise SignalError("field is empty")
    try:
        raw = bytes.fromhex(text)
    except Exception:
        raise SignalError("field is not valid hex")
    if expect_len is not None and len(raw) != expect_len:
        raise SignalError("field must be %d bytes, got %d"
                          % (expect_len, len(raw)))
    return raw


def _epoch_field(text: str) -> int:
    try:
        epoch = int(text, 10)
    except Exception:
        raise SignalError("epoch is not an integer")
    if epoch < 0 or epoch >= VoiceKeySchedule.MAX_EPOCH:
        raise SignalError("epoch out of range")
    return epoch


class CallControlChannel:
    """The path from a Termux notification button back into a running call.

    A Termux:API notification action is a shell command the Termux app runs
    in its own process.  It cannot call answer_call() directly, so the button
    writes one short line into a FIFO that the client is reading, and the
    client turns that line into exactly the same call the terminal makes.

    Nothing here is a second state machine.  A command resolves to
    ``answer_call`` or ``reject_call`` verbatim, so every gate those already
    enforce still applies — most importantly the SMP check in ``_on_invite``,
    which rejects an unverified peer before a session exists at all.  A
    button can only ever act on a call the client already decided to ring.

    Three properties make the channel safe to hand to the Android UI layer:

    * The generated command contains only a path we chose and a token we
      generated.  No peer-derived text ever reaches a shell command.
    * The token is single-use and bound to one (peer, call_id).  A stale
      "answer" from a previous call cannot answer the one that replaced it,
      and a replayed line finds its token already spent.
    * Every command is re-checked against live session state on arrival, on
      the event loop, exactly as ``/answer`` is.
    """

    VERBS = ("answer", "decline")
    TOKEN_BYTES = 16
    MAX_TOKENS = 8
    TOKEN_TTL = 900.0                 # backstop; disarm() is the normal path
    MAX_LINE = 256
    MAX_BUFFER = 4096

    # The FIFO path is embedded in a shell command, so it may contain only
    # characters that cannot change the command's meaning.  A path failing
    # this yields no buttons rather than a quoted guess.
    _PATH_ALLOWED = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "_./@+-")

    def __init__(self, loop, path=None, which=None, dispatch=None):
        self.loop = loop
        self.path = path or self.default_path()
        self._which = which
        self._dispatch = dispatch
        self._tokens = {}             # token -> (peer, call_id, expiry)
        self._rfd = None
        self._wfd = None
        self._buffer = b""
        self.error = None

    @staticmethod
    def default_path() -> str:
        override = os.environ.get("OTRV4PLUS_CALL_CTL")
        if override:
            return override
        return os.path.join(os.path.expanduser("~"), ".otrv4plus", "call-ctl")

    # -- availability -----------------------------------------------------

    def available(self) -> bool:
        """True when notification buttons can actually do something.

        Off Termux, or without Termux:API installed, this is False and the
        ringer posts the notification it always posted.  There is no partial
        mode: a button that cannot be delivered is worse than no button.
        """
        if not hasattr(os, "mkfifo"):
            return False
        if not _HOST.get("is_termux"):
            return False
        which = self._which or _HOST.get("which")
        if which is None:
            return False
        try:
            return bool(which("termux-notification"))
        except Exception:
            return False

    # -- arming -----------------------------------------------------------

    def arm(self, peer: str, call_id: bytes):
        """Mint a token for one ringing call.  Returns the button list."""
        if not self.available():
            return []
        if set(self.path) - self._PATH_ALLOWED:
            self._note("control path has characters a shell command cannot "
                       "safely carry — buttons disabled")
            return []
        if not self._open():
            return []

        self._expire_tokens()
        if len(self._tokens) >= self.MAX_TOKENS:
            return []
        token = secrets.token_hex(self.TOKEN_BYTES)
        self._tokens[token] = (peer, bytes(call_id),
                               time.monotonic() + self.TOKEN_TTL)
        return [("Answer", self._command("answer", token)),
                ("Decline", self._command("decline", token))]

    def _command(self, verb: str, token: str) -> str:
        # `test -p` first: if the client is gone the FIFO is gone with it, so
        # the button becomes a no-op instead of creating a stray file or
        # blocking the Termux action shell on a pipe nobody is reading.
        return ("test -p '%s' && printf '%s %s\\n' > '%s'"
                % (self.path, verb, token, self.path))

    def disarm(self, peer: str) -> None:
        """Revoke every token for a peer.  Called when the ringing stops."""
        for token, (owner, _cid, _exp) in list(self._tokens.items()):
            if owner == peer:
                self._tokens.pop(token, None)
        if not self._tokens:
            self.close()

    def _expire_tokens(self) -> None:
        now = time.monotonic()
        for token, (_p, _c, expiry) in list(self._tokens.items()):
            if expiry <= now:
                self._tokens.pop(token, None)

    # -- the pipe ---------------------------------------------------------

    def _open(self) -> bool:
        if self._rfd is not None:
            return True
        try:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, mode=0o700, exist_ok=True)
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
            if os.path.exists(self.path) and not _is_fifo(self.path):
                # Something else owns the name.  Ours is the only thing that
                # belongs here, and a regular file would silently swallow
                # every button press.
                os.unlink(self.path)
            if not os.path.exists(self.path):
                os.mkfifo(self.path, 0o600)
            os.chmod(self.path, 0o600)

            rfd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        except Exception as exc:
            return self._open_failed(exc)
        try:
            # Hold a writer of our own so the reader never sees EOF when the
            # last button-press shell exits.  Without this the fd reports
            # readable forever and the loop spins.
            wfd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
        except Exception as exc:
            _close_fd(rfd)
            return self._open_failed(exc)
        try:
            self.loop.add_reader(rfd, self._readable)
        except Exception as exc:
            _close_fd(rfd)
            _close_fd(wfd)
            return self._open_failed(exc)
        self._rfd, self._wfd = rfd, wfd
        return True

    def _open_failed(self, exc) -> bool:
        self.error = str(exc)
        self._note("call control channel unavailable: %s" % _san(str(exc), 120))
        return False

    def close(self) -> None:
        """Tear the channel down.  Idempotent, never raises."""
        rfd, self._rfd = self._rfd, None
        wfd, self._wfd = self._wfd, None
        self._buffer = b""
        if rfd is not None:
            try:
                self.loop.remove_reader(rfd)
            except Exception:
                pass
        for fd in (rfd, wfd):
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass
        try:
            if os.path.exists(self.path) and _is_fifo(self.path):
                os.unlink(self.path)
        except Exception:
            pass

    def shutdown(self) -> None:
        self._tokens.clear()
        self.close()

    # -- reading ----------------------------------------------------------

    def _readable(self) -> None:
        """One readable event on the FIFO.  Event-loop thread only."""
        rfd = self._rfd
        if rfd is None:
            return
        try:
            chunk = os.read(rfd, self.MAX_BUFFER)
        except BlockingIOError:
            return
        except OSError:
            self.close()
            return
        if not chunk:
            return
        self._buffer += chunk
        if len(self._buffer) > self.MAX_BUFFER:
            # A writer sending unbounded data is not one of our buttons.
            self._buffer = b""
            return
        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            self._consume(line)

    def _consume(self, raw: bytes) -> None:
        if not raw or len(raw) > self.MAX_LINE:
            return
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        parts = text.split()
        if len(parts) != 2:
            return
        verb, token = parts
        if verb not in self.VERBS:
            return
        if len(token) != self.TOKEN_BYTES * 2:
            return

        entry = self._tokens.get(token)
        if entry is None:
            return
        peer, call_id, expiry = entry
        # Single use, whichever button was pressed: the call is being decided
        # right now, so neither token survives the decision.
        self.disarm(peer)
        if expiry <= time.monotonic():
            return
        dispatch = self._dispatch
        if dispatch is None:
            return
        try:
            dispatch(verb, peer, call_id)
        except Exception as exc:
            self._note("call control dispatch failed: %s" % _san(str(exc), 120))

    def _note(self, message: str) -> None:
        try:
            _print("[voice] %s" % message)
        except Exception:
            pass


def _close_fd(fd) -> None:
    try:
        os.close(fd)
    except Exception:
        pass


def _is_fifo(path: str) -> bool:
    try:
        import stat
        return stat.S_ISFIFO(os.stat(path).st_mode)
    except OSError:
        return False


class VoiceCallManager:
    """Voice-call lifecycle, signalling and policy.

    SIGNALLING
    ----------
    Control messages ride inside ordinary <message><body> stanzas with a
    distinctive prefix, always through the established OTR session.  IQ
    round-trips were deliberately avoided: over a 3-hop I2P path an IQ
    frequently exceeds slixmpp's reply timeout, whereas a <message> is
    fire-and-forget and traverses reliably.

    Every control message carries the call_id and is rejected unless it
    matches the live call.  v2 identified calls by bare JID alone, so an END
    or a REKEY from a previous call acted on the current one.

    POLICY
    ------
    A call requires an OTR session that is ENCRYPTED and cryptographically
    SMP-verified.  Verification is read only from the engine's own predicate
    — never from printed text, badge state or a set populated by matching
    substrings in log lines, which is what v2 did and which meant a peer
    could satisfy the voice gate by getting a string rendered to a panel.
    Media is never sent in the clear under any circumstance.
    """

    INVITE_TIMEOUT = SAM_SESSION_TIMEOUT + 120

    # Mirrors the module-level constant.  otrv4plus_xmpp.py reaches for
    # VoiceCallManager.CALL_PREFIX in three places to decide whether a
    # decrypted body is call signalling; v2 defined it on the class and v3
    # moved it to module scope, which turned every inbound INVITE into an
    # AttributeError inside the OTR receive path.  Both spellings resolve.
    CALL_PREFIX = CALL_PREFIX

    def __init__(self, xmpp_client, loop, sam_host="127.0.0.1", sam_port=7656):
        self.client = xmpp_client
        #: Event-loop scheduling lag. See _loop_lag_monitor.
        self.loop_lag = Percentiles(512)
        self._lag_task = None
        self.loop = loop
        self.sam_host = sam_host
        self.sam_port = sam_port
        self._calls = {}
        self._timeouts = {}
        self._stats_tasks = {}
        self._rekey_tasks = {}
        self._last_invite = {}
        self._ringers = {}
        # Notification ACCEPT/DECLINE. Opened lazily on the first ring and
        # torn down when nothing is ringing, so a client that never receives
        # a call never creates the FIFO.
        self._call_control = CallControlChannel(
            loop, dispatch=self._on_control_command)
        self._control_limiter = RateLimiter(VOICE_MAX_CONTROL_PER_MIN)
        self._rekey_limiter = RateLimiter(VOICE_MAX_REKEY_PER_MIN)
        # Endpoint changes are rare by nature. A tighter bound than the
        # general control limiter keeps a peer from forcing endpoint churn.
        self._endpoint_limiter = RateLimiter(VOICE_MAX_MEDIAPATH_PER_MIN)
        self.debug = False
        self._debug_t0 = {}

    # -- helpers ----------------------------------------------------------

    #: Diagnostics and the setup detail are ONE switch.
    #:
    #: The call-setup lines moved behind `_vprint` when the terminal output
    #: was tidied, and a second, separate flag for them would have been a
    #: trap: the person who types /voicedebug because a call sounds wrong is
    #: asking for exactly those lines, and would have got telemetry without
    #: the codec, transport and playout geometry that explain it.  Wiring the
    #: two together means --voice-debug and /voicedebug restore the whole of
    #: the old output, and nothing new has to be discovered to get it back.
    @property
    def debug(self) -> bool:
        return self._debug

    @debug.setter
    def debug(self, on) -> None:
        self._debug = bool(on)
        set_voice_verbose(self._debug)

    @staticmethod
    def _bare(jid: str) -> str:
        return (jid or "").split("/", 1)[0]

    def _vdbg(self, peer: str, message: str) -> None:
        if not self.debug:
            return
        elapsed = time.time() - self._debug_t0.get(peer, time.time())
        _print("[voice-dbg %6.2fs] %s: %s"
               % (elapsed, _san(peer, 40), _san(message, 200)))

    def _signal(self, peer: str, verb: str, fields=()) -> bool:
        """Send one control message INSIDE the OTR channel.

        Returns True only if the frame was handed to the transport. Most
        callers ignore it -- a lost REKEY already fails safe on the committed
        epoch -- but media recovery must not, because it changes our own
        destination before telling the peer where it went.

        Call setup is never sent as plaintext.  An eavesdropper on the XMPP
        link — including the server operator — would otherwise learn who
        called whom and when, and would see the initiator's I2P destination.
        If OTR is unavailable the signal is dropped rather than downgraded.
        """
        payload = "|".join(str(f) for f in fields)
        body = CALL_PREFIX + verb + ((":" + payload) if payload else "")
        try:
            frame, should_send = self.client.otr.handle_outgoing_message(
                peer, body)
        except Exception as exc:
            _print("[voice] could not encrypt call signal: %s"
                   % _san(str(exc), 120))
            return False
        if not (should_send and frame):
            _print("[voice] call signal dropped — OTR channel unavailable "
                   "(signalling is never sent in the clear)")
            return False
        try:
            self.client.send_otr_fragmented(
                peer, frame if isinstance(frame, str) else frame.decode())
        except Exception as exc:
            # A dropped signal used to be indistinguishable from a delivered
            # one. Media recovery cannot afford that: it changes our own
            # destination and then tells the peer, so a silent failure leaves
            # the peer addressing an endpoint that no longer exists.
            _print("[voice] call signal could not be sent: %s"
                   % _san(str(exc), 120))
            return False
        return True

    # -- policy -----------------------------------------------------------

    def _smp_verified(self, peer: str) -> bool:
        """True only when the OTR engine cryptographically says so.

        This consults `_smp_query`, which reads the engine's published
        predicates — is_smp_verified(peer), get_smp_status(peer)["verified"],
        and the session-level is_smp_verified().  Nothing else.

        Explicitly NOT consulted, and why:
          * client._smp_reported — populated by the TUI matching substrings
            such as "SMP VERIFIED" and "IDENTITY VERIFIED" in printed lines.
            Peer-influenced text reaching a panel could insert an entry, so
            reading it here made a log string sufficient to unlock a call.
          * Name-token heuristics on the state string.  v2 treated
            "STATE_UPDATED" as success, which is a generic state-change
            notification and says nothing about the outcome.
          * Session attributes named *_complete.  SMP completes on failure
            too; completion is not verification.
        """
        query = getattr(self.client, "_smp_query_fn", None)
        try:
            if callable(query):
                verified, _ = query(self.client.otr, peer)
            else:
                verified, _ = _smp_query_default(self.client.otr, peer)
            return bool(verified)
        except Exception:
            return False

    def _smp_state_name(self, peer: str) -> str:
        query = getattr(self.client, "_smp_query_fn", None)
        try:
            if callable(query):
                return query(self.client.otr, peer)[1]
            return _smp_query_default(self.client.otr, peer)[1]
        except Exception:
            return ""

    def _explain_unverified(self, peer: str) -> None:
        name = self._smp_state_name(peer) or "unavailable"
        _print("[voice] refusing: identity of %s is not SMP-verified"
               % _san(peer, 64))
        _print("[voice] engine reports SMP state: %s" % _san(name, 60))
        _print("[voice] encryption alone proves nobody is listening, not who "
               "is on the line. Run  /smp <shared-secret>  on both sides.")

    def _otr_material(self, peer: str):
        """Collect the OTR-side inputs to the media transcript.

        Returns (otr_binding, local_fp, remote_fp) or None.

        The engine's session id is used ONLY when it can be shown to be
        shared.  It cannot be shown to be shared locally: the engine assigns
            session.session_id = session_keys.get("session_id")
                                 or secrets.token_bytes(32)
        so when the DAKE does not populate it each side invents its own
        random 32 bytes, and mixing that in guarantees the two endpoints
        derive different roots — the "media keys did not agree" failure.

        The binding therefore rests on values provably identical on both
        sides: the sorted fingerprint pair, the per-call salt, and above all
        the fresh hybrid exchange, which is where the security actually
        lives.  A fixed label stands in for the session id so the transcript
        shape is stable.
        """
        try:
            if not self.client.otr.has_encrypted_session(peer):
                return None
        except Exception:
            return None

        local_fp = normalise_fingerprint(self.client._local_fp(peer))
        remote_fp = normalise_fingerprint(self.client._remote_fp(peer))
        if (not local_fp or not remote_fp
                or "UNAVAILABLE" in (local_fp, remote_fp)):
            return None
        if local_fp == remote_fp:
            # Both fingerprints identical means we are looking at ourselves,
            # or the engine returned the same value twice.  Either way the
            # sorted pair carries no binding at all.
            return None
        return b"OTRv4+Voice/session/v3", local_fp, remote_fp

    # -- call bookkeeping -------------------------------------------------

    def _call_for(self, peer: str, call_id_hex: str):
        """Return the live session iff it matches this call_id.

        Every inbound control message goes through here.  A message whose
        call_id does not match the live call is not for this call: it is a
        replay from a previous one, a message crossing a teardown, or an
        injection, and in all three cases the right answer is to ignore it.
        """
        session = self._calls.get(peer)
        if session is None:
            return None
        try:
            call_id = _hex_field(call_id_hex, 16)
        except SignalError:
            return None
        if not hmac.compare_digest(call_id, session.call_id):
            self._vdbg(peer, "control message for a different call_id — ignored")
            return None
        if session.state == CallState.ENDED:
            return None
        return session

    def has_active_call(self, peer: str = None) -> bool:
        if peer:
            session = self._calls.get(self._bare(peer))
            return session is not None and session.is_live
        return any(s.is_live for s in self._calls.values())

    def _live_call_count(self) -> int:
        return sum(1 for s in self._calls.values() if s.is_live)

    def status_line(self) -> str:
        if not self._calls:
            return "[voice] no calls"
        return "\n".join("[voice] %s: %s" % (_san(p, 64), s.describe())
                         for p, s in self._calls.items())

    def ringing_peer(self):
        """The peer whose incoming call is ringing now, if any."""
        for peer, session in self._calls.items():
            if session.state == CallState.RINGING:
                return peer
        return None

    def any_active_peer(self):
        for peer, session in self._calls.items():
            if session.state != CallState.ENDED:
                return peer
        return None

    def _cancel_timeout(self, peer: str) -> None:
        handle = self._timeouts.pop(peer, None)
        if handle is not None:
            try:
                handle.cancel()
            except Exception:
                pass

    def _arm_timeout(self, peer: str, call_id: bytes) -> None:
        self._cancel_timeout(peer)

        def _expire():
            session = self._calls.get(peer)
            # Bound to the call_id: a timer armed for a previous call must
            # never terminate the one that replaced it.
            if session is None or session.call_id != call_id:
                return
            if session.state in (CallState.INVITING, CallState.RINGING,
                                 CallState.CONNECTING,
                                 CallState.KEY_CONFIRMING,
                                 CallState.MEDIA_CONNECTING):
                _print("[voice] no answer from %s — cancelling" % _san(peer, 64))
                asyncio.ensure_future(self.end_call(peer))

        self._timeouts[peer] = self.loop.call_later(self.INVITE_TIMEOUT, _expire)

    # -- outbound ---------------------------------------------------------

    async def start_call(self, peer: str) -> bool:
        """Place a call.  Initiator role: publish a destination, then accept."""
        peer = self._bare(peer)
        # Why the last start_call answered False, for a host that shows it
        # (android_bridge.voice); the printed line says the same to a terminal.
        self.last_refusal = ""
        ok, reason = _HOST["voice_available"]()
        if not ok:
            _print("[voice] unavailable: %s" % reason)
            self.last_refusal = "unavailable"
            return False
        try:
            kem_provider()
        except KemUnavailable as exc:
            _print("[voice] unavailable: %s" % _san(str(exc), 300))
            self.last_refusal = "unavailable"
            return False
        if self._live_call_count() >= VOICE_MAX_CONCURRENT_CALLS:
            _print("[voice] already in a call")
            self.last_refusal = "in_call"
            return False

        material = self._otr_material(peer)
        if material is None:
            _print("[voice] refusing: no usable encrypted OTR session with %s"
                   % _san(peer, 64))
            _print("[voice] run /otr first — voice is never sent unencrypted")
            self.last_refusal = "no_session"
            return False
        if not self._smp_verified(peer):
            self._explain_unverified(peer)
            self.last_refusal = "unverified"
            return False

        now = time.monotonic()
        last = self._last_invite.get(peer, 0.0)
        if now - last < VOICE_MIN_INVITE_INTERVAL:
            _print("[voice] slow down — one call attempt every %ds"
                   % int(VOICE_MIN_INVITE_INTERVAL))
            self.last_refusal = "rate_limited"
            return False
        self._last_invite[peer] = now

        # Fresh per-call salt.  It is what stops a second call inside the
        # same OTR session from reusing the first call's key while the frame
        # counters restart at zero.  It is a salt, not a secret.
        call_id = secrets.token_bytes(16)
        self._debug_t0[peer] = time.time()
        self._vdbg(peer, "placing call, call_id=%s" % call_id.hex()[:16])

        try:
            session = VoiceCallSession(peer, self.loop, call_id, True,
                                       self.sam_host, self.sam_port)
        except Exception as exc:
            _print("[voice] could not start the key exchange: %s"
                   % _san(str(exc), 200))
            self._last_invite.pop(peer, None)   # nothing was sent: retry freely
            self.last_refusal = "key_exchange"
            return False
        session.on_stream_lost = self._handle_stream_lost
        session.on_media_stalled = self._handle_media_stalled
        session.otr_material = material
        session.debug_binding = self.debug
        session.transition(CallState.INVITING)
        self._calls[peer] = session

        _print("[voice] building I2P tunnels for the call — this takes "
               "30-120 s and can be longer on a busy phone; the client is "
               "not stuck")
        try:
            our_dest = await session.create_session()
        except Exception as exc:
            _print("[voice] could not create SAM session: %s"
                   % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=False)
            # No INVITE went out, so the attempt does not count against the
            # retry interval: it used to turn one tunnel failure into a
            # string of `call_rate_limited` on the retries.
            self._last_invite.pop(peer, None)
            self.last_refusal = "tunnel"
            return False

        # Park in ACCEPT *before* the invite goes out, so the responder's
        # connect always finds a listener.  This ordering is what makes the
        # handshake deterministic; the reverse deadlocks.
        session._accept_task = asyncio.ensure_future(
            self._await_media(peer, session))

        self._signal(peer, "INVITE", (call_id.hex(), our_dest,
                                      session.kex.public.hex(),
                                      session.kex.mlkem_ek.hex()))
        self._vdbg(peer, "sent INVITE (dest %d B, x448 %d B, mlkem ek %d B)"
                   % (len(our_dest), len(session.kex.public),
                      len(session.kex.mlkem_ek)))
        self._arm_timeout(peer, call_id)
        _print("[voice] calling %s — waiting for an answer" % _san(peer, 64))
        return True

    async def _await_media(self, peer: str, session) -> None:
        """Initiator side: bring the media transport up, then start audio.

        On the stream transport this blocks in STREAM ACCEPT.  On datagrams
        there is nothing to accept, so it returns at once and the session
        simply cannot send until the callee's first packet authenticates and
        its destination is latched.  Either way the media path can come up
        before the ACCEPT has been processed, so this waits for mutual key
        confirmation before any audio starts.
        """
        try:
            await session.accept_media_stream()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            _print("[voice] media stream failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        if session.is_ended:
            return

        if not session.keys_confirmed.is_set():
            self._vdbg(peer, "media stream up, waiting for key confirmation")
            try:
                await asyncio.wait_for(session.keys_confirmed.wait(),
                                       timeout=120)
            except asyncio.TimeoutError:
                _print("[voice] key confirmation never completed — ending call")
                await self.end_call(peer, notify_peer=True)
                return

        self._cancel_timeout(peer)
        if not session.try_transition(CallState.MEDIA_CONNECTING):
            return
        try:
            await session.start_audio()
        except Exception as exc:
            _print("[voice] audio failed to start: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return
        self._start_stats(peer)
        self._start_rekey(peer)
        _print("[voice] call active with %s — /hangup to end, /mute to toggle mic"
               % _san(peer, 64))
        self._announce_security(session)

    async def answer_call(self, peer: str) -> None:
        """Responder role: derive keys, then create our session and connect."""
        peer = self._bare(peer)
        session = self._calls.get(peer)
        if session is None or session.state != CallState.RINGING:
            _print("[voice] no incoming call to answer")
            return

        # Before anything opens a playback stream, so the two never contend.
        self._stop_ringing(peer)

        # THE GATE AGAIN, AT ANSWER. It was checked when the INVITE arrived,
        # but verification can end while the phone rings: the OTRv4+ session
        # may have been replaced by a new handshake (a peer restart, a
        # recovered DAKE), and a replacement starts unverified by design.
        # Answering on the old verdict would take a call from a peer whose
        # current keys nobody has checked.
        if not self._smp_verified(peer):
            _print("[voice] not answering: %s is no longer SMP-verified"
                   % _san(peer, 64))
            self._signal(peer, "REJECT", (session.call_id.hex(), "unverified"))
            await self.end_call(peer, notify_peer=False)
            return

        if not session.try_transition(CallState.CONNECTING):
            return
        self._cancel_timeout(peer)

        try:
            our_confirm, _, mlkem_ct = session.responder_derive(
                session._peer_x448, session._peer_mlkem_ek)
        except Exception as exc:
            _print("[voice] key agreement failed: %s" % _san(str(exc), 200))
            self._signal(peer, "REJECT", (session.call_id.hex(), "bad-kex"))
            await self.end_call(peer, notify_peer=False)
            return

        session.transition(CallState.KEY_CONFIRMING)
        self._vdbg(peer, "hybrid agreed, confirm=%s" % our_confirm.hex()[:16])

        # ACCEPT carries our X448 public, the ML-KEM ciphertext, and our
        # confirmation tag, so the initiator can complete the agreement and
        # prove it matched.  We do NOT start audio yet: the initiator's
        # CONFIRM is what proves it derived the same root.
        self._signal(peer, "ACCEPT", (session.call_id.hex(),
                                      session.kex.public.hex(),
                                      mlkem_ct.hex(), our_confirm.hex()))

        # Build the tunnel while waiting for CONFIRM — it is the slow step
        # and overlapping it removes almost all of the post-answer delay.
        try:
            prewarm = session._prewarm
            if prewarm is not None:
                try:
                    await asyncio.wait_for(asyncio.shield(prewarm), timeout=150)
                except asyncio.TimeoutError:
                    pass
            if session._sam_session_id is None:
                _print("[voice] building I2P tunnel (30-120 s is normal)…")
                await session.create_session()
            else:
                self._vdbg(peer, "reusing pre-warmed SAM session")
        except Exception as exc:
            _print("[voice] call failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        try:
            await asyncio.wait_for(session.keys_confirmed.wait(), timeout=120)
        except asyncio.TimeoutError:
            _print("[voice] the caller never confirmed the keys — ending call")
            await self.end_call(peer, notify_peer=True)
            return

        if not session.try_transition(CallState.MEDIA_CONNECTING):
            return
        try:
            await session.connect_media_stream(session._peer_dest)
            await session.start_audio()
        except Exception as exc:
            _print("[voice] call failed: %s" % _san(str(exc), 200))
            await self.end_call(peer, notify_peer=True)
            return

        self._start_stats(peer)
        self._start_rekey(peer)
        _print("[voice] call active with %s — /hangup to end, /mute to toggle mic"
               % _san(peer, 64))
        self._announce_security(session)

    # -- inbound ----------------------------------------------------------

    async def handle_signal(self, peer: str, body: str) -> None:
        peer = self._bare(peer)
        try:
            verb, fields = parse_signal(body)
        except SignalError:
            return

        # Rate-limit before doing any work.  Every verb below either allocates
        # or performs public-key operations, so an unbounded stream of them is
        # a cheap remote CPU and tunnel-exhaustion attack.
        if not self._control_limiter.allow(peer):
            self._vdbg(peer, "control message rate limit hit — dropped")
            return

        handlers = {
            "INVITE": self._on_invite,
            "ACCEPT": self._on_accept,
            "CONFIRM": self._on_confirm,
            "REJECT": self._on_reject,
            "REKEY": self._on_rekey,
            "REKEYACK": self._on_rekey_ack,
            "REKEYCOMMIT": self._on_rekey_commit,
            "END": self._on_end,
            "MEDIAPATH": self._on_media_path,
        }
        handler = handlers.get(verb)
        if handler is None:
            return
        try:
            await handler(peer, fields)
        except SignalError as exc:
            self._vdbg(peer, "malformed %s ignored: %s"
                       % (verb, _san(str(exc), 120)))
        except Exception as exc:
            self._vdbg(peer, "%s handler error: %s"
                       % (verb, _san(str(exc), 120)))

    async def _on_invite(self, peer: str, fields) -> None:
        ok, reason = _HOST["voice_available"]()
        if not ok:
            self._signal(peer, "REJECT", ("00" * 16, "unsupported"))
            _print("[voice] rejected call from %s (%s)" % (_san(peer, 64), reason))
            return
        if len(fields) != 4:
            raise SignalError("INVITE takes 4 fields")

        call_id = _hex_field(fields[0], 16)
        caller_dest = fields[1]
        caller_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        caller_ek = _hex_field(fields[3], MLKEM_EK_LEN)

        # Policy checks first, so a peer we will never talk to cannot make us
        # allocate a session or build a tunnel.
        material = self._otr_material(peer)
        if material is None:
            self._signal(peer, "REJECT", (call_id.hex(), "no-otr"))
            _print("[voice] rejected call from %s (no encrypted OTR session)"
                   % _san(peer, 64))
            return
        if not self._smp_verified(peer):
            self._signal(peer, "REJECT", (call_id.hex(), "unverified"))
            _print("[voice] rejected call from %s — identity not SMP-verified"
                   % _san(peer, 64))
            return
        try:
            kem_provider()
        except KemUnavailable:
            self._signal(peer, "REJECT", (call_id.hex(), "no-pq"))
            _print("[voice] rejected call from %s — no ML-KEM available; "
                   "voice will not fall back to X448 alone" % _san(peer, 64))
            return
        if self._live_call_count() >= VOICE_MAX_CONCURRENT_CALLS:
            self._signal(peer, "REJECT", (call_id.hex(), "busy"))
            return
        if not caller_dest or len(caller_dest) < 64 or len(caller_dest) > 2048:
            self._signal(peer, "REJECT", (call_id.hex(), "bad-destination"))
            return
        # Normalise to the Destination alone. A peer running the older code
        # sends the whole SAM private key blob; the datagram source filter
        # compares against SAM's reported source, which is always the
        # destination, so the two have to be in the same form or every media
        # packet is discarded.
        try:
            caller_dest = i2p_public_destination(caller_dest)
        except ValueError as exc:
            self._vdbg(peer, "INVITE destination did not parse: %s"
                       % _san(str(exc), 120))
            self._signal(peer, "REJECT", (call_id.hex(), "bad-destination"))
            return

        now = time.monotonic()
        if now - self._last_invite.get(peer, 0.0) < VOICE_MIN_INVITE_INTERVAL:
            self._vdbg(peer, "INVITE rate limit hit — dropped")
            return
        self._last_invite[peer] = now

        try:
            session = VoiceCallSession(peer, self.loop, call_id, False,
                                       self.sam_host, self.sam_port)
        except Exception as exc:
            self._signal(peer, "REJECT", (call_id.hex(), "internal"))
            self._vdbg(peer, "could not build session: %s" % _san(str(exc), 120))
            return
        session.on_stream_lost = self._handle_stream_lost
        session.on_media_stalled = self._handle_media_stalled
        session.otr_material = material
        session.debug_binding = self.debug
        session._peer_dest = caller_dest
        session._peer_x448 = caller_x448
        session._peer_mlkem_ek = caller_ek
        session.transition(CallState.RINGING)

        self._debug_t0[peer] = time.time()
        self._vdbg(peer, "invite received, call_id=%s" % call_id.hex()[:16])

        # Build our SAM session now rather than on /answer: an I2P tunnel
        # takes 30-120 s, so overlapping it with the ring costs one tunnel if
        # the call is declined and removes almost all of the post-answer wait.
        session._prewarm = asyncio.ensure_future(
            self._prewarm_session(peer, session))
        self._calls[peer] = session
        self._arm_timeout(peer, call_id)

        self._start_ringing(peer, call_id)
        # A bare y/n answers it (owner, 2026-10-14: "less typing"). The
        # client may be a test stub without the method.
        ask = getattr(self.client, "ask_answer_call", None)
        if ask is not None:
            try:
                ask(peer)
            except Exception:
                ask = None
        _print("\n[voice] incoming call from %s" % _san(peer, 64))
        if ask is not None:
            _print("[voice] Answer? [y/n]   (or /answer, /reject%s)\n"
                   % (", or the notification's buttons"
                      if getattr(self._ringers.get(peer), "_actions", None) else ""))
        elif self._ringers.get(peer) is not None \
                and getattr(self._ringers[peer], "_actions", None):
            _print("[voice] Answer/Decline on the notification, or "
                   "/answer and /reject here\n")
        else:
            _print("[voice] /answer to accept, /reject to decline\n")

    def _start_ringing(self, peer: str, call_id: bytes = b"") -> None:
        """Ring, notify and vibrate for an incoming call."""
        self._stop_ringing(peer)
        actions = []
        if call_id:
            try:
                actions = self._call_control.arm(peer, call_id)
            except Exception as exc:
                # The buttons are a convenience; the tone and /answer are not.
                self._vdbg(peer, "call control unavailable: %s"
                           % _san(str(exc), 120))
        try:
            ringer = _audio.Ringer(actions=actions)
            ringer.start(peer=peer, which=_HOST["which"],
                         write_all=_HOST["pipe_write_all"])
            self._ringers[peer] = ringer
        except Exception as exc:
            # Never let a ringtone failure stop a call arriving.
            self._vdbg(peer, "ringer failed: %s" % _san(str(exc), 120))

    def _stop_ringing(self, peer: str) -> None:
        """Silence the ringer.  Must run before the call opens playback."""
        try:
            self._call_control.disarm(peer)
        except Exception:
            pass
        ringer = self._ringers.pop(peer, None)
        if ringer is None:
            return
        try:
            ringer.stop()
        except Exception:
            pass

    def _on_control_command(self, verb: str, peer: str, call_id: bytes) -> None:
        """One ACCEPT/DECLINE press.  Event-loop thread only.

        The token proved which call the button belonged to; this re-checks
        that the call is still that call and still ringing, then takes the
        ordinary path.  A press that arrives after the call moved on — the
        caller hung up, the timeout fired, the terminal already answered —
        does nothing at all.
        """
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            self._vdbg(peer, "notification %s for a call that has gone" % verb)
            return
        if session.state != CallState.RINGING:
            self._vdbg(peer, "notification %s in state %s — ignored"
                       % (verb, session.state))
            return
        _print("[voice] %s from the notification" % verb)
        # create_task rather than ensure_future: this runs from the reader
        # callback, so the manager's own loop is the only correct one and
        # naming it removes any dependence on a current-loop lookup.
        if verb == "answer":
            self.loop.create_task(self.answer_call(peer))
        else:
            self.loop.create_task(self.reject_call(peer))

    async def _on_accept(self, peer: str, fields) -> None:
        if len(fields) != 4:
            raise SignalError("ACCEPT takes 4 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if not session.is_initiator or session.state != CallState.INVITING:
            self._vdbg(peer, "ACCEPT in state %s — ignored" % session.state)
            return
        # The caller's gate, again when the answer arrives: see answer_call.
        if not self._smp_verified(peer):
            _print("[voice] ending call: %s is no longer SMP-verified"
                   % _san(peer, 64))
            self._signal(peer, "REJECT", (session.call_id.hex(), "unverified"))
            await self.end_call(peer, notify_peer=False)
            return

        peer_x448 = _hex_field(fields[1], VoiceKeyExchange.PUB_LEN)
        mlkem_ct = _hex_field(fields[2], MLKEM_CT_LEN)
        peer_confirm = _hex_field(fields[3], CONFIRM_LEN)

        try:
            our_confirm, _ = session.initiator_derive(peer_x448, mlkem_ct)
        except Exception as exc:
            _print("[voice] key agreement failed: %s" % _san(str(exc), 200))
            await self.end_call(peer)
            return

        if not session.verify_peer_confirm(peer_confirm):
            # Comparing in constant time costs nothing and avoids leaking,
            # through timing, how much of the tag matched.
            _print("[voice] ABORTING: media keys did not agree with %s."
                   % _san(peer, 64))
            _print("[voice] the OTR sessions differ or the exchange was "
                   "tampered with — no audio will be sent")
            self._signal(peer, "REJECT", (session.call_id.hex(), "key-mismatch"))
            await self.end_call(peer, notify_peer=False)
            return

        session.transition(CallState.KEY_CONFIRMING)
        self._signal(peer, "CONFIRM", (session.call_id.hex(),
                                       our_confirm.hex()))
        session.mark_keys_confirmed()
        self._vdbg(peer, "hybrid agreed and confirmed, confirm=%s"
                   % our_confirm.hex()[:16])
        _print("[voice] %s answered — keys confirmed, establishing media…"
               % _san(peer, 64))

    async def _on_confirm(self, peer: str, fields) -> None:
        """Responder side: the initiator's proof that it derived the same root."""
        if len(fields) != 2:
            raise SignalError("CONFIRM takes 2 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if session.is_initiator or session.state != CallState.KEY_CONFIRMING:
            return
        peer_confirm = _hex_field(fields[1], CONFIRM_LEN)
        if not session.verify_peer_confirm(peer_confirm):
            _print("[voice] ABORTING: the caller's key confirmation did not "
                   "match — no audio will be sent")
            await self.end_call(peer, notify_peer=True)
            return
        session.mark_keys_confirmed()
        self._vdbg(peer, "caller confirmed — media may start")

    async def _on_reject(self, peer: str, fields) -> None:
        if not fields:
            raise SignalError("REJECT takes at least 1 field")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        reason = _san(fields[1] if len(fields) > 1 else "", 40)
        explain = {
            "busy": "already on a call",
            "no-otr": "no encrypted OTR session on their side",
            "unsupported": "voice support unavailable on their device",
            "no-pq": "no ML-KEM available on their device",
            "bad-destination": "malformed invite",
            "bad-kex": "malformed key exchange",
            "key-mismatch": "media keys did not agree",
            "unverified": "your identity is not SMP-verified on their side",
            "internal": "internal error on their side",
        }.get(reason, reason or "declined")
        _print("[voice] %s declined: %s" % (_san(peer, 64), _san(explain, 64)))
        await self.end_call(peer, notify_peer=False)

    async def _on_end(self, peer: str, fields) -> None:
        if not fields:
            raise SignalError("END takes 1 field")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        await self.end_call(peer, notify_peer=False)
        _print("[voice] %s ended the call" % _san(peer, 64))

    # -- rekey ------------------------------------------------------------

    async def _initiate_rekey(self, peer: str, session) -> None:
        """Initiator: run one two-phase hybrid rekey.

        CURRENT -> PENDING -> CONFIRMED -> COMMITTED.  Nothing about the
        committed epoch changes until the responder's confirmation verifies,
        so a lost, replayed, delayed or forged REKEYACK costs one rekey and
        never the call.
        """
        if session.state != CallState.ACTIVE:
            return

        # Re-announce the previous commit before asking for the next epoch.
        #
        # We commit an epoch the moment the peer's confirmation verifies and
        # only then send REKEYCOMMIT.  If that one message is lost the peer
        # stays an epoch behind forever: every REKEY we send afterwards is for
        # an epoch it considers two ahead, so it rejects all of them and the
        # call never rekeys again.  Repeating the last commit costs one small
        # signal per rekey interval and is idempotent — a peer that already
        # committed has nothing pending and ignores it.  The tag proves the
        # same thing it proved the first time, and can promote only the exact
        # epoch it names.
        last_commit = getattr(session, "_last_rekey_commit", None)
        if last_commit is not None:
            self._signal(peer, "REKEYCOMMIT",
                         (session.call_id.hex(), last_commit[0],
                          last_commit[1]))

        try:
            epoch, kex = session.begin_rekey_initiator()
        except Exception as exc:
            self._vdbg(peer, "rekey setup failed: %s" % _san(str(exc), 120))
            return

        waiter = self.loop.create_future()
        session._rekey_waiter = (epoch, waiter)
        self._vdbg(peer, "rekey %d: sending fresh X448 + ML-KEM" % epoch)
        self._signal(peer, "REKEY", (session.call_id.hex(), epoch,
                                     kex.public.hex(), kex.mlkem_ek.hex()))

        try:
            peer_x448, mlkem_ct, peer_confirm = await asyncio.wait_for(
                waiter, timeout=VOICE_REKEY_TIMEOUT)
        except asyncio.TimeoutError:
            # A failed rekey must never drop a working call.  The committed
            # epoch stays in force and the next attempt runs on schedule.
            self._vdbg(peer, "rekey %d timed out — continuing on epoch %d"
                       % (epoch, session.schedule.epoch))
            session._rekey_waiter = None
            session._rekey_kex = None
            session.abort_rekey()
            return
        except asyncio.CancelledError:
            session._rekey_waiter = None
            session.abort_rekey()
            raise
        finally:
            session._rekey_waiter = None

        try:
            our_confirm, expected = session.rekey_initiator_finish(
                epoch, peer_x448, mlkem_ct)
        except Exception as exc:
            self._vdbg(peer, "rekey %d derivation failed: %s"
                       % (epoch, _san(str(exc), 120)))
            session.abort_rekey()
            return

        if not hmac.compare_digest(bytes(peer_confirm), expected):
            # Discard the pending key, retain the current one, wipe the
            # temporary material.  The call continues on the old epoch.
            self._vdbg(peer, "rekey %d confirmation mismatch — pending key "
                       "discarded, call continues on epoch %d"
                       % (epoch, session.schedule.epoch))
            session.abort_rekey(discard_receive=True)
            return

        if not session.commit_rekey(epoch, peer_confirm):
            session.abort_rekey()
            return
        commit_hex = our_confirm.hex()
        session._last_rekey_commit = (epoch, commit_hex)
        self._signal(peer, "REKEYCOMMIT", (session.call_id.hex(), epoch,
                                           commit_hex))
        self._vdbg(peer, "rekey %d committed" % epoch)

    async def _on_rekey(self, peer: str, fields) -> None:
        """Responder: derive the pending epoch and confirm it.  No commit yet."""
        if len(fields) != 4:
            raise SignalError("REKEY takes 4 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if session.is_initiator:
            # Only the initiator drives rekeys, so the two can never collide.
            self._vdbg(peer, "REKEY from the responder — ignored")
            return
        if session.state != CallState.ACTIVE:
            self._vdbg(peer, "REKEY in state %s — ignored" % session.state)
            return
        if not self._rekey_limiter.allow(peer):
            self._vdbg(peer, "rekey rate limit hit — dropped")
            return

        epoch = _epoch_field(fields[1])
        peer_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        peer_ek = _hex_field(fields[3], MLKEM_EK_LEN)

        if epoch <= session.schedule.epoch:
            # Old and duplicate epochs.  The counter only ever moves forward,
            # so a REKEY for an epoch we already hold proves nothing and is
            # the shape a replay takes.
            self._vdbg(peer, "REKEY epoch %d rejected (already at %d)"
                       % (epoch, session.schedule.epoch))
            return
        if epoch > session.schedule.epoch + VOICE_REKEY_MAX_CATCHUP:
            # An implausible jump.  Bounded so a peer cannot make us derive
            # arbitrarily far ahead, and so the epoch space cannot be burned.
            self._vdbg(peer, "REKEY epoch %d rejected (more than %d ahead of %d)"
                       % (epoch, VOICE_REKEY_MAX_CATCHUP,
                          session.schedule.epoch))
            return
        if epoch > session.schedule.epoch + 1:
            # The peer is AHEAD of us, not merely next.
            #
            # This used to be rejected together with replays, and that is how
            # a long call lost forward secrecy permanently.  The initiator
            # commits an epoch as soon as our tag verifies; if the REKEYCOMMIT
            # that tells us so goes missing, it moves on and we do not.  Every
            # REKEY afterwards is for an epoch we consider two ahead, so we
            # rejected all of them -- and no later message could ever repair
            # it, because the repair was the thing being rejected.
            #
            # Catching up is safe.  REKEY arrives inside the authenticated OTR
            # channel, so only the real peer can send one; accepting it only
            # DERIVES a pending epoch, and committing still requires a
            # confirmation tag that only the real peer can produce.  Nothing
            # is rolled back: the epoch strictly increases either way.
            self._vdbg(peer, "REKEY epoch %d is ahead of ours (%d) — "
                       "catching up" % (epoch, session.schedule.epoch))
            if session.schedule.pending_epoch is not None:
                session.abort_rekey()
        if session.schedule.pending_epoch is not None:
            # A pending epoch that is still young belongs to a REKEY we are
            # already answering: a duplicate or a replay must not restart it.
            #
            # An old one is a different animal.  The initiator gives up on an
            # unanswered rekey after VOICE_REKEY_TIMEOUT and retries with a
            # fresh key exchange, but the responder had no expiry at all — so
            # a single REKEYACK or REKEYCOMMIT lost to a control-plane blip
            # left `pending` set forever and every later REKEY was ignored.
            # A 69-minute call rekeyed 12 times, lost one REKEYCOMMIT, and
            # then failed all 15 remaining attempts: no forward-secrecy
            # refresh for the last 40 minutes.  Give the responder the same
            # expiry the initiator has, so a blip costs one rekey, not all of
            # them.
            age = session.schedule.pending_age
            if age is not None and age < VOICE_REKEY_TIMEOUT:
                self._vdbg(peer, "REKEY while epoch %d already pending — "
                           "ignored" % session.schedule.pending_epoch)
                return
            self._vdbg(peer, "pending epoch %d unconfirmed for %.0fs — "
                       "superseded" % (session.schedule.pending_epoch,
                                       age or 0.0))
            session.abort_rekey()

        try:
            our_confirm, mlkem_ct, our_x448 = session.rekey_responder(
                epoch, peer_x448, peer_ek)
        except Exception as exc:
            self._vdbg(peer, "rekey %d rejected: %s"
                       % (epoch, _san(str(exc), 120)))
            session.abort_rekey(discard_receive=True)
            return

        self._signal(peer, "REKEYACK", (session.call_id.hex(), epoch,
                                        our_x448.hex(), mlkem_ct.hex(),
                                        our_confirm.hex()))
        self._vdbg(peer, "rekey %d derived and acknowledged (pending)" % epoch)

    async def _on_rekey_ack(self, peer: str, fields) -> None:
        if len(fields) != 5:
            raise SignalError("REKEYACK takes 5 fields")
        session = self._call_for(peer, fields[0])
        if session is None or not session.is_initiator:
            return
        waiter = getattr(session, "_rekey_waiter", None)
        if waiter is None:
            return
        epoch_expected, future = waiter
        epoch = _epoch_field(fields[1])
        if epoch != epoch_expected or future.done():
            # A REKEYACK for any other epoch — including a replay of the
            # previous one — is not an answer to the question we asked.
            self._vdbg(peer, "REKEYACK for epoch %d ignored (awaiting %d)"
                       % (epoch, epoch_expected))
            return
        peer_x448 = _hex_field(fields[2], VoiceKeyExchange.PUB_LEN)
        mlkem_ct = _hex_field(fields[3], MLKEM_CT_LEN)
        peer_confirm = _hex_field(fields[4], CONFIRM_LEN)
        future.set_result((peer_x448, mlkem_ct, peer_confirm))

    async def _on_rekey_commit(self, peer: str, fields) -> None:
        """Responder: the initiator verified our tag, so commit the epoch."""
        if len(fields) != 3:
            raise SignalError("REKEYCOMMIT takes 3 fields")
        session = self._call_for(peer, fields[0])
        if session is None or session.is_initiator:
            return
        epoch = _epoch_field(fields[1])
        peer_confirm = _hex_field(fields[2], CONFIRM_LEN)
        if session.schedule.pending_epoch != epoch:
            if epoch <= session.schedule.epoch:
                # The initiator repeats its last commit with every REKEY.
                # Once we have committed that epoch the repeat is a no-op.
                self._vdbg(peer, "REKEYCOMMIT for epoch %d already applied"
                           % epoch)
            else:
                self._vdbg(peer, "REKEYCOMMIT for epoch %d with none pending"
                           % epoch)
            return
        if session.commit_rekey(epoch, peer_confirm):
            self._vdbg(peer, "rekey %d committed" % epoch)
        else:
            self._vdbg(peer, "rekey %d commit rejected — staying on epoch %d"
                       % (epoch, session.schedule.epoch))

    async def _rekey_loop(self, peer: str) -> None:
        """Initiator-side timer driving periodic hybrid rekeys."""
        try:
            while True:
                await asyncio.sleep(VOICE_REKEY_SECONDS)
                session = self._calls.get(peer)
                if session is None or session.state != CallState.ACTIVE:
                    return
                await self._initiate_rekey(peer, session)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self._vdbg(peer, "rekey loop stopped: %s" % _san(str(exc), 120))

    def _start_rekey(self, peer: str) -> None:
        session = self._calls.get(peer)
        if session is None or not session.is_initiator:
            return
        task = self._rekey_tasks.get(peer)
        if task is None or task.done():
            self._rekey_tasks[peer] = asyncio.ensure_future(
                self._rekey_loop(peer))

    # -- background -------------------------------------------------------

    async def _prewarm_session(self, peer: str, session) -> None:
        try:
            await session.create_session()
            self._vdbg(peer, "SAM session pre-warmed while ringing")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._vdbg(peer, "pre-warm failed (%s), will retry on answer"
                       % _san(str(exc), 120))

    async def _stats_loop(self, peer: str) -> None:
        session = self._calls.get(peer)
        last = dict(session.stats) if session else {}
        try:
            while self.debug:
                await asyncio.sleep(5)
                session = self._calls.get(peer)
                if session is None or session.state != CallState.ACTIVE:
                    return
                cur = session.stats
                delta = {k: cur.get(k, 0) - last.get(k, 0) for k in cur}
                last = dict(cur)
                # backpressure and stale are the two counters that tell a
                # congested path apart from a lossy one: a path that is simply
                # dropping shows rx far below tx with both at zero, whereas a
                # path whose queues are full shows them climbing while rx
                # arrives in bursts. Without them in this line the two look
                # identical, which is how a 24-second send queue went
                # undiagnosed across several calls.
                # jitter is reported as depth/target with the measured
                # arrival deviation and the resulting buffer delay beside it.
                # depth/max said nothing about whether the buffer was sized
                # for the path or merely parked at its shed threshold, which
                # is what it was doing at 840 ms.
                # dg= is the raw arrival count. rx=0 with dg=0 means the
                # path is dead; rx=0 with dg>0 means it is not, and the fault
                # is above the transport. The live failure could not be
                # classified because this number did not exist.
                self._vdbg(peer, "5s: tx=%d dg=%d rx=%d drop=%d bp=%d "
                           "stale=%d "
                           "foreign=%d late=%d nokey=%d authfail=%d replay=%d "
                           "jitter=%d/%d jit=%.0fms buf=%dms epoch=%d %s"
                           % (delta.get("sent", 0), delta.get("dgram_in", 0),
                              delta.get("recv", 0),
                              delta.get("dropped", 0),
                              delta.get("backpressure", 0),
                              delta.get("stale", 0),
                              delta.get("foreign", 0),
                              delta.get("late", 0),
                              delta.get("rej_no_key", 0),
                              delta.get("auth_fail", 0), delta.get("replay", 0),
                              session.jitter.depth(),
                              session.jitter.target_depth,
                              session.jitter.jitter_ms,
                              session.jitter.depth() * VOICE_FRAME_MS,
                              session.schedule.epoch,
                              session.latency.summary()))
                # A call can run its whole length with rtt=- and oneway=-,
                # which says only that no probe completed -- not whether the
                # PINGs went out, whether they were answered, or whether the
                # answers timed out. Those three are already tracked; printing
                # them is what turns "no measurement" into a measurement.
                # Levels. "Hard to hear on one phone, clear on the other"
                # is a measurable statement and was left unmeasured for
                # several calls; the two devices differed by 17 dB at the
                # microphone.
                try:
                    session._mic_gain.sample()
                    session._speaker_gain.sample()
                    self._vdbg(peer, "levels: %s %s"
                               % (session._mic_gain.summary(),
                                  session._mic_comp.summary()))
                    self._vdbg(peer, "levels: %s %s"
                               % (session._speaker_gain.summary(),
                                  session._speaker_comp.summary()))
                except Exception:
                    pass
                # Distributions, not just the current value. Phase 2 of the
                # brief asks where every millisecond goes; a single instant
                # cannot answer that, and the tail is what sets the buffer.
                try:
                    lo, hi = session.jitter.sample_depth()
                    self._vdbg(peer,
                               "spacing: %s | buffer depth %d-%d frames "
                               "(%d-%d ms) target %d | underrun=%d "
                               "overflow=%d shed=%d bursts=%d"
                               % (session.jitter.spacing.summary(),
                                  lo, hi, lo * VOICE_FRAME_MS,
                                  hi * VOICE_FRAME_MS,
                                  session.jitter.target_depth,
                                  session.jitter.stats["underrun"],
                                  session.jitter.stats["overflow"],
                                  session.jitter.stats["drift"],
                                  session.jitter.stats["burst_drain"]))
                    self._vdbg(peer, "rtt: %s"
                               % session.latency.rtt_pct.summary())
                    # The decomposition. p50/p95 per stage, in ms.
                    self._vdbg(peer, "stages(p50/p95): %s"
                               % session.stages.summary())
                    self._vdbg(peer, "dwell: %s | loop lag: %s"
                               % (session.jitter.dwell.summary(),
                                  self.loop_lag.summary()))
                    # The headline: how much of the reported one-way figure
                    # this device produced rather than the network.
                    oneway = session.latency.oneway_ms or 0.0
                    local = session.stages.local_send_ms()
                    if oneway > 0:
                        dwell = session.jitter.dwell.percentile(0.50)
                        playout = (session.stages.t["decode"].percentile(0.50)
                                   + session.stages.t["play"].percentile(0.50))
                        m2e = oneway + dwell + playout
                        self._vdbg(
                            peer,
                            "budget: one-way %s = local send %.0fms + "
                            "network %.0fms (%.0f%% local) | + dwell %.0fms "
                            "+ playout %.0fms = mouth-to-ear ~%s"
                            % (colour_latency(oneway), local,
                               max(0.0, oneway - local),
                               100.0 * local / oneway, dwell, playout,
                               colour_latency(m2e)))
                except Exception:
                    pass
                lat = session.latency
                if lat.sent and not lat.answered:
                    self._vdbg(peer,
                               "probes: %d sent, 0 answered, %d timed out — "
                               "latency cannot be reported until one "
                               "completes" % (lat.sent, lat.timed_out))
                # 5000 // FRAME_MS, not (1000 // FRAME_MS) * 5: at 60 ms the
                # latter truncates 16.67 to 16 and reports the expectation as
                # 80 frames instead of 83.
                expect = 5000 // VOICE_FRAME_MS
                if delta.get("recv", 0) == 0:
                    self._vdbg(peer, "WARNING: no audio received in 5 s")
                elif delta.get("recv", 0) < expect // 2:
                    self._vdbg(peer, "WARNING: receiving %d/%d expected frames "
                               "— the I2P path may not sustain the bitrate"
                               % (delta.get("recv", 0), expect))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def _loop_lag_monitor(self) -> None:
        """Measure how late the shared event loop runs its own timers.

        otrv4plus_xmpp hands this manager asyncio.get_event_loop() -- the same
        loop slixmpp runs on. Media sendto, AEAD verify and decrypt for every
        inbound frame, XMPP TLS and XML, OTR handling including ML-DSA-87
        verification, and rekey key generation all execute on that one thread,
        and the GIL means none of it overlaps.

        So XMPP work delays media, and in the existing telemetry that is
        indistinguishable from network jitter -- both show up as irregular
        arrival spacing. Sleeping for a known interval and measuring the
        overshoot separates them: lag here is ours, spacing minus lag is the
        path's.

        Ten samples a second, one timer each. Negligible against the media
        work already on this loop, and it is the only way to tell a busy loop
        from a slow network.
        """
        interval = 0.1
        try:
            while True:
                start = time.monotonic()
                await asyncio.sleep(interval)
                overshoot = (time.monotonic() - start - interval) * 1000.0
                self.loop_lag.add(max(0.0, overshoot))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def _start_stats(self, peer: str) -> None:
        if not self.debug:
            return
        task = self._stats_tasks.get(peer)
        if task is None or task.done():
            # Once per call, so the colours mean something without having to
            # remember the thresholds.
            self._vdbg(peer, latency_legend())
            self._stats_tasks[peer] = asyncio.ensure_future(
                self._stats_loop(peer))
        # One monitor for the loop, not one per call: it measures the loop,
        # and there is only one of those.
        if self._lag_task is None or self._lag_task.done():
            self._lag_task = asyncio.ensure_future(self._loop_lag_monitor())

    # -- media endpoint recovery -------------------------------------------

    def _control_plane_ready(self, peer: str) -> bool:
        """Whether an authenticated signal can actually reach the peer now.

        Media recovery is not a local operation: it replaces our destination
        and then tells the peer where it moved. Doing the first half without
        the second is strictly worse than doing nothing -- the peer keeps
        addressing an endpoint we have just destroyed, and the old one can no
        longer come back when the router rebuilds its tunnels.

        A WiFi-to-mobile transition takes both planes down together, and the
        media watchdog fires at 15 s while XMPP reconnects in 10-70 s, so
        this is the common case rather than a corner one.
        """
        client = self.client
        try:
            is_connected = getattr(client, "is_connected", None)
            if is_connected is not None and not is_connected():
                return False
        except Exception:
            return False
        try:
            return bool(client.otr.has_encrypted_session(peer))
        except Exception:
            return False

    def _handle_media_stalled(self, peer: str, call_id: bytes) -> bool:
        """The session's watchdog wants its media endpoint replaced.

        Called on the event loop from the watchdog. Returns True only if a
        recovery task was actually started; False refunds the attempt, since
        the budget bounds rebuilds rather than bounding how often we ask.

        Starts at most one task per session; the session set _recovering and
        counted the attempt, and the task clears the flag however it ends.
        """
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            return False
        existing = session._recover_task
        if existing is not None and not existing.done():
            return False
        if not self._control_plane_ready(peer):
            self._vdbg(peer, "media recovery deferred — no signalling path "
                             "to announce a new endpoint on")
            return False
        session._recover_task = self.loop.create_task(
            self._recover_media(peer, call_id))
        return True

    async def _recover_media(self, peer: str, call_id: bytes) -> None:
        """Replace our media endpoint and tell the peer where it moved.

        Bound to the call_id at every step that can outlive an await: a
        rebuild takes as long as an I2P tunnel build, and the call it started
        for can end, be replaced, or be torn down while the router works.
        Nothing here may act on the call that replaced this one.
        """
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            return
        # An endpoint we already replaced but never managed to announce needs
        # the announcement, not another endpoint.
        announce_only = bool(session._endpoint_announce_pending
                             and session._our_dest)
        if announce_only:
            _print("[voice] re-announcing the media path — the signalling "
                   "channel was down when it moved")
        else:
            _print("[voice] rebuilding the media path (%d/%d) — this takes as "
                   "long as a new I2P tunnel"
                   % (session._recover_attempts, VOICE_RECOVER_ATTEMPTS))
        # The deadline is handed back on EVERY exit, including cancellation.
        # A suspended deadline that is never returned would leave the call
        # dead and silent forever, which is the condition all of this exists
        # to remove -- so it is structural rather than something to get right
        # at each of five return paths.
        try:
            if not announce_only:
                try:
                    await asyncio.wait_for(session.rebuild_media_endpoint(),
                                           timeout=VOICE_RECOVER_TIMEOUT_S)
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    self._vdbg(peer, "media rebuild timed out")
                    return
                except Exception as exc:
                    self._vdbg(peer, "media rebuild failed: %s"
                               % _san(str(exc), 120))
                    return

            # Re-resolve: the call may have ended or been replaced while the
            # router was building tunnels.
            session = self._calls.get(peer)
            if session is None or session.call_id != call_id:
                return
            try:
                epoch, seq, destination, tag = \
                    session.build_endpoint_announcement()
            except Exception as exc:
                self._vdbg(peer, "endpoint announcement failed: %s"
                           % _san(str(exc), 120))
                return
            if self._signal(peer, "MEDIAPATH", (call_id.hex(), epoch, seq,
                                                destination, tag.hex())):
                session._endpoint_announce_pending = False
                self._vdbg(peer, "announced media endpoint seq=%d epoch=%d"
                           % (seq, epoch))
            else:
                # The endpoint moved and the peer does not know. Rebuilding
                # again would strand a second one; retry the announcement.
                session._endpoint_announce_pending = True
                session._recover_attempts = max(
                    0, session._recover_attempts - 1)
                self._vdbg(peer, "endpoint announcement could not be sent — "
                                 "will retry when signalling returns")
        finally:
            self._finish_recovery(peer, call_id)

    def _finish_recovery(self, peer: str, call_id: bytes) -> None:
        """Hand the deadline back to the watchdog.  Idempotent."""
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            return
        session._recovering = False

    async def _on_media_path(self, peer: str, fields) -> None:
        """The peer's media endpoint moved.  Adopt it if it authenticates."""
        if len(fields) != 5:
            raise SignalError("MEDIAPATH takes 5 fields")
        session = self._call_for(peer, fields[0])
        if session is None:
            return
        if not self._endpoint_limiter.allow(peer):
            self._vdbg(peer, "endpoint announcement rate limit hit — dropped")
            return
        epoch = _epoch_field(fields[1])
        seq = _epoch_field(fields[2])
        destination = fields[3]
        if not destination or len(destination) > 2048:
            self._vdbg(peer, "MEDIAPATH carried no usable destination")
            return
        tag = _hex_field(fields[4], CONFIRM_LEN)
        reason = session.accept_endpoint(epoch, seq, destination, tag)
        if reason != "ok":
            self._vdbg(peer, "MEDIAPATH seq=%d rejected: %s"
                       % (seq, _san(reason, 80)))
            return
        _print("[voice] %s moved its media path — audio should resume"
               % _san(peer, 64))
        self._vdbg(peer, "adopted endpoint seq=%d epoch=%d" % (seq, epoch))

    def _handle_stream_lost(self, peer: str, call_id: bytes, why: str) -> None:
        """Media path died by itself.

        Bound to the call_id: a callback fired by a dying session must never
        tear down the call that replaced it.
        """
        session = self._calls.get(peer)
        if session is None or session.call_id != call_id:
            return
        _print("[voice] call with %s lost: %s"
               % (_san(peer, 64), _san(why, 80)))
        asyncio.ensure_future(self.end_call(peer, notify_peer=True))

    # -- teardown ---------------------------------------------------------

    async def end_call(self, peer: str, notify_peer: bool = True) -> None:
        peer = self._bare(peer)
        self._stop_ringing(peer)
        session = self._calls.pop(peer, None)
        self._cancel_timeout(peer)
        for registry in (self._stats_tasks, self._rekey_tasks):
            task = registry.pop(peer, None)
            if task is not None and not task.done():
                task.cancel()
        if session is None:
            _print("[voice] no active call")
            return
        waiter = getattr(session, "_rekey_waiter", None)
        if waiter is not None and not waiter[1].done():
            waiter[1].cancel()
        if notify_peer:
            try:
                self._signal(peer, "END", (session.call_id.hex(),))
            except Exception:
                pass
        # Gathered BEFORE end(), which tears down the jitter buffer and the
        # latency tracker the figures come from. Printed after, so the two
        # lines are not split by whatever teardown has to say.
        summary = self._call_summary(session)
        stats = await session.end()
        for line in summary:
            _print(line)
        self._report_teardown(stats)

    def _report_teardown(self, stats) -> None:
        """The second hangup line: keys gone, and anything that smelled wrong.

        The full packet tally used to print on every call.  Five counters is
        a diagnostic, and it is the wrong thing to hand somebody who has just
        put the phone down -- but two of those counters are NOT diagnostics.
        A non-zero auth-failure or replay count means frames arrived that did
        not authenticate under our key, and burying that behind a debug flag
        would hide the one number a user of an encrypted call is entitled to
        see.  So they are printed whenever they are non-zero, and only then.

        The wipe confirmation is printed LAST and outside every try, because
        it is the one statement here that is not a reading: the keys were
        zeroized by `session.end()` before this was called, and a counter
        that could not be formatted must not be able to withhold the fact.
        """
        def _n(key):
            try:
                return int(stats.get(key, 0))
            except Exception:
                return 0

        try:
            bad = _n("auth_fail") + _n("replay")
            if bad:
                _print("[voice] ⚠ %d frame(s) failed authentication or "
                       "replayed and were DISCARDED — sent %d, received %d, "
                       "auth-failed %d, replayed %d"
                       % (bad, _n("sent"), _n("recv"),
                          _n("auth_fail"), _n("replay")))
            else:
                _vprint("[voice] sent %d, received %d, dropped %d"
                        % (_n("sent"), _n("recv"), _n("dropped")))
        except Exception:
            pass
        _print("[voice] 🔒 every media key for this call has been zeroized")

    def _announce_security(self, session) -> None:
        """Say what protects the call, once, as it goes live.

        The setup output described gains, buffers and Android stream types
        and never once named the cryptography, so a user had no way to tell a
        post-quantum call from a classical one.  This is the line that
        answers "what am I protected by", and it prints at normal volume
        because it is the only setup line that changes what the call means.

        Never raises: a report that fails must not take the call with it.
        """
        try:
            _print(session.security_line())
        except Exception as exc:
            self._vdbg(getattr(session, "peer", "?"),
                       "security line failed: %s" % type(exc).__name__)

    #: A call is reported bad below this delivery ratio, whatever the delay.
    #: Concealment hides a few per cent; a fifth of the audio missing is a
    #: call the other person struggled through.
    CALL_GOOD_DELIVERY = 0.95

    #: How much audio the buffer may shed before the call is reported bad.
    #:
    #: Shedding is a healthy mechanism in small amounts -- it is how a call
    #: that started on a congested path gets its latency back.  Above this it
    #: is the symptom of a playout device that cannot keep up, which is what
    #: destroyed a third of a 1960 s call while every counter read healthy.
    CALL_MAX_SHED = 0.05

    def _call_summary(self, session) -> list:
        """The lines that say whether the call was any good.

        Asked for from a handset: the only thing printed at hangup was a
        packet tally, which says whether the software worked and nothing
        about whether the CALL worked.  Mouth-to-ear delay and delivery are
        what a person actually experienced, and they were computed already --
        for the debug stream, where nobody watching a call would see them.

        Read BEFORE `session.end()`, because end() tears down the jitter
        buffer and the latency tracker that these come from.  A summary
        gathered afterwards reports zeros, which is worse than no summary at
        all: it looks like a measurement.

        Never raises.  A hangup that fails because the report failed would be
        a call you cannot leave.
        """
        try:
            return self._call_summary_inner(session)
        except Exception as exc:
            self._vdbg(getattr(session, "peer", "?"),
                       "summary failed: %s" % type(exc).__name__)
            return ["[voice] call ended"]

    def _call_summary_inner(self, session) -> list:
        # Wall-clock length of the call. NOT LatencyTracker.call_ms(), which
        # despite the name is a masked frame timestamp with a random per-call
        # origin -- using it here would print a duration of several weeks.
        secs = 0.0
        timed = False
        try:
            secs = max(0.0, time.monotonic() - session._call_t0)
            timed = True
        except Exception:
            pass
        duration = ("%dm%02ds" % (int(secs) // 60, int(secs) % 60)
                    if secs >= 60 else "%ds" % int(secs))

        # Mouth-to-ear: the same decomposition the debug stream reports --
        # network one-way, plus how long a frame waited in our jitter buffer,
        # plus decode and playout.  Not the round trip, and not the network
        # alone: what the far end says takes this long to reach an ear.
        m2e = None
        try:
            oneway = session.latency.oneway_ms
            if oneway:
                m2e = (oneway
                       + session.jitter.dwell.percentile(0.50)
                       + session.stages.t["decode"].percentile(0.50)
                       + session.stages.t["play"].percentile(0.50))
        except Exception:
            m2e = None

        sent = 0
        try:
            sent = int(session.stats.get("sent", 0))
        except Exception:
            pass

        # How much of the far end's speech an ear actually received.
        #
        # NOT recv/(recv+dropped): `dropped` mixes send-side drops into a
        # receive-side ratio, so a call that could not transmit would report
        # as one that could not listen.  The jitter buffer already knows the
        # answer -- `queued` is every frame accepted for playout and `gaps`
        # is every frame missing from the sequence when its turn came, which
        # is exactly the audio that had to be concealed.
        # From the definitions in otrv4plus_mediapath.COUNTER_DEFINITIONS.
        # `played` is frames actually taken for playout. It used to be the
        # jitter buffer's `queued` -- frames ACCEPTED -- which also counted
        # every frame later shed to cut latency or evicted when full, so
        # shed audio was reported twice (as played and as shed) and the
        # delivery ratio was overstated by exactly the shed fraction.
        counts = _mediapath.counters_from(session)
        played, gaps = counts.played, counts.gaps
        delivery = None
        if played + gaps:
            delivery = float(played) / float(played + gaps)

        # Audio we threw away ourselves, as a share of everything that
        # reached playout or should have. Reported because a shed frame
        # leaves no gap, so nothing else shows it: a 1960 s call once shed a
        # third of its audio while every other counter read healthy.
        shed = None
        if counts.shed and (played + gaps + counts.shed):
            shed = float(counts.shed) / float(played + gaps + counts.shed)

        # If NOTHING could be read, say nothing.
        #
        # Every field above degrades on its own, which is right for one
        # missing counter and wrong for a session that has been torn down or
        # was never a session: those produce "0s, mouth-to-ear not measured
        # (call too short)", which is a sentence full of figures that were
        # never measured.  The docstring's own warning applies to this
        # function as much as to a caller who reads it too late.
        if not timed and m2e is None and delivery is None and not sent:
            return ["[voice] call ended"]

        # The verdict. Delay and loss both have to be acceptable: a call with
        # no delay that lost a fifth of its audio was not a good call, and
        # neither was a perfectly delivered one two seconds behind.
        bands = []
        if m2e is not None:
            bands.append(latency_band(m2e))
        if delivery is not None:
            bands.append("good" if delivery >= self.CALL_GOOD_DELIVERY
                         else "bad")
        if shed is not None:
            bands.append("good" if shed <= self.CALL_MAX_SHED else "bad")
        if not bands:
            mark, verdict = "•", "call ended"
        elif "bad" in bands:
            mark, verdict = "🔴", "call ended — quality was poor"
        elif "warn" in bands:
            mark, verdict = "🟡", "call ended — workable"
        else:
            mark, verdict = "🟢", "call ended — good"

        parts = [duration]
        if m2e is not None:
            parts.append("mouth-to-ear ~%s" % colour_latency(m2e))
        else:
            # Say why rather than printing a dash. On a short call the probes
            # have not completed and that is not a fault.
            parts.append("mouth-to-ear not measured"
                         + (" (call too short)" if secs < 10 else ""))
        if delivery is not None:
            # COUNTS, not a percentage. "0.0% of audio delivered" was printed
            # to somebody who had just finished a working 41-minute
            # conversation, because a rekey had added 2**62 to the gap
            # counter (fixed in JitterBuffer.pop). Even uncorrupted the
            # phrasing invites the reading "zero audio was received", which
            # is not what the ratio ever meant.
            parts.append(_mediapath.delivery_line(_mediapath.MediaCounters(
                played=played, gaps=gaps, shed=counts.shed,
                reordered=counts.reordered, late=counts.late,
                dropped_tx=counts.dropped_tx, dropped_rx=counts.dropped_rx)))

        if sent:
            parts.append("%d frames sent" % sent)

        lines = ["[voice] %s %s — %s" % (mark, verdict, ", ".join(parts))]
        budget = self._budget_line(session, m2e)
        if budget:
            lines.append(budget)
        return lines

    def _budget_line(self, session, m2e):
        """Where the mouth-to-ear delay went: network, buffer, playout.

        The single most useful line in a latency investigation, and until now
        it existed only inside `--voice-debug`.  Without it "914 ms" invites
        the assumption that the cryptography is expensive; with it, the
        v10.15.1 soak's answer is visible on every call -- sealing and
        opening together cost half a millisecond of an 855 ms budget, and
        the network is two thirds of it.

        Only the two parts this client can do anything about are separated
        out.  The network figure is two three-hop I2P tunnels, one each way,
        and is not ours; the buffer and the playout path are.
        """
        try:
            if m2e is None:
                return None
            oneway = float(session.latency.oneway_ms or 0.0)
            dwell = float(session.jitter.dwell.percentile(0.50))
            playout = (float(session.stages.t["decode"].percentile(0.50))
                       + float(session.stages.t["play"].percentile(0.50)))
            if oneway <= 0:
                return None
            # The hop note is NOT a literal any more. `(6 I2P hops)` was
            # typed into this string by somebody describing the architecture
            # from memory, at a time when the client sent no tunnel-length
            # option at all -- so it had never asked the router how many hops
            # it was using, and "6 hops" reads as one six-hop path rather than
            # two three-hop ones, a different and worse anonymity story than
            # the architecture actually has. SESSION CREATE now carries the
            # request, and the note reports it as a request.
            line = ("[voice]   %.0fms network (%s) + %.0fms jitter "
                    "buffer + %.0fms playout"
                    % (oneway, _mediapath.hop_note(), dwell, playout))
            learned = getattr(session.jitter, "learned_frames", 0)
            if learned:
                line += ("; buffer holding %d extra frame(s) after "
                         "underruns" % learned)
            return line
        except Exception:
            return None

    async def reject_call(self, peer: str) -> None:
        peer = self._bare(peer)
        self._stop_ringing(peer)
        session = self._calls.pop(peer, None)
        self._cancel_timeout(peer)
        if session is None:
            _print("[voice] no incoming call to reject")
            return
        self._signal(peer, "REJECT", (session.call_id.hex(), "declined"))
        await session.end()
        _print("[voice] call rejected")

    def toggle_mute(self, peer: str) -> None:
        session = self._calls.get(self._bare(peer))
        if session is not None and session.state == CallState.ACTIVE:
            _print("[voice] microphone %s"
                   % ("MUTED" if session.toggle_mute() else "live"))
        else:
            _print("[voice] no active call")

    def _stop_lag_monitor(self) -> None:
        """Cancel the loop-lag monitor. Idempotent."""
        task = self._lag_task
        self._lag_task = None
        if task is not None and not task.done():
            try:
                task.cancel()
            except Exception:
                pass

    async def cleanup(self) -> None:
        """End every call gracefully and destroy every media key."""
        self._stop_lag_monitor()
        try:
            self._call_control.shutdown()
        except Exception:
            pass
        for peer in list(self._calls.keys()):
            try:
                await self.end_call(peer, notify_peer=True)
            except Exception:
                session = self._calls.pop(peer, None)
                if session is not None:
                    session.force_close_sync()

    def cleanup_sync(self) -> int:
        """Synchronous teardown for paths with no usable event loop."""
        self._stop_lag_monitor()
        for peer in list(self._ringers):
            self._stop_ringing(peer)
        try:
            self._call_control.shutdown()
        except Exception:
            pass
        count = 0
        for peer in list(self._calls.keys()):
            session = self._calls.pop(peer, None)
            self._cancel_timeout(peer)
            if session is None:
                continue
            try:
                session.force_close_sync()
                count += 1
            except Exception:
                pass
        return count


# ---------------------------------------------------------------------------
# SMP verification
# ---------------------------------------------------------------------------

def _smp_query_default(manager, peer):
    """Ask the OTR engine whether SMP has cryptographically verified a peer.

    Returns (verified, state_name).  The boolean is authoritative and comes
    only from the engine's published predicates.  state_name is best-effort
    and is used for display only — no decision anywhere in this module is
    taken on the strength of it.

    Earlier revisions inferred verification from the state NAME, treating
    "STATE_UPDATED" and anything containing "COMPLETE" as success.
    STATE_UPDATED is a generic state-change notification, and SMP completes
    on failure as readily as on success, so both readings could report an
    unverified — or actively failed — session as verified.
    """
    if manager is None or not peer:
        return False, ""

    verified = False
    state = ""

    try:
        if manager.is_smp_verified(peer):
            verified = True
    except Exception:
        pass

    try:
        status = manager.get_smp_status(peer)
        if isinstance(status, dict):
            if status.get("verified") is True:
                verified = True
            raw = status.get("state")
            if raw:
                state = str(getattr(raw, "name", raw)).upper().strip()
    except Exception:
        pass

    if not verified:
        try:
            session = manager.get_session(peer)
            checker = getattr(session, "is_smp_verified", None)
            if callable(checker) and checker() is True:
                verified = True
        except Exception:
            pass

    return verified, state


__all__ = [
    "bind_host", "kem_provider", "set_kem_provider_for_testing",
    "KemUnavailable", "VoiceKeyExchange", "VoiceFrameCrypto",
    "VoiceKeySchedule", "VoiceCallSession", "VoiceCallManager",
    "CallState", "IllegalTransition", "ReplayWindow", "JitterBuffer",
    "RateLimiter", "FrameError", "SignalError", "parse_signal",
    "build_transcript", "derive_voice_root", "derive_rekey_root",
    "derive_confirmations",
    "pack_media_header", "parse_media_header", "media_aad", "media_nonce",
    "pad_opus", "unpad_opus", "sorted_fingerprints", "normalise_fingerprint",
    "CALL_PREFIX", "DIR_INITIATOR", "DIR_RESPONDER",
    "VOICE_PROTOCOL_VERSION", "VOICE_HDR_LEN", "VOICE_SEALED_LEN",
    "VOICE_PACKET_LEN", "VOICE_PLAIN_LEN", "VOICE_OPUS_SLOT",
    "MLKEM_EK_LEN", "MLKEM_CT_LEN", "MLKEM_SS_LEN", "ROOT_LEN",
    "CONFIRM_LEN", "_smp_query_default",
]
