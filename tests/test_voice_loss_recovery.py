# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Less audio lost on an I2P call (owner, 2026-11-11: "minimise the audio
loss"). Device reports that day: 8-12% of frames missing at playout, and
~500 frames shed by the jitter buffer in an 8-minute call.

  * the sender marks each frame SPEECH or SILENCE, in padding it always sent,
    inside the AEAD -- nothing on the wire changes;
  * the buffer sheds SILENCE first (a shorter pause) and speech only past a
    hard excess; frames from a sender without the mark are shed as before;
  * each PONG carries the receiver's measured loss, in padding a PONG always
    had, and the sender sets its Opus FEC to it.
"""
import math
import os
import struct
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))

import otrv4plus_voice as V                 # noqa: E402
import otrv4plus_voice_jitter as J          # noqa: E402


# -- the frame-kind byte ---------------------------------------------------

def test_the_kind_rides_in_the_padding_and_the_frame_is_the_same_size():
    opus = os.urandom(180)
    for kind in (J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE):
        plain = J.pad_opus(opus, 1234, kind)
        assert len(plain) == V.VOICE_PLAIN_LEN
        assert J.frame_kind(plain) == kind
        assert J.unpad_frame(plain) == (opus, 1234)       # unchanged for old readers


def test_a_frame_from_an_older_sender_is_unknown():
    plain = J.pad_opus(os.urandom(180), 1)               # no kind: zero padding
    assert plain[-1] == 0
    assert J.frame_kind(plain) == J.FRAME_KIND_UNKNOWN


def test_a_full_slot_has_no_room_and_reads_unknown():
    plain = J.pad_opus(os.urandom(V.VOICE_OPUS_SLOT), 1, J.FRAME_KIND_SPEECH)
    assert len(plain) == V.VOICE_PLAIN_LEN
    assert J.frame_kind(plain) == J.FRAME_KIND_UNKNOWN


def test_garbage_in_the_kind_byte_is_unknown():
    plain = bytearray(J.pad_opus(os.urandom(180), 1))
    plain[-1] = 0x7F
    assert J.frame_kind(bytes(plain)) == J.FRAME_KIND_UNKNOWN


# -- shedding: silence first -----------------------------------------------

def _buffer_with(kinds, **kw):
    jb = J.JitterBuffer(adaptive=False, prefill=2, drift_high=3, shed_margin=1,
                        drain_ms=60, **kw)
    for n, kind in enumerate(kinds):
        assert jb.push(0, n, bytearray(b"%d" % n), kind)
    return jb


def _drain(jb):
    out = []
    while True:
        item = jb.pop()
        if item is None:
            return out
        out.append((bytes(item[0]), item[1]))


def test_a_deep_buffer_shortens_a_pause_and_keeps_every_word():
    S, Q = J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE
    kinds = [S, S, S, Q, Q, Q, Q, S, S, S]
    jb = _buffer_with(kinds)
    played = _drain(jb)
    names = [p for p, _gap in played]
    for n, kind in enumerate(kinds):
        if kind == S:
            assert b"%d" % n in names, "speech frame %d was shed" % n
    assert jb.stats["shed_speech"] == 0 and jb.stats["shed_silence"] > 0
    # A shortened pause is not a hole: nothing concealed, nothing missing.
    assert all(gap == 0 for _p, gap in played)
    assert jb.stats["gaps"] == 0


def test_speech_is_shed_only_past_the_hard_excess():
    S = J.FRAME_KIND_SPEECH
    small = _buffer_with([S] * 8)                 # excess below the line
    _drain(small)
    assert small.stats["shed_speech"] == 0
    big = _buffer_with([S] * (8 + J.SPEECH_SHED_EXCESS + 6))
    big.pop()
    assert big.stats["shed_speech"] > 0, "a runaway backlog must still come down"


def test_frames_without_a_kind_are_shed_as_before():
    jb = _buffer_with([J.FRAME_KIND_UNKNOWN] * 10)
    _drain(jb)
    assert jb.stats["drift"] > 0
    assert jb.stats["shed_speech"] == 0 and jb.stats["shed_silence"] == 0


def test_a_late_copy_of_a_shed_frame_is_a_duplicate_not_a_new_frame():
    S, Q = J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE
    jb = _buffer_with([S, S, Q, Q, Q, Q, S, S, S, S])
    jb.pop()
    shed = sorted(jb._shed_seqs)
    if shed:
        assert not jb.push(0, shed[0], bytearray(b"again"), Q)
        assert jb.stats["duplicate"] >= 1


def test_holes_are_counted_by_length():
    jb = J.JitterBuffer(adaptive=False, prefill=1, drift_high=50, shed_margin=40)
    for n in (0, 2, 5, 10):                     # holes of 1, 2 and 4 frames
        jb.push(0, n, bytearray(b"x"), J.FRAME_KIND_SPEECH)
    _drain(jb)
    assert (jb.stats["gap1"], jb.stats["gap2_3"], jb.stats["gap4"]) == (1, 1, 1)
    assert jb.stats["gaps"] == 1 + 2 + 4


# -- the loss report and the FEC it sets -----------------------------------

def test_a_pong_carries_the_loss_and_the_pinger_reads_it():
    a, b = J.LatencyTracker(), J.LatencyTracker()
    _pid, ping = a.build_ping()
    pong = b.build_pong_stamped(ping, 87)
    padded = pong + b"\x00" * (V.VOICE_PLAIN_LEN - len(pong))
    assert a.handle_pong(padded)
    assert a.peer_loss_permille == 87


def test_a_pong_from_an_older_peer_reports_nothing_and_still_counts():
    a, b = J.LatencyTracker(), J.LatencyTracker()
    _pid, ping = a.build_ping()
    old = b.build_pong_stamped(ping)            # no report: 32 bytes
    assert len(old) == 32
    assert a.handle_pong(old + b"\x00" * (V.VOICE_PLAIN_LEN - 32))
    assert a.peer_loss_permille is None


def test_an_older_reader_sees_the_same_32_bytes():
    b = J.LatencyTracker()
    ping = struct.pack(">QQ", 7, 99)
    assert b.build_pong_stamped(ping, 50)[:32][:16] == struct.pack(">QQ", 7, 99)


def test_fec_follows_the_measured_loss_within_bounds():
    assert V.fec_pct_for_loss(0) == V.VOICE_FEC_MIN_PCT
    assert V.fec_pct_for_loss(80) == 10          # 8% missing -> 10%
    assert V.fec_pct_for_loss(120) == 15
    assert V.fec_pct_for_loss(1000) == V.VOICE_FEC_MAX_PCT
    assert V.VOICE_FEC_MIN_PCT <= V.VOICE_LOSS_PCT <= V.VOICE_FEC_MAX_PCT


def test_the_capture_thread_applies_the_new_level_to_the_encoder():
    s = object.__new__(V.VoiceCallSession)
    s.stats = V.new_media_stats()
    s._fec_wanted, s._fec_applied = 18, V.VOICE_LOSS_PCT
    s._opus_enc = types.SimpleNamespace(packet_loss_perc=V.VOICE_LOSS_PCT)
    s._apply_fec()
    assert s._opus_enc.packet_loss_perc == 18 and s.stats["fec_pct"] == 18
    s._opus_enc.packet_loss_perc = -1
    s._apply_fec()                               # unchanged: no CTL call
    assert s._opus_enc.packet_loss_perc == -1


def test_the_reported_loss_is_what_was_missing_at_playout_since_last_time():
    s = object.__new__(V.VoiceCallSession)
    s.jitter = types.SimpleNamespace(stats={"gaps": 0, "played": 0})
    s._loss_mark = (0, 0)
    assert s._rx_loss_permille() is None          # too few frames yet
    s.jitter.stats.update(gaps=9, played=91)
    assert s._rx_loss_permille() == 90
    s.jitter.stats.update(gaps=9, played=191)
    assert s._rx_loss_permille() == 0


# -- the speech detector ---------------------------------------------------

def _pcm(amplitude, n=1440):
    return struct.pack("<%dh" % n, *[int(amplitude * math.sin(i / 7.0)) for i in range(n)])


def test_quiet_is_silence_after_the_hangover_and_speech_is_speech():
    d = V.SpeechDetector()
    quiet = _pcm(20)
    kinds = [d.kind(quiet) for _ in range(V.SpeechDetector.HANGOVER + 3)]
    assert kinds[-1] == J.FRAME_KIND_SILENCE
    assert d.kind(_pcm(4000)) == J.FRAME_KIND_SPEECH
    # The tail of a word is held as speech for the hangover.
    after = [d.kind(quiet) for _ in range(V.SpeechDetector.HANGOVER)]
    assert all(k == J.FRAME_KIND_SPEECH for k in after)
    assert d.kind(quiet) == J.FRAME_KIND_SILENCE


def test_the_detector_never_raises_on_odd_input():
    d = V.SpeechDetector()
    assert d.kind(b"") == J.FRAME_KIND_SILENCE
    assert d.kind(b"\x01\x02\x03") in (J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE)
    assert d.kind(object()) == J.FRAME_KIND_UNKNOWN


# -- rc.201: the cap chooses like the shedder, and every frame counts once --

def test_an_overflowing_burst_gives_up_a_pause_before_a_word():
    S, Q = J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE
    jb = J.JitterBuffer(adaptive=False, prefill=2, maxlen=6)
    kinds = [S, S, Q, S, S, S, S]               # one more than the cap
    for n, kind in enumerate(kinds):
        jb.push(0, n, bytearray(b"%d" % n), kind)
    assert jb.stats["overflow"] == 1
    assert jb.stats["shed_silence"] == 1 and jb.stats["shed_speech"] == 0
    played = [bytes(p) for p, _gap in iter(jb.pop, None)]
    assert b"2" not in played and all(b"%d" % n in played for n in (0, 1, 3, 4, 5, 6))


def test_an_overflowed_frame_is_not_also_a_hole():
    """Device report 2026-11-11 (rc.200): 10106 played + 1899 missing + 1426
    shed was 1,000 more than the 12370 frames the laptop sent, because a
    frame dropped at the cap was later counted as missing too."""
    jb = J.JitterBuffer(adaptive=False, prefill=1, maxlen=4, drift_high=50,
                        shed_margin=40)
    jb.push(0, 0, bytearray(b"x"), J.FRAME_KIND_SPEECH)
    jb.pop()
    for n in range(1, 8):                       # a burst of 7 into a cap of 4
        jb.push(0, n, bytearray(b"x"), J.FRAME_KIND_SPEECH)
    while jb.pop() is not None:
        pass
    s = jb.stats
    assert s["overflow"] == 3 and s["gaps"] == 0
    assert s["played"] + s["gaps"] + s["overflow"] + s["drift"] == 8


def test_played_missing_and_shed_add_up_to_what_was_sent():
    import random
    rnd = random.Random(7)
    jb = J.JitterBuffer(adaptive=False, prefill=2, maxlen=8, drift_high=4,
                        shed_margin=1, drain_ms=120)
    sent, n = 0, 0
    for _round in range(300):
        for _ in range(rnd.choice((0, 0, 1, 1, 1, 2, 6))):
            if rnd.random() > 0.05:             # 5% never arrive
                jb.push(0, n, bytearray(b"x"),
                        rnd.choice((J.FRAME_KIND_SPEECH, J.FRAME_KIND_SILENCE)))
            n += 1
        jb.pop()
    sent = n
    while jb.pop() is not None:
        pass
    s = jb.stats
    accounted = s["played"] + s["gaps"] + s["drift"] + s["overflow"]
    # Anything after the last frame played is unknown, not missing.
    tail = sent - 1 - jb._last_played
    assert accounted + tail == sent, s


def test_the_repair_line_reaches_the_report_with_its_counts():
    from android_bridge.voice import call_stage
    line = ("[voice] audio repair: 12 frames repaired by FEC; holes 1-frame 9, "
            "2-3 frames 4, longer 2; pauses shortened 300 frames, speech dropped 7; "
            "FEC at 15%; peer missed 3.1% of ours; ran dry 14 times, burst "
            "overflow 120 frames; audio route changed 1 times")
    code, _sev, reason = call_stage(line)
    assert code == "call_audio_repair"
    assert reason.startswith("audio repair: 12 frames") and reason.endswith("1 times")
    code, _sev, reason = call_stage("[voice] audio route changed — capture reopened")
    assert code == "audio_rerouted" and "capture" in reason


def test_the_repair_line_says_when_the_buffer_ran_dry_and_overflowed():
    s = object.__new__(V.VoiceCallSession)
    s.stats = V.new_media_stats()
    s.jitter = types.SimpleNamespace(stats={"gaps": 5, "drift": 0, "gap1": 5,
                                            "underrun": 3, "overflow": 40})
    line = V.VoiceCallManager._repair_line(s)
    assert "ran dry 3 times, burst overflow 40 frames" in line
