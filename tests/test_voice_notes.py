# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice notes: the mask is mandatory, the raw recording never survives,
the file carries nothing but audio, and received notes are parsed as the
untrusted input they are."""
from __future__ import annotations

import math
import os
import random
import stat
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "voice_mask"):
    pytest.skip("otrv4_core built without the voice mask", allow_module_level=True)

import otrv4plus_voicenote as vn                                    # noqa: E402


def speech(seconds=2.0, f0=130.0, rate=16000):
    """A crude voiced 'speaker': a pulse train through two resonators, in
    syllable-like bursts."""
    n = int(seconds * rate)
    x = [0.0] * n
    period = rate / f0
    nxt = 0.0
    for i in range(n):
        if i >= nxt:
            x[i] = 1.0
            nxt += period
    for f in (650.0, 1500.0):
        r, th = 0.97, 2 * math.pi * f / rate
        a1, a2 = -2 * r * math.cos(th), r * r
        y1 = y2 = 0.0
        for i in range(n):
            y = x[i] - a1 * y1 - a2 * y2
            y2, y1 = y1, y
            x[i] = y
    peak = max(abs(v) for v in x) or 1.0
    out = bytearray()
    for i, v in enumerate(x):
        on = ((i / rate) * 4) % 1.0 < 0.7
        out += struct.pack("<h", int(v / peak * 12000 * on))
    return bytes(out)


def test_every_note_is_masked_differently_and_stays_speech_length():
    pcm = speech()
    a = vn.mask(pcm, 16000, "synthetic")
    b = vn.mask(pcm, 16000, "synthetic")
    assert a != b
    for out in (a, b):
        assert 1.0 < len(out) / 2 / vn.RATE < 3.0


def test_no_mask_means_no_note(monkeypatch):
    """A build without the mask refuses; it never sends the real voice."""
    monkeypatch.setattr(vn, "_core", lambda: None)
    with pytest.raises(vn.VoiceNoteError) as e:
        vn.mask(speech(), 16000, "synthetic")
    assert e.value.code == "unavailable"
    pcm = bytearray(speech())
    with pytest.raises(vn.VoiceNoteError):
        vn.make_note(pcm, 16000, "synthetic", tempfile.mkdtemp())
    assert not any(pcm), "the raw recording must be wiped even on failure"


def test_bad_mode_short_and_silent_notes():
    with pytest.raises(vn.VoiceNoteError) as e:
        vn.mask(speech(), 16000, "loud")
    assert e.value.code == "bad_mode"
    with pytest.raises(vn.VoiceNoteError) as e:
        vn.mask(b"\x00\x00" * 4000, 16000, "synthetic")
    assert e.value.code == "too_short"
    with pytest.raises(vn.VoiceNoteError) as e:
        vn.mask(b"\x00\x00" * 32000, 16000, "synthetic")
    assert e.value.code == "no_speech"


def test_a_note_file_is_private_random_and_wipes_the_recording():
    d = tempfile.mkdtemp()
    pcm = bytearray(speech())
    note = vn.make_note(pcm, 16000, "synthetic", d)
    assert not any(pcm)
    path = note["path"]
    assert os.path.dirname(path) == d
    assert os.path.basename(path).startswith("voice-note-")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert note["mode"] == "synthetic" and note["seconds"] > 1.0
    other = vn.make_note(bytearray(speech()), 16000, "synthetic", d)
    assert other["path"] != path


def _ogg_pages(data):
    pages, pos = [], 0
    while pos < len(data):
        assert data[pos:pos + 4] == b"OggS"
        nseg = data[pos + 26]
        size = sum(data[pos + 27:pos + 27 + nseg])
        end = pos + 27 + nseg + size
        pages.append(data[pos:end])
        pos = end
    return pages


@pytest.mark.skipif(vn._opus_encoder() is None, reason="no Opus encoder in this build")
def test_ogg_opus_round_trip_and_nothing_but_audio():
    pcm = vn.mask(speech(3.0), 16000, "synthetic")
    data, ext = vn.encode(pcm)
    assert ext == "ogg" and data[:4] == b"OggS"
    pages = _ogg_pages(data)
    for page in pages:                                   # every CRC is right
        blank = bytearray(page)
        blank[22:26] = b"\x00\x00\x00\x00"
        assert struct.unpack_from("<I", page, 22)[0] == vn._ogg_crc(bytes(blank))
    tags = pages[1][27 + pages[1][26]:]
    assert tags == b"OpusTags" + struct.pack("<I", len(vn.VENDOR)) + vn.VENDOR + b"\x00" * 4
    assert pages[-1][5] & 0x04                           # end of stream
    back, rate = vn.decode(data)
    assert rate == vn.RATE
    assert abs(len(back) - len(pcm)) <= vn.FRAME * 2
    assert len(data) < len(pcm) / 4                      # it is compressed


def test_wav_round_trip():
    pcm = vn.mask(speech(), 16000, "natural")
    data, ext = vn.encode(pcm, prefer_opus=False)
    assert ext == "wav"
    back, rate = vn.decode(data)
    assert (back, rate) == (pcm, vn.RATE)


def test_received_notes_are_untrusted():
    rnd = random.Random(5)
    good = vn.encode(vn.mask(speech(), 16000, "synthetic"))[0]
    samples = [b"", b"OggS", b"RIFF" + b"\x00" * 40, b"x" * 100,
               good[:50], good[:-7], good.replace(b"OpusHead", b"OpusHexd")]
    for _ in range(60):
        bad = bytearray(good)
        for _ in range(rnd.randint(1, 20)):
            bad[rnd.randrange(len(bad))] = rnd.randrange(256)
        samples.append(bytes(bad))
    for data in samples:
        try:
            vn.decode(data)
        except vn.VoiceNoteError:
            pass
    with pytest.raises(vn.VoiceNoteError):
        vn.decode(b"OggS" + b"\x00" * (vn.MAX_NOTE_BYTES + 1))


class FakeCapture:
    def __init__(self, frames):
        self.frames = list(frames)
        self.stopped = False

    def read_frame(self, timeout_ms=200):
        return self.frames.pop(0) if self.frames else None

    def stop(self):
        self.stopped = True


def test_recorder_keeps_audio_in_memory_and_cancel_wipes_it():
    pcm = speech(1.0, rate=24000)
    frames = [pcm[i:i + 1920] for i in range(0, len(pcm), 1920)]
    cap = FakeCapture(frames)
    rec = vn.Recorder(open_capture=lambda: (cap, []))
    rec.start()
    for _ in range(100):
        if not cap.frames:
            break
        import time
        time.sleep(0.01)
    got, rate = rec.stop()
    assert rate == 24000 and bytes(got) == pcm and cap.stopped
    cap2 = FakeCapture(frames)
    rec2 = vn.Recorder(open_capture=lambda: (cap2, []))
    rec2.start()
    rec2.cancel()
    assert rec2.seconds == 0.0


def test_recorder_without_a_microphone():
    def broken():
        raise OSError("no device")
    with pytest.raises(vn.VoiceNoteError) as e:
        vn.Recorder(open_capture=broken).start()
    assert e.value.code == "no_microphone"


def test_the_app_and_desktop_host_expose_the_same_operations():
    from android_bridge.app import OtrApp
    from desktop_bridge.host import APP_OPS
    ops = [op for op in APP_OPS if op.startswith("voice_note_")]
    assert len(ops) == 10
    for op in ops:
        assert callable(getattr(OtrApp, op))


def test_the_app_makes_a_note_and_never_leaves_the_recording(monkeypatch):
    from android_bridge.app import OtrApp
    app = OtrApp.__new__(OtrApp)
    app._wiped = False
    pcm = speech(1.5, rate=24000)
    frames = [pcm[i:i + 1920] for i in range(0, len(pcm), 1920)]
    cap = FakeCapture(frames)
    app._voice_recorder = vn.Recorder(open_capture=lambda: (cap, []))
    assert app.voice_note_start() == "ok"
    import time
    for _ in range(200):
        if not cap.frames:
            break
        time.sleep(0.01)
    d = tempfile.mkdtemp()
    note = app.voice_note_stop("synthetic", d)
    assert "error" not in note, note
    assert os.path.isfile(note["path"])
    app.voice_note_discard(note["path"])
    assert not os.path.exists(note["path"])
    # Only voice notes can be deleted this way.
    keep = os.path.join(d, "keep.txt")
    open(keep, "w").close()
    app.voice_note_discard(keep)
    assert os.path.exists(keep)
    # A stop with nothing recorded is an error, not a crash.
    assert app.voice_note_stop("synthetic", d).get("error") == "too_short"


def test_modes_are_described_for_the_ui():
    from android_bridge.app import OtrApp
    app = OtrApp.__new__(OtrApp)
    info = app.voice_note_modes()
    assert info["default"] == "synthetic" and info["mask_available"]
    assert set(info["labels"]) == set(vn.MODES)


def test_terminal_voice_command_records_masks_and_cleans_up(capsys, monkeypatch):
    pytest.importorskip("slixmpp")
    import otrv4plus_xmpp as X
    from xmpp_double import bare_client
    c = bare_client(X.OTRv4PlusXMPP)
    pcm = speech(1.5, rate=24000)
    frames = [pcm[i:i + 1920] for i in range(0, len(pcm), 1920)]
    cap = FakeCapture(frames)
    real = vn.Recorder
    monkeypatch.setattr(vn, "Recorder", lambda: real(open_capture=lambda: (cap, [])))
    d = tempfile.mkdtemp()
    monkeypatch.setattr(X._filetransfer, "staging_dir", lambda: d)
    c._cmd_voice("bob@x", "synthetic")
    assert "recording" in capsys.readouterr().out
    import time
    for _ in range(200):
        if not cap.frames:
            break
        time.sleep(0.01)
    c._cmd_voice("bob@x", "")
    out = capsys.readouterr().out
    assert "note ready" in out and "Synthetic" in out
    path = c._vn_note["path"]
    assert os.path.isfile(path)
    c._cmd_voice("bob@x", "cancel")
    assert not os.path.exists(path) and c._vn_note is None
    c._cmd_voice("bob@x", "send")
    assert "record one first" in capsys.readouterr().out


def test_a_note_is_never_cut_down_to_a_fragment():
    """1 note in 200 came out at a third of its length (or as "no speech"):
    trim measured against one spike from the warped filter. Rust now measures
    against the 95th percentile of frame levels."""
    pcm = speech()
    for mode in ("synthetic",):
        for _ in range(60):
            assert len(vn.mask(pcm, 16000, mode)) / 2 / vn.RATE > 1.2


def test_no_caller_can_choose_the_settings():
    """Owner (2026-10-15): "true random entropy". The settings come only from
    the OS generator inside Rust: the Python API has no seed to pass."""
    import otrv4_core
    pcm = speech()
    with pytest.raises(TypeError):
        otrv4_core.voice_mask(pcm, 16000, "synthetic", b"\x00" * 32)
    with pytest.raises(TypeError):
        otrv4_core.voice_mask(pcm, 16000, "synthetic", seed=b"\x00" * 32)
    # Two notes from the same recording never come out the same.
    assert otrv4_core.voice_mask(pcm, 16000, "synthetic") != otrv4_core.voice_mask(pcm, 16000, "synthetic")


def test_disguise_is_gone():
    """Owner (2026-10-16): Disguised was hard to understand; Synthetic only.
    Neither the note pipeline nor the Rust core accepts it any more."""
    import otrv4_core
    assert "disguise" not in vn.MODES
    with pytest.raises(vn.VoiceNoteError):
        vn.mask(speech(), 16000, "disguise")
    with pytest.raises(ValueError):
        otrv4_core.voice_mask(speech(), 16000, "disguise")
