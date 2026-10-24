# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Termux: group files and the "remove hidden information?" question.

The question (owner request, 2026-10-11): a file that carries metadata is
not sent until the user answers -- y removes it, n keeps it and sends the
original, c sends nothing. A file with nothing to remove is sent without a
question; a kind that cannot be checked is sent and said so. The same in
1:1 and in groups, and the app asks the same thing (MetadataChoice.kt).
"""
import os
import shutil
import struct
import sys
import tempfile
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

pytest.importorskip("otrv4_core")
pytest.importorskip("slixmpp")

import otrv4plus_groups as OG  # noqa: E402
import otrv4plus_xmpp as X  # noqa: E402
from android_bridge.events import FileTransferChanged  # noqa: E402

ROOM = "mls@conference.x.i2p"


@pytest.fixture
def tmp():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _jpeg_with_gps():
    exif = b"Exif\x00\x00" + b"MM\x00\x2a" + b"GPS-LOCATION" * 4
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif
    return b"\xff\xd8" + app1 + b"\xff\xda\x00\x02" + b"\x11" * 32 + b"\xff\xd9"


def _client():
    c = types.SimpleNamespace(_metadata_question=None,
                              METADATA_QUESTION_SECONDS=600.0)
    c.confirm_metadata = lambda *a, **k: X.OTRv4PlusXMPP.confirm_metadata(c, *a, **k)
    c.answer = lambda line: X.OTRv4PlusXMPP._answer_metadata(c, line)
    return c


class TestTheMetadataQuestion:

    def _photo(self, tmp):
        p = os.path.join(tmp, "cam.jpg")
        with open(p, "wb") as fh:
            fh.write(_jpeg_with_gps())
        return p

    @pytest.mark.parametrize("answer,strip", [("y", True), ("yes", True),
                                              ("n", False), ("NO", False)])
    def test_y_removes_n_keeps(self, tmp, capsys, answer, strip):
        c, chose = _client(), []
        c.confirm_metadata(self._photo(tmp), chose.append)
        out = capsys.readouterr().out
        assert "hidden information" in out and "[y/n/c]" in out
        assert chose == []                         # nothing until answered
        assert c.answer(answer) is True
        assert chose == [strip]

    def test_c_sends_nothing_and_discards(self, tmp):
        c, chose, gone = _client(), [], []
        c.confirm_metadata(self._photo(tmp), chose.append, on_cancel=lambda: gone.append(1))
        assert c.answer("c") is True
        assert chose == [] and gone == [1]

    def test_other_text_is_not_an_answer(self, tmp):
        c, chose = _client(), []
        c.confirm_metadata(self._photo(tmp), chose.append)
        assert c.answer("hello there") is False
        assert chose == [] and c._metadata_question is not None

    def test_nothing_to_remove_is_not_asked(self, tmp, capsys):
        p = os.path.join(tmp, "clean.jpg")
        with open(p, "wb") as fh:
            fh.write(b"\xff\xd8\xff\xda\x00\x02" + b"\x11" * 32 + b"\xff\xd9")
        c, chose = _client(), []
        c.confirm_metadata(p, chose.append)
        assert chose == [False] and c._metadata_question is None

    def test_an_uncheckable_kind_is_sent_and_said(self, tmp, capsys):
        p = os.path.join(tmp, "notes.bin")
        with open(p, "wb") as fh:
            fh.write(os.urandom(64))
        c, chose = _client(), []
        c.confirm_metadata(p, chose.append)
        assert chose == [False]
        assert "cannot be checked" in capsys.readouterr().out

    def test_the_question_expires(self, tmp, monkeypatch):
        c, chose, gone = _client(), [], []
        c.confirm_metadata(self._photo(tmp), chose.append, on_cancel=lambda: gone.append(1))
        on_choice, on_cancel, at = c._metadata_question
        c._metadata_question = (on_choice, on_cancel, at - 601)
        assert c.answer("y") is False
        assert chose == [] and gone == [1]

    def test_it_is_answered_before_any_other_y_n(self):
        src = open(X.__file__, encoding="utf-8").read()
        line = src.index("answer_metadata(line):")
        assert line < src.index("consent_for = self._pending_consent_peer()")
        assert line < src.index("groups.answer_prompt(line)")


class _Files:
    def __init__(self):
        self.rows, self.done = [], []

    def transfers(self):
        return list(self.rows)

    def accept(self, tid):
        self.done.append(("accept", tid))
        return True

    def decline(self, tid):
        self.done.append(("decline", tid))
        return True

    def close(self):
        pass


def _termux():
    class Core:
        RustMlsClient = object
    printed = []
    g = OG.TermuxGroups(type("H", (), {})(), None, printer=printed.append, core=Core())
    g._opened = True
    g.files = _Files()
    return g, printed


class TestGroupFilesInTheTerminal:

    def _offer(self, g, tid="ab" * 16):
        g.files.rows = [{"id": tid, "peer": ROOM, "from": "bob@x.i2p",
                         "filename": "cat.jpg", "size": 2048, "state": "offered",
                         "outgoing": False, "progress": 0.0, "path": ""}]
        g._on_event(FileTransferChanged(peer=ROOM, transfer_id=tid, filename="cat.jpg",
                                        size=2048, outgoing=False, state="offered"))
        return tid

    @pytest.mark.parametrize("word,action", [("y", "accept"), ("n", "decline")])
    def test_an_offer_is_answered_with_y_or_n(self, word, action):
        g, printed = _termux()
        tid = self._offer(g)
        assert any("bob@x.i2p offers cat.jpg" in line and "[y/n]" in line
                   for line in printed)
        assert g.answer_prompt(word) is True
        assert g.files.done == [(action, tid)]

    def test_a_finished_offer_is_no_longer_answered(self):
        g, printed = _termux()
        self._offer(g)
        g.files.rows[0]["state"] = "cancelled"
        assert g.answer_prompt("y") is False
        assert g.files.done == []

    def test_a_received_file_says_where_and_that_it_was_checked(self):
        g, printed = _termux()
        tid = "cd" * 16
        g.files.rows = [{"id": tid, "peer": ROOM, "from": "bob@x.i2p",
                         "filename": "cat.jpg", "size": 2048, "state": "received",
                         "outgoing": False, "progress": 1.0, "path": "/p/cat.jpg"}]
        g._on_event(FileTransferChanged(peer=ROOM, transfer_id=tid, filename="cat.jpg",
                                        size=2048, outgoing=False, state="received"))
        assert any("received cat.jpg from bob@x.i2p" in l and "SHA-256 verified" in l
                   and "/p/cat.jpg" in l for l in printed)

    def test_refusals_are_explained(self):
        g, printed = _termux()
        g.files = types.SimpleNamespace(send=lambda room, path, strip: "unverified")
        assert g.send_file(ROOM, "/x/cat.jpg", False) == "unverified"
        assert any("must be verified" in l for l in printed)

    def test_pieces_go_with_the_no_store_hint(self):
        sent = []

        class Msg:
            def __init__(self):
                self.extra = []

            def append(self, el):
                self.extra.append(el.tag)

            def send(self):
                sent.append(self.extra)

        class Host:
            loop = None

            def make_message(self, mto, mbody, mtype):
                assert mtype == "groupchat"
                return Msg()

        g = OG.TermuxGroups.__new__(OG.TermuxGroups)
        g.host = Host()
        g._send_room_volatile(ROOM, "piece")
        assert sent == [["{urn:xmpp:hints}no-store"]]


class TestAudiotestOnLinux:
    """/audiotest used to refuse anywhere but Termux ("self-test is
    Termux-only"), so a laptop with no call audio had no way to check
    itself. It now plays a tone and records 3 s on Linux too."""

    def test_it_runs_off_termux_and_tests_both_directions(self, monkeypatch, capsys):
        import asyncio
        import otrv4plus_audio as A

        written = []

        class Out:
            name = "pulseaudio"

            def write_frame(self, pcm, timeout_ms=200):
                written.append(len(pcm))
                return True

            def stop(self):
                pass

        class In:
            name = "pulseaudio"

            def read_frame(self, timeout_ms=200):
                return struct.pack("<4h", 0, 300, -300, 5)

            def stop(self):
                pass

        monkeypatch.setattr(X._host, "IS_TERMUX", False)
        monkeypatch.setattr(A, "open_playback", lambda **k: (Out(), []))
        monkeypatch.setattr(A, "open_capture", lambda **k: (In(), []))
        monkeypatch.setattr(X._termux, "_capture_selftest",
                            lambda seconds=3.0: (True, 8, 300, "pulseaudio"))
        asyncio.run(X._termux._audio_selftest_async(X.voice_available))
        out = capsys.readouterr().out
        assert "Termux-only" not in out
        assert "speaker: tone sent via pulseaudio" in out
        assert "OK" in out and "peak amplitude 300" in out
        assert written and all(n == A.FRAME_SAMPLES * 2 for n in written)


class TestARoomThatTimesOutIsTriedAgain:
    """"could not rejoin the room (TimeoutError)" used to be the end of it:
    the group stayed syncing, holding what was typed, until a restart."""

    def test_retried_then_back(self):
        import asyncio

        g, printed = _termux()
        later = []

        class Loop:
            def call_later(self, delay, fn):
                later.append((delay, fn))

        g.host.loop = Loop()
        g.groups.rooms = lambda: [ROOM]
        tries = []

        async def join(room, create, rejoin):
            tries.append(room)
            if len(tries) == 1:
                raise asyncio.TimeoutError()
            return False

        rejoined = []
        g._join = join
        g.groups.on_room_rejoined = rejoined.append

        async def go():
            await g._rejoin_one(ROOM, attempt=0)
            assert later and later[0][0] == g.REJOIN_RETRY_SECONDS[0]
            assert any("trying again in 30 s" in l for l in printed)
            await g._rejoin_one(ROOM, attempt=1)       # what the timer runs
        asyncio.run(go())
        assert rejoined == [ROOM]
        assert any("back in the room" in l for l in printed)

    def test_gives_up_after_the_last_try_and_says_so(self):
        import asyncio

        g, printed = _termux()
        g.host.loop = None
        g.groups.rooms = lambda: [ROOM]

        async def join(room, create, rejoin):
            raise asyncio.TimeoutError()
        g._join = join
        asyncio.run(g._rejoin_one(ROOM, attempt=len(g.REJOIN_RETRY_SECONDS)))
        assert any("after %d tries" % (len(g.REJOIN_RETRY_SECONDS) + 1) in l
                   for l in printed)
