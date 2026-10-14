# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Files in a secure group (owner request, 2026-10-11), app and Termux alike.

Members are in-process with real MLS (test_secure_groups' World). What is
checked: a file reaches every member that accepts it, intact; nobody else
writes it; it is sent only when every other member is verified and refused
from an unverified sender; a lost piece is asked for again; a late member
gets the whole file; pieces never show as chat, never travel as plaintext,
and are posted with the room's no-store hint; metadata is removed only when
the user says so.
"""
import hashlib
import os
import pathlib
import shutil
import struct
import sys
import tempfile
import types
import zlib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core has no MLS", allow_module_level=True)

from android_bridge import group_files as G  # noqa: E402
from android_bridge.events import (ErrorOccurred, FileTransferChanged,  # noqa: E402
                                   RoomMessageReceived, SecurityState)

import test_secure_groups as T  # noqa: E402

ROOM = T.ROOM


@pytest.fixture
def tmp_path():
    """Our own: conftest stubs `pwd`, which pytest's tmp_path needs."""
    d = tempfile.mkdtemp()
    yield pathlib.Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def _private_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("OTRV4PLUS_FILE_DIR", str(tmp_path / "received"))
    yield


def _sharing(n=3, levels=None):
    w, members = T._group(n, levels=levels)
    now = [1000.0]
    volatile = []
    for m in members:
        m.files = G.GroupFiles(m.groups, emit=m.events.append,
                               clock=lambda: now[0], schedule=lambda d, f: None)

        def vol(room, body, jid=m.jid):
            volatile.append(body)
            w.room.post(jid, body)
        m.groups._pacer._send_volatile = vol
    return w, members, now, volatile


def _verify_all(members):
    for a in members:
        for b in members:
            if a is not b:
                a.groups._bound.setdefault(ROOM, {})[b.jid] = (
                    b.groups.own_fingerprint(ROOM), True)


def _file(tmp_path, size, name="photo.bin"):
    p = tmp_path / name
    p.write_bytes(os.urandom(size))
    return str(p)


def _offer(m):
    return [e for e in m.events if isinstance(e, FileTransferChanged)
            and not e.outgoing and e.state == "offered"][-1]


def _run(members, now, ticks=200):
    for _ in range(ticks):
        for m in members:
            m.files.tick()


def _received(m, tid):
    row = [r for r in m.files.transfers() if r["id"] == tid][0]
    return row


class TestAFileReachesTheGroup:

    def test_every_member_that_accepts_gets_it_intact(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        path = _file(tmp_path, 3 * G.CHUNK + 77)
        assert a.files.send(ROOM, path) == "started"
        tid = _offer(b).transfer_id
        assert _offer(c).transfer_id == tid
        assert b.files.accept(tid) and c.files.accept(tid)
        _run([a, b, c], now)
        want = hashlib.sha256(open(path, "rb").read()).digest()
        for m in (b, c):
            row = _received(m, tid)
            assert row["state"] == "received" and row["from"] == "alice@x.i2p"
            assert hashlib.sha256(open(row["path"], "rb").read()).digest() == want
            # (Both members share one directory here: the second is "photo (1)".)
            assert os.path.basename(row["path"]).startswith("photo")
        out = _received(a, tid)
        # Every other member confirmed it: finished now, not after the
        # 30-minute offer time (and the sender's copy is zeroed).
        assert out["state"] == "delivered" and out["delivered_to"] == 2
        assert tid not in a.files._out

    def test_until_every_member_has_it_the_sender_keeps_it(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, G.CHUNK + 5))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b, c], now)
        out = _received(a, tid)
        assert out["state"] == "sent" and out["delivered_to"] == 1
        assert tid in a.files._out          # c may still accept

    def test_an_expired_offer_tells_a_member_still_waiting(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, G.CHUNK + 5))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b, c], now)
        assert _received(c, tid)["state"] == "offered"
        now[0] += G.OFFER_SECONDS + 1
        a.files.tick()
        _run([a, b, c], now)
        row = _received(c, tid)
        assert (row["state"], row["reason"]) == ("cancelled", "expired")
        assert _received(b, tid)["state"] == "received"   # unaffected

    def test_a_repeated_accept_sends_nothing_again(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, 2 * G.CHUNK))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b, c], now)
        out = a.files._out[tid]
        a.files._on_control(ROOM, "bob@x.i2p", True, '{"t":"accept","id":"%s"}' % tid)
        assert out.resend == [] and out.state == "sent"

    def test_a_member_that_does_not_accept_writes_nothing(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, G.CHUNK + 1))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b, c], now)
        assert _received(c, tid)["state"] == "offered"
        assert _received(c, tid)["path"] == ""
        assert c.files.decline(tid)
        assert _received(c, tid)["state"] == "declined"

    def test_pieces_are_mls_ciphertext_never_chat_and_kept_out_of_history(self, tmp_path):
        w, (a, b), now, volatile = _sharing(2)
        _verify_all([a, b])
        marker = b"MARKER-must-not-leak" * 200
        path = tmp_path / "m.txt"
        path.write_bytes(marker)
        a.files.send(ROOM, str(path))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b], now)
        assert _received(b, tid)["state"] == "received"
        assert not any(isinstance(e, RoomMessageReceived) for m in (a, b) for e in m.events)
        for _s, body in w.room.log:
            assert b"MARKER" not in body.encode() and "photo" not in body
        # Every piece of data went with the no-store hint; the offer did not
        # need to (it is one small message).
        assert volatile
        assert all(body in [x for _s, x in w.room.log] for body in volatile)


class TestWhoMaySendAndReceive:

    def test_not_sent_while_a_member_is_unverified(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b])            # nobody verified Carol
        for m in (a, b):
            m.groups._bound[ROOM]["carol@x.i2p"] = ("00" * 48, False)
        assert a.files.send(ROOM, _file(tmp_path, 10)) == "unverified"
        assert not [e for e in b.events if isinstance(e, FileTransferChanged)]

    def test_an_offer_from_an_unverified_member_is_refused(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        b.groups._bound[ROOM]["alice@x.i2p"] = ("00" * 48, False)
        assert a.files.send(ROOM, _file(tmp_path, 10)) == "started"
        assert not [e for e in b.events if isinstance(e, FileTransferChanged)]
        assert "group_file_unverified" in [e.code for e in b.events
                                           if isinstance(e, ErrorOccurred)]

    def test_alone_in_the_group_nothing_is_sent(self, tmp_path):
        w, (a,), now, _vol = _sharing(1)
        assert a.files.send(ROOM, _file(tmp_path, 10)) == "no_members"

    def test_too_big_or_empty_is_refused(self, tmp_path, monkeypatch):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        assert a.files.send(ROOM, _file(tmp_path, 0, "e")) == "bad_file"
        monkeypatch.setattr(G, "MAX_BYTES", 100)
        assert a.files.send(ROOM, _file(tmp_path, 101, "big")) == "bad_file"
        assert a.files.send(ROOM, str(tmp_path / "missing")) == "bad_file"

    def test_pieces_from_anyone_but_the_sender_are_dropped(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, 100))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        # Carol forges a piece of Alice's file: same id, her own bytes.
        c.files._control(ROOM, {"t": "data", "id": tid, "i": 0,
                                "d": "QUFB" * 33 + "QQ=="})
        assert 0 not in b.files._in[tid].have
        _run([a, b, c], now)
        assert _received(b, tid)["state"] == "received"

    def test_a_tampered_offer_hash_fails_the_file(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        path = _file(tmp_path, 500)
        real = a.files._control

        def lie(room, msg):
            if msg.get("t") == "offer":
                msg = dict(msg, sha="00" * 32)
            real(room, msg)
        a.files._control = lie
        a.files.send(ROOM, path)
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b], now)
        row = _received(b, tid)
        assert row["state"] == "failed" and row["reason"] == "verify_failed"
        assert row["path"] == ""
        assert not os.listdir(os.path.join(os.environ["OTRV4PLUS_FILE_DIR"], ".incoming"))

    def test_an_unverified_member_joining_stops_a_file_going_out(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        a.files.send(ROOM, _file(tmp_path, 5 * G.CHUNK))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        a.groups._bound[ROOM]["carol@x.i2p"] = ("00" * 48, False)
        a.files.tick()
        row = _received(a, tid)
        assert row["state"] == "cancelled" and row["reason"] == "unverified_member"
        assert _received(b, tid)["state"] == "cancelled"


class TestLostAndLate:

    def test_a_lost_piece_is_asked_for_and_sent_again(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        path = _file(tmp_path, 4 * G.CHUNK)
        a.files.send(ROOM, path)
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        real = b.files._on_piece
        lost = []

        def drop_second(inc, msg):
            if msg.get("i") == 1 and not lost:
                lost.append(1)
                return
            real(inc, msg)
        b.files._on_piece = drop_second
        _run([a, b], now, ticks=20)
        assert _received(b, tid)["state"] == "accepted"
        now[0] += G.STALL_SECONDS + 1
        _run([a, b], now, ticks=20)
        assert _received(b, tid)["state"] == "received"

    def test_a_member_that_accepts_late_gets_the_whole_file(self, tmp_path):
        w, (a, b, c), now, _vol = _sharing(3)
        _verify_all([a, b, c])
        path = _file(tmp_path, 3 * G.CHUNK)
        a.files.send(ROOM, path)
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b, c], now)
        assert _received(b, tid)["state"] == "received"
        c.files.accept(tid)
        _run([a, b, c], now)
        assert _received(c, tid)["state"] == "received"
        assert _received(a, tid)["delivered_to"] == 2

    def test_the_sender_forgets_the_file_after_the_offer_time(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        a.files.send(ROOM, _file(tmp_path, 10))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        _run([a, b], now)
        now[0] += G.OFFER_SECONDS + 1
        a.files.tick()
        assert tid not in a.files._out
        assert _received(a, tid)["state"] == "delivered"

    def test_cancel_by_the_sender_ends_it_for_everyone(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        a.files.send(ROOM, _file(tmp_path, 3 * G.CHUNK))
        tid = _offer(b).transfer_id
        b.files.accept(tid)
        assert a.files.cancel(tid)
        assert _received(b, tid)["state"] == "cancelled"
        assert _received(b, tid)["reason"] == "by_peer"


def _jpeg_with_gps():
    """A minimal JPEG with an APP1 (EXIF) segment."""
    exif = b"Exif\x00\x00" + b"MM\x00\x2a" + b"GPS-LOCATION" * 4
    app1 = b"\xff\xe1" + struct.pack(">H", len(exif) + 2) + exif
    return b"\xff\xd8" + app1 + b"\xff\xda\x00\x02" + b"\x11" * 32 + b"\xff\xd9"


class TestMetadataIsTheUsersChoice:

    def test_kept_when_asked_to_keep_removed_when_asked_to_remove(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        path = tmp_path / "cam.jpg"
        path.write_bytes(_jpeg_with_gps())
        got = {}
        for strip in (False, True):
            a.files.send(ROOM, str(path), strip_metadata=strip)
            tid = _offer(b).transfer_id
            b.files.accept(tid)
            _run([a, b], now)
            got[strip] = open(_received(b, tid)["path"], "rb").read()
        assert b"GPS-LOCATION" in got[False]
        assert b"GPS-LOCATION" not in got[True]
        # The user's original is untouched either way.
        assert path.read_bytes() == _jpeg_with_gps()

    def test_a_format_that_cannot_be_checked_is_refused_not_sent_as_is(self, tmp_path):
        w, (a, b), now, _vol = _sharing(2)
        _verify_all([a, b])
        p = tmp_path / "x.unknownformat"
        p.write_bytes(zlib.compress(os.urandom(100)))
        assert a.files.send(ROOM, str(p), strip_metadata=True) == "cannot_scrub"


class TestTheAppRoutesGroupFiles:
    """`OtrApp` sends a secure room's file to GroupFiles, lists its rows with
    the 1:1 ones, and routes Accept/Decline/Cancel by id."""

    def _app(self, secure=True):
        from android_bridge.app import OtrApp

        class Files:
            def __init__(self):
                self.calls = []

            def send(self, room, path, strip):
                self.calls.append(("send", room, path, strip))
                return "started"

            def knows(self, tid):
                return tid == "g" * 32

            def accept(self, tid):
                self.calls.append(("accept", tid))
                return True

            def decline(self, tid):
                return True

            def cancel(self, tid):
                return True

            def transfers(self):
                return [{"id": "g" * 32, "group": True}]

        class OneToOne:
            def transfers(self):
                return [{"id": "1" * 32}]

            def accept(self, tid):
                return "one_to_one"

        app = OtrApp.__new__(OtrApp)
        app._wiped = False
        app._group_files = Files()
        app._files_bridge = OneToOne()
        app._rooms = {ROOM}
        app.canonical_peer = lambda p: p
        app._groups = types.SimpleNamespace(is_secure=lambda r: secure)
        return app

    def test_routing(self):
        app = self._app()
        assert app.send_file(ROOM, "/x/a.jpg", True) == "started"
        assert app._group_files.calls == [("send", ROOM, "/x/a.jpg", True)]
        assert app.accept_file("g" * 32) == "started"
        assert app.accept_file("1" * 32) == "one_to_one"
        assert [r["id"] for r in app.transfers()] == ["1" * 32, "g" * 32]

    def test_an_ordinary_room_has_no_files(self):
        app = self._app(secure=False)
        assert app.send_file(ROOM, "/x/a.jpg", False) == "unavailable"
        assert app._group_files.calls == []
