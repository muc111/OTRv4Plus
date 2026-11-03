# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A file arriving in the apps is never plaintext on disk, not even partly.

Each decrypted chunk is sealed at once under the process's RunKey (256
random bits made in Rust, never written anywhere), and the finished `.part`
is resealed straight into the at-rest container
(`otrv4_core.otrv_reseal_run_file`), which also returns the hash the
transfer checks. A `.part` left by a crash, a kill or a power cut is
ciphertext whose key died with the process.
"""
from __future__ import annotations

import hashlib
import os
import tempfile

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RunSealedWriter"):
    pytest.skip("core built before run-sealed partial files", allow_module_level=True)

import otrv4plus_filetransfer as ft  # noqa: E402
import time  # noqa: E402

from test_android_files import a_file, landing, pair, verified  # noqa: E402,F401 -- fixtures

PLAIN = b"the quick brown fox jumps over the lazy dog. " * 3000


def _part(chunks, key=None):
    path = os.path.join(tempfile.mkdtemp(), "x.part")
    w = core.RunSealedWriter(key or core.RunKey(), path)
    for c in chunks:
        w.write(c)
    return path, w.finish()


def _dek():
    return core.FileDek.load_or_create(os.path.join(tempfile.mkdtemp(), "files.dek"))


class TestThePartialFileIsSealedAsItArrives:

    def test_no_chunk_is_ever_on_disk_in_the_clear(self, verified, a_file, landing,
                                                   monkeypatch):
        seen = []
        real = ft._RunSealedPart.write

        def watch(self, data):
            real(self, data)
            with open(self._path, "rb") as fh:
                seen.append((bytes(data), fh.read()))
        monkeypatch.setattr(ft._RunSealedPart, "__init__", _remember_path(ft._RunSealedPart.__init__))
        monkeypatch.setattr(ft._RunSealedPart, "write", watch)

        verified.alice.send_file(verified.bob_jid, a_file)
        verified.bob.accept_file(verified.bob.transfers()[0]["id"])
        for _ in range(200):                # the send runs on its own thread
            time.sleep(0.02)

        assert seen, "the transfer did not go through the run-sealed part"
        for chunk, on_disk in seen:
            assert chunk[:24] not in on_disk, "a chunk reached the disk in the clear"
        arrived = landing.files()
        assert arrived and arrived[0].endswith(".otrv")
        assert verified.bob.open_received(arrived[0]) == open(a_file, "rb").read()
        incoming = os.path.join(landing.path, ".incoming")
        assert not os.path.exists(incoming) or os.listdir(incoming) == [], \
            "the partial file outlived the transfer"


def _remember_path(init):
    def __init__(self, path):
        init(self, path)
        self._path = path
    return __init__


class TestTheReseal:

    def test_it_round_trips_and_returns_the_plaintext_hash(self):
        chunks = [PLAIN[i:i + 4096] for i in range(0, len(PLAIN), 4096)]
        key = core.RunKey()
        path, n = _part(chunks, key)
        assert n == len(PLAIN)
        assert PLAIN[:24] not in open(path, "rb").read()
        dek, dst = _dek(), os.path.join(tempfile.mkdtemp(), "f.otrv")
        digest = bytes(core.otrv_reseal_run_file(key, dek, path, dst, n))
        assert digest == hashlib.sha256(PLAIN).digest()
        assert bytes(core.otrv_open_bytes(dek, dst, 1 << 24)) == PLAIN

    def test_a_leftover_part_does_not_open_under_another_run_key(self):
        # What a crash leaves: the file, and a new process with a new key.
        path, n = _part([PLAIN])
        dst = os.path.join(tempfile.mkdtemp(), "f.otrv")
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(core.RunKey(), _dek(), path, dst, n)
        assert not os.path.exists(dst)

    def test_a_tampered_part_is_refused_and_leaves_nothing(self):
        key = core.RunKey()
        path, n = _part([PLAIN[:5000], PLAIN[5000:9000]], key)
        raw = bytearray(open(path, "rb").read())
        raw[40] ^= 1
        open(path, "wb").write(bytes(raw))
        dst = os.path.join(tempfile.mkdtemp(), "f.otrv")
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(key, _dek(), path, dst, n)
        assert not os.path.exists(dst)

    @pytest.mark.parametrize("delta", [-1, 1])
    def test_a_length_that_does_not_match_is_refused(self, delta):
        key = core.RunKey()
        path, n = _part([PLAIN[:3000]], key)
        dst = os.path.join(tempfile.mkdtemp(), "f.otrv")
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(key, _dek(), path, dst, n + delta)
        assert not os.path.exists(dst)

    def test_chunks_cannot_be_relabelled(self):
        # Each record carries its index, bound into its tag: swapping two
        # records' labels is refused.
        key = core.RunKey()
        path, n = _part([b"A" * 2000, b"B" * 2000], key)
        raw = bytearray(open(path, "rb").read())
        rec = 8 + 2000 + 16
        raw[16:20], raw[16 + rec:20 + rec] = raw[16 + rec:20 + rec], raw[16:20]
        open(path, "wb").write(bytes(raw))
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(key, _dek(), path, os.path.join(tempfile.mkdtemp(), "f"), n)

    def test_out_of_order_arrival_reseals_in_order(self):
        key = core.RunKey()
        path = os.path.join(tempfile.mkdtemp(), "g.part")
        w = core.RunSealedWriter(key, path)
        pieces = [PLAIN[i:i + 5000] for i in range(0, 20000, 5000)]
        for i in (2, 0, 3, 1):
            w.write_at(i, pieces[i])
        n = w.finish()
        dek, dst = _dek(), os.path.join(tempfile.mkdtemp(), "g.otrv")
        assert bytes(core.otrv_reseal_run_file(key, dek, path, dst, n)) == \
            hashlib.sha256(b"".join(pieces)).digest()
        assert bytes(core.otrv_open_bytes(dek, dst, 1 << 24)) == b"".join(pieces)

    @pytest.mark.parametrize("indices", [(0, 0), (0, 2)])
    def test_a_duplicate_or_a_gap_is_refused(self, indices):
        key = core.RunKey()
        path = os.path.join(tempfile.mkdtemp(), "g.part")
        w = core.RunSealedWriter(key, path)
        for i in indices:
            w.write_at(i, b"x" * 2000)
        n = w.finish()
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(key, _dek(), path, os.path.join(tempfile.mkdtemp(), "f"), n)

    def test_a_destroyed_run_key_opens_nothing(self):
        key = core.RunKey()
        path, n = _part([PLAIN[:3000]], key)
        key.zeroize()
        with pytest.raises(Exception):
            core.otrv_reseal_run_file(key, _dek(), path, os.path.join(tempfile.mkdtemp(), "f"), n)
        assert "REDACTED" in repr(key)


class TestTheReadBackStillDecides:

    def test_a_reseal_that_reads_back_wrong_bytes_leaves_no_file(self, verified, a_file,
                                                                landing, monkeypatch):
        # Step 5's independent read-back: what came off the disk must hash to
        # what was offered, or nothing is kept.
        real = ft._core.otrv_reseal_run_file

        def corrupt(*args, **kw):
            real(*args, **kw)
            return b"\x00" * 32
        monkeypatch.setattr(ft._core, "otrv_reseal_run_file", corrupt)
        verified.alice.send_file(verified.bob_jid, a_file)
        verified.bob.accept_file(verified.bob.transfers()[0]["id"])
        for _ in range(200):
            time.sleep(0.02)
        assert landing.files() == [], "a file that failed its read-back was kept"
