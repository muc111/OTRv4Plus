# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Wipe & Exit's file destruction does what docs/ANDROID_WIPE_AND_EXIT.md says.

`_secure_file_destroy` overwrites a file once with kernel-CSPRNG bytes,
fsyncs it, and unlinks it; `destroy_tree` applies it to every regular file
under a state root and never follows a link out of it. Checked by watching
the bytes on disk at the moment of the fsync, not by reading the source.

What is NOT claimed, and so not tested: physical erasure of flash. Wear
levelling can leave the old block in place whatever a file-level call does
(see the function's docstring and SECURITY_ISSUES.md).
"""
from __future__ import annotations

import os
import tempfile

import pytest

otr = pytest.importorskip("otrv4plus")
from android_bridge import wipe  # noqa: E402

_REAL_FSYNC = os.fsync
SECRET = (b"correct horse battery staple " * 4000)[:100_000]


def _destroy_watching(monkeypatch, path):
    """Run the destroyer and return what the file held when it was fsync'd."""
    seen = []

    def _fsync(fd):
        _REAL_FSYNC(fd)
        with open(path, "rb") as fh:
            seen.append(fh.read())

    monkeypatch.setattr(os, "fsync", _fsync)
    otr._secure_file_destroy(path)
    return seen


def _write(path, data=SECRET):
    with open(path, "wb") as fh:
        fh.write(data)


def test_the_file_is_overwritten_in_full_before_it_is_unlinked(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(), "smp_secrets.json")
    _write(path)
    seen = _destroy_watching(monkeypatch, path)
    assert seen, "the overwrite was never fsync'd to storage"
    on_disk = seen[-1]
    assert len(on_disk) == len(SECRET), "the overwrite did not cover the whole file"
    for i in range(0, len(SECRET) - 16, 997):
        assert SECRET[i:i + 16] not in on_disk, "plaintext survived the overwrite"
    assert not os.path.exists(path), "the file was overwritten but not unlinked"


def test_the_overwrite_is_random_not_a_fixed_pattern(monkeypatch):
    # Zeros or a repeated byte would still replace the data, but the
    # documented behaviour is CSPRNG output: two runs never match, and the
    # bytes are spread across all values.
    runs = []
    for _ in range(2):
        path = os.path.join(tempfile.mkdtemp(), "key")
        _write(path)
        runs.append(_destroy_watching(monkeypatch, path)[-1])
    assert runs[0] != runs[1]
    assert len(set(runs[0])) > 250


def test_an_empty_file_is_simply_removed():
    path = os.path.join(tempfile.mkdtemp(), "empty")
    _write(path, b"")
    otr._secure_file_destroy(path)
    assert not os.path.exists(path)


def test_the_tree_wipe_uses_it_for_every_file_and_removes_the_tree(monkeypatch):
    root = tempfile.mkdtemp(prefix="wipe-root-")
    nested = os.path.join(root, "files", ".incoming")
    os.makedirs(nested)
    paths = [os.path.join(root, "trust.json"), os.path.join(nested, "part")]
    for p in paths:
        _write(p)
    overwritten = []
    real = otr._secure_file_destroy
    monkeypatch.setattr(otr, "_secure_file_destroy",
                        lambda p: overwritten.append(p) or real(p))
    destroyed, failed = wipe.destroy_tree(root)
    assert (destroyed, failed) == (2, 0)
    assert sorted(overwritten) == sorted(paths), "a file was unlinked without the overwrite"
    assert not os.path.exists(root)


def test_the_tree_wipe_never_follows_a_link_out_of_the_root():
    outside = tempfile.mkdtemp(prefix="wipe-outside-")
    victim = os.path.join(outside, "not-ours")
    _write(victim)
    root = tempfile.mkdtemp(prefix="wipe-root-")
    os.symlink(victim, os.path.join(root, "link"))
    wipe.destroy_tree(root)
    with open(victim, "rb") as fh:
        assert fh.read() == SECRET, "a file outside the wipe root was destroyed"


# -- the pass count follows the storage --------------------------------------

def test_a_spinning_disk_gets_zeros_then_ones_then_random(monkeypatch):
    monkeypatch.setattr(otr, "_on_rotational_disk", lambda p: True)
    path = os.path.join(tempfile.mkdtemp(), "trust.json")
    _write(path)
    seen = _destroy_watching(monkeypatch, path)
    assert len(seen) == 3, "each of the three passes must reach storage"
    assert seen[0] == b"\x00" * len(SECRET)
    assert seen[1] == b"\xff" * len(SECRET)
    assert len(set(seen[2])) > 250 and len(seen[2]) == len(SECRET)
    assert not os.path.exists(path)


def test_flash_gets_one_random_pass(monkeypatch):
    # Extra passes on flash land on new blocks and reach nothing.
    monkeypatch.setattr(otr, "_on_rotational_disk", lambda p: False)
    path = os.path.join(tempfile.mkdtemp(), "trust.json")
    _write(path)
    seen = _destroy_watching(monkeypatch, path)
    assert len(seen) == 1 and len(set(seen[0])) > 250


def test_storage_that_cannot_be_identified_counts_as_flash(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(), "x")
    _write(path, b"x")

    def _no_stat(p, *a, **k):
        raise OSError("no device")
    monkeypatch.setattr(os, "stat", _no_stat)
    assert otr._on_rotational_disk(path) is False


def test_a_file_that_survives_its_unlink_is_an_error(monkeypatch):
    path = os.path.join(tempfile.mkdtemp(), "stubborn")
    _write(path)
    monkeypatch.setattr(os, "remove", lambda p: None)
    with pytest.raises(OSError):
        otr._secure_file_destroy(path)


# -- the wipe checks itself ----------------------------------------------------

@pytest.fixture
def home(monkeypatch):
    home = tempfile.mkdtemp(prefix="wipe-verify-home-")
    monkeypatch.setenv("HOME", home)
    monkeypatch.delenv("OTRV4PLUS_FILE_DIR", raising=False)
    state = os.path.join(home, ".otrv4plus", "files", ".incoming")
    os.makedirs(state)
    _write(os.path.join(home, ".otrv4plus", "trust.json"))
    _write(os.path.join(state, "partial"))
    return home


def test_a_complete_wipe_is_verified(home):
    report = wipe.wipe_disk()
    assert report["files_destroyed"] == 2
    assert report["survivors"] == 0 and report["verified"] is True


def test_anything_left_behind_fails_verification(home, monkeypatch):
    real = wipe.destroy_tree

    def _leaves_one(root):
        keep = os.path.join(root, "kept")
        out = real(root)
        if root.endswith(".otrv4plus"):
            os.makedirs(root, exist_ok=True)
            _write(keep)
        return out
    monkeypatch.setattr(wipe, "destroy_tree", _leaves_one)
    report = wipe.wipe_disk()
    assert report["verified"] is False and report["survivors"] >= 1


def test_a_file_that_had_only_an_unlink_fails_verification(home, monkeypatch):
    def _refuse(path):
        raise OSError("overwrite refused")
    monkeypatch.setattr(otr, "_secure_file_destroy", _refuse)
    report = wipe.wipe_disk()
    assert report["files_unlinked_only"] == 2
    assert report["survivors"] == 0, "the fallback unlink still ran"
    assert report["verified"] is False, "an unlink alone was counted as a wipe"


def test_the_app_wipe_reports_its_verification(home):
    from test_wipe_and_exit import _pair
    app = _pair().alice
    try:
        report = app.wipe()
    finally:
        app.shutdown()
    assert report["verified"] is True and report["survivors"] == 0


@pytest.mark.parametrize("flag,partition,want", [
    ("1", False, True), ("0", False, False), ("1", True, True), ("0", True, False)])
def test_the_device_is_read_from_sysfs(monkeypatch, flag, partition, want):
    path = os.path.join(tempfile.mkdtemp(), "f")
    _write(path, b"x")
    dev = os.stat(path).st_dev
    sysfs = tempfile.mkdtemp(prefix="fake-sysfs-")
    disk = os.path.join(sysfs, "disk")
    os.makedirs(os.path.join(disk, "queue"))
    with open(os.path.join(disk, "queue", "rotational"), "w") as fh:
        fh.write(flag + "\n")
    node = os.path.join(sysfs, "%d:%d" % (os.major(dev), os.minor(dev)))
    if partition:                      # a partition has no queue/ of its own
        os.makedirs(os.path.join(disk, "part1"))
        os.symlink(os.path.join(disk, "part1"), node)
    else:
        os.symlink(disk, node)
    monkeypatch.setattr(otr, "_SYSFS_BLOCK", sysfs)
    assert otr._on_rotational_disk(path) is want
