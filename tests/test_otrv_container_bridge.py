# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Received files at rest as `.otrv` containers, through the bridge.

The format and its refusals are tested in Rust (Rust/src/container.rs).
Here: what the Android bridge does with them -- Open in memory or to a
transient path, Save replacing a destination, a portable passphrase export
that opens on any build, and refusal of anything outside the received
directory or altered on disk.
"""
import os
import tempfile

import pytest

core = pytest.importorskip("otrv4_core")
ft = pytest.importorskip("otrv4plus_filetransfer")
from android_bridge.files import FileBridge  # noqa: E402


@pytest.fixture
def store(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("OTRV4PLUS_FILE_DIR", d)
    bridge = FileBridge.__new__(FileBridge)
    plain = os.path.join(tempfile.mkdtemp(), "photo.jpg")
    data = os.urandom(200_000)
    open(plain, "wb").write(data)
    container = os.path.join(d, "photo.jpg" + ft.CONTAINER_SUFFIX)
    core.otrv_seal_file(ft.at_rest_dek(), plain, container)
    return bridge, d, container, data


def test_open_returns_the_plaintext_and_writes_nothing(store):
    bridge, d, container, data = store
    before = sorted(os.listdir(d))
    assert bridge.open_received(container) == data
    assert sorted(os.listdir(d)) == before


def test_the_container_holds_no_plaintext(store):
    _, _, container, data = store
    assert data[:64] not in open(container, "rb").read()


def test_a_transient_open_lands_where_asked_not_in_the_store(store):
    bridge, d, container, data = store
    view = tempfile.mkdtemp()
    out = bridge.open_received_to(container, view)
    assert os.path.dirname(out) == view and open(out, "rb").read() == data
    assert not [n for n in os.listdir(d) if n.endswith(".jpg")], "plaintext in the store"


def test_save_replaces_an_existing_destination(store):
    bridge, _, container, data = store
    dest = os.path.join(tempfile.mkdtemp(), "photo.jpg")
    open(dest, "wb").write(b"older file")
    assert bridge.save_received(container, dest) == len(data)
    assert open(dest, "rb").read() == data
    assert os.listdir(os.path.dirname(dest)) == ["photo.jpg"], "a '(1)' copy appeared"


def test_anything_outside_the_received_directory_is_refused(store):
    bridge, d, container, _ = store
    elsewhere = os.path.join(tempfile.mkdtemp(), "x.otrv")
    open(elsewhere, "wb").write(open(container, "rb").read())
    for path in (elsewhere, os.path.join(d, "..", os.path.basename(d), "nope.otrv"),
                 os.path.join(d, ft.AT_REST_DEK_NAME), ""):
        with pytest.raises(Exception):
            bridge.open_received(path)


def test_an_altered_container_opens_nothing(store):
    bridge, _, container, _ = store
    raw = bytearray(open(container, "rb").read())
    raw[len(raw) // 2] ^= 1
    open(container, "wb").write(bytes(raw))
    with pytest.raises(Exception):
        bridge.open_received(container)
    view = tempfile.mkdtemp()
    with pytest.raises(Exception):
        bridge.open_received_to(container, view)
    assert os.listdir(view) == [], "a partial plaintext file was left behind"


def test_a_passphrase_export_opens_anywhere_and_only_with_it(store):
    bridge, _, container, data = store
    out = os.path.join(tempfile.mkdtemp(), "photo.jpg.otrv")
    bridge.export_received(container, out, "correct horse battery")
    assert core.otrv_info(out)["key_source"] == "passphrase"
    dst = os.path.join(tempfile.mkdtemp(), "photo.jpg")
    with pytest.raises(Exception):
        FileBridge.import_container(out, dst, "wrong horse battery")
    assert not os.path.exists(dst)
    assert FileBridge.import_container(out, dst, "correct horse battery") == len(data)
    assert open(dst, "rb").read() == data


def test_the_device_key_is_not_python_bytes():
    dek = ft.at_rest_dek()
    assert "REDACTED" in repr(dek)
    assert not any(isinstance(getattr(dek, a, None), (bytes, bytearray))
                   for a in dir(dek) if not a.startswith("__"))
