# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Crypto-erase on the desktop: the key-wrapping key and its key store.

Every key file is wrapped by a KEK kept in the platform key store
(`android_bridge.key_custody`, Rust/src/at_rest.rs). These tests run the
real Rust core against a fake key store: a record sealed under a key file
must open while the KEK is installed and never again once Wipe & Exit has
deleted it -- even though the key file and the record are still on disk,
which is the case flash wear levelling leaves.
"""
from __future__ import annotations

import os
import tempfile

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "set_key_wrapping_key"):
    pytest.skip("core built before key wrapping", allow_module_level=True)

from android_bridge import key_custody as K  # noqa: E402


class FakeSecretService:
    """`secret-tool` as a dict, recording every argv and stdin."""

    def __init__(self, running=True, keeps=True):
        self.items, self.calls = {}, []
        self.running, self.keeps = running, keeps

    def __call__(self, argv, stdin):
        self.calls.append((list(argv), stdin))
        if not self.running:
            return 2, b""
        verb, key = argv[1], tuple(a for a in argv[2:] if not a.startswith("--"))
        if verb == "lookup":
            return (0, self.items[key]) if key in self.items else (1, b"")
        if verb == "store":
            if self.keeps:
                self.items[key] = stdin
            return 0, b""
        if verb == "clear":
            self.items.pop(key, None)
            return 0, b""
        return 2, b""


def _backend(fake):
    return K.SecretToolBackend(run=fake, which=lambda name: "/usr/bin/" + name)


@pytest.fixture(autouse=True)
def _no_kek_left_behind():
    yield
    core.clear_key_wrapping_key()
    K._STATE.update(backend=None, installed=False)


def _seal_one(dek_path):
    dek = core.FileDek.load_or_create(dek_path)
    nonce = os.urandom(12)
    return nonce, bytes(dek.seal(nonce, b"alice's identity", b"aad"))


def _opens(dek_path, nonce, blob):
    try:
        return bytes(core.FileDek.load_or_create(dek_path).open(nonce, blob, b"aad")) == b"alice's identity"
    except Exception:
        return False


def test_first_start_creates_a_kek_in_the_store_and_wraps_the_key_files():
    fake = FakeSecretService()
    s = K.install(_backend(fake))
    assert s == {"key_store": "secret-service", "key_store_tier": "keyring", "key_wrapping": True}
    assert core.key_wrapping_active()
    path = os.path.join(tempfile.mkdtemp(), "identity.dek")
    _seal_one(path)
    with open(path, "rb") as fh:
        assert fh.read(8) == b"OTRVKW1\x00", "the key file is not wrapped"


def test_the_same_kek_comes_back_on_the_next_start():
    fake = FakeSecretService()
    K.install(_backend(fake))
    path = os.path.join(tempfile.mkdtemp(), "trust.dek")
    nonce, blob = _seal_one(path)
    core.clear_key_wrapping_key()                     # the app exits
    assert not _opens(path, nonce, blob)
    K.install(_backend(fake))                         # and starts again
    assert _opens(path, nonce, blob)


def test_wipe_destroys_the_kek_and_nothing_opens_afterwards():
    fake = FakeSecretService()
    K.install(_backend(fake))
    path = os.path.join(tempfile.mkdtemp(), "groups.dek")
    nonce, blob = _seal_one(path)
    report = K.destroy()
    assert report == {"key_store": "secret-service", "key_store_tier": "keyring",
                      "crypto_erased": True}
    assert fake.items == {}, "the KEK is still in the key store"
    assert not core.key_wrapping_active()
    # The key file and the record are still on disk -- what wear levelling
    # can leave -- and still do not open, now or on a later start.
    assert os.path.exists(path)
    assert not _opens(path, nonce, blob)
    K.install(_backend(fake))                         # a new KEK is made
    assert not _opens(path, nonce, blob)


def test_the_kek_is_never_on_a_command_line():
    fake = FakeSecretService()
    K.install(_backend(fake))
    secret = next(iter(fake.items.values())).decode()
    for argv, _stdin in fake.calls:
        assert all(secret not in a for a in argv), "the KEK was passed on argv"


def test_a_store_that_does_not_keep_the_kek_means_no_wrapping():
    # Wrapping under a KEK the store lost would lose every key file at the
    # next start.
    s = K.install(_backend(FakeSecretService(keeps=False)))
    assert s["key_wrapping"] is False and not core.key_wrapping_active()
    assert K.destroy()["crypto_erased"] is False


def test_no_key_store_says_so_and_changes_nothing():
    fake = FakeSecretService(running=False)
    b = K.choose([_backend(fake)])
    assert b.tier == "none"
    s = K.install(b)
    assert s == {"key_store": "none", "key_store_tier": "none", "key_wrapping": False}
    path = os.path.join(tempfile.mkdtemp(), "x.dek")
    _seal_one(path)
    assert os.path.getsize(path) == 32, "a plain key file is expected without a store"
    assert K.destroy()["crypto_erased"] is False


def test_a_delete_the_store_does_not_confirm_is_not_crypto_erase():
    class Stubborn(FakeSecretService):
        def __call__(self, argv, stdin):
            if argv[1] == "clear":
                return 0, b""                         # says yes, keeps it
            return super().__call__(argv, stdin)
    K.install(_backend(Stubborn()))
    assert K.destroy()["crypto_erased"] is False


def test_the_macos_keychain_gets_the_key_on_stdin_only():
    seen = []

    def run(argv, stdin):
        seen.append((list(argv), stdin))
        return 0, b""
    b = K.MacKeychainBackend(run=run, which=lambda n: "/usr/bin/" + n)
    kek = bytearray(os.urandom(32))
    b.store(kek)
    argv, stdin = seen[-1]
    assert argv == ["security", "-i"]
    assert kek.hex().encode() in stdin and all(kek.hex() not in a for a in argv)


def test_wipe_and_exit_destroys_the_kek_first_and_reports_it(monkeypatch):
    from test_wipe_and_exit import _pair
    monkeypatch.setenv("HOME", tempfile.mkdtemp(prefix="custody-home-"))
    fake = FakeSecretService()
    K.install(_backend(fake))
    app = _pair().alice
    try:
        report = app.wipe()
    finally:
        app.shutdown()
    assert report["crypto_erased"] is True and report["key_store"] == "secret-service"
    assert fake.items == {} and not core.key_wrapping_active()
