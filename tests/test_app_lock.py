# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The app lock's data key (Rust/src/app_lock.rs via android_bridge.app_lock).

Design: docs/APP_LOCK_PASSPHRASE.md. The passphrase and the key store's HMAC
reach Rust as bytearrays and are zeroed; the data key never leaves Rust; a
wrong passphrase and a damaged record are the same failure; locking makes
every sealed record unreadable and removes the key-wrapping key.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

otrv4_core = pytest.importorskip("otrv4_core")
if not hasattr(otrv4_core, "app_lock_enrol"):
    pytest.skip("otrv4_core built without the app lock", allow_module_level=True)

from android_bridge import app_lock as L  # noqa: E402

# The cheapest cost the record allows, to keep the suite fast. The default
# cost is exercised once below.
CHEAP = {"t": 1, "m_kib": 8 * 1024, "p": 1}
HW = bytes(range(32))


def pw(text="correct horse battery"):
    return bytearray(text.encode())


@pytest.fixture(autouse=True)
def locked_around():
    L.lock()
    yield
    L.lock()


def enrol(passphrase="correct horse battery", **cost):
    salt = L.new_salt()
    record = L.enrol(pw(passphrase), bytearray(HW), salt, **(cost or CHEAP))
    assert L.commit()
    return record


def test_nothing_uses_the_new_key_until_its_record_is_stored():
    L.enrol(pw(), bytearray(HW), L.new_salt(), **CHEAP)
    assert not L.unlocked() and not otrv4_core.key_wrapping_active()
    with pytest.raises(L.AppLocked):
        L.seal("vault/x", b"y")
    assert L.commit() and L.unlocked() and otrv4_core.key_wrapping_active()
    assert not L.commit()


def test_locking_drops_an_enrolment_never_committed():
    L.enrol(pw(), bytearray(HW), L.new_salt(), **CHEAP)
    L.lock()
    assert not L.commit()


def test_enrol_unlocks_and_the_record_holds_no_secret():
    record = enrol()
    assert L.unlocked()
    assert len(record) == otrv4_core.APP_LOCK_RECORD_LEN
    assert b"correct horse" not in record and HW not in record
    info = L.record_info(record)
    assert info["mode"] == "passphrase" and info["t"] == 1 and len(info["salt"]) == 32


def test_the_passphrase_and_hardware_value_are_wiped_after_use():
    salt = L.new_salt()
    p, h = pw(), bytearray(HW)
    L.enrol(p, h, salt, **CHEAP)
    assert p == bytearray(len(p)) and h == bytearray(32)
    L.commit()
    record = L.rewrap(pw("x"), bytearray(HW), salt, **CHEAP)
    L.lock()
    p, h = pw("x"), bytearray(HW)
    assert L.unlock(p, h, record)
    assert p == bytearray(len(p)) and h == bytearray(32)


def test_secrets_must_be_wipeable():
    with pytest.raises(TypeError):
        otrv4_core.app_lock_enrol(b"immutable", bytearray(HW), L.new_salt(), 1, 8192, 1)
    with pytest.raises(TypeError):
        otrv4_core.app_lock_unlock(bytearray(b"pw"), HW, b"\0" * 113)


def test_lock_then_unlock_with_the_right_passphrase_only():
    record = enrol("right")
    L.lock()
    assert not L.unlocked()
    assert not L.unlock(pw("wrong"), bytearray(HW), record)
    assert not L.unlock(pw("right"), bytearray(bytes(32)), record)   # another phone
    assert not L.unlocked()
    assert L.unlock(pw("right"), bytearray(HW), record)
    assert L.unlocked()


def test_a_damaged_record_fails_like_a_wrong_passphrase():
    record = bytearray(enrol("right"))
    L.lock()
    record[-1] ^= 1
    assert L.unlock(pw("right"), bytearray(HW), bytes(record)) is False


def test_locked_means_nothing_sealed_reads_and_the_wrapping_key_is_gone():
    enrol()
    sealed = L.seal("vault/credentials", b"account password")
    assert otrv4_core.key_wrapping_active()
    assert L.open_sealed("vault/credentials", sealed) == b"account password"
    L.lock()
    assert not otrv4_core.key_wrapping_active()
    with pytest.raises(L.AppLocked):
        L.open_sealed("vault/credentials", sealed)
    with pytest.raises(L.AppLocked):
        L.seal("vault/credentials", b"x")


def test_a_sealed_record_is_bound_to_its_name():
    enrol()
    sealed = L.seal("vault/credentials", b"pw")
    assert L.is_sealed(sealed) and not L.is_sealed(b"legacy")
    assert L.open_sealed("vault/history", sealed) is None


def test_changing_the_passphrase_keeps_the_data():
    record = enrol("old")
    sealed = L.seal("trust/a", b"pins")
    assert L.check(pw("old"), bytearray(HW), record)
    assert not L.check(pw("nope"), bytearray(HW), record)
    new = L.rewrap(pw("new"), bytearray(HW), L.new_salt(), **CHEAP)
    L.lock()
    assert not L.unlock(pw("old"), bytearray(HW), new)
    assert L.unlock(pw("new"), bytearray(HW), new)
    assert L.open_sealed("trust/a", sealed) == b"pins"      # nothing re-encrypted


def test_turning_the_lock_off_keeps_the_data_under_the_device_key():
    enrol("pw")
    sealed = L.seal("vault/x", b"history")
    device = L.rewrap(None, bytearray(HW), L.new_salt())
    assert L.record_info(device)["mode"] == "device"
    L.lock()
    assert L.unlock(None, bytearray(HW), device)
    assert L.open_sealed("vault/x", sealed) == b"history"


def test_enrolling_again_while_unlocked_is_refused():
    enrol()
    with pytest.raises(RuntimeError):
        enrol()


def test_a_record_naming_a_huge_cost_is_refused():
    record = bytearray(enrol())
    L.lock()
    record[13:17] = (64 * 1024 * 1024).to_bytes(4, "big")
    with pytest.raises(ValueError):
        L.record_info(bytes(record))
    assert L.unlock(pw(), bytearray(HW), bytes(record)) is False


def test_the_default_cost_works_and_releases_the_gil():
    import threading
    ticks = []
    stop = threading.Event()

    def tick():
        while not stop.is_set():
            ticks.append(1)
            stop.wait(0.005)
    t = threading.Thread(target=tick)
    t.start()
    try:
        record = L.enrol(pw(), bytearray(HW), L.new_salt())     # t=3, 64 MiB, p=4
        assert L.commit()
    finally:
        stop.set()
        t.join()
    assert L.record_info(record)["m_kib"] == 64 * 1024
    assert len(ticks) > 1          # Python kept running during Argon2id


def test_kotlin_byte_arrays_become_bytearrays_without_a_bytes_copy():
    class JArray(list):      # what a Chaquopy jarray('B') iterates as: signed
        pass
    out = L._secret(JArray([-1, 0, 127, -128]))
    assert out == bytearray([255, 0, 127, 128])
