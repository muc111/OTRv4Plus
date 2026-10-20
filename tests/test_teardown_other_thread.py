# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Sessions made on one thread can be torn down from another.

Desktop report (2026-10-20), on closing the app after a call:

    File "otrv4_.py", line 9660, in clear_all_sessions
        self.end_session(peer, reason)
    RuntimeError: otrv4_core::dake::DakeOutput is unsendable, but is being
    dropped on another thread

The handshake runs on the client's OTR worker thread; shutdown, logout and
Wipe & Exit run elsewhere, so the teardown stopped at the first session and
left the rest. `DakeOutput` is no longer bound to its creating thread."""
import os
import sys
import tempfile
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")


def _manager():
    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"), ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(d, name))
    return otr.EnhancedSessionManager(config=config)


def _handshake(a, b, alice, bob):
    current, _ = a.handle_outgoing_message(bob, "")
    sender, receiver, sid = a, b, alice
    for _ in range(10):
        if not current:
            break
        out = receiver.handle_incoming_message(sid, current)
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        if not text or not text.startswith("?OTRv4"):
            break
        current = text
        sender, receiver = receiver, sender
        sid = bob if sid == alice else alice


def test_sessions_built_on_a_worker_thread_tear_down_on_another():
    try:
        otr._dake1_rate_limiter._attempts.clear()
    except Exception:
        pass
    a, b = _manager(), _manager()
    alice, bob = "alice@teardown.test", "bob@teardown.test"
    # Both a finished session and one left mid-handshake (DAKE2 held).
    a2, c = _manager(), _manager()
    carol = "carol@teardown.test"
    errors = []

    def worker():
        try:
            _handshake(a, b, alice, bob)
            dake1, _ = a2.handle_outgoing_message(carol, "")
            c.handle_incoming_message(alice, dake1)
        except BaseException as exc:          # noqa: BLE001
            errors.append(exc)
    t = threading.Thread(target=worker, name="otr-worker")
    t.start()
    t.join(60)
    assert not errors, errors
    assert a.get_session(bob) is not None

    for m in (a, b, a2, c):
        m.clear_all_sessions("test teardown")     # this thread, not the worker's
    assert a.get_session(bob) is None and c.get_session(alice) is None
