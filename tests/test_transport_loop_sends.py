# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A send made from the transport's own event-loop thread must not wait for
that loop (device report, 2026-10-04: a secure group sending its Welcomes
when its commit came back deadlocked for 30 s per Welcome, and the stalled
loop then lost the connection)."""
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import transport as T  # noqa: E402


class _Client:
    def __init__(self):
        self.sent = []

    def send_message(self, mto, mbody, mtype):
        self.sent.append((str(mto), mbody, mtype))


def _transport():
    t = T.XmppTransport.__new__(T.XmppTransport)
    t._loop = None
    t._thread = None
    t._closed = False
    t._lock = threading.RLock()
    t._client = _Client()
    t._connected = threading.Event()
    t._connected.set()
    t._frag_seq = 0
    t._ensure_loop()
    return t


def test_a_room_send_from_the_loop_thread_does_not_deadlock():
    t = _transport()
    done = threading.Event()
    took = []

    def on_loop():
        start = time.monotonic()
        t.send_room_message("room@conference.x", "body")   # as a handler would
        took.append(time.monotonic() - start)
        done.set()
    t._loop.call_soon_threadsafe(on_loop)
    assert done.wait(5), "the send blocked the loop"
    assert took[0] < 1.0
    deadline = time.time() + 5
    while not t._client.sent and time.time() < deadline:
        time.sleep(0.01)
    assert t._client.sent == [("room@conference.x", "body", "groupchat")]


def test_a_send_from_another_thread_still_waits_for_completion():
    t = _transport()
    t.send_room_message("room@conference.x", "body")
    assert t._client.sent == [("room@conference.x", "body", "groupchat")]
