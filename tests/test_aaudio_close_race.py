# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""AAudio forbids closing a stream while another thread is inside read or
write on it (the close frees it). Device report 2026-10-15: the app crashed
on hanging up a group call. The close must wait for the I/O in flight."""
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_audio as A  # noqa: E402


class _Lib:
    def __init__(self):
        self.in_read = threading.Event()
        self.release = threading.Event()
        self.events = []

    def AAudioStream_read(self, stream, buf, frames, timeout):
        self.events.append("read-start")
        self.in_read.set()
        self.release.wait(2)
        self.events.append("read-end")
        return 0

    def AAudioStream_requestStop(self, stream):
        self.events.append("requestStop")
        self.release.set()            # as AAudio does: a blocked read returns
        return 0

    def AAudioStream_close(self, stream):
        self.events.append("close")
        return 0


def _stream(lib):
    s = A.AAudioStreamBase.__new__(A.AAudioStreamBase)
    s._lib, s._stream, s._closed = lib, object(), False
    s._lock, s._io = threading.Lock(), threading.Lock()
    return s


def test_close_waits_for_a_read_in_flight():
    lib = _Lib()
    s = _stream(lib)
    reader = threading.Thread(target=s._io_call, args=(lib.AAudioStream_read, None, 0, 0))
    reader.start()
    assert lib.in_read.wait(2)
    s.stop()
    reader.join(2)
    assert lib.events.index("read-end") < lib.events.index("close")
    assert lib.events.count("close") == 1


def test_no_io_after_close():
    lib = _Lib()
    s = _stream(lib)
    s.stop()
    assert s._io_call(lib.AAudioStream_read, None, 0, 0) is None
    assert "read-start" not in lib.events
    s.stop()                          # idempotent
    assert lib.events.count("close") == 1
