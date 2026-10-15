# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The call path built before the call (otrv4plus_warmpath): the green phone."""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_warmpath as W  # noqa: E402


class _Thing:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _path(fail=False, gate=None):
    now = [1000.0]
    built = []

    def build(host, port):
        if gate is not None:
            gate.wait(2)
        if fail:
            raise RuntimeError("no tunnel")
        s = W.Spare(_Thing(), _Thing(), "sid%d" % len(built), "dest%d" % len(built), (host, port))
        built.append(s)
        return s

    return W.WarmPath(build=build, clock=lambda: now[0], keep=600.0), now, built


def _settle(p):
    for t in threading.enumerate():
        if t.name == "otrv4plus-warmpath":
            t.join(2)


def test_cold_then_warming_then_ready():
    gate = threading.Event()
    p, now, built = _path(gate=gate)
    assert p.state() == "cold"
    assert p.warm("127.0.0.1", 7656) == "warming"
    gate.set()
    _settle(p)
    assert p.describe() == {"state": "ready", "seconds_left": 600}


def test_a_call_takes_it_once_and_a_new_one_is_built():
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    first = p.take(("127.0.0.1", 7656))
    assert first is built[0] and not first.control.closed
    _settle(p)
    second = p.take(("127.0.0.1", 7656))
    assert second is built[1] and second is not first


def test_another_sam_bridge_does_not_get_it():
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    assert p.take(("127.0.0.1", 9999)) is None
    assert p.state() == "ready"


def test_it_is_closed_ten_minutes_after_the_last_ask():
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    now[0] += 599
    assert p.state() == "ready"
    now[0] += 2
    assert p.state() == "cold"
    assert built[0].control.closed and built[0].sock.closed
    assert p.take() is None


def test_asking_again_keeps_it():
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    now[0] += 500
    p.warm("127.0.0.1", 7656)
    now[0] += 500
    assert p.state() == "ready" and len(built) == 1


def test_a_failed_build_is_not_retried_at_once():
    p, now, built = _path(fail=True)
    p.warm("127.0.0.1", 7656)
    _settle(p)
    assert p.state() == "cold" and p.stats["failed"] == 1
    p.warm("127.0.0.1", 7656)
    _settle(p)
    assert p.stats["failed"] == 1                 # within RETRY_AFTER
    now[0] += W.RETRY_AFTER + 1
    p.warm("127.0.0.1", 7656)
    _settle(p)
    assert p.stats["failed"] == 2


def test_close_drops_it():
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    p.close()
    assert p.state() == "cold" and built[0].control.closed


def test_a_one_to_one_call_uses_the_spare_and_builds_nothing():
    import asyncio
    import otrv4plus_voice as V
    p, now, built = _path()
    p.warm("127.0.0.1", 7656)
    _settle(p)
    real, W.WARM = W.WARM, p
    loop = asyncio.new_event_loop()
    try:
        s = V.VoiceCallSession("bob@x.i2p", loop, b"\x01" * 16, True)
        if s._transport_mode != V.VOICE_TRANSPORT_DATAGRAM:
            return
        dest = loop.run_until_complete(s.create_session())
        assert dest == "dest0"
        assert s._sam_control is built[0].control
        assert s._dgram_sock is built[0].sock
    finally:
        W.WARM = real
        loop.close()
