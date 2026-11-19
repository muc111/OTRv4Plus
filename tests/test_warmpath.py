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


def _path(fail=False, gate=None, ready_age=0.0):
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

    return (W.WarmPath(build=build, clock=lambda: now[0], keep=600.0,
                       ready_age=ready_age), now, built)


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


def test_held_from_sign_in_without_any_chat_and_without_a_countdown():
    p, now, built = _path()
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    now[0] += 10 * 3600                        # hours later, nothing looked at
    assert p.describe() == {"state": "ready", "seconds_left": 0}
    p.warm("127.0.0.1", 7656)                  # a chat's ask does not shorten it
    now[0] += 3600
    assert p.state() == "ready" and len(built) == 1


def test_a_dead_session_is_replaced():
    p, now, built = _path()
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    p.alive = lambda spare: spare is not built[0]
    p.check()
    _settle(p)
    assert built[0].control.closed and p.stats["dead"] == 1
    assert p.state() == "ready" and len(built) == 2


def test_taking_while_held_builds_the_next():
    p, now, built = _path()
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    p.take(("127.0.0.1", 7656))
    _settle(p)
    assert p.state() == "ready" and len(built) == 2


def test_sign_out_stops_holding():
    p, now, built = _path()
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    p.close()
    p.check()
    _settle(p)
    assert p.state() == "cold" and len(built) == 1


def test_a_new_spare_is_amber_until_it_has_settled():
    """Owner, 2026-11-11: green only once the tunnel has been prepared long
    enough. Built is amber with a countdown; settled is green."""
    p, now, built = _path(ready_age=60.0)
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    assert len(built) == 1
    assert p.describe() == {"state": "warming", "seconds_left": 60}
    now[0] += 45
    assert p.describe() == {"state": "warming", "seconds_left": 15}
    now[0] += 15
    assert p.describe() == {"state": "ready", "seconds_left": 0}


def test_a_settling_spare_is_still_handed_to_a_call():
    """Amber is a warning, not a lock: a young spare beats building one."""
    p, now, built = _path(ready_age=60.0)
    p.hold("127.0.0.1", 7656, check=0)
    _settle(p)
    assert p.state() == "warming"
    assert p.take(("127.0.0.1", 7656)) is built[0]


def test_while_the_tunnels_build_there_is_no_countdown():
    gate = threading.Event()
    p, now, built = _path(gate=gate, ready_age=60.0)
    assert p.warm("127.0.0.1", 7656) == "warming"
    assert p.describe() == {"state": "warming", "seconds_left": 0}
    gate.set()
    _settle(p)


def test_the_default_needs_a_minute():
    assert W.READY_AGE == 60.0
    assert W.WarmPath()._ready_age == W.READY_AGE
