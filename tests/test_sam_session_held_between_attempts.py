# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A failed sign-in attempt's I2P session is reused by the next attempt.

Owner (2026-10-17): "I2P router 0:02, sign-in 2:39, 10 attempts". Every
attempt made a new transient destination and a failed STREAM CONNECT closed
it, so each retry built tunnels and looked the server up from nothing. Now
the session is held (otrv4plus_xmpp.HeldSamSession) and the next attempt
tries again on it. The real I2PSAMConnection and the real forwarder, against
a scripted SAM bridge.
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
otr = pytest.importorskip("otrv4_")
import otrv4plus_xmpp as X                                           # noqa: E402

DEST = "A" * 516 + "AAAA"
NAME = "server.i2p"


class FlakySam:
    """A SAM bridge whose STREAM CONNECT fails `failures` times first."""

    def __init__(self, failures):
        self.failures = failures
        self.commands = []
        self.open_sessions = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        buf, session = b"", False
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode().strip()
                    self.commands.append(line.split()[0] + " " + line.split()[1])
                    if line.startswith("HELLO"):
                        out = "HELLO REPLY RESULT=OK VERSION=3.1"
                    elif line.startswith("NAMING LOOKUP"):
                        out = "NAMING REPLY RESULT=OK NAME=%s VALUE=%s" % (NAME, DEST)
                    elif line.startswith("SESSION CREATE"):
                        session = True
                        self.open_sessions += 1
                        out = "SESSION STATUS RESULT=OK DESTINATION=" + "C" * 600
                    elif line.startswith("STREAM CONNECT"):
                        if self.failures > 0:
                            self.failures -= 1
                            out = "STREAM STATUS RESULT=CANT_REACH_PEER"
                        else:
                            conn.sendall(b"STREAM STATUS RESULT=OK\n")
                            while conn.recv(4096):
                                pass
                            return
                    else:
                        out = "UNKNOWN"
                    conn.sendall((out + "\n").encode())
        except OSError:
            pass
        finally:
            if session:
                self.open_sessions -= 1
            conn.close()

    def sessions_created(self):
        return self.commands.count("SESSION CREATE")

    def close(self):
        self.sock.close()


@pytest.fixture
def sam():
    s = FlakySam(failures=2)
    X.HELD_SAM.drop()
    yield s
    X.HELD_SAM.drop()
    s.close()


def _attempt(port, hold):
    async def go():
        resources = []
        try:
            return await X.start_i2p_sam_forwarder(
                NAME, 5222, "127.0.0.1", port, resources=resources,
                log=lambda _l: None, aliases=False, hold=hold)
        finally:
            if resources:
                resources[0].close()
    return asyncio.run(go())


def _fails(port, hold):
    with pytest.raises(Exception) as caught:
        _attempt(port, hold)
    assert getattr(caught.value, "stage", "") == "stream"


def test_retries_reuse_the_failed_attempts_session(sam):
    _fails(sam.port, hold=True)
    assert X.HELD_SAM.holding
    _fails(sam.port, hold=True)
    _attempt(sam.port, hold=True)            # the third works
    assert sam.sessions_created() == 1, sam.commands
    assert sam.commands.count("STREAM CONNECT") == 3
    # A sign-in that worked owns its session; nothing is held for later.
    assert not X.HELD_SAM.holding


def test_without_hold_each_attempt_starts_again_as_before(sam):
    _fails(sam.port, hold=False)
    assert not X.HELD_SAM.holding
    _fails(sam.port, hold=False)
    assert sam.sessions_created() == 2


def test_drop_closes_the_held_session(sam):
    _fails(sam.port, hold=True)
    assert X.HELD_SAM.holding
    X.HELD_SAM.drop()
    assert not X.HELD_SAM.holding
    for _ in range(50):
        if sam.open_sessions == 0:
            break
        threading.Event().wait(0.02)
    assert sam.open_sessions == 0


def test_a_held_session_for_another_server_is_not_used(sam):
    _fails(sam.port, hold=True)
    assert X.HELD_SAM.take(("127.0.0.1", sam.port, "other.i2p")) is None
    assert not X.HELD_SAM.holding


def test_sign_out_drops_it():
    from android_bridge import connection
    held = X.HELD_SAM
    closed = []
    held.keep(("h", 1, "n"), type("S", (), {"close": lambda self: closed.append(1)})())
    connection._drop_held_sam()
    assert closed == [1] and not held.holding


def test_the_android_transport_asks_for_it():
    src = open(os.path.join(ROOT, "android_bridge", "transport.py"), encoding="utf-8").read()
    assert 'if _accepts(forward, "hold"):' in src
    assert 'extra["hold"] = True' in src
