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

from source_of import transport_source  # noqa: E402
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
    src = transport_source()
    assert 'if _accepts(forward, "hold"):' in src
    assert 'extra["hold"] = True' in src


class SlowSam(FlakySam):
    """STREAM CONNECT that never answers the first `stalls` times -- a server
    whose tunnel the router cannot reach yet. Then it answers OK."""

    def __init__(self, stalls):
        self.stalls = stalls
        super().__init__(failures=0)

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
                        if self.stalls > 0:
                            self.stalls -= 1
                            while conn.recv(4096):      # never answers
                                pass
                            return
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


@pytest.fixture
def slow_sam(monkeypatch):
    monkeypatch.setattr(otr.I2PSAMConnection, "reply_timeout", 1)
    s = SlowSam(stalls=1)
    X.HELD_SAM.drop()
    yield s
    X.HELD_SAM.drop()
    s.close()


def test_a_stream_connect_that_times_out_is_a_stream_failure(slow_sam):
    """Device report (2026-11-04): a server blip became an 18-minute, six-
    attempt reconnect, and the error said the SAM bridge was unreachable
    although it answered. A STREAM CONNECT that times out was classified as a
    BRIDGE failure, so its session was thrown away and every retry built
    tunnels from cold with a new destination. It is a stream failure: the
    session is held, the retry reuses it, and the code is not sam_unavailable."""
    with pytest.raises(Exception) as caught:
        _attempt(slow_sam.port, hold=True)
    assert getattr(caught.value, "stage", "") == "stream", caught.value
    assert getattr(caught.value, "result", "") == "TIMEOUT"
    assert X.HELD_SAM.holding, "the built session was thrown away"
    _attempt(slow_sam.port, hold=True)        # the retry works, on the same session
    assert slow_sam.sessions_created() == 1, slow_sam.commands


def test_timeouts_are_reported_by_the_stage_that_stalled():
    from android_bridge.transport import _sam_failure
    stream = otr.SamError("stream", "x did not answer", "TIMEOUT")
    session = otr.SamError("session", "tunnels not built", "TIMEOUT")
    assert _sam_failure(stream, "s.i2p").code == "i2p_destination_unreachable"
    assert _sam_failure(session, "s.i2p").code == "i2p_session_failed"


def test_a_bridge_failure_says_which_kind_without_the_reply():
    from android_bridge.transport import _sam_failure
    err = _sam_failure(otr.SamError("bridge", "SAM bridge closed connection"), "s.i2p")
    assert err.code == "sam_unavailable" and "(closed)" in str(err)
    err = _sam_failure(otr.SamError("bridge", "SAM handshake failed: HELLO REPLY RESULT=NOVERSION"), "s.i2p")
    assert "(handshake)" in str(err) and "NOVERSION" not in str(err)
