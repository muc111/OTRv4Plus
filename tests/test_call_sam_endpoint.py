# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A call's I2P tunnel goes to the connection's SAM bridge, not to 7656.

Device report, Pixel 7, 2026-10-24: `call_tunnel x2`, `call_rate_limited x3`,
the audio engine running with `peers=0`. The call manager was built with its
default SAM address, 127.0.0.1:7656, while the app's built-in router listens
on a random port. Every call tunnel dialled a port with nothing behind it
(and the ready-made call path, built on the right port and looked up by
address, was never used); the user's retries then hit the call-attempt
interval although no invitation had ever gone out.

These run the real bridge, the real VoiceCallManager and a real TCP listener
standing in for the router's SAM port, so what is checked is where the
manager actually connects.
"""
import socket
import threading
import time

import pytest

import otrv4plus_voice as voice
from test_android_calls import audio_available, pair, verified, voice_log  # noqa: F401


class _SamStandIn:
    """A listener on a random loopback port that records each connection and
    closes it, so the manager's SAM handshake fails fast after reaching it."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.hits += 1
            conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.fixture(autouse=True)
def _sam_helpers():
    """The terminal client's real SAM helpers, which importing it binds once
    per process; conftest restores the hooks after every test, so a later
    test would otherwise see them unbound."""
    import otrv4plus_xmpp as x
    voice.bind_host(sam_open=x._sam_open, sam_read_line=x._sam_read_line,
                    sam_parse=x._sam_parse)


@pytest.fixture
def sam():
    s = _SamStandIn()
    yield s
    s.close()


def _until(cond, seconds=15.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def test_the_manager_follows_the_connections_sam_port(pair):
    app = pair.alice
    app.sam_endpoint = ("127.0.0.1", 41234)
    manager = app.calls._ensure_manager()
    assert (manager.sam_host, manager.sam_port) == ("127.0.0.1", 41234)
    app.sam_endpoint = ("127.0.0.1", 41999)      # a new sign-in, a new router port
    app.calls._ensure_manager()
    assert manager.sam_port == 41999


def test_a_placed_call_builds_its_tunnel_on_that_port(verified, sam, voice_log):
    app, peer = verified.alice, verified.bob_jid
    app.sam_endpoint = ("127.0.0.1", sam.port)
    assert app.calls.start_call(peer) == "started"
    assert _until(lambda: sam.hits >= 1), (
        "the call tunnel never reached the connection's SAM port: %s" % voice_log)


def test_a_failed_tunnel_does_not_rate_limit_the_retry(verified, sam, voice_log):
    app, peer = verified.alice, verified.bob_jid
    app.sam_endpoint = ("127.0.0.1", sam.port)
    manager = app.calls._ensure_manager()
    app.calls.start_call(peer)
    assert _until(lambda: any("could not create SAM session" in l for l in voice_log))
    assert _until(lambda: peer not in manager._last_invite), \
        "no INVITE went out, so the attempt must not count"
    assert _until(lambda: not app.calls._live(peer))
    app.calls.start_call(peer)
    assert _until(lambda: sam.hits >= 2)
    assert not any("slow down" in l for l in voice_log), voice_log


def test_the_answering_side_builds_on_the_managers_port():
    # The callee's session is made in _on_invite from the manager's address,
    # which `_ensure_manager` has just synced (handle_signal calls it first).
    import inspect
    src = inspect.getsource(voice.VoiceCallManager._on_invite)
    assert "VoiceCallSession(peer, self.loop, call_id, False,\n" in src
    assert "self.sam_host, self.sam_port)" in src
    from android_bridge import voice as bridge
    assert "self._ensure_manager()" in inspect.getsource(bridge.CallBridge.handle_signal)
