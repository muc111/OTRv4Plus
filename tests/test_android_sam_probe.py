"""The probe that turns a four-minute hang into a sentence.

The connection path has five places to fail. Rolled into one "could not
connect" they are indistinguishable, and the first two are separated by seconds
while the third takes up to four minutes -- SAM_CONNECT_TIMEOUT is 240s because
building an I2P tunnel is genuinely slow. Someone whose router is not running
would watch a spinner for four minutes and learn nothing.

So these tests are mostly about *which* sentence comes out, and they are worth
their length for that reason alone.

Half of them run against a real loopback socket rather than a fake. A probe is
a thing that opens a socket; a probe tested only against an injected opener has
had the one interesting part stubbed out.
"""

import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.connection import (
    SAM_HELLO, SAM_PROBE_TIMEOUT, SamProbe, probe_profile, probe_sam,
)
from android_bridge.settings import ConnectionProfile


class FakeBridge:
    """A socket server that answers the way something on that port might."""

    def __init__(self, reply=b"HELLO REPLY RESULT=OK VERSION=3.1\n",
                 *, silent=False, drop=False):
        self.reply = reply
        self.silent = silent
        self.drop = drop
        self.seen = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            if self.drop:
                conn.close()
                return
            conn.settimeout(5)
            self.seen.append(conn.recv(256))
            if not self.silent:
                conn.sendall(self.reply)
                # Held open briefly so the probe reads before the close.
                conn.settimeout(1)
                try:
                    conn.recv(1)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestAgainstARealSocket:

    def test_a_sam_bridge_is_recognised(self):
        bridge = FakeBridge()
        try:
            got = probe_sam(bridge.host, bridge.port)
            assert got.reachable and got.code == "ok"
            assert got.version == "3.1"
        finally:
            bridge.close()

    def test_it_sends_the_samv3_hello(self):
        bridge = FakeBridge()
        try:
            probe_sam(bridge.host, bridge.port)
            assert bridge.seen and bridge.seen[0] == SAM_HELLO
        finally:
            bridge.close()

    def test_it_does_not_create_a_session(self):
        """SESSION CREATE makes i2pd build tunnels before replying -- minutes,
        on a phone. The question here is only whether a router exists."""
        bridge = FakeBridge()
        try:
            probe_sam(bridge.host, bridge.port)
            assert b"SESSION" not in b"".join(bridge.seen)
        finally:
            bridge.close()

    def test_nothing_listening_says_start_your_router(self):
        got = probe_sam("127.0.0.1", free_port())
        assert not got.reachable
        assert got.code == "refused"
        assert "sam.enabled" in got.detail, (
            "the message should name the i2pd setting, because that is the "
            "thing the user has to change")

    def test_something_else_on_the_port_is_named_as_such(self):
        bridge = FakeBridge(reply=b"220 smtp.example ESMTP\r\n")
        try:
            got = probe_sam(bridge.host, bridge.port)
            assert not got.reachable and got.code == "not_sam"
            assert "not as a SAM bridge" in got.detail
        finally:
            bridge.close()

    def test_a_port_that_accepts_then_drops_is_not_a_crash(self):
        bridge = FakeBridge(drop=True)
        try:
            got = probe_sam(bridge.host, bridge.port)
            assert not got.reachable and got.code == "not_sam"
        finally:
            bridge.close()

    def test_a_silent_port_does_not_hang_forever(self):
        """A probe that reads until newline from an arbitrary service is how a
        probe becomes the hang it was written to prevent."""
        bridge = FakeBridge(silent=True)
        try:
            got = probe_sam(bridge.host, bridge.port, timeout=1.0)
            assert not got.reachable
        finally:
            bridge.close()

    def test_a_flood_without_a_newline_is_bounded(self):
        bridge = FakeBridge(reply=b"x" * 100000)
        try:
            got = probe_sam(bridge.host, bridge.port, timeout=2.0)
            assert not got.reachable and got.code == "not_sam"
        finally:
            bridge.close()


class TestTheBudgetIsTheRightOne:

    def test_the_probe_is_not_the_tunnel_timeout(self):
        """SAM_CONNECT_TIMEOUT is 240s because tunnels are slow. A HELLO is a
        local handshake and must not inherit that budget -- waiting minutes to
        find out a port is closed is the failure being prevented."""
        assert SAM_PROBE_TIMEOUT <= 10

    def test_a_refusal_is_quick(self):
        import time
        start = time.time()
        probe_sam("127.0.0.1", free_port())
        assert time.time() - start < 5


class TestTheErrorsAreDistinguishable:
    """Five failures, five sentences. Rolled into one they are useless."""

    def _with_opener(self, exc):
        def opener(*_a, **_kw):
            raise exc
        return probe_sam("127.0.0.1", 7656, opener=opener)

    def test_refused(self):
        assert self._with_opener(ConnectionRefusedError()).code == "refused"

    def test_timeout(self):
        assert self._with_opener(socket.timeout()).code == "timeout"

    def test_other_oserrors_are_unreachable_not_refused(self):
        got = self._with_opener(OSError("ENETUNREACH"))
        assert got.code == "unreachable"

    def test_an_oserror_message_is_not_quoted_back(self):
        """An OSError's text carries paths and addresses."""
        got = self._with_opener(OSError("/data/data/com.example/secret.sock"))
        assert "secret.sock" not in got.detail
        assert "OSError" in got.detail

    def test_every_code_is_one_of_the_documented_set(self):
        allowed = {"ok", "refused", "timeout", "not_sam", "unreachable"}
        for exc in (ConnectionRefusedError(), socket.timeout(), OSError("x")):
            assert self._with_opener(exc).code in allowed


class TestTheProfileShortcut:

    def test_a_clearnet_profile_is_not_told_its_router_is_missing(self):
        """There is no SAM bridge in that path; reporting one as unreachable
        would be a false alarm about a component that is not in use."""
        p = ConnectionProfile(jid="a@b.test", server="b.test", use_i2p=False)
        got = probe_profile(p)
        assert got.reachable and "no SAM bridge needed" in got.detail

    def test_an_i2p_profile_probes_its_configured_bridge(self):
        seen = {}

        def opener(addr, _timeout):
            seen["addr"] = addr
            raise ConnectionRefusedError()

        p = ConnectionProfile(jid="a@b.i2p", server="b.i2p",
                              sam_host="10.0.0.9", sam_port=7000)
        probe_profile(p, opener=opener)
        assert seen["addr"] == ("10.0.0.9", 7000)


class TestItCrossesToKotlinCleanly:

    def test_as_dict_carries_the_four_fields(self):
        got = SamProbe(True, "ok", "fine", "3.1").as_dict()
        assert got == {"reachable": True, "code": "ok",
                       "detail": "fine", "version": "3.1"}

    def test_a_probe_result_is_not_an_exception(self):
        """"No router" is the expected state on a fresh install, not an error
        condition, and the screen renders it as guidance."""
        assert not isinstance(probe_sam("127.0.0.1", free_port()),
                              BaseException)
