# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Qubes SAM relay (qubes/relay/otrv4plus-qubes-relay).

On Qubes the chat qube has no network and the router is in sys-i2p.
qubes.ConnectTCP carries SAM streams but not the UDP datagrams voice calls
use; the relay carries both. Here qrexec-client-vm is replaced by a stand-in
that runs the service end locally and connects ConnectTCP to a stand-in SAM
router, so the whole path runs: client -> proxy -> "qrexec" -> service ->
router, and back.
"""
import importlib.machinery
import importlib.util
import os
import socket
import subprocess
import shutil
import sys
import tempfile
import textwrap
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELAY = os.path.join(ROOT, "qubes", "relay", "otrv4plus-qubes-relay")

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux sockets")


def _load():
    loader = importlib.machinery.SourceFileLoader("otrv4plus_qubes_relay", RELAY)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _free(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakeRouter:
    """Enough of i2pd's SAM: HELLO, a datagram SESSION CREATE that records
    the forward port, STREAM CONNECT that echoes, and a UDP port that answers
    each datagram to the session's forward port, as a repliable datagram."""

    SOURCE = b"A" * 80

    def __init__(self):
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.forward = {}
        self.lines = []
        threading.Thread(target=self._accept, daemon=True).start()
        threading.Thread(target=self._datagrams, daemon=True).start()

    def _accept(self):
        while True:
            conn, _ = self.tcp.accept()
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        f = conn.makefile("rb")
        while True:
            line = f.readline()
            if not line:
                return
            self.lines.append(line)
            words = line.decode().split()
            if words[:1] == ["HELLO"]:
                conn.sendall(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            elif words[:2] == ["SESSION", "CREATE"]:
                opts = dict(w.split("=", 1) for w in words if "=" in w)
                self.forward[opts["ID"]] = int(opts["PORT"])
                conn.sendall(b"SESSION STATUS RESULT=OK DESTINATION=xyz\n")
            elif words[:2] == ["STREAM", "CONNECT"]:
                conn.sendall(b"STREAM STATUS RESULT=OK\n")
                while True:
                    data = f.read1(4096)
                    if not data:
                        return
                    conn.sendall(data)

    def _datagrams(self):
        while True:
            data, _ = self.udp.recvfrom(65535)
            head, payload = data.split(b"\n", 1)
            sid = head.split(b" ")[1].decode()
            if sid in self.forward:
                self.udp.sendto(self.SOURCE + b"\n" + payload.upper(),
                                ("127.0.0.1", self.forward[sid]))


@pytest.fixture
def relay():
    import pathlib
    # tempfile, not tmp_path: the suite's conftest stubs pwd, which
    # tmp_path's user lookup needs.
    tmp = tempfile.mkdtemp()
    router = FakeRouter()
    fake = pathlib.Path(tmp) / "qrexec-client-vm"
    fake.write_text(textwrap.dedent("""\
        #!%s
        # Stand-in for qrexec-client-vm: QUBE SERVICE, stdin/stdout joined to
        # the service in the "other qube" (here, this machine).
        import os, socket, sys, threading
        qube, service = sys.argv[1], sys.argv[2]
        if service == "otrv4plus.SamUdp":
            os.execv(sys.executable, [sys.executable, %r, "service"])
        assert service.startswith("qubes.ConnectTCP+"), service
        s = socket.create_connection(("127.0.0.1", int(os.environ["FAKE_ROUTER_TCP"])))
        def down():
            while True:
                d = s.recv(65536)
                if not d:
                    os._exit(0)
                sys.stdout.buffer.write(d); sys.stdout.buffer.flush()
        threading.Thread(target=down, daemon=True).start()
        while True:
            d = sys.stdin.buffer.read1(65536)
            if not d:
                break
            s.sendall(d)
        s.shutdown(socket.SHUT_WR)
        threading.Event().wait(2)
        """ % (sys.executable, RELAY)))
    fake.chmod(0o755)
    tcp, udp = _free(socket.SOCK_STREAM), _free(socket.SOCK_DGRAM)
    env = dict(os.environ,
               OTRV4PLUS_QREXEC_CLIENT=str(fake),
               OTRV4PLUS_RELAY_SAM_TCP=str(tcp),
               OTRV4PLUS_RELAY_SAM_UDP=str(udp),
               OTRV4PLUS_RELAY_ROUTER_UDP=str(router.udp.getsockname()[1]),
               FAKE_ROUTER_TCP=str(router.tcp.getsockname()[1]))
    proc = subprocess.Popen([sys.executable, RELAY, "proxy"], env=env,
                            stderr=subprocess.PIPE)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", tcp), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("proxy did not start: %s" % proc.stderr.read().decode())
    yield router, tcp, udp
    proc.kill()
    proc.wait()
    shutil.rmtree(tmp, ignore_errors=True)


def _line(f):
    return f.readline().decode().strip()


def _datagram_session(tcp, sid):
    """A client's call setup: its own UDP port, a datagram session naming it."""
    mine = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mine.bind(("127.0.0.1", 0))
    mine.settimeout(5)
    ctrl = socket.create_connection(("127.0.0.1", tcp), timeout=10)
    f = ctrl.makefile("rb")
    ctrl.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
    assert _line(f).startswith("HELLO REPLY RESULT=OK")
    ctrl.sendall(b"SESSION CREATE STYLE=DATAGRAM ID=%s DESTINATION=TRANSIENT "
                 b"SIGNATURE_TYPE=7 PORT=%d HOST=127.0.0.1 inbound.length=3\n"
                 % (sid.encode(), mine.getsockname()[1]))
    assert _line(f).startswith("SESSION STATUS RESULT=OK")
    return ctrl, mine


class TestVoiceThroughTheRelay:

    def test_datagrams_both_ways(self, relay):
        router, tcp, udp = relay
        ctrl, mine = _datagram_session(tcp, "otrv4voice_1")
        # The router was told the relay's port in sys-i2p, not the client's.
        assert router.forward["otrv4voice_1"] != mine.getsockname()[1]
        assert any(b"inbound.length=3" in l for l in router.lines), "options kept"
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for n in range(5):
            out.sendto(b"3.0 otrv4voice_1 peerdest\nframe %d" % n, ("127.0.0.1", udp))
            data, _ = mine.recvfrom(65535)
            assert data == FakeRouter.SOURCE + b"\nFRAME %d" % n
        ctrl.close()

    def test_two_sessions_are_kept_apart(self, relay):
        router, tcp, udp = relay
        c1, m1 = _datagram_session(tcp, "otrv4voice_a")
        c2, m2 = _datagram_session(tcp, "otrv4gcall_b")
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.sendto(b"3.0 otrv4gcall_b d\nto b", ("127.0.0.1", udp))
        out.sendto(b"3.0 otrv4voice_a d\nto a", ("127.0.0.1", udp))
        assert m1.recvfrom(65535)[0].endswith(b"TO A")
        assert m2.recvfrom(65535)[0].endswith(b"TO B")
        c1.close()
        c2.close()

    def test_an_unknown_session_is_dropped(self, relay):
        router, tcp, udp = relay
        ctrl, mine = _datagram_session(tcp, "otrv4voice_k")
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.sendto(b"3.0 nobody d\nx", ("127.0.0.1", udp))
        out.sendto(b"garbage", ("127.0.0.1", udp))
        out.sendto(b"3.0 otrv4voice_k d\nreal", ("127.0.0.1", udp))
        assert mine.recvfrom(65535)[0].endswith(b"REAL")
        mine.settimeout(0.5)
        with pytest.raises(socket.timeout):
            mine.recvfrom(65535)
        ctrl.close()

    def test_the_session_ends_with_its_control_connection(self, relay):
        router, tcp, udp = relay
        ctrl, mine = _datagram_session(tcp, "otrv4voice_e")
        ctrl.close()
        time.sleep(0.5)
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.sendto(b"3.0 otrv4voice_e d\nlate", ("127.0.0.1", udp))
        mine.settimeout(0.7)
        with pytest.raises(socket.timeout):
            mine.recvfrom(65535)


class TestStreamsAreUntouched:

    def test_stream_data_passes_byte_for_byte(self, relay):
        router, tcp, udp = relay
        ctrl = socket.create_connection(("127.0.0.1", tcp), timeout=10)
        f = ctrl.makefile("rb")
        ctrl.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
        _line(f)
        ctrl.sendall(b"STREAM CONNECT ID=s DESTINATION=x.i2p\n")
        assert _line(f) == "STREAM STATUS RESULT=OK"
        # After STREAM CONNECT the socket is data: a line that looks like a
        # command is the user's bytes and must not be acted on.
        payload = (b"SESSION CREATE STYLE=DATAGRAM ID=evil PORT=1 HOST=127.0.0.1\n"
                   + bytes(range(256)) * 40)
        ctrl.sendall(payload)
        got = b""
        while len(got) < len(payload):
            got += f.read1(65536)
        assert got == payload
        assert "evil" not in router.forward
        ctrl.close()


class TestParsing:

    def test_only_loopback_datagram_sessions_are_relayed(self):
        r = _load()
        assert r._session_create(b"SESSION CREATE STYLE=DATAGRAM ID=a PORT=5 HOST=127.0.0.1\n") == ("a", 5)
        assert r._session_create(b"SESSION CREATE STYLE=RAW ID=a PORT=5\n") == ("a", 5)
        assert r._session_create(b"SESSION CREATE STYLE=STREAM ID=a PORT=5\n") is None
        assert r._session_create(b"SESSION CREATE STYLE=DATAGRAM ID=a PORT=5 HOST=10.0.0.9\n") is None
        assert r._session_create(b"SESSION CREATE STYLE=DATAGRAM ID=a\n") is None

    def test_the_port_is_rewritten_and_nothing_else(self):
        r = _load()
        line = b"SESSION CREATE STYLE=DATAGRAM ID=a PORT=5 HOST=127.0.0.1 x=y\n"
        assert r._rewrite_port(line, 4242) == (
            b"SESSION CREATE STYLE=DATAGRAM ID=a PORT=4242 HOST=127.0.0.1 x=y\n")

    def test_the_client_needs_no_change(self, monkeypatch):
        # The proxy listens where the client already looks for SAM.
        for name in ("OTRV4PLUS_RELAY_SAM_UDP", "OTRV4PLUS_RELAY_SAM_TCP"):
            monkeypatch.delenv(name, raising=False)
        import otrv4plus_voice as V
        r = _load()
        assert r.SAM_UDP == V.SAM_UDP_PORT == 7655
        assert r.SAM_TCP == 7656
