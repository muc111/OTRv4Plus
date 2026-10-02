# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the server says over I2P reaches the user, at once.

Device report, 2026-10-02 (rc.16): the tunnel to otrv4plus.i2p opened, the
server sent 492 bytes of XMPP, and the client closed the stream 2 s later --
with no reason recorded and the attempt left waiting for its 300 s timeout.
A server's stream error (`host-unknown` for a domain it does not serve) was
handled on clearnet only (`_StreamWatch`); over I2P and Tor it was dropped.

These run the REAL XmppTransport and the real slixmpp against a scripted XMPP
server on 127.0.0.1, reached through a forwarder that stands in for the SAM
tunnel.
"""

import os
import socket
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

pytest.importorskip("slixmpp")

from android_bridge import transport as T  # noqa: E402
from android_bridge.settings import ConnectionProfile  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402

JID = "alice@otrv4plus.i2p"
HEADER = ("<?xml version='1.0'?><stream:stream "
          "xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' "
          "id='0f1e2d3c' from='otrv4plus.i2p' version='1.0' "
          "xmlns='jabber:client'>")
HOST_UNKNOWN = ("<stream:error><host-unknown "
                "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>This server "
                "does not serve otrv4plus.i2p</text></stream:error>")
MECHS = ("<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
         "%s</mechanisms></stream:features>")


class XmppServer:
    """Answers the client's stream header with `reply`, records every byte,
    and (with close=True) hangs up straight after."""

    def __init__(self, reply: str, close: bool = False):
        self.reply, self.close_after = reply.encode(), close
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        conn.settimeout(10)
        answered = False
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                self.received += data
                if not answered and b"<stream:stream" in self.received:
                    conn.sendall(self.reply)
                    answered = True
                    if self.close_after:
                        conn.close()
                        return
        except OSError:
            pass

    def stop(self):
        self.sock.close()


def _attempt(server, monkeypatch, timeout=20.0):
    monkeypatch.setattr(T, "CONNECT_TIMEOUT", timeout)

    async def forward(dest, port, sam_host, sam_port, **_kw):
        return ("127.0.0.1", server.port)

    TRACE.clear()
    t = T.XmppTransport(ConnectionProfile(jid=JID, server="otrv4plus.i2p"),
                        "not-the-password", on_payload=lambda *a: None,
                        forwarder=forward)
    started = time.monotonic()
    try:
        with pytest.raises(T.TransportError) as exc:
            t.connect()
    finally:
        t.close()
        server.stop()
    return exc.value, time.monotonic() - started


class TestAStreamErrorIsReportedAtOnce:

    def test_host_unknown_names_the_domain_and_does_not_wait(self, monkeypatch):
        err, took = _attempt(XmppServer(HEADER + HOST_UNKNOWN), monkeypatch)
        assert err.code == "xmpp_stream_failure"
        assert "host-unknown" in err.detail
        assert "otrv4plus.i2p" in err.detail and "VirtualHost" in err.detail
        assert took < 10, "waited for the timeout instead of failing"

    def test_the_condition_is_traced_but_not_the_servers_text(self, monkeypatch):
        _attempt(XmppServer(HEADER + HOST_UNKNOWN), monkeypatch)
        (ev,) = [e for e in TRACE.events(200) if e["event"] == "stream_error"]
        assert ev["fields"]["condition"] == "host-unknown"
        assert "does not serve" not in repr(TRACE.events(200))

    def test_a_server_that_hangs_up_says_where(self, monkeypatch):
        err, took = _attempt(XmppServer(HEADER, close=True), monkeypatch)
        assert err.code in ("server_closed_connection", "xmpp_stream_failure",
                            "stream_failed")
        assert took < 10


class TestSignInRulesAreUnchanged:

    def test_plain_only_is_still_refused_and_said_at_once(self, monkeypatch):
        server = XmppServer(HEADER + MECHS % "<mechanism>PLAIN</mechanism>")
        err, took = _attempt(server, monkeypatch)
        assert err.code == "no_safe_auth_mechanism"
        assert b"<auth" not in server.received
        assert took < 10


def test_the_meaning_of_each_condition():
    profile = ConnectionProfile(jid=JID, server="otrv4plus.i2p")
    assert "does not host otrv4plus.i2p" in T._stream_error_text(
        "host-unknown", profile)
    assert "(undefined-condition)" in T._stream_error_text(
        "undefined-condition", profile)


SHIPPED_B32 = "nquyxk5atgvp5yn3d4czvtb4qavysbxwjormmewhoyrdux5i4ika.b32.i2p"


class TestAnAccountOnTheShippedB32IsAnAccountOnItsName:
    """Device report, 2026-10-02: the client sent 179 bytes -- the stream
    header with to='<b32>' (60 characters where otrv4plus.i2p is 13; the
    header for otrv4plus.i2p is 132 bytes) -- and the server, which hosts
    otrv4plus.i2p, refused the domain. The JID had been built from a server
    typed as the b32 ("Custom"), which was the only way to reach the server
    before rc.15, and the app remembers it."""

    @pytest.mark.parametrize("jid,server", [
        ("alice@" + SHIPPED_B32, SHIPPED_B32),          # Custom: the b32
        ("alice@" + SHIPPED_B32, ""),                    # remembered account
        ("Alice@" + SHIPPED_B32.upper(), ""),
    ])
    def test_the_jid_takes_the_servers_name(self, jid, server):
        p = ConnectionProfile(jid=jid, server=server)
        assert p.jid.lower() == "alice@otrv4plus.i2p"
        assert p.route.kind == "i2p_sam"

    def test_other_addresses_are_left_alone(self):
        for jid in ("bob@other.i2p", "bob@" + "a" * 52 + ".b32.i2p",
                    "carol@07f.de"):
            assert ConnectionProfile(jid=jid).jid == jid

    def test_the_server_is_greeted_as_otrv4plus_i2p(self, monkeypatch):
        server = XmppServer(HEADER + HOST_UNKNOWN)
        monkeypatch.setattr(T, "CONNECT_TIMEOUT", 20.0)

        async def forward(dest, port, sam_host, sam_port, **_kw):
            return ("127.0.0.1", server.port)

        t = T.XmppTransport(
            ConnectionProfile(jid="alice@" + SHIPPED_B32, server=SHIPPED_B32),
            "not-the-password", on_payload=lambda *a: None, forwarder=forward)
        try:
            with pytest.raises(T.TransportError):
                t.connect()
        finally:
            t.close()
            server.stop()
        assert b"to='otrv4plus.i2p'" in server.received
        assert SHIPPED_B32.encode() not in server.received


STARTTLS = ("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
            "<required/></starttls></stream:features>")
PROCEED = b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
#: A fatal TLS alert, handshake_failure (40): what OpenSSL sends when the
#: server has no certificate/key it can use.
ALERT_HANDSHAKE_FAILURE = b"\x15\x03\x03\x00\x02\x02\x28"


class TlsRefusingServer(XmppServer):
    """Offers STARTTLS, says proceed, then answers the client's TLS hello
    with a fatal alert -- the device report's 670 bytes received."""

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        conn.settimeout(10)
        stage = 0
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                self.received += data
                if stage == 0 and b"<stream:stream" in self.received:
                    conn.sendall((HEADER + STARTTLS).encode())
                    stage = 1
                elif stage == 1 and b"<starttls" in self.received:
                    conn.sendall(PROCEED)
                    stage = 2
                elif stage == 2 and data[:1] == b"\x16":
                    conn.sendall(ALERT_HANDSHAKE_FAILURE)
                    stage = 3
        except OSError:
            pass


class TestATlsFailureSaysWhyAndBlamesNoCertificate:

    def test_handshake_failure_is_reported_at_once(self, monkeypatch):
        err, took = _attempt(TlsRefusingServer(""), monkeypatch)
        assert err.code == "tls_failed"
        assert "HANDSHAKE_FAILURE" in err.detail.upper()
        assert "not a certificate check" in err.detail
        assert "prosodyctl check certs" in err.detail
        assert took < 10

    def test_the_reason_is_traced(self, monkeypatch):
        _attempt(TlsRefusingServer(""), monkeypatch)
        (ev,) = [e for e in TRACE.events(200) if e["event"] == "tls_failed"]
        assert "HANDSHAKE_FAILURE" in ev["fields"]["reason"].upper()


def test_the_terminal_client_uses_the_same_rule():
    """otrv4plus_xmpp.main() rewrites --jid with canonical_jid, the function
    the Android profile uses."""
    import inspect
    import otrv4plus_address as A
    import otrv4plus_xmpp
    assert "_address.canonical_jid(args.jid)" in inspect.getsource(
        otrv4plus_xmpp.main)
    assert A.canonical_jid("bob@" + SHIPPED_B32) == "bob@otrv4plus.i2p"
    assert A.canonical_jid("bob@" + SHIPPED_B32 + "/termux") == \
        "bob@otrv4plus.i2p/termux"
    assert A.canonical_jid("bob@other.i2p") == "bob@other.i2p"
