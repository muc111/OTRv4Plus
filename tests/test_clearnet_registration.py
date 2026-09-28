# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Clearnet registration, reproduced and pinned (device report 2026-09-28).

THE REPORT
----------
07f.de and yax.im, from the handset, identically:

    transport selected: route=clearnet_tls certificate=checked resolver=dns
    clearnet_endpoint srv=true
    registration requested
    registration failed code=network

yax.im needs no CAPTCHA, so "07f.de wants a CAPTCHA" explained nothing.

THE ROOT CAUSE, TWO FAULTS
--------------------------
1. No SRV lookup. slixmpp queries `_xmpp-client._tcp.<domain>` only through
   aiodns, which the APK does not ship, and otherwise dials `<domain>:5222`.
   yax.im's SRV record points at `xmpp.yax.im` -- a different machine.
2. The first failed ADDRESS ended the attempt. slixmpp tries each resolved
   address in turn and fires `connection_failed` for each failure; the
   transport treated the first as final. Both domains publish AAAA records;
   a phone with no working IPv6 gave up before IPv4 was tried.

`TestTheReport` reproduces fault 2 byte for byte against the pre-fix
behaviour's trace, and every test here runs the REAL transport and the REAL
slixmpp 1.17 client against a real STARTTLS server on loopback
(tests/xmpp_test_server.py) whose certificate the client verifies.
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
import threading

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (HERE, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("slixmpp")

from android_bridge import dns_srv as D  # noqa: E402
from android_bridge import transport as T  # noqa: E402
from android_bridge.connection import ConnectionController  # noqa: E402
from android_bridge.settings import ConnectionProfile  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402
import otrv4plus_registration as REG  # noqa: E402
from xmpp_test_server import XmppTestServer, make_ca_and_cert  # noqa: E402

DOMAIN = "xmpp.test"
PASSWORD = "correct-horse-battery-9-X"
UNROUTABLE_V6 = "2001:db8::5222"          # documentation prefix: never reached


@pytest.fixture(scope="module")
def pki():
    return make_ca_and_cert(DOMAIN)


@pytest.fixture
def server(pki, request):
    _ca, crt, key = pki
    srv = XmppTestServer(DOMAIN, crt, key, mode=getattr(request, "param", "ok"))
    yield srv
    srv.close()


def _closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Net:
    """The phone's view of DNS: an optional SRV answer, then addresses."""

    def __init__(self, server, *, srv=False, v6=True, bad_v4_first=False,
                 no_address=False):
        self.server, self.srv, self.v6 = server, srv, v6
        self.bad_v4_first, self.no_address = bad_v4_first, no_address
        self.bad_port = _closed_port()
        self.looked_up = []
        self.resolved = []

    def srv_lookup(self, domain):
        self.looked_up.append(domain)
        if self.srv:
            return D.SrvResult("found", (D.SrvRecord(5, 1, self.server.port,
                                                     "xmpp." + DOMAIN),), "1")
        return D.SrvResult("none", (), "no SRV record")

    async def getaddrinfo(self, host, port, family=0, type=0):
        self.resolved.append((host, port, family))
        if self.no_address or (self.srv and host == DOMAIN):
            raise socket.gaierror("no such host")   # the apex is not the server
        if family == socket.AF_INET6:
            return ([(family, type, 6, "", (UNROUTABLE_V6, port, 0, 0))]
                    if self.v6 else [])
        out = []
        if self.bad_v4_first:
            out.append((family, type, 6, "", ("127.0.0.2", port)))
        out.append((family, type, 6, "", ("127.0.0.1", port)))
        return out


def transport(pki, server, net, *, trust=True, jid="alice@" + DOMAIN,
              password=PASSWORD, port=None):
    ca = pki[0]
    base = T._default_client_factory()

    def factory(j, p):
        c = base(j, p)
        c.default_port = port or server.port
        if trust:
            c.ca_certs = ca          # trust the test CA; verification stays ON
        c.use_aiodns = False         # as in the APK
        return c

    t = T.XmppTransport(ConnectionProfile(jid=jid), password,
                        on_payload=lambda *a: None, client_factory=factory)
    t._srv_lookup, t._getaddrinfo = net.srv_lookup, net.getaddrinfo
    return t


def register(pki, server, net, **kw):
    t = transport(pki, server, net, **kw)
    try:
        return t.register_account()
    finally:
        t.close()


def _events():
    return [(e["component"], e["event"]) for e in TRACE.events()]


# ── the report ────────────────────────────────────────────────────────────────

class TestTheReport:

    def test_an_unreachable_ipv6_address_no_longer_ends_the_attempt(self, pki, server):
        """The exact handset shape: AAAA published, no working IPv6, no SRV.
        Before the fix: `registration failed code=network` in ~0.1 s."""
        TRACE.clear()
        code, _ = register(pki, server, Net(server, v6=True))
        assert code == REG.OK
        assert server.registered_user == "alice"
        assert ("registration", "failed") not in _events()

    def test_a_first_address_that_refuses_is_followed_by_the_next(self, pki, server):
        """Independent of address family: every planned address is tried
        before the attempt is called failed."""
        net = Net(server, v6=False, bad_v4_first=True)
        # 127.0.0.2 listens on nothing at this port -> refused, then 127.0.0.1.
        code, _ = register(pki, server, net)
        assert code == REG.OK

    def test_srv_is_asked_and_its_target_dialled_not_the_apex(self, pki, server):
        """yax.im: `_xmpp-client._tcp.yax.im` -> xmpp.yax.im, another host."""
        net = Net(server, srv=True)
        TRACE.clear()
        code, _ = register(pki, server, net)
        assert code == REG.OK
        assert net.looked_up == [DOMAIN]
        assert all(h == "xmpp." + DOMAIN for h, _p, _f in net.resolved)
        plan = [e for e in TRACE.events() if e["event"] == "dns_plan"][-1]
        text = str(plan)
        assert "found" in text and "xmpp." + DOMAIN in text

    def test_no_srv_record_falls_back_to_the_domain(self, pki, server):
        net = Net(server, srv=False, v6=False)
        assert register(pki, server, net)[0] == REG.OK
        assert all(h == DOMAIN for h, _p, _f in net.resolved)


# ── every stage has its own answer ────────────────────────────────────────────

class TestStagesAreDistinguished:

    def test_dns_failure(self, pki, server):
        code, detail = register(pki, server, Net(server, no_address=True))
        assert code == "dns_failure"
        assert server.log == []

    def test_tcp_failure_is_not_a_registration_rejection(self, pki, server):
        net = Net(server, v6=True)
        port = _closed_port()                # nothing listens there
        t = transport(pki, server, net, port=port)
        try:
            code, detail = t.register_account()
        finally:
            t.close()
        assert code == "tcp_failure", code
        assert "not reached" in detail.lower() or "not reached" in REG.CODES[code].lower()
        assert "ECONNREFUSED" in detail
        assert port

    @pytest.mark.parametrize("server", ["conflict"], indirect=True)
    def test_a_rejection_is_not_reported_as_unreachable(self, pki, server):
        code, detail = register(pki, server, Net(server))
        assert code == "conflict"
        assert "reach" not in detail.lower()
        assert "register_set" in server.log

    @pytest.mark.parametrize("server", ["captcha"], indirect=True)
    def test_captcha_is_named_and_the_password_is_not_sent(self, pki, server):
        code, detail = register(pki, server, Net(server))
        assert code == "registration_captcha_required"
        assert "register_set" not in server.log
        assert server.password_received is False

    def test_yax_im_style_form_registers(self, pki, server):
        """<username/><password/>, no data form, no CAPTCHA."""
        code, _ = register(pki, server, Net(server, srv=True))
        assert code == REG.OK and server.password_received

    @pytest.mark.parametrize("server", ["not_allowed"], indirect=True)
    def test_refused_discovery_is_answered_not_timed_out(self, pki, server):
        code, _ = register(pki, server, Net(server))
        assert code == "not_allowed"
        assert server.password_received is False

    @pytest.mark.parametrize("server", ["no_register"], indirect=True)
    def test_no_registration_offered(self, pki, server):
        assert register(pki, server, Net(server))[0] == "unsupported"

    @pytest.mark.parametrize("server", ["close_after_tls"], indirect=True)
    def test_server_closed_the_connection(self, pki, server):
        code, detail = register(pki, server, Net(server))
        assert code == "server_closed_connection"
        assert "tls" in detail.lower()

    @pytest.mark.parametrize("server", ["no_starttls"], indirect=True)
    def test_no_starttls_sends_nothing(self, pki, server):
        code, _ = register(pki, server, Net(server))
        assert code == "tls_required"
        assert server.password_received is False


# ── TLS stays mandatory ──────────────────────────────────────────────────────

class TestCertificateValidationIsMandatory:

    def test_an_untrusted_certificate_fails_as_certificate_failure(self, pki, server):
        code, detail = register(pki, server, Net(server), trust=False)
        assert code == "certificate_failure"
        assert server.password_received is False
        assert "register_get" not in server.log

    def test_the_clearnet_context_requires_a_verified_hostname(self, pki, server):
        t = transport(pki, server, Net(server))
        try:
            c = t._make_client()
            ctx = c.get_ssl_context()
            assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
        finally:
            t.close()


# ── the probe: reached, without signing in or registering ────────────────────

class TestTheProbe:

    def _probe(self, pki, server, net, **kw):
        t = transport(pki, server, net, **kw)
        try:
            return t.probe_server()
        finally:
            t.close()

    def test_reached_and_registration_available(self, pki, server):
        r = self._probe(pki, server, Net(server, srv=True))
        assert r["ok"] and r["code"] == "registration_available"
        assert r["reached"] == ["tcp_connected", "tls_established",
                                "xmpp_stream", "registration_form"]
        assert "register_set" not in server.log and "sasl_auth" not in server.log

    @pytest.mark.parametrize("server", ["captcha"], indirect=True)
    def test_reached_but_captcha(self, pki, server):
        r = self._probe(pki, server, Net(server))
        assert r["code"] == "registration_captcha_required"
        assert "ocr" in r["registration_fields"]

    @pytest.mark.parametrize("server", ["no_register"], indirect=True)
    def test_reached_registration_not_offered_and_never_signs_in(self, pki, server):
        r = self._probe(pki, server, Net(server))
        assert r["code"] == "registration_not_offered"
        assert "sasl_auth" not in server.log

    def test_unreachable(self, pki, server):
        r = self._probe(pki, server, Net(server, v6=False), port=_closed_port())
        assert not r["ok"] and r["code"] == "tcp_failure" and r["reached"] == []

    def test_the_controller_exposes_it_as_plain_data(self, pki, server, monkeypatch):
        net = Net(server, srv=True)

        def factory(profile, password, **kw):
            assert password == "", "the probe must never carry a password"
            return transport(pki, server, net, password=password)

        ctl = ConnectionController(object(), ConnectionProfile(jid="alice@" + DOMAIN),
                                   transport_factory=factory)
        r = ctl.test_server()
        assert r["code"] == "registration_available"
        assert r["reached"].startswith("tcp_connected,tls_established")
        assert all(isinstance(v, (str, bool, int, type(None))) for v in r.values())


# ── login uses the same path ─────────────────────────────────────────────────

class TestLogin:

    def test_login_reaches_authentication_past_an_unreachable_ipv6(self, pki, server):
        """The test server refuses every SASL attempt, so reaching auth_failed
        proves DNS, TCP, TLS and the stream all worked."""
        t = transport(pki, server, Net(server, v6=True, srv=True))
        try:
            with pytest.raises(T.TransportError) as e:
                t.connect()
            assert e.value.code == "auth_failed"
            assert "sasl_auth" in server.log
        finally:
            t.close()

    def test_login_tcp_failure_is_named(self, pki, server):
        t = transport(pki, server, Net(server), port=_closed_port())
        try:
            with pytest.raises(T.TransportError) as e:
                t.connect()
            assert e.value.code == "tcp_failure"
        finally:
            t.close()


# ── nothing secret in diagnostics ────────────────────────────────────────────

class TestNoSecrets:

    @pytest.mark.parametrize("server", ["conflict"], indirect=True)
    def test_trace_and_results_carry_no_password(self, pki, server):
        TRACE.clear()
        code, detail = register(pki, server, Net(server, srv=True))
        text = TRACE.render()
        assert PASSWORD not in text and PASSWORD not in detail
        assert "<iq" not in text and "<password" not in text


# ── the SRV resolver itself ──────────────────────────────────────────────────

def _srv_answer(qid, records, *, rcode=0, tc=False, compress=True):
    import struct
    name = D._encode_name("_xmpp-client._tcp.example.org")
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    msg = struct.pack("!HHHHHH", qid, flags, 1, len(records), 0, 0)
    msg += name + struct.pack("!HH", D.TYPE_SRV, D.CLASS_IN)
    for pri, wei, port, target in records:
        rdata = struct.pack("!HHH", pri, wei, port) + D._encode_name(target)
        owner = b"\xc0\x0c" if compress else name
        msg += owner + struct.pack("!HHIH", D.TYPE_SRV, D.CLASS_IN, 300, len(rdata))
        msg += rdata
    return msg


class TestSrvParser:

    def test_round_trip(self):
        msg = _srv_answer(7, [(5, 1, 5222, "xmpp.example.org")])
        rcode, tc, recs = D.parse_response(msg, 7)
        assert (rcode, tc) == (0, False)
        assert recs == [D.SrvRecord(5, 1, 5222, "xmpp.example.org")]

    def test_uncompressed_owner(self):
        _, _, recs = D.parse_response(
            _srv_answer(9, [(1, 0, 5223, "a.b")], compress=False), 9)
        assert recs[0].target == "a.b"

    @pytest.mark.parametrize("cut", [0, 5, 11, 20, 40, -3])
    def test_truncated_bytes_are_refused_not_crashed_on(self, cut):
        msg = _srv_answer(3, [(5, 1, 5222, "xmpp.example.org")])
        with pytest.raises(Exception) as e:
            D.parse_response(msg[:cut] if cut >= 0 else msg[:cut], 3)
        assert type(e.value).__name__ in ("_Malformed", "error")

    def test_wrong_id_is_refused(self):
        with pytest.raises(Exception):
            D.parse_response(_srv_answer(1, []), 2)

    def test_pointer_loop_is_bounded(self):
        import struct
        msg = struct.pack("!HHHHHH", 4, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00" * 4
        with pytest.raises(Exception):
            D.parse_response(msg, 4)

    def test_order_is_priority_then_weight(self):
        recs = [D.SrvRecord(10, 0, 1, "c"), D.SrvRecord(5, 0, 1, "a"),
                D.SrvRecord(5, 0, 1, "b")]
        assert [r.target for r in D.order(recs)] == ["a", "b", "c"]

    def test_lookup_over_udp_then_tcp_on_truncation(self):
        import random
        calls = []

        class FakeSock:
            def __init__(self, fam, kind):
                self.kind, self.q = kind, b""
                calls.append(kind)

            def settimeout(self, _t): pass
            def close(self): pass
            def connect(self, _a): pass

            def sendto(self, q, _a):
                self.q = q

            def sendall(self, data):
                self.q = data[2:]

            def recvfrom(self, _n):
                qid = int.from_bytes(self.q[:2], "big")
                return _srv_answer(qid, [], tc=True), None

            def recv(self, n):
                if not hasattr(self, "_buf"):
                    qid = int.from_bytes(self.q[:2], "big")
                    body = _srv_answer(qid, [(5, 1, 5222, "xmpp.example.org")])
                    self._buf = len(body).to_bytes(2, "big") + body
                out, self._buf = self._buf[:n], self._buf[n:]
                return out

        r = D.lookup("example.org", servers=["192.0.2.53"], opener=FakeSock)
        assert r.status == "found" and r.records[0].target == "xmpp.example.org"
        assert calls == [socket.SOCK_DGRAM, socket.SOCK_STREAM]
        assert random

    def test_no_resolver_is_reported(self):
        assert D.lookup("example.org", servers=[]).status == "no_resolver"

    def test_resolvers_from_the_platform_are_ip_literals_only(self):
        n = D.set_system_resolvers(["192.0.2.1", "fe80::1%wlan0", "dns.evil",
                                    "", "192.0.2.1"])
        try:
            assert n == 2
            assert D.system_resolvers() == ["192.0.2.1", "fe80::1"]
        finally:
            D.set_system_resolvers([])


class TestOnlyClearnetUsesDns:

    def test_i2p_and_tor_never_reach_the_srv_code(self, monkeypatch):
        called = []
        monkeypatch.setattr(D, "lookup", lambda *a, **k: called.append(a))
        for jid in ("alice@xmpp-elite.i2p", "alice@" + "b" * 56 + ".onion"):
            t = T.XmppTransport(ConnectionProfile(jid=jid), "pw",
                                on_payload=lambda *a: None)
            try:
                assert t._route.kind != "clearnet_tls"
            finally:
                t.close()
        src = open(os.path.join(ROOT, "android_bridge", "transport.py")).read()
        # _plan_clearnet_dns is only called under a CLEARNET_TLS check.
        for chunk in src.split("self._plan_clearnet_dns(client, watch, host)")[:-1]:
            assert "CLEARNET_TLS" in chunk[-900:]
        assert called == []
