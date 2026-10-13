# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Which transport a server is reached over -- and that clearnet never touches
the I2P router path.

THE REPORT
----------
Registering on `07f.de`, an ordinary clearnet XMPP server, from the handset:

    registration started -> checking_router -> failed        (3 ms)

No DNS, no TCP, no TLS. `controller_for` never set `use_i2p`, whose default
was True, so every server was an I2P server; the SAM bridge was probed, the
phone had no router, and the attempt ended before it began.

Nothing here special-cases `07f.de`: it is one of several ordinary names, and
the rule under test is the generic one in android_bridge/route.py.
"""
from __future__ import annotations

import os
import ssl
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import route as R  # noqa: E402
from android_bridge.connection import (  # noqa: E402
    ConnectionController, SamProbe, controller_for, probe_profile, probe_tor)
from android_bridge.settings import ConnectionProfile  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402
from android_bridge.transport import (  # noqa: E402
    TransportError, XmppTransport, endpoint_authenticated_by)
from tests.fake_sasl import sasl_plugins  # noqa: E402

B32 = "a" * 52 + ".b32.i2p"
ONION = "b" * 56 + ".onion"
CLEARNET = ("07f.de", "example.com", "xmpp.example.org")


# ── 1. classification: the one authority ─────────────────────────────────────

class TestOrdinaryNamesAreClearnet:

    @pytest.mark.parametrize("name", CLEARNET)
    def test_clearnet_tls(self, name):
        r = R.classify(name)
        assert r.kind == R.CLEARNET_TLS
        assert r.host == name
        assert r.verify_certificate is True
        assert r.resolver == "dns"
        assert r.port is None

    @pytest.mark.parametrize("raw,host", [
        ("07F.DE", "07f.de"), ("  Example.COM  ", "example.com"),
        ("xmpp.example.org.", "xmpp.example.org"), ("\t07f.de\n", "07f.de"),
    ])
    def test_case_whitespace_and_trailing_dot_do_not_matter(self, raw, host):
        r = R.classify(raw)
        assert (r.kind, r.host) == (R.CLEARNET_TLS, host)

    @pytest.mark.parametrize("name", ["www.07f.de", "www.example.com"])
    def test_www_is_irrelevant(self, name):
        assert R.classify(name).kind == R.CLEARNET_TLS

    def test_explicit_port(self):
        r = R.classify("xmpp.example.org:5223")
        assert (r.kind, r.host, r.port) == (R.CLEARNET_TLS, "xmpp.example.org", 5223)

    def test_ip_literals(self):
        assert R.classify("192.0.2.7").kind == R.CLEARNET_TLS
        r = R.classify("[2001:db8::1]:5222")
        assert (r.host, r.port) == ("2001:db8::1", 5222)


class TestI2PAndTorNames:

    def test_named_i2p_goes_to_sam_lookup(self):
        r = R.classify("otrv4plus.i2p")
        assert r.kind == R.I2P_SAM and r.resolver == "sam"
        assert r.self_authenticating is False, (
            "a human-readable .i2p name is bound by the address book, not by "
            "the key: X1 pinning applies to it")
        assert r.verify_certificate is False

    def test_b32_is_direct_and_self_authenticating(self):
        r = R.classify(B32.upper())
        assert r.kind == R.I2P_SAM and r.host == B32
        assert r.self_authenticating is True

    def test_onion_goes_to_tor(self):
        r = R.classify(ONION)
        assert r.kind == R.TOR and r.resolver == "tor"
        assert r.self_authenticating is True

    def test_i2p_port(self):
        assert R.classify("otrv4plus.i2p:5223").port == 5223


class TestOverrides:

    def test_clearnet_name_over_tor_keeps_certificate_checks(self):
        r = R.classify("07f.de", "tor")
        assert r.kind == R.TOR
        assert r.verify_certificate is True, (
            "a Tor exit authenticates nothing about a clearnet server")
        assert r.self_authenticating is False

    def test_explicit_clearnet(self):
        assert R.classify("example.com", "clearnet_tls").kind == R.CLEARNET_TLS

    @pytest.mark.parametrize("name,override", [
        ("otrv4plus.i2p", "clearnet_tls"), ("otrv4plus.i2p", "tor"),
        (B32, "clearnet_tls"), (ONION, "clearnet_tls"), (ONION, "i2p_sam"),
        ("example.com", "i2p_sam"),
    ])
    def test_overrides_that_would_leak_a_name_are_refused(self, name, override):
        with pytest.raises(R.RouteError) as e:
            R.classify(name, override)
        assert e.value.code == "route_refused"

    def test_unknown_override(self):
        with pytest.raises(R.RouteError) as e:
            R.classify("example.com", "carrier-pigeon")
        assert e.value.code == "bad_transport"


class TestMalformed:

    @pytest.mark.parametrize("bad", [
        "", "   ", "bad..name", "-x.example.com", "a@example.com",
        "https://example.com", "example.com:0", "example.com:70000",
        "example.com:port", "exa mple.com", "localhostx", "[::1",
        "short.b32.i2p", "notv3.onion", ":5222",
    ])
    def test_rejected_before_any_network(self, bad):
        with pytest.raises(R.RouteError) as e:
            R.classify(bad)
        assert e.value.code in ("malformed_server", "no_server")


# ── 2. the profile Kotlin builds ─────────────────────────────────────────────

class TestTheProfileKotlinBuilds:
    """`controller_for` is the entry point Kotlin calls, with jid and server
    only. This is the exact path of the report."""

    @pytest.mark.parametrize("domain", CLEARNET)
    def test_controller_for_a_clearnet_account_is_clearnet(self, domain):
        ctl = controller_for(object(), "alice@" + domain, "")
        assert ctl._profile.route.kind == R.CLEARNET_TLS

    def test_controller_for_the_default_server_is_i2p(self):
        ctl = controller_for(object(), "alice@otrv4plus.i2p", "")
        assert ctl._profile.route.kind == R.I2P_SAM

    def test_a_stale_use_i2p_flag_decides_nothing(self):
        p = ConnectionProfile.from_dict(
            {"jid": "alice@07f.de", "server": "", "use_i2p": True})
        assert p.route.kind == R.CLEARNET_TLS

    def test_the_profile_round_trips_the_override(self):
        p = ConnectionProfile(jid="a@07f.de", transport="tor")
        q = ConnectionProfile.from_dict(p.to_dict())
        assert q.transport == "tor" and q.route.kind == R.TOR

    def test_policy_answer_follows_the_route(self):
        assert endpoint_authenticated_by(ConnectionProfile(jid="a@07f.de")) is None
        assert endpoint_authenticated_by(
            ConnectionProfile(jid="a@otrv4plus.i2p")) == "I2P"
        assert endpoint_authenticated_by(ConnectionProfile(jid="a@" + ONION)) == "Tor"
        assert endpoint_authenticated_by(
            ConnectionProfile(jid="a@07f.de", transport="tor")) is None


# ── 3. the controller: clearnet never enters the router path ─────────────────

class FakeApp:
    def __init__(self):
        self._transport = None

    def receive_message(self, *_a):
        pass

    def note_presence(self, *_a):
        pass

    def set_event_sink(self, sink):
        pass


class RecordingTransport:
    """Accepts what the real transport's constructor accepts."""

    def __init__(self, profile, password, *, on_payload, on_state=None,
                 fail=None, **_kw):
        self.profile = profile
        self.on_state = on_state
        self.fail = fail
        self.is_connected = False
        self.registered = False

    def connect(self):
        if self.fail:
            raise self.fail
        self.on_state and self.on_state("connecting", "")
        self.on_state and self.on_state("connected", "")
        self.is_connected = True

    def register_account(self):
        self.registered = True
        return "ok", "created"

    def close(self):
        self.is_connected = False


def _never_probe(*_a, **_kw):
    raise AssertionError("the I2P/Tor prober was called for a clearnet server")


def _controller(jid, *, prober=_never_probe, fail=None, server=""):
    made = {}

    def factory(p, password, **kw):
        made["t"] = RecordingTransport(p, password, fail=fail, **kw)
        return made["t"]

    ctl = ConnectionController(FakeApp(), ConnectionProfile(jid=jid, server=server),
                               transport_factory=factory, prober=prober)
    seen = []
    ctl._on_state = lambda s, _srv: seen.append(s)
    return ctl, made, seen


class TestClearnetNeverEntersCheckingRouter:

    @pytest.mark.parametrize("domain", CLEARNET)
    def test_connect(self, domain):
        TRACE.clear()
        ctl, made, seen = _controller("alice@" + domain)
        got = ctl.connect("pw")
        assert got["ok"], got
        assert "checking_router" not in seen and "checking_tor" not in seen
        assert got["route"] == R.CLEARNET_TLS
        ev = [e for e in TRACE.events() if e.get("event") == "selected"]
        assert ev and "clearnet_tls" in str(ev[-1])

    @pytest.mark.parametrize("domain", CLEARNET)
    def test_register(self, domain):
        ctl, made, seen = _controller("alice@" + domain)
        got = ctl.register("pw")
        assert got["ok"], got
        assert made["t"].registered
        assert "checking_router" not in seen

    def test_a_clearnet_failure_is_its_own_not_the_routers(self):
        ctl, _, seen = _controller(
            "alice@07f.de",
            fail=TransportError("stream_failed", "the TLS handshake failed"))
        got = ctl.connect("pw")
        assert not got["ok"]
        assert got["code"] == "stream_failed"
        assert "checking_router" not in seen
        assert "router" not in got["detail"].lower()
        assert "i2p" not in got["detail"].lower()

    def test_i2p_still_checks_the_router(self):
        called = []
        ctl, _, seen = _controller(
            "alice@otrv4plus.i2p",
            prober=lambda p, **k: called.append(p) or SamProbe(True, "ok", "", "3.1"))
        assert ctl.connect("pw")["ok"]
        assert called and seen[0] == "checking_router"

    def test_i2p_without_a_router_fails_at_checking_router(self):
        ctl, made, seen = _controller(
            "alice@otrv4plus.i2p",
            prober=lambda p, **k: SamProbe(False, "refused", "start i2pd"))
        got = ctl.connect("pw")
        assert got["code"] == "refused" and "t" not in made

    def test_onion_checks_tor_not_the_router(self):
        ctl, _, seen = _controller(
            "alice@" + ONION,
            prober=lambda p, **k: SamProbe(True, "ok", ""))
        assert ctl.connect("pw")["ok"]
        assert "checking_tor" in seen and "checking_router" not in seen

    def test_onion_without_tor_fails_closed(self):
        ctl, made, seen = _controller(
            "alice@" + ONION,
            prober=lambda p, **k: SamProbe(False, "tor_unavailable", "start Orbot"))
        got = ctl.connect("pw")
        assert not got["ok"] and got["code"] == "tor_unavailable"
        assert "t" not in made, "no transport, so no DNS and no clearnet fallback"

    def test_a_malformed_server_fails_before_anything(self):
        ctl, made, seen = _controller("alice@07f.de", server="bad..name")
        got = ctl.connect("pw")
        assert not got["ok"] and "t" not in made
        assert "checking_router" not in seen

    def test_probe_profile_for_clearnet_does_not_touch_sam(self, monkeypatch):
        import android_bridge.connection as C
        monkeypatch.setattr(C, "probe_sam", _never_probe)
        monkeypatch.setattr(C, "probe_tor", _never_probe)
        assert probe_profile(ConnectionProfile(jid="a@07f.de")).reachable


class TestTorProbe:

    class _Sock:
        def __init__(self, reply):
            self.reply, self.sent = reply, b""

        def settimeout(self, _t):
            pass

        def sendall(self, b):
            self.sent += b

        def recv(self, _n):
            return self.reply

        def close(self):
            pass

    def test_socks5_greeting_ok(self):
        s = self._Sock(b"\x05\x00")
        assert probe_tor("127.0.0.1", 9050, opener=lambda *a, **k: s).reachable
        assert s.sent == b"\x05\x01\x00", "greeting only: no CONNECT, no name"

    def test_nothing_listening(self):
        def refuse(*_a, **_k):
            raise ConnectionRefusedError()
        got = probe_tor("127.0.0.1", 9050, opener=refuse)
        assert not got.reachable and got.code == "tor_unavailable"

    def test_not_socks(self):
        got = probe_tor("127.0.0.1", 9050,
                        opener=lambda *a, **k: self._Sock(b"HTTP/1.1"))
        assert not got.reachable and got.code == "tor_unavailable"


# ── 4. the real transport: where slixmpp is pointed, and with what TLS ───────

class FakeClient:
    """Enough of slixmpp.ClientXMPP for connect()."""

    def __init__(self, jid, password):
        self.plugin = sasl_plugins()
        self.handlers = {}
        self.connected_to = None
        self.ssl_context = "slixmpp-default"
        self.client_roster = {}
        self.features = {"starttls"}

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def register_plugin(self, _name):
        pass

    def __getitem__(self, name):
        return self.plugin[name]

    def add_filter(self, *_a, **_k):
        pass

    def connect(self, host=None, port=None):
        self.connected_to = (host, port)
        for fn in list(self.handlers.get("session_start", [])):
            fn(None)

    def send_presence(self, **_k):
        pass

    def get_roster(self, **_k):
        pass

    def abort(self):
        pass

    def disconnect(self, *_a, **_k):
        pass


def _transport(jid, server="", transport="auto"):
    made = {"forward": [], "tor": []}

    def factory(j, p):
        made["client"] = FakeClient(j, p)
        return made["client"]

    async def forwarder(*a, verify=None, **k):
        made["forward"].append(a)
        return ("127.0.0.1", 41000)

    async def tor_forwarder(*a, **k):
        made["tor"].append(a)
        return ("127.0.0.1", 42000)

    t = XmppTransport(ConnectionProfile(jid=jid, server=server, transport=transport),
                      "pw", on_payload=lambda *a: None, client_factory=factory,
                      forwarder=forwarder, tor_forwarder=tor_forwarder)
    return t, made


class TestTheRealTransportOnClearnet:

    @pytest.mark.parametrize("domain", CLEARNET)
    def test_srv_lookup_no_forwarder_default_tls(self, domain):
        t, made = _transport("alice@" + domain)
        try:
            t.connect()
            assert made["client"].connected_to == (None, None), (
                "the JID's own domain: slixmpp does SRV, then the domain:5222")
            assert made["forward"] == [] and made["tor"] == []
            assert made["client"].ssl_context == "slixmpp-default", (
                "clearnet keeps slixmpp's CERT_REQUIRED context untouched")
            assert made["client"].plugin["feature_mechanisms"].use_mechs is None
        finally:
            t.close()

    def test_explicit_server_and_port(self):
        t, made = _transport("alice@example.com", server="xmpp.example.org:5223")
        try:
            t.connect()
            assert made["client"].connected_to == ("xmpp.example.org", 5223)
            assert made["forward"] == []
        finally:
            t.close()

    def test_no_tls_means_no_password(self):
        """slixmpp does not insist on STARTTLS; the transport does."""
        t, made = _transport("alice@07f.de")

        def connect(host=None, port=None):
            c = made["client"]
            c.features = set()
            for fn in list(c.handlers.get("failed_auth", [])):
                fn(None)

        try:
            orig = FakeClient.connect
            FakeClient.connect = lambda self, host=None, port=None: connect(host, port)
            with pytest.raises(TransportError) as e:
                t.connect()
            assert e.value.code == "tls_required"
        finally:
            FakeClient.connect = orig
            t.close()


class TestTheRealTransportOnTorAndI2P:

    def test_onion_uses_the_tor_forwarder_only(self):
        t, made = _transport("alice@" + ONION)
        try:
            t.connect()
            assert made["tor"] and made["tor"][0][0] == ONION
            assert made["forward"] == []
            assert made["client"].connected_to == ("127.0.0.1", 42000)
            mech = made["client"].plugin["feature_mechanisms"]
            assert mech.use_mechs and all(m.startswith("SCRAM-") for m in mech.use_mechs)
        finally:
            t.close()

    def test_tor_that_fails_does_not_fall_back(self):
        t, made = _transport("alice@" + ONION)

        async def dead(*_a, **_k):
            raise ConnectionRefusedError("no Orbot")

        t._tor_forwarder = dead
        try:
            with pytest.raises(TransportError) as e:
                t.connect()
            assert e.value.code == "tor_unavailable"
            assert "client" not in made or made["client"].connected_to is None
            assert made["forward"] == []
        finally:
            t.close()

    def test_b32_uses_the_sam_forwarder(self):
        t, made = _transport("alice@" + B32)
        try:
            t.connect()
            assert made["forward"] and made["forward"][0][0] == B32
            assert made["tor"] == []
        finally:
            t.close()

    def test_a_forwarder_that_cannot_verify_is_refused(self):
        """X1: without the destination check, a substituted server could
        receive the stream; the transport refuses to go on."""
        t, made = _transport("alice@otrv4plus.i2p")

        async def old(dest, port, sam_host, sam_port):
            raise AssertionError("must not be called")

        t._forwarder = old
        try:
            with pytest.raises(TransportError) as e:
                t.connect()
            assert e.value.code == "forwarder_import_failed"
        finally:
            t.close()


class TestNothingWeakensTLS:
    """A source-level guard: the only CERT_NONE context in the transport is the
    one behind endpoint_authenticated_by, and nothing trusts all."""

    def test_source(self):
        src = open(os.path.join(ROOT, "android_bridge", "transport.py")).read()
        assert src.count("ssl.CERT_NONE") == 1
        assert src.count("check_hostname = False") == 1
        for bad in ("_create_unverified_context", "verify=False",
                    "CERT_OPTIONAL", "trust_all", "trustAll"):
            assert bad not in src, bad
        route_src = open(os.path.join(ROOT, "android_bridge", "route.py")).read()
        assert "07f" not in route_src.replace("`07f.de`", ""), (
            "no special case for the server in the report")

    def test_default_slixmpp_context_verifies(self):
        import slixmpp
        c = slixmpp.ClientXMPP("a@07f.de", "x")
        ctx = c.ssl_context
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
