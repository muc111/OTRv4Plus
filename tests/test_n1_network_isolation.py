# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""N1 -- the route decides the network, for the whole process.

  .i2p / .b32.i2p  only the local SAM bridge: no other socket, no DNS at all
  .onion           only the local Tor SOCKS port: no other socket, no DNS
  anything else    TLS with certificate checks (route.py), DNS allowed
  every route      an .i2p or .onion name never reaches a resolver

`android_bridge.route` already chose the transport from the name; this pins
that the choice is ENFORCED (`otrv4plus_egress`, a CPython audit hook), from
the route gate that sign-in, account creation and the server test all pass
first, so no authentication or registration byte -- and nothing a library
does -- can leave another way. Router choice stays localhost-only: no LAN
address, scan or discovery is ever tried.

Scope, stated rather than implied: the rule binds the app's own code (Python
and Kotlin). The bundled i2pd is a separate native process whose reseed and
router-to-router links are its own; a local I2P app on 127.0.0.1:7656, when
present, is preferred and the bundled router then does not run.
"""
import asyncio
import io
import os
import re
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))
import otrv4plus_egress as N                                           # noqa: E402

KT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                  "android", "connection")
EXTERNAL = ("198.51.100.7", 5222)            # TEST-NET-2: never routable


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture
def events():
    """Every socket and resolver audit event while the test runs."""
    seen = []
    live = [True]

    def hook(event, args):
        if live[0] and event.startswith("socket.") and event != "socket.__new__":
            seen.append((event, args[1] if event in N._SEND_EVENTS and len(args) > 1
                         else args[0] if args else None))

    sys.addaudithook(hook)
    yield seen
    live[0] = False


# ── the rule itself ─────────────────────────────────────────────────────────

class TestTheRule:
    @pytest.mark.parametrize("mode", ["i2p_sam", "tor"])
    def test_loopback_only_routes(self, mode):
        N.check_connect(("127.0.0.1", 7656), mode, set())
        N.check_connect(("::1", 9050), mode, set())
        with pytest.raises(N.EgressRefused):
            N.check_connect(EXTERNAL, mode, set())
        with pytest.raises(N.EgressRefused):
            N.check_connect(("example.org", 443), mode, set())
        for ok in ("localhost", "127.0.0.1", None, ""):
            N.check_resolve(ok, mode)
        with pytest.raises(N.EgressRefused):
            N.check_resolve("example.org", mode)
        with pytest.raises(N.EgressRefused):
            N.check_reverse("8.8.8.8", mode)
        N.check_reverse(("127.0.0.1", 0), mode)

    @pytest.mark.parametrize("mode", ["clearnet_tls", "none"])
    def test_open_routes(self, mode):
        N.check_connect(EXTERNAL, mode, set())
        N.check_resolve("example.org", mode)

    @pytest.mark.parametrize("mode", ["i2p_sam", "tor", "clearnet_tls", "none"])
    @pytest.mark.parametrize("name", ["server.i2p", "abcd.b32.i2p", "x.onion", "X.ONION.", b"y.i2p"])
    def test_hidden_names_never_reach_a_resolver(self, mode, name):
        with pytest.raises(N.EgressRefused):
            N.check_resolve(name, mode)
        with pytest.raises(N.EgressRefused):
            N.check_connect((name, 80), mode, set())

    def test_an_explicit_bridge_elsewhere_must_be_an_ip_and_is_the_only_exception(self):
        N.enter("i2p_sam", ("192.168.1.10", 7656))
        N.check_connect(("192.168.1.10", 7656))
        with pytest.raises(N.EgressRefused):
            N.check_connect(("192.168.1.10", 7657))
        with pytest.raises(N.EgressRefused):
            N.check_connect(("192.168.1.11", 7656))
        with pytest.raises(N.EgressRefused):
            N.enter("i2p_sam", ("router.lan", 7656))


# ── enforced on the real socket calls ───────────────────────────────────────

class TestEnforced:
    def test_on_i2p_nothing_leaves_but_loopback(self):
        N.enter("i2p_sam", ("127.0.0.1", 7656))
        before = N.refusals()
        s = socket.socket()
        try:
            with pytest.raises(N.EgressRefused):
                s.connect(EXTERNAL)
        finally:
            s.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(N.EgressRefused):
                u.sendto(b"x", EXTERNAL)
            u.sendto(b"x", ("127.0.0.1", 9))           # SAM datagrams: allowed
        finally:
            u.close()
        for call in ((socket.getaddrinfo, ("example.org", 443)),
                     (socket.gethostbyname, ("example.org",)),
                     (socket.gethostbyaddr, ("8.8.8.8",))):
            with pytest.raises(N.EgressRefused):
                call[0](*call[1])
        assert N.refusals() - before == 5

    def test_asyncio_lookups_are_refused_too(self):
        N.enter("tor", ("127.0.0.1", 9050))

        async def go():
            return await asyncio.get_event_loop().getaddrinfo("example.org", 443)
        with pytest.raises(N.EgressRefused):
            asyncio.run(go())

    def test_a_dot_i2p_lookup_is_refused_even_on_clearnet(self):
        N.enter("clearnet_tls")
        with pytest.raises(N.EgressRefused):
            socket.getaddrinfo("server.i2p", 5222)

    def test_no_resolver_that_bypasses_the_hook_on_a_hidden_route(self):
        resolver = pytest.importorskip("slixmpp.xmlstream.resolver")
        N.enter("clearnet_tls")
        had = resolver.AIODNS_AVAILABLE
        N.enter("i2p_sam", ("127.0.0.1", 7656))
        assert resolver.AIODNS_AVAILABLE is False, "c-ares would resolve outside the hook"
        N.enter("tor", ("127.0.0.1", 9050))
        assert resolver.AIODNS_AVAILABLE is False
        N.leave()
        assert resolver.AIODNS_AVAILABLE == had

    def test_signed_out_is_no_route(self):
        N.enter("i2p_sam", ("127.0.0.1", 7656))
        N.leave()
        assert N.mode() == N.NONE


# ── the gate every connection passes, before any byte ───────────────────────

def _controller(server, sam_host="127.0.0.1"):
    from android_bridge.connection import ConnectionController
    from android_bridge.settings import ConnectionProfile
    profile = ConnectionProfile(jid="alice@" + server, server=server,
                                sam_host=sam_host, sam_port=7656)
    seen = {}

    def prober(p):
        seen["mode"] = N.mode()                        # what was in force then
        from android_bridge.connection import SamProbe
        return SamProbe(False, "refused", "stub: stop here")

    ctl = ConnectionController.__new__(ConnectionController)
    ctl._profile, ctl._prober, ctl._stage = profile, prober, "idle"
    ctl._probe_version = ""
    ctl._enter = lambda stage: None
    return ctl, seen


class TestTheGate:
    @pytest.mark.parametrize("server,mode", [
        ("example.i2p", "i2p_sam"), ("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.b32.i2p", "i2p_sam"),
        ("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion", "tor"),
    ])
    def test_the_rule_is_in_force_before_the_bridge_is_even_probed(self, server, mode):
        ctl, seen = _controller(server)
        refused = ctl._gate_route()
        assert refused is not None and seen["mode"] == mode

    def test_clearnet_is_clearnet(self):
        ctl, _seen = _controller("example.org")
        assert ctl._gate_route() is None and N.mode() == "clearnet_tls"

    def test_a_bridge_named_by_a_hostname_is_refused_before_any_lookup(self, events):
        ctl, seen = _controller("example.i2p", sam_host="router.lan")
        refused = ctl._gate_route()
        assert refused.code == "bridge_not_local" and "mode" not in seen
        assert not [e for e in events if e[0] in N._RESOLVE_EVENTS]

    def test_sign_in_account_creation_and_the_server_test_all_pass_it_first(self):
        src = _read(ROOT, "android_bridge", "connection.py")
        for fn in ("def _connect(self, password: str)", "def _register(self, password: str)",
                   "def test_server(self)"):
            body = src[src.index(fn):]
            body = body[:body.index("\n    def ", 10)]
            first = body.index("self._gate_route()")
            for later in ("self._transport_factory", "_transport_factory(", "register(", "connect("):
                i = body.find(later, first + 1)
                assert i == -1 or i > first, (fn, later)

    def test_the_whole_sam_path_touches_only_loopback(self, events, monkeypatch):
        """Through the Android transport's own endpoint, with the real SAM
        forwarder and a scripted SAM bridge: every socket event is to
        loopback and nothing is resolved."""
        import test_i2p_naming_no_dns as F
        from android_bridge import transport as T, server_pins as _sp
        from android_bridge.settings import ConnectionProfile
        import otrv4plus_xmpp
        monkeypatch.setattr(F.otr, "i2p_hosts_path", lambda: os.devnull)
        monkeypatch.setattr(F.otr, "i2p_hosts_defaults_path", lambda: os.devnull)
        fake = F.FakeSam(names={F.NEW: F.DEST})
        profile = ConnectionProfile(jid="alice@" + F.NEW, server=F.NEW,
                                    sam_host="127.0.0.1", sam_port=fake.port)
        N.enter("i2p_sam", ("127.0.0.1", fake.port))
        t = T.XmppTransport.__new__(T.XmppTransport)
        t._profile, t._forwarder = profile, otrv4plus_xmpp.start_i2p_sam_forwarder
        t._i2p_resources, t._emit_state = [], (lambda *a, **k: None)
        t._route, t._tor_forwarder, t._server_pins = profile.route, None, _sp.ServerPins(None)
        before = N.refusals()
        try:
            host, _port = asyncio.run(t._endpoint())
        finally:
            for r in t._i2p_resources:
                try:
                    r.close()
                except Exception:
                    pass
            fake.close()
        assert host == "127.0.0.1" and fake.connected_to() == [F.DEST]
        sends = [a for e, a in events if e in N._SEND_EVENTS and isinstance(a, tuple)]
        assert sends and all(N._is_loopback(a[0]) for a in sends), sends
        names = [a for e, a in events if e in N._RESOLVE_EVENTS + N._REVERSE_EVENTS]
        assert all(a in (None, "", "localhost") or N._is_ip(a) for a in names), names
        assert N.refusals() == before, "nothing even tried to leave"


# ── router choice: localhost only ───────────────────────────────────────────

class TestLocalhostOnlyRouter:
    def test_the_probe_asks_loopback_7656_and_nothing_else(self):
        src = _read(KT, "RouterChoice.kt")
        probe = src[src.index("fun probeSam("):src.index("fun findExternalSam(")]
        assert 'java.net.InetSocketAddress("127.0.0.1", port)' in probe
        assert "const val EXTERNAL_SAM_PORT = 7656" in src

    def test_no_lan_address_scan_or_discovery_anywhere(self):
        for name in os.listdir(KT):
            if not name.endswith(".kt"):
                continue
            src = _read(KT, name)
            for bad in ("NsdManager", "MulticastSocket", "WifiManager", "192.168.",
                        "10.0.", "InetAddress.getByName", "getAllByName", "mdns", "jmdns"):
                assert bad not in src, (name, bad)

    def test_the_bundled_router_listens_on_loopback_only(self):
        src = _read(KT, "RouterChoice.kt")
        sam = src[src.index("|[sam]"):src.index("|[bob]")]
        assert "|address = 127.0.0.1" in sam
        for off in ("[http]", "[httpproxy]", "[socksproxy]", "[i2pcontrol]", "[upnp]"):
            block = src[src.index("|" + off):]
            assert "enabled = false" in block[:60], off

    def test_sign_out_stops_the_bundled_router(self):
        svc = _read(KT, "OtrConnectionService.kt")
        logout = svc[svc.index("ACTION_LOGOUT -> {"):][:600]
        assert "stopConnection(explicit = true, stopRouter = true)" in logout


# ── the terminal client and packaging ───────────────────────────────────────

class TestTheTerminalAndTheApk:
    def test_the_terminal_enforces_before_any_tunnel(self):
        src = _read(ROOT, "client", "otrv4plus_xmpp.py")
        fn = src[src.index("def _open_connection("):]
        assert fn.index("_egress.enter(kind, bridge=bridge)") < fn.index("start_i2p_sam_forwarder")

    def test_no_i2p_with_an_i2p_server_is_refused(self):
        import types
        import otrv4plus_xmpp as X
        args = types.SimpleNamespace(jid="a@server.i2p", server="", no_i2p=True,
                                     no_tor=False, tor=False)
        with pytest.raises(SystemExit):
            X._choose_transport(args)

    def test_the_apk_carries_the_rule_and_no_network_library(self):
        gradle = _read(ROOT, "android", "app", "build.gradle.kts")
        assert '"otrv4plus_egress.py",' in gradle
        gradle = re.sub(r"//[^\n]*", "", gradle)           # what is built, not what is said
        deps = re.findall(r'^\s*implementation\("([^"]+)"\)', gradle, re.M)
        assert deps and all(d.startswith("androidx.") for d in deps), deps
        pips = re.findall(r'install\("([^"=]+)', gradle)
        # aiodns (c-ares) would resolve names outside Python's socket layer,
        # where the audit hook cannot see it: it must never be installed.
        assert set(pips) <= {"otrv4_core", "PySocks", "slixmpp", "pyasn1", "pyasn1-modules"}, pips
        assert "aiodns" not in pips and "pycares" not in pips
        assert "import otrv4plus_egress as _egress" in _read(ROOT, "android_bridge", "connection.py")

    def test_the_desktop_warns_under_a_bridge_elsewhere(self):
        src = _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop",
                    "ui", "ConnectScreen.kt")
        assert "Text(SAM_ELSEWHERE_WARNING" in src and "has no password" in src

    def test_sign_out_leaves_the_route(self):
        app = _read(ROOT, "android_bridge", "app.py")
        shutdown = app[app.index("    def shutdown(self) -> None:"):]
        shutdown = shutdown[:shutdown.index("\n    @property")]
        assert "otrv4plus_egress.leave()" in shutdown
