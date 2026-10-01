#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""An .i2p address is resolved by the ROUTER over SAM, never by DNS.

Device report, 2026-09-28: a newly created I2P server entered by name in the
Android app could not be reached. Every path for that name ended at the OLD
destination without asking the router:

  * the app's "default server" was the old server's b32, compiled in
    (`android_bridge/settings.DEFAULT_SERVER`), and a remembered account on
    that domain was routed to it;
  * a name typed as a custom server was rewritten, BEFORE any NAMING LOOKUP,
    by the shipped alias file (`i2p_hosts.defaults`), which mapped the
    project's server name to that same old b32;
  * `controller_for` substituted the default whenever the route was blank,
    so an account on any other server could be sent to the default one.

The model these tests pin:
  * `x.i2p`     -> `NAMING LOOKUP NAME=x.i2p`, first and always;
  * `x.b32.i2p` -> resolved by SAM from the hash, no alias consulted;
  * INVALID_KEY / KEY_NOT_FOUND / malformed / timeout -> a classified
    failure, never a fallback to DNS or to a remembered destination;
  * no hostname resolution at all, instrumented rather than assumed.
"""

import asyncio
import os
import socket
import sys
import tempfile
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
otr = pytest.importorskip("otrv4_")

DEST = "A" * 516 + "AAAA"                       # a well-formed base64 destination
OTHER_DEST = "B" * 520
B32 = "abcd" * 13 + ".b32.i2p"                  # 52 chars of a-z2-7
NEW = "newserver.i2p"


class FakeSam:
    """A scripted SAM v3.1 bridge on 127.0.0.1. Records every command."""

    def __init__(self, names=None, naming_reply=None, stream_result="OK",
                 hello="HELLO REPLY RESULT=OK VERSION=3.1", silent_on=None,
                 raw_naming=None):
        self.names = dict(names or {})
        self.naming_reply = naming_reply
        self.raw_naming = raw_naming
        self.stream_result = stream_result
        self.hello = hello
        self.silent_on = silent_on
        self.commands = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        f = conn.makefile("rb")
        try:
            for raw in f:
                line = raw.decode().strip()
                self.commands.append(line)
                if self.silent_on and line.startswith(self.silent_on):
                    continue                           # never answer
                if line.startswith("HELLO"):
                    out = self.hello
                elif line.startswith("NAMING LOOKUP"):
                    name = line.split("NAME=", 1)[1]
                    if self.raw_naming is not None:
                        conn.sendall(self.raw_naming)
                        continue
                    if self.naming_reply:
                        out = self.naming_reply.format(name=name)
                    elif name in self.names:
                        out = "NAMING REPLY RESULT=OK NAME=%s VALUE=%s" % (name, self.names[name])
                    else:
                        out = "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=%s" % name
                elif line.startswith("SESSION CREATE"):
                    out = "SESSION STATUS RESULT=OK DESTINATION=" + "C" * 600
                elif line.startswith("STREAM CONNECT"):
                    out = "STREAM STATUS RESULT=%s" % self.stream_result
                else:
                    out = "UNKNOWN"
                conn.sendall((out + "\n").encode())
        except OSError:
            pass

    def close(self):
        self._stop = True
        self.sock.close()

    def looked_up(self):
        return [c.split("NAME=", 1)[1] for c in self.commands if c.startswith("NAMING LOOKUP")]

    def connected_to(self):
        return [c.split("DESTINATION=", 1)[1].split()[0]
                for c in self.commands if c.startswith("STREAM CONNECT")]


@pytest.fixture
def no_dns(monkeypatch):
    """Any hostname resolution at all fails the test."""
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args[:1])
        raise AssertionError("hostname resolution attempted: %r" % (args[:1],))

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                 "gethostbyaddr", "getnameinfo", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    return calls


@pytest.fixture
def aliases(monkeypatch):
    """A user alias file mapping names to OTHER_DEST's b32, and empty shipped
    defaults, so a test can tell 'router answered' from 'alias used'."""
    d = tempfile.mkdtemp()
    user = os.path.join(d, "i2p_hosts")
    with open(user, "w") as fh:
        fh.write("%s = %s\n" % (NEW, B32))
        fh.write("known-only-locally.i2p = %s\n" % B32)
    defaults = os.path.join(d, "defaults")
    open(defaults, "w").close()
    monkeypatch.setattr(otr, "i2p_hosts_path", lambda: user)
    monkeypatch.setattr(otr, "i2p_hosts_defaults_path", lambda: defaults)
    return user


def _sam(fake, timeout=5):
    c = otr.I2PSAMConnection("127.0.0.1", fake.port)
    c.reply_timeout = timeout
    return c


class TestShortNames:
    def test_a_short_name_is_looked_up_by_the_router(self, no_dns, aliases):
        fake = FakeSam(names={NEW: DEST})
        sock = _sam(fake).connect(NEW)
        sock.close()
        assert fake.looked_up() == [NEW]
        assert fake.connected_to() == [DEST]
        assert no_dns == []

    def test_the_router_beats_a_local_alias(self, no_dns, aliases):
        """The device bug: the name used to be rewritten to a remembered
        destination before the router was asked. Now the router is asked
        first and its answer is used, whatever the file says."""
        fake = FakeSam(names={NEW: DEST, B32: OTHER_DEST})
        _sam(fake).connect(NEW).close()
        assert fake.looked_up() == [NEW]
        assert fake.connected_to() == [DEST]

    def test_an_alias_only_when_the_router_does_not_know_the_name(self, no_dns, aliases):
        fake = FakeSam(names={B32: OTHER_DEST})
        _sam(fake).connect("known-only-locally.i2p").close()
        assert fake.looked_up() == ["known-only-locally.i2p", B32]
        assert fake.connected_to() == [OTHER_DEST]

    def test_aliases_off_means_the_file_is_never_used(self, no_dns, aliases):
        """How the Android app calls it."""
        fake = FakeSam(names={B32: OTHER_DEST})
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect("known-only-locally.i2p", allow_aliases=False)
        assert exc.value.stage == "naming" and exc.value.result == "KEY_NOT_FOUND"
        assert fake.looked_up() == ["known-only-locally.i2p"]
        assert fake.connected_to() == []

    def test_an_unknown_name_fails_cleanly(self, no_dns, aliases):
        fake = FakeSam()
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect("unknown.i2p")
        assert exc.value.stage == "naming"
        assert not any(c.startswith(("SESSION", "STREAM")) for c in fake.commands)
        assert no_dns == []

    def test_invalid_key_fails_cleanly_with_no_fallback(self, no_dns, aliases):
        fake = FakeSam(naming_reply="NAMING REPLY RESULT=INVALID_KEY NAME={name}")
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert (exc.value.stage, exc.value.result) == ("naming", "INVALID_KEY")
        assert fake.looked_up() == [NEW], "INVALID_KEY fell back to something"
        assert fake.connected_to() == []


class TestB32:
    def test_a_b32_is_resolved_from_the_hash_with_no_alias(self, no_dns, monkeypatch):
        d = tempfile.mkdtemp()
        user = os.path.join(d, "hosts")
        with open(user, "w") as fh:          # an attempt to redirect a b32
            fh.write("%s = %s\n" % (B32, "e" * 52 + ".b32.i2p"))
        monkeypatch.setattr(otr, "i2p_hosts_path", lambda: user)
        fake = FakeSam(names={B32: DEST})
        _sam(fake).connect(B32).close()
        assert fake.looked_up() == [B32]
        assert fake.connected_to() == [DEST]
        assert no_dns == []

    def test_an_upper_case_b32_is_the_same_address(self, no_dns, aliases):
        fake = FakeSam(names={B32: DEST})
        _sam(fake).connect(B32.upper()).close()
        assert fake.connected_to() == [DEST]


class TestMalformed:
    @pytest.mark.parametrize("bad", [
        "example.com", "server", "bad name.i2p", "x\n.i2p", "x.i2p\nSTREAM CONNECT",
        "-bad.i2p", "a..i2p", "abc.b32.i2p", "a" * 52 + "1.b32.i2p", "", ".i2p",
    ])
    def test_a_malformed_address_never_reaches_sam(self, no_dns, bad):
        fake = FakeSam()
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(bad)
        assert exc.value.stage == "naming"
        assert fake.commands == [], "a malformed address was sent to SAM"

    def test_a_reply_for_another_name_is_refused(self, no_dns, aliases):
        fake = FakeSam(naming_reply="NAMING REPLY RESULT=OK NAME=other.i2p VALUE=" + DEST)
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert exc.value.stage == "bridge"
        assert fake.connected_to() == []

    @pytest.mark.parametrize("reply", [
        "NAMING REPLY RESULT=OK NAME={name}",
        "NAMING REPLY RESULT=OK NAME={name} VALUE=short",
        "NAMING REPLY RESULT=OK NAME={name} VALUE=" + "!" * 600,
        "GARBAGE",
        "NAMING REPLY NAME={name}",
    ])
    def test_a_malformed_naming_reply_is_a_bridge_fault(self, no_dns, aliases, reply):
        fake = FakeSam(naming_reply=reply)
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert exc.value.stage in ("bridge", "naming")
        assert fake.connected_to() == []

    def test_an_oversized_reply_is_refused(self, no_dns, aliases):
        fake = FakeSam(raw_naming=b"NAMING REPLY RESULT=OK VALUE=" + b"A" * 100000)
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert exc.value.stage == "bridge"

    def test_a_non_ascii_reply_is_refused(self, no_dns, aliases):
        fake = FakeSam(raw_naming="NAMING REPLY RESULT=OK VALUE=é\n".encode())
        with pytest.raises(otr.SamError):
            _sam(fake).connect(NEW)


class TestBridgeFailures:
    def test_no_bridge(self, no_dns):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        c = otr.I2PSAMConnection("127.0.0.1", port)
        with pytest.raises(otr.SamError) as exc:
            c.connect(NEW)
        assert exc.value.stage == "bridge"

    def test_a_bridge_that_never_answers_times_out(self, no_dns, aliases):
        fake = FakeSam(silent_on="NAMING LOOKUP")
        with pytest.raises(otr.SamError) as exc:
            _sam(fake, timeout=0.5).connect(NEW)
        assert exc.value.stage == "bridge" and "timeout" in str(exc.value)

    def test_hello_refused(self, no_dns):
        fake = FakeSam(hello="HELLO REPLY RESULT=NOVERSION")
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert exc.value.stage == "bridge"

    def test_an_unreachable_destination_is_not_a_naming_failure(self, no_dns, aliases):
        fake = FakeSam(names={NEW: DEST}, stream_result="CANT_REACH_PEER")
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(NEW)
        assert (exc.value.stage, exc.value.result) == ("stream", "CANT_REACH_PEER")


class TestNoShippedDestination:
    def test_the_shipped_alias_file_maps_no_name(self):
        assert otr.i2p_aliases(otr.i2p_hosts_defaults_path()) == {}

    def test_the_android_default_is_a_name_not_a_destination(self):
        from android_bridge import settings
        assert settings.DEFAULT_SERVER.endswith(".i2p")
        assert not settings.DEFAULT_SERVER.endswith(".b32.i2p")

    def test_no_production_source_hard_codes_a_b32_destination(self):
        import re
        pat = re.compile(r"\b[a-z2-7]{52}\.b32\.i2p\b")
        for rel in ("android_bridge/settings.py", "android_bridge/connection.py",
                    "android_bridge/transport.py", "i2p_hosts.defaults"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                assert not pat.search(f.read()), rel


class TestAndroidFlow:
    def test_a_blank_route_uses_the_jids_own_domain(self):
        from android_bridge.connection import controller_for
        from android_bridge.app import OtrApp
        app = OtrApp.__new__(OtrApp)
        ctl = controller_for(app, "alice@" + NEW, "")
        assert ctl._profile.effective_server == NEW

    def test_the_transport_resolves_a_typed_name_through_sam(self, no_dns, aliases):
        """Through the Android transport's own `_endpoint`, with the real
        forwarder: the typed name reaches SAM as a NAMING LOOKUP, the alias
        file is not read, and nothing touches a resolver."""
        from android_bridge import transport as T
        from android_bridge.settings import ConnectionProfile
        import otrv4plus_xmpp
        fake = FakeSam(names={NEW: DEST})
        profile = ConnectionProfile(jid="alice@" + NEW, server=NEW,
                                    sam_host="127.0.0.1", sam_port=fake.port)
        t = T.XmppTransport.__new__(T.XmppTransport)
        t._profile = profile
        t._forwarder = otrv4plus_xmpp.start_i2p_sam_forwarder
        t._i2p_resources = []
        t._emit_state = lambda *a, **k: None
        # What __init__ sets for the route and the X1 destination check.
        from android_bridge import server_pins as _sp
        t._route = profile.route
        t._tor_forwarder = None
        t._server_pins = _sp.ServerPins(None)
        host, port = asyncio.run(t._endpoint())
        assert host == "127.0.0.1"
        assert fake.looked_up() == [NEW]
        assert fake.connected_to() == [DEST]
        for r in t._i2p_resources:
            try:
                r.close()
            except Exception:
                pass

    def test_a_name_the_router_does_not_know_is_reported_as_naming(self, no_dns, aliases):
        from android_bridge import transport as T
        from android_bridge.settings import ConnectionProfile
        import otrv4plus_xmpp
        fake = FakeSam(names={B32: OTHER_DEST})   # the alias would resolve; must not be used
        profile = ConnectionProfile(jid="alice@known-only-locally.i2p",
                                    server="known-only-locally.i2p",
                                    sam_host="127.0.0.1", sam_port=fake.port)
        t = T.XmppTransport.__new__(T.XmppTransport)
        t._profile = profile
        t._forwarder = otrv4plus_xmpp.start_i2p_sam_forwarder
        t._i2p_resources = []
        t._emit_state = lambda *a, **k: None
        # What __init__ sets for the route and the X1 destination check.
        from android_bridge import server_pins as _sp
        t._route = profile.route
        t._tor_forwarder = None
        t._server_pins = _sp.ServerPins(None)
        with pytest.raises(T.TransportError) as exc:
            asyncio.run(t._endpoint())
        assert exc.value.code == "i2p_name_not_found"
        assert "DNS" in str(exc.value)
        assert fake.connected_to() == []

    @pytest.mark.parametrize("stage,result,code", [
        ("bridge", "", "sam_unavailable"),
        ("naming", "KEY_NOT_FOUND", "i2p_name_not_found"),
        ("naming", "INVALID_KEY", "i2p_name_not_found"),
        ("naming", "INVALID_NAME", "i2p_name_invalid"),
        ("session", "I2P_ERROR", "i2p_session_failed"),
        ("stream", "CANT_REACH_PEER", "i2p_destination_unreachable"),
    ])
    def test_each_layer_has_its_own_code(self, stage, result, code):
        from android_bridge import transport as T
        err = T._sam_failure(otr.SamError(stage, "x", result), NEW)
        assert err.code == code


class TestTheProjectServerFallback:
    """otrv4plus.i2p is dialled at its shipped b32 when -- and only when --
    the router has never heard of the name. The router stays the authority:
    a router that knows the name is used, and the result is still pinned."""

    SERVER = "otrv4plus.i2p"
    SHIPPED = "nquyxk5atgvp5yn3d4czvtb4qavysbxwjormmewhoyrdux5i4ika.b32.i2p"

    def test_the_shipped_address_is_the_one_the_operator_gave(self):
        assert otr.SERVER_NAME_FALLBACKS == {self.SERVER: self.SHIPPED}
        assert otr._B32_RE.match(self.SHIPPED)

    def test_the_apps_default_server_has_a_fallback(self):
        from android_bridge import settings
        assert settings.DEFAULT_SERVER in otr.SERVER_NAME_FALLBACKS

    def test_a_router_that_knows_the_name_is_used(self, no_dns, aliases):
        fake = FakeSam(names={self.SERVER: DEST, self.SHIPPED: OTHER_DEST})
        sam = _sam(fake)
        sam.connect(self.SERVER, allow_aliases=False).close()
        assert fake.looked_up() == [self.SERVER]
        assert fake.connected_to() == [DEST]
        assert sam.used_builtin_fallback is False

    def test_an_unknown_name_is_dialled_at_the_shipped_address(self, no_dns, aliases):
        """The Android app: no alias file, and still a working default."""
        fake = FakeSam(names={self.SHIPPED: OTHER_DEST})
        sam = _sam(fake)
        sam.connect(self.SERVER, allow_aliases=False).close()
        assert fake.looked_up() == [self.SERVER, self.SHIPPED]
        assert fake.connected_to() == [OTHER_DEST]
        assert sam.used_builtin_fallback is True
        assert no_dns == []

    def test_the_fallback_destination_still_goes_through_the_pin(self, no_dns, aliases):
        fake = FakeSam(names={self.SHIPPED: OTHER_DEST})
        seen = []

        def refuse(dest):
            seen.append(dest)
            raise RuntimeError("pinned elsewhere")

        with pytest.raises(RuntimeError):
            _sam(fake).connect(self.SERVER, allow_aliases=False,
                               verify_destination=refuse)
        assert seen == [OTHER_DEST]
        assert fake.connected_to() == [], "a stream opened before the pin check"

    def test_a_users_own_alias_wins_over_the_shipped_address(self, no_dns, aliases):
        with open(aliases, "a") as fh:
            fh.write("%s = %s\n" % (self.SERVER, B32))
        fake = FakeSam(names={B32: DEST, self.SHIPPED: OTHER_DEST})
        sam = _sam(fake)
        sam.connect(self.SERVER).close()
        assert fake.looked_up() == [self.SERVER, B32]
        assert fake.connected_to() == [DEST]
        assert sam.used_builtin_fallback is False

    def test_invalid_key_gets_no_fallback(self, no_dns, aliases):
        fake = FakeSam(naming_reply="NAMING REPLY RESULT=INVALID_KEY NAME={name}")
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(self.SERVER, allow_aliases=False)
        assert exc.value.result == "INVALID_KEY"
        assert fake.looked_up() == [self.SERVER]

    def test_other_names_get_no_fallback(self, no_dns, aliases):
        fake = FakeSam(names={self.SHIPPED: OTHER_DEST})
        with pytest.raises(otr.SamError):
            _sam(fake).connect("someone-else.i2p", allow_aliases=False)
        assert self.SHIPPED not in fake.looked_up()

    def test_an_offline_server_says_it_is_a_tunnel_problem(self, no_dns, aliases):
        fake = FakeSam()   # the router knows neither the name nor the b32
        with pytest.raises(otr.SamError) as exc:
            _sam(fake).connect(self.SERVER, allow_aliases=False)
        assert exc.value.stage == "naming"
        assert "router or tunnel problem" in str(exc.value)
