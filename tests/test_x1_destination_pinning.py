# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""SECURITY_ISSUES X1: no account password to a substituted I2P destination.

THE ATTACK
----------
A short `.i2p` name is bound to a destination by the router's address book,
which a subscription feed or a first registrant can influence. Over I2P the
transport turns TLS certificate checks off (there is no CA for `.i2p`). Before
this fix, whoever held the destination the name resolved to received the
XMPP stream -- and, with SASL PLAIN, the account password itself.

THE DEFENCE, TWO LAYERS
-----------------------
A. Destination pinning (android_bridge/server_pins.py). The destination a
   name resolves to is pinned on first successful use. A different one is
   refused BETWEEN the NAMING LOOKUP and the STREAM CONNECT: no stream to it
   exists, so no byte -- and no credential -- reaches it. Only an explicit
   approval of exactly the refused destination replaces the pin.
B. SCRAM only wherever certificate checks are off (transport._restrict_to_scram).
   Even on first contact a substituted server never receives the password,
   only a SCRAM proof. Residual: that proof allows an offline guess at a weak
   password -- documented in SECURITY_ISSUES.md, not claimed away.

Everything here runs the REAL forwarder and the REAL I2PSAMConnection against
a scripted SAM bridge on loopback, and the REAL slixmpp SASL plugin.
"""
from __future__ import annotations

import base64
import os
import socket
import stat
import sys
import tempfile
import threading
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

pytest.importorskip("otrv4_")

from android_bridge import server_pins as SP  # noqa: E402
from android_bridge.connection import ConnectionController  # noqa: E402
from android_bridge.settings import ConnectionProfile  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402
from android_bridge.transport import (  # noqa: E402
    SCRAM_ONLY, TransportError, XmppTransport)
from tests.fake_sasl import sasl_plugins  # noqa: E402

# Any server named by a short name -- NOT the project's own server, which is
# dialled at its shipped b32 and never pinned (otrv4plus_address.SHIPPED_SERVERS).
NAME = "example-server.i2p"
JID = "alice@" + NAME
PASSWORD = "correct-horse-battery-staple-X1"

# Two well-formed I2P base64 destinations (I2P's alphabet uses '-' and '~').
DEST_A = "A" * 516 + "AAAA"
DEST_B = "B" * 516 + "BBBA"
B32_A = SP.b32_of_destination(DEST_A)
B32_B = SP.b32_of_destination(DEST_B)


class ScriptedSam:
    """A SAM v3.1 bridge on 127.0.0.1 whose name table can be changed
    mid-test, and which then plays the XMPP server at each destination:
    every byte that reaches a destination through a stream is recorded."""

    def __init__(self, names):
        self.names = dict(names)
        self.commands = []
        self.received = {}          # destination -> bytes
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
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
        buf = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode().strip()
                    self.commands.append(line)
                    if line.startswith("HELLO"):
                        out = "HELLO REPLY RESULT=OK VERSION=3.1"
                    elif line.startswith("NAMING LOOKUP"):
                        name = line.split("NAME=", 1)[1].split()[0]
                        if name in self.names:
                            out = "NAMING REPLY RESULT=OK NAME=%s VALUE=%s" % (
                                name, self.names[name])
                        elif name.endswith(".b32.i2p"):
                            dest = {B32_A: DEST_A, B32_B: DEST_B}.get(name)
                            out = ("NAMING REPLY RESULT=OK NAME=%s VALUE=%s" % (name, dest)
                                   if dest else
                                   "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=%s" % name)
                        else:
                            out = "NAMING REPLY RESULT=KEY_NOT_FOUND NAME=%s" % name
                    elif line.startswith("SESSION CREATE"):
                        out = "SESSION STATUS RESULT=OK DESTINATION=" + "C" * 600
                    elif line.startswith("STREAM CONNECT"):
                        dest = line.split("DESTINATION=", 1)[1].split()[0]
                        conn.sendall(b"STREAM STATUS RESULT=OK\n")
                        self._be_server(conn, dest, buf)
                        return
                    else:
                        out = "UNKNOWN"
                    conn.sendall((out + "\n").encode())
        except OSError:
            pass

    def _be_server(self, conn, dest, pending):
        got = self.received.setdefault(dest, bytearray())
        got += pending
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                got += data
        except OSError:
            return

    def streams_to(self):
        return [c.split("DESTINATION=", 1)[1].split()[0]
                for c in self.commands if c.startswith("STREAM CONNECT")]

    def close(self):
        self._stop = True
        self.sock.close()


class WireClient:
    """A slixmpp stand-in that, on connect, writes the credential into the
    socket it was pointed at -- the worst case, as SASL PLAIN would. If the
    transport ever lets it reach a destination, the destination has the
    password."""

    def __init__(self, jid, password):
        self.plugin = sasl_plugins()
        self.password = password
        self.handlers = {}
        self.client_roster = {}
        self.features = {"starttls"}
        self.sock = None

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def register_plugin(self, _n):
        pass

    def __getitem__(self, n):
        return self.plugin[n]

    def add_filter(self, *_a, **_k):
        pass

    def connect(self, host=None, port=None):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.sendall(b"<auth mechanism='PLAIN'>" +
                          base64.b64encode(b"\0alice\0" + self.password.encode()) +
                          b"</auth>" + self.password.encode())
        for fn in list(self.handlers.get("session_start", [])):
            fn(None)

    def send_presence(self, **_k):
        pass

    def get_roster(self, **_k):
        pass

    def abort(self):
        self.disconnect()

    def disconnect(self, *_a, **_k):
        if self.sock:
            self.sock.close()
            self.sock = None


@pytest.fixture
def sam():
    s = ScriptedSam({NAME: DEST_A})
    yield s
    s.close()


def _transport(sam, pins, jid=JID, server=""):
    return XmppTransport(
        ConnectionProfile(jid=jid, server=server, sam_host="127.0.0.1",
                          sam_port=sam.port),
        PASSWORD, on_payload=lambda *a: None,
        client_factory=WireClient, server_pins=pins)


def _connect(sam, pins, **kw):
    t = _transport(sam, pins, **kw)
    try:
        t.connect()
    finally:
        t.close()


def _wait_for(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return pred()


def _password_reached(sam, dest):
    return PASSWORD.encode() in bytes(sam.received.get(dest, b""))


# ── the attack, end to end ───────────────────────────────────────────────────

class TestSubstitutionIsBlocked:

    def test_first_connection_pins_A(self, sam):
        pins = SP.ServerPins(None)
        # Kept open until the bytes are across: closing at once can tear the
        # forwarder down before it has pumped them, which made this flaky.
        t = _transport(sam, pins)
        try:
            t.connect()
            reached = _wait_for(lambda: _password_reached(sam, DEST_A))
        finally:
            t.close()
        assert pins.pinned(NAME) == B32_A
        assert reached, (
            "the harness must show the credential DOES flow to a trusted "
            "destination, or the negative test below proves nothing")

    def test_reconnect_to_A_is_allowed(self, sam):
        pins = SP.ServerPins(None)
        _connect(sam, pins)
        _connect(sam, pins)
        assert sam.streams_to() == [DEST_A, DEST_A]
        assert pins.pinned(NAME) == B32_A

    def test_B_is_refused_and_receives_nothing(self, sam):
        pins = SP.ServerPins(None)
        _connect(sam, pins)
        TRACE.clear()
        sam.names[NAME] = DEST_B                 # the address book is poisoned
        with pytest.raises(TransportError) as e:
            _connect(sam, pins)
        assert e.value.code == "i2p_destination_changed"
        assert B32_A in str(e.value) and B32_B in str(e.value)
        # NO XMPP ACCOUNT PASSWORD SENT TO DESTINATION B -- and nothing else:
        assert DEST_B not in sam.streams_to(), "a stream to B was opened"
        assert DEST_B not in sam.received
        time.sleep(0.2)
        assert not _password_reached(sam, DEST_B)
        # ...and no SAM session was even created for the refused attempt.
        last_lookup = max(i for i, c in enumerate(sam.commands)
                          if c.startswith("NAMING LOOKUP"))
        assert not any(c.startswith(("SESSION CREATE", "STREAM CONNECT"))
                       for c in sam.commands[last_lookup:])
        assert pins.pinned(NAME) == B32_A, "the pin must not move by itself"
        events = [(ev["component"], ev["event"]) for ev in TRACE.events()]
        assert ("i2p", "destination_changed") in events
        assert ("auth", "blocked") in events
        assert ("auth", "allowed") not in events

    def test_it_stays_blocked_on_every_retry(self, sam):
        pins = SP.ServerPins(None)
        _connect(sam, pins)
        sam.names[NAME] = DEST_B
        for _ in range(3):
            with pytest.raises(TransportError):
                _connect(sam, pins)
        assert DEST_B not in sam.streams_to()

    def test_registration_is_blocked_too(self, sam):
        pins = SP.ServerPins(None)
        _connect(sam, pins)
        sam.names[NAME] = DEST_B
        t = _transport(sam, pins)
        try:
            code, _detail = t.register_account()
        finally:
            t.close()
        assert code == "server_identity_changed"
        assert DEST_B not in sam.streams_to()

    def test_a_typed_b32_must_resolve_to_itself(self, sam):
        """A .b32.i2p is the key hash; a router answering with another
        destination is refused the same way."""
        pins = SP.ServerPins(None)
        sam.names[B32_A] = DEST_B
        with pytest.raises(TransportError) as e:
            _connect(sam, pins, jid="alice@" + B32_A)
        assert e.value.code == "i2p_destination_changed"
        assert DEST_B not in sam.streams_to()

    def test_the_trace_holds_no_secret(self, sam):
        pins = SP.ServerPins(None)
        TRACE.clear()
        _connect(sam, pins)
        sam.names[NAME] = DEST_B
        with pytest.raises(TransportError):
            _connect(sam, pins)
        text = TRACE.render()
        assert PASSWORD not in text
        assert DEST_A not in text and DEST_B not in text


# ── re-approval ──────────────────────────────────────────────────────────────

class TestReapproval:

    def _changed(self, sam):
        pins = SP.ServerPins(None)
        _connect(sam, pins)
        sam.names[NAME] = DEST_B
        with pytest.raises(TransportError):
            _connect(sam, pins)
        return pins

    def test_approving_the_refused_destination_then_connecting_moves_the_pin(self, sam):
        pins = self._changed(sam)
        pins.approve(NAME, B32_B)
        assert pins.pinned(NAME) == B32_A, "approval alone does not re-pin"
        _connect(sam, pins)
        assert pins.pinned(NAME) == B32_B
        assert DEST_B in sam.streams_to()

    def test_only_the_refused_destination_can_be_approved(self, sam):
        pins = self._changed(sam)
        other = "c" * 52 + ".b32.i2p"
        with pytest.raises(ValueError):
            pins.approve(NAME, other)
        with pytest.raises(ValueError):
            pins.approve(NAME, "not-a-b32")

    def test_no_approval_without_a_refusal(self):
        pins = SP.ServerPins(None)
        with pytest.raises(ValueError):
            pins.approve(NAME, B32_B)

    def test_confirm_never_overwrites_a_different_pin(self):
        pins = SP.ServerPins(None)
        assert pins.check(NAME, B32_A) == SP.NEW
        pins.confirm(NAME)
        assert pins.check(NAME, B32_B) == SP.CHANGED
        assert pins.confirm(NAME) is None
        assert pins.pinned(NAME) == B32_A

    def test_approval_is_for_that_destination_only(self, sam):
        pins = self._changed(sam)
        pins.approve(NAME, B32_B)
        third = "D" * 516 + "DDDA"
        sam.names[NAME] = third
        with pytest.raises(TransportError) as e:
            _connect(sam, pins)
        assert e.value.code == "i2p_destination_changed"
        assert third not in sam.streams_to()

    def test_the_controller_exposes_the_change_and_the_approval(self, sam):
        pins = self._changed(sam)
        saved = SP._DEFAULT
        SP._DEFAULT = pins
        try:
            ctl = ConnectionController(object(), ConnectionProfile(jid=JID))
            change = ctl.destination_change()
            assert change == {"server": NAME, "trusted": B32_A, "seen": B32_B}
            assert not ctl.approve_server_destination("e" * 52 + ".b32.i2p")["ok"]
            assert ctl.approve_server_destination(B32_B)["ok"]
        finally:
            SP._DEFAULT = saved


# ── persistence ──────────────────────────────────────────────────────────────

class TestPersistence:

    # tempfile rather than pytest's tmp_path: conftest stubs `pwd`, which
    # tmp_path needs to name its directory.
    def test_pins_survive_a_restart_and_are_private(self):
        path = os.path.join(tempfile.mkdtemp(), "state", "server_pins.json")
        a = SP.ServerPins(path)
        a.check(NAME, B32_A)
        a.confirm(NAME)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        b = SP.ServerPins(path)
        assert b.pinned(NAME) == B32_A
        assert b.check(NAME, B32_B) == SP.CHANGED

    def test_forget_removes_the_file(self):
        path = os.path.join(tempfile.mkdtemp(), "server_pins.json")
        a = SP.ServerPins(path)
        a.check(NAME, B32_A)
        a.confirm(NAME)
        a.forget()
        assert not os.path.exists(path)
        assert SP.ServerPins(path).pinned(NAME) is None

    def test_wipe_forgets_the_pins(self):
        src = open(os.path.join(ROOT, "android_bridge", "app.py")).read()
        assert "_pins.default_store().forget()" in src

    def test_b32_of_destination_is_the_i2p_hash(self):
        import hashlib
        raw = base64.b64decode(DEST_A.replace("-", "+").replace("~", "/"))
        want = base64.b32encode(hashlib.sha256(raw).digest()).decode().lower().rstrip("=")
        assert B32_A == want + ".b32.i2p"
        assert len(B32_A) == 60


# ── SCRAM only where the certificate is not checked: the real plugin ─────────

def _sasl_attempt(jid, offered, *, tls=True):
    """Run the real slixmpp mechanism choice; return (what was sent, events)."""
    t = XmppTransport(ConnectionProfile(jid=jid), PASSWORD,
                      on_payload=lambda *a: None)
    try:
        c = t._make_client()
        mech = c.plugin["feature_mechanisms"]
        sent, events = [], []
        c.send = lambda s, *a, **k: sent.append(str(s))
        c.disconnect = lambda *a, **k: events.append("disconnect")
        c.event = lambda name, *a, **k: events.append(name)
        c.features = {"starttls"} if tls else set()
        mech.mech_list = set(offered)
        mech.attempted_mechs = set()
        mech._send_auth()
        wire = b"".join(
            base64.b64decode((s.split(">", 1)[1].split("<", 1)[0]) or "=")
            for s in sent)
        return sent, events, wire, mech
    finally:
        t.close()


class TestScramOnlyOnTheWire:

    @pytest.mark.parametrize("jid", [JID, "alice@" + B32_A,
                                     "alice@" + "b" * 56 + ".onion"])
    def test_restricted_to_scram(self, jid):
        _s, _e, _w, mech = _sasl_attempt(jid, {"SCRAM-SHA-1"})
        assert mech.use_mechs == set(SCRAM_ONLY)
        assert mech.encrypted_plain is False and mech.unencrypted_plain is False

    def test_a_server_offering_only_plain_gets_nothing(self):
        sent, events, wire, _ = _sasl_attempt(JID, {"PLAIN", "LOGIN", "DIGEST-MD5"})
        assert sent == []
        assert "no_auth" in events
        assert PASSWORD.encode() not in wire

    def test_scram_is_chosen_and_the_password_is_not_on_the_wire(self):
        sent, events, wire, mech = _sasl_attempt(
            JID, {"PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256"})
        assert len(sent) == 1 and "SCRAM-SHA-256" in sent[0]
        assert PASSWORD.encode() not in wire
        assert b"n=alice,r=" in wire

    def test_no_tls_no_scram_either(self):
        sent, events, _w, _ = _sasl_attempt(JID, {"SCRAM-SHA-1", "PLAIN"}, tls=False)
        assert sent == [] and "no_auth" in events

    def test_clearnet_is_not_restricted_but_plain_needs_verified_tls(self):
        # Clearnet: the certificate IS checked, so PLAIN inside that TLS is
        # the standard; without TLS nothing is sent.
        sent, _e, wire, mech = _sasl_attempt("alice@07f.de", {"PLAIN"})
        assert mech.use_mechs is None
        assert PASSWORD.encode() in wire
        sent, events, _w, _ = _sasl_attempt("alice@07f.de", {"PLAIN"}, tls=False)
        assert sent == [] and "no_auth" in events

    def test_no_auth_is_reported_as_no_safe_mechanism(self):
        class NoAuthClient(WireClient):
            def connect(self, host=None, port=None):
                for fn in list(self.handlers.get("no_auth", [])):
                    fn(None)

        t = XmppTransport(ConnectionProfile(jid="alice@" + B32_A),
                          PASSWORD, on_payload=lambda *a: None,
                          client_factory=NoAuthClient,
                          forwarder=_null_forwarder)
        try:
            with pytest.raises(TransportError) as e:
                t.connect()
            assert e.value.code == "no_safe_auth_mechanism"
            assert "SCRAM" in str(e.value)
        finally:
            t.close()

    def test_the_restriction_cannot_be_silently_skipped(self):
        class NoSasl(WireClient):
            def __init__(self, jid, password):
                super().__init__(jid, password)
                self.plugin = {}

        t = XmppTransport(ConnectionProfile(jid="alice@" + B32_A),
                          PASSWORD, on_payload=lambda *a: None,
                          client_factory=NoSasl, forwarder=_null_forwarder)
        try:
            with pytest.raises(TransportError):
                t.connect()
        finally:
            t.close()


async def _null_forwarder(*_a, verify=None, **_k):
    return ("127.0.0.1", 9)
