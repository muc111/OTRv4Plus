# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""SCRAM ends in "signed in" only when the server has proved itself.

Red team 2026-11, R2-R4: slixmpp 1.17.0 marked a session authenticated when a
server answered the client's first message with `<success/>` carrying text
shaped like a challenge; it ran whatever iteration count the server named,
in Python, on the event loop; and it drew its nonce from `random.random()`.
Over I2P and Tor, where the certificate is not checked, SCRAM is the only
proof the far end knows the account. These drive slixmpp's own handlers,
patched by `android_bridge.sasl_hardening`, against a small honest server
and against the three attacks.
"""
import base64
import hashlib
import hmac
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("slixmpp")

from slixmpp.features.feature_mechanisms.mechanisms import (  # noqa: E402
    FeatureMechanisms)
from slixmpp.util.sasl import mechanisms as M  # noqa: E402

from android_bridge import sasl_hardening as H  # noqa: E402
from android_bridge.xmlguard import REFUSED_EVENT  # noqa: E402

PASSWORD = b"correct horse battery"


@pytest.fixture(autouse=True)
def hardened():
    assert H.apply() == {"success_needs_proof": True,
                         "iteration_bounds": True,
                         "csprng_nonce": True}


class Client:
    """What the SASL plugin touches on a slixmpp client."""
    stream_header = "<stream>"

    def __init__(self):
        self.authenticated = False
        self.features = set()
        self.events = []
        self.closed = []
        self.restarted = 0

    def event(self, name, data=None):
        self.events.append((name, data))

    def init_parser(self):
        self.restarted += 1

    def send_raw(self, _data):
        pass

    def abort(self):
        self.closed.append("abort")

    def disconnect(self, *_a, **_k):
        self.closed.append("disconnect")

    def names(self):
        return [name for name, _ in self.events]


class Reply:
    """Stands in for the Response/Abort stanzas the plugin builds."""
    sent = None

    def __init__(self, _xmpp=None):
        self.value = None

    def __setitem__(self, key, value):
        self.value = value

    def get_value(self):
        return self.value

    def del_value(self):
        self.value = None

    def send(self):
        type(self).sent = self


class Server:
    """An honest SCRAM server (RFC 5802) for one account."""

    def __init__(self, digest="sha1", iterations=10000, password=PASSWORD):
        self.digest = digest
        self.iterations = iterations
        self.salt = b"0123456789abcdef"
        salted = hashlib.pbkdf2_hmac(digest, password, self.salt, iterations)
        client_key = hmac.new(salted, b"Client Key", digest).digest()
        self.stored_key = hashlib.new(digest, client_key).digest()
        self.server_key = hmac.new(salted, b"Server Key", digest).digest()

    def first(self, client_first: bytes) -> bytes:
        self.bare = client_first.split(b",", 2)[2]
        cnonce = dict(p.split(b"=", 1) for p in self.bare.split(b","))[b"r"]
        self.nonce = cnonce + b"SERVERNONCE"
        self.server_first = (b"r=" + self.nonce + b",s="
                             + base64.b64encode(self.salt)
                             + b",i=" + str(self.iterations).encode())
        return self.server_first

    def final(self, client_final: bytes) -> bytes:
        without_proof, proof = client_final.rsplit(b",p=", 1)
        auth = self.bare + b"," + self.server_first + b"," + without_proof
        signature = hmac.new(self.stored_key, auth, self.digest).digest()
        client_key = bytes(a ^ b for a, b in
                           zip(base64.b64decode(proof), signature))
        assert hashlib.new(self.digest, client_key).digest() == self.stored_key
        return b"v=" + base64.b64encode(
            hmac.new(self.server_key, auth, self.digest).digest())


def plugin_for(mechanism="SCRAM-SHA-1"):
    creds = {"username": M.bytes("alice"), "password": M.bytes(PASSWORD),
             "authzid": M.bytes(""), "channel_binding": None}
    security = {"encrypted": True, "unencrypted_scram": False,
                "tls_version": "TLSv1.3", "binding_proposed": False}
    plugin = FeatureMechanisms.__new__(FeatureMechanisms)
    plugin.xmpp = Client()
    plugin.attempted_mechs = set()
    plugin.mech = M.SCRAM(mechanism, creds, security)

    class Stanzas:
        Response = Reply
        Abort = Reply
    plugin.stanza = Stanzas
    Reply.sent = None
    return plugin


def challenge(plugin, data: bytes):
    plugin._handle_challenge({"value": data})
    sent = Reply.sent
    Reply.sent = None
    return sent.value if sent is not None else None


@pytest.mark.parametrize("mechanism,digest", [
    ("SCRAM-SHA-1", "sha1"), ("SCRAM-SHA-256", "sha256"),
    ("SCRAM-SHA-512", "sha512")])
def test_an_honest_server_still_signs_in(mechanism, digest):
    plugin = plugin_for(mechanism)
    server = Server(digest)
    client_final = challenge(plugin, server.first(plugin.mech.process()))
    plugin._handle_success({"value": server.final(bytes(client_final))})
    assert plugin.xmpp.authenticated is True
    assert plugin.xmpp.closed == []
    assert "auth_success" in plugin.xmpp.names()
    assert plugin.xmpp.restarted == 1


def test_success_straight_after_the_first_message_is_refused():
    """The bypass: no challenge, no signature, `<success/>` carrying
    something shaped like a challenge."""
    plugin = plugin_for()
    plugin.mech.process()
    forged = (b"r=" + plugin.mech.cnonce + b"x,s="
              + base64.b64encode(b"saltsalt") + b",i=4096")
    plugin._handle_success({"value": forged})
    assert plugin.xmpp.authenticated is False
    assert plugin.xmpp.closed == ["abort"]
    assert (REFUSED_EVENT, "success_before_challenge") in plugin.xmpp.events
    assert "auth_success" not in plugin.xmpp.names()
    assert plugin.xmpp.restarted == 0


def test_success_before_anything_was_sent_is_refused():
    plugin = plugin_for()
    plugin._handle_success({"value": b""})
    assert plugin.xmpp.authenticated is False
    assert plugin.xmpp.closed == ["abort"]


def test_a_wrong_signature_is_refused():
    plugin = plugin_for()
    server = Server()
    challenge(plugin, server.first(plugin.mech.process()))
    plugin._handle_success({"value": b"v=" + base64.b64encode(b"\0" * 20)})
    assert plugin.xmpp.authenticated is False
    assert plugin.xmpp.closed
    assert "auth_success" not in plugin.xmpp.names()


def test_a_server_that_does_not_know_the_password_is_refused():
    plugin = plugin_for()
    impostor = Server(password=b"not the password")
    client_final = challenge(plugin, impostor.first(plugin.mech.process()))
    without_proof = bytes(client_final).rsplit(b",p=", 1)[0]
    auth = impostor.bare + b"," + impostor.server_first + b"," + without_proof
    forged = b"v=" + base64.b64encode(
        hmac.new(impostor.server_key, auth, "sha1").digest())
    plugin._handle_success({"value": forged})
    assert plugin.xmpp.authenticated is False
    assert "auth_success" not in plugin.xmpp.names()


@pytest.mark.parametrize("count", [0, 1, 100, H.MIN_ITERATIONS - 1,
                                   H.MAX_ITERATIONS + 1, 10 ** 12])
def test_an_iteration_count_outside_the_bounds_ends_the_connection(count):
    plugin = plugin_for()
    server = Server()
    first = server.first(plugin.mech.process())
    forged = first.rsplit(b",i=", 1)[0] + b",i=" + str(count).encode()
    challenge(plugin, forged)
    assert plugin.xmpp.authenticated is False
    assert plugin.xmpp.closed == ["abort"]
    assert (REFUSED_EVENT, "iteration_count") in plugin.xmpp.events


def test_the_bounds_admit_what_real_servers_use():
    # ejabberd 4096, Prosody 10000, and a server following OWASP for SHA-1.
    assert H.MIN_ITERATIONS <= 4096
    assert H.MAX_ITERATIONS >= 1_300_000
    plugin = plugin_for()
    for count in (4096, 10000):
        assert len(plugin.mech.Hi(M.bytes(PASSWORD), b"salt", count)) == 20


def test_the_salted_password_is_the_rfc_5802_one():
    # RFC 5802 §5: user "user", password "pencil", i=4096.
    plugin = plugin_for()
    salt = base64.b64decode("QSXCR+Q6sek8bf92")
    salted = plugin.mech.Hi(M.bytes("pencil"), salt, 4096)
    client_key = hmac.new(salted, b"Client Key", "sha1").digest()
    stored = hashlib.sha1(client_key).digest()
    auth = (b"n=user,r=fyko+d2lbbFgONRv9qkxdawL,"
            b"r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,"
            b"s=QSXCR+Q6sek8bf92,i=4096,"
            b"c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j")
    proof = bytes(a ^ b for a, b in zip(
        client_key, hmac.new(stored, auth, "sha1").digest()))
    assert base64.b64encode(proof) == b"v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="


def test_the_nonce_is_long_and_never_repeats():
    seen = set()
    for _ in range(200):
        plugin = plugin_for()
        plugin.mech.process()
        nonce = bytes(plugin.mech.cnonce)
        assert len(nonce) >= 32 and b"," not in nonce
        seen.add(nonce)
    assert len(seen) == 200
    assert isinstance(M.random, H._Nonce)


def test_applying_twice_changes_nothing():
    before = (M.SCRAM.Hi, FeatureMechanisms._handle_success,
              FeatureMechanisms._handle_challenge, M.random)
    H.apply()
    assert before == (M.SCRAM.Hi, FeatureMechanisms._handle_success,
                      FeatureMechanisms._handle_challenge, M.random)


def test_both_clients_harden_sasl_before_they_are_built():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "android_bridge", "transport.py")) as fh:
        transport = fh.read()
    factory = transport[transport.index("def _default_client_factory"):]
    assert factory.index("sasl_hardening.apply()") < factory.index(
        "GuardedClient(jid, password)")
    with open(os.path.join(here, "client", "otrv4plus_xmpp.py")) as fh:
        terminal = fh.read()
    assert terminal.index("_sasl_hardening.apply()") < terminal.index(
        "class OTRv4PlusXMPP(")


def test_the_user_is_told_and_no_retry_follows():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "android_bridge", "transport.py")) as fh:
        transport = fh.read()
    assert 'SERVER_NOT_PROVEN_CODE = "server_not_proven"' in transport
    assert "client.add_event_handler(REFUSED_EVENT, on_refused)" in transport
    kt = os.path.join(here, "android", "app", "src", "main", "java", "org",
                      "otrv4plus", "android", "connection",
                      "ConnectProblem.kt")
    with open(kt) as fh:
        source = fh.read()
    needs = source[source.index("val NEEDS_YOU"):source.index("val TRANSIENT")]
    assert '"server_not_proven"' in needs
    assert '"server_not_proven" ->' in source
