"""XMPP session lifecycle, TLS guarantees, and stale-session isolation.

Companions to tests/test_transport_failclosed.py (I2P), tests/test_tor_transport.py
(Tor/SOCKS5) and tests/test_xmpp_keepalive.py (liveness). This file covers what
those do not: the TLS properties inherited from slixmpp, transport immutability
at runtime, and whether a dead session can disturb the one that replaces it.

Code-path tests. They do not prove live TLS, Tor or I2P operation.
"""

import asyncio

import pytest

pytest.importorskip("slixmpp")
import slixmpp
import otrv4plus_xmpp as xmpp


def _run(coro, timeout=5.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

class TestNoCredentialsOverAnUnencryptedStream:
    """The defence against a stripped STARTTLS.

    slixmpp 1.17 has no force_starttls: FeatureSTARTTLS._handle_starttls only
    runs if the server ADVERTISES starttls in stream:features. An attacker who
    strips that advertisement would otherwise see the client proceed straight
    to authentication in the clear.

    What actually stops it is the SASL layer refusing every password mechanism
    on an unencrypted stream. That is a library default we rely on and never
    stated, so it is pinned here: if a future slixmpp flips one of these, this
    fails loudly instead of the password going out in plaintext.
    """

    @pytest.mark.parametrize("setting", ["unencrypted_plain",
                                         "unencrypted_scram",
                                         "unencrypted_digest",
                                         "unencrypted_cram"])
    def test_the_mechanism_is_refused_without_tls(self, setting):
        from slixmpp.features.feature_mechanisms import mechanisms
        assert mechanisms.FeatureMechanisms.default_config[setting] is False, (
            "%s defaults to True: a stripped STARTTLS would send credentials "
            "over an unencrypted stream" % setting)

    def test_the_application_does_not_re_enable_any_of_them(self):
        source = open(xmpp.__file__, encoding="utf-8").read()
        for setting in ("unencrypted_plain", "unencrypted_scram",
                        "unencrypted_digest", "unencrypted_cram"):
            assert setting not in source, (
                "%s is referenced in the client; it must stay at the "
                "library default" % setting)


class TestTlsConfiguration:
    def test_starttls_is_enabled_and_direct_tls_is_not(self):
        source = open(xmpp.__file__, encoding="utf-8").read()
        assert "client.enable_starttls = True" in source
        assert "client.enable_direct_tls = False" in source

    def test_verification_is_only_disabled_by_the_explicit_flag(self):
        # Never as a fallback after a handshake failure.
        source = open(xmpp.__file__, encoding="utf-8").read()
        assert source.count("CERT_NONE") == 1
        idx = source.index("CERT_NONE")
        assert "insecure_tls" in source[max(0, idx - 600):idx]

    def test_the_clearnet_warning_names_the_actual_risk(self):
        # A warning that does not say what is lost teaches nothing.
        source = open(xmpp.__file__, encoding="utf-8").read()
        start = source.index("--insecure-tls on a CLEARNET connection")
        window = source[start:start + 500]
        assert "MITM" in window
        assert "password" in window


# ---------------------------------------------------------------------------
# Transport is fixed for the life of the process
# ---------------------------------------------------------------------------

class TestTransportCannotChangeAtRuntime:
    """A reconnect must not be able to move a session to another transport.

    Guaranteed structurally rather than by a check: the markers are assigned
    at construction and once during setup, and never again.
    """

    @pytest.mark.parametrize("field", ["_is_i2p", "_is_tor",
                                       "_sam_params", "_tor_params"])
    def test_the_marker_is_never_reassigned_after_setup(self, field):
        import re
        source = open(xmpp.__file__, encoding="utf-8").read()
        # Assignments of the form `<something>._is_i2p =` or `self._is_i2p =`.
        assignments = re.findall(r"^\s*(?:self|client)\.%s\s*=" % field,
                                 source, re.MULTILINE)
        # One in __init__, plus the setup assignments in main(). Anything
        # inside a handler or the reconnect loop would exceed this.
        assert len(assignments) <= 3, (
            "%s is assigned %d times; a runtime reassignment could move a "
            "session between transports" % (field, len(assignments)))

    def test_the_reconnect_loop_assigns_no_transport_marker(self):
        import ast
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._reconnect)))
        assigned = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        assigned.add(target.attr)
        for marker in ("_is_i2p", "_is_tor", "_sam_params", "_tor_params"):
            assert marker not in assigned, (
                "_reconnect assigns %s -- transport must be immutable" % marker)


# ---------------------------------------------------------------------------
# Stale session isolation
# ---------------------------------------------------------------------------

class _Lifecycle:
    """Just the lifecycle surface, with the real methods bound."""

    _schedule_reconnect = xmpp.OTRv4PlusXMPP._schedule_reconnect
    _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params
    _on_disconnected = xmpp.OTRv4PlusXMPP._on_disconnected
    _clear_peer_gone = xmpp.OTRv4PlusXMPP._clear_peer_gone

    def __init__(self):
        self._shutting_down = False
        self._sam_params = {"server_b32": "x.b32.i2p"}
        self._tor_params = None
        self._reconnect_task = None
        self._keepalive_task = None
        self._password_prompt = None
        self._peer_gone_at = {}
        self.reconnects = 0

    async def _reconnect(self):
        self.reconnects += 1
        await asyncio.sleep(3600)


class TestStaleKeepaliveCannotDisturbTheNewSession:
    def test_disconnect_cancels_the_running_keepalive(self):
        async def _drive():
            client = _Lifecycle()
            stale = asyncio.ensure_future(asyncio.sleep(3600))
            client._keepalive_task = stale
            client._on_disconnected(None)
            await asyncio.sleep(0)
            cancelled = stale.cancelled() or stale.cancelling() > 0
            for task in (client._reconnect_task, stale):
                if task is not None:
                    task.cancel()
            return cancelled

        assert _run(_drive()) is True, (
            "a keepalive loop from the dead session would keep probing and "
            "incrementing the shared failure counter")

    def test_a_fresh_loop_starts_from_zero_failures(self):
        # Proved behaviourally in test_xmpp_keepalive.py; asserted here as the
        # lifecycle property it belongs to.
        import ast
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._keepalive_loop)))
        reset = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Attribute)
                         and t.attr == "_keepalive_ping_fails"
                         for t in n.targets)]
        assert reset, "the loop never resets the consecutive failure counter"


class TestVoiceIsUntouchedByTheLifecycle:
    """The live call's most valuable result: audio continued across
    reconnects. Nothing in the lifecycle may reach the voice manager."""

    @pytest.mark.parametrize("method", ["_on_disconnected",
                                        "_on_connection_failed",
                                        "_schedule_reconnect",
                                        "_reconnect",
                                        "_declare_stream_dead",
                                        "_keepalive_loop"])
    def test_the_method_references_no_voice_state(self, method):
        import ast
        import inspect
        import textwrap
        tree = ast.parse(textwrap.dedent(
            inspect.getsource(getattr(xmpp.OTRv4PlusXMPP, method))))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                lowered = node.attr.lower()
                for banned in ("voice", "ratchet", "epoch", "media"):
                    assert banned not in lowered, (
                        "%s touches %s" % (method, node.attr))
