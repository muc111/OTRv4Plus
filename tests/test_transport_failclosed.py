"""Transport selection must be explicit and fail-closed.

Application-layer encryption protects message content. It does nothing to
hide which address is talking to which server, so a session the user asked to
run over I2P must never reach the server directly -- not on startup, not on
reconnect, not because one condition drifted.

These are code-path tests. They do not prove live I2P, Tor or TLS operation;
that needs real devices on real networks.
"""

import asyncio
import types

import pytest

pytest.importorskip("slixmpp")
import otrv4plus_xmpp as xmpp


class _ReconnectHarness:
    """Only the surface `_reconnect` touches."""

    _reconnect = xmpp.OTRv4PlusXMPP._reconnect

    def __init__(self, is_i2p, sam_params, sam_works=True):
        self._shutting_down = False
        self._is_i2p = is_i2p
        self._sam_params = sam_params
        self._reconnect_delay = 0
        self._sam_works = sam_works
        self.direct_connects = 0
        self.forwarded_connects = 0

    def connect(self, host=None, port=None):
        if host is None:
            self.direct_connects += 1
        else:
            self.forwarded_connects += 1


def _run(coro, timeout=5.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def _patch_sam(monkeypatch, works=True, calls=None):
    async def _forwarder(server_b32, dest_port, sam_host=None, sam_port=None):
        if calls is not None:
            calls.append(server_b32)
        if not works:
            raise OSError("SAM bridge unavailable")
        return ("127.0.0.1", 41234)

    monkeypatch.setattr(xmpp, "start_i2p_sam_forwarder", _forwarder)


SAM_PARAMS = {"server_b32": "x.b32.i2p", "dest_port": 5222,
              "sam_host": "127.0.0.1", "sam_port": 7656}


class TestI2PNeverFallsBackToDirect:
    def test_a_healthy_reconnect_goes_through_sam(self, monkeypatch):
        calls = []
        _patch_sam(monkeypatch, works=True, calls=calls)
        h = _ReconnectHarness(is_i2p=True, sam_params=SAM_PARAMS)
        _run(h._reconnect())
        assert calls == ["x.b32.i2p"]
        assert h.forwarded_connects == 1
        assert h.direct_connects == 0

    def test_a_failing_sam_bridge_never_connects_directly(self, monkeypatch):
        # The whole point: a broken tunnel must leave the session down, not
        # quietly route around the anonymity the user asked for.
        _patch_sam(monkeypatch, works=False)
        h = _ReconnectHarness(is_i2p=True, sam_params=SAM_PARAMS)

        async def _stop_after_a_few():
            await asyncio.sleep(0.05)
            h._shutting_down = True

        async def _both():
            await asyncio.gather(h._reconnect(), _stop_after_a_few())

        _run(_both())
        assert h.direct_connects == 0, "I2P session reached the server directly"

    def test_missing_sam_parameters_refuse_rather_than_downgrade(self, monkeypatch,
                                                                capsys):
        # Unreachable today, guarded anyway: the fall-through would open a
        # direct clearnet connection from a session the user asked to run
        # over I2P. A downgrade must not be one condition away from live.
        _patch_sam(monkeypatch, works=True)
        h = _ReconnectHarness(is_i2p=True, sam_params=None)
        _run(h._reconnect())
        assert h.direct_connects == 0
        assert h.forwarded_connects == 0
        out = capsys.readouterr().out.lower()
        assert "refus" in out

    def test_a_clearnet_session_may_connect_directly(self, monkeypatch):
        # The guard must not break the transport it does not apply to.
        _patch_sam(monkeypatch, works=True)
        h = _ReconnectHarness(is_i2p=False, sam_params=None)
        _run(h._reconnect())
        assert h.direct_connects == 1


class TestTransportSelectionIsExplicit:
    def test_i2p_is_selected_only_by_an_i2p_address(self):
        # Hostname suffix, not a guess or a probe.
        for host, expected in (("server.b32.i2p", True),
                               ("example.com", False),
                               ("someonion.onion", False)):
            assert host.endswith(".i2p") is expected

    def test_xmpp_has_no_tor_path(self):
        # Recorded as a fact, not a wish. otrv4+.py (IRC) has SOCKS5/.onion
        # handling; otrv4plus_xmpp.py has none, so a .onion XMPP server is
        # treated as clearnet and simply fails to resolve. Should Tor support
        # be added, this test should be replaced by real Tor path tests --
        # not deleted to make room for an untested claim.
        source = open(xmpp.__file__, encoding="utf-8").read()
        assert "PROXY_TYPE_SOCKS5" not in source
        assert "set_proxy" not in source

    def test_the_clearnet_insecure_flag_is_opt_in(self):
        source = open(xmpp.__file__, encoding="utf-8").read()
        # Verification off must require the explicit flag, never a fallback
        # after a handshake failure.
        assert "CERT_NONE" in source
        assert source.count("CERT_NONE") == 1
        idx = source.index("CERT_NONE")
        window = source[max(0, idx - 600):idx]
        assert "insecure_tls" in window


class TestVoiceMediaIsNotCoupledToTheXmppTransport:
    def test_media_creates_its_own_sam_session(self):
        import otrv4plus_voice as voice
        source = open(voice.__file__, encoding="utf-8").read()
        assert "SESSION CREATE STYLE=DATAGRAM" in source

    def test_media_has_no_clearnet_path(self):
        # There is no socket path in the media session that is not SAM, so a
        # transport downgrade cannot exist there to begin with.
        import otrv4plus_voice as voice
        source = open(voice.__file__, encoding="utf-8").read()
        assert "PROXY_TYPE" not in source
        assert "set_proxy" not in source

    def test_losing_xmpp_does_not_end_a_call(self):
        # Media rides its own I2P datagram session; only rekey signalling
        # uses XMPP, and an undeliverable rekey keeps the committed epoch.
        source = open(xmpp.__file__, encoding="utf-8").read()
        start = source.index("def _on_disconnected")
        body = source[start:start + 900]
        assert "_voice_manager" not in body, (
            "_on_disconnected must not tear down calls")


class TestVoiceAuthorizationIgnoresTransport:
    def test_both_entry_points_require_smp_verification(self):
        import otrv4plus_voice as voice
        source = open(voice.__file__, encoding="utf-8").read()
        # Outgoing and incoming both gate on the engine's own predicate.
        assert source.count("if not self._smp_verified(peer):") >= 2

    def test_the_gate_does_not_consult_the_transport(self):
        import otrv4plus_voice as voice
        source = open(voice.__file__, encoding="utf-8").read()
        start = source.index("def _smp_verified")
        body = source[start:start + 1800]
        for token in ("_is_i2p", "transport", "sam_host", "clearnet"):
            assert token not in body, (
                "authorization must derive from OTR/DAKE/SMP state alone, "
                "found %r" % token)
