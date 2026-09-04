"""XMPP over Tor: SOCKS5 tunnel, DNS containment, and fail-closed behaviour.

The property that decides whether Tor support is safe at all is DNS. A
.onion has no address a resolver could return, so resolving it locally is
both useless and a disclosure of intent. The destination therefore travels
as a DOMAIN NAME inside the SOCKS5 CONNECT (ATYP 0x03) and Tor resolves it
inside the network.

The second property is that slixmpp never sees the onion name. It is handed
a loopback address for the local forwarder, and its own docstring says "If an
address was provided, disable using DNS SRV lookup" -- so there is no SRV
query either.

PySocks is deliberately unused: it works by replacing socket.socket globally,
which in this process would also capture the I2P SAM bridge and every voice
media socket.

These are code-path tests against a stand-in SOCKS5 server. They do NOT prove
that a real Tor daemon carries a real XMPP session.
"""

import asyncio
import socket

import pytest

pytest.importorskip("slixmpp")
import otrv4plus_xmpp as xmpp


# ---------------------------------------------------------------------------
# A stand-in SOCKS5 server that records what it was asked for
# ---------------------------------------------------------------------------

class FakeSocks5:
    def __init__(self, reply=0x00, offer_auth=False, bad_version=False):
        self.requests = []
        self.reply = reply
        self.offer_auth = offer_auth
        self.bad_version = bad_version
        self.server = None
        self.payload_seen = bytearray()

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[:2]

    async def stop(self):
        # No wait_closed(): the forwarder deliberately holds its tunnel open
        # for the process lifetime, so waiting for connections to drain would
        # block forever. Closing the listener is enough for a test.
        self.server.close()

    async def _handle(self, reader, writer):
        try:
            head = await reader.readexactly(2)
            await reader.readexactly(head[1])          # methods
            writer.write(bytes([0x04 if self.bad_version else 0x05,
                                0x02 if self.offer_auth else 0x00]))
            await writer.drain()
            if self.bad_version or self.offer_auth:
                return

            req = await reader.readexactly(4)
            atyp = req[3]
            if atyp == 0x03:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode()
            elif atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            else:
                host = "?"
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requests.append((atyp, host, port))

            writer.write(bytes([0x05, self.reply, 0x00, 0x01,
                                127, 0, 0, 1, 0x00, 0x50]))
            await writer.drain()
            if self.reply != 0x00:
                return
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                self.payload_seen += data
                writer.write(b"echo:" + data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def _run(coro, timeout=10.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


def _close_forwarders():
    """Release forwarders the module pins for the process lifetime.

    start_tor_socks_forwarder keeps its server and tunnel alive on purpose --
    losing them to the garbage collector mid-session would drop the XMPP
    connection. Tests have to undo that explicitly or the loop cannot close.
    """
    while xmpp._TOR_FORWARDERS:
        server, _reader, writer = xmpp._TOR_FORWARDERS.pop()
        for closeable in (server, writer):
            try:
                closeable.close()
            except Exception:
                pass


ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion"


class TestSocks5Handshake:
    def test_the_destination_travels_as_a_domain_name(self):
        # THE test. ATYP 0x03 means Tor resolves it; anything else means we
        # resolved it first, which for a .onion is impossible and for any
        # host is a disclosure.
        async def _go():
            proxy = FakeSocks5()
            host, port = await proxy.start()
            reader, writer = await xmpp.socks5_connect(
                ONION, 5222, socks_host=host, socks_port=port)
            writer.close()
            await proxy.stop()
            return proxy.requests

        requests = _run(_go())
        assert len(requests) == 1
        atyp, sent_host, sent_port = requests[0]
        assert atyp == xmpp.SOCKS5_ATYP_DOMAIN, "destination was not a domain"
        assert sent_host == ONION
        assert sent_port == 5222

    def test_bytes_flow_through_the_tunnel(self):
        async def _go():
            proxy = FakeSocks5()
            host, port = await proxy.start()
            reader, writer = await xmpp.socks5_connect(
                ONION, 5222, socks_host=host, socks_port=port)
            writer.write(b"<stream:stream>")
            await writer.drain()
            echoed = await reader.readexactly(len(b"echo:<stream:stream>"))
            writer.close()
            await proxy.stop()
            return echoed

        assert _run(_go()) == b"echo:<stream:stream>"

    @pytest.mark.parametrize("code,fragment", [
        (0x04, "host unreachable"),
        (0x05, "connection refused"),
        (0x02, "not allowed"),
    ])
    def test_a_refusal_raises_rather_than_returning_a_broken_stream(self, code,
                                                                   fragment):
        async def _go():
            proxy = FakeSocks5(reply=code)
            host, port = await proxy.start()
            try:
                await xmpp.socks5_connect(ONION, 5222, socks_host=host,
                                          socks_port=port)
            finally:
                await proxy.stop()

        with pytest.raises(ConnectionError, match=fragment):
            _run(_go())

    def test_a_non_socks5_listener_is_rejected(self):
        async def _go():
            proxy = FakeSocks5(bad_version=True)
            host, port = await proxy.start()
            try:
                await xmpp.socks5_connect(ONION, 5222, socks_host=host,
                                          socks_port=port)
            finally:
                await proxy.stop()

        with pytest.raises(ConnectionError, match="not a SOCKS5 proxy"):
            _run(_go())

    def test_a_proxy_demanding_authentication_is_rejected(self):
        async def _go():
            proxy = FakeSocks5(offer_auth=True)
            host, port = await proxy.start()
            try:
                await xmpp.socks5_connect(ONION, 5222, socks_host=host,
                                          socks_port=port)
            finally:
                await proxy.stop()

        with pytest.raises(ConnectionError, match="authentication"):
            _run(_go())

    def test_no_proxy_at_all_fails_closed(self):
        # Nothing listening: must raise, never return something usable.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]
        with pytest.raises(Exception):
            _run(xmpp.socks5_connect(ONION, 5222, socks_host="127.0.0.1",
                                     socks_port=dead_port, timeout=2.0))


class TestForwarderKeepsTheOnionOffTheResolver:
    def test_slixmpp_is_handed_a_loopback_address(self):
        # The onion name never reaches slixmpp, so it cannot SRV-resolve it.
        async def _go():
            proxy = FakeSocks5()
            host, port = await proxy.start()
            local_host, local_port = await xmpp.start_tor_socks_forwarder(
                ONION, 5222, socks_host=host, socks_port=port)
            _close_forwarders()
            await proxy.stop()
            return local_host, local_port, proxy.requests

        local_host, local_port, requests = _run(_go())
        assert local_host == "127.0.0.1"
        assert local_port > 0
        assert requests[0][1] == ONION, "the onion went to Tor, not a resolver"

    def test_no_name_resolution_happens_locally(self, monkeypatch):
        # Hard proof: make every local resolver call explode, then run the
        # whole path. If anything resolved the onion, this fails.
        def _boom(*a, **kw):
            raise AssertionError("a hostname was resolved locally")

        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        monkeypatch.setattr(socket, "gethostbyname", _boom, raising=False)

        async def _go():
            proxy = FakeSocks5()
            host, port = await proxy.start()
            # Numeric host, so asyncio needs no resolution of its own.
            reader, writer = await xmpp.socks5_connect(
                ONION, 5222, socks_host=host, socks_port=port)
            writer.close()
            await proxy.stop()
            return proxy.requests

        requests = _run(_go())
        assert requests[0][1] == ONION


class TestPysocksIsNotUsed:
    def test_the_global_socket_class_is_never_replaced(self):
        # PySocks routes by assigning socket.socket globally, which here
        # would also capture the I2P SAM bridge and every voice media socket.
        source = open(xmpp.__file__, encoding="utf-8").read()
        assert "socket.socket = " not in source
        assert "setdefaultproxy" not in source


class TestReconnectPreservesTor:
    class _Harness:
        _reconnect = xmpp.OTRv4PlusXMPP._reconnect
        _has_transport_params = xmpp.OTRv4PlusXMPP._has_transport_params

        def __init__(self, tor_params, tor_works=True):
            self._shutting_down = False
            self._is_i2p = False
            self._is_tor = True
            self._sam_params = None
            self._tor_params = tor_params
            self._reconnect_delay = 0
            self.direct_connects = 0
            self.forwarded_connects = 0

        def connect(self, host=None, port=None):
            if host is None:
                self.direct_connects += 1
            else:
                self.forwarded_connects += 1

    TOR_PARAMS = {"onion_host": ONION, "dest_port": 5222,
                  "socks_host": "127.0.0.1", "socks_port": 9050}

    def _patch(self, monkeypatch, works):
        async def _fwd(onion_host, dest_port, socks_host=None, socks_port=None):
            if not works:
                raise ConnectionError("tor down")
            return ("127.0.0.1", 45000)
        monkeypatch.setattr(xmpp, "start_tor_socks_forwarder", _fwd)

    def test_a_healthy_reconnect_goes_back_through_tor(self, monkeypatch):
        self._patch(monkeypatch, works=True)
        h = self._Harness(self.TOR_PARAMS)
        _run(h._reconnect())
        assert h.forwarded_connects == 1
        assert h.direct_connects == 0

    def test_a_dead_tor_never_connects_directly(self, monkeypatch):
        self._patch(monkeypatch, works=False)
        h = self._Harness(self.TOR_PARAMS)

        async def _stop():
            await asyncio.sleep(0.05)
            h._shutting_down = True

        async def _both():
            await asyncio.gather(h._reconnect(), _stop())

        _run(_both())
        assert h.direct_connects == 0, "Tor session reached the server directly"

    def test_missing_socks_parameters_refuse_rather_than_downgrade(self, monkeypatch,
                                                                   capsys):
        self._patch(monkeypatch, works=True)
        h = self._Harness(None)
        _run(h._reconnect())
        assert h.direct_connects == 0
        assert "refus" in capsys.readouterr().out.lower()

    def test_reconnect_is_scheduled_for_a_tor_session(self):
        h = self._Harness(self.TOR_PARAMS)
        assert h._has_transport_params() is True

    def test_reconnect_is_not_scheduled_without_any_transport(self):
        h = self._Harness(None)
        assert h._has_transport_params() is False
