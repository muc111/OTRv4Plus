"""Media over SAM datagrams.

The stream transport could not carry a call: it is reliable and ordered, so
congestion became delay instead of loss. A live call reached 24 s of one-way
delay with drop=0/late=0/authfail=0 and recovered by draining a standing
queue at a constant rate. i2pd fixes INITIAL_RTO at 9000 ms at compile time,
so a single lost segment stalls every frame behind it for nine seconds and no
sender-side tuning can change that.

These tests cover the datagram path that replaces it: SAM framing, the
send/receive plumbing against a stand-in SAM UDP bridge, the destination
filter, and the fallback that keeps the stream transport reachable.
"""

import asyncio
import os
import socket

import pytest

import otrv4plus_voice as voice


# --------------------------------------------------------------------------
# SAM v3 datagram framing
# --------------------------------------------------------------------------

class TestSendHeader:
    def test_it_is_the_sam_v3_datagram_form(self):
        header = voice.build_datagram_send_header("sess-1", "DESTBASE64")
        assert header == b"3.0 sess-1 DESTBASE64\n"

    def test_the_payload_is_not_length_prefixed(self):
        # The UDP datagram boundary is the frame boundary. A length prefix
        # would reintroduce the stream framing this transport exists to leave
        # behind.
        header = voice.build_datagram_send_header("s", "d")
        assert header.endswith(b"\n")
        assert not header.startswith(b"\x00")

    def test_it_is_ascii_and_single_line(self):
        header = voice.build_datagram_send_header("s", "d")
        assert header.count(b"\n") == 1
        header.decode("ascii")


class TestReceiveSplit:
    def test_a_repliable_datagram_yields_source_and_payload(self):
        dest = "A" * 516
        source, payload = voice.split_datagram_receive(
            dest.encode() + b"\n" + b"\xa7payload")
        assert source == dest
        assert payload == b"\xa7payload"

    def test_a_payload_with_no_header_is_returned_whole(self):
        # A router forwarding RAW has no source line; the payload still
        # authenticates, so it must not be discarded.
        source, payload = voice.split_datagram_receive(b"\xa7no header here")
        assert source is None
        assert payload == b"\xa7no header here"

    def test_a_binary_first_line_is_not_mistaken_for_a_destination(self):
        source, payload = voice.split_datagram_receive(b"\xff\xfe\n\xa7body")
        assert source is None

    def test_a_short_first_line_is_not_a_destination(self):
        source, payload = voice.split_datagram_receive(b"abc\n\xa7body")
        assert source is None
        assert payload == b"abc\n\xa7body"

    def test_a_payload_containing_newlines_survives(self):
        dest = "B" * 516
        body = b"\xa7\n\n\x00\n"
        source, payload = voice.split_datagram_receive(
            dest.encode() + b"\n" + body)
        assert source == dest
        assert payload == body

    def test_an_empty_datagram_is_handled(self):
        source, payload = voice.split_datagram_receive(b"")
        assert source is None
        assert payload == b""


# --------------------------------------------------------------------------
# Transport selection
# --------------------------------------------------------------------------

class TestTransportSelection:
    def test_datagram_is_the_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_VOICE_TRANSPORT", raising=False)
        assert voice.voice_transport_mode() == voice.VOICE_TRANSPORT_DATAGRAM

    def test_the_stream_transport_stays_reachable(self, monkeypatch):
        # A router with SAM UDP disabled cannot do datagrams at all.
        monkeypatch.setenv("OTRV4PLUS_VOICE_TRANSPORT", "stream")
        assert voice.voice_transport_mode() == voice.VOICE_TRANSPORT_STREAM

    def test_an_unrecognised_value_does_not_silently_pick_stream(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_VOICE_TRANSPORT", "quic")
        assert voice.voice_transport_mode() == voice.VOICE_TRANSPORT_DATAGRAM

    def test_the_sam_udp_port_defaults_to_the_i2pd_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_SAM_UDP_PORT", raising=False)
        assert voice.sam_udp_port() == 7655

    def test_the_sam_udp_port_is_overridable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SAM_UDP_PORT", "7699")
        assert voice.sam_udp_port() == 7699

    @pytest.mark.parametrize("bad", ["0", "70000", "", "abc", "-1"])
    def test_a_nonsense_port_falls_back_to_the_default(self, monkeypatch, bad):
        monkeypatch.setenv("OTRV4PLUS_SAM_UDP_PORT", bad)
        assert voice.sam_udp_port() == 7655


# --------------------------------------------------------------------------
# Send / receive against a stand-in SAM UDP bridge
# --------------------------------------------------------------------------

DEST_A = "A" * 516
DEST_B = "B" * 516


def _session(mode=voice.VOICE_TRANSPORT_DATAGRAM):
    """A VoiceCallSession carrying only the transport state."""
    s = object.__new__(voice.VoiceCallSession)
    s._running = True
    s._writer = None
    s._transport_mode = mode
    s._dgram_sock = None
    s._dgram_transport = None
    s._dgram_send_addr = None
    s._dgram_send_header = None
    s._sam_session_id = "sess-1"
    s._peer_dest = None
    # Built from the production key set, not restated here: a hand-rolled
    # copy went stale the moment a counter was added.
    s.stats = voice.new_media_stats()
    s._foreign_warned = True          # suppress the console warning in tests
    s.loop = None
    return s


class TestDatagramSocketBinding:
    def test_it_binds_loopback_only(self):
        # This socket is reachable by anything that can send it a packet and
        # the AEAD is the only thing behind it, so it must not be off-device.
        s = _session()
        port = s._bind_datagram_socket()
        try:
            assert 1 <= port <= 65535
            assert s._dgram_sock.getsockname()[0] == "127.0.0.1"
        finally:
            s._dgram_sock.close()

    def test_the_socket_is_non_blocking(self):
        s = _session()
        s._bind_datagram_socket()
        try:
            assert s._dgram_sock.gettimeout() == 0.0
        finally:
            s._dgram_sock.close()


async def _body_a_packet_reaches_the_sam_bridge_with_the_right_header():
    """The full send path, against a UDP socket standing in for SAM."""
    bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bridge.bind(("127.0.0.1", 0))
    bridge.settimeout(2.0)
    bridge_port = bridge.getsockname()[1]

    s = _session()
    s.loop = asyncio.get_running_loop()
    s.sam_host = "127.0.0.1"
    s._peer_dest = DEST_B
    s._bind_datagram_socket()
    os.environ["OTRV4PLUS_SAM_UDP_PORT"] = str(bridge_port)
    try:
        await s.open_datagram_endpoint()
        assert s._datagram_ready()

        packet = bytes([voice.VOICE_SYNC]) + b"\x01" * 40
        s._write_packet(packet, None)
        await asyncio.sleep(0.05)

        data, _addr = bridge.recvfrom(voice.SAM_DATAGRAM_MAX)
        assert data == b"3.0 sess-1 " + DEST_B.encode() + b"\n" + packet
        assert s.stats["sent"] == 1
    finally:
        os.environ.pop("OTRV4PLUS_SAM_UDP_PORT", None)
        if s._dgram_transport is not None:
            s._dgram_transport.close()
        bridge.close()


async def _body_the_initiator_cannot_send_before_it_knows_the_peer():
    s = _session()
    s.loop = asyncio.get_running_loop()
    s.sam_host = "127.0.0.1"
    s._bind_datagram_socket()
    try:
        await s.open_datagram_endpoint()
        assert s._dgram_send_header is None
        s._write_packet(bytes([voice.VOICE_SYNC]) + b"\x00" * 40, None)
        # Counted, not silently dropped: a peer that never sends must be
        # distinguishable from a lossy path.
        assert s.stats["backpressure"] == 1
        assert s.stats["sent"] == 0
    finally:
        if s._dgram_transport is not None:
            s._dgram_transport.close()


class TestInboundFiltering:
    def _armed(self, drained):
        s = _session()
        s._drain_buffer = lambda buf: drained.append(bytes(buf))
        return s

    def test_a_datagram_from_the_peer_is_parsed(self):
        drained = []
        s = self._armed(drained)
        s._peer_dest = DEST_B
        s._on_datagram(DEST_B.encode() + b"\n" + b"\xa7frame")
        assert drained == [b"\xa7frame"]

    def test_a_datagram_from_a_stranger_never_reaches_the_cipher(self):
        drained = []
        s = self._armed(drained)
        s._peer_dest = DEST_B
        s._on_datagram(DEST_A.encode() + b"\n" + b"\xa7frame")
        assert drained == []
        # Counted as foreign, not as a drop: a filter rejecting everything and
        # a path losing everything are different faults and looked identical
        # while they shared a counter.
        assert s.stats["foreign"] == 1
        assert s.stats["dropped"] == 0

    def test_a_datagram_with_no_source_still_reaches_the_cipher(self):
        # RAW forwarding carries no source. The AEAD is the real boundary.
        drained = []
        s = self._armed(drained)
        s._peer_dest = DEST_B
        s._on_datagram(b"\xa7frame")
        assert drained == [b"\xa7frame"]

    def test_nothing_is_parsed_once_the_session_stops(self):
        drained = []
        s = self._armed(drained)
        s._running = False
        s._on_datagram(DEST_B.encode() + b"\n" + b"\xa7frame")
        assert drained == []

    def test_a_drain_failure_is_counted_rather_than_raised(self):
        s = _session()

        def _boom(buf):
            raise ValueError("bad frame")

        s._drain_buffer = _boom
        s._on_datagram(b"\xa7frame")
        assert s.stats["dropped"] == 1


class TestPeerDestinationLatching:
    def test_it_latches_only_on_a_datagram_that_authenticates(self):
        # The initiator published a destination and waited to be connected to,
        # so it never learns the callee's from signalling. Latching from the
        # first packet that survives the AEAD is safe; latching from any
        # packet at all would let a stranger claim the slot.
        s = _session()
        s._drain_buffer = lambda buf: s.stats.__setitem__(
            "recv", s.stats["recv"] + 1)
        s._on_datagram(DEST_B.encode() + b"\n" + b"\xa7frame")
        assert s._peer_dest == DEST_B
        assert s._dgram_send_header == b"3.0 sess-1 " + DEST_B.encode() + b"\n"

    def test_a_datagram_that_fails_to_authenticate_latches_nothing(self):
        s = _session()
        s._drain_buffer = lambda buf: None     # nothing authenticated
        s._on_datagram(DEST_A.encode() + b"\n" + b"\xa7garbage")
        assert s._peer_dest is None
        assert s._dgram_send_header is None

    def test_the_latch_does_not_move_once_set(self):
        s = _session()
        s._peer_dest = DEST_B
        s._drain_buffer = lambda buf: s.stats.__setitem__(
            "recv", s.stats["recv"] + 1)
        s._on_datagram(DEST_A.encode() + b"\n" + b"\xa7frame")
        assert s._peer_dest == DEST_B
        assert s.stats["foreign"] == 1


async def _body_two_sessions_exchange_frames_through_a_stand_in_bridge():
    """End to end: A -> bridge -> B and back, with real sockets.

    The bridge does what i2pd's SAM UDP bridge does -- strip the send header,
    prepend the sender's destination, forward to the other side's port.
    """
    loop = asyncio.get_running_loop()

    a, b = _session(), _session()
    for s in (a, b):
        s.loop = loop
        s.sam_host = "127.0.0.1"
    port_a = a._bind_datagram_socket()
    port_b = b._bind_datagram_socket()

    got_a, got_b = [], []
    a._drain_buffer = lambda buf: (got_a.append(bytes(buf)),
                                   a.stats.__setitem__("recv",
                                                       a.stats["recv"] + 1))
    b._drain_buffer = lambda buf: (got_b.append(bytes(buf)),
                                   b.stats.__setitem__("recv",
                                                       b.stats["recv"] + 1))

    ports = {DEST_A: port_a, DEST_B: port_b}
    dest_of = {port_a: DEST_A, port_b: DEST_B}

    bridge = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bridge.bind(("127.0.0.1", 0))
    bridge.setblocking(False)
    bridge_port = bridge.getsockname()[1]

    class _Bridge(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            head, _, payload = data.partition(b"\n")
            _ver, _sid, dest = head.decode().split(" ", 2)
            sender = dest_of[addr[1]]
            bridge.sendto(sender.encode() + b"\n" + payload,
                          ("127.0.0.1", ports[dest]))

    bridge_transport, _ = await loop.create_datagram_endpoint(
        _Bridge, sock=bridge)

    os.environ["OTRV4PLUS_SAM_UDP_PORT"] = str(bridge_port)
    try:
        # B knows A's destination from the INVITE; A knows nothing yet.
        b._peer_dest = DEST_A
        await a.open_datagram_endpoint()
        await b.open_datagram_endpoint()

        assert b._dgram_send_header is not None
        assert a._dgram_send_header is None

        frame = bytes([voice.VOICE_SYNC]) + b"\x11" * 40
        b._write_packet(frame, None)
        await asyncio.sleep(0.1)

        assert got_a == [frame], "callee -> caller did not arrive"
        # A has now learned B's destination from that packet and can reply.
        assert a._peer_dest == DEST_B
        assert a._dgram_send_header is not None

        reply = bytes([voice.VOICE_SYNC]) + b"\x22" * 40
        a._write_packet(reply, None)
        await asyncio.sleep(0.1)
        assert got_b == [reply], "caller -> callee did not arrive"
    finally:
        os.environ.pop("OTRV4PLUS_SAM_UDP_PORT", None)
        for s in (a, b):
            if s._dgram_transport is not None:
                s._dgram_transport.close()
        bridge_transport.close()


async def _body_out_of_order_and_duplicate_datagrams_reach_the_parser():
    """Datagrams reorder and duplicate; that is the trade being made.

    Both are already handled downstream -- the jitter buffer is sequence
    aware and each epoch carries a replay window -- so the transport's job is
    simply to deliver them, not to restore order.
    """
    s = _session()
    seen = []
    s._drain_buffer = lambda buf: seen.append(bytes(buf))
    s._peer_dest = DEST_B
    for body in (b"\xa7three", b"\xa7one", b"\xa7two", b"\xa7one"):
        s._on_datagram(DEST_B.encode() + b"\n" + body)
    assert seen == [b"\xa7three", b"\xa7one", b"\xa7two", b"\xa7one"]


class TestStreamTransportIsUntouched:
    def test_a_stream_session_is_never_reported_datagram_ready(self):
        s = _session(mode=voice.VOICE_TRANSPORT_STREAM)
        assert s._datagram_ready() is False

    def test_a_datagram_session_without_a_transport_is_not_ready(self):
        s = _session()
        assert s._datagram_ready() is False


# ---------------------------------------------------------------------------
# The repo carries no async test plugin and the phones must not need one, so
# the coroutine bodies above are driven directly.
# ---------------------------------------------------------------------------

def test_a_packet_reaches_the_sam_bridge_with_the_right_header():
    asyncio.run(_body_a_packet_reaches_the_sam_bridge_with_the_right_header())


def test_the_initiator_cannot_send_before_it_knows_the_peer():
    asyncio.run(_body_the_initiator_cannot_send_before_it_knows_the_peer())


def test_two_sessions_exchange_frames_through_a_stand_in_bridge():
    asyncio.run(_body_two_sessions_exchange_frames_through_a_stand_in_bridge())


def test_out_of_order_and_duplicate_datagrams_reach_the_parser():
    asyncio.run(_body_out_of_order_and_duplicate_datagrams_reach_the_parser())
