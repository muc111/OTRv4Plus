# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The 3-hop requirement, asked for on the wire instead of assumed.

The requirement was documented everywhere and asserted nowhere. `SESSION
CREATE` carried no tunnel-length option at all, so the length was whatever the
router defaulted to -- and a router set to `inbound.length=1`, a common
latency tweak, would have given this application a 1-hop path while the call
summary printed `6 I2P hops` from a format string.

These tests execute the request rather than describing it: they drive a real
`create_session()` against a fake SAM bridge and read the bytes that came out
of the socket.

WHAT THEY DELIBERATELY DO NOT TEST
----------------------------------
That the router obeyed. It cannot be tested from here and it is not claimed --
see `TestTheLimitIsStated`.
"""

import asyncio
import os
import socket as _socket
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_mediapath as mp
import otrv4plus_voice as V


# ── driving the real SESSION CREATE ──────────────────────────────────────────

def _capture(transport_mode):
    """Run `create_session()` against a fake SAM and return what it sent."""
    opened = []
    sent = []
    saved = {k: V._HOST[k] for k in ("sam_open", "sam_read_line", "sam_parse")}

    def _open(host, port, timeout):
        a, b = _socket.socketpair()
        opened.append((a, b))
        return a

    def _read(sock, timeout):
        # Drain whatever create_session() wrote before answering it.
        peer = opened[-1][1]
        peer.settimeout(2.0)
        sent.append(peer.recv(65535).decode("ascii"))
        body = (b"\x01" * 384) + bytes([5]) + (4).to_bytes(2, "big") + b"cert"
        return ("SESSION STATUS RESULT=OK DESTINATION=%s"
                % V.i2p_b64encode(body))

    def _parse(line, prefix):
        return dict(p.split("=", 1) for p in line[len(prefix):].split())

    async def _drive():
        s = object.__new__(V.VoiceCallSession)
        s.loop = asyncio.get_event_loop()
        s.sam_host, s.sam_port = "127.0.0.1", 7656
        s._transport_mode = transport_mode
        s._dgram_sock = None
        s._dgram_transport = None
        s._dgram_send_header = None
        s._sam_control = None
        s._sam_session_id = None
        s._our_dest = None
        s._sam_pending = []
        await s.create_session()
        s._close_datagram_transport()

    V.bind_host(sam_open=_open, sam_read_line=_read, sam_parse=_parse)
    try:
        asyncio.run(asyncio.wait_for(_drive(), 10))
    finally:
        V._HOST.update(saved)
        for a, b in opened:
            for sock in (a, b):
                try:
                    sock.close()
                except Exception:
                    pass
    assert sent, "create_session() sent nothing"
    return sent[0]


class TestTheRequestIsOnTheWire:
    """THE FIX. Not "the source mentions inbound.length" -- the bytes that
    left the socket contain it."""

    @pytest.mark.parametrize("mode", [V.VOICE_TRANSPORT_DATAGRAM,
                                      V.VOICE_TRANSPORT_STREAM])
    def test_session_create_carries_three_hops_each_way(self, mode):
        line = _capture(mode)
        assert "SESSION CREATE" in line
        assert "inbound.length=3" in line
        assert "outbound.length=3" in line

    @pytest.mark.parametrize("mode", [V.VOICE_TRANSPORT_DATAGRAM,
                                      V.VOICE_TRANSPORT_STREAM])
    def test_the_variance_is_pinned_on_the_wire_too(self, mode):
        """Without this the length is a midpoint. See `TestARouterCannot
        SilentlyReduceTheLength`."""
        line = _capture(mode)
        assert "inbound.lengthVariance=0" in line
        assert "outbound.lengthVariance=0" in line

    def test_both_transports_ask_for_the_same_path(self):
        """The stream transport is the datagram transport's fallback, and a
        fallback that quietly drops to the router's default would be the
        original defect with an extra step in front of it."""
        datagram = _capture(V.VOICE_TRANSPORT_DATAGRAM)
        stream = _capture(V.VOICE_TRANSPORT_STREAM)
        for option in mp.tunnel_options().split():
            assert option in datagram, option
            assert option in stream, option

    def test_the_line_is_still_well_formed_sam(self):
        """One line, space-separated `key=value` fields, terminated once.

        i2pd's parser splits on spaces and keeps every field containing `=`
        (`SAMSocket::ExtractParams`), so a stray newline or a doubled space
        is the difference between an option and a dropped option.
        """
        line = _capture(V.VOICE_TRANSPORT_DATAGRAM)
        assert line.endswith("\n")
        assert line.count("\n") == 1
        assert "  " not in line
        head, _, rest = line.strip().partition("SESSION CREATE ")
        assert head == ""
        for field in rest.split():
            if field in ("STYLE=DATAGRAM",):
                continue
            assert "=" in field, field

    def test_the_transient_destination_survived_the_change(self):
        """A per-call identity is the other half of the privacy story, and it
        sits on the same line that just grew four fields."""
        line = _capture(V.VOICE_TRANSPORT_DATAGRAM)
        assert "DESTINATION=TRANSIENT" in line
        assert "SIGNATURE_TYPE=7" in line

    def test_the_datagram_forward_port_survived_the_change(self):
        line = _capture(V.VOICE_TRANSPORT_DATAGRAM)
        assert "HOST=127.0.0.1" in line
        assert "PORT=" in line
        port = [f for f in line.split() if f.startswith("PORT=")][0]
        assert int(port.split("=", 1)[1]) > 0, "no forward port was bound"


# ── the reason the variance is there at all ──────────────────────────────────

class TestARouterCannotSilentlyReduceTheLength:
    """`inbound.length=3` alone does NOT mean "at least three hops".

    From i2pd `TunnelPool.cpp:645-660`:

        numHops = m_NumInboundHops;
        if (m_InboundVariance) {
            int offset = rng() % (std::abs(m_InboundVariance) + 1);
            if (m_InboundVariance < 0) offset = -offset;
            numHops += offset;
        }

    Length is the centre of a range and variance is its width, so a router
    holding a negative variance would build fewer hops than were asked for
    and answer `RESULT=OK` either way. Pinning the variance is what turns the
    request into a floor.
    """

    def test_the_pinned_configuration_admits_exactly_three_hops(self):
        assert mp.hop_range(mp.REQUIRED_HOPS, mp.LENGTH_VARIANCE) == (3, 3)

    def test_the_shipped_options_are_the_pinned_configuration(self):
        options = dict(mp.TUNNEL_OPTIONS)
        for direction in ("inbound", "outbound"):
            low, high = mp.hop_range(options["%s.length" % direction],
                                     options["%s.lengthVariance" % direction])
            assert low == mp.REQUIRED_HOPS, direction
            assert high == mp.REQUIRED_HOPS, direction

    def test_a_negative_variance_would_have_reduced_it(self):
        """The attack the pin closes, stated as arithmetic."""
        assert mp.hop_range(3, -2) == (1, 5)
        assert mp.hop_range(3, -1)[0] == 2
        assert mp.hop_range(3, -2)[0] < mp.REQUIRED_HOPS

    def test_a_positive_variance_never_goes_below_the_request(self):
        assert mp.hop_range(3, 1) == (3, 4)
        assert mp.hop_range(3, 5)[0] == 3

    def test_a_one_hop_router_default_is_overridden_not_inherited(self):
        """The concrete scenario: a router configured for the common
        `inbound.length=1` latency tweak. The client no longer inherits it,
        because it names its own value on every session."""
        options = dict(mp.TUNNEL_OPTIONS)
        assert options["inbound.length"] == 3
        assert options["outbound.length"] == 3
        assert mp.hop_range(1, 0) == (1, 1)      # what it used to inherit
        assert mp.hop_range(options["inbound.length"],
                            options["inbound.lengthVariance"]) == (3, 3)

    def test_zero_hops_are_not_reachable_from_the_shipped_options(self):
        """A zero-hop tunnel publishes the local router as the endpoint. It
        must not be an outcome of any variance draw."""
        options = dict(mp.TUNNEL_OPTIONS)
        for direction in ("inbound", "outbound"):
            low, _ = mp.hop_range(options["%s.length" % direction],
                                  options["%s.lengthVariance" % direction])
            assert low > 0, direction

    def test_the_range_never_goes_negative(self):
        assert mp.hop_range(1, -5)[0] == 0


# ── the two tunnels stay two tunnels ─────────────────────────────────────────

class TestTheArchitectureIsNotDescribedAsSixHops:

    def test_inbound_and_outbound_are_configured_separately(self):
        names = [name for name, _ in mp.TUNNEL_OPTIONS]
        assert "inbound.length" in names
        assert "outbound.length" in names

    def test_nothing_anywhere_asks_for_six(self):
        assert mp.REQUIRED_HOPS == 3
        for _, value in mp.TUNNEL_OPTIONS:
            assert value != 6
        assert "6" not in mp.tunnel_options()
        assert "6" not in mp.hop_note()

    def test_the_summary_line_describes_two_tunnels(self):
        note = mp.hop_note()
        assert "inbound" in note and "outbound" in note

    def test_the_options_render_in_a_stable_order(self):
        """So the wire form is reviewable and the tests above are not
        accidentally order-dependent."""
        assert mp.tunnel_options() == (
            "inbound.length=3 outbound.length=3 "
            "inbound.lengthVariance=0 outbound.lengthVariance=0")


# ── what is NOT claimed ──────────────────────────────────────────────────────

class TestTheLimitIsStated:
    """§: "If the underlying SAM/I2CP interface cannot guarantee that the
    requested value was actually accepted, make that limitation explicit
    rather than claiming enforcement."

    It cannot. SAM answers `SESSION CREATE` with

        SESSION STATUS RESULT=OK DESTINATION=$privkey

    and nothing else -- there is no accepted-options echo in the SAM v3
    grammar, so a router that clamped or ignored `inbound.length` replies
    exactly like one that honoured it.
    """

    def test_confirmation_is_reported_as_absent(self):
        assert mp.hops_are_confirmed() is False

    def test_requesting_and_confirming_are_separate_questions(self):
        """The whole point. The old code could not tell them apart because it
        did neither."""
        assert mp.hops_are_configured() is True
        assert mp.hops_are_confirmed() is False

    def test_the_note_says_the_router_was_not_heard_from(self):
        assert "SAM does not report" in mp.hop_note()

    def test_the_session_status_reply_carries_no_tunnel_information(self):
        """Stated against the parsed reply, so the day SAM grows an
        accepted-options field this test is where somebody notices."""
        line = _capture(V.VOICE_TRANSPORT_DATAGRAM)
        assert "inbound.length=3" in line        # we asked
        reply = "SESSION STATUS RESULT=OK DESTINATION=abc"
        assert "length" not in reply             # it did not answer

    def test_no_code_path_reports_a_measured_hop_count(self):
        """There is no measurement to report. A function returning one would
        be the `6 I2P hops` literal again."""
        assert not hasattr(mp, "measured_hops")
        assert not hasattr(mp, "actual_hops")


# ── it still leaks nothing ───────────────────────────────────────────────────

class TestTheOptionsCarryNothingIdentifying:

    def test_the_option_string_is_numbers_and_names_only(self):
        text = mp.tunnel_options()
        for forbidden in ("@", ".i2p", "b32", "127.0.0.1"):
            assert forbidden not in text, forbidden

    def test_the_options_do_not_touch_quantity_or_backups(self):
        """The brief allowed tunnel *length* to change and nothing else.
        Quantity and backup quantity are load and reliability knobs, not the
        security property, and they stay with the router."""
        names = {name for name, _ in mp.TUNNEL_OPTIONS}
        for unrelated in ("inbound.quantity", "outbound.quantity",
                          "inbound.backupQuantity", "outbound.backupQuantity",
                          "inbound.allowZeroHop", "i2cp.reduceOnIdle",
                          "i2cp.closeOnIdle", "inbound.nickname"):
            assert unrelated not in names, unrelated

    def test_only_length_and_variance_are_set(self):
        for name, _ in mp.TUNNEL_OPTIONS:
            assert name.endswith(".length") or name.endswith(".lengthVariance")
