# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The `?OTRv4F|` wire format, and the fact that two clients speak it.

WHY THESE TESTS EXIST
---------------------
Fragmentation lived in `otrv4plus_xmpp.py` as two methods on the terminal
client. `android_bridge` had neither, and the consequence was not a degraded
experience -- it was a hard interoperability failure in both directions:

  * Termux -> Android: a DAKE2 goes out as several `?OTRv4F|` stanzas. The
    Android side handed each one to the engine as if it were a whole frame.
  * Android -> Termux: the same DAKE2 went out as one ~11.7 KB stanza, aimed
    straight at the ~8 KB I2P cliff `MAX_FRAGMENT` exists to stay under.

Either way the handshake never completed, so between a phone and a laptop
there was no OTR session, no SMP, and no calls.

The fix was to move the implementation into `otrv4plus_fragment` and have both
callers use it. That makes the wire format a shared asset, and a shared asset
needs tests that pin it -- including the golden vectors below, which were
captured from the terminal client BEFORE the move and are what "byte-for-byte
unchanged" actually means here.

WHAT IS PINNED, AND WHY EACH ONE
--------------------------------
The threshold, the header layout, the 1-based numbering, the eight-hex-digit
id, the id being consumed only when a payload actually fragments, and every
bound on the receiving side. The last group matters because those bounds are
what stop a peer holding memory open, and a refactor that quietly dropped one
would look exactly like a refactor that did not.
"""

import pytest

import otrv4plus_fragment as frag


PEER = "bob@xmpp-elite.i2p"
OTHER = "carol@xmpp-elite.i2p"


def payload_of(size, fill="A"):
    """A payload of exactly *size* bytes that looks like an OTR frame."""
    head = "?OTRv4 "
    return head + fill * (size - len(head))


# ── Golden vectors, captured from the terminal client before the move ────────

#: name -> (payload size, stanzas, fragment lengths)
#:
#: Taken by running the pre-refactor `send_otr_fragmented` against a stub and
#: recording what it put on the wire. Reproduced here so a future change to
#: the shared module has to disagree with the terminal client's own history
#: rather than merely with a test someone wrote afterwards.
GOLDEN = {
    "tiny":           (12,    1, [12]),
    "exact_6000":     (6000,  1, [6000]),
    "just_over_6000": (6001,  2, [6021, 22]),
    "dake1_4455":     (4455,  1, [4455]),
    "dake3_4857":     (4857,  1, [4857]),
    "dake2_11716":    (11716, 2, [6021, 5737]),
    "three_frags":    (13000, 3, [6021, 6021, 1021]),
}


class TestTheGoldenVectors:
    """Byte-for-byte, against what the terminal client produced before."""

    @pytest.mark.parametrize("name", sorted(GOLDEN))
    def test_the_stanza_count_matches(self, name):
        size, stanzas, _lens = GOLDEN[name]
        parts, _seq = frag.fragment(payload_of(size), 0)
        assert len(parts) == stanzas

    @pytest.mark.parametrize("name", sorted(GOLDEN))
    def test_the_fragment_lengths_match(self, name):
        size, _stanzas, lens = GOLDEN[name]
        parts, _seq = frag.fragment(payload_of(size), 0)
        assert [len(p) for p in parts] == lens

    @pytest.mark.parametrize("name", sorted(GOLDEN))
    def test_it_round_trips(self, name):
        size, _stanzas, _lens = GOLDEN[name]
        original = payload_of(size)
        parts, _seq = frag.fragment(original, 0)
        assert _reassemble(parts) == original

    def test_the_first_fragment_is_exactly_this(self):
        """The header, spelled out, so a change to it cannot be silent."""
        parts, _seq = frag.fragment(payload_of(6001), 0)
        assert parts[0].startswith("?OTRv4F|00000001|1|2|")
        assert parts[1].startswith("?OTRv4F|00000001|2|2|")
        # 8 + 8 + 1 + 1 + 1 + 1 + 1 = 21 bytes of header.
        assert len(parts[0]) == 21 + frag.MAX_FRAGMENT
        assert len(parts[1]) == 21 + 1

    def test_the_threshold_is_6000(self):
        """Not a tuning knob: it is a property of the I2P transport, and
        raising it to make something fit is how you get a dropped stream."""
        assert frag.MAX_FRAGMENT == 6000


class TestTheBoundaryIsExact:
    """Off-by-one here means a payload at the cliff edge goes unfragmented."""

    def test_exactly_max_fragment_is_sent_whole(self):
        original = payload_of(frag.MAX_FRAGMENT)
        parts, _seq = frag.fragment(original, 0)
        assert parts == [original]
        assert not frag.is_fragment(parts[0])

    def test_one_byte_over_fragments(self):
        parts, _seq = frag.fragment(payload_of(frag.MAX_FRAGMENT + 1), 0)
        assert len(parts) == 2
        assert all(frag.is_fragment(p) for p in parts)

    def test_one_byte_under_is_sent_whole(self):
        parts, _seq = frag.fragment(payload_of(frag.MAX_FRAGMENT - 1), 0)
        assert len(parts) == 1

    def test_an_exact_multiple_does_not_produce_an_empty_tail(self):
        """A trailing empty fragment would be a valid-looking stanza carrying
        nothing, and the receiver would wait for it."""
        parts, _seq = frag.fragment(payload_of(frag.MAX_FRAGMENT * 3), 0)
        assert len(parts) == 3
        assert all(len(p) > 21 for p in parts)


class TestDakeSizedPayloads:
    """The sizes that made this a blocker rather than an optimisation.

    From SPEC.md: ML-KEM-1024 ciphertext 1568, ML-DSA-87 public key 2592,
    ML-DSA-87 signature 4627. DAKE1 is at most 4455 bytes and DAKE3 4857, both
    under the threshold; a DAKE2 carries all three pieces and is about 11.7 KB
    once base64-armoured, which is what forces fragmentation.
    """

    def test_dake1_sized_does_not_fragment(self):
        parts, _seq = frag.fragment(payload_of(4455), 0)
        assert len(parts) == 1

    def test_dake3_sized_does_not_fragment(self):
        parts, _seq = frag.fragment(payload_of(4857), 0)
        assert len(parts) == 1

    def test_dake2_sized_fragments(self):
        original = payload_of(11716)
        parts, _seq = frag.fragment(original, 0)
        assert len(parts) == 2, (
            "a DAKE2 must not go out as one stanza; that is the ~8 KB I2P "
            "cliff and it drops the stream")
        assert _reassemble(parts) == original

    def test_an_smp_sized_payload_fragments_and_survives(self):
        original = payload_of(8100, "B")
        parts, _seq = frag.fragment(original, 0)
        assert len(parts) == 2
        assert _reassemble(parts) == original

    @pytest.mark.parametrize("size", [6001, 8100, 12000, 18000, 24000, 60000])
    def test_larger_payloads_round_trip(self, size):
        original = payload_of(size, "C")
        parts, _seq = frag.fragment(original, 0)
        assert len(parts) > 1
        assert _reassemble(parts) == original


class TestTheMessageIdCounter:
    """Consumed only when a payload actually fragments.

    That is the pre-existing behaviour and it is load-bearing: an id burned on
    a message that was never fragmented shifts every later id, so the two
    implementations would produce different bytes for the same sequence of
    sends and the golden vectors above would be wrong for one of them.
    """

    def test_a_small_payload_does_not_consume_an_id(self):
        _parts, seq = frag.fragment(payload_of(100), 0)
        assert seq == 0

    def test_a_large_payload_consumes_one(self):
        _parts, seq = frag.fragment(payload_of(6001), 0)
        assert seq == 1

    def test_small_sends_do_not_shift_the_next_large_one(self):
        seq = 0
        for _ in range(10):
            _parts, seq = frag.fragment(payload_of(100), seq)
        parts, seq = frag.fragment(payload_of(6001), seq)
        assert seq == 1
        assert parts[0].startswith("?OTRv4F|00000001|")

    def test_ids_advance_across_fragmented_sends(self):
        seq = 0
        ids = []
        for _ in range(3):
            parts, seq = frag.fragment(payload_of(6001), seq)
            ids.append(parts[0].split("|")[1])
        assert ids == ["00000001", "00000002", "00000003"]

    def test_the_id_is_eight_hex_digits(self):
        parts, _seq = frag.fragment(payload_of(6001), 0)
        msg_id = parts[0].split("|")[1]
        assert len(msg_id) == 8
        int(msg_id, 16)

    def test_it_wraps_at_32_bits(self):
        _parts, seq = frag.fragment(payload_of(6001), 0xFFFFFFFF)
        assert seq == 0


class TestReassembly:

    def test_fragments_in_order(self):
        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler()
        for part in parts[:-1]:
            assert r.feed(PEER, part) is None
        assert r.feed(PEER, parts[-1]) == original

    def test_fragments_out_of_order(self):
        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler()
        out = [r.feed(PEER, p) for p in reversed(parts)]
        assert out[-1] == original
        assert all(x is None for x in out[:-1])

    def test_an_incomplete_set_yields_nothing(self):
        """Never a partial payload. Handing half a frame to the decoder is
        worse than handing it nothing."""
        parts, _seq = frag.fragment(payload_of(13000), 0)
        r = frag.Reassembler()
        for part in parts[:-1]:
            assert r.feed(PEER, part) is None
        assert r.pending() == 1

    def test_a_duplicate_fragment_does_not_complete_a_set(self):
        parts, _seq = frag.fragment(payload_of(13000), 0)
        r = frag.Reassembler()
        for _ in range(5):
            assert r.feed(PEER, parts[0]) is None

    def test_a_duplicate_does_not_inflate_the_byte_tally(self):
        """A peer resending the same fragment must not be able to push a set
        over the per-set cap and evict it."""
        parts, _seq = frag.fragment(payload_of(13000), 0)
        r = frag.Reassembler()
        r.feed(PEER, parts[0])
        key = next(iter(r.buffers))
        after_one = r.buffers[key]["bytes"]
        for _ in range(10):
            r.feed(PEER, parts[0])
        assert r.buffers[key]["bytes"] == after_one

    def test_a_resent_fragment_still_completes_the_set(self):
        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler()
        r.feed(PEER, parts[0])
        r.feed(PEER, parts[0])
        r.feed(PEER, parts[1])
        assert r.feed(PEER, parts[2]) == original

    def test_two_peers_do_not_contaminate_each_other(self):
        a = payload_of(13000, "A")
        b = payload_of(13000, "B")
        pa, _ = frag.fragment(a, 0)
        pb, _ = frag.fragment(b, 0)          # same msg_id, different peer
        r = frag.Reassembler()
        for x, y in zip(pa, pb):
            got_a = r.feed(PEER, x)
            got_b = r.feed(OTHER, y)
        assert got_a == a
        assert got_b == b

    def test_a_completed_set_is_released(self):
        parts, _seq = frag.fragment(payload_of(13000), 0)
        r = frag.Reassembler()
        for part in parts:
            r.feed(PEER, part)
        assert r.pending() == 0, "a finished set was left in the buffer"

    def test_chunks_containing_the_separator_survive(self):
        """`|` is legal inside a chunk. Parsing splits with maxsplit=4 for
        exactly this reason, and base64 armour is not the only thing that can
        end up in a body."""
        original = "?OTRv4 " + ("|" * 7000)
        parts, _seq = frag.fragment(original, 0)
        assert len(parts) > 1
        assert _reassemble(parts) == original


class TestMalformedInput:
    """Everything here must return None rather than raise. The far side is a
    peer, and a parser that throws on bad input is a denial of service."""

    @pytest.mark.parametrize("body", [
        "?OTRv4F|",
        "?OTRv4F|abc",
        "?OTRv4F|abc|1",
        "?OTRv4F|abc|1|2",
        "?OTRv4F|abc|x|2|data",
        "?OTRv4F|abc|1|y|data",
        "?OTRv4F|abc|-1|2|data",
        "?OTRv4F|abc|0|2|data",
        "?OTRv4F|abc|3|2|data",
        "?OTRv4F|abc|1|0|data",
        "?OTRv4F|abc|1|99999|data",
        "?OTRv4F||||",
    ])
    def test_it_is_dropped(self, body):
        r = frag.Reassembler()
        assert r.feed(PEER, body) is None

    def test_a_malformed_fragment_leaves_no_buffer(self):
        r = frag.Reassembler()
        r.feed(PEER, "?OTRv4F|abc|x|2|data")
        assert r.pending() == 0

    def test_the_fragment_ceiling_is_enforced(self):
        r = frag.Reassembler()
        assert r.feed(PEER, "?OTRv4F|abc|1|%d|x" % (frag.MAX_FRAGMENTS + 1)) is None
        assert r.feed(PEER, "?OTRv4F|abc|1|%d|x" % frag.MAX_FRAGMENTS) is None
        assert r.pending() == 1, "the largest legal total was rejected"


class TestCleanupAndBounds:
    """There is no time-based timeout -- partial sets are bounded by count and
    by bytes, and evicted oldest-first. Tested as it is, not as it might be."""

    def test_too_many_in_flight_sets_are_evicted(self):
        r = frag.Reassembler()
        for i in range(frag.MAX_INFLIGHT + 20):
            r.feed(PEER, "?OTRv4F|%08x|1|2|chunk" % i)
        assert r.pending() <= frag.MAX_INFLIGHT + 1, (
            "in-flight sets are unbounded, so a peer can hold memory open")

    def test_eviction_takes_the_oldest_first(self):
        r = frag.Reassembler()
        for i in range(frag.MAX_INFLIGHT + 5):
            r.feed(PEER, "?OTRv4F|%08x|1|2|chunk" % i)
        remaining = {key[1] for key in r.buffers}
        assert "00000000" not in remaining
        assert "%08x" % (frag.MAX_INFLIGHT + 4) in remaining

    def test_an_oversized_set_is_dropped(self):
        """One fragment claiming more than the per-set cap."""
        r = frag.Reassembler()
        huge = "x" * (frag.MAX_BUFFER_BYTES + 1)
        assert r.feed(PEER, "?OTRv4F|abcdef01|1|2|%s" % huge) is None
        assert r.pending() == 0, "the oversized set was kept"

    def test_clear_drops_everything(self):
        parts, _seq = frag.fragment(payload_of(13000), 0)
        r = frag.Reassembler()
        r.feed(PEER, parts[0])
        assert r.pending() == 1
        r.clear()
        assert r.pending() == 0

    def test_the_bounds_are_what_they_were(self):
        """Moved, not retuned."""
        assert frag.MAX_FRAGMENTS == 4096
        assert frag.MAX_INFLIGHT == 64
        assert frag.MAX_BUFFER_BYTES == 8 * 1024 * 1024
        assert frag.MAX_TOTAL_BYTES == 32 * 1024 * 1024


class TestKnownWeaknessCrossPeerEviction:
    """One peer can evict another peer's in-progress reassembly.

    NOT A PASSING GRADE. This test characterises behaviour that is wrong, so
    that it is visible and so that fixing it is a deliberate act rather than an
    accident. It was found while extracting this module and reported rather
    than redesigned: changing the eviction policy is a protocol-behaviour
    decision, not part of a refactor that had to preserve the wire format.

    The mechanism: `MAX_INFLIGHT` is a budget shared across all peers, and
    eviction takes the oldest set first. A peer who can send you stanzas opens
    65 partial sets and your correspondent's half-received DAKE2 is gone. Their
    handshake then fails, repeatably, and nothing on either side says why.

    Sixty-five small stanzas is not a flood, so the receive path's rate limiting
    does not close this.

    **If you fix this, this test will fail.** That is the intent. Replace it
    with one asserting the victim's frame survives.
    """

    def test_a_flooding_peer_evicts_another_peers_partial_set(self):
        victim, attacker = "alice@good.i2p", "mallory@bad.i2p"
        original = payload_of(13000, "V")
        parts, _seq = frag.fragment(original, 0)

        r = frag.Reassembler()
        r.feed(victim, parts[0])
        r.feed(victim, parts[1])
        assert r.pending() == 1

        for i in range(frag.MAX_INFLIGHT + 5):
            r.feed(attacker, "?OTRv4F|%08x|1|2|x" % i)

        assert not [k for k in r.buffers if k[0] == victim], (
            "the victim's set survived -- if this is now true, the weakness "
            "has been fixed and this test should be replaced")
        assert r.feed(victim, parts[2]) is None, (
            "the victim's frame reassembled, so the weakness is fixed")

    def test_the_budget_is_global_rather_than_per_peer(self):
        """The property the weakness reduces to, stated directly."""
        r = frag.Reassembler()
        for i in range(10):
            r.feed("peer%d@x.i2p" % i, "?OTRv4F|%08x|1|2|x" % i)
        assert r.pending() == 10, (
            "ten peers with one partial set each consume ten of one shared "
            "budget; a per-peer budget would be the obvious remedy")


class TestTheHooksCannotBreakReassembly:
    """A caller's logging is not allowed to cost a message."""

    def test_a_debug_hook_that_raises_is_contained(self):
        def explode(_message):
            raise RuntimeError("no")

        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler(on_debug=explode)
        out = [r.feed(PEER, p) for p in parts]
        assert out[-1] == original

    def test_a_progress_hook_that_raises_is_contained(self):
        def explode(*_a):
            raise RuntimeError("no")

        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler(on_progress=explode)
        out = [r.feed(PEER, p) for p in parts]
        assert out[-1] == original

    def test_progress_is_reported_per_incomplete_fragment(self):
        seen = []
        original = payload_of(13000)
        parts, _seq = frag.fragment(original, 0)
        r = frag.Reassembler(on_progress=lambda p, h, t: seen.append((h, t)))
        for part in parts:
            r.feed(PEER, part)
        assert seen == [(1, 3), (2, 3)], (
            "progress must fire for incomplete sets only")


def _reassemble(parts, peer=PEER):
    """Feed *parts* to a fresh reassembler and return what comes out."""
    if len(parts) == 1 and not frag.is_fragment(parts[0]):
        return parts[0]
    r = frag.Reassembler()
    out = None
    for part in parts:
        got = r.feed(peer, part)
        if got is not None:
            out = got
    return out
