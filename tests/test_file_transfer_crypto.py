#!/usr/bin/env python3
"""INV-21: the /sendfile FileKey is Rust-owned, and the format is authenticated.

These run against REAL ratchets from a REAL DAKE, not stubs, because the
property under test is that a transfer keys from the session and only from
that session.  A fake ratchet would prove nothing about that.

The transfer is XMPP-only.  Nothing here imports the IRC client's transport,
and `test_file_transfer_boundary.py` is what fails if the feature ever grows
an IRC path.
"""

import hashlib
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")


# --------------------------------------------------------------------------
# a real session
# --------------------------------------------------------------------------

def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


def _relay(first, sender, receiver, sender_id, receiver_id, limit=10):
    current, delivered = first, 0
    for _ in range(limit):
        if not current:
            break
        out = receiver.handle_incoming_message(sender_id, current)
        delivered += 1
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        if not text or not text.startswith("?OTRv4"):
            break
        current = text
        sender, receiver = receiver, sender
        sender_id, receiver_id = receiver_id, sender_id
    return delivered


def _clear_dake_rate_limit():
    """Reset the engine's DAKE1 limiter between handshakes.

    FOUND WHILE WRITING THESE TESTS, and worth recording: DAKE1RateLimiter
    documents itself as "per-peer", but both real call sites invoke
    `process_dake1(dake1_msg)` without the `peer_key` argument, so every peer
    shares the default bucket "unknown".  It is therefore a GLOBAL limiter of
    5 attempts per 60 seconds, and one peer exhausting it locks out DAKE1
    from every other peer.

    That is an engine-wide property affecting IRC and XMPP alike, so it is
    deliberately NOT changed here -- file transfer has no business altering
    session establishment.  These tests reset the bucket so they exercise the
    transfer rather than the limiter.
    """
    try:
        otr._dake1_rate_limiter._attempts.clear()
    except Exception:
        pass


@pytest.fixture(scope="module")
def ratchets():
    """Two live RustDoubleRatchets from one completed DAKE.

    Both carry the extra symmetric key the transfer derives from, which is
    the whole point: it is the one session secret that does not advance.
    """
    _clear_dake_rate_limit()
    alice_mgr, bob_mgr = _manager(), _manager()
    alice, bob = "alice@example.test", "bob@example.test"
    dake1, _ = alice_mgr.handle_outgoing_message(bob, "")
    assert dake1, "no DAKE1 produced"
    _relay(dake1, alice_mgr, bob_mgr, alice, bob)
    assert alice_mgr.has_encrypted_session(bob)
    assert bob_mgr.has_encrypted_session(alice)

    a = alice_mgr.get_session(bob).ratchet._rust
    b = bob_mgr.get_session(alice).ratchet._rust
    assert a.supports_file_transfer and b.supports_file_transfer, (
        "a DAKE-established session has no extra symmetric key, so nothing "
        "can key a file transfer")
    return a, b, alice_mgr, bob_mgr, alice, bob


def _roundtrip(tx, rx, blob, chunk=None):
    """Seal `blob` with `tx`, open it with `rx`.  Returns the plaintext."""
    chunk = chunk or core.file_transfer_chunk_len()
    pieces, out = [], b""
    remaining = len(blob)
    offset = 0
    while True:
        block = blob[offset:offset + chunk]
        offset += len(block)
        remaining -= len(block)
        pieces.append(tx.seal_chunk(block, remaining <= 0))
        if remaining <= 0:
            break
    for i, sealed in enumerate(pieces):
        out += rx.open_chunk(sealed, i + 1 == len(pieces))
    return out, pieces


# --------------------------------------------------------------------------
# the key
# --------------------------------------------------------------------------

class TestTheFileKey:

    def test_a_transfer_can_be_keyed_from_a_real_session(self, ratchets):
        a, b, *_ = ratchets
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        rx = b.file_receiver(tid, tx.envelope)
        assert bytes(tx.transfer_id) == bytes(rx.transfer_id)

    def test_the_key_never_crosses_the_boundary(self, ratchets):
        """The property this module exists for.  A getter is the only way a
        FileKey could reach Python, so there must not be one."""
        a, _b, *_ = ratchets
        tx = a.file_sender(core.file_transfer_new_id())
        for banned in ("file_key", "filekey", "key", "secret", "raw",
                       "expose", "wrap_key", "reveal"):
            assert not hasattr(tx, banned), (
                "RustFileSender grew a %r accessor" % banned)

    def test_the_ratchet_still_exposes_no_secret(self, ratchets):
        a, *_ = ratchets
        for banned in ("root_key", "chain_key", "extra_sym_key", "brace_key",
                       "wrap_key"):
            assert not hasattr(a, banned), (
                "the ratchet grew a %r accessor while file transfer was "
                "being added" % banned)

    def test_every_transfer_gets_a_different_key(self, ratchets):
        """Identical plaintext under two transfers must not produce identical
        ciphertext -- that is the observable consequence of a reused key, and
        it can be asserted without reading either key."""
        a, _b, *_ = ratchets
        first = a.file_sender(core.file_transfer_new_id())
        second = a.file_sender(core.file_transfer_new_id())
        assert first.seal_chunk(b"same bytes", True) != \
               second.seal_chunk(b"same bytes", True)

    def test_the_envelope_is_not_the_key(self, ratchets):
        a, _b, *_ = ratchets
        tx = a.file_sender(core.file_transfer_new_id())
        env = bytes(tx.envelope)
        assert len(env) == 60, "nonce(12) + wrapped key(32) + tag(16)"
        sealed = tx.seal_chunk(b"x" * 64, True)
        assert env not in sealed

    def test_zeroize_stops_the_sender(self, ratchets):
        a, _b, *_ = ratchets
        tx = a.file_sender(core.file_transfer_new_id())
        tx.zeroize()
        assert tx.zeroized
        with pytest.raises(Exception):
            tx.seal_chunk(b"after", True)


# --------------------------------------------------------------------------
# session binding
# --------------------------------------------------------------------------

class TestSessionBinding:

    def test_the_peer_can_open_it(self, ratchets):
        a, b, *_ = ratchets
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        rx = b.file_receiver(tid, tx.envelope)
        out, _ = _roundtrip(tx, rx, b"the quick brown fox")
        assert out == b"the quick brown fox"

    def test_a_different_session_cannot(self, ratchets):
        """A third party with a valid OTR session of their own must not be
        able to open an offer addressed to someone else."""
        a, _b, *_ = ratchets
        other_a, other_b, *_ = _fresh_ratchets()
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        with pytest.raises(Exception):
            other_b.file_receiver(tid, tx.envelope)

    def test_a_different_transfer_id_cannot(self, ratchets):
        a, b, *_ = ratchets
        tx = a.file_sender(core.file_transfer_new_id())
        with pytest.raises(Exception):
            b.file_receiver(core.file_transfer_new_id(), tx.envelope)

    def test_a_replayed_offer_into_a_new_session_fails(self, ratchets):
        """The envelope is bound to the session that sealed it, so capturing
        an offer and replaying it later into a fresh session does not work."""
        a, _b, *_ = ratchets
        tid = core.file_transfer_new_id()
        envelope = a.file_sender(tid).envelope
        _, later_b, *_ = _fresh_ratchets()
        with pytest.raises(Exception):
            later_b.file_receiver(tid, envelope)

    def test_advancing_the_ratchet_does_not_break_a_live_transfer(self, ratchets):
        """The transfer-lifetime rule.  Messages sent while a file is in
        flight advance the ratchet; the transfer must not care."""
        a, b, alice_mgr, bob_mgr, alice, bob = ratchets
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        rx = b.file_receiver(tid, tx.envelope)
        first = tx.seal_chunk(b"chunk zero", False)

        # Real traffic between the same peers, mid-transfer.
        for _ in range(3):
            frame, should_send = alice_mgr.handle_outgoing_message(bob, "hello")
            assert should_send and frame
            bob_mgr.handle_incoming_message(alice, frame)
        assert a.ratchet_id() >= 0            # it really is the same object

        second = tx.seal_chunk(b" and one", True)
        assert rx.open_chunk(first, False) == b"chunk zero"
        assert rx.open_chunk(second, True) == b" and one"

    def test_a_session_without_a_dake_refuses(self):
        """A ratchet built by the legacy or test constructor has no extra
        symmetric key.  It must fail closed rather than key from something
        else."""
        r = core.RustDoubleRatchet(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32,
                                   b"\x04" * 32, b"\x05" * 56, True)
        assert r.supports_file_transfer is False
        with pytest.raises(Exception):
            r.file_sender(core.file_transfer_new_id())


def _fresh_ratchets():
    _clear_dake_rate_limit()
    alice_mgr, bob_mgr = _manager(), _manager()
    alice, bob = "carol@example.test", "dave@example.test"
    dake1, _ = alice_mgr.handle_outgoing_message(bob, "")
    _relay(dake1, alice_mgr, bob_mgr, alice, bob)
    return (alice_mgr.get_session(bob).ratchet._rust,
            bob_mgr.get_session(alice).ratchet._rust,
            alice_mgr, bob_mgr, alice, bob)


# --------------------------------------------------------------------------
# the file format
# --------------------------------------------------------------------------

class TestTheFormat:

    @pytest.fixture
    def pair(self, ratchets):
        a, b, *_ = ratchets
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        return tx, b.file_receiver(tid, tx.envelope)

    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024])
    def test_small_files_round_trip(self, pair, size):
        tx, rx = pair
        blob = os.urandom(size)
        out, _ = _roundtrip(tx, rx, blob)
        assert out == blob

    def test_a_one_megabyte_file_round_trips(self, pair):
        tx, rx = pair
        blob = os.urandom(1024 * 1024)
        out, pieces = _roundtrip(tx, rx, blob)
        assert out == blob
        assert len(pieces) == 16, "64 KiB chunks over 1 MiB"

    def test_a_multi_chunk_file_uses_multiple_chunks(self, pair):
        tx, rx = pair
        blob = os.urandom(core.file_transfer_chunk_len() * 3 + 7)
        out, pieces = _roundtrip(tx, rx, blob)
        assert out == blob and len(pieces) == 4

    def test_the_hashes_agree_across_the_pair(self, pair):
        tx, rx = pair
        blob = os.urandom(70_000)
        _roundtrip(tx, rx, blob)
        assert bytes(tx.plaintext_sha256()) == bytes(rx.plaintext_sha256())
        assert bytes(tx.ciphertext_sha256()) == bytes(rx.ciphertext_sha256())
        assert bytes(tx.plaintext_sha256()) == hashlib.sha256(blob).digest()

    def test_the_declared_sizes_match_reality(self, pair):
        tx, rx = pair
        blob = os.urandom(100_000)
        _roundtrip(tx, rx, blob)
        sealed_size, chunks = core.file_transfer_sizes(len(blob))
        assert tx.plaintext_len == len(blob)
        assert tx.ciphertext_len == sealed_size
        assert tx.next_index == chunks

    def test_an_empty_file_is_still_one_authenticated_chunk(self, pair):
        tx, rx = pair
        sealed = tx.seal_chunk(b"", True)
        assert len(sealed) == 16, "the tag, and nothing else"
        assert rx.open_chunk(sealed, True) == b""
        assert rx.finished

    def test_an_oversized_chunk_is_refused(self, pair):
        tx, _rx = pair
        with pytest.raises(Exception):
            tx.seal_chunk(b"x" * (core.file_transfer_chunk_len() + 1), True)


# --------------------------------------------------------------------------
# things that must fail
# --------------------------------------------------------------------------

class TestCorruptionIsCaught:

    @pytest.fixture
    def pair(self, ratchets):
        a, b, *_ = ratchets
        tid = core.file_transfer_new_id()
        tx = a.file_sender(tid)
        return tx, b.file_receiver(tid, tx.envelope)

    def test_a_flipped_ciphertext_bit(self, pair):
        tx, rx = pair
        sealed = bytearray(tx.seal_chunk(b"payload here", True))
        sealed[0] ^= 0x01
        with pytest.raises(Exception):
            rx.open_chunk(bytes(sealed), True)

    def test_a_flipped_tag_bit(self, pair):
        tx, rx = pair
        sealed = bytearray(tx.seal_chunk(b"payload here", True))
        sealed[-1] ^= 0x01
        with pytest.raises(Exception):
            rx.open_chunk(bytes(sealed), True)

    def test_a_truncated_chunk(self, pair):
        tx, rx = pair
        sealed = tx.seal_chunk(b"payload here", True)
        with pytest.raises(Exception):
            rx.open_chunk(sealed[:-1], True)

    def test_a_chunk_shorter_than_its_tag(self, pair):
        _tx, rx = pair
        with pytest.raises(Exception):
            rx.open_chunk(b"short", True)

    def test_a_chunk_from_the_wrong_transfer(self, ratchets):
        a, b, *_ = ratchets
        tid_one = core.file_transfer_new_id()
        tx_one = a.file_sender(tid_one)
        rx_one = b.file_receiver(tid_one, tx_one.envelope)
        tid_two = core.file_transfer_new_id()
        tx_two = a.file_sender(tid_two)
        with pytest.raises(Exception):
            rx_one.open_chunk(tx_two.seal_chunk(b"other transfer", True), True)

    def test_a_chunk_replayed_at_the_wrong_index(self, pair):
        """Chunk 0 must not be acceptable as chunk 1: the index is in the
        AAD, so reordering or duplicating a chunk fails the tag."""
        tx, rx = pair
        first = tx.seal_chunk(b"aaaa", False)
        tx.seal_chunk(b"bbbb", True)
        assert rx.open_chunk(first, False) == b"aaaa"
        with pytest.raises(Exception):
            rx.open_chunk(first, True)

    def test_a_middle_chunk_cannot_be_presented_as_final(self, pair):
        """The truncation attack: deliver the first chunk and claim the file
        is complete.  The final flag is authenticated, so it fails."""
        tx, rx = pair
        first = tx.seal_chunk(b"first half", False)
        tx.seal_chunk(b"second half", True)
        with pytest.raises(Exception):
            rx.open_chunk(first, True)

    def test_a_forged_chunk_advances_nothing(self, pair):
        """Nothing commits before the tag verifies, so a rejected chunk
        leaves the receiver exactly where it was."""
        tx, rx = pair
        good = tx.seal_chunk(b"real data", True)
        before = (rx.next_index, rx.plaintext_len,
                  bytes(rx.plaintext_sha256()))
        with pytest.raises(Exception):
            rx.open_chunk(b"\x00" * 32, True)
        assert (rx.next_index, rx.plaintext_len,
                bytes(rx.plaintext_sha256())) == before
        assert rx.open_chunk(good, True) == b"real data"

    def test_a_zeroized_receiver_refuses(self, pair):
        tx, rx = pair
        sealed = tx.seal_chunk(b"data", True)
        rx.zeroize()
        with pytest.raises(Exception):
            rx.open_chunk(sealed, True)
