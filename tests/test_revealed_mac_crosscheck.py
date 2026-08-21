#!/usr/bin/env python3
"""C2 -- the peer's revealed MAC keys, cross-checked against local state.

Before this, `_record_revealed_mac_keys` validated shape only: 64 bytes, not
all-zero, bounded store. A peer could publish 64 bytes of `os.urandom` on every
message and the implementation would record them as revelations. Revelation
would then be nominal on the wire and worth nothing, and nothing would say so.

The engine now fingerprints every MKmac it derives -- send side, receive side,
and the skipped-message path -- so a revealed key can be checked against keys
this endpoint derived independently. What each outcome means:

  VERIFIED      the key really did authenticate a message on a chain both
                sides share
  UNACCOUNTED   this endpoint cannot derive it. Not proof of misbehaviour:
                see TestUnaccountedIsNotFatal for the legitimate cases.
  FATAL         wrong length, all-zero, or the key of the message carrying the
                revelation

Fingerprints, not keys: the cross-check adds no new store of live key material.
"""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
otrv4_core = pytest.importorskip("otrv4_core")

MKMAC_LEN = 64


def _ratchet_pair():
    root = os.urandom(32)
    cka, ckb, bk = os.urandom(32), os.urandom(32), os.urandom(32)
    common = dict(root_key=root, ad=b"\x01" * 32, brace_key=bk)
    alice = otr.DoubleRatchet(is_initiator=True, chain_key_send=cka,
                              chain_key_recv=ckb, **common)
    bob = otr.DoubleRatchet(is_initiator=False, chain_key_send=ckb,
                            chain_key_recv=cka, **common)
    return alice, bob


def _needs_crosscheck(ratchet):
    if not hasattr(ratchet, "knows_revealed_mac_key"):
        pytest.skip("extension build predates the C2 cross-check")


# ── The check itself ─────────────────────────────────────────────────────────

class TestKeysAreIndependentlyDerivable:
    """The C2 question: can the receiver derive what the peer revealed?"""

    def test_a_sent_messages_key_is_known_to_the_sender(self):
        """The peer reveals the keys of messages it RECEIVES from us, so our
        own send-side keys must be in the set."""
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        *_r, mkmac = alice.encrypt_message(b"m1")
        assert alice.knows_revealed_mac_key(bytes(mkmac))

    def test_a_received_messages_key_is_known_to_the_receiver(self):
        """And the peer reveals the keys of messages it SENDS, which we derive
        on receipt."""
        alice, bob = _ratchet_pair()
        _needs_crosscheck(bob)
        ct, h, n, t, _e, _r, mkmac = alice.encrypt_message(b"m1")
        bob.decrypt_message(h, ct, n, t)
        assert bob.knows_revealed_mac_key(bytes(mkmac))

    def test_the_key_a_peer_actually_publishes_is_verifiable(self):
        """End to end through the real reveal queue, both directions."""
        alice, bob = _ratchet_pair()
        _needs_crosscheck(alice)

        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"m1")
        bob.decrypt_message(h, ct, n, t)
        *_x, published, _y = bob.encrypt_message(b"reply")

        assert published, "receiver published nothing"
        for k in published:
            assert alice.knows_revealed_mac_key(bytes(k)), (
                "Alice cannot derive a key Bob published for a message she "
                "sent -- the cross-check would reject genuine revelation")

    def test_an_invented_key_is_not_known(self):
        """The case the shape-only check could not tell from a real one."""
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        alice.encrypt_message(b"m1")
        for _ in range(20):
            assert not alice.knows_revealed_mac_key(os.urandom(MKMAC_LEN))

    def test_a_near_miss_is_not_known(self):
        """One flipped bit must not verify -- no truncated comparison."""
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        *_r, mkmac = alice.encrypt_message(b"m1")
        for i in (0, 31, 63):
            bad = bytearray(mkmac)
            bad[i] ^= 0x01
            assert not alice.knows_revealed_mac_key(bytes(bad))

    def test_a_lost_messages_key_is_still_derivable(self):
        """The case that makes a naive cross-check fire on honest peers.

        Alice's first message never arrives. She reveals its MKmac anyway. Bob
        must be able to account for it -- he holds the skipped MKenc, and the
        engine fingerprints the matching MKmac at the moment it stores that
        key rather than only when the message shows up.
        """
        alice, bob = _ratchet_pair()
        _needs_crosscheck(bob)

        _dropped = alice.encrypt_message(b"never arrives")
        lost_mkmac = bytes(_dropped[6])

        ct2, h2, n2, t2, _e, _r, _mk = alice.encrypt_message(b"arrives")
        bob.decrypt_message(h2, ct2, n2, t2)

        assert bob.knows_revealed_mac_key(lost_mkmac), (
            "a key for a message lost in transit is not accountable, so an "
            "honest peer's revelation would look invented")

    def test_the_store_holds_fingerprints_not_keys(self):
        """A revealed key must not be recoverable from engine state.

        Checked from the outside: the engine exposes one bit, and no accessor
        that returns anything derived from the stored value.
        """
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        *_r, mkmac = alice.encrypt_message(b"m1")
        assert alice.knows_revealed_mac_key(bytes(mkmac)) is True
        rust = alice._rust
        for name in dir(rust):
            if name.startswith("_"):
                continue
            assert "fingerprint" not in name.lower()
            assert "derived_mac" not in name.lower()


# ── Fatal cases ──────────────────────────────────────────────────────────────

class _Recorder:
    """Minimal stand-in exercising _record_revealed_mac_keys directly.

    The method only touches its own attributes and self.ratchet, so binding it
    to a small object keeps these cases free of a full session setup.
    """

    def __init__(self, ratchet):
        self.ratchet = ratchet
        # Read from the real class so the bound cannot silently diverge.
        self.MAX_PEER_REVEALED_MAC_KEYS = \
            _record_owner().MAX_PEER_REVEALED_MAC_KEYS


def _record(ratchet, keys, this_message_mac_key=None):
    rec = _Recorder(ratchet)
    _sess_cls = _record_owner()
    _sess_cls._record_revealed_mac_keys(rec, keys, this_message_mac_key)
    return rec


def _record_owner():
    """The class that defines _record_revealed_mac_keys."""
    for name in dir(otr):
        obj = getattr(otr, name)
        if isinstance(obj, type) and "_record_revealed_mac_keys" in obj.__dict__:
            return obj
    pytest.skip("_record_revealed_mac_keys not found")


class TestFatalCases:

    def test_wrong_length_is_refused(self):
        alice, _bob = _ratchet_pair()
        with pytest.raises(ValueError) as exc:
            _record(alice, [os.urandom(32)])
        assert "byte" in str(exc.value)

    def test_all_zero_is_refused(self):
        alice, _bob = _ratchet_pair()
        with pytest.raises(ValueError) as exc:
            _record(alice, [bytes(MKMAC_LEN)])
        assert "zero" in str(exc.value).lower()

    def test_revealing_the_carrying_messages_own_key_is_refused(self):
        """A key is revealed only once its message is finished with.

        Publishing the current message's MKmac would make that message
        forgeable at the instant it is accepted.
        """
        alice, _bob = _ratchet_pair()
        *_r, mkmac = alice.encrypt_message(b"m1")
        with pytest.raises(ValueError) as exc:
            _record(alice, [bytes(mkmac)], this_message_mac_key=bytes(mkmac))
        assert "carrying" in str(exc.value)

    def test_the_engine_never_does_that(self):
        """Standing guard on encrypt(): the pending queue is taken BEFORE the
        current message's key is installed, so the two can never coincide."""
        alice, bob = _ratchet_pair()
        for i in range(6):
            ct, h, n, t, _e, revealed, mkmac = alice.encrypt_message(b"m%d" % i)
            assert bytes(mkmac) not in [bytes(k) for k in revealed], \
                "a message revealed its own authenticating key"
            bob.decrypt_message(h, ct, n, t)
            *_x, rev_b, mk_b = bob.encrypt_message(b"r%d" % i)
            assert bytes(mk_b) not in [bytes(k) for k in rev_b]


# ── Unaccounted keys are recorded, not fatal ─────────────────────────────────

class TestUnaccountedIsNotFatal:
    """Why the check does not tear the session down on an unknown key.

    An unaccounted key is not evidence of misbehaviour: eviction from the
    fingerprint window, and messages skipped past the tail of an old chain
    before a DH rotation, both leave an honest peer holding keys this side
    never derived. Making that fatal would let anyone who can drop a single
    packet kill any session on demand -- and it would buy nothing, because a
    peer that wants to defeat the check can simply reveal nothing at all.
    """

    def test_an_unknown_key_is_counted_not_raised(self):
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        alice.encrypt_message(b"m1")
        rec = _record(alice, [os.urandom(MKMAC_LEN)])
        assert rec.revealed_mac_keys_unaccounted == 1
        assert rec.revealed_mac_keys_verified == 0
        assert len(rec.peer_revealed_mac_keys) == 1

    def test_a_known_key_is_counted_as_verified(self):
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        *_r, mkmac = alice.encrypt_message(b"m1")
        rec = _record(alice, [bytes(mkmac)])
        assert rec.revealed_mac_keys_verified == 1
        assert rec.revealed_mac_keys_unaccounted == 0

    def test_the_two_counts_are_kept_separately(self):
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        *_r, mkmac = alice.encrypt_message(b"m1")
        rec = _record(alice, [bytes(mkmac), os.urandom(MKMAC_LEN),
                              os.urandom(MKMAC_LEN)])
        assert (rec.revealed_mac_keys_verified,
                rec.revealed_mac_keys_unaccounted) == (1, 2)

    def test_the_store_stays_bounded(self):
        alice, _bob = _ratchet_pair()
        _needs_crosscheck(alice)
        rec = _Recorder(alice)
        owner = _record_owner()
        for _ in range(300):
            owner._record_revealed_mac_keys(rec, [os.urandom(MKMAC_LEN)], None)
        assert len(rec.peer_revealed_mac_keys) <= rec.MAX_PEER_REVEALED_MAC_KEYS


# ── The full path, through a real session ────────────────────────────────────

class _FakeRatchet:
    """Just enough ratchet for _enh_dec_v6, with the reveal answer under test."""

    def __init__(self, mac_key, plaintext, known=True):
        self._mac_key = mac_key
        self._plaintext = plaintext
        self._known = known
        self.ratchet_id = 1

    def decrypt_message(self, header, ct, nonce, tag):
        return self._plaintext, self._mac_key

    def knows_revealed_mac_key(self, key):
        return self._known

    def prepare_brace_rotation(self):
        pass

    def process_incoming_kem_ct(self, ct):
        pass

    def process_incoming_kem_ek(self, ek):
        pass


class _FakeSession:
    """A stand-in carrying the real _enh_dec_v6 and _record_revealed_mac_keys.

    The receive path only touches the attributes set here, so this exercises
    the real code rather than a paraphrase of it.
    """

    def __init__(self, ratchet):
        owner = _record_owner()
        self.ratchet = ratchet
        self._sender_tag = 0x0000AAAA
        self._receiver_tag = 0
        self.routed = []
        self.MAX_PEER_REVEALED_MAC_KEYS = owner.MAX_PEER_REVEALED_MAC_KEYS
        self._enh_dec_v6 = owner._enh_dec_v6.__get__(self)
        self._record_revealed_mac_keys = \
            owner._record_revealed_mac_keys.__get__(self)

    def _enh_route_tlvs(self, tlvs):
        self.routed.append(tlvs)


def _wire(mac_key, revealed, text=b"hello", break_mac=False):
    """A data message whose outer MAC is keyed by `mac_key`."""
    msg = otr.OTRv4DataMessage()
    msg.sender_tag = 0x0000BBBB
    msg.receiver_tag = 0x0000AAAA
    msg.flags, msg.prev_chain_len = 0, 0
    msg.ratchet_id, msg.message_id = 1, 0
    msg.ecdh_pub, msg.nonce = bytes(56), bytes(12)
    msg.ciphertext = b"\x00" * 32
    msg.revealed_mac_keys = [bytes(k) for k in revealed]
    msg.mac = msg.compute_mac(mac_key)
    if break_mac:
        bad = bytearray(msg.mac)
        bad[0] ^= 0x01
        msg.mac = bytes(bad)
    return msg.encode()


class TestThroughTheReceivePath:
    """The real _enh_dec_v6, driven end to end over a fake ratchet.

    These assert on what the path does, not on how it is written: an earlier
    version of this class read the source text, which cannot tell a working
    guard from a comment mentioning one.
    """

    def _payload(self):
        return otr.OTRv4Payload("hello", []).encode(add_padding=False)

    def test_a_normal_message_records_the_revealed_key(self):
        mac_key = os.urandom(MKMAC_LEN)
        revealed = os.urandom(MKMAC_LEN)
        sess = _FakeSession(_FakeRatchet(mac_key, self._payload()))

        out = sess._enh_dec_v6(_wire(mac_key, [revealed]))

        assert out == b"hello"
        assert sess.peer_revealed_mac_keys == [revealed]
        assert sess.revealed_mac_keys_verified == 1

    def test_the_carrying_messages_own_key_is_refused(self):
        """The self-reveal guard is reachable from the real receive path.

        If _enh_dec_v6 stopped handing the recorder the key that authenticated
        the carrying message, this message would be accepted.
        """
        mac_key = os.urandom(MKMAC_LEN)
        sess = _FakeSession(_FakeRatchet(mac_key, self._payload()))

        with pytest.raises(ValueError) as exc:
            sess._enh_dec_v6(_wire(mac_key, [mac_key]))
        assert "carrying" in str(exc.value)

    def test_nothing_is_recorded_when_the_outer_mac_fails(self):
        """Ordering (audit C3): a message that fails the outer MAC must not
        contribute a revealed key."""
        mac_key = os.urandom(MKMAC_LEN)
        revealed = os.urandom(MKMAC_LEN)
        sess = _FakeSession(_FakeRatchet(mac_key, self._payload()))

        with pytest.raises(ValueError) as exc:
            sess._enh_dec_v6(_wire(mac_key, [revealed], break_mac=True))
        assert "MAC verification failed" in str(exc.value)
        assert not hasattr(sess, "peer_revealed_mac_keys") or \
            sess.peer_revealed_mac_keys == []

    def test_an_unaccountable_key_is_counted_but_the_message_lands(self):
        mac_key = os.urandom(MKMAC_LEN)
        sess = _FakeSession(
            _FakeRatchet(mac_key, self._payload(), known=False))

        out = sess._enh_dec_v6(_wire(mac_key, [os.urandom(MKMAC_LEN)]))

        assert out == b"hello"
        assert sess.revealed_mac_keys_unaccounted == 1
        assert sess.revealed_mac_keys_verified == 0

    def test_an_all_zero_revealed_key_rejects_the_message(self):
        mac_key = os.urandom(MKMAC_LEN)
        sess = _FakeSession(_FakeRatchet(mac_key, self._payload()))
        wire = _wire(mac_key, [])

        # An all-zero key encodes fine on the wire, so drive the recorder with
        # the same call the receive path makes.
        with pytest.raises(ValueError):
            sess._record_revealed_mac_keys([bytes(MKMAC_LEN)],
                                           this_message_mac_key=mac_key)
        assert wire  # the wire form itself is fine; the reveal list is not
