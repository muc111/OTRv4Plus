#!/usr/bin/env python3
"""C3 -- nothing is committed or published until the message is authenticated.

The required ordering on the receive path:

    unauthenticated input
      -> parse and structurally validate
        -> AEAD (AES-256-GCM) authentication
          -> outer OTRv4 MAC verification
            -> commit ratchet state
              -> queue the MAC key for revelation

Getting this wrong is not a style problem. Publishing a MAC key on the strength
of a message that was never authenticated hands out a key an attacker chose the
moment to extract; committing ratchet state on one desynchronises the chain and
kills the session permanently.

These tests assert on what the implementation emits rather than on the shape of
the source, so they would fail if the order were quietly restored.

Note on the last two steps. The engine queues the reveal immediately after the
AEAD tag verifies, which is before the caller checks the outer MAC. That is
sound and deliberate: MKmac = KDF(0x14, MKenc, 64), so anyone able to produce a
valid GCM tag under MKenc can compute the outer MAC too. The outer MAC is a
second, spec-mandated check whose key is later published -- it is not what
stands between a forgery and the ratchet. AES-256-GCM is, and it runs first.
"""

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


def _published(ratchet, text=b"reply"):
    """Drain whatever the ratchet would publish on its next message."""
    *_x, revealed, _y = ratchet.encrypt_message(text)
    return [bytes(k) for k in revealed]


def _flip(data, index=0, bit=0x01):
    b = bytearray(data)
    b[index] ^= bit
    return bytes(b)


# ── 1. A forged message publishes nothing ────────────────────────────────────

class TestForgeryPublishesNothing:

    def test_a_forged_ciphertext_publishes_no_key(self):
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"real")

        with pytest.raises(Exception):
            bob.decrypt_message(h, _flip(ct), n, t)

        assert _published(bob) == [], \
            "a key was published for a message that never authenticated"

    def test_a_forged_tag_publishes_no_key(self):
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"real")

        with pytest.raises(Exception):
            bob.decrypt_message(h, ct, n, _flip(t))

        assert _published(bob) == []

    def test_a_wholly_invented_message_publishes_no_key(self):
        """No relationship to any real message at all."""
        _alice, bob = _ratchet_pair()
        header = otr.RatchetHeader(os.urandom(56), 0, 0).encode()

        with pytest.raises(Exception):
            bob.decrypt_message(header, os.urandom(48), os.urandom(12),
                                os.urandom(16))

        assert _published(bob) == []

    def test_repeated_forgeries_publish_nothing(self):
        """An attacker must not be able to pump keys out by volume."""
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"real")
        for i in range(32):
            with pytest.raises(Exception):
                bob.decrypt_message(h, _flip(ct, i % len(ct)), n, t)
        assert _published(bob) == []


# ── 2. A failed message commits no ratchet state ─────────────────────────────

class TestFailureCommitsNothing:

    def test_the_genuine_message_still_decrypts_after_a_forgery(self):
        """The observable consequence of a premature commit.

        If the chain advanced on the forgery, the real message would then
        derive from the wrong chain key and fail -- one injected packet would
        end the session.
        """
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"the real one")

        with pytest.raises(Exception):
            bob.decrypt_message(h, _flip(ct), n, t)

        plaintext, _mkmac = bob.decrypt_message(h, ct, n, t)
        assert plaintext == b"the real one", \
            "the forgery advanced the receiving chain"

    def test_the_session_survives_a_burst_of_forgeries(self):
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"survivor")

        for i in range(50):
            with pytest.raises(Exception):
                bob.decrypt_message(h, _flip(ct, i % len(ct)), n, t)

        assert bob.decrypt_message(h, ct, n, t)[0] == b"survivor"

    def test_a_forged_high_message_number_does_not_flood_skipped_keys(self):
        """A forged header names any msg_num it likes. If skipped keys were
        derived before authentication, one packet could evict every genuine
        stored key."""
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"still here")

        real_header = otr.RatchetHeader.decode(h)
        forged_header = otr.RatchetHeader(real_header.dh_pub, 0, 900).encode()
        with pytest.raises(Exception):
            bob.decrypt_message(forged_header, ct, n, t)

        assert bob.decrypt_message(h, ct, n, t)[0] == b"still here"


# ── 3. A replay publishes no new key ─────────────────────────────────────────

class TestReplayPublishesNothing:

    def test_a_replayed_message_is_refused(self):
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"once")
        assert bob.decrypt_message(h, ct, n, t)[0] == b"once"

        with pytest.raises(Exception):
            bob.decrypt_message(h, ct, n, t)

    def test_a_replay_publishes_no_second_copy(self):
        """The key for that message was published when it was first accepted.
        Publishing it again on a replay would let an attacker choose how often
        keys appear on the wire."""
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, mkmac = alice.encrypt_message(b"once")
        bob.decrypt_message(h, ct, n, t)

        first = _published(bob, b"reply 1")
        assert bytes(mkmac) in first

        with pytest.raises(Exception):
            bob.decrypt_message(h, ct, n, t)

        assert _published(bob, b"reply 2") == [], \
            "a replay caused a second publication"


# ── 4. A valid message publishes exactly the expected key ────────────────────

class TestValidMessagePublishesTheRightKey:

    def test_the_published_key_is_the_one_that_authenticated_it(self):
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, alice_mkmac = alice.encrypt_message(b"m1")
        _pt, bob_mkmac = bob.decrypt_message(h, ct, n, t)

        published = _published(bob)
        assert published == [bytes(alice_mkmac)], \
            f"expected exactly the authenticating key, got {len(published)} keys"
        assert bytes(bob_mkmac) == bytes(alice_mkmac)

    def test_nothing_is_published_before_the_message_arrives(self):
        """Bob has authenticated nothing yet."""
        _alice, bob = _ratchet_pair()
        assert _published(bob, b"first") == []

    def test_three_messages_publish_three_keys_in_order(self):
        alice, bob = _ratchet_pair()
        expected = []
        for i in range(3):
            ct, h, n, t, _e, _r, mkmac = alice.encrypt_message(b"m%d" % i)
            bob.decrypt_message(h, ct, n, t)
            expected.append(bytes(mkmac))

        assert _published(bob) == expected


# ── 5. A forgery after a valid message leaves earlier state intact ───────────

class TestEarlierStateSurvivesAForgery:

    def test_an_already_published_key_still_verifies_its_message(self):
        alice, bob = _ratchet_pair()
        ct1, h1, n1, t1, _e, _r, mkmac1 = alice.encrypt_message(b"first")
        bob.decrypt_message(h1, ct1, n1, t1)
        published = _published(bob)

        with pytest.raises(Exception):
            bob.decrypt_message(h1, _flip(ct1), n1, t1)

        msg = otr.OTRv4DataMessage()
        msg.sender_tag, msg.receiver_tag = 0x0101, 0x0202
        msg.flags, msg.prev_chain_len = 0, 0
        msg.ratchet_id, msg.message_id = 1, 0
        msg.ecdh_pub, msg.nonce = bytes(56), n1
        msg.ciphertext, msg.revealed_mac_keys = ct1, []
        msg.mac = msg.compute_mac(published[0])

        assert msg.verify_mac(bytes(mkmac1)), \
            "the earlier message's key stopped verifying after a forgery"

    def test_the_conversation_continues_in_both_directions(self):
        alice, bob = _ratchet_pair()
        ct1, h1, n1, t1, _e, _r, _mk = alice.encrypt_message(b"first")
        bob.decrypt_message(h1, ct1, n1, t1)

        ctb, hb, nb, tb, _e, _rb, _mkb = bob.encrypt_message(b"reply")
        assert alice.decrypt_message(hb, ctb, nb, tb)[0] == b"reply"

        with pytest.raises(Exception):
            alice.decrypt_message(hb, _flip(ctb), nb, tb)

        ct2, h2, n2, t2, _e, _r2, _mk2 = alice.encrypt_message(b"second")
        assert bob.decrypt_message(h2, ct2, n2, t2)[0] == b"second"

    def test_a_forgery_does_not_disturb_the_pending_queue(self):
        """Keys queued from earlier authenticated messages must still be
        published, and no extra key must appear."""
        alice, bob = _ratchet_pair()
        ct1, h1, n1, t1, _e, _r, mkmac1 = alice.encrypt_message(b"first")
        bob.decrypt_message(h1, ct1, n1, t1)

        with pytest.raises(Exception):
            bob.decrypt_message(h1, _flip(ct1), n1, t1)

        assert _published(bob) == [bytes(mkmac1)]
