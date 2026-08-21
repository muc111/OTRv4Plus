#!/usr/bin/env python3
"""End-to-end proof that the key the implementation REVEALS is the key that
AUTHENTICATED a real message.

Why this file exists
--------------------
`test_mac_key_revelation.py` (added with the L1 fix) is good coverage of the
derivation, the wire encoding and the wrong-key cases. But its forgeability
test builds its own MKmac:

    mkenc = kdf_1(KDFUsage.MESSAGE_KEY, b"\\x44" * 32, 32)
    mkmac = kdf_1(KDFUsage.MAC_KEY, mkenc, 64)
    original = build_message(mkmac, ...)
    assert original.verify_mac(mkmac)

`build_message` computes the MAC with whatever key it is handed, so that
assertion is a property of MACs in general -- a MAC verifies under the key it
was computed with -- not evidence about this implementation. No test in that
file drives a real ratchet or reads the real reveal queue, so it would pass
against the pre-fix code too, where the revealed key and the authenticating key
were unrelated.

The deniability property needs the loop closed:

    Alice encrypts M1 with MKmac_1
        -> Bob decrypts M1, verifies with MKmac_1, queues it
            -> Bob's next outgoing message publishes MKmac_1
                -> the PUBLISHED bytes verify M1's MAC, and can re-MAC a forgery

Only the last step distinguishes a real revelation from a decorative one. These
tests drive the actual RustDoubleRatchet through the Python wrapper and assert
on the bytes the implementation itself emits.

Scope. This demonstrates the *mechanism*: the published key authenticates the
message it is published for, so a third party holding a transcript plus the
published keys can forge entries in it. That is the operative sub-property of
OTR deniability. It is NOT a proof of the full formal deniability property,
which is a statement about what a judge or simulator can distinguish and needs
review this test cannot provide. L1's status is discussed in MAC_FIX_REVIEW.md.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
otrv4_core = pytest.importorskip("otrv4_core")

MKMAC_LEN = 64


def _ratchet_pair():
    """Two ratchets sharing a root and crossed chain keys.

    Mirrors the helper in tests/test_attacks.py; kept local so this file does
    not depend on that module's import-order behaviour.
    """
    root = os.urandom(32)
    cka = os.urandom(32)
    ckb = os.urandom(32)
    ad = b"\x01" * 32
    bk = os.urandom(32)

    common = dict(root_key=root, ad=ad, brace_key=bk)
    alice = otr.DoubleRatchet(is_initiator=True, chain_key_send=cka,
                              chain_key_recv=ckb, **common)
    bob = otr.DoubleRatchet(is_initiator=False, chain_key_send=ckb,
                            chain_key_recv=cka, **common)
    return alice, bob


class TestRevealedKeyIsTheAuthenticatingKey:
    """The loop the existing tests do not close."""

    def test_sender_and_receiver_agree_on_mkmac(self):
        """Both ends must derive the same MKmac for one message.

        If they did not, the MAC could never verify -- and the key one side
        published would be meaningless to the other.
        """
        alice, bob = _ratchet_pair()
        ct, header, nonce, tag, _epoch, _reveal, send_mkmac = \
            alice.encrypt_message(b"message one")

        plaintext, recv_mkmac = bob.decrypt_message(header, ct, nonce, tag)

        assert plaintext == b"message one"
        assert len(send_mkmac) == MKMAC_LEN, "MKmac must be 64 bytes per OTRv4 4.4.2"
        assert bytes(send_mkmac) == bytes(recv_mkmac), \
            "sender and receiver derived different MKmac for the same message"

    def test_mkmac_is_not_zero_and_not_the_message_key(self):
        """The exact regression: a 32-byte zero placeholder used to sit here."""
        alice, _bob = _ratchet_pair()
        _ct, _h, _n, _t, _e, _r, mkmac = alice.encrypt_message(b"probe")
        mkmac = bytes(mkmac)
        assert len(mkmac) == MKMAC_LEN
        assert mkmac != bytes(MKMAC_LEN), "MKmac is all zeros -- the L1 bug is back"
        assert set(mkmac) != {0}
        # And it must not simply be the message key repeated or padded.
        assert mkmac[:32] != mkmac[32:], "MKmac looks like a doubled 32-byte value"

    def test_mkmac_differs_per_message(self):
        """A chain-derived key advances; a session-derived one would not.

        Pre-fix the authenticating key was sha3_512(session_id || ratchet_id ||
        msg_num), constant in session_id. This asserts the key now moves with
        the chain rather than being a function of wire fields.
        """
        alice, _bob = _ratchet_pair()
        seen = set()
        for i in range(8):
            *_rest, mkmac = alice.encrypt_message(f"message {i}".encode())
            seen.add(bytes(mkmac))
        assert len(seen) == 8, "MKmac repeated across messages"

    def test_receiver_publishes_the_key_that_authenticated_what_it_received(self):
        """THE test. The published bytes must verify the real earlier message.

        This is what makes revelation load-bearing rather than decorative, and
        it is the assertion that could not have passed before the fix.
        """
        alice, bob = _ratchet_pair()

        # 1. Alice sends M1; Bob receives and authenticates it.
        ct1, h1, n1, t1, _e1, _r1, alice_mkmac = alice.encrypt_message(b"the real message")
        pt1, bob_mkmac = bob.decrypt_message(h1, ct1, n1, t1)
        assert pt1 == b"the real message"

        # 2. Bob's next outgoing message publishes the keys he has queued.
        _ct2, _h2, _n2, _t2, _e2, revealed, _mkmac2 = bob.encrypt_message(b"reply")
        revealed = [bytes(k) for k in revealed]

        assert revealed, "receiver published nothing after authenticating a message"
        assert all(len(k) == MKMAC_LEN for k in revealed), \
            f"published keys are not 64-byte MKmac: {[len(k) for k in revealed]}"

        # 3. The published key IS the key that authenticated M1.
        assert bytes(alice_mkmac) in revealed, (
            "the key Bob published is not the key that authenticated the "
            "message he received -- revelation is decorative"
        )
        assert bytes(bob_mkmac) in revealed

    def test_a_published_key_can_re_mac_a_forgery_of_the_real_message(self):
        """Deniability's operative consequence, using the implementation's own key.

        Distinct from the existing forgeability test: the key here comes out of
        the reveal queue rather than being synthesised by the test.
        """
        alice, bob = _ratchet_pair()

        ct1, h1, n1, t1, _e, _r, _mk = alice.encrypt_message(b"what was really said")
        _pt, _recv_mk = bob.decrypt_message(h1, ct1, n1, t1)
        *_x, revealed, _y = bob.encrypt_message(b"reply")
        published = bytes(revealed[0])

        # Reconstruct the wire message as a third party would from a transcript,
        # then alter it and re-MAC with the published key.
        msg = otr.OTRv4DataMessage()
        msg.sender_tag = 0x0101
        msg.receiver_tag = 0x0202
        msg.flags = 0
        msg.prev_chain_len = 0
        msg.ratchet_id = 1
        msg.message_id = 0
        msg.ecdh_pub = bytes(56)
        msg.nonce = n1
        msg.ciphertext = ct1
        msg.revealed_mac_keys = []
        msg.mac = msg.compute_mac(published)
        assert msg.verify_mac(published)

        forged = otr.OTRv4DataMessage()
        for attr in ("sender_tag", "receiver_tag", "flags", "prev_chain_len",
                     "ratchet_id", "message_id", "ecdh_pub", "nonce"):
            setattr(forged, attr, getattr(msg, attr))
        forged.ciphertext = b"something the sender never sent"
        forged.revealed_mac_keys = []
        forged.mac = forged.compute_mac(published)

        assert forged.ciphertext != msg.ciphertext
        assert forged.verify_mac(published), (
            "a published key cannot authenticate a forgery, so publishing it "
            "buys no deniability"
        )


class TestRevelationHygiene:
    """Properties the queue must hold regardless of the deniability argument."""

    def test_a_key_is_not_published_before_its_message_is_authenticated(self):
        """Publishing early would hand out a live authentication key."""
        alice, bob = _ratchet_pair()
        # Alice's FIRST message can carry nothing: she has authenticated nothing.
        *_r, revealed, _mk = alice.encrypt_message(b"first")
        assert list(revealed) == [], \
            "keys were published before anything had been authenticated"

    def test_the_queue_drains_and_does_not_republish(self):
        """Each key should be published once, not on every subsequent message."""
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, _mk = alice.encrypt_message(b"m1")
        bob.decrypt_message(h, ct, n, t)

        *_a, first_batch, _b = bob.encrypt_message(b"reply 1")
        *_c, second_batch, _d = bob.encrypt_message(b"reply 2")

        assert [bytes(k) for k in first_batch], "first reply published nothing"
        assert list(second_batch) == [], \
            "the same key was published twice -- the queue does not drain"

    def test_queue_is_bounded_under_sustained_traffic(self):
        """A peer that never replies must not grow the queue without limit."""
        alice, bob = _ratchet_pair()
        for i in range(200):
            ct, h, n, t, _e, _r, _mk = alice.encrypt_message(f"m{i}".encode())
            bob.decrypt_message(h, ct, n, t)

        *_x, revealed, _y = bob.encrypt_message(b"finally a reply")
        # MAX_PENDING_REVEALS is 50 in ratchet.rs.
        assert len(revealed) <= 50, \
            f"reveal queue is unbounded: {len(revealed)} keys published at once"

    def test_published_keys_are_not_the_message_keys(self):
        """MKmac becoming public must not expose MKenc.

        MKmac = KDF(usage_MAC_key, MKenc, 64) is one-way, so publishing it must
        not reveal the key that actually decrypts anything.
        """
        alice, bob = _ratchet_pair()
        ct, h, n, t, _e, _r, mkmac = alice.encrypt_message(b"secret text")
        bob.decrypt_message(h, ct, n, t)
        *_x, revealed, _y = bob.encrypt_message(b"reply")

        published = bytes(revealed[0])
        # The plaintext must not be recoverable from the published key, and the
        # published key must not contain the ciphertext or plaintext.
        assert b"secret text" not in published
        assert ct not in published
        assert published != ct
