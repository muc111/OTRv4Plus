#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""R2: the per-message MAC key (MKmac) never becomes a Python object.

Every data message used to hand Python its 64-byte MKmac -- on send to
compute the outer SHA3-512 MAC, on receive to check it -- so a live
authentication key sat on the Python heap for every message. Now the ratchet
returns a `MessageMacKey` handle: Rust computes and checks the MAC over the
public region Python frames, answers "is this revealed key this one?" with
one bit, and the session destroys the handle when the message is done.
Keys the peer has already PUBLISHED are public by design (deniability), and
are the only MKmac bytes Python ever holds.
"""

import os

import pytest

import otrv4_core
from otrv4_ import DoubleRatchet, OTRv4DataMessage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pair():
    root, cka, ckb, bk = (os.urandom(32) for _ in range(4))
    common = dict(root_key=root, ad=b"\x01" * 32, brace_key=bk)
    a = DoubleRatchet(is_initiator=True, chain_key_send=cka, chain_key_recv=ckb, **common)
    b = DoubleRatchet(is_initiator=False, chain_key_send=ckb, chain_key_recv=cka, **common)
    return a, b


class TestTheBoundary:
    def test_the_rust_ratchet_returns_a_handle_not_bytes(self):
        a, b = _pair()
        enc = a._rust.encrypt(b"hello")
        assert isinstance(enc["mac_key"], otrv4_core.MessageMacKey)
        res = b._rust.decrypt_same_dh(enc["header"], enc["ciphertext"],
                                      enc["nonce"], enc["tag"])
        assert isinstance(res["mac_key"], otrv4_core.MessageMacKey)
        # The results carry only public wire values and the plaintext; the
        # 64-byte header is the ratchet's public DH key and counters.
        assert set(enc) == {"ciphertext", "header", "nonce", "tag", "ratchet_id",
                            "reveal_mac_keys", "mac_key"}
        assert set(res) == {"plaintext", "mac_key"}

    def test_the_handle_cannot_be_read(self):
        a, _b = _pair()
        *_x, handle = a.encrypt_message(b"m")
        with pytest.raises(TypeError):
            bytes(handle)
        with pytest.raises(TypeError):
            bytearray(handle)
        public = {n for n in dir(handle) if not n.startswith("_")}
        assert public == {"seal", "verify", "matches", "zeroize", "destroyed",
                          "from_revealed"}, public
        assert "held in Rust" in repr(handle)

    def test_a_zeroized_handle_is_spent(self):
        a, _b = _pair()
        *_x, handle = a.encrypt_message(b"m")
        handle.zeroize()
        assert handle.destroyed
        assert not handle.matches(os.urandom(64))
        with pytest.raises(ValueError):
            handle.seal(b"region")

    def test_the_mac_is_the_otrv4_construction(self):
        """SHA3-512(MKmac || region), computed in Rust. Checked with a key
        that is public (as published) so the test itself may hold it."""
        import hashlib
        key = os.urandom(64)
        h = otrv4_core.MessageMacKey.from_revealed(key)
        region = os.urandom(300)
        assert bytes(h.seal(region)) == hashlib.sha3_512(key + region).digest()
        assert h.verify(region, hashlib.sha3_512(key + region).digest())
        assert not h.verify(region + b"x", hashlib.sha3_512(key + region).digest())


class TestTheSessionDestroysIt:
    def test_the_data_message_takes_only_a_handle(self):
        msg = OTRv4DataMessage()
        msg.sender_tag, msg.receiver_tag, msg.flags = 0x101, 0x202, 0
        msg.prev_chain_len, msg.ratchet_id, msg.message_id = 0, 1, 0
        msg.ecdh_pub, msg.nonce, msg.ciphertext = bytes(56), bytes(12), b"c" * 32
        msg.revealed_mac_keys = []
        with pytest.raises(AttributeError):
            msg.compute_mac(os.urandom(64))
        assert not msg.verify_mac(os.urandom(64))

    def test_production_python_never_hashes_a_mac_key(self):
        with open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8") as f:
            src = f.read()
        assert "sha3_512(mac_key" not in src
        assert 'enc["mac_key"]' in src           # passed through, as a handle
        assert "mac_key.zeroize()" in src         # destroyed on both paths
        assert src.count("mac_key.zeroize()") >= 2
