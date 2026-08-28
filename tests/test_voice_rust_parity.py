#!/usr/bin/env python3
"""INV-08: media keys are Rust-owned, and the derivation still matches.

Two jobs, and the second is the one that saves a live call.

Ownership.  `VoiceFrameCrypto` used to hold its keys as Python bytearrays and
hand each one to OpenSSL as `AESGCM(bytes(key))` -- an immutable copy nothing
could wipe, once per direction per sub-epoch.  The keys now live in
`RustVoiceCipher` as `SecretBytes<32>` with no getter.

Parity.  Both ends of a live call must derive identical keys, so the Rust
construction has to reproduce the Python one byte for byte.  It did not, the
first time: `_lp` length-prefixes with four bytes and the Rust used eight.
Every cross-implementation frame failed its tag, and the only symptom was
that nothing decrypted -- no error, no clue, just silence on the call.  These
tests are what turn that into a red build instead.
"""

import os
import sys

import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

V = pytest.importorskip("otrv4plus_voice")
C = pytest.importorskip("otrv4_core")

CALL = bytes(range(16))
ROOT = bytes(range(64))
PLAIN = b"A" * V.VOICE_PLAIN_LEN


# --------------------------------------------------------------------------
# Cross-implementation parity
# --------------------------------------------------------------------------

def _reference_media_key(root, call_id, epoch, direction):
    """Derive the media key WITHOUT touching the code under test.

    This matters more than it looks.  `VoiceFrameCrypto` now delegates to
    `RustVoiceCipher`, so a test that seals with one and opens with the other
    is comparing Rust against Rust: a mutation in the Rust derivation changes
    both sides identically and the test still passes.  A deliberately
    introduced 8-byte length prefix survived exactly that way.

    So the reference is rebuilt here from the primitives -- Python's
    `cryptography` HKDF-SHA512, and the length-prefix rule written out
    literally rather than imported.  If the Rust derivation drifts, these
    disagree.
    """
    import struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    # SPEC: info = label || LP(call_id) || u64(epoch) || u8(direction),
    # where LP is a FOUR-byte big-endian length.  Written out rather than
    # calling V._lp, so importing the wrong helper cannot hide a change.
    info = (b"OTRv4+Voice/Media/v1"
            + struct.pack(">I", len(call_id)) + call_id
            + struct.pack(">Q", epoch)
            + struct.pack(">B", direction))
    return HKDF(algorithm=hashes.SHA512(), length=32,
                salt=call_id, info=info).derive(bytes(root))


def _reference_seal(root, call_id, epoch, direction, counter, plaintext, aad):
    """Seal a frame with an independently derived key."""
    import struct
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _reference_media_key(root, call_id, epoch, direction)
    nonce = struct.pack(">I", epoch & 0xFFFFFFFF) + struct.pack(">Q", counter)
    return AESGCM(key).encrypt(nonce, plaintext, aad)


class TestTheRustDerivationMatchesTheSpec:
    """Differential against a reference built from primitives, not from the
    module under test."""

    def test_rust_opens_a_reference_frame(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, False)     # responder
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        sealed = _reference_seal(ROOT, CALL, 0, V.DIR_INITIATOR, 0, PLAIN, aad)
        assert rust.open(sealed, aad, 0) == PLAIN, (
            "the Rust media-key derivation no longer matches the spec")

    def test_a_reference_receiver_opens_a_rust_frame(self):
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)      # initiator
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        _, sealed = rust.seal(PLAIN, aad)
        key = _reference_media_key(ROOT, CALL, 0, V.DIR_INITIATOR)
        nonce = struct.pack(">I", 0) + struct.pack(">Q", 0)
        assert AESGCM(key).decrypt(nonce, sealed, aad) == PLAIN

    @pytest.mark.parametrize("epoch", [0, 1, 7, 1000])
    def test_it_holds_across_epochs(self, epoch):
        rust = C.RustVoiceCipher(ROOT, CALL, epoch, False)
        hdr = V.pack_media_header(epoch, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        sealed = _reference_seal(ROOT, CALL, epoch, V.DIR_INITIATOR, 0,
                                 PLAIN, aad)
        assert rust.open(sealed, aad, 0) == PLAIN

    @pytest.mark.parametrize("call", [bytes(range(16)), bytes(range(16, 32)),
                                      b"x" * 24])
    def test_it_holds_across_call_ids(self, call):
        rust = C.RustVoiceCipher(ROOT, call, 0, False)
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(call, V.DIR_INITIATOR, hdr)
        sealed = _reference_seal(ROOT, call, 0, V.DIR_INITIATOR, 0, PLAIN, aad)
        assert rust.open(sealed, aad, 0) == PLAIN, (
            "the call_id length prefix disagrees -- a 24-byte call id is "
            "where a wrong prefix width shows up")

    def test_the_ratchet_matches_the_spec(self):
        """One sub-epoch step, derived independently."""
        import struct
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = _reference_media_key(ROOT, CALL, 0, V.DIR_INITIATOR)
        stepped = HKDF(algorithm=hashes.SHA512(), length=32, salt=b"",
                       info=b"OTRv4+Voice/Ratchet/v1").derive(key)

        counter = 500                    # RATCHET_INTERVAL: sub-epoch 1
        hdr = V.pack_media_header(0, counter, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        nonce = struct.pack(">I", 0) + struct.pack(">Q", counter)
        sealed = AESGCM(stepped).encrypt(nonce, PLAIN, aad)

        rust = C.RustVoiceCipher(ROOT, CALL, 0, False)
        assert rust.open(sealed, aad, counter) == PLAIN, (
            "the Rust ratchet step no longer matches the spec")

    def test_a_different_root_does_not_open(self):
        """The differential must not be so loose that anything opens."""
        rust = C.RustVoiceCipher(bytes(64), CALL, 0, False)
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        sealed = _reference_seal(ROOT, CALL, 0, V.DIR_INITIATOR, 0, PLAIN, aad)
        with pytest.raises(ValueError):
            rust.open(sealed, aad, 0)

    def test_the_wire_length_is_unchanged(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        _, sealed = rust.seal(PLAIN, V.media_aad(CALL, V.DIR_INITIATOR, hdr))
        assert len(sealed) == V.VOICE_SEALED_LEN


class TestTheWrapperStillRoundTrips:
    """VoiceFrameCrypto delegates to Rust now; both ends must still agree."""

    def test_initiator_to_responder(self):
        ini = V.VoiceFrameCrypto(bytearray(ROOT), CALL, 0, True)
        res = V.VoiceFrameCrypto(bytearray(ROOT), CALL, 0, False)
        wire = ini.seal(PLAIN)
        assert res.open(wire[:V.VOICE_HDR_LEN], wire[V.VOICE_HDR_LEN:]) == PLAIN

    def test_responder_to_initiator(self):
        ini = V.VoiceFrameCrypto(bytearray(ROOT), CALL, 0, True)
        res = V.VoiceFrameCrypto(bytearray(ROOT), CALL, 0, False)
        wire = res.seal(PLAIN)
        assert ini.open(wire[:V.VOICE_HDR_LEN], wire[V.VOICE_HDR_LEN:]) == PLAIN


class TestNoKeyReachesPython:

    def test_the_cipher_exposes_no_key(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)
        for attr in dir(rust):
            low = attr.lower()
            assert not any(bad in low for bad in
                           ("key", "secret", "chain", "root", "material")), (
                "RustVoiceCipher exposes %s" % attr)

    def test_the_wrapper_holds_no_key_attributes(self):
        py = V.VoiceFrameCrypto(bytearray(ROOT), CALL, 0, True)
        for gone in ("_send_key", "_recv_key", "_recv_prev_key",
                     "_send_gcm", "_recv_gcm", "_recv_prev_gcm"):
            assert not hasattr(py, gone), (
                "%s is back on the Python side" % gone)

    def test_the_kex_exposes_no_private_scalar(self):
        kex = C.RustVoiceKex()
        for attr in dir(kex):
            low = attr.lower()
            assert not any(bad in low for bad in ("secret", "private", "scalar")), (
                "RustVoiceKex exposes %s" % attr)

    def test_repr_leaks_nothing(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)
        text = repr(rust)
        assert ROOT.hex()[:16] not in text
        assert "key" not in text.lower()
        assert repr(C.RustVoiceKex()).count("spent") == 1

    def test_counters_are_still_observable(self):
        """Ownership must not have cost the diagnostics."""
        rust = C.RustVoiceCipher(ROOT, CALL, 3, True)
        assert rust.epoch == 3
        assert rust.send_counter == 0
        assert rust.ratchet_steps == 0
        assert rust.send_sub == 0 and rust.recv_sub == 0
        assert rust.zeroized is False


# --------------------------------------------------------------------------
# Behaviour preserved through the migration
# --------------------------------------------------------------------------

class TestSecurityPropertiesSurvived:

    def test_zeroize_stops_the_cipher(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)
        rust.zeroize()
        assert rust.zeroized is True
        with pytest.raises(RuntimeError):
            rust.seal(PLAIN, b"aad")

    def test_zeroize_is_idempotent(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, True)
        rust.zeroize()
        rust.zeroize()

    def test_a_tampered_frame_fails(self):
        rust_send = C.RustVoiceCipher(ROOT, CALL, 0, True)
        rust_recv = C.RustVoiceCipher(ROOT, CALL, 0, False)
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        _, sealed = rust_send.seal(PLAIN, aad)
        bad = bytearray(sealed)
        bad[-1] ^= 0xFF
        with pytest.raises(ValueError):
            rust_recv.open(bytes(bad), aad, 0)

    def test_the_wrong_aad_fails(self):
        """Direction is not on the wire; a reflected frame must fail."""
        rust_send = C.RustVoiceCipher(ROOT, CALL, 0, True)
        rust_recv = C.RustVoiceCipher(ROOT, CALL, 0, False)
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        _, sealed = rust_send.seal(PLAIN, V.media_aad(CALL, V.DIR_INITIATOR, hdr))
        with pytest.raises(ValueError):
            rust_recv.open(sealed, V.media_aad(CALL, V.DIR_RESPONDER, hdr), 0)

    def test_a_far_future_subepoch_is_refused(self):
        """One crafted header must not cost unbounded hashing."""
        rust = C.RustVoiceCipher(ROOT, CALL, 0, False)
        far = 500 * 100          # RATCHET_INTERVAL * 100
        with pytest.raises(ValueError, match="sub-epoch"):
            rust.open(b"\x00" * V.VOICE_SEALED_LEN, b"aad", far)

    def test_a_forged_frame_does_not_advance_the_chain(self):
        rust = C.RustVoiceCipher(ROOT, CALL, 0, False)
        before = rust.recv_sub
        with pytest.raises(ValueError):
            rust.open(b"\x00" * V.VOICE_SEALED_LEN, b"aad", 500)
        assert rust.recv_sub == before, (
            "a frame that failed its tag moved the receive chain forward")

    def test_directions_derive_different_keys(self):
        """Both counters start at zero, so a shared key would repeat a nonce."""
        a = C.RustVoiceCipher(ROOT, CALL, 0, True)
        b = C.RustVoiceCipher(ROOT, CALL, 0, True)   # same direction
        hdr = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN)
        aad = V.media_aad(CALL, V.DIR_INITIATOR, hdr)
        _, one = a.seal(PLAIN, aad)
        _, two = b.seal(PLAIN, aad)
        assert one == two, "same key, same nonce, same plaintext must agree"

        other = C.RustVoiceCipher(ROOT, CALL, 0, False)
        _, three = other.seal(PLAIN, aad)
        assert three != one, (
            "the two directions share a key, so both counters starting at "
            "zero repeat a nonce")


# --------------------------------------------------------------------------
# X448
# --------------------------------------------------------------------------

class TestTheKexMatchesTheLibraryItReplaced:

    def test_agreement_matches_python_cryptography(self):
        crypto = pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.asymmetric import x448
        from cryptography.hazmat.primitives import serialization as ser

        rust = C.RustVoiceKex()
        peer = x448.X448PrivateKey.generate()
        peer_pub = peer.public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw)

        ours = bytes(rust.agree(peer_pub))
        theirs = peer.exchange(
            x448.X448PublicKey.from_public_bytes(bytes(rust.public)))
        assert ours == theirs, (
            "the Rust X448 disagrees with the library it replaced, so no "
            "call would ever key")

    def test_the_shared_secret_is_wipeable(self):
        """A bytes return would have made it unwipeable and undone the point."""
        rust = C.RustVoiceKex()
        peer = C.RustVoiceKex()
        shared = rust.agree(bytes(peer.public))
        assert isinstance(shared, bytearray)

    def test_the_scalar_is_single_use(self):
        rust = C.RustVoiceKex()
        peer = C.RustVoiceKex()
        assert rust.spent is False
        rust.agree(bytes(peer.public))
        assert rust.spent is True
        with pytest.raises(RuntimeError):
            rust.agree(bytes(peer.public))

    def test_reflection_is_refused(self):
        rust = C.RustVoiceKex()
        with pytest.raises(ValueError, match="echoed"):
            rust.agree(bytes(rust.public))

    def test_an_all_zero_peer_key_is_refused(self):
        rust = C.RustVoiceKex()
        with pytest.raises(ValueError, match="all-zero"):
            rust.agree(b"\x00" * 56)

    def test_a_refused_agreement_still_spends_the_scalar(self):
        """Retrying with a different peer key is a small-subgroup probe."""
        rust = C.RustVoiceKex()
        with pytest.raises(ValueError):
            rust.agree(b"\x00" * 56)
        assert rust.spent is True

    def test_a_wrong_length_peer_key_is_refused(self):
        rust = C.RustVoiceKex()
        with pytest.raises(ValueError):
            rust.agree(b"\x01" * 32)

    def test_two_exchanges_have_different_public_keys(self):
        assert bytes(C.RustVoiceKex().public) != bytes(C.RustVoiceKex().public)

    def test_the_voice_module_uses_it(self):
        kex = V.VoiceKeyExchange(True)
        assert isinstance(kex._kex, C.RustVoiceKex)
        assert bytes(kex.public) == bytes(kex._kex.public)
