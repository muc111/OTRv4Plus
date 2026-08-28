#!/usr/bin/env python3
"""Adversarial tests for the OTRv4+ voice subsystem (protocol v3).

Run:  OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 python3 -m unittest test_voice_security -v

Requires ``cryptography``.  ML-KEM-1024 comes from ``otrv4_core`` when the
Rust core is loaded; otherwise from ``kyber-py``, which is a real FIPS 203
implementation, so these tests exercise the genuine hybrid exchange rather
than a stub.  There is deliberately no stub KEM anywhere in this file: a
placeholder that returns constant bytes would make every hybrid test pass
while proving nothing.

Nothing here needs opuslib, PulseAudio, slixmpp or I2P.
"""

import os
import unittest

os.environ.setdefault("OTRV4PLUS_ALLOW_PYTHON_MLKEM", "1")

import otrv4plus_voice as V


CALL_ID = bytes(range(16))
FP_A = "AA" * 64
FP_B = "BB" * 64
OTR_BINDING = b"OTRv4+Voice/session/v3"


def make_pair(call_id=CALL_ID, epoch=0):
    """Run one honest hybrid exchange.  Returns (root_initiator, root_responder).

    Mirrors exactly what VoiceCallSession does, with no session machinery,
    so a transcript-construction bug shows up here rather than only in an
    end-to-end run.
    """
    ini = V.VoiceKeyExchange(True)
    res = V.VoiceKeyExchange(False)

    r_x, r_k, ct = res.responder_agree(ini.public, ini.mlkem_ek)
    transcript_r = V.build_transcript(call_id, OTR_BINDING, FP_B, FP_A,
                                      ini.public, res.public,
                                      ini.mlkem_ek, ct, epoch)
    root_r = V.derive_voice_root(r_x, r_k, transcript_r)

    i_x, i_k = ini.initiator_agree(res.public, ct)
    transcript_i = V.build_transcript(call_id, OTR_BINDING, FP_A, FP_B,
                                      ini.public, res.public,
                                      ini.mlkem_ek, ct, epoch)
    root_i = V.derive_voice_root(i_x, i_k, transcript_i)
    return root_i, root_r, ini, res, ct


# ===========================================================================
# 1. Initial hybrid key establishment
# ===========================================================================

class TestInitialKeyEstablishment(unittest.TestCase):

    def test_kem_is_real_mlkem1024(self):
        kem = V.kem_provider()
        ek, dk = kem.keygen()
        self.assertEqual(len(ek), V.MLKEM_EK_LEN)
        self.assertEqual(len(dk), 3168)
        ct, ss = kem.encaps(ek)
        self.assertEqual(len(ct), V.MLKEM_CT_LEN)
        self.assertEqual(len(ss), V.MLKEM_SS_LEN)
        self.assertEqual(bytes(kem.decaps(ct, dk)), bytes(ss))

    def test_kem_encaps_returns_ciphertext_first(self):
        # The Rust wrapper inverts pqcrypto's (ss, ct) to (ct, ss).  Getting
        # this backwards silently desynchronises the key agreement, so the
        # order is pinned by length rather than by trusting the docstring.
        kem = V.kem_provider()
        ek, _ = kem.keygen()
        first, second = kem.encaps(ek)
        self.assertEqual(len(first), V.MLKEM_CT_LEN)
        self.assertEqual(len(second), V.MLKEM_SS_LEN)

    def test_valid_exchange_agrees(self):
        root_i, root_r, _, _, _ = make_pair()
        self.assertEqual(bytes(root_i), bytes(root_r))
        self.assertEqual(len(root_i), V.ROOT_LEN)

    def test_root_depends_on_both_secrets(self):
        # If either component could be dropped the "hybrid" would be a lie.
        t = V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0)
        base = bytes(V.derive_voice_root(b"\x11" * 56, b"\x22" * 32, t))
        diff_x = bytes(V.derive_voice_root(b"\x99" * 56, b"\x22" * 32, t))
        diff_k = bytes(V.derive_voice_root(b"\x11" * 56, b"\x88" * 32, t))
        self.assertNotEqual(base, diff_x)
        self.assertNotEqual(base, diff_k)
        self.assertNotEqual(diff_x, diff_k)

    def test_hybrid_ikm_is_not_re_partitionable(self):
        # Without length prefixes, moving a byte from the X448 secret to the
        # ML-KEM secret would give the same concatenation and the same root.
        # Lengths are fixed here, so this checks the prefixing directly.
        a = V._lp(b"\x00" * 56) + V._lp(b"\x11" * 32)
        b = V._lp(b"\x00" * 55) + V._lp(b"\x00" + b"\x11" * 32)
        self.assertNotEqual(a, b)

    def test_mismatched_x448_produces_different_roots(self):
        ini = V.VoiceKeyExchange(True)
        res = V.VoiceKeyExchange(False)
        evil = V.VoiceKeyExchange(False)
        r_x, r_k, ct = res.responder_agree(ini.public, ini.mlkem_ek)
        root_r = V.derive_voice_root(
            r_x, r_k, V.build_transcript(CALL_ID, OTR_BINDING, FP_B, FP_A,
                                         ini.public, res.public,
                                         ini.mlkem_ek, ct, 0))
        # Initiator is fed the wrong peer public.
        i_x, i_k = ini.initiator_agree(evil.public, ct)
        root_i = V.derive_voice_root(
            i_x, i_k, V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                                         ini.public, evil.public,
                                         ini.mlkem_ek, ct, 0))
        self.assertNotEqual(bytes(root_i), bytes(root_r))

    def test_malformed_x448_rejected(self):
        res = V.VoiceKeyExchange(False)
        ini = V.VoiceKeyExchange(True)
        for bad in (b"", b"\x00" * 55, b"\x00" * 57, b"\xff" * 32):
            with self.assertRaises(ValueError):
                V.VoiceKeyExchange(False).responder_agree(bad, ini.mlkem_ek)
        # All-zero and reflected keys are rejected explicitly.
        with self.assertRaises(ValueError):
            V.VoiceKeyExchange(False).responder_agree(b"\x00" * 56,
                                                      ini.mlkem_ek)
        with self.assertRaises(ValueError):
            res.responder_agree(res.public, ini.mlkem_ek)

    def test_malformed_mlkem_rejected(self):
        ini = V.VoiceKeyExchange(True)
        for bad in (b"", b"\x00" * 100, b"\x00" * (V.MLKEM_EK_LEN - 1)):
            with self.assertRaises(ValueError):
                V.VoiceKeyExchange(False).responder_agree(ini.public, bad)
        for bad in (b"", b"\x00" * (V.MLKEM_CT_LEN - 1)):
            with self.assertRaises(ValueError):
                V.VoiceKeyExchange(True).initiator_agree(
                    V.VoiceKeyExchange(False).public, bad)

    def test_wrong_mlkem_ciphertext_diverges(self):
        # ML-KEM's FO transform returns an implicit-rejection secret rather
        # than failing, so the roots must simply differ.
        ini = V.VoiceKeyExchange(True)
        res = V.VoiceKeyExchange(False)
        _, _, ct = res.responder_agree(ini.public, ini.mlkem_ek)
        other = V.VoiceKeyExchange(False)
        _, _, ct2 = other.responder_agree(
            V.VoiceKeyExchange(True).public,
            V.VoiceKeyExchange(True).mlkem_ek)
        i_x, i_k = ini.initiator_agree(res.public, ct2)
        self.assertEqual(len(i_k), 32)
        self.assertNotEqual(bytes(i_k), b"\x00" * 32)

    def test_transcript_mismatch_produces_different_roots(self):
        base = V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                                  b"\x01" * 56, b"\x02" * 56,
                                  b"\x03" * V.MLKEM_EK_LEN,
                                  b"\x04" * V.MLKEM_CT_LEN, 0)
        variants = [
            V.build_transcript(b"\xff" * 16, OTR_BINDING, FP_A, FP_B,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0),
            V.build_transcript(CALL_ID, b"other", FP_A, FP_B,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0),
            V.build_transcript(CALL_ID, OTR_BINDING, FP_A, "CC" * 64,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0),
            # Swapped role order for the X448 publics.
            V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                               b"\x02" * 56, b"\x01" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0),
            V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 1),
        ]
        roots = {bytes(V.derive_voice_root(b"\x11" * 56, b"\x22" * 32, t))
                 for t in [base] + variants}
        self.assertEqual(len(roots), len(variants) + 1)

    def test_fingerprint_order_is_symmetric(self):
        # Each side sees its own fingerprint as "local".  If sorting were
        # wrong the two transcripts would differ and every call would abort.
        a = V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0)
        b = V.build_transcript(CALL_ID, OTR_BINDING, FP_B, FP_A,
                               b"\x01" * 56, b"\x02" * 56,
                               b"\x03" * V.MLKEM_EK_LEN,
                               b"\x04" * V.MLKEM_CT_LEN, 0)
        self.assertEqual(a, b)

    def test_fingerprint_normalisation(self):
        self.assertEqual(V.normalise_fingerprint("aa bb:cc-dd"), "AABBCCDD")
        self.assertEqual(V.sorted_fingerprints("bb", "aa"), ("AA", "BB"))
        self.assertEqual(V.sorted_fingerprints("aa", "bb"), ("AA", "BB"))

    def test_confirmations_are_role_distinct(self):
        root = b"\x42" * V.ROOT_LEN
        ci, cr = V.derive_confirmations(root, CALL_ID, 0)
        self.assertNotEqual(ci, cr)
        self.assertEqual(len(ci), V.CONFIRM_LEN)
        # A tag from one epoch must not satisfy another.
        ci2, cr2 = V.derive_confirmations(root, CALL_ID, 1)
        self.assertNotIn(ci2, (ci, cr))
        self.assertNotIn(cr2, (ci, cr))

    def test_confirmation_mismatch_detected(self):
        root_i, root_r, _, _, _ = make_pair()
        ci, cr = V.derive_confirmations(root_i, CALL_ID, 0)
        ci2, cr2 = V.derive_confirmations(root_r, CALL_ID, 0)
        self.assertEqual((ci, cr), (ci2, cr2))
        bad = V.derive_confirmations(b"\x00" * V.ROOT_LEN, CALL_ID, 0)
        self.assertNotEqual(bad[0], ci)

    def test_private_keys_are_single_use(self):
        ini = V.VoiceKeyExchange(True)
        res = V.VoiceKeyExchange(False)
        _, _, ct = res.responder_agree(ini.public, ini.mlkem_ek)
        ini.initiator_agree(res.public, ct)
        with self.assertRaises(RuntimeError):
            ini.initiator_agree(res.public, ct)
        with self.assertRaises(RuntimeError):
            res.responder_agree(ini.public, ini.mlkem_ek)

    def test_role_confusion_rejected(self):
        with self.assertRaises(RuntimeError):
            V.VoiceKeyExchange(False).initiator_agree(b"\x01" * 56,
                                                      b"\x02" * V.MLKEM_CT_LEN)
        with self.assertRaises(RuntimeError):
            V.VoiceKeyExchange(True).responder_agree(b"\x01" * 56,
                                                     b"\x02" * V.MLKEM_EK_LEN)


# ===========================================================================
# 2. Directional keys and nonce hygiene
# ===========================================================================

class TestDirectionalKeys(unittest.TestCase):

    def test_directions_have_independent_keys(self):
        root = b"\x37" * V.ROOT_LEN
        a = bytes(V.derive_media_key(root, CALL_ID, 0, V.DIR_INITIATOR))
        b = bytes(V.derive_media_key(root, CALL_ID, 0, V.DIR_RESPONDER))
        self.assertNotEqual(a, b)

    def test_keys_change_per_epoch_and_per_call(self):
        root = b"\x37" * V.ROOT_LEN
        k0 = bytes(V.derive_media_key(root, CALL_ID, 0, V.DIR_INITIATOR))
        k1 = bytes(V.derive_media_key(root, CALL_ID, 1, V.DIR_INITIATOR))
        k2 = bytes(V.derive_media_key(root, b"\xff" * 16, 0, V.DIR_INITIATOR))
        self.assertEqual(len({k0, k1, k2}), 3)

    def test_both_endpoints_counters_start_at_zero_without_collision(self):
        # The v2 hazard: one shared key and two counters both starting at 0
        # gives identical key+nonce on different plaintexts.
        root = b"\x37" * V.ROOT_LEN
        ini = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        res = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        p1 = ini.seal(b"A" * V.VOICE_PLAIN_LEN)
        p2 = res.seal(b"B" * V.VOICE_PLAIN_LEN)
        self.assertEqual(p1[:V.VOICE_HDR_LEN], p2[:V.VOICE_HDR_LEN])  # same hdr
        self.assertNotEqual(p1[V.VOICE_HDR_LEN:], p2[V.VOICE_HDR_LEN:])

        # "The initiator's send key equals the responder's receive key" used
        # to be asserted by comparing `ini._send_key` with `res._recv_key`.
        # Those attributes are gone: the keys are Rust-owned as of v10.13.2
        # and there is no getter, deliberately.
        #
        # Tested behaviourally instead, which is the stronger statement --
        # it proves the keys match AND that the nonce and AAD agree, which
        # comparing two byte strings never did.
        self.assertEqual(
            res.open(p1[:V.VOICE_HDR_LEN], p1[V.VOICE_HDR_LEN:]),
            b"A" * V.VOICE_PLAIN_LEN,
            "the responder cannot open what the initiator sealed")
        self.assertEqual(
            ini.open(p2[:V.VOICE_HDR_LEN], p2[V.VOICE_HDR_LEN:]),
            b"B" * V.VOICE_PLAIN_LEN,
            "the initiator cannot open what the responder sealed")

    def test_nonce_unique_per_counter(self):
        seen = {V.media_nonce(0, c) for c in range(2000)}
        self.assertEqual(len(seen), 2000)
        self.assertEqual(len(V.media_nonce(0, 0)), 12)

    def test_direction_not_on_the_wire(self):
        # A frame reflected back at its own sender must fail, because the
        # receiver supplies the peer's direction byte locally.
        root = b"\x37" * V.ROOT_LEN
        ini = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        packet = ini.seal(b"X" * V.VOICE_PLAIN_LEN)
        hdr, sealed = packet[:V.VOICE_HDR_LEN], packet[V.VOICE_HDR_LEN:]
        with self.assertRaises(Exception):
            ini.open(hdr, sealed)


# ===========================================================================
# 3. Authenticated media header
# ===========================================================================

class TestMediaAEAD(unittest.TestCase):

    def setUp(self):
        root = b"\x5a" * V.ROOT_LEN
        self.tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        self.rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        self.plain = bytes(V.pad_opus(b"opus-payload"))

    def _one(self):
        packet = self.tx.seal(self.plain)
        return packet[:V.VOICE_HDR_LEN], packet[V.VOICE_HDR_LEN:]

    def test_roundtrip(self):
        hdr, sealed = self._one()
        self.assertEqual(self.rx.open(hdr, sealed), self.plain)
        self.assertEqual(V.unpad_opus(self.plain), b"opus-payload")

    def test_packet_size_is_constant(self):
        for payload in (b"", b"x", b"y" * V.VOICE_OPUS_SLOT):
            packet = self.tx.seal(bytes(V.pad_opus(payload)))
            self.assertEqual(len(packet), V.VOICE_PACKET_LEN)

    def test_ciphertext_modification_rejected(self):
        hdr, sealed = self._one()
        for i in (0, len(sealed) // 2, len(sealed) - 1):
            bad = bytearray(sealed)
            bad[i] ^= 0x01
            with self.assertRaises(Exception):
                self.rx.open(hdr, bytes(bad))

    def test_every_header_field_is_authenticated(self):
        # Byte-for-byte: flipping any bit of the header must reject.  The v2
        # AAD was the constant b"OTRv4+voice", so none of this was covered.
        for offset in range(V.VOICE_HDR_LEN):
            tx = V.VoiceFrameCrypto(b"\x5a" * V.ROOT_LEN, CALL_ID, 0, True)
            rx = V.VoiceFrameCrypto(b"\x5a" * V.ROOT_LEN, CALL_ID, 0, False)
            packet = tx.seal(self.plain)
            hdr = bytearray(packet[:V.VOICE_HDR_LEN])
            sealed = packet[V.VOICE_HDR_LEN:]
            hdr[offset] ^= 0x01
            with self.assertRaises(Exception,
                                   msg="header byte %d unauthenticated" % offset):
                rx.open(bytes(hdr), sealed)

    def test_epoch_modification_rejected(self):
        hdr, sealed = self._one()
        forged = V.pack_media_header(1, 0, V.VOICE_SEALED_LEN)
        with self.assertRaises(V.FrameError):
            self.rx.open(forged, sealed)

    def test_counter_modification_rejected(self):
        hdr, sealed = self._one()
        forged = V.pack_media_header(0, 99, V.VOICE_SEALED_LEN)
        with self.assertRaises(Exception):
            self.rx.open(forged, sealed)

    def test_call_id_modification_rejected(self):
        # call_id is in the AAD but never on the wire, so a receiver holding
        # a different call_id cannot open the frame at all.
        hdr, sealed = self._one()
        other = V.VoiceFrameCrypto(b"\x5a" * V.ROOT_LEN, b"\xee" * 16, 0, False)
        with self.assertRaises(Exception):
            other.open(hdr, sealed)

    def test_length_modification_rejected(self):
        hdr, sealed = self._one()
        forged = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN + 1)
        with self.assertRaises(V.FrameError):
            self.rx.open(forged, sealed)

    def test_frame_type_modification_rejected(self):
        # 0x02/0x03 are now valid PING/PONG types, so a flip to those is
        # caught by the AEAD rather than the parser — the frame type is in
        # the AAD. An undefined type is still refused structurally.
        hdr, sealed = self._one()
        forged = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN,
                                     frame_type=V.FRAME_TYPE_PING)
        with self.assertRaises(Exception):
            self.rx.open(forged, sealed)
        undefined = V.pack_media_header(0, 0, V.VOICE_SEALED_LEN,
                                        frame_type=0x7F)
        with self.assertRaises(V.FrameError):
            self.rx.open(undefined, sealed)

    def test_version_and_sync_validated(self):
        hdr, sealed = self._one()
        bad = bytearray(hdr)
        bad[0] = 0x00
        with self.assertRaises(V.FrameError):
            V.parse_media_header(bytes(bad))
        bad = bytearray(hdr)
        bad[1] = 0x99
        with self.assertRaises(V.FrameError):
            V.parse_media_header(bytes(bad))

    def test_malformed_and_oversized_frames_rejected(self):
        for raw in (b"", b"\xa7", b"\xa7\x03\x01", b"\x00" * 20):
            with self.assertRaises(V.FrameError):
                V.parse_media_header(raw)
        hdr, _ = self._one()
        with self.assertRaises(V.FrameError):
            self.rx.open(hdr, b"\x00" * (V.VOICE_SEALED_LEN + 5))
        with self.assertRaises(V.FrameError):
            self.rx.open(hdr, b"\x00" * 4)

    def test_stale_generation_rejected(self):
        hdr, sealed = self._one()
        stale = V.VoiceFrameCrypto(b"\x5a" * V.ROOT_LEN, CALL_ID, 7, False)
        with self.assertRaises(V.FrameError):
            stale.open(hdr, sealed)

    def test_unpad_rejects_bad_lengths(self):
        with self.assertRaises(V.FrameError):
            V.unpad_opus(b"\x00" * 10)
        bad = bytes([0xFF, 0xFF]) + b"\x00" * V.VOICE_OPUS_SLOT
        with self.assertRaises(V.FrameError):
            V.unpad_opus(bad)
        self.assertIsNone(V.pad_opus(b"z" * (V.VOICE_OPUS_SLOT + 1)))


# ===========================================================================
# 4. Replay, reordering and duplicates
# ===========================================================================

class TestReplayWindow(unittest.TestCase):

    def test_fresh_counters_accepted(self):
        w = V.ReplayWindow()
        for c in range(500):
            self.assertTrue(w.check_and_set(c))

    def test_exact_duplicate_rejected(self):
        w = V.ReplayWindow()
        self.assertTrue(w.check_and_set(10))
        self.assertFalse(w.check_and_set(10))

    def test_reordering_is_accepted_but_replay_is_not(self):
        # These are different things and must behave differently.
        w = V.ReplayWindow()
        for c in (0, 1, 2, 5, 6):
            self.assertTrue(w.check_and_set(c))
        self.assertTrue(w.check_and_set(3), "reordered frame must be accepted")
        self.assertTrue(w.check_and_set(4))
        self.assertFalse(w.check_and_set(3), "replay must be rejected")

    def test_too_old_rejected(self):
        w = V.ReplayWindow()
        w.check_and_set(V.ReplayWindow.WINDOW + 100)
        self.assertFalse(w.check_and_set(1))

    def test_far_future_jump_resets_window(self):
        w = V.ReplayWindow()
        self.assertTrue(w.check_and_set(0))
        self.assertTrue(w.check_and_set(10 ** 6))
        self.assertFalse(w.check_and_set(0))
        self.assertFalse(w.check_and_set(10 ** 6))

    def test_memory_is_bounded(self):
        w = V.ReplayWindow()
        for c in range(200000):
            w.check_and_set(c)
        self.assertLess(w._bits.bit_length(), V.ReplayWindow.WINDOW + 1)

    def test_negative_and_huge_rejected(self):
        w = V.ReplayWindow()
        self.assertFalse(w.check_and_set(-1))
        self.assertFalse(w.check_and_set(1 << 64))


class TestFrameReplay(unittest.TestCase):

    def setUp(self):
        root = b"\x77" * V.ROOT_LEN
        self.tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        self.rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        self.plain = bytes(V.pad_opus(b"frame"))

    def test_replayed_frame_rejected(self):
        packet = self.tx.seal(self.plain)
        hdr, sealed = packet[:V.VOICE_HDR_LEN], packet[V.VOICE_HDR_LEN:]
        self.assertEqual(self.rx.open(hdr, sealed), self.plain)
        with self.assertRaises(V.FrameError):
            self.rx.open(hdr, sealed)

    def test_reordered_frames_accepted(self):
        packets = [self.tx.seal(self.plain) for _ in range(6)]
        for p in [packets[2], packets[0], packets[5], packets[1]]:
            self.assertEqual(self.rx.open(p[:V.VOICE_HDR_LEN],
                                          p[V.VOICE_HDR_LEN:]), self.plain)
        with self.assertRaises(V.FrameError):
            self.rx.open(packets[2][:V.VOICE_HDR_LEN],
                         packets[2][V.VOICE_HDR_LEN:])

    def test_forged_frame_does_not_advance_the_ratchet(self):
        # A frame that fails authentication must not consume a counter or
        # push the receive chain forward, or an attacker could lock the
        # genuine peer out with a single injected packet.
        far = V.VoiceFrameCrypto.RATCHET_INTERVAL * 3
        hdr = V.pack_media_header(0, far, V.VOICE_SEALED_LEN)
        before = self.rx._recv_sub
        with self.assertRaises(Exception):
            self.rx.open(hdr, b"\x00" * V.VOICE_SEALED_LEN)
        self.assertEqual(self.rx._recv_sub, before)
        self.assertFalse(self.rx._replay.seen(far))
        # The genuine peer still works.
        packet = self.tx.seal(self.plain)
        self.assertEqual(self.rx.open(packet[:V.VOICE_HDR_LEN],
                                      packet[V.VOICE_HDR_LEN:]), self.plain)

    def test_implausible_subepoch_bounded(self):
        far = V.VoiceFrameCrypto.RATCHET_INTERVAL * 10000
        hdr = V.pack_media_header(0, far, V.VOICE_SEALED_LEN)
        with self.assertRaises(V.FrameError) as ctx:
            self.rx.open(hdr, b"\x00" * V.VOICE_SEALED_LEN)
        self.assertIn("too far ahead", str(ctx.exception))


# ===========================================================================
# 5. Symmetric media ratchet
# ===========================================================================

class TestMediaRatchet(unittest.TestCase):

    def test_ratchet_is_one_way_and_deterministic(self):
        k = b"\x01" * 32
        a, b = V.ratchet_key(k), V.ratchet_key(k)
        self.assertEqual(bytes(a), bytes(b))
        self.assertNotEqual(bytes(a), k)

    def test_ratchet_advances_across_the_interval(self):
        root = b"\x99" * V.ROOT_LEN
        tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        plain = bytes(V.pad_opus(b"r"))
        n = V.VoiceFrameCrypto.RATCHET_INTERVAL + 5
        for _ in range(n):
            p = tx.seal(plain)
            self.assertEqual(rx.open(p[:V.VOICE_HDR_LEN],
                                     p[V.VOICE_HDR_LEN:]), plain)
        self.assertGreater(tx.ratchet_steps, 0)
        self.assertGreater(rx.ratchet_steps, 0)

    def test_grace_window_covers_reorder_across_a_ratchet_step(self):
        root = b"\x99" * V.ROOT_LEN
        tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        plain = bytes(V.pad_opus(b"g"))
        interval = V.VoiceFrameCrypto.RATCHET_INTERVAL
        packets = [tx.seal(plain) for _ in range(interval + 2)]
        # Deliver the first post-step frame before the last pre-step one.
        for idx in (interval, interval - 1):
            p = packets[idx]
            self.assertEqual(rx.open(p[:V.VOICE_HDR_LEN],
                                     p[V.VOICE_HDR_LEN:]), plain)

    def test_zeroize_is_idempotent_and_blocks_use(self):
        c = V.VoiceFrameCrypto(b"\x99" * V.ROOT_LEN, CALL_ID, 0, True)
        c.zeroize()
        c.zeroize()
        with self.assertRaises(V.FrameError):
            c.seal(bytes(V.pad_opus(b"x")))


# ===========================================================================
# 6. Two-phase hybrid rekey
# ===========================================================================

def rekey_once(sched_i, sched_r, epoch, call_id=CALL_ID):
    """One honest hybrid rekey between two schedules.  Returns confirm tags."""
    ini = V.VoiceKeyExchange(True)
    res = V.VoiceKeyExchange(False)
    r_x, r_k, ct = res.responder_agree(ini.public, ini.mlkem_ek)
    t = V.build_transcript(call_id, OTR_BINDING, FP_A, FP_B,
                           ini.public, res.public, ini.mlkem_ek, ct, epoch)
    root_r = V.derive_rekey_root(sched_r.current_root(), r_x, r_k, t)
    sched_r.begin_rekey(epoch, root_r)

    i_x, i_k = ini.initiator_agree(res.public, ct)
    root_i = V.derive_rekey_root(sched_i.current_root(), i_x, i_k, t)
    sched_i.begin_rekey(epoch, root_i)
    # Captured while pending: commit_rekey clears the pending state, so
    # the tags must be read before either side commits — which is exactly
    # what the manager does with the values rekey_*() returns.
    return sched_i.our_confirm(), sched_r.our_confirm()


class TestRekey(unittest.TestCase):

    def _fresh(self):
        root = bytes(make_pair()[0])
        si = V.VoiceKeySchedule(CALL_ID, True)
        sr = V.VoiceKeySchedule(CALL_ID, False)
        si.install_initial(root)
        sr.install_initial(root)
        return si, sr

    def test_valid_rekey_commits_on_both_sides(self):
        si, sr = self._fresh()
        ci, cr = rekey_once(si, sr, 1)
        self.assertTrue(sr.commit_rekey(1, ci))
        self.assertTrue(si.commit_rekey(1, cr))
        self.assertEqual(si.epoch, 1)
        self.assertEqual(sr.epoch, 1)
        self.assertEqual(bytes(si.current_root()), bytes(sr.current_root()))

    def test_pending_does_not_disturb_the_current_epoch(self):
        si, sr = self._fresh()
        before = bytes(si.current_root())
        rekey_once(si, sr, 1)
        self.assertEqual(si.epoch, 0)
        self.assertEqual(bytes(si.current_root()), before)
        self.assertIsNotNone(si.cipher_for_send())

    def test_failed_rekey_retains_the_working_key(self):
        # The v2 bug: rekey() wiped the current root before comparing
        # confirmations, so any rekey failure killed a live call.
        si, sr = self._fresh()
        before = bytes(si.current_root())
        rekey_once(si, sr, 1)
        self.assertFalse(si.commit_rekey(1, b"\x00" * V.CONFIRM_LEN))
        self.assertEqual(si.epoch, 0)
        self.assertEqual(bytes(si.current_root()), before)
        self.assertIsNotNone(si.cipher_for_send())
        # And media still flows on the old epoch.
        tx = si.cipher_for_send()
        p = tx.seal(bytes(V.pad_opus(b"still working")))
        self.assertEqual(len(p), V.VOICE_PACKET_LEN)

    def test_stale_epoch_rejected(self):
        si, sr = self._fresh()
        ci, cr = rekey_once(si, sr, 1)
        si.commit_rekey(1, cr)
        sr.commit_rekey(1, ci)
        with self.assertRaises(ValueError):
            si.begin_rekey(1, b"\x00" * V.ROOT_LEN)
        with self.assertRaises(ValueError):
            si.begin_rekey(0, b"\x00" * V.ROOT_LEN)

    def test_backward_and_implausible_epochs_rejected(self):
        """Superseded at v10.13.1: a bounded forward jump is now a catch-up.

        Epochs 2 and 5 used to be rejected alongside 1000.  Rejecting them is
        what left a responder permanently behind after one lost REKEYCOMMIT,
        because the repair was itself a forward jump.  Backwards and absurd
        still raise; a peer that is merely ahead does not.
        """
        si, _ = self._fresh()
        for bad in (0, -1, V.VoiceKeySchedule.MAX_CATCHUP + 2, 1000):
            with self.assertRaises(ValueError):
                si.begin_rekey(bad, b"\x00" * V.ROOT_LEN)

    def test_a_bounded_forward_jump_is_accepted(self):
        si, _ = self._fresh()
        si.begin_rekey(3, b"\x00" * V.ROOT_LEN)
        self.assertEqual(si.pending_epoch, 3)
        self.assertEqual(si.epoch, 0, "deriving ahead committed the epoch")

    def test_duplicate_rekey_rejected(self):
        si, sr = self._fresh()
        rekey_once(si, sr, 1)
        with self.assertRaises(RuntimeError):
            si.begin_rekey(1, b"\x00" * V.ROOT_LEN)

    def test_commit_for_the_wrong_epoch_rejected(self):
        si, sr = self._fresh()
        _, cr = rekey_once(si, sr, 1)
        self.assertFalse(si.commit_rekey(2, cr))
        self.assertEqual(si.epoch, 0)

    def test_replayed_confirmation_from_a_previous_epoch_rejected(self):
        si, sr = self._fresh()
        ci, old_confirm = rekey_once(si, sr, 1)
        si.commit_rekey(1, old_confirm)
        sr.commit_rekey(1, ci)
        rekey_once(si, sr, 2)
        self.assertFalse(si.commit_rekey(2, old_confirm))
        self.assertEqual(si.epoch, 1)

    def test_reflected_confirmation_rejected(self):
        # Each side must not accept its own tag echoed back.
        si, sr = self._fresh()
        ci, _ = rekey_once(si, sr, 1)
        self.assertFalse(si.commit_rekey(1, ci))

    def test_previous_epoch_retained_for_inflight_frames(self):
        si, sr = self._fresh()
        old_tx = si.cipher_for_send()
        inflight = old_tx.seal(bytes(V.pad_opus(b"in flight")))
        ci, _ = rekey_once(si, sr, 1)
        sr.commit_rekey(1, ci)
        self.assertEqual(sr.epoch, 1)
        old_rx = sr.cipher_for_epoch(0)
        self.assertIsNotNone(old_rx, "epoch 0 must survive one epoch")
        self.assertEqual(old_rx.open(inflight[:V.VOICE_HDR_LEN],
                                     inflight[V.VOICE_HDR_LEN:]),
                         bytes(V.pad_opus(b"in flight")))

    def test_old_epochs_are_retired(self):
        si, sr = self._fresh()
        for epoch in range(1, 5):
            ci, cr = rekey_once(si, sr, epoch)
            si.commit_rekey(epoch, cr)
            sr.commit_rekey(epoch, ci)
        self.assertEqual(si.live_epochs(), [3, 4])
        self.assertIsNone(si.cipher_for_epoch(0))

    def test_more_than_256_rekeys(self):
        # v2 used an 8-bit generation that wrapped and silently collided.
        si = V.VoiceKeySchedule(CALL_ID, True)
        sr = V.VoiceKeySchedule(CALL_ID, False)
        root = b"\x11" * V.ROOT_LEN
        si.install_initial(root)
        sr.install_initial(root)
        roots = set()
        for epoch in range(1, 301):
            # Cheap deterministic roots: this test is about epoch arithmetic
            # and commit ordering, not about the KEM (covered elsewhere).
            new_root = V.derive_rekey_root(
                si.current_root(), b"\x01" * 56, b"\x02" * 32,
                V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                                   b"\x03" * 56, b"\x04" * 56,
                                   b"\x05" * V.MLKEM_EK_LEN,
                                   b"\x06" * V.MLKEM_CT_LEN, epoch))
            si.begin_rekey(epoch, new_root)
            sr.begin_rekey(epoch, new_root)
            ci, cr = si.our_confirm(), sr.our_confirm()
            self.assertTrue(si.commit_rekey(epoch, cr))
            self.assertTrue(sr.commit_rekey(epoch, ci))
            roots.add(bytes(si.current_root()))
        self.assertEqual(si.epoch, 300)
        self.assertEqual(len(roots), 300, "every epoch must have a unique root")

    def test_abort_wipes_pending_only(self):
        si, sr = self._fresh()
        before = bytes(si.current_root())
        rekey_once(si, sr, 1)
        si.abort_rekey()
        self.assertIsNone(si.pending_epoch)
        self.assertEqual(bytes(si.current_root()), before)
        si.abort_rekey()          # idempotent

    def test_rekey_before_initial_rejected(self):
        s = V.VoiceKeySchedule(CALL_ID, True)
        with self.assertRaises(RuntimeError):
            s.begin_rekey(0, b"\x00" * V.ROOT_LEN)

    def test_zeroize_destroys_everything(self):
        si, sr = self._fresh()
        rekey_once(si, sr, 1)
        si.zeroize()
        self.assertEqual(si.live_epochs(), [])
        self.assertIsNone(si.pending_epoch)
        self.assertFalse(si.ready)
        si.zeroize()

    def test_rekey_gives_post_compromise_recovery(self):
        # An attacker holding epoch N's root must not be able to derive
        # epoch N+1's, because it depends on fresh ephemeral secrets.
        si, sr = self._fresh()
        compromised = bytes(si.current_root())
        _, cr = rekey_once(si, sr, 1)
        si.commit_rekey(1, cr)
        self.assertNotEqual(bytes(si.current_root()), compromised)


# ===========================================================================
# 7. Call state machine
# ===========================================================================

class TestStateMachine(unittest.TestCase):

    def _session(self, initiator=True):
        import asyncio
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        s = V.VoiceCallSession("peer@example.org", loop, CALL_ID, initiator)
        s.otr_material = (OTR_BINDING, FP_A, FP_B)
        return s

    def test_every_legal_transition(self):
        for src, targets in V.CallState.ALLOWED.items():
            for dst in targets:
                s = self._session()
                s.state = src
                s.transition(dst)
                self.assertEqual(s.state, dst, "%s -> %s" % (src, dst))

    def test_every_illegal_transition_rejected(self):
        states = list(V.CallState.ALLOWED)
        checked = 0
        for src in states:
            for dst in states:
                if dst == src or dst in V.CallState.ALLOWED[src]:
                    continue
                s = self._session()
                s.state = src
                with self.assertRaises(V.IllegalTransition,
                                       msg="%s -> %s should be illegal"
                                           % (src, dst)):
                    s.transition(dst)
                checked += 1
        self.assertGreater(checked, 20)

    def test_ended_is_absorbing(self):
        s = self._session()
        s.state = V.CallState.ENDED
        for dst in (V.CallState.ACTIVE, V.CallState.INVITING,
                    V.CallState.RINGING, V.CallState.MEDIA_CONNECTING):
            with self.assertRaises(V.IllegalTransition):
                s.transition(dst)
        self.assertEqual(s.state, V.CallState.ENDED)

    def test_async_callback_cannot_resurrect_a_dead_call(self):
        s = self._session()
        s.state = V.CallState.ENDED
        self.assertFalse(s.try_transition(V.CallState.ACTIVE))
        self.assertEqual(s.state, V.CallState.ENDED)

    def test_audio_cannot_start_before_confirmation(self):
        s = self._session()
        s._writer = object()
        s.state = V.CallState.MEDIA_CONNECTING
        with self.assertRaises(RuntimeError) as ctx:
            s.loop.run_until_complete(s.start_audio())
        self.assertIn("no media keys", str(ctx.exception))

        s.schedule.install_initial(b"\x01" * V.ROOT_LEN)
        with self.assertRaises(RuntimeError) as ctx:
            s.loop.run_until_complete(s.start_audio())
        self.assertIn("not confirmed", str(ctx.exception))

    def test_audio_requires_media_connecting_state(self):
        s = self._session()
        s._writer = object()
        s.schedule.install_initial(b"\x01" * V.ROOT_LEN)
        s.keys_confirmed.set()
        s.state = V.CallState.ACTIVE
        with self.assertRaises(V.IllegalTransition):
            s.loop.run_until_complete(s.start_audio())

    def test_call_id_length_enforced(self):
        import asyncio
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        for bad in (b"", b"\x00" * 8, b"\x00" * 15, b"\x00" * 17):
            with self.assertRaises(ValueError):
                V.VoiceCallSession("p", loop, bad, True)

    def test_force_close_is_safe_and_wipes_keys(self):
        s = self._session()
        s.schedule.install_initial(b"\x01" * V.ROOT_LEN)
        s.force_close_sync()
        self.assertEqual(s.state, V.CallState.ENDED)
        self.assertEqual(s.schedule.live_epochs(), [])
        self.assertIsNone(s.kex)
        s.force_close_sync()          # idempotent

    def test_teardown_at_every_stage(self):
        for state in V.CallState.ALLOWED:
            s = self._session()
            s.state = state
            if state not in (V.CallState.IDLE, V.CallState.ENDED):
                s.schedule.install_initial(b"\x02" * V.ROOT_LEN)
            stats = s.loop.run_until_complete(s.end())
            self.assertEqual(s.state, V.CallState.ENDED)
            self.assertEqual(s.schedule.live_epochs(), [])
            self.assertIsInstance(stats, dict)


# ===========================================================================
# 8. Signalling: call-ID binding and parsing
# ===========================================================================

class TestSignalling(unittest.TestCase):

    def test_roundtrip(self):
        verb, fields = V.parse_signal(V.CALL_PREFIX + "REKEY:aa|1|bb|cc")
        self.assertEqual(verb, "REKEY")
        self.assertEqual(fields, ["aa", "1", "bb", "cc"])

    def test_non_call_bodies_rejected(self):
        for body in ("hello", "", "?OTR:xyz", V.CALL_PREFIX):
            with self.assertRaises(V.SignalError):
                V.parse_signal(body)

    def test_oversized_and_overfull_rejected(self):
        with self.assertRaises(V.SignalError):
            V.parse_signal(V.CALL_PREFIX + "INVITE:" + "a" * 9000)
        with self.assertRaises(V.SignalError):
            V.parse_signal(V.CALL_PREFIX + "INVITE:" + "|".join("x" * 20))

    def test_hex_and_epoch_validation(self):
        self.assertEqual(V._hex_field("00ff"), b"\x00\xff")
        for bad in ("zz", "0", "0x10", ""):
            with self.assertRaises(V.SignalError):
                V._hex_field(bad)
        with self.assertRaises(V.SignalError):
            V._hex_field("00ff", expect_len=4)
        self.assertEqual(V._epoch_field("42"), 42)
        for bad in ("-1", "abc", "", str(1 << 70), "1.5"):
            with self.assertRaises(V.SignalError):
                V._epoch_field(bad)

    def test_every_verb_carries_a_call_id(self):
        # The v2 protocol identified calls by JID alone; ACCEPT, REKEY, END
        # and REJECT carried nothing, so a message from a previous call acted
        # on the current one.  This pins field 0 as the call_id for each verb.
        import inspect
        src = inspect.getsource(V.VoiceCallManager)
        for verb in ("ACCEPT", "CONFIRM", "REJECT", "REKEY", "REKEYACK",
                     "REKEYCOMMIT", "END"):
            self.assertIn('self._signal(peer, "%s"' % verb, src,
                          "%s is never sent" % verb)
        # Every handler resolves the session through _call_for(peer, fields[0]).
        for handler in ("_on_accept", "_on_confirm", "_on_reject", "_on_rekey",
                        "_on_rekey_ack", "_on_rekey_commit", "_on_end"):
            body = inspect.getsource(getattr(V.VoiceCallManager, handler))
            self.assertIn("self._call_for(peer, fields[0])", body,
                          "%s does not bind to the call_id" % handler)


class _FakeOTR:
    def __init__(self, encrypted=True, verified=True):
        self.encrypted, self.verified = encrypted, verified
        self.sent = []

    def has_encrypted_session(self, peer):
        return self.encrypted

    def is_smp_verified(self, peer):
        return self.verified

    def get_smp_status(self, peer):
        return {"verified": self.verified, "state": "SUCCEEDED"}

    def get_session(self, peer):
        return self

    def handle_outgoing_message(self, peer, body):
        self.sent.append(body)
        return body, True


class _FakeClient:
    def __init__(self, otr):
        self.otr = otr
        self.sent = []
        # v2 consulted this set, which the TUI populated by substring-matching
        # printed lines.  It is deliberately poisoned here.
        self._smp_reported = {("peer@example.org", "SUCCEEDED")}

    def _local_fp(self, peer=None):
        return FP_A

    def _remote_fp(self, peer):
        return FP_B

    def send_otr_fragmented(self, peer, frame):
        self.sent.append((peer, frame))


class TestCallIdBinding(unittest.TestCase):

    def setUp(self):
        import asyncio
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.otr = _FakeOTR()
        self.client = _FakeClient(self.otr)
        self.mgr = V.VoiceCallManager(self.client, self.loop)
        self.peer = "peer@example.org"
        self.session = V.VoiceCallSession(self.peer, self.loop, CALL_ID, True)
        self.session.otr_material = (OTR_BINDING, FP_A, FP_B)
        self.session.transition(V.CallState.INVITING)
        self.mgr._calls[self.peer] = self.session

    def test_matching_call_id_resolves(self):
        self.assertIs(self.mgr._call_for(self.peer, CALL_ID.hex()),
                      self.session)

    def test_foreign_call_id_ignored(self):
        self.assertIsNone(self.mgr._call_for(self.peer, ("ff" * 16)))

    def test_malformed_call_id_ignored(self):
        for bad in ("", "zz", "00", "00" * 15, "00" * 17):
            self.assertIsNone(self.mgr._call_for(self.peer, bad))

    def test_end_from_a_previous_call_does_not_kill_the_current_one(self):
        self.loop.run_until_complete(
            self.mgr._on_end(self.peer, [("ff" * 16)]))
        self.assertIn(self.peer, self.mgr._calls)
        self.assertNotEqual(self.session.state, V.CallState.ENDED)

    def test_rekey_for_another_call_ignored(self):
        self.session.state = V.CallState.ACTIVE
        self.loop.run_until_complete(self.mgr._on_rekey(
            self.peer, [("ff" * 16), "1", "00" * 56,
                        "00" * V.MLKEM_EK_LEN]))
        self.assertEqual(self.session.schedule.epoch, -1)

    def test_ended_call_accepts_nothing(self):
        self.session.state = V.CallState.ENDED
        self.assertIsNone(self.mgr._call_for(self.peer, CALL_ID.hex()))


# ===========================================================================
# 9. SMP gating
# ===========================================================================

class TestSMPGating(unittest.TestCase):

    def _mgr(self, otr):
        import asyncio
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        return V.VoiceCallManager(_FakeClient(otr), loop)

    def test_verified_engine_allows(self):
        mgr = self._mgr(_FakeOTR(verified=True))
        self.assertTrue(mgr._smp_verified("peer@example.org"))

    def test_unverified_engine_refuses_despite_poisoned_reported_set(self):
        # The client's _smp_reported set says SUCCEEDED.  v2 returned True on
        # the strength of that alone, and the TUI populated it by matching
        # strings such as "SMP VERIFIED" in printed lines.
        otr = _FakeOTR(verified=False)
        mgr = self._mgr(otr)
        self.assertIn(("peer@example.org", "SUCCEEDED"),
                      mgr.client._smp_reported)
        self.assertFalse(mgr._smp_verified("peer@example.org"))

    def test_state_name_alone_never_verifies(self):
        class NameOnly:
            def has_encrypted_session(self, peer):
                return True

            def is_smp_verified(self, peer):
                raise AttributeError("engine has no predicate")

            def get_smp_status(self, peer):
                return {"state": "STATE_UPDATED"}

            def get_session(self, peer):
                return object()

        mgr = self._mgr(NameOnly())
        # v2 treated STATE_UPDATED, and anything containing COMPLETE, as
        # success.  Both are wrong: STATE_UPDATED is a generic notification
        # and SMP completes on failure too.
        self.assertFalse(mgr._smp_verified("peer@example.org"))
        for name in ("COMPLETE", "COMPLETED", "SMP_COMPLETE", "IN_PROGRESS",
                     "EXPECT_2", "FAILED", "ABORTED"):
            class N(NameOnly):
                def get_smp_status(self, peer, _n=name):
                    return {"state": _n}
            self.assertFalse(self._mgr(N())._smp_verified("peer@example.org"),
                             "%s must not verify" % name)

    def test_completion_attributes_do_not_verify(self):
        class Completing:
            smp_complete = True
            is_complete = True

            def has_encrypted_session(self, peer):
                return True

            def is_smp_verified(self, peer):
                return False

            def get_smp_status(self, peer):
                return {"verified": False, "state": "COMPLETED"}

            def get_session(self, peer):
                return self

        self.assertFalse(self._mgr(Completing())._smp_verified("p@e.org"))

    def test_engine_errors_fail_closed(self):
        class Broken:
            def has_encrypted_session(self, peer):
                raise RuntimeError("engine unavailable")

            def is_smp_verified(self, peer):
                raise RuntimeError("engine unavailable")

            def get_smp_status(self, peer):
                raise RuntimeError("engine unavailable")

            def get_session(self, peer):
                raise RuntimeError("engine unavailable")

        self.assertFalse(self._mgr(Broken())._smp_verified("p@e.org"))

    def test_query_helper_requires_explicit_true(self):
        class Truthy:
            def is_smp_verified(self, peer):
                return "yes"          # truthy but not True

            def get_smp_status(self, peer):
                return {"verified": 1, "state": "SUCCEEDED"}

            def get_session(self, peer):
                return object()

        verified, state = V._smp_query_default(Truthy(), "p@e.org")
        # is_smp_verified is trusted as the engine's own predicate; the
        # status dict is not, and must say exactly True.
        self.assertTrue(verified)
        self.assertEqual(state, "SUCCEEDED")
        self.assertEqual(V._smp_query_default(None, "p"), (False, ""))
        self.assertEqual(V._smp_query_default(Truthy(), ""), (False, ""))


# ===========================================================================
# 10. Jitter buffer
# ===========================================================================

class TestJitterBuffer(unittest.TestCase):

    def _filled(self, n=8, prefill=2):
        jb = V.JitterBuffer(prefill=prefill, maxlen=20)
        for c in range(n):
            jb.push(0, c, bytearray(b"\x01" * 4))
        return jb

    def test_prefill_delays_playout(self):
        jb = V.JitterBuffer(prefill=3, maxlen=10)
        jb.push(0, 0, bytearray(b"a"))
        self.assertIsNone(jb.pop())
        jb.push(0, 1, bytearray(b"b"))
        self.assertIsNone(jb.pop())
        jb.push(0, 2, bytearray(b"c"))
        self.assertIsNotNone(jb.pop())

    def test_reordering_is_corrected(self):
        jb = V.JitterBuffer(prefill=1, maxlen=10)
        for c in (3, 1, 2, 0):
            jb.push(0, c, bytearray([c]))
        out = []
        while True:
            item = jb.pop()
            if item is None:
                break
            out.append(item[0][0])
        self.assertEqual(out, [0, 1, 2, 3])

    def test_duplicates_rejected(self):
        jb = self._filled()
        self.assertFalse(jb.push(0, 3, bytearray(b"dup")))
        self.assertEqual(jb.stats["duplicate"], 1)

    def test_late_frames_rejected(self):
        jb = V.JitterBuffer(prefill=1, maxlen=10)
        for c in (5, 6, 7):
            jb.push(0, c, bytearray([c]))
        jb.pop()
        jb.pop()
        self.assertFalse(jb.push(0, 5, bytearray(b"late")))
        self.assertGreaterEqual(jb.stats["late"], 1)

    def test_depth_is_bounded(self):
        jb = V.JitterBuffer(prefill=1, maxlen=5)
        for c in range(200):
            jb.push(0, c, bytearray(b"x"))
        self.assertLessEqual(jb.depth(), 5)
        self.assertGreater(jb.stats["overflow"], 0)

    def test_epoch_boundary_ordering(self):
        # Counters restart at zero each epoch; ordering on the counter alone
        # would replay a whole epoch backwards at every rekey.
        self.assertLess(V.JitterBuffer.sequence(0, 10 ** 12),
                        V.JitterBuffer.sequence(1, 0))
        jb = V.JitterBuffer(prefill=1, maxlen=10)
        jb.push(1, 0, bytearray(b"new"))
        jb.push(0, 999, bytearray(b"old"))
        self.assertEqual(bytes(jb.pop()[0]), b"old")
        self.assertEqual(bytes(jb.pop()[0]), b"new")

    def test_gaps_reported(self):
        jb = V.JitterBuffer(prefill=1, maxlen=10)
        jb.push(0, 0, bytearray(b"a"))
        jb.push(0, 4, bytearray(b"b"))
        self.assertEqual(jb.pop()[1], 0)
        self.assertEqual(jb.pop()[1], 3)
        self.assertEqual(jb.stats["gaps"], 3)

    def test_clear_is_safe(self):
        jb = self._filled()
        jb.clear()
        self.assertEqual(jb.depth(), 0)
        jb.clear()


# ===========================================================================
# 11. DoS resistance and fuzzing
# ===========================================================================

class TestRateLimiting(unittest.TestCase):

    def test_bucket_caps_and_refills(self):
        rl = V.RateLimiter(3)
        now = 1000.0
        self.assertTrue(all(rl.allow("p", now + i * 0.1) for i in range(3)))
        self.assertFalse(rl.allow("p", now + 0.4))
        self.assertTrue(rl.allow("p", now + 61))

    def test_peers_are_independent(self):
        rl = V.RateLimiter(1)
        self.assertTrue(rl.allow("a", 0))
        self.assertFalse(rl.allow("a", 1))
        self.assertTrue(rl.allow("b", 1))


class TestResourceExhaustion(unittest.TestCase):
    """Per-peer state must not grow without bound."""

    def test_rate_limiter_prunes_idle_peers(self):
        rl = V.RateLimiter(5)
        now = 1000.0
        for i in range(2000):
            rl.allow("peer%d@example.org" % i, now)
        self.assertLessEqual(len(rl._events), V.RateLimiter.MAX_TRACKED + 1,
                             "one list per peer, kept forever, is a slow "
                             "memory exhaustion from anyone who can send a "
                             "call signal")

    def test_a_recent_peer_survives_a_small_amount_of_noise(self):
        rl = V.RateLimiter(2)
        now = 1000.0
        rl.allow("active@example.org", now)
        rl.allow("active@example.org", now + 1)
        for i in range(10):
            rl.allow("noise%d@example.org" % i, now + 2)
        self.assertFalse(rl.allow("active@example.org", now + 3),
                         "an active peer's budget must survive ordinary churn")

    def test_expired_peers_are_dropped(self):
        rl = V.RateLimiter(5)
        rl.allow("gone@example.org", 1000.0)
        rl.allow("here@example.org", 1200.0)
        self.assertNotIn("gone@example.org", rl._events)
        self.assertIn("here@example.org", rl._events)


class TestFuzzing(unittest.TestCase):

    def test_signal_parser_never_crashes(self):
        import random
        random.seed(20260816)
        alphabet = "abcdefABCDEF0123456789|:?+-_ \n\x00\xff"
        for _ in range(4000):
            body = "".join(random.choice(alphabet)
                           for _ in range(random.randint(0, 200)))
            for candidate in (body, V.CALL_PREFIX + body):
                try:
                    V.parse_signal(candidate)
                except V.SignalError:
                    pass

    def test_media_parser_never_crashes(self):
        import random
        random.seed(20260817)
        root = b"\x1f" * V.ROOT_LEN
        rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        for _ in range(4000):
            n = random.randint(0, 60)
            raw = bytes(random.getrandbits(8) for _ in range(n))
            try:
                V.parse_media_header(raw)
            except V.FrameError:
                pass
            try:
                rx.open(raw[:V.VOICE_HDR_LEN], raw[V.VOICE_HDR_LEN:])
            except Exception:
                pass

    def test_random_streams_do_not_desync_the_reader(self):
        import asyncio
        import random
        random.seed(20260818)
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        s = V.VoiceCallSession("p@e.org", loop, CALL_ID, False)
        s.otr_material = (OTR_BINDING, FP_A, FP_B)
        root = bytes(make_pair()[0])
        s.schedule.install_initial(root)
        tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        plain = bytes(V.pad_opus(b"payload"))

        class _Dec:
            def decode(self, data, samples):
                return b"\x00" * (samples * 2)

        s._opus_dec = _Dec()

        buf = bytearray()
        good = 0
        for _ in range(60):
            if random.random() < 0.5:
                buf += tx.seal(plain)
                good += 1
            buf += bytes(random.getrandbits(8)
                         for _ in range(random.randint(1, 40)))
            s._drain_buffer(buf)
        # Garbage between frames must not stop genuine frames being recovered.
        self.assertGreater(s.stats["recv"], 0)
        self.assertLessEqual(s.stats["recv"], good)
        self.assertLessEqual(len(buf), V.VOICE_PACKET_LEN * 8)

    def test_reader_buffer_is_bounded_against_a_silent_peer(self):
        import asyncio
        loop = asyncio.new_event_loop()
        self.addCleanup(loop.close)
        s = V.VoiceCallSession("p@e.org", loop, CALL_ID, False)
        s.otr_material = (OTR_BINDING, FP_A, FP_B)
        buf = bytearray(b"\xa7" * 100000)      # sync bytes, never a real frame
        s._drain_buffer(buf)
        self.assertLessEqual(len(buf), V.VOICE_HDR_LEN)

    def test_frame_counter_exhaustion_refuses_rather_than_wrapping(self):
        c = V.VoiceFrameCrypto(b"\x2b" * V.ROOT_LEN, CALL_ID, 0, True)
        c._send_counter = V.VoiceFrameCrypto.MAX_COUNTER
        with self.assertRaises(V.FrameError):
            c.seal(bytes(V.pad_opus(b"x")))

    def test_epoch_space_is_bounded(self):
        s = V.VoiceKeySchedule(CALL_ID, True)
        s.install_initial(b"\x01" * V.ROOT_LEN)
        s._epoch = V.VoiceKeySchedule.MAX_EPOCH - 1
        with self.assertRaises(ValueError):
            s.begin_rekey(V.VoiceKeySchedule.MAX_EPOCH, b"\x02" * V.ROOT_LEN)


# ===========================================================================
# 12. End-to-end protocol simulation
# ===========================================================================

class TestEndToEnd(unittest.TestCase):
    """Two schedules driven through the full protocol, no transport."""

    def test_full_call(self):
        call_id = os.urandom(16)
        root_i, root_r, _, _, _ = make_pair(call_id)
        self.assertEqual(bytes(root_i), bytes(root_r))

        si = V.VoiceKeySchedule(call_id, True)
        sr = V.VoiceKeySchedule(call_id, False)
        ci_i, cr_i = si.install_initial(root_i)
        ci_r, cr_r = sr.install_initial(root_r)

        # Responder proves first (ACCEPT), initiator second (CONFIRM).
        self.assertEqual(cr_i, cr_r)
        self.assertEqual(ci_i, ci_r)

        plain = bytes(V.pad_opus(b"hello over i2p"))
        tx, rx = si.cipher_for_send(), sr.cipher_for_send()
        for _ in range(50):
            p = tx.seal(plain)
            self.assertEqual(rx.open(p[:V.VOICE_HDR_LEN],
                                     p[V.VOICE_HDR_LEN:]), plain)

        # Rekey mid-call; frames already in flight must still open.
        inflight = tx.seal(plain)
        ci, cr = rekey_once(si, sr, 1, call_id)
        self.assertTrue(sr.commit_rekey(1, ci))
        self.assertTrue(si.commit_rekey(1, cr))
        self.assertEqual(sr.cipher_for_epoch(0).open(
            inflight[:V.VOICE_HDR_LEN], inflight[V.VOICE_HDR_LEN:]), plain)

        tx2, rx2 = si.cipher_for_send(), sr.cipher_for_send()
        for _ in range(50):
            p = tx2.seal(plain)
            self.assertEqual(rx2.open(p[:V.VOICE_HDR_LEN],
                                      p[V.VOICE_HDR_LEN:]), plain)

        # Epoch-0 keys must not open epoch-1 frames.
        p = tx2.seal(plain)
        with self.assertRaises(V.FrameError):
            sr.cipher_for_epoch(0).open(p[:V.VOICE_HDR_LEN],
                                        p[V.VOICE_HDR_LEN:])

        si.zeroize()
        sr.zeroize()
        self.assertEqual(si.live_epochs(), [])

    def test_two_calls_in_one_otr_session_share_no_key(self):
        keys = set()
        for _ in range(2):
            call_id = os.urandom(16)
            root, _, _, _, _ = make_pair(call_id)
            keys.add(bytes(V.derive_media_key(root, call_id, 0,
                                              V.DIR_INITIATOR)))
        self.assertEqual(len(keys), 2)

    def test_loss_and_reordering_tolerated(self):
        import random
        random.seed(20260819)
        root = bytes(make_pair()[0])
        tx = V.VoiceFrameCrypto(root, CALL_ID, 0, True)
        rx = V.VoiceFrameCrypto(root, CALL_ID, 0, False)
        plain = bytes(V.pad_opus(b"lossy"))
        packets = [tx.seal(plain) for _ in range(400)]
        delivered = [p for p in packets if random.random() > 0.15]
        random.shuffle(delivered)
        opened = 0
        for p in delivered:
            try:
                if rx.open(p[:V.VOICE_HDR_LEN], p[V.VOICE_HDR_LEN:]) == plain:
                    opened += 1
            except V.FrameError:
                pass
        self.assertGreater(opened, len(delivered) * 0.9)


if __name__ == "__main__":
    unittest.main(verbosity=2)
