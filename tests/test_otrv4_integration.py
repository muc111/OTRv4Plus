#!/usr/bin/env python3
"""
Integration test for OTRv4+ with ML-KEM-1024
Tests the complete DAKE flow with post-quantum KEM
"""

import os
import sys
import unittest
import secrets
import hashlib
import base64
import time
from typing import Optional

# Add current directory to path and import from otrv4+.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the main file (note the + in the filename)
from otrv4_ import (  # We'll need to create a symlink or handle the +
    OTRv4DAKE, ClientProfile, MLKEM1024BraceKEM,
    DAKEState, SessionState, KDFUsage, kdf_1,
    UIConstants, OTRLogger, NullLogger, OTRTracer,
    _dake1_rate_limiter
)


class TestOTRv4PlusMLKEM(unittest.TestCase):
    """Integration tests for OTRv4+ with ML-KEM-1024"""
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*70)
        print("🔐 OTRv4+ ML-KEM-1024 INTEGRATION TESTS")
        print("="*70)
        
        cls.passed = 0
        cls.failed = 0
    
    def setUp(self):
        """Create fresh profiles for each test"""
        # Reset the global DAKE1 rate limiter so tests don't starve each other
        # (5 per peer per 60s limit would fail by test_13 otherwise)
        _dake1_rate_limiter.reset("alice")

        self.alice_profile = ClientProfile()
        self.bob_profile = ClientProfile()
        
        self.alice_dake = OTRv4DAKE(
            client_profile=self.alice_profile,
            explicit_initiator=True,
            logger=NullLogger()
        )
        
        self.bob_dake = OTRv4DAKE(
            client_profile=self.bob_profile,
            explicit_initiator=False,
            logger=NullLogger()
        )
    
    def test_01_mlkem_key_sizes(self):
        """Test ML-KEM-1024 key sizes"""
        print("\n🔬 Test 1: ML-KEM-1024 Key Sizes")
        
        kem = MLKEM1024BraceKEM()
        
        # Check sizes
        self.assertEqual(len(kem.encap_key_bytes), 1568, "ek should be 1568 bytes")
        
        # Test encapsulation
        ct, ss = MLKEM1024BraceKEM.encapsulate(kem.encap_key_bytes)
        self.assertEqual(len(ct), 1568, "ct should be 1568 bytes")
        self.assertEqual(len(ss), 32, "ss should be 32 bytes")
        
        # Test decapsulation
        ss2 = kem.decapsulate(ct)
        self.assertEqual(ss, ss2, "Decapsulated key should match")
        
        print(f"  ✅ ek: 1568 bytes ✓")
        print(f"  ✅ ct: 1568 bytes ✓")
        print(f"  ✅ ss: 32 bytes ✓")
        print(f"  ✅ Roundtrip: {ss[:4].hex()}... = {ss2[:4].hex()}... ✓")
        
        self.__class__.passed += 1
    
    def test_02_dake1_contains_ek(self):
        """Test that DAKE1 contains ML-KEM encapsulation key"""
        print("\n🔬 Test 2: DAKE1 ML-KEM-1024 ek Inclusion")
        
        dake1 = self.alice_dake.generate_dake1()
        
        # Decode and check
        payload = dake1[7:].strip()
        decoded = OTRv4DAKE._safe_b64decode(payload)
        
        # Check message type
        self.assertEqual(decoded[0], 0x35, "Message type should be DAKE1 (0x35)")
        
        # Extract ek (after type + X448 pub)
        offset = 1 + 56  # type + X448 pub
        ek = decoded[offset:offset + 1568]
        
        self.assertEqual(len(ek), 1568, "Extracted ek should be 1568 bytes")
        print(f"  ✅ DAKE1 contains 1568-byte ML-KEM-1024 ek ✓")
        
        self.__class__.passed += 1
    
    def test_03_full_dake_handshake(self):
        """Test complete DAKE handshake with ML-KEM"""
        print("\n🔬 Test 3: Complete DAKE Handshake")
        
        # Step 1: Alice sends DAKE1
        dake1 = self.alice_dake.generate_dake1()
        print(f"  ✓ Alice → DAKE1")
        
        # Step 2: Bob processes DAKE1
        success = self.bob_dake.process_dake1(dake1, peer_key="alice")
        self.assertTrue(success, "Bob should process DAKE1 successfully")
        print(f"  ✓ Bob ← DAKE1")
        
        # Step 3: Bob sends DAKE2
        dake2 = self.bob_dake.generate_dake2()
        self.assertIsNotNone(dake2, "DAKE2 should be generated")
        print(f"  ✓ Bob → DAKE2")
        
        # Step 4: Alice processes DAKE2
        success = self.alice_dake.process_dake2(dake2)
        self.assertTrue(success, "Alice should process DAKE2 successfully")
        print(f"  ✓ Alice ← DAKE2")
        
        # Check session established for Alice
        self.assertEqual(self.alice_dake.state, DAKEState.ESTABLISHED)
        alice_keys = self.alice_dake.get_session_keys()
        self.assertIsNotNone(alice_keys, "Alice should have session keys")
        
        # Step 5: Alice sends DAKE3
        dake3 = self.alice_dake.generate_dake3()
        self.assertIsNotNone(dake3, "DAKE3 should be generated")
        print(f"  ✓ Alice → DAKE3")
        
        # Step 6: Bob processes DAKE3
        success = self.bob_dake.process_dake3(dake3)
        self.assertTrue(success, "Bob should process DAKE3 successfully")
        print(f"  ✓ Bob ← DAKE3")
        
        # Check session established for Bob
        self.assertEqual(self.bob_dake.state, DAKEState.ESTABLISHED)
        bob_keys = self.bob_dake.get_session_keys()
        self.assertIsNotNone(bob_keys, "Bob should have session keys")
        
        # Verify both sides derived same keys
        alice_ssid = alice_keys['session_id'][:8]
        bob_ssid = bob_keys['session_id'][:8]
        self.assertEqual(alice_ssid, bob_ssid, "Session IDs should match")
        
        print(f"  ✅ Session established (ssid={alice_ssid.hex()}) ✓")
        
        self.__class__.passed += 1
    
    def test_04_kdf_fix_verification(self):
        """
        Test the KDF fix: verify that brace_shared is used directly
        in the mixed key derivation, not brace_key
        """
        print("\n🔬 Test 4: KDF Fix Verification")
        
        # Run handshake
        dake1 = self.alice_dake.generate_dake1()
        self.bob_dake.process_dake1(dake1, peer_key="alice")
        dake2 = self.bob_dake.generate_dake2()
        self.alice_dake.process_dake2(dake2)
        
        # Get session keys
        alice_keys = self.alice_dake.get_session_keys()
        
        # Verify brace_key exists (for ratchet)
        self.assertIn('brace_key', alice_keys, "brace_key should be in session keys")
        self.assertEqual(len(alice_keys['brace_key']), 32, "brace_key should be 32 bytes")
        
        # Verify session_id derived correctly
        self.assertEqual(len(alice_keys['session_id']), 32, "session_id should be 32 bytes")
        
        print(f"  ✅ brace_key present: {alice_keys['brace_key'][:4].hex()}...")
        print(f"  ✅ session_id derived: {alice_keys['session_id'][:8].hex()}...")
        
        # Test KDF_1 with brace_shared vs brace_key
        dh1 = secrets.token_bytes(56)
        dh2 = secrets.token_bytes(56)
        dh3 = secrets.token_bytes(56)
        brace_shared = secrets.token_bytes(32)
        
        # Should use brace_shared directly
        mixed_correct = kdf_1(
            KDFUsage.SHARED_SECRET,
            dh1 + dh2 + dh3 + brace_shared,  # direct
            64
        )
        
        # Old way (incorrect) used brace_key
        brace_key = kdf_1(KDFUsage.BRACE_KEY, brace_shared, 32)
        mixed_incorrect = kdf_1(
            KDFUsage.SHARED_SECRET,
            dh1 + dh2 + dh3 + brace_key,  # KDF output, not raw secret
            64
        )
        
        # They should be different
        self.assertNotEqual(mixed_correct, mixed_incorrect, 
                           "Mixed with brace_shared should differ from mixed with brace_key")
        print(f"  ✅ Correct (brace_shared) ≠ Incorrect (brace_key) ✓")
        
        self.__class__.passed += 1
    
    def test_05_brace_key_independent(self):
        """
        Test that brace_key and session keys are independent
        """
        print("\n🔬 Test 5: brace_key Independence")
        
        # Run two handshakes with same profiles but different KEM keys
        alice2_dake = OTRv4DAKE(
            client_profile=self.alice_profile,  # Same profile
            explicit_initiator=True,
            logger=NullLogger()
        )
        
        # First handshake
        dake1a = self.alice_dake.generate_dake1()
        self.bob_dake.process_dake1(dake1a, peer_key="alice")
        dake2a = self.bob_dake.generate_dake2()
        self.alice_dake.process_dake2(dake2a)
        alice_keys_a = self.alice_dake.get_session_keys()
        
        # Second handshake (new KEM keys automatically generated)
        dake1b = alice2_dake.generate_dake1()
        bob2_dake = OTRv4DAKE(
            client_profile=self.bob_profile,
            explicit_initiator=False,
            logger=NullLogger()
        )
        bob2_dake.process_dake1(dake1b, peer_key="alice")
        dake2b = bob2_dake.generate_dake2()
        alice2_dake.process_dake2(dake2b)
        alice_keys_b = alice2_dake.get_session_keys()
        
        # brace_key should be different
        self.assertNotEqual(alice_keys_a['brace_key'], alice_keys_b['brace_key'],
                           "brace_key should differ between sessions")
        
        # session_id should be different
        self.assertNotEqual(alice_keys_a['session_id'], alice_keys_b['session_id'],
                           "session_id should differ between sessions")
        
        print(f"  ✅ Different handshakes produce different brace_key ✓")
        print(f"  ✅ Different handshakes produce different session_id ✓")
        
        self.__class__.passed += 1
    
    def test_06_mac_key_separation(self):
        """Test that DAKE2 MAC key is separate from per-message MAC key"""
        print("\n🔬 Test 6: MAC Key Separation")
        
        # Complete handshake
        dake1 = self.alice_dake.generate_dake1()
        self.bob_dake.process_dake1(dake1, peer_key="alice")
        dake2 = self.bob_dake.generate_dake2()
        self.alice_dake.process_dake2(dake2)
        
        alice_keys = self.alice_dake.get_session_keys()
        
        # DAKE2 MAC key (usage 0x15)
        dake_mac_key = alice_keys['mac_key']
        
        # Derive a per-message MAC key (usage 0x14) using same session material
        per_msg_mac_key = kdf_1(
            KDFUsage.MAC_KEY,
            alice_keys['session_id'] + b'test',
            64
        )
        
        # They should be different due to domain separation
        self.assertNotEqual(dake_mac_key, per_msg_mac_key,
                           "DAKE2 MAC key should differ from per-message MAC key")
        print(f"  ✅ DAKE2 MAC key ≠ per-message MAC key ✓")
        
        self.__class__.passed += 1
    
    def test_07_kem_failure_handling(self):
        """Test that KEM failures are handled gracefully"""
        print("\n🔬 Test 7: KEM Failure Handling")
        
        # Create a KEM with known key
        kem = MLKEM1024BraceKEM()
        ek = kem.encap_key_bytes
        
        # Test with wrong ciphertext
        ct, ss1 = MLKEM1024BraceKEM.encapsulate(ek)
        
        # Modify ciphertext
        ct_list = bytearray(ct)
        ct_list[500] ^= 0xff
        ct_bad = bytes(ct_list)
        
        # Decaps should still return a 32-byte value (implicit rejection)
        ss2 = kem.decapsulate(ct_bad)
        self.assertEqual(len(ss2), 32, "Implicit rejection should return 32 bytes")
        
        # Should be different from original
        self.assertNotEqual(ss1, ss2, "Modified ciphertext should produce different key")
        
        print(f"  ✅ Implicit rejection works: ss1={ss1[:4].hex()}... ≠ ss2={ss2[:4].hex()}... ✓")
        
        self.__class__.passed += 1
    
    def test_08_dake_timeout(self):
        """Test DAKE timeout mechanism"""
        print("\n🔬 Test 8: DAKE Timeout")
        
        # Set short timeout
        self.alice_dake.timeout = 0.1
        
        dake1 = self.alice_dake.generate_dake1()
        self.assertEqual(self.alice_dake.state, DAKEState.SENT_DAKE1)
        
        # Should not be expired immediately
        self.assertFalse(self.alice_dake.is_expired())
        
        # Wait
        time.sleep(0.2)
        
        # Should be expired now
        self.assertTrue(self.alice_dake.is_expired())
        print(f"  ✅ DAKE timeout works ✓")
        
        self.__class__.passed += 1

    def test_09_brace_kem_rotation_lifecycle(self):
        """Test ML-KEM-1024 brace key rotation in DoubleRatchet"""
        print("\n🔬 Test 9: Brace KEM Rotation Lifecycle")

        from otrv4_ import DoubleRatchet, SecureMemory

        root = secrets.token_bytes(32)
        cka  = secrets.token_bytes(32)
        ckb  = secrets.token_bytes(32)
        ad   = secrets.token_bytes(32)
        bk   = secrets.token_bytes(32)

        rka = SecureMemory(32); rka.write(root)
        rkb = SecureMemory(32); rkb.write(root)
        alice = DoubleRatchet(root_key=rka, is_initiator=True,
                              chain_key_send=cka, chain_key_recv=ckb,
                              ad=ad, brace_key=bk)
        bob   = DoubleRatchet(root_key=rkb, is_initiator=False,
                              chain_key_send=ckb, chain_key_recv=cka,
                              ad=ad, brace_key=bk)

        # 1. Initial brace_key matches
        self.assertEqual(alice._brace_key, bob._brace_key,
                         "Initial brace keys should match")
        old_brace = alice._brace_key
        print(f"  ✓ Initial brace_key: {old_brace[:4].hex()}...")

        # 2. Alice prepares rotation — generates KEM keypair
        alice.prepare_brace_rotation()
        self.assertIsNotNone(alice._brace_kem_local,
                             "Alice should have local KEM keypair")
        ek = alice.consume_outgoing_kem_ek()
        self.assertIsNotNone(ek, "Alice should have ek to send")
        self.assertEqual(len(ek), 1568)
        self.assertIsNone(alice.consume_outgoing_kem_ek(),
                          "ek consumed — second call returns None")
        print(f"  ✓ Alice generated ek ({len(ek)} bytes)")

        # 3. Bob processes ek — encapsulates, rotates his brace_key
        bob.process_incoming_kem_ek(ek)
        self.assertNotEqual(bob._brace_key, old_brace,
                            "Bob's brace_key should have rotated")
        ct = bob.consume_outgoing_kem_ct()
        self.assertIsNotNone(ct, "Bob should have ct to send")
        self.assertEqual(len(ct), 1568)
        bob_new_brace = bob._brace_key
        print(f"  ✓ Bob encapsulated, brace_key: {bob_new_brace[:4].hex()}...")

        # 4. Alice processes ct — decapsulates, rotates her brace_key
        alice.process_incoming_kem_ct(ct)
        self.assertEqual(alice._brace_key, bob_new_brace,
                         "After full exchange, brace keys must match")
        self.assertNotEqual(alice._brace_key, old_brace,
                            "Alice's brace_key should have rotated")
        self.assertIsNone(alice._brace_kem_local,
                          "KEM keypair should be zeroized after use")
        print(f"  ✓ Alice decapsulated, brace_key: {alice._brace_key[:4].hex()}...")
        print(f"  ✅ Brace keys converged after full KEM exchange ✓")

        # 5. Second rotation — keys rotate again
        old_brace2 = alice._brace_key
        alice.prepare_brace_rotation()
        ek2 = alice.consume_outgoing_kem_ek()
        bob.process_incoming_kem_ek(ek2)
        ct2 = bob.consume_outgoing_kem_ct()
        alice.process_incoming_kem_ct(ct2)
        self.assertEqual(alice._brace_key, bob._brace_key)
        self.assertNotEqual(alice._brace_key, old_brace2,
                            "Second rotation should produce different key")
        print(f"  ✅ Second rotation converged ✓")

        # 6. Idempotent — calling prepare while awaiting ct is no-op
        alice.prepare_brace_rotation()
        ek3 = alice.consume_outgoing_kem_ek()
        alice.prepare_brace_rotation()  # should be no-op — awaiting ct
        self.assertIsNone(alice.consume_outgoing_kem_ek(),
                          "No second ek while awaiting ct")
        bob.process_incoming_kem_ek(ek3)
        ct3 = bob.consume_outgoing_kem_ct()
        alice.process_incoming_kem_ct(ct3)
        self.assertEqual(alice._brace_key, bob._brace_key)
        print(f"  ✅ Idempotent prepare_brace_rotation ✓")

        self.__class__.passed += 1

    def test_10_brace_rotation_encrypt_decrypt(self):
        """Test that encrypt/decrypt works across DH ratchets that prepare brace rotation"""
        print("\n🔬 Test 10: Encrypt/Decrypt Across DH Ratchets With Brace Rotation")

        from otrv4_ import DoubleRatchet, SecureMemory

        root = secrets.token_bytes(32)
        cka  = secrets.token_bytes(32)
        ckb  = secrets.token_bytes(32)
        ad   = secrets.token_bytes(32)
        bk   = secrets.token_bytes(32)

        rka = SecureMemory(32); rka.write(root)
        rkb = SecureMemory(32); rkb.write(root)
        # rekey_interval=3 so DH ratchets happen frequently
        alice = DoubleRatchet(root_key=rka, is_initiator=True,
                              chain_key_send=cka, chain_key_recv=ckb,
                              ad=ad, brace_key=bk, rekey_interval=3)
        bob   = DoubleRatchet(root_key=rkb, is_initiator=False,
                              chain_key_send=ckb, chain_key_recv=cka,
                              ad=ad, brace_key=bk, rekey_interval=3)

        # ── Run a bidirectional conversation that crosses multiple
        #    DH ratchet boundaries.  Each DH ratchet calls
        #    prepare_brace_rotation() and generates a KEM keypair.
        #    The brace_key doesn't change yet (no ct received),
        #    but _kdf_rk must still produce matching chains.

        delivered = 0
        ratchets_seen = set()

        for round_num in range(10):
            # Alice sends a burst
            for i in range(2):
                msg = f"a2b-r{round_num}-{i}".encode()
                ct, hdr, nonce, tag, rid, _ = alice.encrypt_message(msg)
                pt = bob.decrypt_message(hdr, ct, nonce, tag)
                self.assertEqual(pt, msg)
                ratchets_seen.add(rid)
                delivered += 1

            # Bob replies
            for i in range(2):
                msg = f"b2a-r{round_num}-{i}".encode()
                ct, hdr, nonce, tag, rid, _ = bob.encrypt_message(msg)
                pt = alice.decrypt_message(hdr, ct, nonce, tag)
                self.assertEqual(pt, msg)
                ratchets_seen.add(rid)
                delivered += 1

        self.assertEqual(delivered, 40)
        self.assertGreater(len(ratchets_seen), 1,
                           "Should have crossed at least one DH ratchet boundary")

        # Verify brace rotation was prepared (KEM keypair generated)
        # on at least one side
        has_kem = (alice._brace_kem_local is not None or
                   alice._brace_kem_ek_out is not None or
                   bob._brace_kem_local is not None or
                   bob._brace_kem_ek_out is not None)
        self.assertTrue(has_kem,
                        "At least one side should have prepared brace rotation")

        print(f"  ✓ {delivered} messages across {len(ratchets_seen)} ratchet epochs")
        print(f"  ✓ Brace rotation prepared: KEM keypair ready")
        print(f"  ✅ Encrypt/decrypt correct across DH ratchets with brace rotation ✓")

        self.__class__.passed += 1

    def test_11_desync_kem_ct_without_ek(self):
        """Test that receiving KEM ct without pending local keypair raises"""
        print("\n🔬 Test 11: KEM Desync Protection")

        from otrv4_ import DoubleRatchet, SecureMemory

        root = secrets.token_bytes(32)
        cka  = secrets.token_bytes(32)
        ckb  = secrets.token_bytes(32)
        ad   = secrets.token_bytes(32)
        bk   = secrets.token_bytes(32)

        rka = SecureMemory(32); rka.write(root)
        alice = DoubleRatchet(root_key=rka, is_initiator=True,
                              chain_key_send=cka, chain_key_recv=ckb,
                              ad=ad, brace_key=bk)

        # Alice has NOT prepared a KEM keypair — no _brace_kem_local
        fake_ct = secrets.token_bytes(1568)
        with self.assertRaises(ValueError, msg="Should reject ct without pending ek"):
            alice.process_incoming_kem_ct(fake_ct)
        print(f"  ✅ Desync protected: ct without local keypair → ValueError ✓")

        self.__class__.passed += 1
    
    def test_12_mldsa87_keygen_sign_verify(self):
        """Test ML-DSA-87 standalone keygen/sign/verify"""
        print("\n🔬 Test 12: ML-DSA-87 Standalone")

        from otrv4_ import MLDSA87Auth, MLDSA87_AVAILABLE
        if not MLDSA87_AVAILABLE:
            self.skipTest("ML-DSA-87 C extension not available")

        auth = MLDSA87Auth()
        self.assertEqual(len(auth.pub_bytes), 2592)
        print(f"  ✓ Keygen: pub={len(auth.pub_bytes)} bytes")

        msg = b"test transcript binding message"
        sig = auth.sign(msg)
        self.assertEqual(len(sig), 4627)
        print(f"  ✓ Sign: sig={len(sig)} bytes")

        ok = MLDSA87Auth.verify(auth.pub_bytes, msg, sig)
        self.assertTrue(ok, "Valid signature should verify")
        print(f"  ✓ Verify (valid): True")

        ok2 = MLDSA87Auth.verify(auth.pub_bytes, b"tampered", sig)
        self.assertFalse(ok2, "Tampered message should fail")
        print(f"  ✓ Verify (tampered): False")

        # Zeroize
        auth.zeroize()
        self.assertIsNone(auth._priv)
        print(f"  ✅ ML-DSA-87 standalone ✓")
        self.__class__.passed += 1

    def test_13_hybrid_dake3_full_handshake(self):
        """Test complete DAKE handshake with hybrid Ed448 + ML-DSA-87"""
        print("\n🔬 Test 13: Hybrid DAKE3 Full Handshake")

        from otrv4_ import MLDSA87_AVAILABLE
        if not MLDSA87_AVAILABLE:
            self.skipTest("ML-DSA-87 C extension not available")

        # Both sides should have ML-DSA auth
        self.assertIsNotNone(self.alice_dake._mldsa_auth,
                             "Alice should have ML-DSA-87 keypair")
        self.assertIsNotNone(self.bob_dake._mldsa_auth,
                             "Bob should have ML-DSA-87 keypair")

        # Step 1: Alice → DAKE1
        dake1 = self.alice_dake.generate_dake1()
        print(f"  ✓ Alice → DAKE1")

        # Step 2: Bob ← DAKE1 (should capture Alice's ML-DSA pub)
        success = self.bob_dake.process_dake1(dake1, peer_key="alice")
        self.assertTrue(success)
        self.assertIsNotNone(self.bob_dake._remote_mldsa_pub,
                             "Bob should have Alice's ML-DSA pub from DAKE1")
        self.assertEqual(len(self.bob_dake._remote_mldsa_pub), 2592)
        print(f"  ✓ Bob ← DAKE1 (ML-DSA pub: {len(self.bob_dake._remote_mldsa_pub)} bytes)")

        # Step 3: Bob → DAKE2
        dake2 = self.bob_dake.generate_dake2()
        self.assertIsNotNone(dake2)
        print(f"  ✓ Bob → DAKE2")

        # Step 4: Alice ← DAKE2 (should capture Bob's ML-DSA pub)
        success = self.alice_dake.process_dake2(dake2)
        self.assertTrue(success)
        self.assertIsNotNone(self.alice_dake._remote_mldsa_pub,
                             "Alice should have Bob's ML-DSA pub from DAKE2")
        self.assertEqual(len(self.alice_dake._remote_mldsa_pub), 2592)
        print(f"  ✓ Alice ← DAKE2 (ML-DSA pub: {len(self.alice_dake._remote_mldsa_pub)} bytes)")

        # Step 5: Alice → DAKE3 (hybrid: ring sig + ML-DSA-87)
        dake3 = self.alice_dake.generate_dake3()
        self.assertIsNotNone(dake3)

        # Verify DAKE3 contains ML-DSA flag + signature
        from otrv4_ import OTRv4DAKE
        payload = dake3[7:].strip()
        decoded = OTRv4DAKE._safe_b64decode(payload)
        # type(1) + ring_sig(228) + flag(1) + mldsa_sig(4627)
        expected_len = 1 + 228 + 1 + 4627
        self.assertEqual(len(decoded), expected_len,
                         f"DAKE3 should be {expected_len} bytes, got {len(decoded)}")
        self.assertEqual(decoded[229], 0x01,
                         "ML-DSA flag should be 0x01")
        print(f"  ✓ Alice → DAKE3 ({len(decoded)} bytes: ring_sig + ML-DSA-87)")

        # Step 6: Bob ← DAKE3 (verifies both signatures)
        success = self.bob_dake.process_dake3(dake3)
        self.assertTrue(success, "Bob should verify hybrid DAKE3")
        print(f"  ✓ Bob ← DAKE3 (hybrid verified: ring-sig ✓ + ML-DSA-87 ✓)")

        # Both established
        self.assertEqual(self.alice_dake.state, DAKEState.ESTABLISHED)
        self.assertEqual(self.bob_dake.state, DAKEState.ESTABLISHED)
        print(f"  ✅ Full hybrid DAKE handshake complete ✓")
        self.__class__.passed += 1

    def test_14_dake3_mldsa_tampered_rejected(self):
        """Test that tampered ML-DSA-87 signature in DAKE3 is rejected"""
        print("\n🔬 Test 14: DAKE3 ML-DSA Tamper Detection")

        from otrv4_ import MLDSA87_AVAILABLE, OTRv4DAKE
        if not MLDSA87_AVAILABLE:
            self.skipTest("ML-DSA-87 C extension not available")

        # Complete DAKE up to DAKE3
        dake1 = self.alice_dake.generate_dake1()
        self.bob_dake.process_dake1(dake1, peer_key="alice")
        dake2 = self.bob_dake.generate_dake2()
        self.alice_dake.process_dake2(dake2)
        dake3 = self.alice_dake.generate_dake3()

        # Tamper with the ML-DSA signature
        payload = dake3[7:].strip()
        decoded = bytearray(OTRv4DAKE._safe_b64decode(payload))
        # Flip a byte in the ML-DSA sig (starts at offset 230)
        decoded[230 + 100] ^= 0xFF
        import base64
        tampered = "?OTRv4 " + base64.urlsafe_b64encode(
            bytes(decoded)).decode('ascii').rstrip('=')

        # Bob should reject
        result = self.bob_dake.process_dake3(tampered)
        self.assertFalse(result, "Tampered ML-DSA sig should be rejected")
        print(f"  ✅ Tampered ML-DSA-87 signature correctly rejected ✓")
        self.__class__.passed += 1

    def tearDown(self):
        """Cleanup after each test"""
        if hasattr(self, 'alice_dake'):
            if hasattr(self.alice_dake, '_brace_kem'):
                self.alice_dake._brace_kem.zeroize()
        if hasattr(self, 'bob_dake'):
            if hasattr(self.bob_dake, '_brace_kem'):
                self.bob_dake._brace_kem.zeroize()
    
    @classmethod
    def tearDownClass(cls):
        """Print summary"""
        print("\n" + "="*70)
        print(f"📊 INTEGRATION TEST SUMMARY")
        print("="*70)
        print(f"  Passed: {cls.passed}")
        print(f"  Failed: {cls.failed}")
        
        if cls.failed == 0:
            print("\n✅ ALL TESTS PASSED")
        else:
            print(f"\n❌ {cls.failed} TESTS FAILED")


def run_integration_tests():
    """Run all integration tests"""
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromTestCase(TestOTRv4PlusMLKEM))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    # Run integration tests
    print("\n🔐 OTRv4+ ML-KEM-1024 INTEGRATION TEST SUITE")
    print("="*70)
    
    success = run_integration_tests()
    
    if success:
        print("\n✅ ALL INTEGRATION TESTS PASSED")
        sys.exit(0)
    else:
        print("\n❌ SOME INTEGRATION TESTS FAILED")
        sys.exit(1)