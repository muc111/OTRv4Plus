#!/usr/bin/env python3
"""L1 regression tests — OTRv4 MAC-key revelation.

    python3 -m unittest test_mac_key_revelation -v

Covers the wire encoding, the KDF, and the forgeability property, using the
real `OTRv4DataMessage` codec from the engine. Tests that need a live ratchet
are in `ratchet.rs::tests` (`cargo test --lib ratchet`), because the chain
lives in Rust.

No test prints key material. Diagnostics are length, all-zero status and
SHA-256 digests only.
"""

import hashlib
import importlib.util
import os
import struct
import sys
import unittest


def _stub_core_if_absent():
    """Satisfy the engine's import-time guard when otrv4_core is not built.

    The guard checks that the compiled core exposes the DAKE, key-handle and
    PQ symbols. Nothing under test in this file touches any of them — the
    OTRv4DataMessage codec, `kdf_1` and `_kdf_ck` are all pure Python — so the
    stub exists solely to get past the import and is refused the moment a real
    core is present.

    If `otrv4_core` IS built, it is used and this does nothing.
    """
    try:
        import otrv4_core                                    # noqa: F401
        return False
    except ImportError:
        pass

    import types
    mod = types.ModuleType("otrv4_core")

    class _Unavailable:
        """Every attribute raises. A stub must never silently stand in for
        real cryptography."""
        def __getattr__(self, name):
            raise RuntimeError(
                "otrv4_core is stubbed for the pure-Python tests; %r needs a "
                "built core (cargo build --release "
                "--features extension-module,pq-rust)" % name)

    class _RustDAKE:
        new_from_bytearrays = None
        sign_profile_body_and_construct = None
        sign_profile_body_and_construct_with_handles = None
        ed448_sign_test = None
        generate_dake2_output = None
        process_dake2_output = None

    mod.RustDAKE = _RustDAKE
    for sym in ("Ed448KeyHandle", "X448KeyHandle", "generate_ed448_keypair",
                "generate_x448_keypair", "verify_ed448_sig", "mldsa87_keygen",
                "mldsa87_sign", "mldsa87_verify", "aes256gcm_encrypt",
                "aes256gcm_decrypt", "mlkem1024_keygen", "mlkem1024_encaps",
                "mlkem1024_decaps", "py_ring_sign", "py_ring_verify",
                "RustDoubleRatchet", "RustSMP", "kdf_1"):
        setattr(mod, sym, _Unavailable())
    sys.modules["otrv4_core"] = mod
    return True


STUBBED = _stub_core_if_absent()


def _load_engine():
    """Import the engine module by path.

    The filename varies by checkout (`otrv4+.py` is not a legal identifier),
    so it is loaded by spec rather than by name.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("otrv4_.py", "otrv4+.py", "otrv4plus.py"):
        path = os.path.join(here, name)
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location("_otr_engine", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_otr_engine"] = mod
        try:
            spec.loader.exec_module(mod)
            return mod
        except Exception as exc:                      # pragma: no cover
            raise unittest.SkipTest(
                "engine needs otrv4_core built: %s" % exc)
    raise unittest.SkipTest("engine module not found beside the tests")


OTR = _load_engine()
DataMessage = OTR.OTRv4DataMessage
KDFUsage = OTR.KDFUsage
kdf_1 = OTR.kdf_1

MAC_LEN = DataMessage.REVEALED_MAC_KEY_LEN


def digest(b):
    """Safe diagnostic: never returns key material."""
    return hashlib.sha256(bytes(b)).hexdigest()[:16]


def build_message(mac_key, ciphertext=b"ciphertext-under-test",
                  revealed=()):
    m = DataMessage()
    m.sender_tag = 0x00000101
    m.receiver_tag = 0x00000202
    m.flags = 0
    m.prev_chain_len = 0
    m.ratchet_id = 1
    m.message_id = 7
    m.ecdh_pub = bytes(range(56))
    m.nonce = bytes(12)
    m.ciphertext = ciphertext
    m.revealed_mac_keys = list(revealed)
    m.mac = m.compute_mac(mac_key)
    return m


# ===========================================================================
# TEST 1 — the key itself
# ===========================================================================

class TestMKmacDerivation(unittest.TestCase):

    def test_mkmac_is_64_bytes_and_not_zero(self):
        mkenc = kdf_1(KDFUsage.MESSAGE_KEY, b"\x11" * 32, 32)
        mkmac = kdf_1(KDFUsage.MAC_KEY, mkenc, 64)
        self.assertEqual(len(mkmac), MAC_LEN)
        self.assertEqual(MAC_LEN, 64, "OTRv4 §4.4.2 requires 64 bytes")
        self.assertTrue(any(mkmac), "MKmac must not be all-zero")

    def test_mkmac_derives_from_the_message_key_not_the_chain_key(self):
        ck = b"\x22" * 32
        mkenc = kdf_1(KDFUsage.MESSAGE_KEY, ck, 32)
        from_mkenc = kdf_1(KDFUsage.MAC_KEY, mkenc, 64)
        from_ck = kdf_1(KDFUsage.MAC_KEY, ck, 64)
        self.assertNotEqual(from_mkenc, from_ck,
                            "MKmac must chain off MKenc, so revealing it says "
                            "nothing about the chain's future")

    def test_usage_id_matches_the_spec(self):
        self.assertEqual(KDFUsage.MAC_KEY, 0x14)

    def test_python_shadow_chain_returns_a_real_mkmac(self):
        # The regression: _kdf_ck returned bytes(32) in the MKmac position.
        rb = OTR.RustBackedDoubleRatchet.__new__(OTR.RustBackedDoubleRatchet)
        new_ck, mkenc, mkmac = rb._kdf_ck(b"\x33" * 32)
        self.assertEqual(len(new_ck), 32)
        self.assertEqual(len(mkenc), 32)
        self.assertEqual(len(mkmac), 64, "was bytes(32) of zeros")
        self.assertTrue(any(mkmac))
        self.assertEqual(mkmac, kdf_1(KDFUsage.MAC_KEY, mkenc, 64))


# ===========================================================================
# TEST 2 — FORGEABILITY. The property the whole fix exists for.
# ===========================================================================

class TestForgeability(unittest.TestCase):
    """A revealed MAC key must let anyone forge a message that verifies.

    If this fails, revelation is decorative: the key being published is not
    the key that authenticated anything.
    """

    def test_revealed_key_forges_a_modified_message(self):
        mkenc = kdf_1(KDFUsage.MESSAGE_KEY, b"\x44" * 32, 32)
        mkmac = kdf_1(KDFUsage.MAC_KEY, mkenc, 64)

        original = build_message(mkmac, b"the original ciphertext")
        self.assertTrue(original.verify_mac(mkmac))

        # The sender later publishes mkmac. A third party now alters the
        # message and re-MACs it with the published key.
        forged = build_message(mkmac, b"a DIFFERENT ciphertext entirely")
        self.assertNotEqual(forged.ciphertext, original.ciphertext)
        self.assertTrue(
            forged.verify_mac(mkmac),
            "a revealed key must authenticate a forgery — that is deniability")

        # And it survives a wire round trip.
        decoded = DataMessage.decode(forged.encode())
        self.assertTrue(decoded.verify_mac(mkmac))
        self.assertEqual(decoded.ciphertext, forged.ciphertext)


# ===========================================================================
# TEST 3 — a different key must NOT verify
# ===========================================================================

class TestWrongKey(unittest.TestCase):

    def test_unrelated_key_does_not_verify(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\x55" * 32, 64)
        other = kdf_1(KDFUsage.MAC_KEY, b"\x66" * 32, 64)
        m = build_message(mkmac)
        self.assertTrue(m.verify_mac(mkmac))
        self.assertFalse(m.verify_mac(other))

    def test_all_zero_key_does_not_verify(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\x77" * 32, 64)
        m = build_message(mkmac)
        self.assertFalse(m.verify_mac(bytes(64)),
                         "the old revealed value was 64 zero bytes")

    def test_truncated_key_does_not_verify(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\x88" * 32, 64)
        m = build_message(mkmac)
        self.assertFalse(m.verify_mac(mkmac[:32]),
                         "the old code truncated the MAC key to 32 bytes")


# ===========================================================================
# TEST 6 — the wire encoding
# ===========================================================================

class TestWireEncoding(unittest.TestCase):

    def test_revealed_keys_survive_a_round_trip_byte_exact(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\x99" * 32, 64)
        revealed = [kdf_1(KDFUsage.MAC_KEY, bytes([i]) * 32, 64)
                    for i in range(1, 4)]
        m = build_message(mkmac, revealed=revealed)
        decoded = DataMessage.decode(m.encode())
        self.assertEqual(len(decoded.revealed_mac_keys), 3)
        for sent, got in zip(revealed, decoded.revealed_mac_keys):
            self.assertEqual(len(got), 64)
            self.assertEqual(digest(sent), digest(got),
                             "transport must not alter the key")

    def test_empty_queue_encodes_as_empty_not_a_zero_key(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\xaa" * 32, 64)
        m = build_message(mkmac, revealed=[])
        wire = m.encode()
        decoded = DataMessage.decode(wire)
        self.assertEqual(decoded.revealed_mac_keys, [])
        # The count field must literally be zero, with no key bytes after it.
        self.assertTrue(wire.endswith(struct.pack("!I", 0)))

    def test_wrong_length_key_is_refused_not_padded(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\xbb" * 32, 64)
        m = build_message(mkmac)
        m.revealed_mac_keys = [b"\x01" * 32]        # the old size
        with self.assertRaises(ValueError):
            m.encode()

    def test_decoder_rejects_a_truncated_reveal_list(self):
        mkmac = kdf_1(KDFUsage.MAC_KEY, b"\xcc" * 32, 64)
        m = build_message(mkmac, revealed=[kdf_1(KDFUsage.MAC_KEY,
                                                 b"\xdd" * 32, 64)])
        wire = bytearray(m.encode())
        del wire[-10:]
        with self.assertRaises(ValueError):
            DataMessage.decode(bytes(wire))


# ===========================================================================
# TEST 7 — no secret logging
# ===========================================================================

class TestNoSecretLogging(unittest.TestCase):

    def test_no_mac_key_is_printed_on_the_send_or_receive_path(self):
        import inspect
        src = inspect.getsource(OTR)
        offenders = []
        for n, line in enumerate(src.split("\n"), 1):
            low = line.lower()
            if ("print(" not in low and "trace(" not in low
                    and "log(" not in low):
                continue
            if "mac_key" in low and ".hex()" in low:
                offenders.append((n, line.strip()[:70]))
            if "revealed_mac_keys" in low and (".hex()" in low
                                               or "%s" in low):
                offenders.append((n, line.strip()[:70]))
        self.assertEqual(offenders, [],
                         "MAC key material must never reach a log")

    def test_diagnostics_helper_returns_no_key_material(self):
        key = kdf_1(KDFUsage.MAC_KEY, b"\xee" * 32, 64)
        d = digest(key)
        self.assertEqual(len(d), 16)
        self.assertNotIn(d.encode(), key)


# ===========================================================================
# Guards against the specific regression returning
# ===========================================================================

def _code_only(src):
    """Strip comments and docstrings.

    The guards below search for the removed patterns. Without this they match
    the comments that document their removal, which is both a false positive
    and a reason nobody would trust the guard.
    """
    import io
    import tokenize
    out, prev = [], tokenize.INDENT
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                continue
            if tok.type == tokenize.STRING and prev in (
                    tokenize.INDENT, tokenize.NEWLINE, tokenize.NL):
                continue
            out.append(tok.string)
            if tok.type not in (tokenize.NL, tokenize.NEWLINE):
                prev = tok.type
    except Exception:
        return src
    return " ".join(out).replace(" . ", ".")


class TestRegressionGuards(unittest.TestCase):

    def test_no_zero_placeholder_remains_in_the_chain_kdf(self):
        import inspect
        src = _code_only(inspect.getsource(OTR.RustBackedDoubleRatchet._kdf_ck))
        self.assertNotIn("bytes(32)", src,
                         "the all-zero MKmac placeholder is back")
        self.assertIn("KDFUsage.MAC_KEY", src)

    def test_send_path_does_not_derive_mac_from_session_id(self):
        import inspect
        src = _code_only(inspect.getsource(OTR))
        self.assertNotIn('b"OTRv4-MAC-KEY"', src,
                         "the MAC key must come from the ratchet chain, not "
                         "from session_id and two cleartext wire fields")

    def test_send_path_does_not_filter_reveal_keys_by_length(self):
        import inspect
        src = _code_only(inspect.getsource(OTR))
        self.assertNotIn("if len(k) == 32", src,
                         "a silent length filter drops every spec-sized key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
