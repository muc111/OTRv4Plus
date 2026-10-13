#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""R1: DAKE3 is signed, verified and decided in Rust.

Until this change the responder's DAKE3 checks -- ring signature, ML-DSA-87,
the "peer committed a PQ key so its signature is mandatory" rule -- and the
move to ESTABLISHED were Python logic, and the initiator's DAKE3 was signed
from Python with a Python-assembled fallback. Rust's own `process_dake3`
was never called, and could not have been: it verified over the raw
transcript while every deployed client signs KDF_1(0x05, DAKE1 || DAKE2).

Now Rust signs and verifies over that Auth-I message, from the transcript it
recorded itself. These tests pin three things:

  * WIRE COMPATIBILITY, both ways, with a peer still running the old code:
    a DAKE3 signed the old way verifies here, and a DAKE3 from here verifies
    the old way (`tests/fixtures/dake_recorded_v1.json` is also checked in
    Rust, `dake::dake3_tests`).
  * AUTHORITY: the Rust state machine, not a Python mirror, reaches
    ESTABLISHED, and refuses what it must.
  * NO PYTHON DAKE3 CRYPTO in production source.
"""

import base64
import os
import re

import pytest

from otrv4_ import (  # otrv4+.py is loaded under this alias by conftest
    RustDAKEAdapter, ClientProfile, NullLogger, DAKEState, KDFUsage, kdf_1,
    RingSignature, _safe_b64decode, _dake1_rate_limiter,
)
import otrv4_core

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _pair():
    _dake1_rate_limiter.reset("alice")
    a = RustDAKEAdapter(client_profile=ClientProfile(), explicit_initiator=True,
                        logger=NullLogger())
    b = RustDAKEAdapter(client_profile=ClientProfile(), explicit_initiator=False,
                        logger=NullLogger())
    d1 = a.generate_dake1()
    assert b.process_dake1(d1, peer_key="alice")
    d2 = b.generate_dake2()
    assert a.process_dake2(d2)
    return a, b, _raw(d1), _raw(d2)


def _raw(msg):
    return _safe_b64decode(msg[7:].strip())


def _wire(raw):
    return "?OTRv4 " + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _auth_i(d1, d2):
    return kdf_1(KDFUsage.AUTH_I_MSG, d1 + d2, 64)


class TestWireCompatibility:
    def test_an_old_style_dake3_is_accepted(self):
        """A pre-R1 initiator (e.g. an older Termux build) signs in Python
        over KDF_1(0x05, DAKE1||DAKE2) with its handle. This responder,
        verifying in Rust, must accept it."""
        a, b, d1, d2 = _pair()
        msg = _auth_i(d1, d2)
        ident = a.client_profile.identity_key
        sigma = RingSignature.sign(ident, bytes(a.client_profile.identity_pub_bytes),
                                   bytes(b.client_profile.identity_pub_bytes), msg)
        raw = bytes([0x37]) + sigma + b"\x01" + a._mldsa_auth.sign(msg)
        assert b.process_dake3(_wire(raw))
        assert b.state == DAKEState.ESTABLISHED
        assert b._rust.get_phase() == "ESTABLISHED"

    def test_a_new_dake3_verifies_the_old_way(self):
        """An older responder verifies with py_ring_verify and ML-DSA over the
        same Auth-I message. What Rust signs now must pass that."""
        a, b, d1, d2 = _pair()
        raw = _raw(a.generate_dake3())
        msg = _auth_i(d1, d2)
        assert raw[0] == 0x37 and raw[229] == 0x01 and len(raw) == 1 + 228 + 1 + 4627
        assert otrv4_core.py_ring_verify(bytes(a.client_profile.identity_pub_bytes),
                                         bytes(b.client_profile.identity_pub_bytes),
                                         msg, raw[1:229])
        assert otrv4_core.mldsa87_verify(a._mldsa_auth.pub_bytes, msg, raw[230:])


class TestRustDecides:
    def test_both_rust_state_machines_reach_established(self):
        a, b, _, _ = _pair()
        assert b.process_dake3(a.generate_dake3())
        assert a._rust.get_phase() == "ESTABLISHED"
        assert b._rust.get_phase() == "ESTABLISHED"
        assert b.state == DAKEState.ESTABLISHED

    def test_a_stripped_ml_dsa_signature_is_refused(self):
        a, b, _, _ = _pair()
        raw = _raw(a.generate_dake3())
        stripped = raw[:229] + b"\x00"
        assert not b.process_dake3(_wire(stripped))
        assert b.state == DAKEState.FAILED
        assert b._rust.get_phase() != "ESTABLISHED"

    @pytest.mark.parametrize("pos", [1, 200, 231, -1])
    def test_a_tampered_dake3_is_refused(self, pos):
        a, b, _, _ = _pair()
        raw = bytearray(_raw(a.generate_dake3()))
        raw[pos] ^= 0x01
        assert not b.process_dake3(_wire(bytes(raw)))
        assert b._rust.get_phase() != "ESTABLISHED"

    def test_a_dake3_for_another_handshake_is_refused(self):
        a1, _, _, _ = _pair()
        _, b2, _, _ = _pair()
        assert not b2.process_dake3(a1.generate_dake3())
        assert b2._rust.get_phase() != "ESTABLISHED"

    def test_dake3_cannot_be_generated_twice_or_by_the_responder(self):
        a, b, _, _ = _pair()
        assert a.generate_dake3() is not None
        assert a.generate_dake3() is None
        assert b.generate_dake3() is None


class TestNoPythonDake3Crypto:
    def _adapter_source(self):
        with open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8") as f:
            src = f.read()
        start = src.index("class RustDAKEAdapter")
        end = src.index("\ndef ", start)
        return src[start:end]

    def test_the_adapter_neither_signs_nor_verifies(self):
        src = self._adapter_source()
        for forbidden in ("AUTH_I_MSG", "RingSignature.sign", "RingSignature.verify",
                          "MLDSA87Auth.verify", "_mldsa_auth.sign(", "assemble_dake3",
                          "msg.extend(sigma)"):
            assert forbidden not in src, forbidden

    def test_no_production_module_signs_a_ring_signature(self):
        for rel in ("otrv4+.py", "otrv4plus_xmpp.py", "otrv4plus_voice.py"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                src = f.read()
            calls = [m.start() for m in re.finditer(r"RingSignature\.sign\(", src)]
            assert calls == [], rel


class TestTheLivePathNeedsNoRawKeyApi:
    """What production runs -- DAKE, ratchets from the DakeOutput, messages
    both ways with the outer MAC in Rust -- uses handles only, so it also
    runs on a release wheel built without `raw-key-test-api` (CI runs this
    file against that wheel)."""

    def test_handshake_then_messages_both_ways(self):
        from otrv4_ import RustBackedDoubleRatchet
        a, b, _, _ = _pair()
        assert b.process_dake3(a.generate_dake3())
        ra = RustBackedDoubleRatchet.from_dake_output(
            a.get_session_keys()["_dake_output"], is_initiator=True)
        rb = RustBackedDoubleRatchet.from_dake_output(
            b.get_session_keys()["_dake_output"], is_initiator=False)
        for sender, receiver, text in ((ra, rb, b"hello bob"), (rb, ra, b"hello alice"),
                                       (ra, rb, b"again")):
            ct, header, nonce, tag, _e, _rev, send_mac = sender.encrypt_message(text)
            region = b"public region"
            sealed = bytes(send_mac.seal(region))
            plaintext, recv_mac = receiver.decrypt_message(header, ct, nonce, tag)
            assert plaintext == text
            assert recv_mac.verify(region, sealed)
            send_mac.zeroize()
            recv_mac.zeroize()
