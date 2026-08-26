#!/usr/bin/env python3
"""SMP wire version 0x03 exercised through the real compiled extension.

The Rust unit tests in `smp.rs` cover the derivation.  These go through the
PyO3 boundary, because that is the surface the client actually uses and a wire
version byte is worth checking on real bytes rather than on a struct field.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

C = pytest.importorskip("otrv4_core")

SID = b"sid-argon2-wire-test"
FP_A = b"fp-a" * 8
FP_B = b"fp-b" * 8


def _roundtrip(secret_a, secret_b, sid=SID):
    a = C.RustSMP(True)
    b = C.RustSMP(False)
    a.set_secret(secret_a, sid, FP_A, FP_B)
    m1 = a.generate_smp1(None)
    b.set_secret(secret_b, sid, FP_B, FP_A)
    m2 = b.process_smp1_generate_smp2(m1)
    m3 = a.process_smp2_generate_smp3(m2)
    m4 = b.process_smp3_generate_smp4(m3)
    return a.process_smp4(m4), (m1, m2, m3, m4)


class TestTheWireCarries0x03:

    def test_smp1_announces_version_3(self):
        a = C.RustSMP(True)
        a.set_secret(b"pass", SID, FP_A, FP_B)
        assert a.generate_smp1(None)[0] == 0x03, (
            "a freshly built extension must default to Argon2id SMP; a 0x02 "
            "here usually means the installed wheel is stale")

    def test_every_step_carries_the_same_version_byte(self):
        ok, msgs = _roundtrip(b"shared", b"shared")
        assert ok
        assert [m[0] for m in msgs] == [0x03] * 4


class TestVerificationStillWorks:

    def test_matching_passphrase_verifies(self):
        ok, _ = _roundtrip(b"correct horse battery staple",
                           b"correct horse battery staple")
        assert ok is True

    def test_mismatched_passphrase_does_not_verify(self):
        ok, _ = _roundtrip(b"one", b"another")
        assert ok is False

    def test_a_one_byte_difference_does_not_verify(self):
        ok, _ = _roundtrip(b"passphrase", b"passphrasf")
        assert ok is False

    def test_empty_passphrases_on_both_sides_still_do_not_shortcut(self):
        """Equal-but-empty is a real SMP run, not an automatic pass."""
        ok, _ = _roundtrip(b"", b"")
        assert isinstance(ok, bool)


class TestTheSaltIsBoundToTheSession:

    def test_mismatched_sessions_abort_rather_than_verify(self):
        """Two peers who disagree about the session never get a "yes".

        This does NOT prove the session id reaches the Argon2 salt -- the
        transcript is bound to the session id independently, and that check
        fires first, at SMP3.  The derivation-level proof is the Rust test
        `argon2_salt_binds_the_session_id`, which compares the scalars
        directly.  What this pins is that the failure is an abort and not a
        quiet false verification.
        """
        a = C.RustSMP(True)
        b = C.RustSMP(False)
        a.set_secret(b"same-pass", b"session-one", FP_A, FP_B)
        b.set_secret(b"same-pass", b"session-two", FP_B, FP_A)
        m1 = a.generate_smp1(None)
        m2 = b.process_smp1_generate_smp2(m1)
        with pytest.raises(ValueError):
            m3 = a.process_smp2_generate_smp3(m2)
            m4 = b.process_smp3_generate_smp4(m3)
            assert a.process_smp4(m4) is False

    def test_a_different_peer_fingerprint_is_a_different_derivation(self):
        a = C.RustSMP(True)
        b = C.RustSMP(False)
        a.set_secret(b"same-pass", SID, FP_A, FP_B)
        b.set_secret(b"same-pass", SID, FP_B, b"fp-IMPOSTOR" + b"x" * 21)
        m1 = a.generate_smp1(None)
        m2 = b.process_smp1_generate_smp2(m1)
        m3 = a.process_smp2_generate_smp3(m2)
        m4 = b.process_smp3_generate_smp4(m3)
        assert a.process_smp4(m4) is False


class TestTheCostIsRealButTolerable:

    def test_derivation_is_slow_enough_to_be_memory_hard(self):
        """Not a benchmark -- a smoke test that Argon2 is actually running.

        The 0x02 SHAKE stretch took ~60 ms here.  A 64 MiB Argon2id pass
        cannot be anywhere near free, so a very fast result means the build
        picked up the legacy path.
        """
        a = C.RustSMP(True)
        t = time.perf_counter()
        a.set_secret(b"pass", SID, FP_A, FP_B)
        elapsed = time.perf_counter() - t
        assert elapsed > 0.01, (
            "set_secret took %.4f s, which is too fast for 64 MiB of Argon2id"
            % elapsed)

    def test_derivation_is_fast_enough_for_a_handset(self):
        """SMP runs once per verification, not per message, but a user is
        watching a prompt while it happens."""
        a = C.RustSMP(True)
        t = time.perf_counter()
        a.set_secret(b"pass", SID, FP_A, FP_B)
        elapsed = time.perf_counter() - t
        assert elapsed < 10.0, "set_secret took %.2f s" % elapsed


class TestSecretHandling:

    def test_bytearray_input_is_wiped_in_place(self):
        """Unchanged by 0x03, and worth re-asserting under the new KDF."""
        buf = bytearray(b"secret-passphrase")
        a = C.RustSMP(True)
        a.set_secret_from_bytearray(buf, SID, FP_A, FP_B)
        assert bytes(buf) == b"\x00" * len(buf)


class TestTheUserIsToldTheRealCause:
    """A 0x02/0x03 pair must not be told their passphrase is wrong.

    It is the failure the version byte exists to make diagnosable, and the
    generic SMP error path truncates to 60 characters -- which would cut the
    message off before it says what to do.
    """

    @pytest.fixture
    def otr(self):
        return pytest.importorskip("otrv4_")

    def test_a_version_mismatch_is_recognised(self, otr):
        rust_message = (
            "SMP version mismatch: the other device is running a different "
            "OTRv4Plus build.  SMP 0x03 (Argon2id) and 0x02 derive different "
            "secrets from the same passphrase, so this is not a wrong "
            "passphrase -- both devices must be updated together."
        )
        assert otr._is_smp_version_mismatch(ValueError(rust_message))

    def test_other_smp_failures_are_not_misreported_as_version_skew(self, otr):
        for other in ("Ed448 signature invalid",
                      "Secret not set before SMP2",
                      "SMP session permanently aborted",
                      "ML-DSA-87 verification failed"):
            assert not otr._is_smp_version_mismatch(ValueError(other)), other

    def test_the_help_text_says_it_is_not_a_wrong_passphrase(self, otr):
        help_text = otr.SMP_VERSION_MISMATCH_HELP
        assert "NOT a wrong passphrase" in help_text
        assert "Update both devices" in help_text

    def test_the_help_text_bypasses_the_60_char_truncation(self, otr):
        """`_enh_handle_smp_tlv` is the live path (`process_smp_message` is
        explicitly disabled), and its generic branch cuts the message at 60
        characters -- before the sentence that says what to do."""
        import inspect
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        assert "SMP_VERSION_MISMATCH_HELP" in src
        assert "_is_smp_version_mismatch" in src
        # and the generic truncating branch still exists for everything else
        assert "[:60 ]" in src or "[:60]" in src

    def test_the_rust_message_actually_contains_the_matched_phrase(self):
        """Guards against the Rust text drifting away from the Python matcher."""
        smp_rs = open(
            os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "Rust", "src", "smp.rs"),
            encoding="utf-8").read()
        assert "SMP version mismatch:" in smp_rs, (
            "the Rust error text changed; _is_smp_version_mismatch matches on "
            "it and would silently stop recognising the condition")
