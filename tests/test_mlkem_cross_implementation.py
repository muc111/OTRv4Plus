#!/usr/bin/env python3
"""ML-KEM-1024 checked against a second, independent implementation.

WHY THIS EXISTS
===============
Every other ML-KEM test in this repository checks the implementation against
itself: keygen, encapsulate, decapsulate, assert the two shared secrets match.
That catches a broken build.  It cannot catch the thing that would actually
matter -- the vendored PQClean code implementing something that is not FIPS 203
ML-KEM-1024, or drifting from it in a future release.  A self-consistent wrong
algorithm passes a round-trip test perfectly.

So this compares against Go's `crypto/mlkem`, which is a separate codebase, a
separate language, and FIPS 140 validated.  Only public values cross between
them -- an encapsulation key and a ciphertext -- which is all that is needed:
if the two agree on the shared secret, they agree on the algorithm.

WHEN IT SKIPS
=============
Go is not available on Termux, so this skips there and on any machine without
a Go toolchain.  That is deliberate: it is a verification to run on a
development machine, not a runtime dependency.  The skip is loud enough to
notice in the summary and the audit records when it was last actually run.

Recorded result, 2026-09-01, Go 1.25.1 vs pqcrypto-mlkem 0.1.1:
10 agreements, 0 mismatches, both directions.  See GROUP_CRYPTO_AUDIT.md.
"""

import os
import shutil
import subprocess
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")


def _go() -> str:
    """A Go toolchain new enough to have crypto/mlkem (Go 1.24+)."""
    found = shutil.which("go")
    if found:
        return found
    for candidate in ("/usr/local/go1.25.1/bin/go", "/usr/local/go/bin/go"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


GO = _go()

pytestmark = pytest.mark.skipif(
    not GO,
    reason="no Go toolchain; the ML-KEM cross-implementation check needs "
           "Go 1.24+ for crypto/mlkem (expected to skip on Termux)")


HARNESS = r'''
package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	switch os.Args[1] {
	case "gen":
		dk, err := mlkem.GenerateKey1024()
		if err != nil { panic(err) }
		fmt.Println(hex.EncodeToString(dk.Bytes()))
		fmt.Println(hex.EncodeToString(dk.EncapsulationKey().Bytes()))
	case "decap":
		seed, _ := hex.DecodeString(os.Args[2])
		ct, _ := hex.DecodeString(os.Args[3])
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil { panic(err) }
		ss, err := dk.Decapsulate(ct)
		if err != nil { fmt.Println("ERROR"); return }
		fmt.Println(hex.EncodeToString(ss))
	case "encap":
		raw, _ := hex.DecodeString(os.Args[2])
		ek, err := mlkem.NewEncapsulationKey1024(raw)
		if err != nil { panic(err) }
		ss, ct := ek.Encapsulate()
		fmt.Println(hex.EncodeToString(ct))
		fmt.Println(hex.EncodeToString(ss))
	}
}
'''


@pytest.fixture(scope="module")
def harness():
    """Build the Go side once.  Offline: no module dependencies."""
    directory = tempfile.mkdtemp()
    with open(os.path.join(directory, "main.go"), "w") as fh:
        fh.write(HARNESS)
    with open(os.path.join(directory, "go.mod"), "w") as fh:
        fh.write("module mlkemcheck\n\ngo 1.24\n")
    env = dict(os.environ, GOFLAGS="-mod=mod", GOTOOLCHAIN="local")
    probe = subprocess.run([GO, "run", ".", "gen"], cwd=directory,
                           capture_output=True, env=env, timeout=300)
    if probe.returncode != 0:
        pytest.skip("the Go harness would not build: %s"
                    % probe.stderr.decode("utf-8", "replace")[:200])

    def run(*args):
        done = subprocess.run([GO, "run", "."] + list(args), cwd=directory,
                              capture_output=True, env=env, timeout=300)
        assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
        return done.stdout.decode().split()

    return run


class TestAgainstGoFips140:

    def test_go_keygen_pqclean_encapsulates_go_decapsulates(self, harness):
        """The direction that checks PQClean's ENCAPSULATION."""
        seed, ek = harness("gen")
        ct, ss_pqclean = core.mlkem1024_encaps(bytes.fromhex(ek))
        ss_go, = harness("decap", seed, ct.hex())
        assert ss_pqclean.hex() == ss_go, (
            "PQClean and Go disagree on the shared secret; one of them is "
            "not implementing FIPS 203 ML-KEM-1024")

    def test_pqclean_keygen_go_encapsulates_pqclean_decapsulates(self, harness):
        """The other half: PQClean's DECAPSULATION and key generation."""
        ek, dk = core.mlkem1024_keygen()
        ct, ss_go = harness("encap", bytes(ek).hex())
        ss_pqclean = core.mlkem1024_decaps(bytes.fromhex(ct), bytes(dk))
        assert ss_pqclean.hex() == ss_go

    @pytest.mark.parametrize("iteration", range(3))
    def test_it_holds_across_fresh_keys(self, harness, iteration):
        """Once could be a coincidence of a fixed test vector; these are
        fresh random keys every time."""
        seed, ek = harness("gen")
        ct, ss_pqclean = core.mlkem1024_encaps(bytes.fromhex(ek))
        ss_go, = harness("decap", seed, ct.hex())
        assert ss_pqclean.hex() == ss_go

    def test_the_sizes_are_the_fips_203_sizes(self, harness):
        """Both implementations must also agree on the wire sizes, or they
        would not interoperate even while computing the same function."""
        _seed, ek = harness("gen")
        assert len(bytes.fromhex(ek)) == 1568
        our_ek, our_dk = core.mlkem1024_keygen()
        assert len(our_ek) == 1568 and len(our_dk) == 3168
        ct, ss = core.mlkem1024_encaps(bytes(our_ek))
        assert len(ct) == 1568 and len(ss) == 32


class TestImplicitRejection:
    """FIPS 203 decapsulation MUST NOT fail.

    On an invalid ciphertext it returns a pseudorandom shared secret derived
    from the implicit-rejection key z, deterministically.  An implementation
    that raised instead would leak, through the error, whether a ciphertext
    was well formed -- and any caller written against a raising API would
    break when moved to a conforming one.
    """

    def test_a_tampered_ciphertext_does_not_raise(self):
        ek, dk = core.mlkem1024_keygen()
        ct, ss = core.mlkem1024_encaps(bytes(ek))
        bad = bytearray(ct)
        bad[0] ^= 0xFF
        out = core.mlkem1024_decaps(bytes(bad), bytes(dk))
        assert len(out) == 32
        assert out != ss

    def test_implicit_rejection_is_deterministic(self):
        """Same bad ciphertext, same key, same answer -- it is a function of
        z and the ciphertext, not fresh randomness."""
        ek, dk = core.mlkem1024_keygen()
        ct, _ss = core.mlkem1024_encaps(bytes(ek))
        bad = bytearray(ct)
        bad[100] ^= 0x01
        first = core.mlkem1024_decaps(bytes(bad), bytes(dk))
        second = core.mlkem1024_decaps(bytes(bad), bytes(dk))
        assert first == second

    def test_the_wrong_key_does_not_raise_either(self):
        ek, _dk = core.mlkem1024_keygen()
        _ek2, dk2 = core.mlkem1024_keygen()
        ct, ss = core.mlkem1024_encaps(bytes(ek))
        assert core.mlkem1024_decaps(ct, bytes(dk2)) != ss

    def test_a_wrong_length_ciphertext_is_still_refused(self):
        """Implicit rejection is for a well-FORMED ciphertext that does not
        decrypt.  A wrong-length input is a caller bug and must be caught."""
        _ek, dk = core.mlkem1024_keygen()
        for length in (0, 1, 1567, 1569):
            with pytest.raises(ValueError):
                core.mlkem1024_decaps(b"\x00" * length, bytes(dk))
