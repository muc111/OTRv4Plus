#!/usr/bin/env python3
"""The security invariants of OTRv4+, as data.

Why this file exists
--------------------
Security properties in this project have twice been true in the code and
wrong in the documentation, and once been documented as enforced by a test
that did not exist (the SMP wire byte, VERSIONING.md).  Prose cannot be
executed, so it drifts.

This registry is the single machine-readable list.  Every invariant names
the test module that enforces it, and ``test_invariant_registry.py`` fails
if an invariant has no enforcing test or if a named test module is missing.
That makes "we have a rule about this" and "something checks the rule"
the same statement.

Status values
-------------
``ENFORCED``   a test fails if the property is broken.
``PARTIAL``    tested, but the test cannot cover the whole property; the
               ``limits`` field says what is uncovered.
``INHERENT``   guaranteed by a language or library mechanism rather than by
               our code (a Rust Drop impl), and pinned by a test that
               asserts the mechanism is still declared.
``ACCEPTED``   a known limitation that cannot be fixed at this layer; the
               test pins the DOCUMENTATION so the claim cannot silently
               strengthen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class Invariant:
    id: str
    statement: str
    status: str
    tests: Tuple[str, ...]
    rationale: str = ""
    limits: str = ""


INVARIANTS: Tuple[Invariant, ...] = (
    Invariant(
        id="INV-01",
        statement="SMP secrets are never at rest in plaintext.",
        status="ENFORCED",
        tests=("test_secret_at_rest.py",),
        rationale="Sealed with AES-256-GCM under an Argon2id-derived key, "
                  "AAD b'smp_secrets_v1', written 0600 via atomic replace.",
    ),
    Invariant(
        id="INV-02",
        statement="Account passwords are never written to disk.",
        status="PARTIAL",
        tests=("test_secret_at_rest.py",),
        rationale="Collected with getpass, held only for the connection "
                  "attempt, dropped afterwards.",
        limits="Dropping a Python str releases the reference but cannot "
               "overwrite the buffer.  See INV-14.",
    ),
    Invariant(
        id="INV-03",
        statement="No secret value reaches any log sink.",
        status="ENFORCED",
        tests=("test_log_boundary.py",),
        rationale="The session log is an allowlist of line shapes, not a "
                  "denylist of patterns: a line is written only if it "
                  "matches a known-safe form.",
    ),
    Invariant(
        id="INV-04",
        statement="No secret value is printed to the terminal or UI.",
        status="ENFORCED",
        tests=("test_secret_never_echoes.py", "test_log_boundary.py"),
    ),
    Invariant(
        id="INV-05",
        statement="Secret input does not echo, and the client never promises "
                  "secrecy it did not achieve.",
        status="ENFORCED",
        tests=("test_secret_never_echoes.py",),
        rationale="termios ECHO is cleared with TCSANOW; the masking helper "
                  "returns whether it took effect and the prompt wording "
                  "follows that return value.",
    ),
    Invariant(
        id="INV-06",
        statement="No remote protocol message can arm local secret-input "
                  "capture.",
        status="ENFORCED",
        tests=("test_no_remote_input_capture.py",),
        rationale="Secrets come only from an explicit local /smp-secret "
                  "invocation.  There is no pending-input state machine.",
    ),
    Invariant(
        id="INV-07",
        statement="Rust-owned secret material zeroizes on drop.",
        status="INHERENT",
        tests=("test_rust_zeroization.py",),
        rationale="SecretBytes<N> and SecretVec derive ZeroizeOnDrop; their "
                  "Debug impls print [REDACTED].",
    ),
    Invariant(
        id="INV-08",
        statement="Python does not receive long-lived private key material "
                  "that Rust can own instead.",
        status="PARTIAL",
        tests=("test_release_guard.py", "test_rust_zeroization.py"),
        rationale="Ed448 seeds, ratchet keys and SMP scalars never cross the "
                  "PyO3 boundary; the legacy getters are compiled out.",
        limits="Voice keys ARE Python-owned (bytearray, best-effort wipe). "
               "Documented gap, SECURITY.md caveat 11.",
    ),
    Invariant(
        id="INV-09",
        statement="XMPP persistent identity and IRC ephemeral identity are "
                  "separate stores.",
        status="ENFORCED",
        tests=("test_identity_and_tofu.py", "test_transport_isolation.py"),
    ),
    Invariant(
        id="INV-10",
        statement="An IRC run never writes identity, trust or fingerprint "
                  "state to disk.",
        status="ENFORCED",
        tests=("test_transport_isolation.py",),
        rationale="OTRConfig.persist_identity and .persist_trust default "
                  "False; TrustDatabase._save returns early when not "
                  "persistent.",
    ),
    Invariant(
        id="INV-11",
        statement="TOFU never silently re-pins a changed fingerprint.",
        status="ENFORCED",
        tests=("test_identity_and_tofu.py",),
        rationale="The mismatch branch keeps the old pin, offers no y/n, "
                  "refuses voice, and requires an explicit /trust-reset.",
    ),
    Invariant(
        id="INV-12",
        statement="Voice is authorised by cryptographic SMP verification "
                  "alone.  Display or trust state cannot unlock it.",
        status="ENFORCED",
        tests=("test_voice_authorization.py",),
        rationale="_smp_verified reads only the engine's published "
                  "predicates; both the outbound and inbound call paths "
                  "consult it.",
    ),
    Invariant(
        id="INV-13",
        statement="Rejected media is classified by cause.  A missing key, a "
                  "retired epoch, a replay and a failed AEAD tag are "
                  "distinguishable.",
        status="ENFORCED",
        tests=("test_media_reject_classification.py",),
        rationale="Diagnosing rekey divergence requires telling 'we have no "
                  "key for this epoch' apart from 'this packet is forged'.",
    ),
    Invariant(
        id="INV-14",
        statement="No home-grown cryptographic construction exists where the "
                  "Rust core already supplies the primitive.",
        status="ENFORCED",
        tests=("test_no_parallel_crypto.py",),
        rationale="The hand-rolled SHAKE-256 stream cipher in "
                  "otrv4plus_log.py was deleted at v10.13.1.",
    ),
    Invariant(
        id="INV-15",
        statement="Production builds expose no debug secret getters.",
        status="ENFORCED",
        tests=("test_release_guard.py",),
        rationale="legacy-dake-keys and test-only-kdf are off by default and "
                  "build.rs refuses them without an explicit env opt-in.",
    ),
    Invariant(
        id="INV-16",
        statement="A rekey never leaves the two peers on media key states "
                  "that cannot reach each other.",
        status="PARTIAL",
        tests=("test_rekey_divergence.py",),
        rationale="A receive key is retired only once the peer has "
                  "demonstrably stopped sending under it.",
        limits="Proven against the modelled message sequences, not against "
               "live I2P.  See the rekey analysis in SECURITY.md.",
    ),
)


ENFORCED_STATUSES = frozenset({"ENFORCED", "PARTIAL", "INHERENT", "ACCEPTED"})


def by_id(inv_id: str) -> Invariant:
    for inv in INVARIANTS:
        if inv.id == inv_id:
            return inv
    raise KeyError(inv_id)


def all_test_modules() -> Tuple[str, ...]:
    seen = []
    for inv in INVARIANTS:
        for t in inv.tests:
            if t not in seen:
                seen.append(t)
    return tuple(seen)
