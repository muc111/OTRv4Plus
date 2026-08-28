# Security Invariants

The rules OTRv4+ development must not break, and the test that fails when one
does.

This document is generated from `tests/security_invariants.py`, which is the
authoritative list. `tests/test_invariant_registry.py` fails if the two
disagree, if an invariant names no enforcing test, or if a named test module
does not exist. That last check exists because `VERSIONING.md` once claimed
the SMP wire byte was pinned by a test for a whole release before it actually
was, and nothing noticed: prose cannot be executed.

## How to read the status column

| Status | Meaning |
|---|---|
| `ENFORCED` | A test fails if the property is broken. |
| `PARTIAL` | Tested, but the test cannot cover the whole property. The limit is stated. |
| `INHERENT` | Guaranteed by a language or library mechanism rather than by our code, and pinned by a test asserting the mechanism is still declared. |
| `ACCEPTED` | A known limitation that cannot be fixed at this layer. The test pins the DOCUMENTATION, so the claim cannot silently strengthen. |

A `PARTIAL` or `ACCEPTED` entry with no stated limit is an `ENFORCED` claim in
disguise, and the registry test rejects it.

## The invariants

### INV-01 — SMP secrets are never at rest in plaintext.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_at_rest.py`

Sealed with AES-256-GCM under an Argon2id-derived key, AAD b'smp_secrets_v1', written 0600 via atomic replace.

### INV-02 — Account passwords are never written to disk.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_secret_at_rest.py`

Collected with getpass, held only for the connection attempt, dropped afterwards.

**Limit:** Dropping a Python str releases the reference but cannot overwrite the buffer.  See INV-14.

### INV-03 — No secret value reaches any log sink.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_log_boundary.py`

The session log is an allowlist of line shapes, not a denylist of patterns: a line is written only if it matches a known-safe form.

### INV-04 — No secret value is printed to the terminal or UI.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_never_echoes.py`, `tests/test_log_boundary.py`

### INV-05 — Secret input does not echo, and the client never promises secrecy it did not achieve.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_never_echoes.py`

termios ECHO is cleared with TCSANOW; the masking helper returns whether it took effect and the prompt wording follows that return value.

### INV-06 — No remote protocol message can arm local secret-input capture.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_no_remote_input_capture.py`

Secrets come only from an explicit local /smp-secret invocation.  There is no pending-input state machine.

### INV-07 — Rust-owned secret material zeroizes on drop.

**Status:** `INHERENT`  
**Enforced by:** `tests/test_rust_zeroization.py`

SecretBytes<N> and SecretVec derive ZeroizeOnDrop; their Debug impls print [REDACTED].

### INV-08 — Python does not receive long-lived private key material that Rust can own instead.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_release_guard.py`, `tests/test_rust_zeroization.py`

Ed448 seeds, ratchet keys and SMP scalars never cross the PyO3 boundary; the legacy getters are compiled out.

**Limit:** Voice keys ARE Python-owned (bytearray, best-effort wipe). Documented gap, SECURITY.md caveat 11.

### INV-09 — XMPP persistent identity and IRC ephemeral identity are separate stores.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_identity_and_tofu.py`, `tests/test_transport_isolation.py`

### INV-10 — An IRC run never writes identity, trust or fingerprint state to disk.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_isolation.py`

OTRConfig.persist_identity and .persist_trust default False; TrustDatabase._save returns early when not persistent.

### INV-11 — TOFU never silently re-pins a changed fingerprint.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_identity_and_tofu.py`

The mismatch branch keeps the old pin, offers no y/n, refuses voice, and requires an explicit /trust-reset.

### INV-12 — Voice is authorised by cryptographic SMP verification alone.  Display or trust state cannot unlock it.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_voice_authorization.py`

_smp_verified reads only the engine's published predicates; both the outbound and inbound call paths consult it.

### INV-13 — Rejected media is classified by cause.  A missing key, a retired epoch, a replay and a failed AEAD tag are distinguishable.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_media_reject_classification.py`

Diagnosing rekey divergence requires telling 'we have no key for this epoch' apart from 'this packet is forged'.

### INV-14 — No home-grown cryptographic construction exists where the Rust core already supplies the primitive.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_no_parallel_crypto.py`

The hand-rolled SHAKE-256 stream cipher in otrv4plus_log.py was deleted at v10.13.1.

### INV-15 — Production builds expose no debug secret getters.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_release_guard.py`

legacy-dake-keys and test-only-kdf are off by default and build.rs refuses them without an explicit env opt-in.

### INV-16 — A rekey never leaves the two peers on media key states that cannot reach each other.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_rekey_divergence.py`

A receive key is retired only once the peer has demonstrably stopped sending under it.

**Limit:** Proven against the modelled message sequences, not against live I2P.  See the rekey analysis in SECURITY.md.

## Rules that follow from these

**Before changing a security-sensitive subsystem**, search the repository for
existing implementations, tests and documentation. Afterwards, search again
for duplicates and contradictions. Both halves matter: the Argon2id-in-the-core
claim survived a documentation-synchronisation pass because the table was read
and not checked against the source.

**Do not add a cryptographic construction** where the Rust core already
supplies the primitive (INV-14). The last one to try was a SHAKE-256 keystream
cipher in `otrv4plus_log.py`; it was deleted rather than re-based, because the
module did not need to encrypt anything.

**Do not let remote input decide what local input means** (INV-06). A peer
choosing when a prompt appears is a peer choosing what the user's next
keystroke does.

**Fail closed.** A failure to determine SMP state does not authorise a call
(INV-12). An unrecognised log line is not written (INV-03). A rekey that
cannot complete leaves the committed epoch alone (INV-16).

**Do not claim more than the implementation provides.** At-rest protection for
the identity, the SMP secrets and the device seeds is filesystem permissions,
not cryptography: an attacker who can read the home directory can read all of
them. Python `str` cannot be zeroized. Voice key material is Python-owned and
wiped best-effort. All three are recorded in `SECURITY.md`, and the tests pin
those statements so they cannot quietly become stronger.
