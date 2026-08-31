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
**Enforced by:** `tests/test_release_guard.py`, `tests/test_rust_zeroization.py`, `tests/test_voice_rust_parity.py`

Ed448 seeds, ratchet keys, SMP scalars and -- since v10.13.2 -- voice media keys, the voice epoch root and the voice X448 scalar never cross the PyO3 boundary; the legacy getters are compiled out.

**Limit:** The typed SMP passphrase and the account password are Python `str` before anything can touch them, and a `str` cannot be wiped.  The identity DEK and the device seeds are Python `bytes` read from disk.  Everything derived from them is Rust-owned.

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

### INV-17 — A transport failure or degradation never selects a less private transport.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_failclosed.py`, `tests/test_transport_policy.py`

Selection is by address suffix or explicit flag, checked before connecting, and contradictory flags exit rather than guess.  There is no fallback ladder and no latency-triggered switch: I2P that cannot carry a call means no call.

### INV-18 — The transport class is fixed for the lifetime of a call.  An endpoint may change within a class if the change is authenticated; a class change requires ending the call.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_transport_policy.py`

MEDIAPATH moves the media endpoint within the I2P class, authenticated from the committed epoch root -- which is what recovered the Wi-Fi-to-mobile transition.  The forbidden transitions are I2P->TLS, Tor->TLS and TLS->I2P; the matrix is an allowlist.

**Limit:** Enforced today by there being exactly one media transport class, so no cross-class transition is reachable.  The structural guarantee -- binding TransportClass into the voice transcript so a mismatched pair never keys -- is specified in TRANSPORT_POLICY.md section 5 and deferred until the I2P voice and rekey work completes live-device validation.

### INV-19 — A proxy route is never presented as anonymity, and a clearnet transport is never described as weak encryption.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_policy.py`

Encryption, anonymity and routing are three properties, not three points on one scale.  A proxy is routing: the operator can log, identify, inject or be compromised.  Clearnet TLS 1.3 is strong encryption with no anonymity, and calling it 'less secure' teaches the wrong lesson.

## Where secrets live

Updated at v10.13.2, when the voice path finished moving.

| Material | Owner | Representation | Wipeable |
|---|---|---|---|
| Ratchet root / chain keys | Rust | `SecretBytes<32>` | yes, on drop |
| DAKE session keys | Rust | opaque `DakeOutput` | yes, on drop |
| SMP secret scalar | Rust | `SecretVec` | yes, on drop |
| Ed448 identity seed | Rust | `SecretBytes<57>` | yes, on drop |
| Voice epoch root | Rust | `SecretBytes<64>` | yes, on drop |
| Voice media keys | Rust | `SecretBytes<32>` | yes, on drop |
| Voice X448 private scalar | Rust | `SecretBytes<56>` | yes, on drop |
| X448 / ML-KEM shared secrets | Python → Rust | `bytearray`, wiped by Rust | yes |
| SMP passphrase (typed) | Python → Rust | `str` → `bytearray` → Rust | the `str` cannot be |
| Account password | Python | `str` | **no** |
| Identity DEK, device seeds | Python | `bytes` from disk | **no** |

The remaining Python rows are not oversights. The account password must be a
`str` because slixmpp's SASL path requires one; the typed passphrase is a
`str` before anything else can touch it; the DEK and seeds are read from
files. Everything *derived* from them is Rust-owned, and
`tests/test_secret_at_rest.py` pins those statements so they cannot quietly
become claims.

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

**A differential test must not compare an implementation with itself.** When
`VoiceFrameCrypto` began delegating to Rust, the parity test that had caught a
wrong length prefix started comparing Rust against Rust and a reintroduced bug
passed clean. Reference implementations in tests are built from primitives,
not imported from the module under test.

**Prove a secret changed without reading it.** Tests that used to compare
epoch roots byte for byte now compare the confirmation pair, which is a
deterministic function of the root and travels on the wire anyway. Where that
is not possible, assert the observable consequence — two calls that share a
media key produce identical ciphertext for identical plaintext.

**Encryption, anonymity and routing are three properties** (INV-19). A proxy
is routing: it moves who-sees-what, it does not remove it, and the operator can
log, identify, inject or be compromised. Clearnet TLS 1.3 is strong encryption
with no anonymity — calling it "less secure" is wrong and teaches the wrong
lesson. [TRANSPORT_POLICY.md](TRANSPORT_POLICY.md) holds the full policy,
including the transition matrix and the two fallback sequences that must never
exist.

**Fail closed.** A failure to determine SMP state does not authorise a call
(INV-12). An unrecognised log line is not written (INV-03). A rekey that
cannot complete leaves the committed epoch alone (INV-16). A missing
`RustVoiceCipher` means no voice rather than a Python fallback.

**Do not claim more than the implementation provides.** At-rest protection for
the identity, the SMP secrets and the device seeds is filesystem permissions,
not cryptography: an attacker who can read the home directory can read all of
them. Rust ownership does not defend against a compromised kernel, root-level
malware, or an unlocked device — it stops keys outliving their use and being
reachable by ordinary introspection, which is a narrower and real thing.
