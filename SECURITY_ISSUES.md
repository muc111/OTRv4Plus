# Tracked security issues

Open issues carried by the OTRv4+ codebase, with current behaviour, impact, and
what would resolve each. This file exists so that known gaps stay visible
instead of being rediscovered, and so that no gap is described as fixed until a
regression test demonstrates it.

Status vocabulary:

- **OPEN** — present in the shipped code, not remediated.
- **MITIGATED** — cannot currently be reached, but the underlying code remains.
- **RESOLVED** — fixed, with a regression test named here.

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| L1 | MAC-key revelation reveals all-zeros; deniability not achieved | Design | **OPEN** |
| M3 | Legacy DAKE path can hand session keys to Python as PyBytes | Medium | **RESOLVED** |
| G1 | `RustDAKEAdapter.is_expired()` is a stub; DAKE handshake timeout absent | Low | **OPEN** |
| G2 | Two divergent copies of `otrv4_testlib.py`; which loads depends on collection order | Low | **OPEN** |
| B1-seed | Persisting an identity requires the seed to exist in Python | Design | **RESOLVED** |

---

## L1 — MAC-key revelation reveals all-zeros

**Status: OPEN. Do not claim deniability.**

### Current behaviour

OTR's published design has a participant reveal old MAC keys once they can no
longer be used to authenticate anything. Once revealed, any third party could
have forged a transcript with them, so a transcript stops being evidence of who
said what. That is the mechanism behind OTR's deniability property.

In this codebase the revelation machinery is present in the wire format —
`OTRv4DataMessage` carries a `revealed_mac_keys` list, encoded with a length
prefix and decoded on receipt (`otrv4+.py`, `compute_mac` / `verify_mac`
region) — but what gets revealed is all-zeros rather than the real prior MAC
keys. The prior audit recorded this as item L1 and classified it as a design
decision awaiting a call.

### Expected OTR behaviour

Old MAC keys, once retired, are published so that forgery by a third party
becomes possible and the transcript loses evidentiary value.

### Impact

The **deniability** property is not achieved. Nothing else is weakened:
confidentiality, integrity, forward secrecy, post-compromise security and
authentication are unaffected, because none of them depends on revelation.

The practical risk is therefore not cryptographic but representational — a
claim of deniability in product or marketing material would be false. Note that
the ring signature *does* provide participation deniability for the handshake
(a 1-of-2 OR proof: either ring member could have produced it). Transcript
deniability for message MACs is the part that is missing. Conflating the two
would be an easy and material mistake.

### Reproduction

```python
# Complete a DAKE, exchange enough messages to retire a MAC key, then inspect
# the revealed_mac_keys field of an outgoing data message.
# Observed: the entry is all-zero bytes rather than a prior MAC key.
```

A proper regression test must assert that a revealed key **verifies a prior
message's MAC** — not merely that the field is non-zero, which a placeholder
would also satisfy.

### Relevant code paths

- `otrv4+.py` — `OTRv4DataMessage.revealed_mac_keys`, its encode/decode, and
  `compute_mac` / `verify_mac`.
- `Rust/src/kdf.rs` — `hmac_sha3_512`, `verify_mac`.
- `Rust/src/ratchet.rs` — where retired MAC keys would be collected.

### Proposed remediation

Not scheduled, and deliberately not attempted during Phase 2 — a speculative
change here risks revealing a key that is still live, which would be far worse
than the current state. Resolving it needs:

1. A decision on whether deniability is a product goal at all.
2. If yes: define precisely when a MAC key is retired (it must be
   unambiguously unusable for authentication before it is published).
3. Collect retired keys in the Rust ratchet, which owns their lifetime.
4. Reveal them in the existing wire field.
5. A regression test proving a revealed key verifies an old MAC, plus one
   proving no key is ever revealed while still in use.
6. Re-check the interaction with skipped-message-key retention across a DH
   ratchet (prior audit items L2/L3).

### Until then

Do not describe the product as offering deniable messaging. "Participation
deniability in the handshake via a ring signature" is accurate and is a
different claim.

---

## M3 — Legacy DAKE path can hand session keys to Python

**Status: RESOLVED. Compiled out of production builds.**

Regression tests: `tests/test_release_guard.py::test_production_artifact_exposes_no_legacy_dake_session_keys`
and `::test_production_dakeresult_exposes_no_secret_getters`.

The five `Dakeresult` secret getters and `PyDake::generate_dake2` /
`process_dake2` / `get_session_keys` are behind the `legacy-dake-keys` Cargo
feature, OFF by default. They are **absent from a production artifact**, not
merely undocumented. `Rust/build.rs` refuses to build with the feature unless
`OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1` is set explicitly. The live DAKE
implementation is unchanged — `generate_dake2_output` / `process_dake2_output`
use a different internal path and were not touched.

Verified across three wheels: production (guard passes), legacy without opt-in
(guard **fails**, catching the surface), legacy with opt-in (passes).

The original analysis, retained for the record:

### What exists

`Rust/src/dake.rs` exposes `PyDakeSessionKeys` with PyBytes getters for
`root_key`, `chain_key_a`, `chain_key_b`, `brace_key` and `mac_key`, reachable
through `PyDake.get_session_keys()` and the legacy `generate_dake2` /
`process_dake2`. The safe path — `generate_dake2_output` / `process_dake2_output`
— returns an opaque `DakeOutput` whose keys move Rust-to-Rust via
`consume_into_ratchet()` and never become PyBytes.

### Every caller, checked

Production Python calls `RustDAKEAdapter.generate_dake2` / `process_dake2`
(`otrv4+.py`), each of which runtime-feature-detects:

```python
use_output_api = hasattr(self._rust, "generate_dake2_output")
if use_output_api:
    ...                      # opaque DakeOutput; no key bytes
else:
    result = self._rust.generate_dake2(...)
    self._session_keys = self._unpack_session_keys(result, ...)   # PyBytes
```

`_unpack_session_keys` is the only code that reads those getters. The
`hasattr` check that guards it **cannot be false in any importable build**:
`_check_rust_requirements()` (`otrv4+.py:70`) raises `ImportError` at import
time unless both `generate_dake2_output` and `process_dake2_output` are present
on `RustDAKE`. A build missing them cannot get far enough to reach the fallback.

The legacy branch is therefore **dead code on the live path**, confirmed by
reading the gate rather than inferred.

Outside production, the only callers were `tests/test_attacks.py` and
`tests/test_otrv4_integration.py`, both of which have been migrated (see
`tests/test_otrv4_integration.py::test_04/05/06`, which now assert the opposite
property: that `brace_key`, `root_key`, `chain_key_*` and `mac_key` are *absent*
from the session-keys dict).

### Does Android require it?

No. `android_bridge/app.py` never touches session keys; the bridge's contract
is that no secret crosses into Kotlin, and a test asserts `OtrApp` exposes no
key-shaped accessor.

### Does it expose secrets across the boundary?

Only if executed, which it cannot be. The hazard is latent rather than live: a
future refactor that relaxed the import gate, or added a caller, would silently
re-open a PyBytes path for root and chain keys.

### Disposition

**Recommend (B): gate the legacy entry points behind an explicit test-only
Cargo feature**, reusing the `test-only-kdf` mechanism now enforced by
`Rust/build.rs`, so a production build cannot compile them at all.

Rationale for B over the alternatives:

- **(A) remove outright** — cleanest, but `generate_dake2`/`process_dake2` are
  also the only DAKE entry points some Rust-side tests use, and deleting them
  is a larger change than Phase 2 should make to the crypto core.
- **(C) replace with opaque handles** — already done; `*_output` is that
  replacement. Nothing further to build.

Not executed in Phase 2 because it touches `dake.rs`, and the phase brief
requires the disposition to be documented and agreed rather than applied
unilaterally. It is a small, self-contained change once approved.

---

## G1 — DAKE handshake timeout is a stub

**Status: OPEN. Latent, not live.**

`RustDAKEAdapter.is_expired()` unconditionally returns `False`. The `timeout`
attribute callers may set is never read, and `UIConstants.DAKE_TIMEOUT = 120.0`
is defined but referenced nowhere in the codebase. The pure-Python `OTRv4DAKE`
that carried this mechanism was deleted at v10.7 and the behaviour was not
carried over.

**Impact today is nil**: `is_expired()` has no production callers. The separate
`is_session_expired()` — age of an *established* session — is implemented
correctly and is called (`otrv4+.py:5825`).

The hazard is that a future caller gets a silent "never expired". A half-open
DAKE would then be retained indefinitely, which on a mobile client is a
resource-exhaustion concern rather than a confidentiality one.

Tracked visibly as an expected failure:
`tests/test_otrv4_integration.py::test_08_dake_timeout`. It is marked
`@unittest.expectedFailure` with the reasoning inline, so the gap shows up in
every test run instead of being deleted.

Implementing it is a behaviour change and needs sign-off; it was deliberately
not done as part of a test repair.

---

## G2 — Two divergent copies of `otrv4_testlib.py`

**Status: OPEN. Test-harness integrity.**

`otrv4_testlib.py` exists in both the project root and `tests/`, with
substantially different implementations (~286 differing lines; the root version
uses `_SMPMathStub` classes patched into the namespace, the `tests/` version
defines `SMPMath` directly).

Which one a test imports **depends on collection order**: `tests/conftest.py`
puts the project root ahead of `tests/` on `sys.path`, but
`tests/test_attacks.py` front-loads `tests/` at import time. So a single-file
run and a full-suite run can load different code.

This was found because a repair applied to one copy appeared to work in
isolation and failed in the full suite. It is a correctness hazard for the test
suite rather than for the product.

**Interim mitigation:** the v10.7 migration helper block is kept byte-identical
in both copies, so the suite is deterministic either way.

**Proposed fix:** make one canonical and have the other re-export it, or delete
the unused copy after confirming which symbols each provides. Deferred because
unifying them is a larger change than a test repair should carry, and the two
implementations are not trivially interchangeable.

---

## B1-seed — Persisting an identity requires the seed in Python

**Status: RESOLVED. Option B implemented — sealing happens inside Rust.**

Regression tests: `tests/test_rust_identity_sealing.py` (35 tests covering all
nine required proofs).

`Rust/src/identity.rs` seals and unseals the identity using the crate-internal
accessors, so only ciphertext crosses into Python. No `get_seed()` accessor was
added. Writing the proofs found that PyO3 keeps a `#[staticmethod]`
Python-visible regardless of `pub(crate)`, so `from_seed_bytes` was still a seed
*injection* path; it and `from_priv_bytes` are now behind `test-only-kdf`, and
`identity.rs` uses `from_seed_internal` / `from_priv_internal`, which are not
PyO3 methods at all.

Residual, recorded rather than glossed: the DEK itself is still a Python `bytes`
because the provider hands it down to Rust. The **seed** is not, which is what
the decision required. Phase 4 should shorten that path by passing the unwrapped
DEK straight from Kotlin into Rust over JNI.

The original analysis, retained for the record:

Decision B1 (persistent identity) is approved, but there is a boundary in the
way:

`generate_ed448_keypair()` creates the seed **inside Rust** and there is no
PyO3 accessor that returns it — `expose_seed_slice()` is `pub(crate)`. An
identity generated the production way therefore cannot be persisted at all. The
only reconstruction path is `Ed448KeyHandle.from_seed_bytes(seed)`, whose own
docstring describes itself as "test/internal use; production calls
`generate_ed448_keypair` instead so the seed is never observed from Python at
all."

**Option A — generate the seed in Python**, seal it, reconstruct via
`from_seed_bytes`. No Rust change; works today. Costs the documented property
that private key bytes never appear on the Python heap: the seed is a Python
object at creation and again at every load, and CPython offers no reliable
zeroization for it.

**Option B — seal and unseal inside Rust.** An additive `storage.rs` exposing
`seal_ed448_handle(handle, dek) -> bytes` and
`unseal_ed448_handle(blob, dek) -> Ed448KeyHandle`. Only ciphertext crosses the
boundary; the seed never enters Python. Uses the existing AES-256-GCM and
`SecretBytes` — no new primitive. This is what the Phase 1 report proposed.

**Recommendation: B.** It preserves the boundary that is the codebase's main
structural security claim, and the additional work is small and additive.

`android_bridge/identity.py` is written so this is a swap: `IdentityKeyStore`
is the interface, and the package ships no concrete implementation. The test
double in `tests/test_android_identity.py` uses Option A and is explicitly
marked development/test only.
