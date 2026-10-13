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
| L1 | MAC-key revelation reveals all-zeros; deniability not achieved | Design | **OPEN (claim only)** -- the all-zeros mechanism is fixed and proven end to end (`tests/test_mac_revelation_end_to_end.py`: the published key re-MACs a forgery of the real message). What stays open is the *formal* deniability claim, which needs expert review; do not claim it. Re-checked 2026-09-28. |
| M3 | Legacy DAKE path can hand session keys to Python as PyBytes | Medium | **RESOLVED** |
| G1 | `RustDAKEAdapter.is_expired()` is a stub; DAKE handshake timeout absent | Low | **OPEN** |
| G2 | Two divergent copies of `otrv4_testlib.py`; which loads depends on collection order | Low | **OPEN** |
| B1-seed | Persisting an identity requires the seed to exist in Python | Design | **RESOLVED** |
| A1 | Ratchet brace key is never folded into root/chain keys (SPEC §5.2 not implemented): no post-quantum post-compromise recovery | Design / High (spec divergence) | **OPEN** -- pinned by `ratchet::audit_brace_folding`; needs a versioned protocol change. See CRYPTO_AUDIT_2026-09.md |
| A2 | DAKE post-quantum authentication is initiator-only and strippable by an active quantum adversary | Design / Medium | **OPEN** -- documented, SPEC §4.3; needs a protocol version |
| A3 | Crafted `.otrv` header overflowed `8 * p` before bounding p: process abort (overflow-checks + panic=abort) | Medium (DoS) | **RESOLVED** -- `container::tests::a_huge_lane_count_is_refused_not_an_overflow`; found by `fuzz/container_header` |
| A4 | Ring verifier accepted the identity point as a ring member (signable by anyone) | Low | **RESOLVED** -- `ring_sig::audit_identity_point` |
| A5 | Profile expiry and degenerate identity key enforced only in Python | Low | **RESOLVED** -- `dake::profile_tests` |
| A6 | Ring signature scalars reduced mod Q, so every signature had malleable re-encodings | Low / Info | **RESOLVED** -- `ring_sig::audit_identity_point::a_non_canonical_scalar_is_refused` |
| X1 | With TLS certificate checks off (I2P, .onion), a server reached by a human-readable `.i2p` NAME is bound only by the router's address book; a substituted server can offer only SASL PLAIN and capture the XMPP account password | Medium | **RESOLVED (Android), with stated residuals** -- both options, combined: the resolved destination is pinned per server name and a changed one is refused before STREAM CONNECT (nothing reaches it; explicit, confirmed re-approval of exactly that destination), and SASL is SCRAM-only wherever certificate checks are off. `tests/test_x1_destination_pinning.py`. Residuals and the terminal client: see the X1 section. NOT yet confirmed by a handset login |

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

**Now in use beyond Android (v10.12.0).** The XMPP client persists its
identity through this same mechanism via `otrv4plus_identity.py`, so the
seed stays inside Rust on Termux too. What differs from the Android design
is key custody: the DEK is a 0600 file rather than a Keystore-wrapped key,
so the at-rest protection there is filesystem permissions. IRC persists no
identity at all and is unaffected.

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

---

## X1 — Password to a substituted `.i2p` server

**Status: RESOLVED on Android (2026-09-28), with the residuals below. Not yet
exercised by a handset login (PHYSICAL_TEST_PLAN.md §0).**

### The defect

A short `.i2p` name is bound to a destination by the router's address book,
which a subscription feed, a jump service or a first registrant can
influence. Over I2P the transport turns TLS certificate checks off, because
there is no CA for `.i2p`. The client then authenticated with whatever SASL
mechanism the server offered -- including PLAIN, which is the password
itself. A substituted destination therefore collected the account password.
Message content was never exposed (DAKE-authenticated, TOFU-pinned end to end).

### The fix: both options, combined

**B. Destination pinning** (`android_bridge/server_pins.py`). The identity of
an I2P server is its destination -- the `.b32.i2p` hash of the full
destination the router returned -- never its name.

* The first destination a name resolves to is pinned when that connection
  (or registration) succeeds: trust on first use.
* Every later attempt is checked inside the SAM connect, between `NAMING
  LOOKUP` and `SESSION CREATE` (`I2PSAMConnection.connect(verify_destination=)`).
  A different destination raises before any session or stream exists, so
  **not one byte -- no credential -- reaches it**. The failure is
  `i2p_destination_changed` (registration: `server_identity_changed`) and
  names both addresses.
* Nothing retries it in the background (`ReconnectPolicy.NEEDS_THE_USER`).
  The connect screen shows a security warning with both addresses; "Trust new
  address" needs a second confirmation, approves only the destination that
  was refused, and does not connect -- the user logs in again, and the new
  destination becomes the pin only if that succeeds.
* A typed `.b32.i2p` is checked against the destination the router returns
  for it. `.onion` v3 names are self-authenticating and not pinned.
* Pins are public data (names and hashes), stored at
  `~/.otrv4plus/server_pins.json` (0600) and destroyed by Wipe & Exit.
* The transport refuses a forwarder that cannot run the check.

**A. SCRAM only where certificate checks are off**
(`transport._restrict_to_scram`). slixmpp's `feature_mechanisms` is limited to
SCRAM-SHA-512/256/1 (with and without -PLUS); `encrypted_plain` and
`unencrypted_plain` are off. Verified on the wire against the real slixmpp
1.17 plugin: a server offering only PLAIN (or LOGIN, DIGEST-MD5) gets no
`<auth>` at all and the attempt fails as `no_safe_auth_mechanism`; with SCRAM
offered, the first message carries `n=<user>,r=<nonce>` and never the
password. slixmpp also refuses SCRAM on a stream without TLS, so an I2P
server that skips STARTTLS gets nothing. SCRAM is mutual: a server that does
not hold the credential cannot complete it.

Clearnet (`clearnet_tls`) keeps slixmpp's default: CA-verified certificate,
hostname checked; PLAIN is allowed only inside that verified TLS, and the
transport refuses to send a password or a registration form if TLS was not
negotiated (`tls_required`).

### Residual risks, stated

1. **First contact is trust-on-first-use.** If the very first resolution of a
   name is already substituted, that destination is pinned. Layer A then
   still keeps the password off the wire, but:
2. **A SCRAM exchange with an impostor permits an offline guessing attack**
   on a weak password: the impostor picks the salt and iteration count and
   receives the client proof, against which it can test guesses offline. It
   never receives the password itself. Use a strong, unique password.
3. **Registration over I2P on first contact** sends the NEW account's
   password inside the XEP-0077 form over TLS to an unpinned destination.
   After the first success the destination is pinned and later
   registrations are protected.
4. **The terminal client** (`otrv4plus_xmpp.py`) still accepts whatever the
   server offers. It is outside this fix; use a `.b32.i2p` address there.

### Tests

`tests/test_x1_destination_pinning.py` runs the real forwarder and the real
`I2PSAMConnection` against a scripted SAM bridge that plays the XMPP server
at each destination and records every byte: first use pins A; reconnect to
A is allowed; after the name is re-pointed at B the attempt is refused, no
`SESSION CREATE` or `STREAM CONNECT` follows the lookup, B receives zero
bytes and the password never reaches it; registration is blocked the same
way; approval is only for the refused destination and does not re-pin until
a successful connect; the SCRAM restriction is checked on the real slixmpp
plugin. Disabling either layer fails 15 of those tests (checked by mutation
on 2026-09-28). `ReconnectPolicyTest` pins that the refusal is not retried.

