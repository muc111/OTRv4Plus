# OTRv4+ Changelog

## v10.6.2 — Rust DAKE end-to-end correctness

This release makes the Rust DAKE path functional with real peers for the
first time.  Prior versions (v10.6.0 / v10.6.1) shipped the Rust DAKE PyO3
wrapper but it was effectively unreachable in production: the constructor's
expected signature did not match what the Python adapter passed, and even
when the Rust path was reached, four distinct crypto bugs prevented MAC
verification from ever succeeding with a real peer.

All v10.6.0 and v10.6.1 audit fixes (Patch 1 and Patch 2) remain in place
unchanged.  This release adds **correctness** for the Rust DAKE; it does
not weaken any previously-implemented hardening.

### Bug 1 — `pqcrypto_kyber::kyber1024::encapsulate` return tuple order

```rust
// BEFORE — wrong destructuring order:
let (ct, ss) = pqcrypto_kyber::kyber1024::encapsulate(&pk);
Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
```

The `pqcrypto-kyber` API actually returns `(SharedSecret, Ciphertext)`,
not `(Ciphertext, SharedSecret)`.  The destructuring put the 32-byte
shared secret into the variable named `ct` and the 1568-byte ciphertext
into the variable named `ss`.  Net effect:

- DAKE2 wire shipped 32 bytes where 1568 were expected — peer's parser
  failed with "Invalid wire format" the moment it tried to read the
  MLKEM ciphertext slot.
- Locally, the KDF mixing fed the 1568-byte ciphertext bytes into the
  shared-secret slot, so even if wire format had matched, MAC would
  have failed.

**Fix:** explicit re-bind: `let (ss, ct) = ...` then return
`(ct.as_bytes()..., ss.as_bytes()...)`.  Wire CT is now 1568 bytes, KDF
receives the correct 32-byte shared secret.

### Bug 2 — MAC input did not cover the wire it was protecting

Responder's `generate_dake2` MACed over
`(transcript || eph_pub || mlkem_ct || profile)`.

Initiator's `process_dake2` MACed over `data[..off]` — the full wire
body up to but excluding the MAC.  That includes `MSG_DAKE2` (1 byte)
and the optional ML-DSA-87 public key (2592 bytes), neither of which
the responder included in its MAC.

**Fix:** responder now builds `wire_body` first (msg type + eph_pub +
ct + profile + optional ml-dsa pub) and HMACs over the *exact* bytes
that will be transmitted.  Symmetric with the verifier.

### Bug 3 — Initiator DH triples paired with the wrong slots

X448 commutativity requires per-position matching between responder's
and initiator's `(dh1, dh2, dh3)` tuples:

```
Responder side          | Initiator side             | Match
dh1: R.eph × I.eph_pub  | dh1: I.eph × R.eph_pub     | ✓ same value
dh2: R.eph × I.prekey   | dh2: I.prekey × R.eph_pub  | ✓ commute
dh3: R.prekey × I.eph   | dh3: I.eph × R.prekey_pub  | ✓ commute
```

Initiator's `process_dake2` previously computed `dh2` and `dh3` both as
`our_prekey_priv × peer_eph_pub` (identical computations, in the wrong
slots).  This produced a different mixed-secret than the responder and a
different MAC key.

**Fix:** initiator's DH triple now matches the responder by position:

```rust
let dh1 = our_eph_priv    × peer_eph_pub;
let dh2 = our_prekey_priv × peer_eph_pub;     // ← matches resp.dh2
let dh3 = our_eph_priv    × peer_prekey_pub;  // ← matches resp.dh3
```

Required `peer_profile_bytes` to be stored *before* DH computation so
`peer_prekey_pub()` can read the responder's prekey from their profile.
Now stored at parse time, with reset-on-MAC-failure to avoid stale state
in retry scenarios.

### Bug 4 — Adapter passed PUBLIC keys where Rust expected PRIVATE

`RustDAKEAdapter.__init__` in `otrv4+.py` constructed `RustDAKE` with:

```python
_ik_bytes     = self.client_profile.identity_pub_bytes   # public bytes
_prekey_bytes = self.client_profile.prekey_pub_bytes     # public bytes
self._rust = _RustDAKE(explicit_initiator, _profile_bytes,
                       _ik_bytes, _prekey_bytes)
```

`PyDake::new` in `dake.rs` declares these parameters as the 57-byte Ed448
identity *private* seed and the 56-byte X448 *private* scalar (and uses
them for X448 DH later).  Ed448 public keys are also 57 bytes and X448
public keys are also 56 bytes, so `<[u8; N]>::try_into()` did not fail.
Rust silently used the public keys as private scalars.  Every X448 DH
operation produced garbage shared secrets.

**Fix:** adapter now extracts the actual raw private bytes:

```python
_ik_priv_bytes = self.client_profile.identity_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
_prekey_priv_bytes = self.client_profile.prekey.private_bytes(...)
```

Sizes are sanity-checked (57 / 56) before crossing the FFI boundary.
The same `client_profile.identity_key` / `client_profile.prekey` objects
provide both the public (sent on the wire via `encode()`) and private
(passed to Rust) bytes, so the keypair invariant holds.

### Bug 5 (UX, not crypto) — 401 handler tore down sessions mid-DAKE

`ERR_NOSUCHNICK` (IRC numeric 401) was being treated as a fatal
session-ending event on first occurrence.  On I2P, peer nicks routinely
blink in and out of the server's view during the ~30-second multi-
fragment DAKE handshake.  The handler was killing the session before
DAKE2 could possibly arrive.

**Fix:** during `DAKE_IN_PROGRESS` / `PLAINTEXT` / `CREATED` states, 401
is now soft-ignored (logged at debug level) unless **5 consecutive** 401s
arrive without intervening OTR traffic from the peer.  Any OTR fragment
received from the peer resets the counter — proof of life.  Once the
session is past DAKE (`ENCRYPTED` or further), 401 is treated as a real
disconnect on first occurrence (existing behaviour for established
sessions, unchanged).

### Misc

- Startup banner now shows `SMP : 🦀 Rust (ZeroizeOnDrop, 50k-round
  KDF)` alongside the existing `Ratchet` and `DAKE` lines.  The
  in-session banner already showed this; the startup banner did not.

### Build-process note (read this if you maintain a fork)

A significant portion of the development time spent on this release was
debugging a phantom: cargo's incremental build was not picking up source
changes to `dake.rs`, and the deployed `.so` was running stale code while
the source had the fixes.  If you change Rust source and see no apparent
change in runtime behaviour:

```bash
cd Rust && cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so
strings ../otrv4_core.so | grep -c "<unique marker from your change>"
```

`cargo clean` is the reliable way to force a full rebuild when in doubt.
A unique string marker in your change (a comment or panic message) and
`strings` to confirm it landed in the binary is the only reliable
verification that a deployed `.so` actually contains your edits.

### Files changed

| File | Change |
|---|---|
| `Rust/src/dake.rs` | MLKEM tuple swap |
| `Rust/src/dake.rs` | `generate_dake2` MACs over `wire_body` |
| `Rust/src/dake.rs` | `process_dake2` stores `peer_profile_bytes` pre-DH, resets on MAC fail |
| `Rust/src/dake.rs` | `process_dake2` corrected DH triple pairing |
| `otrv4+.py` | `RustDAKEAdapter.__init__` passes private key bytes |
| `otrv4+.py` | 401 handler soft during DAKE handshake |
| `otrv4+.py` | 401 counter reset on observed peer OTR traffic |
| `otrv4+.py` | Startup banner SMP line added |

### Files NOT changed in this release

| File | Reason |
|---|---|
| `Cargo.toml` | v10.6.0 `panic = "unwind"` + `test-only-kdf` feature flag intact |
| `Rust/src/error.rs` | v10.6.0 `SafeSlice`, `try_slice`, `try_byte`, `Internal(&'static str)` intact |
| `Rust/src/header.rs` | v10.6.0 bounds-checking intact |
| `Rust/src/kdf.rs` | v10.6.0 `kdf_1_py` test-only gating intact |
| `Rust/src/ratchet.rs` | v10.6.1 `from_dakeresult` aggressive-zero, no brace_key getter, panic-safe — intact |
| `Rust/src/smp.rs` | v10.6.1 `set_secret_from_bytearray` Rust-side wipe + `Dakeresult.consumed` enforcement — intact |
| `Rust/src/smp_vault.rs` | v10.6.0 `load*` gated behind `test-only-kdf` intact |
| `Rust/src/secure_mem.rs` | ZeroizeOnDrop, no `unsafe`, `ct_eq` via subtle — intact |
| C extensions | OPENSSL_cleanse, BN_mod_exp_mont_consttime, constant-time Ed448 — intact |

---

## Audit status at v10.6.2

The audit work shipped in v10.6.0 and v10.6.1 is unchanged.  Below is the
honest status of each audit finding after this release.

| Audit ID | Description | Status |
|---|---|---|
| **C1** | Test-only API `RustSMPVault::load*` exposed in production | ✅ Fixed v10.6.0 (gated behind `test-only-kdf`) |
| **C2** | `Dakeresult` exposes session keys as `Vec<u8>` `#[pyo3(get,set)]` | ⚠️ **Partial**: v10.6.1 `consumed` flag + aggressive zero + post-consumption getter rejection.  Full close requires `DakeOutput` opaque handle — see ROADMAP Phase 4 |
| **C3** | `process_dh_message` returns secrets to Python | ⚠️ Same as C2 — partial mitigation via consume-pattern in `RustDoubleRatchet`.  Full close in Phase 4 |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter leaks brace key | ✅ Fixed v10.6.0 (getter removed) |
| **C5** | SMP passphrase enters Python `bytes` during `set_secret` | ✅ Fixed v10.6.1 (`set_secret_from_bytearray` + Rust-side wipe) |
| **C6** | Rust DAKE end-to-end correctness (the four bugs) | ✅ Fixed v10.6.2 (this release) |
| **P3** | `panic = "abort"` breaks FFI panic safety | ✅ Fixed v10.6.0 (`unwind` + `try_slice` + `Internal(&'static str)`) |
| **V1-V3** | Wire decoders did not bounds-check before slicing | ✅ Fixed v10.6.0 (`SafeSlice`, `MAX_WIRE_FIELD_LEN`) |
| **M1** | `kdf_1` PyO3 export | ✅ Fixed v10.6.0 (`kdf_1_py` test-only) |
| **M2** | `encode_header` PyO3 export | ✅ Fixed v10.6.0 (`encode_header_py` test-only) |

**Net: 9 of 11 findings fully closed.  2 partially mitigated (C2, C3 —
see ROADMAP Phase 4).**

---

## Commit message for this push

```
v10.6.2 — Rust DAKE end-to-end correctness (the four bugs)

The Rust DAKE wrapper shipped in v10.6.0 / v10.6.1 was effectively
unreachable in production: constructor signature mismatches forced
fallback to Python OTRv4DAKE on every session, and four distinct
crypto bugs prevented MAC verification from succeeding even when the
Rust path was reached.

Bug 1 (dake.rs):    pqcrypto_kyber::encapsulate returns (SharedSecret,
                    Ciphertext) not (Ciphertext, SharedSecret).  Tuple
                    destructuring was reversed; wire shipped 32-byte SS
                    where 1568-byte CT was expected, KDF received
                    1568-byte CT where 32-byte SS was expected.

Bug 2 (dake.rs):    Responder MAC input did not include MSG_DAKE2 byte
                    or ML-DSA pub.  Parser MACs over data[..off] which
                    does include them.  Generator now MACs over
                    wire_body — the exact bytes that go on the wire,
                    sans MAC trailer.

Bug 3 (dake.rs):    Initiator dh2 and dh3 were identical computations
                    (both our_prekey_priv × peer_eph_pub) instead of
                    matching the responder's positional pairing by
                    X448 commutativity.  Fixed to:
                        dh1 = our_eph    × peer_eph
                        dh2 = our_prekey × peer_eph
                        dh3 = our_eph    × peer_prekey
                    peer_profile now stored pre-DH so peer_prekey_pub()
                    can read it; cleared on MAC failure.

Bug 4 (otrv4+.py):  RustDAKEAdapter passed identity_pub_bytes and
                    prekey_pub_bytes (public keys) where the Rust
                    constructor expected private bytes.  Same length
                    (57, 56), so type cast did not fail.  All X448 DH
                    operations produced garbage shared secrets.  Now
                    extracts raw private bytes from cryptography
                    library PrivateKey objects via
                    .private_bytes(Raw, Raw, NoEncryption()).

Bug 5 (otrv4+.py):  ERR_NOSUCHNICK (401) handler killed sessions on
                    first occurrence during multi-fragment DAKE.  Now
                    soft-ignored during DAKE handshake unless 5 in a
                    row without peer OTR traffic.

Misc: startup banner now shows SMP : 🦀 Rust alongside Ratchet and
DAKE.  In-session banner already did.

Audit status: v10.6.0 / v10.6.1 hardening preserved unchanged.  Adds
C6 (end-to-end DAKE correctness) to the closed-finding list.  C2 and
C3 remain partial pending Phase 4 (DakeOutput opaque handle).

Build hygiene note: cargo's incremental build can silently skip
rebuilding when source files change.  Always use `cargo clean` after
non-trivial dake.rs / ratchet.rs / smp.rs edits.  Verify the deployed
.so contains your change with `strings otrv4_core.so | grep <marker>`.
```

---

## Earlier releases (summary)

### v10.6.1 — Boundary hardening Patch 2

`Dakeresult.consumed` flag; aggressive zero (`clear()` + `shrink_to_fit()`)
in `from_dakeresult`; Rust-side bytearray wipe in `set_secret_from_bytearray`;
PyO3 0.21 `Bound<...>` migration; defensive precondition checks.

See MIGRATION.md Section 2 "Patch 2" for detail.

### v10.6.0 — Audit Patch 1

`set_secret_from_bytearray`, `from_dakeresult` (move + zero), brace_key
getter removed, `panic = "unwind"`, `SafeSlice` trait, `try_slice` /
`try_byte`, `MAX_WIRE_FIELD_LEN`, `kdf_1_py` / `encode_header_py` gated
behind `test-only-kdf`, `RustSMPVault::load*` gated test-only.

See MIGRATION.md Section 2 "Patch 1" for detail.

### v10.5.10 — Rust SMP engine

Full four-message SMP state machine in Rust with `ZeroizeOnDrop` on all
exponents.  `RustSMPVault` Rust-owned secret store; secrets never cross
PyO3 boundary outbound.  50k-round SHAKE-256 + HMAC-SHA3-512 KDF.
Canonical fingerprint ordering.  Rate limiting.  Both sides go 🔵
simultaneously.

See ROADMAP.md Phase 2.

### v10.5.8 — Rust Double Ratchet, ML-DSA migration

Pure-Rust double ratchet (chain keys, message keys, AES-256-GCM,
skip-key cache, replay cache).  Switched from deprecated
`pqcrypto-dilithium` to `pqcrypto-mldsa` (FIPS 204).

See ROADMAP.md Phase 1.
