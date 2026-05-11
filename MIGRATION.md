# OTRv4Plus Security Migration — v10.5.10 → v10.6.2

This document tracks the multi-stage hardening of the Rust ↔ Python
boundary in OTRv4Plus.

---

## Section 0 — Critical Exposure Window

The Critical Exposure Window described below is the same as in v10.6.1.
v10.6.2 does not change it.  The four DAKE correctness bugs fixed in
v10.6.2 (described in CHANGELOG.md "v10.6.2") affect whether the Rust
path runs at all, not how long secrets exist as Python `bytes` once it
does.

There is a **brief but real window** during which session keys exist as
Python `bytes` objects in the Python heap.  This window must be
minimized in any production deployment.

### What happens

1. `RustDAKE.process_dake2()` runs in Rust and computes session keys as
   `Vec<u8>` instances inside Rust.
2. PyO3 auto-conversion of `Dakeresult` field assignments creates
   `PyBytes` copies in the Python heap when these Vecs are exposed (the
   `setattr` calls in `dake.rs`).
3. The `RustDAKEAdapter` in `otrv4+.py` receives the `Dakeresult` and is
   expected to call `RustDoubleRatchet.from_dakeresult(result, ...)`
   immediately.
4. Until that call lands, the secrets are reachable as `result.root_key`,
   `result.chain_key_a`, etc. — they exist as `PyBytes` in the Python
   heap.

### Window duration

Under normal load: **microseconds to single-digit milliseconds**.  The
adapter's `_unpack_session_keys()` is invoked synchronously on the same
Python thread that received the `Dakeresult`.

Under abnormal conditions (debugger attached, Python GC pause, GIL
contention, signal handler interrupt) the window can theoretically
extend to seconds.

### Why it matters

An attacker with **process-memory read** capability (debugger, core
dump, `/proc/<pid>/mem`, OOM-killer dump, ptrace) during this window
can recover:

- `root_key` (32 bytes) — full session compromise
- `chain_key_a`, `chain_key_b` (32 bytes each) — both directions
- `brace_key` (32 bytes) — PQ component
- `mac_key` (64 bytes) — message authentication

After the window closes (i.e. after `from_dakeresult()` returns):

- The Python `Dakeresult` object has `consumed=True`
- All secret-field getters raise `Dakeresult has been consumed`
- The original `Vec<u8>` backing memory has been overwritten and
  `shrink_to_fit()`-ed so the allocator may reuse it

### Required deployment discipline

Until Phase 4 (DakeOutput) lands:

1. **Call `from_dakeresult()` IMMEDIATELY after receiving the
   Dakeresult.**  Do not log, copy, serialize, or pass it across thread
   boundaries first.
2. **Never store a Dakeresult in a long-lived Python object.**
3. **Never write the raw bytes to disk** (e.g. through pickle).
4. **Audit any code path that reads `result.root_key` etc.** — these
   reads create additional PyBytes copies that the consumer cannot zero.

The `RustDAKEAdapter._unpack_session_keys()` call site has been audited
and satisfies item 1.

---

## Section 1 — Current Security Status (as of v10.6.2)

This release does **not** achieve the audit's full architectural goal of
"Python is cryptographically blind to all secret material".  It DOES
substantially reduce the attack surface AND makes the Rust DAKE path
actually functional for the first time.

The following remain true as of v10.6.2:

- **Python still receives session keys after DAKE2** as `Dakeresult`
  PyBytes fields, until `from_dakeresult()` consumes them.  See
  "Critical Exposure Window" above.
- **Multiple in-memory copies still exist briefly.**  Phase 4
  eliminates this.
- **Rust's zeroization stops at the FFI boundary** for any data that has
  already been marshalled into `PyBytes`.  Phase 4 prevents marshalling.
- **Python still drives protocol orchestration**
  (`EnhancedSessionManager`, `EnhancedOTRSession`).  Phase 6 scope.

This is a **risk-reduction-plus-correctness release**, not an
architectural fix.  See ROADMAP Phases 4–6.

---

## Section 2 — Issues Fixed by Release

### Patch 1 (v10.6.0)

| Audit ID | Fix | File |
|---|---|---|
| **C5** | `RustSMP::set_secret_from_bytearray()` — accepts mutable `bytearray`, copies to Rust-owned `Vec<u8>` zeroed on drop, no Python `bytes` intermediate created | `smp.rs` |
| **C2 (partial)** | `RustDoubleRatchet::from_dakeresult()` — moves secrets out of Dakeresult, zeroes the Vec<u8> backing memory, sets Python attributes to None | `ratchet.rs` |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter REMOVED — brace key no longer leakable via Python attribute access | `ratchet.rs` |
| **P3** | `panic = "abort"` REMOVED from `[profile.release]` — Rust panics now unwind cleanly through PyO3 | `Cargo.toml` |
| **V1–V3** | `SafeSlice` trait, `try_slice` / `try_byte`, `MAX_WIRE_FIELD_LEN` | `error.rs`, `header.rs`, `dake.rs` |
| **M1, M2** | `kdf_1_py`, `encode_header_py` gated behind `test-only-kdf` feature | `kdf.rs`, `header.rs` |
| **C1** | `RustSMPVault::load*` gated behind `test-only-kdf` | `smp_vault.rs` |

### Patch 2 (v10.6.1)

| Patch ID | Improvement | File |
|---|---|---|
| **§1** | `set_secret_from_bytearray` now wipes the Python bytearray in-place via the safe `set_item` API loop — no `unsafe`, no caller discipline required | `smp.rs` |
| **§2** | `from_dakeresult` now uses **aggressive zero**: overwrite contents → `clear()` → `shrink_to_fit()` so capacity memory is also released | `ratchet.rs`, `dake.rs` |
| **§3** | Added `Dakeresult.consumed: bool` flag, set to `true` by `from_dakeresult()`.  All secret-field getters now check this flag and raise `Dakeresult has been consumed` if reset post-consumption | `dake.rs` |
| **§4** | Single `consumed` flag covers entire object — no partial reuse possible; gating is structural, not field-by-field | `dake.rs` |
| **§7** | `from_dakeresult` rejects already-consumed Dakeresult with `PyValueError`, no panic | `ratchet.rs` |
| **§8** | Stack-allocated key arrays in `from_dakeresult` are explicitly bound at end-of-scope before return; `DoubleRatchet::new` has already copied them into ZeroizeOnDrop fields | `ratchet.rs` |

### Patch 3 (v10.6.2 — this release) — Rust DAKE correctness

| Bug | Fix | File |
|---|---|---|
| **#1** | MLKEM tuple destructuring reversed.  `pqcrypto_kyber::kyber1024::encapsulate` returns `(SharedSecret, Ciphertext)`, not `(Ciphertext, SharedSecret)`.  Wire shipped 32-byte SS where 1568-byte CT was expected; KDF received 1568-byte CT where 32-byte SS was expected. | `dake.rs` |
| **#2** | Responder MAC input did not include `MSG_DAKE2` byte or ML-DSA pub.  Parser MACs over `data[..off]` which does.  Generator now MACs over `wire_body` (exact bytes that go on the wire, sans MAC trailer). | `dake.rs` |
| **#3** | Initiator `dh2` and `dh3` were identical computations (both `our_prekey_priv × peer_eph_pub`) instead of matching responder by X448 commutativity at each position.  Fixed: `dh1 = our_eph × peer_eph`, `dh2 = our_prekey × peer_eph`, `dh3 = our_eph × peer_prekey`.  `peer_profile_bytes` stored pre-DH so `peer_prekey_pub()` reads correct bytes; cleared on MAC failure. | `dake.rs` |
| **#4** | `RustDAKEAdapter.__init__` passed `identity_pub_bytes` / `prekey_pub_bytes` (public keys) where Rust constructor expected private bytes.  Same length (57 / 56) so type cast did not fail; Rust silently used public keys as private scalars.  Adapter now extracts raw private bytes via `.private_bytes(Raw, Raw, NoEncryption())`. | `otrv4+.py` |
| **#5 (UX)** | 401 (`ERR_NOSUCHNICK`) handler killed sessions on first occurrence during multi-fragment DAKE.  Now soft-ignored during `DAKE_IN_PROGRESS` / `PLAINTEXT` / `CREATED` states unless 5 consecutive 401s arrive without peer OTR traffic.  Any received OTR fragment resets the counter. | `otrv4+.py` |

### Specific behavioral changes

#### Before Patch 2

```python
ratchet = RustDoubleRatchet.from_dakeresult(result, dh_pub, True)
# result.root_key is None (set to None inside Rust)
# But the original PyBytes for result.root_key may still be referenced
# elsewhere in Python heap (logs, caller variables, etc.)
print(result.root_key)        # → None
```

#### After Patch 2 (v10.6.1+)

```python
ratchet = RustDoubleRatchet.from_dakeresult(result, dh_pub, True)
print(result.consumed)        # → True
print(result.root_key)        # raises RuntimeError: Dakeresult has been consumed
print(result.chain_key_a)     # raises RuntimeError: Dakeresult has been consumed
# Public fields still readable:
print(result.ssid)            # → b'\x...' (8 bytes, public)
print(result.remote_identity_pub)  # → b'\x...' (57 bytes, public)
```

#### Before Patch 3

The Rust DAKE path was effectively unreachable: constructor raised
`TypeError` during the kwarg-attempt branch and silently fell back to
Python `OTRv4DAKE` in the surrounding `try`/`except`.  Even when the
positional-argument path succeeded, MAC verification with real peers
always failed for the four reasons listed above.

#### After Patch 3 (v10.6.2)

```python
# At session start:
#   /otr <nick>
# Banner shows DAKE: 🦀 Rust (DH secrets never Python)
# Session reaches RECEIVED_DAKE2 → ESTABLISHED on Rust path.
# from_dakeresult consumes session keys; Dakeresult.consumed becomes True.
# All subsequent encrypt/decrypt run on RustDoubleRatchet with secrets
# living only in Rust SecretBytes / SecretVec.
```

#### SMP secret input

```python
# Before Patch 1:
self._vault.store("secret", bytes(bytearray(passphrase, "utf-8")))  # ← bytes!
rust_smp.set_secret_from_vault(self._vault, "secret", ...)

# Patch 1:
raw = bytearray(passphrase, "utf-8")
try:
    rust_smp.set_secret_from_bytearray(raw, sid, our_fp, peer_fp)
finally:
    for i in range(len(raw)): raw[i] = 0   # caller had to wipe

# Patch 2:
raw = bytearray(passphrase, "utf-8")
rust_smp.set_secret_from_bytearray(raw, sid, our_fp, peer_fp)
# raw is already all zeros — Rust did it, no caller discipline required
assert all(b == 0 for b in raw)
```

---

## Section 3 — Remaining Risks (as of v10.6.2)

| Risk | Severity | Why Deferred |
|---|---|---|
| `Dakeresult` still creates PyBytes for session keys at DAKE2 time, before `from_dakeresult()` is called.  See "Critical Exposure Window" above | **MEDIUM** | Removing requires opaque `DakeOutput` handle.  Phase 4 scope. |
| Python `EnhancedOTRSession` orchestrates DAKE / SMP / ratchet state | **MEDIUM** | Architectural — would require porting ~3000 lines of protocol logic to Rust.  Phase 6 scope. |
| `RustSMPVault::load*` exists (gated behind `test-only-kdf`) | **LOW** | Production builds (`--features pq-rust`) do not expose it.  Acceptable. |
| C extensions (`otr4_ed448_ct.c`, `otr4_crypto_ext.c`, `otr4_mldsa_ext.c`) handle ring-sig, ML-KEM, and ML-DSA in C+OpenSSL | **LOW** | Constant-time helpers in place (`BN_mod_exp_mont_consttime`, `OPENSSL_cleanse`); independent timing audit not yet performed |
| Python `bytes.__eq__` used for some non-secret comparisons | **LOW** | Fingerprints are public.  Migration to `hmac.compare_digest()` recommended for defense-in-depth |

---

## Section 4 — Phase 4 Plan (eliminate Critical Exposure Window)

Phase 4 eliminates `Dakeresult` entirely and introduces opaque
session-key handles.  This closes the "Critical Exposure Window"
described in Section 0.

### Phase 4.1 — `DakeOutput` opaque PyO3 class

Replace the `Dakeresult` struct (with its `Vec<u8>` secret fields) with a
`DakeOutput` whose secret fields are private to Rust:

```rust
#[pyclass]
pub struct DakeOutput {
    inner: RefCell<Option<DakeOutputInner>>,
    public_ssid:           [u8; 8],
    public_remote_ipub:    Vec<u8>,
    public_remote_mldsa:   Option<Vec<u8>>,
    public_remote_profile: Vec<u8>,
}

struct DakeOutputInner {  // PRIVATE — never exposed via PyO3
    keys: DakeSessionKeys,
}

#[pymethods]
impl DakeOutput {
    #[getter] fn ssid(&self, py: Python) -> Py<PyBytes> { /* public */ }
    #[getter] fn remote_identity_pub(&self, py: Python) -> Py<PyBytes> { /* public */ }
    // NO getters for root_key / chain_key_* / brace_key / mac_key — they
    // do not exist as PyO3-visible fields at all.

    fn consume_into_ratchet(&self, ad: &[u8])
        -> PyResult<RustDoubleRatchet> { /* moves keys into ratchet */ }
}
```

After Phase 4, the secret keys never become `PyBytes`.  The Critical
Exposure Window collapses to zero.

### Phase 4.2 — `RustDoubleRatchet::from_dake_keys`

Add a constructor on the ratchet that accepts `DakeSessionKeys` (a
private Rust-internal type already defined in `secure_mem.rs`) directly.
This pairs with `DakeOutput::consume_into_ratchet`.

### Phase 4.3 — Migrate Python adapter

`RustDAKEAdapter._unpack_session_keys()` becomes:

```python
output = self._rust.process_dake2_output(...)
self.ssid                       = bytes(output.ssid)
self.remote_identity_pub_bytes  = bytes(output.remote_identity_pub)
self.remote_profile_bytes       = bytes(output.remote_profile_bytes)
self.ratchet = output.consume_into_ratchet(ad=self.ssid)
# After this: output.consumed == True; secrets live ONLY in Rust ratchet.
```

### Phase 4.4 — Delete legacy `Dakeresult`

Once all callers migrate, `Dakeresult` and the old `generate_dake2` /
`process_dake2` methods are removed from PyO3 export.  Internal Rust
code may still use the type but Python loses access entirely.

### Phase 4 estimated effort

- Implementation: 2–3 days
- Live I2P testing: 2–4 days (DAKE handshake timing, SMP verification,
  ratchet ordering under fragment loss must all be re-validated)
- Integration into Python adapter: 1 day
- **Total: ~1 calendar week of focused work**

---

## Section 5 — Phase 6 Vision (single-API Rust engine)

Phase 6 fulfills the audit's full architectural goal: Python becomes a
transport/UI shim with zero protocol logic.

```
┌─────────────────────────────────────────┐
│ Python (~300 lines total)               │
│   • IRC socket I/O                      │
│   • Terminal UI                         │
│   • Fragment reassembly (transport)     │
│   • Pass bytes to/from OtrSession       │
└──────────────┬──────────────────────────┘
               │ raw bytes only
┌──────────────▼──────────────────────────┐
│ Rust OtrSession (~5000 lines)           │
│   • DAKE state machine                  │
│   • SMP state machine                   │
│   • Double Ratchet                      │
│   • Message parser + validator          │
│   • Returns Vec<Event> for Python       │
└─────────────────────────────────────────┘
```

Single entry-point API:

```rust
#[pyclass]
pub struct OtrSession {
    inner: SessionState,                  // private — no getters
}

#[pymethods]
impl OtrSession {
    #[new] fn new(...) -> Self { ... }

    fn handle_outgoing(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>> { ... }
    fn handle_incoming(&mut self, raw: &[u8]) -> PyResult<Vec<Event>> { ... }
    fn set_smp_secret(&mut self, secret: &Bound<PyByteArray>) -> PyResult<()> { ... }
}

#[pyclass]
pub enum Event {
    SendMessage(Vec<u8>),
    DeliverPlaintext(Vec<u8>),
    SmpRequest { question: String },
    SmpResult(bool),
    SessionEstablished { ssid: [u8; 8], remote_fp: Vec<u8> },
    Error(String),
}
```

### Phase 6 estimated effort

- 2–4 weeks of senior Rust engineer time
- Independent code review and audit (audit firm engagement: 4–8 weeks)
- I2P stress testing under packet loss, latency spikes, peer churn

---

## Audit Compliance Status

| Requirement | v10.6.0 (Patch 1) | v10.6.1 (Patch 2) | v10.6.2 (Patch 3) | Phase 4 | Phase 6 |
|---|---|---|---|---|---|
| Python NEVER accesses raw key material | ⚠️ partial | ⚠️ window-only access | ⚠️ window-only access | ✅ DAKE keys | ✅ all keys |
| All secrets remain in Rust as opaque handles | ⚠️ partial | ⚠️ consumed-flag enforced | ⚠️ unchanged | ✅ DakeOutput | ✅ all state |
| FFI exposes only ciphertext/plaintext/IDs | ❌ | ❌ | ❌ | ⚠️ partial | ✅ |
| Constant-time crypto comparisons in Rust | ✅ subtle crate | ✅ | ✅ | ✅ | ✅ |
| Panic-safe FFI boundary | ✅ unwind + SafeSlice | ✅ + defensive asserts | ✅ | ✅ | ✅ |
| Single-session API | ❌ multiple PyO3 classes | ❌ | ❌ | ❌ | ✅ OtrSession |
| Python = transport/UI only | ❌ | ❌ | ❌ | ❌ | ✅ |
| Aggressive zeroization | ❌ Vec drop only | ✅ clear+shrink_to_fit | ✅ | ✅ | ✅ |
| Caller-discipline-free secret wipe | ❌ | ✅ Rust wipes | ✅ | ✅ | ✅ |
| One-time-use Dakeresult | ❌ | ✅ consumed flag | ✅ | ✅ via opaque handle | ✅ |
| **Rust DAKE actually runs end-to-end with real peers** | ❌ (silent fallback) | ❌ (silent fallback) | ✅ | ✅ | ✅ |

---

## Build & Test

```bash
# Production build (no test-only KDF/header exposure):
cd ~/OTRv4Plus && \
    python setup_otr4.py build_ext --inplace && \
    bash build_ed448.sh; \
    cd Rust && \
    cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so && \
    cd .. && \
    pytest tests/ -v --tb=short
```

`cargo clean` is included deliberately.  Cargo's incremental build can
silently skip rebuilding when source files change in non-trivial ways
(e.g. adding new PyO3 method bodies), leaving the deployed `.so`
running stale code while source has the fixes.  Verify the deployed
`.so` contains your change with `strings otrv4_core.so | grep
<unique-marker-from-your-edit>` before testing.
