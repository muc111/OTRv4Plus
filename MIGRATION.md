# OTRv4Plus Security Migration — v10.5.10 → v10.6.3

This document tracks the multi-stage hardening of the Rust ↔ Python
boundary in OTRv4Plus.

---

## Section 0 — Critical Exposure Window: CLOSED in v10.6.3

In v10.6.0 through v10.6.2, there was a brief window during which
session keys (`root_key`, `chain_key_send`, `chain_key_recv`,
`brace_key`, `mac_key`) existed as Python `bytes` objects in the
Python heap.  Window duration was microseconds to single-digit
milliseconds under normal load; could extend to seconds under
debugger / GC pause / signal handler interrupt.

**v10.6.3 eliminates this window.**

The new path (`process_dake2_output` / `generate_dake2_output` →
`DakeOutput` → `consume_into_ratchet` → `RustDoubleRatchet`) keeps
secret session keys exclusively in Rust at all times:

```
DAKE crypto in Rust
  → DakeSessionKeys (private Rust type, ZeroizeOnDrop)
  → DakeOutput.inner: RefCell<Option<DakeSessionKeys>>
                      (private; no PyO3 getter)
  → consume_into_ratchet() — Rust-to-Rust move
  → DoubleRatchet's SecretBytes fields (ZeroizeOnDrop)
```

At no step are secret keys marshalled into `PyBytes`.

The legacy path (`process_dake2` / `generate_dake2` returning
`Dakeresult`) remains available for backward compatibility with older
Rust `.so` builds — when an older binary is loaded, the Python adapter
falls back to v10.6.2 behaviour silently.  The legacy path will be
removed in v10.7.

### How to verify which path is active

```python
ratchet = session.ratchet
if getattr(ratchet, '_dake_output_consumed', False):
    print("Phase-4 hardened: session keys never in Python")
else:
    print("Legacy path: Critical Exposure Window applies")
```

A correctly-built v10.6.3 environment shows `_dake_output_consumed = True`
on every new session.

---

## Section 1 — Current Security Status (as of v10.6.3)

### What is achieved

- **Rust DAKE runs end-to-end with real peers** (v10.6.2 / v10.6.3)
- **DAKE DH secrets** (dh1/dh2/dh3, mlkem_ss) — Rust-only, never PyBytes
- **DAKE session keys** (root, chain×2, brace, mac) — Rust-only, never
  PyBytes (v10.6.3 closes the window)
- **SMP passphrase** — bytearray entry path with Rust-side wipe; vault
  store keyed by random `u64` handle
- **SMP exponents** — all `SecretVec` with `ZeroizeOnDrop`
- **Ratchet keys** — all `SecretBytes` / `SecretVec` with `ZeroizeOnDrop`
- **Wire decoders** — `SafeSlice` trait, no panic on truncated input
- **Panic safety** — `panic = "unwind"`, `try_slice`, `Internal(&'static
  str)`
- **Test-only PyO3 exports** — gated behind `test-only-kdf` feature flag

### What remains

- **Ed448 / X448 long-term private keys** still live in Python
  `cryptography` library objects (underlying bytes in OpenSSL C heap,
  but the Python `PrivateKey` reference is in Python).  Raw private
  bytes are extracted at session start and passed into Rust.  Phase 5
  scope.
- **Python still drives protocol orchestration**
  (`EnhancedSessionManager`, `EnhancedOTRSession`).  Phase 6 scope.
- **C extensions** still handle ring-sig, ML-KEM, ML-DSA.  Constant-time
  helpers in place but no independent timing audit.  Phase 7 scope.

---

## Section 2 — Issues Fixed by Release

### Patch 1 (v10.6.0)

| Audit ID | Fix | File |
|---|---|---|
| **C1** | `RustSMPVault::load*` gated behind `test-only-kdf` | `smp_vault.rs` |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter removed | `ratchet.rs` |
| **C5** | `RustSMP::set_secret_from_bytearray()` — no `bytes` intermediate | `smp.rs` |
| **P3** | `panic = "abort"` → `panic = "unwind"` | `Cargo.toml` |
| **V1–V3** | `SafeSlice` trait, `try_slice` / `try_byte`, `MAX_WIRE_FIELD_LEN` | `error.rs`, `header.rs`, `dake.rs` |
| **M1, M2** | `kdf_1_py`, `encode_header_py` gated behind `test-only-kdf` | `kdf.rs`, `header.rs` |

### Patch 2 (v10.6.1)

| Patch ID | Improvement | File |
|---|---|---|
| **§1** | `set_secret_from_bytearray` wipes Python bytearray in-place via safe `set_item` loop | `smp.rs` |
| **§2** | `from_dakeresult` aggressive zero (overwrite → `clear()` → `shrink_to_fit()`) | `ratchet.rs`, `dake.rs` |
| **§3** | `Dakeresult.consumed: bool`; secret getters raise post-consumption | `dake.rs` |
| **§4** | Single `consumed` flag covers whole object | `dake.rs` |
| **§7** | `from_dakeresult` rejects already-consumed Dakeresult with `PyValueError` | `ratchet.rs` |

### Patch 3 (v10.6.2) — Rust DAKE correctness

| Bug | Fix | File |
|---|---|---|
| **#1** | MLKEM tuple destructuring reversed | `dake.rs` |
| **#2** | Responder MAC input did not cover full wire body | `dake.rs` |
| **#3** | Initiator DH triples paired with wrong slots | `dake.rs` |
| **#4** | Adapter passed public keys where Rust expected private | `otrv4+.py` |
| **#5 (UX)** | IRC 401 handler killed sessions during multi-fragment DAKE | `otrv4+.py` |

Closes audit finding **C6** (Rust DAKE end-to-end correctness).

### Patch 4 (v10.6.3) — Critical Exposure Window closed

| Audit ID | Fix | File |
|---|---|---|
| **C2** | New `DakeOutput` PyO3 class with private `RefCell<Option<DakeSessionKeys>>`; no `#[pyo3(get)]` for secret fields | `dake.rs` |
| **C2** | New PyO3 methods `generate_dake2_output` / `process_dake2_output` | `dake.rs` |
| **C2** | New non-PyO3 constructor `RustDoubleRatchet::from_dake_keys` (takes `DakeSessionKeys` by-move) | `ratchet.rs` |
| **C2** | `Dakeresult` and `DakeOutput` both explicitly registered in PyO3 module | `lib.rs` |
| **C3** | Same as C2 — session keys flow Rust→Rust via `consume_into_ratchet` | (covered above) |
| **C3** | Python adapter migrated: `RustDAKEAdapter` prefers `_output` API; new `RustBackedDoubleRatchet.from_dake_output` classmethod | `otrv4+.py` |
| **C3** | `_initialize_ratchet` prefers Phase-4 path when `session._dake_output` present | `otrv4+.py` |

---

## Section 3 — Audit Compliance Status

| Requirement | v10.6.0 | v10.6.1 | v10.6.2 | v10.6.3 |
|---|---|---|---|---|
| Python NEVER accesses raw key material | ⚠️ partial | ⚠️ window-only | ⚠️ window-only | ✅ |
| All secrets remain in Rust as opaque handles | ⚠️ partial | ⚠️ consumed-flag | ⚠️ unchanged | ✅ DakeOutput |
| FFI exposes only ciphertext/plaintext/IDs | ❌ | ❌ | ❌ | ⚠️ DAKE done; Phase 6 for full |
| Constant-time crypto comparisons in Rust | ✅ subtle | ✅ | ✅ | ✅ |
| Panic-safe FFI boundary | ✅ unwind + SafeSlice | ✅ | ✅ | ✅ |
| Single-session API | ❌ multiple PyO3 classes | ❌ | ❌ | ❌ (Phase 6) |
| Python = transport/UI only | ❌ | ❌ | ❌ | ❌ (Phase 6) |
| Aggressive zeroization | ❌ Vec drop only | ✅ clear+shrink_to_fit | ✅ | ✅ |
| Caller-discipline-free secret wipe | ❌ | ✅ Rust wipes | ✅ | ✅ |
| One-time-use Dakeresult | ❌ | ✅ consumed flag | ✅ | ✅ + DakeOutput opaque |
| **Rust DAKE actually runs end-to-end** | ❌ (silent fallback) | ❌ (silent fallback) | ✅ | ✅ |
| **Session keys never become PyBytes** | ❌ | ❌ | ❌ | ✅ |

### Audit findings — final status

| Audit ID | Description | Status |
|---|---|---|
| **C1** | Test-only `RustSMPVault::load*` exposed in production | ✅ Fixed v10.6.0 |
| **C2** | `Dakeresult` exposes session keys as `Vec<u8>` getters | ✅ **Fixed v10.6.3** |
| **C3** | `process_dh_message` returns secrets to Python | ✅ **Fixed v10.6.3** |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter leaks brace key | ✅ Fixed v10.6.0 |
| **C5** | SMP passphrase enters Python `bytes` during set_secret | ✅ Fixed v10.6.1 |
| **C6** | Rust DAKE end-to-end correctness | ✅ Fixed v10.6.2 |
| **P3** | `panic = "abort"` breaks FFI panic safety | ✅ Fixed v10.6.0 |
| **V1–V3** | Wire decoders did not bounds-check | ✅ Fixed v10.6.0 |
| **M1, M2** | `kdf_1`, `encode_header` PyO3 exports | ✅ Fixed v10.6.0 |

**Net: 11 of 11 findings fully closed.  Rust→Python boundary audit
complete.**

---

## Section 4 — Test-API caveats for Phase 4

The new Phase-4 ratchet path sets `_rks_send`, `_rks_recv`, `_rks_root`
mirrors to zero-byte placeholders because the real chain/root keys
never become accessible to Python.  Production crypto does not touch
these mirrors.

Test code that asserts on mirror contents must check for the Phase-4
marker:

```python
if hasattr(ratchet, '_dake_output_consumed'):
    # Phase-4 ratchet — mirrors are zero placeholders
    pytest.skip("Phase-4 ratchet does not expose real chain/root keys")
else:
    # Legacy ratchet — mirrors are real
    assert ratchet._rks_send.read() == expected_chain_key
```

### Session persistence

Persistence export from a Phase-4 ratchet currently falls back to
fresh DAKE on restore.  Implementing Rust-side ratchet serialization
(encrypted opaque blob with vault key) is planned for v10.6.4.  Until
then, persisted sessions built via the legacy path continue to work
unchanged.

---

## Section 5 — Phase 5 / 6 / 7 (future)

### Phase 5 — Ed448 / X448 long-term keys into Rust SecretVec

Currently the long-term identity key (Ed448) and prekey (X448) live in
Python `cryptography` library `PrivateKey` objects.  Their raw private
bytes are extracted at `RustDAKEAdapter.__init__` and passed into Rust.

Phase 5 holds the private bytes as Rust `SecretVec` inside `PyDake`,
exposes only signing / DH-exchange operations via PyO3 thin wrappers
that take public input and return public output.

### Phase 6 — Single-API Rust protocol engine

Python becomes a ~300-line transport/UI shim.  Rust `OtrSession` is the
single PyO3-exported class with `handle_incoming` / `handle_outgoing` /
`set_smp_secret` methods that return `Vec<Event>`.

### Phase 7 — Hardening & external audit

`mlock` (best-effort on Termux), force-zeroize on SIGABRT/panic, formal
review of Rust↔Python boundary, ProVerif or EasyCrypt model, external
audit firm engagement, I2P stress testing.

---

## Build & Test

```bash
# Production build:
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
silently skip rebuilding when source files change in ways that don't
trigger its change detection (e.g. adding new PyO3 method bodies),
leaving the deployed `.so` running stale code.  Verify the deployed
`.so` contains your change with:

```bash
strings otrv4_core.so | grep -c DakeOutput     # > 0 for v10.6.3+
strings otrv4_core.so | grep -c from_dake_keys # > 0 for v10.6.3+
```

before testing.
