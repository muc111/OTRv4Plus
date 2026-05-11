# OTRv4+ Development Roadmap

## Phase 0 – Migrate to maintained ML-DSA crate ✅ (v10.5.8)

- Replaced deprecated `pqcrypto-dilithium` with `pqcrypto-mldsa` (FIPS 204)
- Same algorithm, same API, zero crypto changes

## Phase 1 – Rust Double Ratchet ✅ (v10.5.8)

- All ratchet operations (chain keys, message keys, AES-256-GCM, skip
  keys, replay cache) inside `otrv4_core`
- Keys `ZeroizeOnDrop`; no `unsafe` blocks

## Phase 2 – Rust SMP Engine ✅ (v10.5.10)

- `SmpState`: full four-message state machine in Rust — all exponents
  (`a2`, `a3`, `b2`, `b3`, `r2`–`r6`, `r2b`–`r6b`) stored as `SecretVec`
  with `ZeroizeOnDrop`
- `RustSMPVault`: Rust-owned secret container — Python receives a random
  `u64` handle; secret bytes never cross the PyO3 boundary outbound
- 50,000-round SHAKE-256 + HMAC-SHA3-512 session-binding KDF
- Canonical fingerprint ordering (lexicographic sort) — both sides derive
  identical secrets regardless of role
- Rate limiting: 3 failures → `Aborted`, 30s retry cooldown, 10-minute
  session expiry
- Transcript MAC keyed to session_id — cross-session replay impossible
- Both sides transition to `SMP_VERIFIED` simultaneously
- Live I2P timing: ~2 minutes for full ZKP exchange

## Phase 3 – Audit boundary hardening ✅ (v10.6.0 + v10.6.1)

Patch 1 (v10.6.0):

- C5: `RustSMP::set_secret_from_bytearray()` — accepts mutable
  `bytearray`, copies into Rust-owned `Vec<u8>`, no Python `bytes`
  intermediate
- C2 (partial): `RustDoubleRatchet::from_dakeresult()` — moves secrets
  out of `Dakeresult`, zeroes the `Vec<u8>` backing memory, sets Python
  attributes to None
- C4: `RustDoubleRatchet::brace_key()` PyO3 getter REMOVED
- P3: `panic = "abort"` → `panic = "unwind"` in `Cargo.toml`
- V1–V3: `SafeSlice` trait, `try_slice` / `try_byte`,
  `MAX_WIRE_FIELD_LEN`
- M1, M2: `kdf_1_py`, `encode_header_py` gated behind `test-only-kdf`
- C1: `RustSMPVault::load*` gated behind `test-only-kdf`

Patch 2 (v10.6.1):

- §1: `set_secret_from_bytearray` wipes Python `bytearray` in-place via
  safe `set_item` loop — no caller discipline
- §2: `from_dakeresult` aggressive zero (overwrite → `clear()` →
  `shrink_to_fit()`)
- §3: `Dakeresult.consumed: bool` flag; secret getters raise
  `Dakeresult has been consumed` post-use
- §7: `from_dakeresult` rejects already-consumed Dakeresult with
  `PyValueError`, no panic

## Phase 3.5 – Rust DAKE end-to-end correctness ✅ (v10.6.2)

The Rust DAKE PyO3 wrapper shipped in v10.6.0 / v10.6.1 was effectively
unreachable in production.  The constructor's argument signature did not
match what the Python adapter passed, so every session fell back to
Python `OTRv4DAKE` via a silent exception-catch.  Once that was fixed,
four distinct crypto bugs (MLKEM tuple order, MAC input scope, initiator
DH triple pairing, public-keys-as-private at constructor) prevented MAC
verification.

v10.6.2 fixes all five issues.  Detail in CHANGELOG.md "v10.6.2".  Net
result: `DAKE : 🦀 Rust (DH secrets never Python)` is no longer
aspirational — Rust DAKE actually runs end-to-end with real peers and
the MAC over the DAKE2 wire body verifies on both sides.

Live I2P timing (v10.6.2, measured):

| Phase | Time |
|---|---|
| DAKE handshake (3 messages, ~24 fragments each direction) | ~2m 44s |
| SMP verification (4-step ZKP) | ~2m 00s |
| Total /otr → 🔵 verified | ~6m 37s |

Cryptographic compute on Termux/aarch64 (50k-round SMP KDF + DAKE
crypto): under 1 second total.  Everything else is I2P tunnel latency.

## Phase 4 – `DakeOutput` opaque handle 🔜 (eliminates Critical Exposure Window)

The `Dakeresult` struct still exposes session keys as PyO3 `Vec<u8>`
fields with `#[pyo3(get, set)]`.  Even with the v10.6.1 `consumed` flag
preventing post-use access, the keys exist as `PyBytes` in the Python
heap for microseconds-to-milliseconds between `process_dake2` returning
and `from_dakeresult` consuming them.  See MIGRATION.md Section 0.

Phase 4 replaces `Dakeresult` with `DakeOutput`:

```rust
#[pyclass]
pub struct DakeOutput {
    inner: RefCell<Option<DakeOutputInner>>,   // PRIVATE, no getters
    // Public fields only:
    public_ssid:           [u8; 8],
    public_remote_ipub:    Vec<u8>,
    public_remote_mldsa:   Option<Vec<u8>>,
    public_remote_profile: Vec<u8>,
}

#[pymethods]
impl DakeOutput {
    #[getter] fn ssid(&self, py: Python) -> Py<PyBytes>;
    #[getter] fn remote_identity_pub(&self, py: Python) -> Py<PyBytes>;
    // NO getters for root_key / chain_key_* / brace_key / mac_key

    fn consume_into_ratchet(&self, ad: &[u8]) -> PyResult<RustDoubleRatchet>;
}
```

The secret session keys never become `PyBytes`.  The Critical Exposure
Window collapses to zero.  Estimated effort: ~1 week of focused work
(implementation: 2-3 days; live I2P revalidation: 2-4 days; adapter
migration: 1 day).

Closes audit findings C2 and C3 fully.

## Phase 5 – Rust Long-Term Identity Keys 🔜

- Store Ed448 & X448 private identity/prekey bytes as Rust `SecretVec`
  inside `PyDake` rather than copying them in at constructor time
- Expose signing / DH-exchange via PyO3 thin wrappers that take public
  input and return public output
- Eliminates the last whole-session Python secret exposure
- Estimated effort: 1–2 weeks

## Phase 6 – Single-API Rust protocol engine 🔜

Architectural goal from the audit prompt: Python becomes a transport/UI
shim with zero protocol logic.

```
┌─────────────────────────────────────────┐
│ Python (~300 lines)                     │
│   • IRC socket I/O                      │
│   • Terminal UI                         │
│   • Fragment reassembly                 │
│   • Bytes in / Vec<Event> out           │
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
    inner: SessionState,   // private — no getters
}

#[pymethods]
impl OtrSession {
    #[new] fn new(...) -> Self;
    fn handle_outgoing(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>>;
    fn handle_incoming(&mut self, raw: &[u8]) -> PyResult<Vec<Event>>;
    fn set_smp_secret(&mut self, secret: &Bound<PyByteArray>) -> PyResult<()>;
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

Closes the architectural intent of the audit fully.  Estimated effort:
2–4 weeks of senior Rust engineer time.

## Phase 7 – Hardening & external audit 🔜

- `mlock` all Rust secret buffers (currently attempted; non-fatal on
  Termux where `RLIMIT_MEMLOCK = 0`)
- Force-zeroize on `SIGABRT` / panic
- Formal security review of entire Rust↔Python boundary
- ProVerif or EasyCrypt model of DAKE + SMP
- Independent code review and audit (audit firm engagement: 4–8 weeks)
- I2P stress testing under packet loss, latency spikes, peer churn

---

Timeline is subject to contributor availability.  All work is done in
the open on the `main` branch.
