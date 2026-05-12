# OTRv4+ Development Roadmap

## Phase 0 – Migrate to maintained ML-DSA crate ✅ (v10.5.8)

Replaced deprecated `pqcrypto-dilithium` with `pqcrypto-mldsa` (FIPS 204).
Same algorithm, same API, zero crypto changes.

## Phase 1 – Rust Double Ratchet ✅ (v10.5.8)

All ratchet operations (chain keys, message keys, AES-256-GCM, skip
keys, replay cache) inside `otrv4_core`.  Keys `ZeroizeOnDrop`; no
`unsafe` blocks.

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
- Transcript MAC keyed to `session_id` — cross-session replay impossible
- Both sides transition to `SMP_VERIFIED` simultaneously
- Live I2P timing: ~2 minutes for full ZKP exchange

## Phase 3 – Audit boundary hardening ✅ (v10.6.0 + v10.6.1)

Patch 1 (v10.6.0):

- C5: `RustSMP::set_secret_from_bytearray()` — accepts mutable
  `bytearray`, copies into Rust-owned `Vec<u8>`, no Python `bytes`
  intermediate
- C2 (partial): `RustDoubleRatchet::from_dakeresult()` — moves secrets
  out of `Dakeresult`, zeroes the `Vec<u8>` backing memory
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
unreachable in production due to constructor signature mismatches and
four crypto bugs.  v10.6.2 fixes all five issues.  Live I2P verified
working: DAKE 🦀 + SMP 🦀 + Ratchet 🦀, full handshake to 🔵 in
~6m37s.

## Phase 4 – `DakeOutput` opaque handle ✅ (v10.6.3)

**This release closes the Critical Exposure Window completely.**

DAKE session keys (`root_key`, `chain_key_send`, `chain_key_recv`,
`brace_key`, `mac_key`) no longer transit through Python `bytes` at any
point.  Flow:

```
DAKE crypto in Rust  →  DakeSessionKeys (private Rust type, ZeroizeOnDrop)
                     →  DakeOutput.inner: RefCell<Option<DakeSessionKeys>>
                                          (private; no PyO3 getter)
                     →  consume_into_ratchet() — Rust-to-Rust move
                     →  DoubleRatchet's SecretBytes fields (ZeroizeOnDrop)
```

Implementation: new `DakeOutput` PyO3 class in `dake.rs` with private
`RefCell<Option<DakeSessionKeys>>`.  No `#[pyo3(get)]` for secret fields;
only `ssid`, `remote_identity_pub`, `remote_mldsa_pub`,
`remote_profile_bytes`, `dake2_bytes` are accessible from Python.

New PyO3 methods `generate_dake2_output` / `process_dake2_output` on
`RustDAKE`.  New non-PyO3 constructor
`RustDoubleRatchet::from_dake_keys` in `ratchet.rs` (outside the
`#[pymethods]` block because PyO3 cannot expose methods taking non-PyO3
types).

Python adapter migrated: `RustDAKEAdapter.generate_dake2` /
`process_dake2` prefer `_output` API when available; session-manager
handoff copies `_dake_output` onto session; `_initialize_ratchet`
prefers the Phase-4 path; new `RustBackedDoubleRatchet.from_dake_output`
classmethod.

Closes audit findings **C2** and **C3** fully.

**Net audit status: 11 of 11 findings fully closed.  The Rust→Python
boundary audit from v10.5.10 is complete.**

Remaining hardening is architectural improvement beyond the original
audit scope — Phases 5, 6, 7 below.

## Phase 5 – Rust Long-Term Identity Keys 🔜

The Ed448 long-term identity key and X448 prekey are still held in
Python `cryptography` library objects (the underlying secret bytes are
in OpenSSL C heap, but the Python `PrivateKey` object reference lives in
Python).  Their raw private bytes are extracted via `.private_bytes(...)`
and passed into Rust at session start.

Phase 5 moves them into Rust `SecretVec` storage inside `PyDake` and
exposes signing / DH-exchange via PyO3 thin wrappers that take public
input and return public output.  Eliminates the last whole-session
Python secret exposure.

Estimated effort: 1–2 weeks.

## Phase 6 – Single-API Rust protocol engine 🔜

Architectural goal: Python becomes a transport/UI shim with zero
protocol logic.

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
    inner: SessionState,                  // private — no getters
}

#[pymethods]
impl OtrSession {
    #[new] fn new(...) -> Self { ... }

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

Estimated effort: 2–4 weeks of senior Rust engineer time.

## Phase 7 – Hardening & external audit 🔜

- `mlock` all Rust secret buffers (currently attempted; non-fatal on
  Termux where `RLIMIT_MEMLOCK = 0`)
- Force-zeroize on `SIGABRT` / panic
- Formal security review of entire Rust↔Python boundary
- ProVerif or EasyCrypt model of DAKE + SMP
- Independent code review and audit (audit firm engagement: 4–8 weeks)
- I2P stress testing under packet loss, latency spikes, peer churn

## Possible future work — Session Verification Token (SVT) 💡

Concept: cache a cryptographic token after successful SMP verification
to allow instant restoration of verified status after IRC transport
drops, avoiding the ~2-minute SMP re-handshake on every reconnect.

Status: **design only, not implemented.**  Trade-off analysis pending.
The token would be:
- Derived from `BLAKE3(smp_output || dake_session_id || domain_tag)`
- Stored in the existing `RustSMPVault` (Argon2id-hardened, memory-locked)
- Exchanged after fresh DAKE under a key derived from the new root key
- Constant-time compared via `subtle::ConstantTimeEq`

Open questions before implementation: SVT replaces a passphrase-based
proof (SMP) with a vault-resident static token.  Anyone who can read
the vault can impersonate the verified peer.  Whether this is an
acceptable trade for the 2-minute saving is a design decision, not a
technical one.  See `SECURITY.md` for the full threat-model writeup
when SVT is scoped.

Not in v10.6.x scope.  Will be revisited after Phase 5 / Phase 6.

---

Timeline is subject to contributor availability.  All work is done in
the open on the `main` branch.
