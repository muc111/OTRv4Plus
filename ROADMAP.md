# OTRv4+ Development Roadmap

## Phase 0 – Migrate to maintained ML-DSA crate ✅ (v10.5.8)

- Replaced deprecated `pqcrypto-dilithium` with `pqcrypto-mldsa` (FIPS 204)
- Same algorithm, same API, zero crypto changes

## Phase 1 – Rust Double Ratchet ✅ (v10.5.8)

- All ratchet operations (chain keys, message keys, AES‑256‑GCM, skip keys, replay cache) inside `otrv4_core`
- Keys `ZeroizeOnDrop`; no `unsafe` blocks

## Phase 2 – Rust SMP Engine ✅ (v10.5.10)

What was done:

- **`SmpState`**: full four-message state machine in Rust — all exponents (`a2`, `a3`, `b2`, `b3`, `r2`–`r6`, `r2b`–`r6b`) stored as `SecretVec` with `ZeroizeOnDrop`
- **`RustSMPVault`**: Rust-owned secret container — Python receives a random `u64` handle; secret bytes never cross the PyO3 boundary outbound
- **`set_secret_from_vault()`**: secrets flow from vault → SMP engine without touching Python memory
- **50,000-round KDF**: SHAKE-256 chain + HMAC-SHA3-512 session binding — brute-force of captured transcript infeasible
- **Canonical fingerprint ordering**: lexicographic sort of fingerprints before HMAC so both sides derive identical secrets
- **Rate limiting**: 3 failures → permanent `Aborted`; 30-second retry cooldown; 10-minute session expiry
- **Transcript MAC**: HMAC-SHA3-512 over all wire messages, keyed to session_id — cross-session replay impossible
- **Both sides go blue**: `is_verified()` checked immediately after `process_smp3_generate_smp4()` so the responder transitions to `SMP_VERIFIED` at the same moment as the initiator

SMP timing over I2P (measured from live sessions):
- Full four-step ZKP exchange: **~2 minutes**
- Total from `/otr nick` to 🔵 verified: **~6 minutes 37 seconds**

## Phase 3 – Rust DAKE Key Derivation 🔜

- Perform DH shared-secret handling and KDF-1 inside Rust
- `dh1` / `dh2` / `dh3` never leave Rust as Python bytes
- Integrate with existing `dake.rs` helpers
- Estimated effort: 2 weeks

## Phase 4 – Rust Long‑Term Identity Keys 🔜

- Store Ed448 & X448 private keys as Rust `SecretVec`
- Expose signing/exchange via PyO3 thin wrappers
- Eliminates the last whole-session Python secret exposure
- Estimated effort: 1–2 weeks

## Phase 5 – Hardening & Audit 🔜

- `mlock` all Rust secret buffers (currently attempted; non-fatal on Termux where RLIMIT_MEMLOCK = 0)
- Force-zeroize on `SIGABRT` / panic
- Formal security review of entire Rust↔Python boundary
- ProVerif or EasyCrypt model of DAKE + SMP
- Estimated effort: 2–3 weeks

---

Timeline is subject to contributor availability. All work is done in the open on the `main` branch.
