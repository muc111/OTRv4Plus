# OTRv4+ Development Roadmap

## Phase 1 – Rust Double Ratchet ✅ (shipped in v10.5.8)
- All ratchet operations (chain keys, message keys, AES‑256‑GCM, skip keys, replay cache) are inside `otrv4_core`.
- Keys are `Zeroize`ed on drop; no unsafe blocks.

## Phase 2 – Rust SMP Engine 🔜
- Move entire SMP state machine (`SmpState`) into Rust.
- Generate exponents directly as `SecretVec`, compute ZKPs with `num_bigint` inside Rust, never expose as Python ints.
- Remove the `RustSMPVault` workaround.
- Estimated effort: 3–4 weeks.

## Phase 3 – Rust DAKE Key Derivation 🔜
- Perform DH shared‑secret handling and KDF‑1 inside Rust, so `dh1`/`dh2`/`dh3` never leave Rust.
- Integrate with existing `dake.rs` helpers.
- Estimated effort: 2 weeks.

## Phase 4 – Rust Long‑Term Identity Keys 🔜
- Store Ed448 & X448 private keys as Rust `SecretVec`.
- Expose signing/exchange via PyO3 (thin wrappers around existing C extensions or `x448`/`ed448` crates).
- Estimated effort: 1–2 weeks.

## Phase 5 – Hardening & Audit 🔜
- `mlock` all Rust secret buffers.
- Force‑zeroize on `SIGABRT`/panic.
- Formal security review of entire Rust↔Python boundary.
- Estimated effort: 2–3 weeks.

Timeline is subject to contributor availability. All work is done in the open on the `main` branch.
