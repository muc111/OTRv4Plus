<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Rust authority audit (before MLS stage 3)

Date 2026-09-24, repository at `74a204a` (main). Every finding below was
traced in the code, not taken from earlier documents. `CRYPTO_SOURCE_OF_TRUTH.md`
was checked against the code and is accurate except where noted.

**Result:** the primitives, key derivation, ratchet, SMP, voice and file
security are Rust-owned, and production never hands Python a session key.
**Three items are not yet Rust-authoritative** (R1 to R3 below), and **rooms
still send plaintext** (R4), which conflicts with the group rule. No code was
changed by this audit.

Classes: **A** authoritative Rust, **B** Python orchestration or FFI wrapper,
**C** legacy or dead code, **D** security-sensitive duplicate needing
remediation.

## 1. Rust modules (all in `Rust/src`, crate `otrv4_core`, unless noted)

| Area | Modules |
|---|---|
| DAKE (key agreement, session keys, phases) | `dake.rs` (`RustDAKE`, `DakeOutput`) |
| Ring signature (Auth-I) | `ring_sig.rs`, via `Ed448KeyHandle.ring_sign` in `key_handles.rs` |
| Double ratchet, brace KEM rotation, replay/skip window | `ratchet.rs` (`RustDoubleRatchet`), `header.rs` |
| SMP (hybrid PQ, state machine, secret binding, vault) | `smp.rs` (`RustSMP`), `smp_vault.rs` (`RustSMPVault`), `at_rest.rs` (`SmpSecretStore`) |
| Primitives | `key_handles.rs` (X448, Ed448), `mlkem.rs`, `mldsa.rs` (`MlDsa87KeyHandle`), `kdf.rs` (SHAKE-256), `aead.rs` (AES-256-GCM), `secure_mem.rs` (zeroize) |
| Voice security | `voice.rs` (`RustVoiceKex`, `RustVoiceAgreement`, `RustVoiceRoot`, `RustVoiceCipher`) |
| File-transfer security | `filetransfer.rs` (`RustFileSender`, `RustFileReceiver`) |
| Identity at rest (Termux) | `identity.rs`, `at_rest.rs` (`FileDek`) |
| MLS | `Rust/mls` (crate `otrv4-mls`, stage 2): `provider.rs`, `hpke_backend.rs`, `mlkem.rs`. Not linked into `otrv4_core`, not called from Python or Kotlin |

## 2. Callers

**Python calling Rust:** `otrv4+.py` (engine: `RustDAKEAdapter`,
`RustBackedDoubleRatchet`, session SMP, `RingSignature`, `MLDSA87Auth`),
`otrv4plus_voice.py`, `otrv4plus_filetransfer.py`, `otrv4plus_identity.py`,
`android_bridge/diagnostics.py` (startup self-test on throwaway keys),
`android_bridge/secure_store.py` (record format; AEAD in Rust).

**Kotlin calling Rust:** none directly. `bridge/ChaquopyOtrCore.kt` calls
`android_bridge` (Python), which calls `otrv4_core`. Kotlin sends user input
down (passwords, SMP passphrase, messages) and receives events, states and
public fingerprints. Kotlin's only cryptography is `security/KeystoreVault.kt`:
AES-256-GCM under a non-exportable AndroidKeyStore key for history, contacts
and credentials at rest. That key lives in the device's keystore hardware and
cannot be held by Rust; this is platform storage, not protocol cryptography.

## 3. Call paths

| # | Path | Rust (authority) | Python / Kotlin role | Secrets live | Destroyed by |
|---|---|---|---|---|---|
| 1 | OTR session creation | `RustDAKE.sign_profile_body_and_construct_with_handles` | constructs with key handles | Rust handles | `RustDAKEAdapter.zeroize` |
| 2 | DAKE | `generate_dake1`, `process_dake1`, `generate_dake2_output`, `process_dake2_output`, `assemble_dake3` | **DAKE3 signing and verification logic, and the ESTABLISHED transition (R1)** | Rust (`DakeOutput`) | `DakeOutput.discard`, `RustDAKE.zeroize` |
| 3 | Message encrypt/decrypt | `RustDoubleRatchet.encrypt`, `decrypt_same_dh`, `decrypt_new_dh` (AES-256-GCM) | encodes the wire message; **outer MAC under MKmac in Python (R2)** | Rust; MKmac per message in Python | ratchet `zeroize` on session end/wipe |
| 4 | Ratchet advance | `send_ratchet` (X448 inside Rust), `brace_encapsulate`, `brace_decapsulate` | calls; mirrors hold one-way tags only | Rust | as 3 |
| 5 | SMP initiation | `RustSMP.generate_smp1` | calls | Rust | `abort`/`destroy` |
| 6 | SMP response | `process_smp1_generate_smp2`, `hold_smp1`, `resume_held_smp1_generate_smp2` | calls | Rust | as 5 |
| 7 | SMP verification | `process_smp2..4`, `is_verified`, `is_failed` | reads the result; UI state mirror | Rust | as 5 |
| 8 | SMP secret binding | `RustSMPVault.store_from_bytearray` then `set_secret_from_vault`; `SmpSecretStore.bind_into` | passphrase `str` exists briefly (residual, documented); bytearray zeroed | Rust vault | `smp_vault.clear`, wipe |
| 9 | Voice security | `RustVoiceKex` then `RustVoiceAgreement`, `RustVoiceRoot`, `RustVoiceCipher` (HKDF-SHA512, AES-256-GCM, rekey, epochs) | compares public confirmation tags; SHA-512 of the public transcript | Rust | `CallBridge.shutdown` then key schedule zeroize |
| 10 | File encryption | `RustFileSender`, `RustFileReceiver` (key from the DAKE extra symmetric key, in Rust) | chunking, I/O, SHA-256 of file content | Rust | `files.shutdown` then zeroize |
| 11 | Secure wipe | every `zeroize`/`destroy` above | `OtrApp.wipe` orders it: calls, transfers, engine on the loop thread, transport, disk; Kotlin clears the Keystore vault | n/a | n/a |
| 12 | MLS group creation | `Rust/mls` only, in tests | none yet | Rust (`MemoryStorage`, R5) | not yet wired to wipe |
| 13 | MLS encrypt/decrypt | `Rust/mls` only, in tests | none yet | Rust | not yet wired |

## 4. Python findings

| Finding | Where | Live? | Class |
|---|---|---|---|
| DAKE3 ring-sig + ML-DSA verification, PQ-downgrade check and ESTABLISHED decided in Python; Rust `process_dake3` never called (its transcript input differs from what Python signs, so it cannot be called as is). Uses Rust primitives, but the protocol decision is Python's | `otrv4+.py` `RustDAKEAdapter.process_dake3`, `generate_dake3` | live | **D (R1)** |
| Python fallback that assembles DAKE3 bytes if `assemble_dake3` fails | `generate_dake3` | live fallback | **D (R1)** |
| Outer data-message MAC: SHA3-512(MKmac ‖ header ‖ ct) computed and checked in Python; MKmac returned by Rust per message | `OTRv4DataMessage.compute_mac`/`verify_mac`; `RustDoubleRatchet.encrypt`/`decrypt_*` return `mac_key` | live | **D (R2)** (documented residual; AES-GCM in Rust is the primary authentication) |
| Raw-key constructors still exported in release builds: `RustDoubleRatchet(root, cks, ckr, brace…)`, `RustDAKE(ik, prekey, mldsa_priv…)`, `new_from_bytearrays`, `py_ring_sign(seed…)`, `RustVoiceRoot.from_initial_agreement(raw…)`, `aes256gcm_*(key…)`, `mlkem1024_*`, `mldsa87_*` | `ratchet.rs`, `dake.rs`, `ring_sig.rs`, `voice.rs`, `aead.rs`, `mlkem.rs`, `mldsa.rs` | callable, no production caller (enforced by `test_rust_owns_secrets.py` allowlist) | **D (R3)** |
| `RustBackedDoubleRatchet.__init__(root_key…)`: derives chain keys with Python `kdf_1` and keeps them in `_RatchetKeyStore` | `otrv4+.py` | tests only; production uses `from_dake_output` | **C** (part of R3) |
| `derive_voice_root`, `derive_rekey_root` taking raw shared secrets | `otrv4plus_voice.py` | no production caller | **C** (part of R3) |
| `smp_engine_compat.py`: pure-Python SMP KDF copy | repo root | tests only; excluded from the APK | **C** |
| `otrv4plus_omemo.py`: recipient-set rules, no crypto, but its text plans `python-omemo` as the group ratchet, contrary to Rust MLS | repo root | no importer, yet packaged into the APK | **C** |
| `integrate_voice_v3.py`, `otrv4_testlib.py`, root `test_*.py` | repo root | tooling/tests; excluded from the APK | **C** |
| `kdf_1` over the public DAKE1‖DAKE2 transcript; SHA3-512 fingerprints of public keys; SHA-256 of file content; SHA-512 of the public voice transcript | various | live | **B** (public inputs) |
| `DAKEState`, `SMPState`, session state enums | `otrv4+.py` | live | **B** display mirrors, except the DAKE ESTABLISHED gate (R1) |
| Stale docstrings claiming the ring signature is made in Python | `RustDAKEAdapter`, `generate_dake3` | text only | **C** (wrong comment; it is Rust) |

No Python implementation of X448, ML-KEM, ML-DSA, Ed448, AES-GCM, HKDF, the
ratchet, SMP arithmetic or voice keys exists in shipped code.

## 5. Secret crossings

**Rust to Python:** MKmac, per data message (R2). Nothing else in production:
session, chain, root, brace, voice, file and SMP keys stay in Rust; ratchet
"mirrors" are SHA3-256 tags. User-typed passphrases and the XMPP password go
the other way and exist briefly as Python `str` (documented residual).

**Rust to Kotlin:** none. Kotlin receives public fingerprints and states only.

## 6. Wipe & Exit

Destroys, in Rust: ratchets, DAKE state and unconsumed `DakeOutput`, SMP state
and vaults, identity handles, voice key schedules, file keys. Tested by
`tests/test_wipe_and_exit.py` and the Kotlin wipe tests. **MLS state is not
covered because the app has none yet**; stage 4 must add it.

## 7. Remediation list (not started)

* **R1, DAKE3 into Rust.** Rust computes the Auth-I digest from its own
  transcript, signs DAKE3 with the identity and ML-DSA handles, and
  `process_dake3` verifies it; Python mirrors the phase. Must stay
  byte-identical on the wire (Termux peers), proven with a recorded DAKE3.
  Delete the Python assembly fallback.
* **R2, outer MAC into Rust.** The ratchet computes and verifies the outer
  MAC over bytes Python passes in, and stops returning MKmac. Revealed keys
  are still published after use, as OTRv4 requires.
* **R3, shrink the release surface.** Put the raw-key constructors and
  primitives behind a test feature (like `legacy-dake-keys`) or a separate
  test module, and move the Python test-only paths (`__init__` raw-key ratchet,
  `derive_voice_root`, `smp_engine_compat.py`) into `tests/`.
* **R4, rooms send plaintext.** The app and Termux send room messages as
  plain MUC, labelled "not end-to-end encrypted". The group rule ("no
  plaintext group fallback") means either refusing to send in ordinary rooms
  until MLS is wired in (stage 3), or keeping labelled plaintext rooms until
  then. Owner decision.
* **R5, MLS storage.** OpenMLS's `MemoryStorage` keeps group secrets as
  serde_json bytes in a `HashMap` and never zeroizes them. Stage 3/4 needs
  its own `StorageProvider`: zeroizing values, no JSON for secret entities,
  encrypted persistence, destroyed by Wipe & Exit.
* Remove `otrv4plus_omemo.py` from the APK and mark it superseded by MLS.
