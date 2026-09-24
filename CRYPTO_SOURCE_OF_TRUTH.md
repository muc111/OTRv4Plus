<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Cryptographic source of truth

**Status: 0.6.0-experimental.** This names, for every cryptographic operation
the project performs, the one place it is implemented. It is checked by
`tests/test_crypto_source_of_truth.py`, which fails if a crate named here is
not a dependency of the core, or if a Rust type named here is not exported by
the built module.

## One crate, both platforms

There is **one** cryptographic implementation: the Rust crate `otrv4_core`
in `Rust/` (see `Rust/Cargo.toml`). Both platforms load the same crate, built
from the same source:

| | Termux (terminal clients) | Android app |
|---|---|---|
| Built by | `Rust/build.sh` (`maturin develop`) on the device | CI: `maturin build` for each ABI, wheels installed into the APK by Chaquopy |
| Loaded by | `otrv4+.py` (`import otrv4_core`) | the same `otrv4+.py`, copied into the APK by `syncPythonSources` |
| Protocol driver | `otrv4+.py` / `otrv4plus_xmpp.py` | `otrv4+.py` driven by `android_bridge/` |
| Kotlin | — | UI and platform. No protocol cryptography and no protocol key material. Its one use of cryptography is the at-rest vault (`security/KeystoreVault.kt`): AES-256-GCM under a non-exportable AndroidKeyStore key, for history, contacts and credentials |

The chain on each platform is therefore:

    Termux:  terminal client -> otrv4+.py -> otrv4_core (PyO3) -> Rust crate -> primitive
    Android: Compose UI -> ViewModel -> ChaquopyOtrCore.kt -> android_bridge -> otrv4+.py
             -> otrv4_core (PyO3) -> Rust crate -> primitive

Kotlin passes UI intent (a peer, a message, a passphrase typed into a dialog)
down and receives events up. It never receives a key, a handle to one, or a
shared secret. The only secret that crosses Kotlin is the SMP passphrase the
user types, which the bridge binds into `RustSMPVault` in one call and does
not retain (`android_bridge/app.py`, `bind_smp_secret`).

## Primitive by primitive

| Operation | Crate | Rust module | Python sees |
|---|---|---|---|
| X448 (DAKE, ratchet DH, voice) | `x448` | `key_handles.rs`, `ratchet.rs`, `dake.rs`, `voice.rs` | `X448KeyHandle` (no private getter); DH outputs never |
| ML-KEM-1024 (DAKE, brace KEM, voice) | `pqcrypto-mlkem` | `mlkem.rs`, `dake.rs`, `ratchet.rs`, `voice.rs` | `MlKem1024Keypair`; shared secrets never |
| ML-DSA-87 (DAKE authentication) | `pqcrypto-mldsa` | `mldsa.rs` | `MlDsa87KeyHandle`; signatures and public keys |
| Ed448 (identity, profile signatures, ring signature) | `ed448-goldilocks-plus` | `key_handles.rs`, `ring_sig.rs` | `Ed448KeyHandle` (no seed getter) |
| OTRv4 KDF, SHAKE-256 / SHA3 | `sha3` | `kdf.rs`, `dake.rs`, `ratchet.rs` | derived keys never |
| AES-256-GCM (messages, media, files, at-rest) | `aes-gcm` | `ratchet.rs`, `voice.rs`, `filetransfer.rs`, `aead.rs`, `identity.rs` | ciphertext; keys only for at-rest storage (see residuals) |
| Double ratchet, brace rotation | — | `ratchet.rs` | `RustDoubleRatchet`, state *tags* (not keys) |
| DAKE → ratchet key hand-over | — | `dake.rs` | `RustDAKE`; its unsendable DAKE output is consumed Rust-to-Rust by `from_dake_output` |
| SMP (hybrid PQ, constant-time modpow) | `crypto-bigint`, `num-bigint`, `argon2` | `smp.rs`, `smp_vault.rs` | `RustSMP`, `RustSMPVault` (no secret getter) |
| Voice key schedule (HKDF-SHA512) | `hkdf`, `sha2`, `hmac` | `voice.rs` | `RustVoiceKex`, `RustVoiceAgreement`, `RustVoiceRoot`, `RustVoiceCipher` |
| File-transfer keys and chunk AEAD | `aes-gcm`, `sha3` (via `kdf.rs`) | `filetransfer.rs` | handles, envelopes, ciphertext |
| Identity sealing (Termux XMPP only) | `aes-gcm` | `identity.rs`, `at_rest.rs` (`FileDek`) | sealed record bytes; the DEK is a Rust `FileDek` |
| At-rest SMP auto-respond store (Termux) | `aes-gcm`, `sha3`, `argon2` (legacy files only) | `at_rest.rs` (`SmpSecretStore`) | booleans and peer names; no passphrase getter |
| Randomness for keys | `rand`, `rand_core`, `getrandom` | all of the above (`OsRng`) | — |
| Zeroisation | `zeroize` | `secure_mem.rs` (`SecretBytes`) and every key type | explicit `zeroize()` / `discard()` methods |

There is no second implementation of any of these in shipped code. The last
ones were removed in 0.6.0-experimental: voice's pure-Python ML-KEM fallback
and Python HKDF key derivations, the `MLKEM1024BraceKEM` key wrapper, the
Python-key DAKE and ratchet paths (`_unpack_session_keys`, the
`_initialize_ratchet` fallback, `_kdf_ck`), and the archived pre-Rust engine
under `.attic/`. 0.7.0 removed the Python at-rest KDF (argon2-cffi /
`hashlib.scrypt`) with the key store it served.

## What Python still computes, and why it is not a second implementation

These run in Python on **public or revealed-by-design inputs**, or are not
cryptographic protections at all:

| Where | What | Why it stays |
|---|---|---|
| `otrv4+.py` fingerprints | SHA3-512 of a *public* key (`hashlib`) | display value of public data |
| `otrv4+.py` `kdf_1` in the DAKE | SHAKE-256 over the *public* DAKE1‖DAKE2 transcript | transcript digest the signature covers |
| `OTRv4DataMessage.compute_mac` | SHA3-512 outer MAC under MKmac | OTRv4 §4.4.2 publishes MKmac after use (deniability); the ratchet returns it for this check, and AES-GCM in Rust is the primary authentication |
| `otrv4plus_voice.py` | SHA-512 of the public call transcript (HKDF salt) | public input; the keys are derived in Rust |
| `otrv4plus_filetransfer.py` | SHA-256 of the file | integrity digest of content the user already holds |
| `_secure_file_destroy` | `os.urandom` overwrite bytes | not a key; see `ANDROID_WIPE_AND_EXIT.md` for what overwrite does and does not guarantee on flash |

Raw-secret primitives (`mlkem1024_keygen`/`encaps`/`decaps`,
`mldsa87_keygen`/`sign`) remain exported for known-answer and
cross-implementation tests. Production may call them only from the startup
self-test on throwaway keys (`android_bridge/diagnostics.py`);
`tests/test_rust_owns_secrets.py` enforces that allowlist.

## Residuals — secrets that are still Python or JVM objects

Recorded, not hidden (INV-08 is PARTIAL in `SECURITY_INVARIANTS.md`). As of
0.7.0 every remaining item is one Rust cannot own under this design:

1. **Passphrases and passwords the user types** exist as a Python `str` or a
   JVM `String` before anything can copy them, and neither runtime can wipe
   a string. SMP passphrases are copied into Rust at once. The XMPP account
   password is held by the transport and by slixmpp (whose SASL needs it on
   every reconnect) for the life of the connection, and dropped with it.
2. **MKmac** is returned to Python for the outer MAC check, as above: it is
   published to the peer after use by design, and it is not retained.

Closed in 0.7.0: the Python at-rest key store (`SecureKeyStorage`, a Python
master key over a write-only public record) is gone and writes no seed; the
Termux SMP auto-respond store is `otrv4_core.SmpSecretStore`; the Termux
identity DEK is `otrv4_core.FileDek`. argon2-cffi is no longer a dependency.

## Native code that is not cryptography

The Android build of `otrv4_core` (feature `android-opus`) statically links
**libopus 1.5.2** (BSD-3-Clause) as the voice codec. It holds no key: it
turns PCM into Opus frames before `voice.rs` seals them, and back after it
opens them. Its FFI is in the separate `Rust/opus-codec` crate, so
`otrv4_core` itself keeps `#![forbid(unsafe_code)]`. Termux uses `opuslib`
over Termux's libopus instead, and its build does not enable the feature.

## Build profile

`Rust/Cargo.toml` release profile: `panic = "abort"`, `overflow-checks =
true`, LTO, one codegen unit. An arithmetic overflow on attacker-controlled
input therefore ends the process rather than wrapping; the voice counters and
epochs are bounded before they reach Rust so that it cannot happen remotely
(`tests/test_voice_integer_bounds.py`). The `test-only-kdf` and
`legacy-dake-keys` features expose key material to Python and are refused by
`build.rs` unless explicitly allowed; `tests/test_release_guard.py` asserts a
built artifact exposes neither surface.

## Dependency advisories

`cargo audit` (RustSec) runs weekly and on every lock change with
`--deny warnings` (`.github/workflows/rust-audit.yml`). As of 2026-09-24:
**no vulnerabilities**. Five crates are flagged **unmaintained**, and they
matter here: `pqcrypto-mlkem`, `pqcrypto-mldsa`, `pqcrypto-traits` and
`pqcrypto-internals` are the ML-KEM-1024 and ML-DSA-87 implementations, and
the PQClean project they vendor is being archived (`paste` is a compile-time
helper of `pqcrypto-mldsa`). Unmaintained is not vulnerable, but it means no
future fix will arrive. Moving to a maintained implementation is a change of
cryptographic implementation, to be made on its own with the known-answer and
cross-implementation tests, not as a dependency bump. The decision and its
reasons are in `Rust/.cargo/audit.toml`.

## Documentation licence

This document, like the rest of the repository's documentation, is under the
repository's licence (AGPL-3.0-only OR `LicenseRef-OTRv4Plus-Commercial`).
Whether the specification documents should carry a separate documentation
licence is an open decision for the copyright holder, recorded in
`LICENSING_AUDIT.md`.
