# OTRv4+ audit handoff

Prepared to brief a professional security audit. Read this first. It states
what an AI-assisted source review did and did NOT cover, the architecture and
trust boundaries, the issues already fixed, the properties checked by hand, and
where paid expert time should go. The goal is to spend your hours on what the
prior review could not reach (fuzzing, constant-time measurement, formal
modelling, crate internals), not on the bugs already found.

## 0. Honest scope of the prior review

The prior review was an AI-assisted SOURCE read of the 15-file Rust
cryptographic core plus the DAKE / SMP / client-profile portions of the Python
adapter. It is NOT a substitute for this audit. It could not, and did not:

- build the code, run the test suite, or do any dynamic analysis;
- fuzz any parser;
- measure constant-time behaviour on real hardware (no timing or cache work);
- inspect the internals of the underlying crypto crates (trusted as-is);
- model the protocol formally;
- audit the transport and framing layers in depth (see section 8).

Treat every claim below as "argued from reading the source," to be confirmed
by you.

## 1. What the software is

Post-quantum-hybrid OTR-style end-to-end encrypted messaging.

- Identity / DAKE auth: Ed448 (RFC 8032) plus a 1-of-2 Ed448 ring signature for
  deniability, plus optional ML-DSA-87 (FIPS 204) for PQ identity.
- Key agreement: X448 (RFC 7748) plus ML-KEM-1024 (FIPS 203), hybrid-combined.
- Message ratchet: Double Ratchet, AES-256-GCM, HKDF/SHAKE-256 KDF.
- Identity verification: SMP (Socialist Millionaire) over the RFC 3526 3072-bit
  MODP group, generator 2, with a PQ variant.
- Transports: IRC and XMPP, over clearnet / Tor / I2P (i2pd SAM, SOCKS5),
  with application-level fragmentation.
- Runtime: Termux / Android; Rust core compiled as a PyO3 module
  (imported as `otrv4_core`), orchestrated by Python.

## 2. Architecture and trust boundaries

Two layers:

1. Rust core (the 15 .rs files). `#![forbid(unsafe_code)]` holds (no `unsafe`
   anywhere). Owns: AEAD, KDF, ML-KEM, ML-DSA, ring signature, DAKE state,
   ratchet, SMP arithmetic (constant-time modexp via crypto-bigint U3072
   DynResidue). Secrets are `SecretBytes` / `ZeroizeOnDrop`.
2. Python adapter (`otrv4_.py`, ~13.7k lines; XMPP transport
   `otrv4plus_xmpp.py`). Orchestrates the DAKE, builds and verifies the ring
   signature (calling the Rust verifier `py_ring_verify`), parses client
   profiles, drives SMP, and owns ALL transport / framing / fragmentation.

Key trust-boundary facts the auditor must keep in mind:

- The DAKE is ORCHESTRATED in Python. The Rust `DakeState::process_dake3` is
  present but NOT on the live path; Python does DAKE3 verification itself.
- The ring signature is VERIFIED through Rust (`ring_sig::ring_verify_bytes`),
  but the message it signs is assembled in Python.
- The at-rest and wire nonce-uniqueness obligations for the stateless Rust AEAD
  are delegated to the Python caller (see section 7, M4).
- Trusted dependencies (NOT reviewed): ed448-goldilocks-plus, pqcrypto-*
  (ML-KEM / ML-DSA), x448, crypto-bigint, num-bigint, sha3, aes-gcm, zeroize,
  subtle, getrandom. A supply-chain and version-pinning review is in scope.

## 3. Security goals

Confidentiality, integrity, forward secrecy and post-compromise security of
messages; mutual authentication of long-term identities via the DAKE;
participation deniability via the ring signature and MAC-key revelation;
post-quantum protection of both confidentiality (ML-KEM) and identity
authentication (ML-DSA) under a harvest-now-decrypt-later adversary; identity
confirmation via SMP without revealing the shared secret.

## 4. Adversary

Active network man-in-the-middle on all transports; able to inject, drop,
reorder, fragment, replay, and modify. Assumed able to run a future
cryptographically-relevant quantum computer against recorded traffic (hence the
PQ layer). NOT assumed to have endpoint code execution. Side-channel adversary
(timing / cache) is IN SCOPE for your audit and was NOT covered by the prior
review.

## 5. Issues found and fixed in this round

Full detail in `otrv4plus_rust_core_audit.md` and `CHANGES.md`. Summary:

- C1 (CRITICAL, ring_sig.rs): ring-signature ephemeral nonce was derived from
  the long-term seed only, so it repeated across signatures and leaked the
  identity scalar from two signatures. Now per-signature, message-bound, and
  hedged with fresh OsRng, full wide reduction. Verification unchanged, so it is
  wire-compatible. PLEASE re-derive the nonce construction and confirm no
  residual reuse and no bias.
- H1 (dake.rs): removed an unsound second ring verifier (challenge omitted the
  public keys and usage tag, OR-of-two acceptance). All verification now goes
  through the single sound verifier. It was dead code on the live path, but it
  was a refactor landmine.
- H2 (dake.rs + otrv4_.py): an advertised/committed ML-DSA-87 key now makes the
  DAKE3 signature mandatory; the prior code allowed a one-byte flag flip to
  strip PQ auth.
- H3 / PY1 (otrv4_.py + dake.rs): the initiator previously swallowed a client-
  profile signature-verification failure and established anyway, trusting an
  unverified identity. Now it aborts and binds identity to the verified profile;
  the Rust core also verifies the profile self-signature as defense in depth.
- M1 (smp.rs): group-element validation tightened to [2, p-2] plus a prime-order
  subgroup check (v^q == 1); verified numerically that for this prime
  (p = 7 mod 8, g = 2 is a QR generating the order-q subgroup) the check accepts
  all honest values. CONFIRM against your SMP KATs.
- M2 (kdf.rs + dake.rs): derived key material is now zeroized on the output side.
- L2/L3/I1/I3: skipped-key retention across a DH ratchet, SMP rb validation,
  an infallible-unwrap to expect, doc/string fixes.

## 6. Properties checked by hand (please re-verify)

These were argued sound from the source; they are the load-bearing assumptions
and deserve independent confirmation:

1. Ring verifier soundness. Standard 1-of-2 OR-proof: challenge
   `c = H(usage ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2)`, verify `T1' = r1·G + c1·A1`,
   `T2' = r2·G + c2·A2`, accept iff `c1 + c2 == c`. Binds both public keys and a
   usage tag.
2. ML-DSA commitment cannot be silently stripped. The committed key is appended
   to the transcript (dake.rs) and the DAKE3 signatures are over the full
   transcript, so stripping it diverges the transcript and the ring signature
   fails; in the DAKE2 direction it is also covered by the MAC.
3. Hybrid secret. `mixed_secret = KDF(dh1 ‖ dh2 ‖ dh3 ‖ mlkem_ss)`, secure if
   either X448 or ML-KEM holds; the ML-KEM ciphertext is authenticated (tamper
   or FIPS 203 implicit rejection both break the DAKE2 MAC).
4. Python/Rust transcript consistency. Both sides feed
   `kdf(raw_dake1 ‖ raw_dake2)`; sender stores pre-base64 bytes, receiver stores
   post-base64 bytes, base64 round-trips exactly, so the signed bytes are
   identical. No re-serialization on the verify side.

## 7. Known limitations and deferred items

- M3: legacy Rust DAKE methods that hand session keys to Python as PyBytes are
  still present (the Python adapter uses them as a fallback). Removing them needs
  a coordinated Python migration. Decide whether to remove or to gate them.
- M4: the Rust AEAD is stateless; at-rest nonce uniqueness is the Python
  caller's responsibility (random-nonce birthday bound). A misuse-resistant
  scheme (XChaCha20-Poly1305 or AES-GCM-SIV) was NOT added because it needs a
  new dependency, a Cargo.toml change, and a storage rewrite that could not be
  built/tested here. Recommended for the hardened release; please scope it.
- L1: MAC-key revelation currently reveals all-zeros, so the intended OTR
  deniability property is not achieved. Design decision; confirm the deniability
  goal and implement or drop the machinery.
- Wire-format-locked items NOT changed because they would break compatibility
  with deployed peers without a version bump: (a) the ring CHALLENGE uses a
  57-byte reduction with a ~2^-10 bias (cosmetic, does not leak the key);
  (b) the optional ML-DSA public key is detected by leftover length rather than
  an explicit presence flag (safe today because the MAC / transcript authenticate
  the byte layout, fragile if the format ever gains trailing fields). Consider a
  versioned wire revision that fixes both.
- L4/L5 partial: most DAKE parsers use guarded raw indexing rather than the
  SafeSlice helper; secret `Scalar` values are not all zeroized (the curve
  crate's Scalar zeroization could not be build-tested).

## 8. Recommended scope for the paid audit (where the prior review could NOT go)

Highest value first:

1. Transport and framing in Python (NOT reviewed). The I2P SAM bridge, the
   SOCKS5 handshake, IRC and XMPP message framing/parsing, base64 handling, and
   especially fragmentation / reassembly. Look for: unbounded buffering and
   fragment-buffer exhaustion (DoS), reassembly logic errors, parser crashes on
   hostile input, and any place a network peer controls an allocation size or a
   loop bound. This is historically where this codebase's bugs have appeared.
2. Constant-time / side channels. Measure (do not eyeball) the SMP arithmetic,
   the ring-signature scalar operations, MAC and tag comparisons, and profile
   parsing, on the actual Termux/Android target. dudect-style or equivalent.
3. Fuzzing. Harness every wire parser: DAKE1/2/3, client profile, SMP messages,
   ratchet headers, and the fragmentation layer. Both Rust (cargo-fuzz) and the
   Python parsers.
4. Crate / supply chain. Review and pin ed448-goldilocks-plus, pqcrypto-*,
   x448, crypto-bigint, aes-gcm; confirm the ML-KEM/ML-DSA implementations are
   the intended FIPS parameter sets and are themselves audited.
5. Formal / symbolic model. A Tamarin or ProVerif model of the DAKE to confirm
   mutual authentication, the deniability claim, and downgrade resistance
   (including the ML-DSA-mandatory logic and the profile-binding fix).
6. RNG and key storage. Entropy source and seeding on Android/Termux; at-rest
   key storage (Argon2id) parameters and the M4 nonce question.
7. Concurrency. Any threading in the Python client around session state and the
   SMP / ratchet objects.

## 9. Build and test

No Rust toolchain was available in the review environment, so the Rust changes
ship UNBUILT and must be built and tested before any rollout:

    cargo build --release
    cargo test  --release
    # then the Python suite, e.g.
    python3 -m pytest -q

Gate the release on, at minimum:
1. `ring_sig::tests::t1_is_not_reused_across_signatures` passes.
2. SMP KATs pass with the new subgroup check (a legitimate value failing
   `validate_group_elem` would mean the subgroup assumption is wrong).
3. A live initiator/responder DAKE round-trip on real Python-signed profiles
   succeeds over BOTH IRC and XMPP (confirms the new profile-signature check and
   PY1 do not reject the happy path).
4. A flag-stripped DAKE3 now fails; classical-only and hybrid peers both work.
5. Out-of-order delivery after a DH ratchet decrypts.

## 10. Assumptions to challenge

If any of these is false, conclusions above may not hold:
- The trusted crates correctly and constant-time-ly implement their primitives.
- base64 decoding is deterministic and the transport delivers the signed bytes
  unaltered or the signature fails.
- The Python adapter is the only DAKE orchestrator (no path calls the Rust DAKE
  directly and bypasses the Python profile / ML-DSA checks).
- The RFC 3526 group parameters and the SMP order constant match the code's
  `SMP_PRIME` / `SMP_ORDER`.
- The reviewer's reading of which code paths are live (vs dead) matches the
  shipped build configuration and feature flags.
