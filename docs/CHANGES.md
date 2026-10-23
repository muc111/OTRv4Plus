# OTRv4+ audit fixes: applied changes

AI-assisted edits, directed by Adam. These resolve findings from the core
audit (otrv4plus_rust_core_audit.md, incl. Addendum A). The Rust changes are
UNBUILT here (no toolchain in the edit environment); they compile in your head
but must be built and tested before you ship. The Python file was syntax
checked with py_compile. This is not a substitute for a professional human
audit, fuzzing, or formal verification.

Seven files changed: ring_sig.rs, dake.rs, kdf.rs, smp.rs, ratchet.rs,
mldsa.rs, otrv4_.py. No other source files were touched. otrv4plus_xmpp.py was
not modified (it has no DAKE logic of its own and the secret scan was clean).
otrv4plus.py was left alone (older/alternate file, not this round's target).

## Applied

### C1 (CRITICAL) ring_sig.rs: per-signature, message-bound ephemeral
`derive_ephemeral_scalar` now takes `(seed, msg)` and computes
`t1 = wide_reduce(SHAKE256("OTRv4-ringsig-nonce-v1" || prefix || rnd32 || msg))`
where `prefix = SHAKE256("OTRv4-ringsig-nonce-prefix-v1" || seed)` and `rnd32`
is fresh `OsRng`. Full 114-byte wide reduction, so the nonce is uniform (no
~2^-10 bias the old 57-byte path had). Repeating `(seed, msg)` still yields a
fresh nonce (hedging); a dead RNG degrades to deterministic-but-message-bound,
which is still safe against the reuse attack as long as messages differ.
Verification is unchanged, so signatures stay wire compatible. The
`t1_is_deterministic` test was replaced with `t1_is_not_reused_across_signatures`
(asserts c1 differs across messages, signatures differ for the same (seed,msg),
and both still verify).

### H1 (HIGH) dake.rs: removed the unsound ring verifier
Deleted `verify_ring_signature` (challenge omitted both public keys and the
usage tag, and it accepted on an OR of two conditions) and the now-unused
`scalar_from_wide_bytes`. `process_dake3` now routes through the single sound
verifier `crate::ring_sig::ring_verify_bytes`, called with the correct argument
order for the responder: `(peer_identity_pub, our_identity_pub, transcript,
sigma)` (the signer signs A1 = own identity, A2 = peer). This path was dead code
in the current Python flow, but it was a refactor landmine; it is now gone.

### H2 (HIGH) dake.rs + otrv4_.py: ML-DSA-87 downgrade protection
If the peer committed an ML-DSA-87 key earlier in the handshake, its DAKE3
signature is now mandatory. The ring signature does not cover the DAKE3 flag
byte, so a MITM could flip 0x01 to 0x00 and strip PQ auth.
- dake.rs `process_dake3`: `mldsa_required = self.peer_mldsa_pub.is_some()`;
  reject when `mldsa_required && flag != 0x01`. Also added a DAKE3 message-type
  byte check.
- otrv4_.py `process_dake3` (the live path): if `_remote_mldsa_pub is not None`
  and ML-DSA is available locally, a stripped flag is rejected; otherwise the
  signature is verified as before.

### H3 / PY1 (HIGH) dake.rs + otrv4_.py: client-profile signature is enforced
The profile self-signature covers the prekey, so verifying it binds identity to
prekey. The bug was that the verification result was discarded on the initiator.
- otrv4_.py `process_dake2` (PY1, the live trigger): previously it swallowed a
  `ClientProfile.decode` failure (`remote_profile = None`) and still reached
  ESTABLISHED, trusting the Rust-extracted identity. It now aborts when
  `remote_profile is None` and binds the trusted identity to the VERIFIED
  profile (`remote_profile.identity_pub_bytes`), cross-checking against the
  Rust extraction with `hmac.compare_digest`. This also restores the expiry and
  downgrade checks that the swallow had bypassed.
- otrv4_.py `process_dake1`: added the same abort-on-None guard (defense in
  depth; already backstopped by `generate_dake2` and `process_dake3`).
- dake.rs `extract_identity_from_profile` (H3, core-side defense in depth): now
  verifies the profile body's Ed448 self-signature (RFC 8032 empty context, the
  same framing as `verify_ed448_sig`) before returning the identity, using
  SafeSlice for bounds. Note: the Rust side does NOT check expiry (left to
  Python to avoid clock-skew breakage).

### M1 (MEDIUM) smp.rs: tighter group-element validation + subgroup check
`validate_group_elem` now rejects outside `[2, p-2]` (was `[2, p-1]`, which
admitted the order-2 element p-1) and adds a prime-order subgroup test
`v^q mod p == 1`. Verified safe for this exact RFC 3526 3072-bit prime:
p = 7 (mod 8), so g = 2 is a quadratic residue and generates the order-q
subgroup; every honest protocol value satisfies `x^q == 1`, so the check does
not reject legitimate inputs. (Confirmed numerically before applying.)

### L3 (LOW) smp.rs: validate rb in process_smp4
Added `validate_group_elem(rb)` before use (the ZKP already constrains it; this
fails fast on malformed input, matching the other SMP messages).

### M2 (MEDIUM) kdf.rs + dake.rs: zeroize derived key material
The heap copies of derived keys are now wiped after being copied into the fixed
arrays: `kdf_chain`, `kdf_root`, `kdf_brace_rotate`, `derive_ratchet_keys`,
`derive_ssid`, `kdf_secret` (kdf.rs), and the `root_seed`/`extra_raw` seeds in
`derive_session_keys` (dake.rs). Inputs were already zeroized; this closes the
output side.

### L2 (LOW) ratchet.rs: keep skipped keys across a DH-ratchet step
`decrypt_new_dh` previously discarded the skipped message keys of the new
receiving chain, so out-of-order messages arriving after a DH ratchet were
unrecoverable. It now stores them in `self.skipped` keyed by
`SkipId { dh_pub, msg_num }` with `MAX_MESSAGE_KEYS` eviction.

### I1 / I3 (INFO) ratchet.rs, mldsa.rs, smp.rs: hardening and doc fixes
- ratchet.rs `zeroize`: `unwrap()` -> `expect("dummy ratchet uses fixed
  non-zero keys")` (infallible; satisfies `#![deny(clippy::unwrap_used)]`).
- mldsa.rs: doc typo "ML-KEM-1024 parameter set" -> "ML-DSA-87 parameter set".
- smp.rs: error string "10-minute limit" -> "45-minute limit" (matches
  SESSION_TIMEOUT_SECS = 2700).

## Deferred (and why)

- M3 (remove legacy key-exposing dake.rs methods, e.g. `generate_dake2` /
  `process_dake2` / `get_session_keys` that hand session keys to Python as
  PyBytes): NOT removed. The Python adapter still uses these as a fallback when
  the opaque `process_dake2_output` API is absent. Removing them needs a
  coordinated Python migration first, or it breaks that path. Track separately.
- M4 (misuse-resistant at-rest AEAD, e.g. XChaCha20-Poly1305 or AES-GCM-SIV):
  NOT added. Needs a new crate dependency, a Cargo.toml change, and a Python
  storage rewrite; cannot be built or tested here.
- L1 (MAC-revelation deniability: reveal_mac_keys currently reveals all-zeros):
  NOT changed. This is a design decision and the change is invasive.
- L4 (SafeSlice across all DAKE parsers): PARTIAL. Done in the H3 area
  (`extract_identity_from_profile`); the remaining raw-indexed parsers are
  guarded and were left to avoid destabilizing working code in an unbuildable
  environment.
- L5 (zeroize secret scalars): PARTIAL. The new ring_sig.rs ephemeral wipes its
  byte buffers (prefix/rnd/wide). The `Scalar` values themselves were not
  zeroized because the curve crate's `Scalar` may not impl `Zeroize` cleanly and
  this cannot be build-tested here.

## REQUIRED before you ship

Rust is unbuilt here. Build and test it:

    cargo build --release
    cargo test  --release

Pay attention to these in particular:
1. `ring_sig::tests::t1_is_not_reused_across_signatures` must pass (C1).
2. The SMP unit tests / KATs must pass with the new subgroup check (M1). If any
   legitimate SMP vector now fails `validate_group_elem`, stop and tell me; that
   would mean the subgroup assumption is wrong for an input I did not model.
3. A full DAKE round-trip on real Python-signed profiles must succeed end to
   end. This confirms the new Rust `extract_identity_from_profile` does NOT
   reject legitimate profiles (H3) and that PY1 does not break the happy path.
   Run a live initiator/responder handshake over both IRC and XMPP transports.
4. ML-DSA hybrid handshake must still establish, and a flag-stripped DAKE3 must
   now fail (H2). Test both classical-only and hybrid peers.
5. Out-of-order delivery after a DH ratchet should now decrypt (L2).

Then your existing Python suite:

    # whatever you normally run, e.g.
    python3 -m pytest -q

## git (review, then commit; nothing pushed)

    git status
    git diff -- ring_sig.rs dake.rs kdf.rs smp.rs ratchet.rs mldsa.rs otrv4_.py
    git add ring_sig.rs dake.rs kdf.rs smp.rs ratchet.rs mldsa.rs otrv4_.py
    git commit -m "Security: fix ring-sig nonce reuse (C1), DAKE downgrade/profile auth (H1/H2/H3/PY1), SMP subgroup (M1), KDF/ratchet hardening"

Do not push until the build is green and the interop checks above pass.
