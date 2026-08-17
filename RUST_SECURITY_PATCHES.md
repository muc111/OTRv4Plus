# Rust core — security patches (R7, R8, R9)

Apply to `Rust/src/dake.rs`, then rebuild:

```bash
cd ~/OTRv4Plus/Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so
```

**These change the DAKE1 wire format. Both ends must be updated together.**
An old client's DAKE1 will be read as "no ML-DSA key present", so the
handshake still completes — it just loses PQ signature binding until both
sides are on the new build. That is the safe direction to fail.

---

## R7 — HIGH: unauthenticated remote DoS on session establishment

**`dake.rs`, `process_dake1`, around line 361.**

DAKE1 detects the optional ML-DSA public key by trailing length alone, and
DAKE1 carries no MAC — it is the first message, so there is nothing to
authenticate it with:

```rust
// optional ML-DSA pub
if data.len() - off >= MLDSA_PUB_SIZE {
    self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec());
}
```

Append 2592 arbitrary bytes to any DAKE1 in flight and the responder records
a garbage `peer_mldsa_pub`. At DAKE3 that sets `mldsa_required = true`, so a
genuine initiator without an ML-DSA key sends flag `0x00` and the handshake
aborts with *"ML-DSA signature stripped: peer committed a PQ key"*.

Cost to the attacker: 2592 bytes and no key material. Effect: OTR sessions
never form, so every downstream protection — SMP gating, rate limits, the
voice state machine — is bypassed by never being reached. The error message
blames the peer's PQ key, so the user misdiagnoses it as an attack on their
contact.

`assemble_dake3` already solves this with an explicit presence flag, and
`process_dake2` bounds the parse by the MAC position. DAKE1 is the only one
of the three that does neither.

### Patch

In **`assemble_dake1`**, add the flag before the key:

```rust
// R7: explicit presence flag, matching assemble_dake3. Length-sniffing an
// optional trailing field in an unauthenticated message lets anyone forge
// its presence.
match self.local_mldsa_pub.as_ref() {
    Some(pk) => {
        msg.push(0x01);
        msg.extend_from_slice(pk);
    }
    None => msg.push(0x00),
}
```

In **`process_dake1`**, replace the length sniff:

```rust
// R7: presence is declared, not inferred. A truncated or absent flag means
// "no key", and a flag of 0x01 must be followed by exactly MLDSA_PUB_SIZE
// bytes or the message is malformed.
self.peer_mldsa_pub = match data.get(off) {
    None | Some(0x00) => None,
    Some(0x01) => {
        off += 1;
        if data.len() - off < MLDSA_PUB_SIZE {
            return Err(OtrError::Dake(
                "DAKE1 declares an ML-DSA key but is truncated"));
        }
        let pk = data[off..off + MLDSA_PUB_SIZE].to_vec();
        off += MLDSA_PUB_SIZE;
        Some(pk)
    }
    Some(_) => {
        return Err(OtrError::Dake("DAKE1 ML-DSA presence flag is invalid"));
    }
};
```

Note this still does not *authenticate* DAKE1 — nothing can, it is the first
message. What it does is remove the attacker's ability to fabricate a
commitment. Stripping the real flag now diverges the transcript, which the
ring signature already catches, so the handshake fails closed rather than
being steerable.

---

## R8 — MEDIUM: raw shared secrets are never zeroized

**`dake.rs`, `generate_dake2` / `process_dake2`, around line 385.**

```rust
let mut combined = Vec::new();          // dh1||dh2||dh3||mlkem_ss = 200 bytes
combined.extend_from_slice(&dh1);
combined.extend_from_slice(&dh2);
combined.extend_from_slice(&dh3);
combined.extend_from_slice(&mlkem_ss);
let mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
let mac_key      = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);
```

All plain `Vec<u8>`, dropped without wiping — and `x448_dh` returns `Vec<u8>`
too, so `dh1`/`dh2`/`dh3` leak as well. `kdf.rs` wipes every heap copy it
makes under an "audit M2" comment, and `derive_session_keys` twenty lines
below zeroizes its temporaries. This is the one function holding *every* raw
shared secret at once, and the one that does not.

### Patch

```rust
use zeroize::Zeroize;

let mut combined = Vec::with_capacity(3 * 56 + 32);
combined.extend_from_slice(&dh1);
combined.extend_from_slice(&dh2);
combined.extend_from_slice(&dh3);
combined.extend_from_slice(&mlkem_ss);

let mut mixed_secret = kdf::kdf_1(usage::SHARED_SECRET, &combined, 64);
let mut mac_key      = kdf::kdf_1(usage::DAKE_MAC_KEY, &mixed_secret, 64);

// R8: wipe every raw secret before it leaves scope. Must also run on the
// error paths below — use a guard, or zeroize before each `return Err`.
combined.zeroize();
dh1.zeroize();
dh2.zeroize();
dh3.zeroize();
mlkem_ss.zeroize();
```

`mixed_secret` and `mac_key` are consumed downstream, so zeroize them at the
end of their real lifetime rather than here. The cleanest form is a small
`Zeroizing<Vec<u8>>` wrapper (`zeroize::Zeroizing`) which handles every exit
path including `?` propagation:

```rust
use zeroize::Zeroizing;
let combined = Zeroizing::new({
    let mut v = Vec::with_capacity(3 * 56 + 32);
    v.extend_from_slice(&dh1);
    v.extend_from_slice(&dh2);
    v.extend_from_slice(&dh3);
    v.extend_from_slice(&mlkem_ss);
    v
});
```

`zeroize` is already a direct dependency with the `alloc` feature, so this
adds nothing to the build.

---

## R9 — LOW: brittle bounds arithmetic in DAKE1

**`dake.rs`, `process_dake1`, around line 352.**

```rust
let num_versions = data[off + 1] as usize;
```

Protected only by a hand-computed `+ 3` in the length guard on line 344. It
is correct today by a margin of two bytes (`off + 1 = 1626`, minimum length
1628). Change `X448_PUB_SIZE`, the header layout, or the guard and it becomes
an out-of-bounds index — which, with `panic = "abort"` in the release
profile, kills the whole Python process from a remote message.

### Patch

```rust
// R9: derive the bound instead of hand-computing the margin, and index
// through get() so a layout change is a clean error rather than an abort.
const DAKE1_FIXED_PREFIX: usize = 1 + X448_PUB_SIZE + MLKEM_EK_SIZE;
if data.len() < DAKE1_FIXED_PREFIX + 2 {
    return Err(OtrError::Dake("DAKE1 too short for a client profile"));
}
let num_versions = *data.get(off + 1)
    .ok_or(OtrError::Dake("DAKE1 truncated in the client profile"))? as usize;
```

---

## Also worth doing

**Make `cargo test` work.** `pyo3/extension-module` in `default` makes it
fail at link time, so 35 `#[test]` functions have never run and `dake.rs` —
where all three findings above live — has none at all. See the corrected
`Cargo.toml`: move `extension-module` out of `default`, add `rlib` to
`crate-type`, set `rust-version = "1.85"`.

Then add tests for exactly these three:

```rust
#[test]
fn dake1_with_appended_garbage_is_rejected_not_misread() { /* R7 */ }

#[test]
fn dake1_declaring_a_key_but_truncated_is_rejected() { /* R7 */ }

#[test]
fn dake1_shorter_than_the_fixed_prefix_does_not_panic() { /* R9 */ }
```

**`ratchet.rs` remains unaudited** — it was never uploaded.
