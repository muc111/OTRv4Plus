<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Security audit, 2026-10-11 (rc.53)

A developer-led review with AI assistance, like the earlier ones
([CRYPTO_AUDIT_2026-09.md](CRYPTO_AUDIT_2026-09.md)). It is **not** an
independent third-party audit. Scope: every dependency, and a manual review of
the code added since the last audit (rc.43 to rc.52: group verification,
group calls, the built-in I2P router, room listing and deletion).

## 1. Dependencies

| Area | What was done | Result |
|---|---|---|
| Rust core, `Rust/Cargo.lock` | `cargo update`; `cargo audit --deny warnings` (1296 advisories, 338 crates) | 61 crates to their latest compatible versions (PyO3 0.29.3 among them). Clean, with the documented exceptions below. |
| MLS crate, `Rust/mls/Cargo.lock` | `cargo update`; **openmls 0.9.0 -> 0.9.1** | 26 crates updated. openmls 0.9.1 validates MLS extensions by context while parsing them from the wire (duplicates and misplaced types refused) -- input from other members. Raises the Rust minimum to 1.91. |
| Opus codec, `Rust/opus-codec/Cargo.lock` | `cargo update`; `cargo audit` | 3 crates updated; no advisories. |
| New advisories | RUSTSEC-2026-0329 (libcrux-hmac-drbg), -0330 and -0331 (libcrux-kem): panics on short input | **Not built.** Locked only as openmls's optional libcrux provider, which is never enabled (otrv4-mls has its own HPKE and provider). `cargo tree -e all --target all -i libcrux-kem` is empty. Pinned exactly by hpke-rs-libcrux, so not updatable; recorded with reasons in `Rust/.cargo/audit.toml`. |
| Python, APK and Termux | Pins checked against PyPI; vulnerabilities from PyPI's OSV data | slixmpp 1.17.0, PySocks 1.7.1, pyasn1 0.6.4, pyasn1-modules 0.4.2, aiodns 4.0.4, pycares 4.11.0, opuslib 3.0.1, maturin 1.13.3: all latest (maturin pinned on purpose, see `Rust/build.sh`), **0 known vulnerabilities**. CPython 3.12.12 (Chaquopy) is the newest 3.12 Chaquopy publishes. |
| Built-in router | **i2pd 2.59.0 -> 2.61.0** | Fixes a reseed failure on a malformed response, an endless reseed loop, a memory leak and race conditions; bounds the streaming receive queue; retries a failed reseed after 30 s; post-quantum (ML-KEM-768) SSU2 with the bundled OpenSSL. Every i2pd.conf key and the SAM datagram-port rule re-checked against 2.61.0. |
| OpenSSL in the router | 3.5.9 | Already the newest of the 3.5 LTS line. |
| Boost in the router | 1.88.0 kept | filesystem and program_options only, statically linked; 1.92.0 exists but brings no fix that matters here. |
| Android toolchain | Not changed | AGP 8.7.3, Kotlin 2.0.21, AndroidX core 1.15 / lifecycle 2.8.7 are a year old but carry no known advisory. Updating is a chained change (compile SDK, AGP, Gradle) that only CI can compile; it is its own change, not part of a security patch. |

## 2. Static analysis

* `cargo clippy -D warnings`, all targets: core (with `mls`) and the MLS crate
  (all features) -- clean.
* `bandit` over the Python clients and the Android bridge: no shell-string
  commands, no unsafe deserialisation, no world-writable temp files, nothing
  bound to all interfaces, no hard-coded secrets (the 17 "password string"
  hits are state names and empty defaults). The three SHA-1 findings are
  XEP-0084 avatar ids, which the standard defines as SHA-1 of the image --
  names, not security; marked `usedforsecurity=False`.

## 3. Manual review and fixes

**F1 (medium) -- the built-in router's SAM port could be taken by another
app.** Loopback is shared by every app on an Android phone. The router used a
fixed port (17656), and "something answers on 17656" was taken as "our router
is ready". Another app could bind that port first -- easily during the minutes
of a first start, before i2pd opens it -- and the app would talk SAM to it:
the XMPP connection's metadata exposed and blockable (message contents stay
end-to-end encrypted by OTRv4+ and MLS). **Fixed:** the port is random,
chosen at each start (20000-59999, CSPRNG) and kept only in app-private
storage, which other apps cannot read (nor our processes' command lines); and
a port counts as ours only while our own i2pd process is alive. With our
router down, an attempt is pointed at a port that refuses, never at the
default 7656. (`BundledRouter`, `RouterChoice.pickSamPort`, tests.)

**F2 (low) -- a room could fake the encrypted-group icon in the room list.**
Since rc.49 the icon came from a room's description, which anybody can
write. The room screen always showed the true state, but the list could
invite somebody into a fake "encrypted group". **Fixed:** the group icon is
shown only for groups whose keys are on this device; a description is shown
as a claim ("Says it is an encrypted group (you hold no keys for it)").

**F3 (low) -- router error lines could name peers.** When the built-in router
stops, its last line goes on screen and into the diagnostics trace, and
i2pd's errors can carry IP addresses and I2P identities. **Fixed:** IPv4,
IPv6, .b32.i2p and long base32/base64 identities are replaced by
placeholders first (`RouterChoice.scrub`, tested).

Reviewed with no change needed:

* **Group verification** (`group_verify.py`): nothing about the passphrase is
  revealed by a run; guesses are capped per member per run (3); a run started
  by another member never makes this device answer until its user joins and
  types the passphrase; results bind the two members' MLS key fingerprints;
  the passphrase is zeroed when the run ends or after 30 minutes.
* **Group calls** (`group_call.py`, media): only verified members' joins are
  accepted; every datagram is opened by the group's AEAD (with replay
  window) before it is played, so packets injected on the loopback UDP port
  are dropped; ringing never auto-joins an unverified caller.
* **Room deletion and listing**: deletion is enforced by the server (owner or
  admin); listing only adds rooms of the account's own groups.
* **Bundled router packaging**: the certificate archive cannot write outside
  its directory (tested); the router's data is private, excluded from
  backups and wiped by Wipe & Exit.

## 4. Known, unchanged

* The external-router path (an I2P app on 7656) has the same property F1
  fixed for ours: any app on the phone can listen on 7656 when the I2P app is
  not running. That is SAM's design; "I2P router: Built-in router" avoids it.
* The PQClean-based ML-KEM/ML-DSA crates are unmaintained upstream (recorded
  since 2026-09); replacing them is a reviewed change of implementation, not
  a dependency bump.
* No paid independent audit.
