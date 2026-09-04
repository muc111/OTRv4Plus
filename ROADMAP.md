# Roadmap

What's next for OTRv4+. Ordered roughly by priority, not by ease.

## Recently shipped

- **v10.16.1** **The file picker waits for the human, and SMP lines carry a padlock.** `/sendfile` with no path reported `no file chosen` while the gallery was still open: `termux-storage-get` returns as soon as it has dispatched the intent, so checking once for the file always found nothing. The destination is polled until the file appears and its size stops changing, so a still-copying file is not sent truncated, and a copy delivered after we gave up is swept rather than left on disk in plaintext. Separately, every `[smp]` line now prints as 🔐 `[smp]` in blue — which meant teaching the session transcript's allowlist to strip status glyphs *before* it matches, since stripping them only in the `[tag]` rule would have let 🔐 `[otr] <peer> body` past the message-body redaction. 16 tests, 3 mutations killed.
- **v10.14.0** **`/sendfile` — encrypted file transfer over XMPP.** A fresh AES-256-GCM FileKey per transfer, generated, used and destroyed inside Rust with no getter; wrapped under a key derived from the session's DAKE extra symmetric key, which is the value OTRv4 reserves for out-of-band use and the one session secret that does not advance as the ratchet moves. No second ML-KEM exchange: the brace key already folds ML-KEM-1024, so the session is already post-quantum and already authenticated. 64 KiB chunks with the index and a final flag in the AAD, so reordering, duplication and truncation all fail the tag. Six verification steps before an atomic rename into `~/.otrv4plus/files/`. XMPP only, enforced by test. Python 2283 passed, Rust 101 passed. Not tested on a device.
- **v10.13.3** **The channel user list works again, and says what it means.** `/names`, `/list` and `/help` had printed the literal string `[IRC line suppressed]` in place of every line since v10.11.0 — the pager measured and truncated each line and then discarded it. The NAMES rendering that already existed was never reached; it now shows a summary count, privilege groups, and detected OTRv4+ users in blue and selectable with a keypress that runs the normal `/otr` entry point. Detection reads the realname the peer's client sent at registration, which is the identification channel this project already had — CTCP VERSION is refused — and which two of three realname paths were failing to fill in, leaving 27 Club and NickServ-registered users undetectable. INV-20 records that the marker is identification and never authentication: the DAKE authenticates, TOFU pins identity, SMP authorises voice. Python 2109 passed, Rust 87 unchanged. Not tested against a live IRC server.
- **v10.13.2** **The voice key path moves into Rust.** The last long-lived key material outside the Rust core. Media keys were Python bytearrays handed to OpenSSL as immutable `bytes` copies — about 276 unwipeable copies over a 69-minute call — and are now `SecretBytes<32>` inside `RustVoiceCipher` with no getter. The voice X448 private scalar was an OpenSSL object Python could neither wipe nor reach, and is now `SecretBytes<56>` in `RustVoiceKex`, single-use, with the reflection and degenerate-shared-secret checks moved down with it. The SMP passphrase stopped being copied into an immutable `bytes` on its way to the vault. Byte-for-byte compatible: same HKDF-SHA512, same labels, same four-byte length prefixes. The epoch root moved too — `RustVoiceRoot` owns it as `SecretBytes<64>` and Python holds a handle that produces ciphers, confirmations and endpoint tags but never the root. The rekey state machine stays in Python deliberately: it is protocol logic and owns the convergence properties fixed at v10.13.1. Python 1992 passed, Rust 87 passed. No live XMPP/I2P testing, and this changes what encrypts every audio frame.
- **v10.16.0** **TLS follows the transport.** `--insecure-tls` is no longer part of any normal command. Over I2P a `.b32.i2p` address is the hash of the server's key and over Tor a v3 `.onion` name is the key, so the transport authenticates the endpoint and certificate checks are skipped with an explanation of what replaces them. Clearnet still requires a valid certificate, Tor to a non-onion host still requires one, and the flag survives for a self-signed clearnet server — passing it where it is not needed now says so. The point is the habit: a flag with "insecure" in it, typed daily for a link that is not insecure, is dangerous the first time it is carried to a clearnet host. 14 tests, 4 mutations killed.
- **v10.15.3 / v10.15.4** **The b32 gets typed once, and a server move reaches people.** The first successful connection to a `.b32.i2p` server records the mapping from the JID's domain in `~/.otrv4plus/i2p_hosts`, after the connection rather than before. `i2p_hosts.defaults` ships with the source, so a fresh clone connects by short name and a migration is a `git pull`. Precedence turns on whose entry it is: a hand-written line always wins, a line the client learned itself yields to a changed shipped default with a notice, and an update never edits the user's file. A retired address given in full is explained, never redirected. The client does not write to i2pd's address book — that format varies by version, the daemon rewrites it, and a bad write would break name resolution for every I2P app on the device. Python 2445 passed, Rust 111 passed.
- **v10.15.2** **Short `.i2p` names.** Connecting meant pasting a 52-character b32 every time, because `.i2p` names are not DNS and a private server is in nobody's address book. A local alias file, `~/.otrv4plus/i2p_hosts`, maps a short name to a destination, after which the JID's own domain is enough and `--server` is unnecessary. An address given in full as `.b32.i2p` is never looked up in the file, so a local file cannot redirect an address typed out in full; aliases cannot chain to another short name; the substitution is printed when used. The resolution failure now names the file and prints the line to add instead of returning the raw SAM reply. `TRANSPORT_POLICY.md` §8.1 records that no system resolver ever sees an `.i2p` or `.onion` name. 19 new tests; Python 2423 passed, Rust 111 passed.
- **v10.15.1** **Three defects the first two-handset run found.** The responder flow was never switched on — `smp_guided_prompt` was plumbed through the manager and sessions and never set to `True`, so an incoming SMP1 aborted exactly as before and the entire responder half of v10.15.0 was unreachable on a device. Simultaneous `/smp` on both sides always failed with `SMP race-recovery: vault rebind failed`, because rebuilding the engine constructed a fresh vault and discarded the secret the rebind then looked for; that path had never worked. And one abort printed both "this is not a wrong-passphrase failure" and "secrets did NOT match — possible MITM", three lines apart. All three were covered on paper by tests that drove the client's own methods with a fake engine; the replacements feed a real SMP1 to a real session, and each fix was checked by reverting it. Python 2404 passed, Rust 111 passed. First live I2P device run; responder prompt still unverified on hardware.
- **v10.15.0** **Guided SMP verification, and a compiled-core version check.** `/smp` is now the only verification command a user needs: it prompts (hidden) for the passphrase when none is stored and then verifies. A responder who has never set one is asked for consent first — a peer's SMP1 can put a prompt on the screen but cannot make a typed line become a passphrase, which is INV-06 restated for a flow where remote messages legitimately prompt. A new Rust phase `SECRET_REQUIRED` holds the received SMP1 so it can be answered rather than restarted. The reported `store_from_bytearray` failure turned out to be a stale compiled core, not an SMP bug: `otrv4plus_coreapi.py` now declares what the clients require and checks it at startup. The IRC client's remote-armed `_set_pending("smp_secret", …)` — the original INV-06 defect, never covered by its test — was removed. Python 2386 passed, Rust 111 passed. No live XMPP/I2P testing.
- **v10.13.1** **Security hardening: input capture, log boundary, rekey divergence.** A repository-wide inventory found three real defects. A remote peer could arm a pending-input state that made the user's next typed line become an SMP passphrase — masked and never transmitted, but a remote party choosing the meaning of local input; the secret now comes only from a locally typed `/smp-secret`. A hand-rolled SHAKE-256 stream cipher in `otrv4plus_log.py`, with a dormant persistent mode one constructor argument from writing every message to disk, was deleted rather than re-based onto the Rust AEAD. The session transcript became an allowlist instead of a one-pattern denylist that failed open. Two rekey defects that could strand a call permanently: an abort destroyed a receive key the peer was already sending under, and an incoming REKEY had to name exactly `ours + 1`, so one lost REKEYCOMMIT rejected every subsequent repair. Media rejections are now classified by cause, so "authfail" means a failed AEAD tag and nothing else. Sixteen invariants enforced by `tests/security_invariants.py`, with `SECURITY_INVARIANTS.md` generated from it. Python 1932 passed, Rust 77 passed. No live XMPP/I2P testing.
- **v10.13.0** **Argon2id SMP secret derivation (wire version `0x03`).** The SMP passphrase was stretched by 50,000 rounds of SHAKE-256 over the passphrase alone, with the session ID and fingerprints bound in afterwards by one HMAC. That is CPU-only work — and, worse, nothing user-specific entered the expensive part, so a dictionary ground out once was reusable against every user and every session forever. `0x03` derives the scalar with Argon2id (m=64 MiB, t=3, p=4) salted with the session ID and both fingerprints, length-prefixed so field boundaries cannot collide. The `0x02` derivation is retained byte-for-byte behind a frozen test vector, cross-checked against an independent implementation; message layouts are unchanged, so a mixed pair aborts at the version check with an error naming the real cause instead of reporting a passphrase mismatch. Also: a documentation claim of Argon2id inside the Rust core, which predated any such code by several releases, retracted and pinned by tests that read the sources rather than the prose; the at-rest Argon2→scrypt fallback made loud and reportable via `kdf_backend()`; the SMP wire byte actually pinned by `tests/test_protocol_version.py`, which `VERSIONING.md` had already claimed. Python 1633 passed, Rust 77 passed. Not yet live-tested between two handsets.
- **v10.12.0** **Voice media liveness, diagnosis and authenticated recovery.** A call whose inbound media died used to stay "up" forever — the transmit side keeps succeeding over a dead SAM session, so nothing failed. A watchdog now measures silence since the last *authenticated* frame, and when nothing is arriving the endpoint is rebuilt and the new destination announced in an authenticated `MEDIAPATH` control message tagged from the committed epoch root. No media key derives from the destination, so recovery costs no key state. The rebuild is held back while the SAM control socket is open, because on a network transition I2P rebuilds tunnels under a session that is still ours (measured: rebuilding anyway cost 21.2 s plus ~20 s of our own `tx` at zero). Cold paths get a 120 s startup grace after a live call lost ~70 s to a rebuild of an endpoint that was merely still coming up. Worst case bounded at 465 s proven / 795 s cold, pinned by a test that fails if the docs and code disagree. Also: the PyO3 `DakeOutput` thread-affinity crash fixed by serialising the OTR executor to one worker; the XMPP keepalive stopped disconnecting streams that were working; rekey no longer wedges on one lost message; Termux incoming-call notification with ACCEPT/DECLINE; latency colour banding. `VERSIONING.md` added and version strings reconciled — five files had disagreed. Python 1483 passed, Rust 65 passed; the session-hold, identity, TOFU and SMP invariants mutation-tested.
- **v10.10.0 – v10.11.1** XMPP transport, its security hardening, the fail-closed Tor control-plane route, and the first working encrypted voice path over I2P. These shipped without changelog entries; see the note in [CHANGELOG.md](CHANGELOG.md).
- **v10.9.2** Formal protocol specification (`SPEC.md`) added — byte-level wire layouts for DAKE1/2/3 and ClientProfile, the KDF usage-ID table, the normative session-key derivation order, the full hybrid PQC SMP construction, fragmentation, state machines, and the RFC 3526 prime. Documentation pass across README (added "Why vs alternatives" comparison + 30-second pitch), SECURITY, and WHY for the hybrid SMP. `termux_install.sh` rewritten Rust-only. No wire change.
- **v10.9.1** SMP session timeout raised to 45 min (from 10) for the hybrid-PQ wire overhead over I2P. I2P transport tuned against irc.postman.i2p: fragment size 450→380 B (postman truncated the DAKE1 tail), send pacing changed to a 2-fragment / 6-second batch after per-fragment delays all triggered Excess Flood. Per-panel scroll fix (`_scroll_history` was global, mixing channels). IRCv3 P2P typing notifications. Measured: DAKE+SMP ~15–16 min over I2P, <6 min over TLS.
- **v10.9.0** **Hybrid post-quantum SMP.** The classical four-step Schnorr ZKP over the 3072-bit group is wrapped in an ML-KEM-1024 + ML-DSA-87 binding layer: SMP1 carries the KEM encapsulation key and an ML-DSA-87 public key, SMP2 derives `pq_binding_key` from the KEM shared secret and signs the wire body with ML-DSA-87, SMP3/4 verify-then-sign. Forging "verified" now requires breaking the discrete log, ML-KEM-1024, and ML-DSA-87 simultaneously. Wire-versioned 0x01/0x02, no silent downgrade. A KEM-key-mixing bug (initiator derived the secret scalar without the KEM key, responder with it → false-negative SMP) was found in live two-session testing and fixed by removing the KEM key from secret derivation entirely. 15 new SMP tests, 30+ total.
- **v10.7.6** Phase 5.4. SMP modular exponentiation made constant-time: `modpow` migrated from `num-bigint` (variable-time) to `crypto-bigint` `DynResidue<48>` (Montgomery-form, constant-time in the exponent). Closes the timing side-channel on the secret SMP exponents (blinding scalars, the SMP secret, ZKP randomisers) — the last open security-hardening item on this roadmap. The 3072-bit group (OTRv4 §5.3) is unchanged, so the wire format and spec compliance are identical; only the exponentiation implementation changed. `crypto-bigint` promoted from transitive to direct dep (no new compile). 6 SMP unit tests added. Verified live over I2P with peer QuartzRoot. Fixed a latent mislabel found during the work: `SMP_PRIME_BYTES` was `256` but the prime is 3072-bit (384 bytes) — corrected (the old `num-bigint` path was unaffected because `fixed_bytes` never truncated).
- **v10.7.5** ClientProfile validity reduced from 365 days to 14 days, matching the OTRv4 spec §4.1 recommendation and `otr4j`'s default.  The previous 1-year value was incoherent with the ephemeral-identity design.  Implemented as a class-level `VALIDITY_SECONDS` constant so the two assignment sites can't drift again.
- **v10.7.4** Phase 5.3k + 5.3i-D.  All C extensions retired.  `otr4_ed448_ct` import deleted from `otrv4+.py` (the import was a defensive ground-truth; a grep for `_ed448_ct.` member access was empty — it was never called).  `otr4_crypto_ext.c`, `otr4_ed448_ct.c`, `otr4_mldsa_ext.c`, and `setup_otr4.py` removed via `git rm`.  Seven test files in `tests/` migrated onto `otrv4_core`; the C-extension smoke test `test_otr.py` deleted.  Concurrent fix in `aead.rs`: deprecated `aes-gcm 0.10` `GenericArray::from_slice` helper replaced by `Aes256Gcm::new_from_slice` (KeyInit) and `Nonce::from(*&[u8;12])`.  Cargo build is back to **0 warnings**, **20 tests passing**.  OTRv4+ is now Rust-core-only — the architectural finish line.
- **v10.7.3** Phase 5.3i-C.  `MLKEM1024BraceKEM` migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem` via a new `src/mlkem.rs` PyO3 module.  Three new Rust unit tests for byte sizes, roundtrip, and wrong-key rejection.  After this commit `otr4_crypto_ext` had no remaining callers.
- **v10.7.2** Phase 5.3i-B.  `_ossl.cleanse()` replaced with a module-level `_secure_wipe(bytearray)` using `ctypes.memset`.  Eight cleanse sites repointed; two redundant ones removed where Rust already zeroizes.
- **v10.7.1** Phase 5.3i-A.  Four dead bignum wrappers deleted (`_ct_mod_exp`, `_ct_mod_inv`, `_ct_rand_range`, `SHA3_512.hash_to_int`).  `disable_core_dumps` moved to Python `resource.setrlimit(RLIMIT_CORE, (0, 0))`.
- **v10.7** Phase 5.3h-D complete — the Python `cryptography` library is fully removed from the codebase. Stages 1 and 2 (v10.6.20, v10.6.21) moved Ed448 verification and the X448 ratchet DH into Rust. v10.7 (stage 3) deleted the dead pure-Python `OTRv4DAKE` fallback class (863 lines) and the unreachable `_use_rust` / `_py_fallback` machinery, rescued `_safe_b64decode` to module scope, removed the four remaining `serialization.Raw` byte-conversion sites, deleted the legacy `ed448`/`x448` `isinstance` branches from `ClientProfile`, and removed the `from cryptography...` import entirely. 883 lines net removed. No OpenSSL-backed Python crypto remains in any code path.
- **v10.6.21** Phase 5.3h-D stage 2. The double ratchet's X448 Diffie-Hellman moved from `cryptography.x448` to the Rust `X448KeyHandle` (`generate_x448_keypair`, `handle.dh`). No new Rust crypto — the handle already existed. The `x448` crate clamps the scalar per RFC 7748 and rejects low-order points, matching OpenSSL byte-for-byte. RFC 7748 §5.2 known-answer vector added to `key_handles.rs` as the build-time desync guard. Verified live across 5+ DH-ratchet epochs.
- **v10.6.20** Phase 5.3h-D stage 1. `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` function (`VerifyingKey::verify_raw`, the exact counterpart of `Ed448KeyHandle::sign`'s `sign_raw`). Three Rust unit tests including a sign-then-verify roundtrip.
- **v10.6.19** Phase 5.3h, parts A2 + B + C. Three live AES-256-GCM call sites (in `SMPAutoRespondStorage`, `SecureKeyStorage`, and `_secure_file_destroy` itself) swapped from `cryptography.AESGCM` to `otrv4_core.aes256gcm_{encrypt,decrypt}` via the new `Rust/src/aead.rs` PyO3 module backed by the `aes-gcm` 0.10 crate. Six `Ed448PublicKey` wrap sites replaced with raw bytes. Top-of-file `cryptography` imports dropped `AESGCM` and `hashes`. Startup migration added to securely destroy legacy `~/.otrv4_vault` and `~/.otrv4_smp_secrets.json` orphans.
- **v10.6.18** Phase 5.3j. `otr4_mldsa_ext` C extension retired. ML-DSA-87 keygen, sign, and verify now backed by `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`. Wire format byte-identical (FIPS 204 ML-DSA-87). Phase 5.3g answered: **ephemeral identity is the design choice** (see below); no persistent vault.
- **v10.6.17** Phase 5.3f-narrow. Removed Python boot-time cross-verify helpers. RFC 8032 Ed448 test vectors moved to Rust `src/test_vectors.rs` with a `#[cfg(test)]` harness; `cargo test` is the release gate for Ed448 correctness.
- **v10.6.16** ML-KEM migration. `pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203). Drop-in API; wire-incompatible with v10.6.15. Build forces `default-features = false, features = ["std"]` to avoid avx2/neon SIGILL on Termux/aarch64.
- **v10.6.15** SMP race fix. When both peers run `/smp start` near-simultaneously, the side with the higher fingerprint yields to responder role. Also restored `signing` + `pkcs8` features on `ed448-goldilocks-plus` that had been silently dropped.
- **v10.6.14** `lazy_static 1.5` (unmaintained per RustSec) replaced by `std::sync::LazyLock` (stable Rust 1.80+).
- **v10.6.13** SMP regression fix from v10.6.12. Seven Python sites still used the legacy `.public_key().public_bytes()` chain; all converted to the Rust handle's `.public_bytes()` method.
- **v10.6.12** Phase 5.3e. Long-term identity keys generated inside Rust. `Ed448KeyHandle` and `X448KeyHandle` PyO3 classes own `SecretBytes<N>` and expose only public bytes and key-specific operations.
- **v10.6.11** Phase 5.4. Rust-only crypto, no fallback paths. Import-time fail-fast if the Rust core is missing or stale.
- **v10.6.9** Phase 5.3c. DAKE3 Schnorr ring signature in pure Rust (`src/ring_sig.rs`).
- **v10.6.8** Phase 5.3b. Removed dead-code disk persistence of private bytes.
- **v10.6.3** Phase 4. DAKE session keys never cross the Python heap. Audit closed 11/11.

## Drop the cryptography library and C extensions from runtime

What was previously labelled "Phase 5.3f" turned out to be larger than a single commit. The honest split into named sub-phases, with the cryptography-library half now complete:

### Phase 5.3f-narrow — boot helpers + RFC 8032 vectors

**Shipped in v10.6.17.** The two Python boot helpers and their four call sites were removed. Rust `src/test_vectors.rs` is the Ed448 release-time gate.

### Phase 5.3h — replace runtime cryptography library uses

**Complete as of v10.7.** The phase was larger than a single commit and was split into sub-phases:

#### Phase 5.3h, parts A2 + B + C — shipped in v10.6.19

- **Part A2 (legacy file cleanup).** Startup migration securely destroying `~/.otrv4_vault`, `~/.otrv4_smp_secrets.json`, and `~/.otrv4_keys/` orphans via `_secure_file_destroy` (NIST SP 800-88r1).
- **Part B (AES-GCM swap).** Three live `AESGCM(key)` call sites swapped to `otrv4_core.aes256gcm_{encrypt,decrypt}` via `Rust/src/aead.rs` (`aes-gcm` 0.10 crate). Wire format identical.
- **Part C (Ed448PublicKey wrap removal).** Six `Ed448PublicKey.from_public_bytes` call sites replaced with raw bytes.

#### Phase 5.3h-D — shipped across v10.6.20, v10.6.21, v10.7

Staged so each piece could be live-tested in isolation before the next began:

1. **Stage 1 (v10.6.20).** `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` PyO3 function. The `ed448-goldilocks-plus` `VerifyingKey::verify_raw` is the exact counterpart of the `sign_raw` used by `Ed448KeyHandle::sign`.
2. **Stage 2 (v10.6.21).** The double ratchet's X448 DH moved from `cryptography.x448` to the Rust `X448KeyHandle`. No new Rust crypto — `generate_x448_keypair` and `X448KeyHandle.dh` already existed. RFC 7748 §5.2 known-answer vector added as the build-time desync guard.
3. **Stage 3 (v10.7).** Deleted the dead pure-Python `OTRv4DAKE` fallback class (863 lines). It was already uninstantiable: `RustDAKEAdapter` raised rather than constructing it, and the Rust ratchet and Rust SMP have been mandatory since v10.6.11, so a build without the Rust core could never complete a session regardless. Stripped the unreachable `_use_rust` / `_py_fallback` machinery, rescued `_safe_b64decode` to module scope, removed the four `serialization.Raw` byte-conversion sites, deleted the legacy `ed448`/`x448` `isinstance` branches from `ClientProfile`, and removed the `from cryptography...` import. The Python cryptography library is gone.

### Phase 5.3i — replace `otr4_crypto_ext` (`_ossl`) uses

**Shipped across v10.7.1 → v10.7.4.**  The original plan estimated this as the largest remaining sub-phase, "200-300 lines plus a constant-time bignum decision, two to three sessions."  It turned out smaller: much of the C extension's bignum surface had already become dead code when the Rust SMP took over (the SMP modular arithmetic moved entirely into `num-bigint` inside `src/smp.rs`).  The remaining concern — that `num-bigint`'s `modpow` is not constant-time — was addressed separately in **Phase 5.4 (v10.7.6)**, which moved the secret-exponent `modpow` calls onto `crypto-bigint` `DynResidue`.  Sub-phases as shipped:

1. **v10.7.1 (5.3i-A)** — four dead bignum wrappers (`_ct_mod_exp`, `_ct_mod_inv`, `_ct_rand_range`, `SHA3_512.hash_to_int`) deleted.  `disable_core_dumps` moved to Python `resource.setrlimit(RLIMIT_CORE, (0, 0))`.  Python-only change; no Rust rebuild.
2. **v10.7.2 (5.3i-B)** — `_ossl.cleanse(buf)` replaced with a module-level `_secure_wipe(bytearray)` using `ctypes.memset` (dead-store-resistant, no DLL surface, no third-party dependency).  Eight cleanse sites repointed; two redundant ones deleted where Rust already wiped.
3. **v10.7.3 (5.3i-C)** — `MLKEM1024BraceKEM` migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem` via a new `src/mlkem.rs` PyO3 module exposing `mlkem1024_keygen` / `_encaps` / `_decaps`.  The pqcrypto `(SharedSecret, Ciphertext)` tuple is inverted to `(ct, ss)` in the Rust wrapper to match the C-extension contract exactly.  After this commit `otr4_crypto_ext` had **no remaining callers anywhere in the codebase** — it was loaded but never invoked.
4. **v10.7.4 (5.3i-D)** — `aead.rs` migrated off the deprecated `aes-gcm 0.10` `GenericArray::from_slice` helper to `Aes256Gcm::new_from_slice` (KeyInit trait) and `Nonce::from(*&[u8;12])` for the nonce.  Restored the zero-warning Rust build that v10.6.18 had originally achieved.
5. **`_ossl.ring_sign` / `_ossl.ring_verify`** — flagged in the original 5.3i plan as "genuinely unused, remove when next touched."  These were eliminated by simple file deletion in 5.3k, not by any code change — once nothing imported the C extension, the entry points were just dead bytes on disk.

### Phase 5.3j — replace `otr4_mldsa_ext` (`_mldsa`) uses

**Shipped in v10.6.18.**  ML-DSA-87 keygen, sign, and verify run through `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`.  `otr4_mldsa_ext.so` is no longer required for the build.

### Phase 5.3k — delete the C extensions

**Shipped in v10.7.4.**  Once 5.3i-C made `otr4_crypto_ext` callerless, 5.3k was pure deletion.  Steps as executed:

- `otr4_ed448_ct` was imported by `otrv4+.py` but a grep for `_ed448_ct.` (member access) was empty — it was a defensive ground-truth import with no live calls.  Both the import block and the `ED448_CT_AVAILABLE` flag were removed.
- The `.c`, `.h`, and `.so` files for `otr4_crypto_ext`, `otr4_ed448_ct`, and the long-dead `otr4_mldsa_ext` (retired at v10.6.18 but never deleted) were removed via `git rm`.
- `setup_otr4.py` was removed.
- Seven test files in `tests/` that imported `otr4_crypto_ext` were migrated to `otrv4_core` via a one-shot script.  `test_attacks.py`, which used `cleanse`, got a small `_OsslShim` providing the Rust ML-KEM functions plus a `ctypes.memset` cleanse.  `test_otr.py` (a smoke test for the C extensions' surface) was deleted as obsolete.
- All eight documentation files (`README`, `SECURITY`, `ROADMAP`, `CHANGELOG`, `FEATURES`, `DEVELOPMENT`, `MIGRATION`, `CONTRIBUTING`, and the two `prebuilt/` READMEs) were updated to reflect the Rust-core-only state.

### Architectural consequence

After 5.3i + 5.3k, the **chat** path has a single cryptographic implementation surface — the Rust `otrv4_core` PyO3 module.  No second crypto backend, no compile-time conditionals selecting between paths, no "Rust verified against C" comparison checks at boot.  The earlier multi-backend complexity that the audit had to reason about is gone from messaging.

> **Status note (v10.12.0).** The entries above are accurate as history and were
> accurate for the whole project when written. They are no longer accurate for
> the whole project: the voice subsystem added at v10.11.0 reintroduced the
> Python `cryptography` library for the media AES-256-GCM, the HKDF-SHA512 voice
> key schedule and the voice X448. So "no OpenSSL-backed Python crypto in any
> code path" holds for chat and not for voice. Closing that is tracked below
> under *Voice: consolidate onto the Rust core*.

## Phase 5.3g — ephemeral identity by design (DECIDED at v10.6.18, SPLIT PER PROTOCOL at v10.12.0)

> **Amended, not reversed (v10.12.0).** The decision below was made when OTRv4+
> was an IRC client. It still stands for IRC and is unchanged there. It does
> **not** hold for XMPP, and holding it there was actively harmful:
>
> A JID is a durable name. An identity that changed under it every launch made
> a changed fingerprint meaningless, so TOFU could not work — and because the
> two protocols shared `~/.otrv4plus/trust.json`, `add_trust` raised
> `FingerprintMismatchError` on the second session with any peer, printing
> "This may indicate a MITM attack" as normal behaviour. A warning shown on
> every reconnect is a warning that will be ignored when it is real.
>
> So the two protocols now differ, deliberately:
>
> | | identity | trust |
> |---|---|---|
> | **IRC** | fresh Ed448 every run | in-memory for the session, nothing on disk |
> | **XMPP** | persistent, sealed Ed448 | pinned fingerprints under `~/.otrv4plus/xmpp/` |
>
> The rationale below is why IRC keeps ephemeral identity. Read points 1 and 4
> as the IRC case: an IRC nick is not a durable name, and pinning a fingerprint
> to one pins it to nothing.

OTRv4+ keeps **ephemeral identities** for IRC by design. Fingerprints regenerate at every launch; there is no on-disk identity vault for that protocol.

Rationale:

- **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
- **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
- **No passphrase to forget.** Termux has no OS keyring; a vault would require user passphrase prompts at every launch.
- **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

SMP trust binding is meaningful within a session. Across sessions, peers must re-verify on each connection. This is correct behaviour for the project's design intent, not a limitation.

**How XMPP persistence was implemented (v10.12.0).** Not through
`from_seed_bytes()`, which would have put the seed on the Python heap and cost
the property that makes the Rust core worth having. It reuses the Android B1
mechanism instead: `Rust/src/identity.rs` seals and unseals inside Rust, so only
ciphertext crosses into Python and no `get_seed()` accessor exists or may be
added. `otrv4plus_identity.py` supplies the Termux-side wiring and the
data-encryption key. **The at-rest protection is filesystem permissions**, not a
passphrase — see SECURITY.md caveat 5b for exactly what that does and does not
defend against.

## Other planned work

### Better trust UX

`/trust` currently asks `y` or `n` after fingerprint display. Trust decisions do not persist across launches (consistent with the ephemeral-identity choice in 5.3g).

### Group messaging

Out of OTRv4 scope. OMEMO or MLS would be a separate project.

### Native Android APK

**Partly done, not finished.** A Gradle project, a Chaquopy configuration, a typed
Kotlin↔Python bridge and a Kotlin application security layer exist under
`android/` and `android_bridge/`, and the storage and architecture questions have
been audited (`ANDROID_ARCHITECTURE_AUDIT.md`, `ANDROID_STORAGE_AUDIT.md`,
`ANDROID_PHASE2_REPORT.md`). What does not exist is a shipped signed APK, an
in-APK I2P router, or any voice testing inside the APK — voice is verified under
Termux, which is a different process model. Termux remains the supported
environment. Do not read "voice works" as "voice works in the APK".

### Tor onion service transport

**Control plane done, live-unverified; voice deliberately excluded.** The XMPP
control plane routes over Tor SOCKS5, fail-closed and with no DNS leak, and IRC
has had Tor support for longer. Neither has been verified on a live `.onion`
service, so the status is "implemented, unverified" rather than "works".

Voice over Tor is **not** planned. There is no Tor UDP transport, and carrying
constant-rate media over TCP would trade the property the datagram transport
exists to provide. I2P remains the only transport that carries voice.

### Voice: consolidate onto the Rust core

`otrv4plus_voice.py` uses the Python `cryptography` library for the media
AES-256-GCM, the HKDF-SHA512 key schedule, and the voice X448. That is a second
implementation of AES-256-GCM in a project whose stated architecture is one
cryptographic surface, and it puts voice key material in Python `bytearray`s
wiped best-effort rather than in Rust `ZeroizeOnDrop` buffers. The Rust core
already exposes `aes256gcm_encrypt`/`_decrypt` and `X448KeyHandle`; the KDF would
need an HKDF-SHA512 binding. This is the largest open architectural item on the
voice path.

### Voice: classify authentication failures

`authfail` currently cannot distinguish "no live key for epoch N" — an ordinary
consequence of a rekey in flight — from a genuine AEAD tag failure, which is an
attack signal. They are counted together, so the interesting one is invisible
inside the boring one. Splitting them is a telemetry and diagnosis fix, not a
cryptographic change.

### Voice: latency

Median mouth-to-ear on the I2P path is about 917 ms, against ITU-T G.114's
400 ms "acceptable" bound. Opus is not the bottleneck (`OPUS_AUDIT.md`). The
playout path shows a p50 of about 93 ms during degraded periods, which is worth
understanding before anything else is tuned. **Reducing the I2P hop count is not
an option** — the 3-hop configuration is the reason the project exists.

### Formal review

The chat crypto path is now small enough to be reviewable: ~3500 lines of Rust across `dake.rs`, `ratchet.rs`, `smp.rs`, `smp_vault.rs`, `ring_sig.rs`, `key_handles.rs`, `mldsa.rs`, `mlkem.rs`, `aead.rs`, `secure_mem.rs`, `kdf.rs`. The Python `cryptography` library was removed from that path at v10.7 and all C extensions at v10.7.5 (Phase 5.3k). A review scoped to chat should note that the **voice** key schedule and media AEAD live in Python (`otrv4plus_voice.py`) and are not covered by reading the Rust alone. As of v10.7.6 (Phase 5.4) the SMP modular exponentiation is constant-time via `crypto-bigint`, and as of v10.9.0 the SMP is hybrid post-quantum. A formal third-party review would significantly increase confidence. No funding for this; expression of interest welcome.

### Full post-quantum SMP / PQ-PAKE

The hybrid SMP (v10.9.0) wraps the classical Schnorr ZKP rather than replacing it, so the equality proof itself is still classical (susceptible to Shor, though an attacker must also break ML-KEM-1024 and ML-DSA-87). SMP is effectively a PAKE that predates the term; modern PQ-PAKE constructions (lattice-based CPace-style, or the newer PQ-PAKE designs) would be a cleaner foundation than bolting PQC onto the Schnorr proof. Evaluating a PQ-PAKE replacement for the equality test is the most significant open cryptographic item.

### Constant-time SMP ZKP scalar arithmetic

The SMP modular exponentiation is constant-time (v10.7.6), but the surrounding ZKP scalar arithmetic — the `d = r - c*x` response computation — still uses variable-time `num-bigint`. This is a real residual timing side-channel on the secret exponents. It was deliberately not hot-patched because rewriting working ZKP arithmetic into `crypto-bigint` constant-time ops risks a correctness regression; it needs its own test vectors and careful review.

### Seed-only ML-KEM key storage (if persistence is ever added)

ML-KEM private keys are currently held as the full expanded decapsulation key (3168 B) rather than the 64-byte (d,z) seed. This is moot today because the keys are fully ephemeral — fresh per DAKE and per ratchet step, used once, zeroized, never persisted — so the binding attacks that seed-only storage defends against (which concern stored-and-reloaded keys) do not apply. If key persistence is ever added, switch to seed-only storage and re-derive deterministically.

### Post-quantum ClientProfile signing

ClientProfile signatures are Ed448 only. Adding an ML-DSA-87 signature alongside would extend hybrid authentication to the profile itself.

## What is not on the roadmap

- Backward compatibility with older v10.6.x versions. The no-fallbacks posture in v10.6.11 onward means peers must run the same major version. Wire incompatibility is accepted.
- Compatibility with stock OTRv4 implementations. The ML-DSA-87, ML-KEM-1024, and SHAKE-256 transcript additions are deliberate OTRv4+ extensions.
- Mobile push notifications. The IRC client uses persistent TCP, not push.
- File transfer. Out of scope.

## Tracking

Issues for the above are filed on the GitHub repo. Tag conventions: `phase-5.3i`, `cargo-hardening`, `phase-5.3g`. Priority is not strict; whichever has the cleanest scope on a given evening gets done.
