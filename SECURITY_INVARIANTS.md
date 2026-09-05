# Security Invariants

The rules OTRv4+ development must not break, and the test that fails when one
does.

This document is generated from `tests/security_invariants.py`, which is the
authoritative list. `tests/test_invariant_registry.py` fails if the two
disagree, if an invariant names no enforcing test, or if a named test module
does not exist. That last check exists because `VERSIONING.md` once claimed
the SMP wire byte was pinned by a test for a whole release before it actually
was, and nothing noticed: prose cannot be executed.

## How to read the status column

| Status | Meaning |
|---|---|
| `ENFORCED` | A test fails if the property is broken. |
| `PARTIAL` | Tested, but the test cannot cover the whole property. The limit is stated. |
| `INHERENT` | Guaranteed by a language or library mechanism rather than by our code, and pinned by a test asserting the mechanism is still declared. |
| `ACCEPTED` | A known limitation that cannot be fixed at this layer. The test pins the DOCUMENTATION, so the claim cannot silently strengthen. |

A `PARTIAL` or `ACCEPTED` entry with no stated limit is an `ENFORCED` claim in
disguise, and the registry test rejects it.

## The invariants

### INV-01 — SMP secrets are never at rest in plaintext.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_at_rest.py`

Sealed with AES-256-GCM under an Argon2id-derived key, AAD b'smp_secrets_v1', written 0600 via atomic replace.

### INV-02 — Account passwords are never written to disk.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_secret_at_rest.py`

Collected with getpass, held only for the connection attempt, dropped afterwards.

**Limit:** Dropping a Python str releases the reference but cannot overwrite the buffer.  Unfixable while credential handling is Python-side -- slixmpp for XMPP, otrv4+.py for IRC -- and not merely by moving storage into Rust, since getpass returns a str.  See INV-08.

### INV-03 — No secret value reaches any log sink.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_log_boundary.py`

The session log is an allowlist of line shapes, not a denylist of patterns: a line is written only if it matches a known-safe form.

### INV-04 — No secret value is printed to the terminal or UI.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_never_echoes.py`, `tests/test_log_boundary.py`

### INV-05 — Secret input does not echo, and the client never promises secrecy it did not achieve.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_secret_never_echoes.py`

termios ECHO is cleared with TCSANOW; the masking helper returns whether it took effect and the prompt wording follows that return value.

### INV-06 — Remote SMP messages may request local user interaction but can never capture arbitrary local input.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_no_remote_input_capture.py`, `tests/test_smp_guided_flow.py`

A peer's SMP1 moves otrv4plus_smpflow.SmpFlow to AWAITING_LOCAL_CONSENT and no further.  The only edges into AWAITING_SECRET -- the state in which a typed line is read as a passphrase -- are local_secret_needed (the user typed /smp) and local_consent (the user typed y).  A chat message typed at a consent prompt is not y, so it is sent as a message.

### INV-07 — Rust-owned secret material zeroizes on drop.

**Status:** `INHERENT`  
**Enforced by:** `tests/test_rust_zeroization.py`

SecretBytes<N> and SecretVec derive ZeroizeOnDrop; their Debug impls print [REDACTED].

### INV-08 — Python does not receive long-lived private key material that Rust can own instead.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_release_guard.py`, `tests/test_rust_zeroization.py`, `tests/test_voice_rust_parity.py`

Ed448 seeds, ratchet keys, SMP scalars and -- since v10.13.2 -- voice media keys, the voice epoch root and the voice X448 scalar never cross the PyO3 boundary; the legacy getters are compiled out.

**Limit:** The typed SMP passphrase and the account password are Python `str` before anything can touch them, and a `str` cannot be wiped.  The identity DEK and the device seeds are Python `bytes` read from disk.  Everything derived from them is Rust-owned.

### INV-09 — XMPP persistent identity and IRC ephemeral identity are separate stores.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_identity_and_tofu.py`, `tests/test_transport_isolation.py`

### INV-10 — An IRC run never writes identity, trust or fingerprint state to disk.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_isolation.py`

OTRConfig.persist_identity and .persist_trust default False; TrustDatabase._save returns early when not persistent.

### INV-11 — TOFU never silently re-pins a changed fingerprint.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_identity_and_tofu.py`

The mismatch branch keeps the old pin, offers no y/n, refuses voice, and requires an explicit /trust-reset.

### INV-12 — Voice is authorised by cryptographic SMP verification alone.  Display or trust state cannot unlock it.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_voice_authorization.py`

_smp_verified reads only the engine's published predicates; both the outbound and inbound call paths consult it.

### INV-13 — Rejected media is classified by cause.  A missing key, a retired epoch, a replay and a failed AEAD tag are distinguishable.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_media_reject_classification.py`

Diagnosing rekey divergence requires telling 'we have no key for this epoch' apart from 'this packet is forged'.

### INV-14 — No home-grown cryptographic construction exists where the Rust core already supplies the primitive.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_no_parallel_crypto.py`

The hand-rolled SHAKE-256 stream cipher in otrv4plus_log.py was deleted at v10.13.1.

### INV-15 — Production builds expose no debug secret getters.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_release_guard.py`

legacy-dake-keys and test-only-kdf are off by default and build.rs refuses them without an explicit env opt-in.

### INV-16 — A rekey never leaves the two peers on media key states that cannot reach each other.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_rekey_divergence.py`

A receive key is retired only once the peer has demonstrably stopped sending under it.

**Limit:** Proven against the modelled message sequences, not against live I2P.  See the rekey analysis in SECURITY.md.

### INV-17 — A transport failure or degradation never selects a less private transport.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_failclosed.py`, `tests/test_transport_policy.py`

Selection is by address suffix or explicit flag, checked before connecting, and contradictory flags exit rather than guess.  There is no fallback ladder and no latency-triggered switch: I2P that cannot carry a call means no call.

### INV-18 — The transport class is fixed for the lifetime of a call.  An endpoint may change within a class if the change is authenticated; a class change requires ending the call.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_transport_policy.py`

MEDIAPATH moves the media endpoint within the I2P class, authenticated from the committed epoch root -- which is what recovered the Wi-Fi-to-mobile transition.  The forbidden transitions are I2P->TLS, Tor->TLS and TLS->I2P; the matrix is an allowlist.

**Limit:** Enforced today by there being exactly one media transport class, so no cross-class transition is reachable.  The structural guarantee -- binding TransportClass into the voice transcript so a mismatched pair never keys -- is specified in TRANSPORT_POLICY.md section 5 and deferred until the I2P voice and rekey work completes live-device validation.

### INV-19 — A proxy route is never presented as anonymity, and a clearnet transport is never described as weak encryption.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_transport_policy.py`

Encryption, anonymity and routing are three properties, not three points on one scale.  A proxy is routing: the operator can log, identify, inject or be compromised.  Clearnet TLS 1.3 is strong encryption with no anonymity, and calling it 'less secure' teaches the wrong lesson.

### INV-20 — OTRv4+ client identification is display metadata.  It never authenticates, confers trust, or unlocks a capability.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_irc_names_list.py`

The blue /names marker comes from the realname (gecos) the peer's own client sent at registration and the server relayed in RPL_WHOREPLY.  Nobody checks it and nobody can: any user may put that string in their own gecos.  It answers 'is this peer likely to understand /otr' and nothing else.  The DAKE authenticates, TOFU pins identity, SMP authorises voice; the renderer is a pure function with no client to promote anything on.

### INV-21 — A /sendfile FileKey is generated, used and destroyed inside Rust.  Python never receives it.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_file_transfer_crypto.py`, `tests/test_file_transfer_boundary.py`

RustFileSender owns a fresh SecretBytes<32> per transfer with no getter; the wrapping key is derived inside Rust from the session's DAKE extra symmetric key and never materialises outside it.  Python holds a handle, an opaque 60-byte envelope and ciphertext.  The offer's wire form is checked for a serialised key, and the orchestration module is checked for any key-shaped name.

### INV-22 — A remote peer never chooses where a received file is written, and an unverified file is never placed.

**Status:** `ENFORCED`  
**Enforced by:** `tests/test_file_transfer_storage.py`, `tests/test_file_transfer_boundary.py`

The output directory is fixed locally and only a sanitised basename comes from the offer, so there is no peer-supplied path to traverse out of.  Placement happens by atomic rename only after the chunk tags, both hashes and the on-disk size all verify; any failure deletes the temporary file and drops the transfer.

### INV-23 — Every Rust dependency on the Python/Rust boundary is checked against known advisories, and the compiled artifact is what gets verified.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_dependency_advisories.py`, `tests/test_pyo3_boundary.py`

PyO3 is the boundary itself, so an advisory against it is an advisory against the boundary.  Cargo.lock is asserted at or above the fixed release AND the vulnerable code is asserted unreachable, because either alone rots: a version check hides that the reachability analysis has expired, and a reachability check leaves us on a known-vulnerable release.  test_pyo3_boundary.py then drives the installed extension module, not the source tree, so a conversion regression introduced by an upgrade is caught in the artifact that ships.

**Limit:** The advisory list is not fetched automatically; GHSA-36hh-v3qg-5jq4 is pinned by name and a new advisory needs a human to add it.  What the tests do enforce is that a remediated advisory cannot silently regress.

### INV-24 — No IRC message survives the connection it arrived on.

**Status:** `PARTIAL`  
**Enforced by:** `tests/test_irc_history_privacy.py`

Panel history is capped at 1000 messages and emptied at every boundary between one connection and the next -- disconnect, reconnect, /quit, process exit -- along with the unread counters, the recent-user sets and the terminal's own saved scrollback.  On I2P the point of a new session is that it is not linkable to the previous one; replaying the old conversation into the new one links them on screen whatever the transport did.

**Limit:** A Python str is immutable and may be interned, so the purge drops the last reference rather than overwriting the characters: the bytes remain in freed heap until the allocator reuses them.  Unfixable for chat text while the UI is Python-side.  Material that must actually be destroyed is not kept here at all -- it lives in Rust behind zeroize().  See INV-02 for the same limit on passwords.

## Where secrets live

Updated at v10.13.2, when the voice path finished moving.

| Material | Owner | Representation | Wipeable |
|---|---|---|---|
| Ratchet root / chain keys | Rust | `SecretBytes<32>` | yes, on drop |
| DAKE session keys | Rust | opaque `DakeOutput` | yes, on drop |
| SMP secret scalar | Rust | `SecretVec` | yes, on drop |
| Ed448 identity seed | Rust | `SecretBytes<57>` | yes, on drop |
| Voice epoch root | Rust | `SecretBytes<64>` | yes, on drop |
| Voice media keys | Rust | `SecretBytes<32>` | yes, on drop |
| Voice X448 private scalar | Rust | `SecretBytes<56>` | yes, on drop |
| X448 / ML-KEM shared secrets | Python → Rust | `bytearray`, wiped by Rust | yes |
| SMP passphrase (typed) | Python → Rust | `str` → `bytearray` → Rust | the `str` cannot be |
| Account password | Python | `str` | **no** |
| Identity DEK, device seeds | Python | `bytes` from disk | **no** |

The remaining Python rows are not oversights. The account password must be a
`str` because slixmpp's SASL path requires one; the typed passphrase is a
`str` before anything else can touch it; the DEK and seeds are read from
files. Everything *derived* from them is Rust-owned, and
`tests/test_secret_at_rest.py` pins those statements so they cannot quietly
become claims.

The account-password row is scoped, not permanent. It is unfixable **while
credential handling is Python-side** — slixmpp for XMPP, `otrv4+.py` for IRC —
rather than unfixable in principle. Note what a fix would actually take:
moving the *storage* into Rust is not enough, because `getpass.getpass()`
returns a `str` and the credential exists in that buffer before anything else
can touch it. The capture has to move too. slixmpp is a test dependency and
the production XMPP client is planned to be Rust-hardened; until that lands
this is a limitation, not a plan.

## Rules that follow from these

**Before changing a security-sensitive subsystem**, search the repository for
existing implementations, tests and documentation. Afterwards, search again
for duplicates and contradictions. Both halves matter: the Argon2id-in-the-core
claim survived a documentation-synchronisation pass because the table was read
and not checked against the source.

**Do not add a cryptographic construction** where the Rust core already
supplies the primitive (INV-14). The last one to try was a SHAKE-256 keystream
cipher in `otrv4plus_log.py`; it was deleted rather than re-based, because the
module did not need to encrypt anything.

**Do not let remote input decide what local input means** (INV-06). A peer
choosing when a prompt appears is a peer choosing what the user's next
keystroke does.

**A differential test must not compare an implementation with itself.** When
`VoiceFrameCrypto` began delegating to Rust, the parity test that had caught a
wrong length prefix started comparing Rust against Rust and a reintroduced bug
passed clean. Reference implementations in tests are built from primitives,
not imported from the module under test.

**Prove a secret changed without reading it.** Tests that used to compare
epoch roots byte for byte now compare the confirmation pair, which is a
deterministic function of the root and travels on the wire anyway. Where that
is not possible, assert the observable consequence — two calls that share a
media key produce identical ciphertext for identical plaintext.

**Encryption, anonymity and routing are three properties** (INV-19). A proxy
is routing: it moves who-sees-what, it does not remove it, and the operator can
log, identify, inject or be compromised. Clearnet TLS 1.3 is strong encryption
with no anonymity — calling it "less secure" is wrong and teaches the wrong
lesson. [TRANSPORT_POLICY.md](TRANSPORT_POLICY.md) holds the full policy,
including the transition matrix and the two fallback sequences that must never
exist.

**Identification is not authentication** (INV-20). The blue OTRv4+ marker in
`/names` is the realname the peer's own client sent at registration; the server
relays it and nobody checks it. It says "this peer probably understands /otr".
The DAKE authenticates, TOFU pins identity, SMP authorises voice. Wiring a
marker into any of those would make a self-asserted string a security decision.

**A file transfer keys from the session, not from a new handshake** (INV-21).
The double ratchet's brace key already folds ML-KEM-1024, so a transfer key
derived from session state is already post-quantum and already
DAKE-authenticated. Running a second KEM to reach a level the session has
would be the second cryptographic system this project keeps refusing to build.

**Fail closed.** A failure to determine SMP state does not authorise a call
(INV-12). An unrecognised log line is not written (INV-03). A rekey that
cannot complete leaves the committed epoch alone (INV-16). A missing
`RustVoiceCipher` means no voice rather than a Python fallback.

**Do not claim more than the implementation provides.** At-rest protection for
the identity, the SMP secrets and the device seeds is filesystem permissions,
not cryptography: an attacker who can read the home directory can read all of
them. Rust ownership does not defend against a compromised kernel, root-level
malware, or an unlocked device — it stops keys outliving their use and being
reachable by ordinary introspection, which is a narrower and real thing.
