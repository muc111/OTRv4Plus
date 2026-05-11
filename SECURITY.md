# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v10.6.2 | ✅ recommended |
| v10.6.0 – v10.6.1 | ⚠️ audit hardening present but Rust DAKE silently falls back to Python.  Upgrade recommended. |
| v10.5.10 | ⚠️ Rust SMP working; DAKE path is Python-only. |
| v10.5.8 – v10.5.9 | ❌ SMP responder did not transition to verified state |
| older | ❌ |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab → Report a
vulnerability).  Do not open a public issue.

Include: description, steps to reproduce, potential impact, suggested
fix (if any).  Acknowledgment within 48 hours; fix for critical issues
within 14 days.

## In-scope

- Cryptographic weaknesses (DAKE, ratchet, SMP, ring signatures)
- Key material leaks (memory, disk, network)
- Authentication bypasses
- Plaintext recovery
- Secret material crossing the Rust/Python boundary unintentionally

## Out-of-scope

- Endpoint compromise (rooted device, malware on the device)
- I2P / Tor network-level attacks
- Social engineering of users into accepting fingerprints

## Known limitations (read before deploying)

OTRv4+ is a research prototype.  No third-party audit has been
performed.  The following are documented and tracked:

### Critical Exposure Window for session keys

After DAKE2 completes, session keys (root key, chain keys, brace key,
MAC key) exist briefly as Python `bytes` in the Python heap until
`RustDoubleRatchet.from_dakeresult(...)` consumes them.  Window
duration is microseconds to single-digit milliseconds under normal
load; can extend to seconds under debugger / GC pause / signal
handler interrupt.

Mitigations in place (v10.6.1+):

- `Dakeresult.consumed` flag prevents post-consumption access via getters
- `from_dakeresult()` aggressively zeroes the `Vec<u8>` backing memory
  (overwrite → `clear()` → `shrink_to_fit()`)
- Adapter calls `from_dakeresult()` synchronously on the same Python
  thread that received the Dakeresult — no thread-boundary or
  long-lived reference

Full closure requires `DakeOutput` opaque handle — see ROADMAP Phase 4.

Threat model: an attacker with process-memory read capability
(debugger, core dump, `/proc/<pid>/mem`, ptrace) active during the
window can recover session keys.  An attacker who reads memory after
the window has closed cannot.

### No formal audit, no formal model

313 automated tests including 100k-message ratchet gauntlets, KEM
known-answer vectors, ring-signature non-malleability checks, SMP
full-protocol flows, and property-based fuzzing via Hypothesis.  No
third-party security review.  No ProVerif or EasyCrypt model.

### No post-quantum deniability

Ed448 ring signatures provide deniable authentication in DAKE3.  ML-DSA
signatures are non-repudiable.  When ML-DSA is enabled (the default),
the post-quantum branch of authentication breaks the deniability
property that the classical branch provides.  Documented limitation.

### Metadata visible to IRC server

Who talks to whom, when, and fragment sizes.  I2P / Tor hide IP but
not timing or fragment-count patterns.  DAKE produces more fragments
(~24 per message) than chat (1 fragment for short messages).  No
padding at the fragment layer.

### Long handshake on I2P

Total `/otr` → 🔵 verified is ~6m 37s.  Cryptographic compute is
under 1 second.  Everything else is I2P tunnel latency.  This is a
usability concern, not a security one — if it's faster you should be
suspicious.

### Endpoint trust

The OTR threat model assumes both endpoints are trusted.  A rooted
device, malware on the device, ptrace by another local process, or a
debugger attached to the OTRv4+ process all defeat OTR's protections.
This is universal to OTR-class systems and not specific to v4+.

### C extensions handle some crypto

`otr4_ed448_ct.c`, `otr4_crypto_ext.c`, `otr4_mldsa_ext.c` use
OpenSSL 3.5+ primitives with `BN_mod_exp_mont_consttime`,
`OPENSSL_cleanse`, and `mlock` where available.  Constant-time helpers
are in place but no independent timing audit has been performed.
ROADMAP Phase 6 ports these to pure Rust.

---

## Disclosure policy

We follow standard responsible disclosure: report privately, allow
~14 days for critical fixes, then public disclosure with attribution.
For findings that need a longer fix horizon we will negotiate the
disclosure date with the reporter.

Public security advisories are published in GitHub's Security tab
once a fix has shipped.
