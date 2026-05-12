# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v10.6.3 | ✅ recommended (Critical Exposure Window closed; 11/11 audit findings resolved) |
| v10.6.2 | ⚠️ Rust DAKE working end-to-end but session keys still briefly PyBytes during DAKE2.  Upgrade to v10.6.3 recommended. |
| v10.6.0 – v10.6.1 | ❌ Rust DAKE silently falls back to Python (signature mismatch).  Upgrade required. |
| v10.5.10 | ⚠️ Rust SMP working; DAKE path is Python-only |
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
performed.  The following are documented and tracked.

### Critical Exposure Window — CLOSED in v10.6.3

In v10.6.0–v10.6.2 there was a brief window (microseconds to
milliseconds, longer under debugger / GC / signal interrupt) during
which session keys existed as Python `bytes` in the Python heap.

**v10.6.3 closes this window.**  The new `DakeOutput` opaque handle and
`consume_into_ratchet` path move session keys directly from Rust DAKE
state into the ratchet's `SecretBytes` fields without ever marshalling
them into `PyBytes`.  Verify with:

```python
ratchet = session.ratchet
assert getattr(ratchet, '_dake_output_consumed', False), \
    "Phase-4 not active — check .so build and Rust DakeOutput class"
```

If `_dake_output_consumed` is False on v10.6.3, the Rust `.so` is
likely from an older build.  Force a clean rebuild:

```bash
cd ~/OTRv4Plus/Rust && cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so
strings ../otrv4_core.so | grep -c DakeOutput   # must be > 0
```

### Long-term identity keys still in Python (Phase 5 scope)

Ed448 identity key and X448 prekey private bytes are held in Python
`cryptography` library `PrivateKey` objects (underlying secret bytes in
OpenSSL C heap, but Python holds the reference).  At session start,
raw private bytes are extracted and passed into Rust.

Threat model: an attacker with process-memory read on the OTRv4+ Python
heap can recover the long-term private keys for as long as the
`PrivateKey` Python object is alive (i.e. the entire process lifetime).
Phase 5 moves these into Rust `SecretVec` storage.

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

Total `/otr` → 🔵 verified is ~6m37s.  Cryptographic compute is under
1 second.  Everything else is I2P tunnel latency.  This is a usability
concern, not a security one — if it's faster you should be suspicious
(it would mean shorter tunnels and less anonymity).

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
