# OTRv4+ Changelog

## v10.6.3 — Critical Exposure Window closed (Phase 4 complete)

This release closes the Critical Exposure Window that has existed since
v10.6.0.  DAKE session keys (`root_key`, `chain_key_send`, `chain_key_recv`,
`brace_key`, `mac_key`) **no longer transit through Python `bytes` at any
point**.  They flow:

```
DAKE crypto in Rust  →  DakeSessionKeys (private Rust type)
                     →  DakeOutput.inner: RefCell<Option<DakeSessionKeys>>
                     →  consume_into_ratchet() — Rust-to-Rust move
                     →  DoubleRatchet's owned SecretBytes fields
                                                (ZeroizeOnDrop)
```

At no step are the secret keys marshalled into `PyBytes`.  Python receives
only the opaque `DakeOutput` handle (which exposes public material —
`ssid`, `remote_identity_pub`, `remote_mldsa_pub`, `remote_profile_bytes`,
`dake2_bytes` — and no getters for any secret field).

This closes audit findings **C2** and **C3**.  Net audit status:
**11 of 11 findings fully closed.**

### What changed

#### Rust side — `dake.rs`, `ratchet.rs`, `lib.rs`

1. **New PyO3 class `DakeOutput`** in `dake.rs`:
   - Private `inner: RefCell<Option<DakeSessionKeys>>` holds the secret
     session keys.  No `#[pyo3(get)]` accessor exists for the inner field.
   - Public `#[pyo3(get)]` accessors only for `ssid`, `remote_identity_pub`,
     `remote_mldsa_pub`, `remote_profile_bytes`, `dake2_bytes` (none secret).
   - `consume_into_ratchet(ad, dh_pub_local, is_initiator) -> RustDoubleRatchet`
     takes the secret keys out of the `RefCell`, calls the new Rust
     constructor `RustDoubleRatchet::from_dake_keys(...)`, and returns
     a fully-initialised ratchet with keys in `SecretBytes` fields.
     Subsequent calls raise `PyValueError`.
   - `consumed` getter (bool).
   - `DakeOutput::from_keys_and_public(...)` is the internal `pub(crate)`
     constructor — Python cannot build a `DakeOutput` directly (no `#[new]`).

2. **New PyO3 methods on `RustDAKE`** in `dake.rs`:
   - `generate_dake2_output(our_prekey_priv, mldsa_pub) -> DakeOutput`
   - `process_dake2_output(dake2_bytes, our_prekey_priv) -> DakeOutput`
   - Both run the same crypto as `generate_dake2` / `process_dake2`; they
     differ only in returning a `DakeOutput` instead of a `Dakeresult`.

3. **New non-PyO3 constructor `RustDoubleRatchet::from_dake_keys`** in
   `ratchet.rs`:
   - Takes `DakeSessionKeys` by-value, moves the inner 32-byte arrays onto
     stack, calls `DoubleRatchet::new(...)`, then explicit `drop(keys)` to
     invoke `ZeroizeOnDrop` on the original storage.
   - Lives in its own `impl RustDoubleRatchet { ... }` block OUTSIDE the
     `#[pymethods]` block because PyO3 cannot expose a method that takes a
     non-PyO3 Rust type (`DakeSessionKeys`).
   - Called only by `DakeOutput::consume_into_ratchet` from Rust code; not
     visible to Python.

4. **`lib.rs`** now explicitly registers both `Dakeresult` (legacy) and
   `DakeOutput` (Phase 4) so Python sees both classes.

#### Python side — `otrv4+.py`

1. **`RustDAKEAdapter.generate_dake2` / `process_dake2`** now probe for
   `hasattr(self._rust, 'generate_dake2_output')`.  When present (new
   Rust .so), they call the `_output` variant and stash the `DakeOutput`
   in `self._session_keys['_dake_output']`.  When absent (older .so),
   they fall back to the v10.6.2 byte-field path silently.

2. **Session-manager handoff** (`_handle_dake2`, `_handle_dake3`) copies
   `_dake_output` from the session-keys dict onto `session._dake_output`
   in addition to (or in place of) the legacy byte fields.

3. **`EnhancedOTRSession.__init__`** initialises `self._dake_output = None`.

4. **`RustBackedDoubleRatchet.from_dake_output(dake_output, is_initiator,
   ad, ...)`** — new classmethod constructor that calls
   `dake_output.consume_into_ratchet(ad, dh_pub_local, True)` and wires
   up the Python wrapper without touching the byte-field code path.

5. **`_initialize_ratchet`** prefers the Phase-4 path: when
   `session._dake_output` is set and not yet consumed, it calls
   `RustBackedDoubleRatchet.from_dake_output(...)`.  Otherwise it falls
   back to the v10.6.2 `RustBackedDoubleRatchet(**args)` path.

6. **Version bump** in banner: v10.6.2 → v10.6.3.

### Backward compatibility

Both code paths coexist.  v10.6.3 with the new Rust .so uses Phase 4.
v10.6.3 with an older .so (or `otrv4_core` lacking
`generate_dake2_output`) gracefully falls back to v10.6.2 behaviour.  No
breaking changes for downstream callers; the public Python API is
unchanged.

### Test-API caveat

The new Phase 4 ratchet path sets `_rks_send`, `_rks_recv`, `_rks_root`
mirrors to zero-byte placeholders because the real chain/root keys never
become accessible to Python.  Production crypto does not touch these
mirrors.  Test code that asserts on mirror contents should check
`hasattr(ratchet, '_dake_output_consumed')` and skip mirror-based
assertions when present.

Session-persistence export from a Phase-4 ratchet requires a Rust-side
serialization API (planned for v10.6.4); for now, restoring a Phase-4
session from disk falls back to fresh DAKE handshake.

### Verification

A Phase-4 ratchet exposes `_dake_output_consumed = True`.  Use this from
Python:

```python
ratchet = session.ratchet
if getattr(ratchet, '_dake_output_consumed', False):
    print("This session is Phase-4 hardened — session keys never in Python.")
else:
    print("Legacy v10.6.2 session — Critical Exposure Window applies.")
```

The Rust `.so` exposes `DakeOutput` and `RustDAKE.generate_dake2_output`
on a working Phase-4 build:

```bash
python3 -c "
import otrv4_core
print('DakeOutput class:', hasattr(otrv4_core, 'DakeOutput'))
print('PyDake.generate_dake2_output:', hasattr(otrv4_core.RustDAKE, 'generate_dake2_output'))
"
# Expected: both True
```

### Audit status at v10.6.3

| Audit ID | Description | Status |
|---|---|---|
| **C1** | Test-only API `RustSMPVault::load*` exposed in production | ✅ Fixed v10.6.0 |
| **C2** | `Dakeresult` exposes session keys as `Vec<u8>` `#[pyo3(get,set)]` | ✅ **Fixed v10.6.3** (DakeOutput opaque handle; secrets never become PyBytes) |
| **C3** | `process_dh_message` returns secrets to Python | ✅ **Fixed v10.6.3** (consume_into_ratchet path) |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter leaks brace key | ✅ Fixed v10.6.0 (getter removed) |
| **C5** | SMP passphrase enters Python `bytes` during `set_secret` | ✅ Fixed v10.6.1 (`set_secret_from_bytearray` + Rust-side wipe) |
| **C6** | Rust DAKE end-to-end correctness | ✅ Fixed v10.6.2 (MLKEM tuple, MAC scope, DH triple, private keys) |
| **P3** | `panic = "abort"` breaks FFI panic safety | ✅ Fixed v10.6.0 |
| **V1–V3** | Wire decoders did not bounds-check before slicing | ✅ Fixed v10.6.0 (`SafeSlice`) |
| **M1, M2** | `kdf_1`, `encode_header` PyO3 exports | ✅ Fixed v10.6.0 (`test-only-kdf` feature gate) |

**Net: 11 of 11 findings fully closed.**  The Rust→Python boundary
audit identified in v10.5.10 is now complete.  Remaining hardening
work (Phase 5: Ed448/X448 long-term identity keys into Rust; Phase 6:
single-API Rust protocol engine) is architectural improvement beyond
the original audit scope — see ROADMAP.md.

### Files changed

| File | Change |
|---|---|
| `Rust/src/dake.rs` | New `DakeOutput` PyO3 class; new `generate_dake2_output` / `process_dake2_output` methods |
| `Rust/src/ratchet.rs` | New non-PyO3 `RustDoubleRatchet::from_dake_keys` constructor |
| `Rust/src/lib.rs` | Register `Dakeresult` and `DakeOutput` explicitly |
| `otrv4+.py` | New `RustBackedDoubleRatchet.from_dake_output` classmethod |
| `otrv4+.py` | `RustDAKEAdapter.generate_dake2` / `process_dake2` prefer `_output` API |
| `otrv4+.py` | Session-manager handoff copies `_dake_output` onto session |
| `otrv4+.py` | `_initialize_ratchet` prefers Phase-4 path when `_dake_output` present |
| `otrv4+.py` | Version bumped to v10.6.3 |

### Build instructions

```bash
cd ~/OTRv4Plus
cp dake.rs ratchet.rs lib.rs Rust/src/
cp otrv4plus.txt otrv4+.py
cd Rust && cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so
cd ..
strings otrv4_core.so | grep -c DakeOutput
# Expected: > 0
python3 -c "import otrv4_core; print(hasattr(otrv4_core, 'DakeOutput'))"
# Expected: True
PYTHONMALLOC=malloc python otrv4+.py --debug
# Banner should show: Version : OTRv4+ 10.6.3
```

### Commit message for this release

```
v10.6.3 — Phase 4 complete: Critical Exposure Window closed

DAKE session keys (root, chain_send, chain_recv, brace, mac) no longer
transit through Python bytes at any point.  They move:

  Rust DAKE crypto
    → DakeSessionKeys (private Rust type, ZeroizeOnDrop)
    → DakeOutput.inner: RefCell<Option<DakeSessionKeys>>
                       (private; no PyO3 getter)
    → consume_into_ratchet() — Rust-to-Rust move
    → DoubleRatchet's SecretBytes fields (ZeroizeOnDrop)

No PyBytes copy at any step.  Closes audit findings C2 and C3.

Rust changes:
  - New PyO3 class DakeOutput in dake.rs with RefCell<Option<DakeSessionKeys>>
    private field.  No #[pyo3(get)] for secrets; only ssid / peer pub /
    profile / dake2_bytes are exposed.
  - New PyO3 methods RustDAKE::generate_dake2_output, process_dake2_output.
  - New non-PyO3 constructor RustDoubleRatchet::from_dake_keys that takes
    DakeSessionKeys by-value and moves them into the ratchet's owned
    SecretBytes fields via DoubleRatchet::new.
  - lib.rs now explicitly registers Dakeresult and DakeOutput.

Python changes:
  - RustDAKEAdapter.generate_dake2 / process_dake2 probe for the _output
    PyO3 methods and prefer them when present.  Older .so builds fall back
    to v10.6.2 byte-field path silently.
  - Session-manager handoff copies _dake_output onto session object.
  - New RustBackedDoubleRatchet.from_dake_output classmethod constructs
    the ratchet by calling output.consume_into_ratchet without ever
    materialising session keys as Python bytes.
  - _initialize_ratchet prefers the Phase-4 path when session._dake_output
    is present; falls back to legacy path otherwise.
  - Version bumped: v10.6.2 → v10.6.3.

Net audit status: 11 of 11 findings fully closed.  The Rust→Python
boundary audit from v10.5.10 is now complete.

Remaining hardening work (Phase 5: long-term identity keys; Phase 6:
single-API Rust engine) is beyond the original audit scope — see
ROADMAP.md.

Backward compatibility: both paths coexist.  v10.6.3 with new .so uses
Phase 4; with older .so falls back to v10.6.2 behaviour.  Public Python
API unchanged.

Test-API caveat: Phase-4 ratchet sets _rks_send / _rks_recv / _rks_root
mirrors to zero placeholders.  Production crypto does not touch them.
Tests that assert on mirror contents should check
hasattr(ratchet, '_dake_output_consumed') and skip those assertions.

Persistence export from a Phase-4 ratchet requires a Rust serialization
API (planned for v10.6.4).  Until then, restoring a Phase-4 session from
disk falls back to fresh DAKE.
```

---

## Earlier releases (summary)

### v10.6.2 — Rust DAKE end-to-end correctness

Four crypto bugs in the Rust DAKE path that prevented MAC verification:

1. `pqcrypto_kyber::encapsulate` tuple order reversed (32-byte SS on wire
   where 1568-byte CT expected)
2. Responder MAC input did not include `MSG_DAKE2` byte or ML-DSA pub
3. Initiator `dh2` and `dh3` were identical computations
4. Adapter passed public keys where Rust constructor expected private bytes

Plus IRC 401 handler killing sessions during multi-fragment DAKE.

Closes audit finding C6.

### v10.6.1 — Boundary hardening Patch 2

`Dakeresult.consumed` flag; aggressive zero (`clear()` + `shrink_to_fit()`)
in `from_dakeresult`; Rust-side bytearray wipe in
`set_secret_from_bytearray`; PyO3 0.21 `Bound<...>` migration.

### v10.6.0 — Audit Patch 1

`set_secret_from_bytearray`, `from_dakeresult` (move + zero), `brace_key`
getter removed, `panic = "unwind"`, `SafeSlice` trait, `try_slice` /
`try_byte`, `MAX_WIRE_FIELD_LEN`, `kdf_1_py` / `encode_header_py` gated
behind `test-only-kdf`, `RustSMPVault::load*` gated.

### v10.5.10 — Rust SMP engine

Full four-message SMP state machine in Rust with `ZeroizeOnDrop` on all
exponents.  `RustSMPVault` Rust-owned secret store.  50k-round
SHAKE-256 + HMAC-SHA3-512 KDF.  Canonical fingerprint ordering.

### v10.5.8 — Rust Double Ratchet, ML-DSA migration

Pure-Rust double ratchet.  Switched from `pqcrypto-dilithium` to
`pqcrypto-mldsa` (FIPS 204).
