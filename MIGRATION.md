# MIGRATION.md

Upgrade notes between OTRv4+ versions. This file covers what changes between
versions for someone already running OTRv4+ — wire compatibility, build changes,
and any manual steps.

> **Wire compatibility policy:** OTRv4+ does not maintain backward compatibility
> across versions. Both peers must run the **same version**. There is no fallback
> path and no negotiation with stock OTRv4. This is deliberate (see
> [ROADMAP.md](ROADMAP.md)).

---

## To v10.12.0 (from v10.11.1)

**Both peers must update if you use voice.** `MEDIAPATH` is a new control
message. A v10.12.0 peer whose media path fails will announce a replacement
endpoint; a v10.11.1 peer does not understand the message, ignores it, and will
keep sending to an address that has gone away — so the recovery silently does
nothing and the call still dies. Nothing is *unsafe* about the mismatch (the
announcement is authenticated and an old peer simply drops it), but the feature
does not work one-sided.

No media frame, key-schedule, replay-window or transcript change in this cycle.
Verified: `VOICE_PROTOCOL_VERSION`, `VOICE_HDR_LEN`, `VOICE_PLAIN_LEN`,
`VOICE_OPUS_SLOT`, `VOICE_TS_LEN` and `VOICE_PACKET_LEN` are all unchanged
across `f129578..HEAD`. A frame produced by either build decodes on the other.

One caveat on that statement: the version strings had drifted across five files
before this release (see [VERSIONING.md](VERSIONING.md)), so "v10.11.1" cannot be
pinned to an exact commit. The frame-format guarantee above is stated against
the commit range, which is checkable; treat it as authoritative over the version
label.

Chat is unchanged. The Rust core moved `0.10.21 → 0.10.22`, but only to catch up
with the MKmac and revealed-MAC-key work that had already shipped without a
crate bump — if you built after those landed, your `.so` is already current.

Check your wire geometry matches on both phones before blaming the network:

```bash
python3.12 -c "import otrv4plus_voice as v; print(v.VOICE_FRAME_MS, v.VOICE_BITRATE, v.VOICE_PACKET_LEN)"
# expected on both ends: 60 24000 279
```

Peers configured differently establish a call, report it healthy, and carry no
audio. `OTRV4PLUS_OPUS_FRAME_MS` and `OTRV4PLUS_OPUS_BITRATE` are wire-format
settings; everything else in `Rust/VOICE_TUNING.md` is local.

New environment switches, all optional:

| Variable | Default | Effect |
|---|---|---|
| `OTRV4PLUS_RX_SESSION_HOLD_MS` | `30000` | how long a still-live SAM session delays an endpoint rebuild; `0` disables the hold |
| `OTRV4PLUS_RX_START_GRACE_MS` | `120000` | how long a call that has never carried audio is given before its path is judged |
| `OTRV4PLUS_RECOVER_ATTEMPTS` | `2` | endpoint rebuild attempts; `0` disables recovery and restores the plain fail-safe |
| `OTRV4PLUS_M2E_GOOD_MS` / `_WARN_MS` | `400` / `800` | latency colour bands; `NO_COLOR` disables banding |

If you are building voice for the first time, note that it needs the Python
`cryptography` package and `libopus`, which chat does not. See
[SECURITY.md](SECURITY.md) caveat 11 for why that is the case and what it costs.

## To v10.10.0 – v10.11.1

Not documented at the time. These releases introduced the XMPP transport and
the first encrypted voice path; both are breaking against v10.9.x. Treat an
upgrade across this range as "update both peers, rebuild, re-verify SMP".

## To v10.9.2 (from v10.9.1)

No protocol or wire change. Documentation only: `SPEC.md` added, README /
SECURITY / WHY updated for the hybrid SMP, `termux_install.sh` rewritten
Rust-only, version strings aligned to 10.9.2.

No rebuild strictly required if you are already on v10.9.1, but pulling the new
`smp.rs` header and `otrv4+.py` version string keeps everything consistent.

## To v10.9.1 (from v10.9.0)

**Rebuild required** (`smp.rs` changed) and **both peers must update**.

- SMP session timeout raised to 45 minutes. If only one peer updates, the
  un-updated peer may still time out on a slow I2P path.
- I2P fragment size reduced to 380 bytes and send pacing changed. The Python
  layer changed; copy the new `otrv4+.py` to both peers.
- Per-panel scroll fix and IRCv3 typing notifications — Python only.

## To v10.9.0 (from v10.8.x) — hybrid PQC SMP

**This is a breaking SMP change. Both peers MUST run v10.9.0+ to complete SMP.**

The SMP wire format is now versioned (byte 0 = `0x01` classical / `0x02` hybrid
PQ). A v10.9.0 peer and an older peer will detect the version mismatch and abort
the SMP session rather than silently downgrading. The DAKE is unaffected; only
the SMP identity-verification step changed.

Rebuild the Rust core and copy both the new `smp.rs` (via rebuild) and
`otrv4+.py` to each peer.

---

## Build & Test

As of v10.7.5 there are no C extensions to build, and chat is Rust-core-only.
Voice additionally needs the Python `cryptography` package and `libopus`.

```bash
# Production build:
cd ~/OTRv4Plus/Rust && \
    cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cp target/release/libotrv4_core.so ../otrv4_core.so && \
    cd ..

# Verification:
cd Rust && cargo test --release --no-default-features --features pq-rust
# Expected: 30+ passed, 0 failed.
cd ..

python3 -c "import ast; ast.parse(open('otrv4+.py').read()); print('AST OK')"
PYTHONMALLOC=malloc python otrv4+.py --debug
```

The `--no-default-features --features pq-rust` flag set is required on
Termux/aarch64 to avoid `SIGILL` from the AVX2/NEON paths of the pqcrypto crates.

> The old `python setup_otr4.py build_ext --inplace` and `bash build_ed448.sh`
> commands are gone — both were for the C extensions retired in Phase 5.3k
> (v10.7.4). If `setup_otr4.py` or `build_ed448.sh` are still present in an old
> tree, they are relics and can be deleted.

---

## Historical migration notes (pre-v10.8)

- **v10.7.5** — C extensions fully retired. ClientProfile validity tightened to
  14 days. If you have offline-cached profiles older than 14 days they now
  require a fresh DAKE1 (which the ephemeral design does anyway).
- **v10.7** — Python `cryptography` library removed entirely. No runtime change
  for users; build no longer needs the `cryptography` package.
- **v10.6.16** — ML-KEM migrated from round-3 Kyber (`pqcrypto-kyber`) to FIPS
  203 (`pqcrypto-mlkem`). Wire-incompatible with v10.6.15 and earlier.
- **v10.6.11 onward** — no-fallback posture: a build without the Rust core
  cannot complete a session. Peers must run the same major version.
