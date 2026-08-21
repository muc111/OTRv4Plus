# I2P transport tuning — what is controllable, and how

Operational companion to `I2P_VOICE_LATENCY_ANALYSIS.md`. That document
explains why each setting exists and what it was measured to be worth; this
one is the reference for changing them.

---

## 1. What the application can control

Everything in this table is sent on the `SESSION CREATE` line and is verified
against i2pd's source, not against documentation.

| Option | Default (i2pd) | Default (Java I2P) | This build sends | Effect |
|---|---|---|---|---|
| `inbound.length` | 3 | 3 | **3** | Hops. Anonymity parameter — not a latency knob. |
| `outbound.length` | 3 | 3 | **3** | As above. |
| `inbound.quantity` | 5 | 2 | **4** | Spare tunnels; absorbs expiry. |
| `outbound.quantity` | 5 | 2 | **4** | As above. |
| `inbound.lengthVariance` | 0 | 0 | **0** | Pinned: variance only ever adds hops. |
| `outbound.lengthVariance` | 0 | 0 | **0** | As above. |
| `latency.min` | 0 | — | *not sent* | i2pd-only peer-selection bound. See §4. |
| `latency.max` | 0 | — | *not sent* | i2pd-only peer-selection bound. See §4. |

Source: `libi2pd/Destination.h` for the names and i2pd defaults;
`libi2pd_client/SAM.cpp::ExtractParams` for the fact that arbitrary `key=value`
pairs on `SESSION CREATE` reach the I2CP destination layer.

Rendered form (sorted, so identical settings always produce an identical
command line):

```
SESSION CREATE STYLE=STREAM ID=otrv4voice_… DESTINATION=TRANSIENT \
  SIGNATURE_TYPE=7 inbound.length=3 inbound.lengthVariance=0 \
  inbound.quantity=4 outbound.length=3 outbound.lengthVariance=0 \
  outbound.quantity=4
```

## 2. What the application cannot control

Recorded because the absence is a real limit, not an oversight.

| Wanted | Why it is unavailable |
|---|---|
| `inbound.backupQuantity`, `outbound.backupQuantity` | Java I2P only. i2pd's `Destination.cpp` never reads them; on the bundled router they would be configuration that looks like resilience and is not. |
| `i2p.streaming.initialAckDelay` | i2pd fixes it at compile time (`Streaming.h`, `MIN_SEND_ACK_TIMEOUT = 2 ms`). |
| `i2p.streaming.initialWindowSize` | Compile-time (`INITIAL_WINDOW_SIZE = 10`). |
| `i2p.streaming.maxWindowSize` | Compile-time (`MAX_WINDOW_SIZE = 512`). |
| `i2p.streaming.connectDelay` | No I2CP option string in i2pd. |
| Per-tunnel selection or replacement | SAM exposes no per-tunnel control. The router owns tunnel selection and must continue to — an application picking its own tunnels is an application picking its own anonymity set. |

`otrv4plus_i2p.session_options()` **raises** on every option in this table.
Silently ignoring one would be worse than failing: it reads as configuration
that is in force when it is not.

i2pd's `INITIAL_RTO = 9000 ms` is the most consequential of these. A segment
lost early in a call, before the streaming layer has an RTT estimate, can cost
seconds — and no setting reachable from this codebase changes it.

## 3. Changing the settings

Edit `otrv4plus_i2p.py`:

```python
VOICE_TUNNEL_OPTIONS = _profile(4)   # media stream
XMPP_TUNNEL_OPTIONS  = _profile(4)   # signalling
```

Or per call, which validates and refuses anything unsupported:

```python
session = VoiceCallSession(
    peer, loop, call_id, is_initiator,
    sam_options=otrv4plus_i2p.session_options({"inbound.quantity": 6}))
```

Constraints to respect:

* **Never lower `inbound.length` or `outbound.length` below 3.** It is the
  fastest way to reduce latency and it is not a latency setting.
* **Do not simply maximise quantity.** Each tunnel is a build, periodic
  rebuilds, bandwidth, and one more set of peers that observes you. 4 was
  chosen as a resilience gain over Java's 2 without exceeding i2pd's 5.
* **Keep variance at 0** unless there is a specific reason to reintroduce
  jitter into the path length.

## 4. `latency.min` / `latency.max`

i2pd supports bounding peer selection by measured tunnel latency. This is the
only genuinely latency-targeted option available, and it is **not enabled**.

Reasons, stated so the decision can be revisited with data:

1. Too tight a bound starves peer selection, and tunnel *builds* begin to
   fail. The failure mode is worse than the problem: no tunnel at all rather
   than a slow one.
2. It is i2pd-only, so behaviour would diverge between routers again — the
   defect §3.4 of the analysis exists to remove.
3. Selecting peers by latency narrows the set of routers carrying the traffic.
   Whether that is an anonymity cost deserves analysis this pass has not done.

To experiment on a host with a router, add `"latency.max": 1500` (ms) to a
profile and watch tunnel-build failures before latency.

## 5. Local socket settings

| Setting | Where | Why |
|---|---|---|
| `TCP_NODELAY` | Every SAM socket and both ends of the local XMPP bridge | Nagle costs ~41 ms whenever a queued burst drains. No effect at steady 40 ms cadence — measured, and reported as a negative in the analysis. |
| Write chunk 1024 B | `otrv4plus_i2p.SAM_CHUNK` | I2P has been observed to drop a stream on a single large write (~8 KB). |
| Burst allowance 1024 B | `SAM_BURST_BYTES` | One chunk. **Was 4096 and that broke SMP on a real path** — the old code's guarantee was ≤1 chunk without a ~20 ms gap, not ≤8 KB per burst. Override with `OTRV4PLUS_SAM_BURST_BYTES` for experiments against a real tunnel only. |
| Sustained rate 51200 B/s | `SAM_RATE_BPS` | Identical to the ceiling the previous fixed-sleep pacing produced. |
| Send-queue bound 400 ms | `VoiceCallSession.VOICE_MAX_WRITE_BACKLOG_MS` | Above this, audio is stale enough that the receiver's jitter buffer would discard it anyway. |

## 6. i2pd configuration

**No i2pd change is required.** Everything above is negotiated per session
through SAM, so a shared or system router is not reconfigured by this
application — which is the correct behaviour: other I2P applications on the
host must not inherit a messenger's tunnel policy.

If a *dedicated bundled* router is used later and its defaults should match,
the equivalent `i2pd.conf` is:

```ini
[sam]
enabled = true
address = 127.0.0.1
port = 7656
```

Tunnel quantity and length stay per-session; do not set them globally.

## 7. Collecting measurements

```sh
OTRV4PLUS_TRANSPORT_LOG=/path/to/transport.jsonl python3 otrv4plus_xmpp.py …
```

Off unless the variable is set. The file is created 0600 and contains numbers,
a closed set of event names, and 8-hex-digit opaque tags — no JIDs, no
destinations, no message content. It is still traffic-analysis material: frame
counts and RTTs describe when a call happened and how long it lasted. Treat it
accordingly and delete it when the measurement is done.

Per-call summary without a file:

```
/status        →  … link=HEALTHY rtt p50/p95/p99/max=1301/1503/1610/8992ms(n=2841)
                  jit p95/max=28/412ms
```

Reproduce the local benchmarks:

```sh
python3 tools/transport_bench.py
```
