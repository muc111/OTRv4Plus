# Transport audit — XMPP control plane and voice media

Audit of commit `624bbca`. Findings from tracing runtime paths, not from
module names or configuration options.

**Nothing here has been tested on a live network.** Everything below is code
tracing plus unit tests. Live TLS, Tor and I2P operation still require real
devices on real networks, and this document does not claim otherwise.

## Support matrix

| Transport | IRC (`otrv4+.py`) | XMPP control | Voice media | Status |
|---|---|---|---|---|
| **Clearnet TLS** | yes | **yes** | no | works; not anonymous |
| **Tor** | yes | **yes** (SOCKS5) | **no** | implemented; LIVE-UNVERIFIED |
| **I2P** | yes | **yes** (SAM) | **yes** (SAM datagram) | works |

Tor for the XMPP control plane was added after this audit's first pass. Voice
media remains I2P-only and deliberately so — see "Tor voice" below.

### Historical note (first pass of this audit)

At the time of the first pass, **XMPP had no Tor support at all.** `otrv4+.py` — the IRC
client — carries a `NetworkConfig` (line 745) that auto-detects clearnet,
Tor and I2P from the server hostname, with `TOR_PROXY_PORT = 9050` and a
`.onion` suffix rule. None of that exists in `otrv4plus_xmpp.py`. The XMPP
client's only branch is:

```python
use_i2p = (not args.no_i2p) and server_b32.endswith(".i2p")
```

I2P or clearnet. There is no SOCKS5 path, no `.onion` handling, and
`pysocks` appears in `otrv4plus_xmpp.py` only as a dependency name in a
requirements list (line 3263). A `.onion` XMPP server would be treated as
clearnet and the connection would simply fail — it would not silently leak,
because there is no resolver that would reach it, but it is not support.

### Tor, as implemented

Selection is by address or explicit flag, never inferred from a failure:

```python
use_tor = (not args.no_tor) and (args.tor or server_b32.endswith(".onion"))
```

`--tor` with a `.i2p` server, or `--no-tor` with a `.onion` server, both exit
rather than guess.

`start_tor_socks_forwarder` mirrors `start_i2p_sam_forwarder` exactly: it
opens a SOCKS5 tunnel and exposes it as a **loopback** TCP endpoint, and
slixmpp is handed that address. Two consequences, both load-bearing:

* slixmpp's own docstring says *"If an address was provided, disable using
  DNS SRV lookup"* — so there is no SRV query, and the onion name never
  reaches slixmpp at all.
* the destination travels as a **domain name** inside the SOCKS5 CONNECT
  (`ATYP 0x03`), which is what makes Tor resolve it internally. A `.onion`
  has no address a resolver could return; resolving locally would be both
  useless and a disclosure of intent.

PySocks is deliberately **not** used. It routes by assigning
`socket.socket` globally, which in this process would also capture the I2P
SAM bridge and every voice media socket. A local tunnel touches nothing else.

## Runtime paths

### Clearnet TLS
`main` → `client.connect()` → slixmpp, STARTTLS enabled
(`enable_starttls = True`, `enable_direct_tls = False`). Certificate
verification is on by default; `--insecure-tls` replaces the context with
`check_hostname = False` / `CERT_NONE` and prints a warning that names the
concrete risk (password capture by an active MITM).

**No reconnect.** `_sam_params` stays `None` for clearnet, and
`_on_disconnected` only schedules `_reconnect` when `_sam_params is not
None`. A dropped clearnet session stays down.

### I2P
`main` → `start_i2p_sam_forwarder(server_b32, ...)` → local forwarder →
`client.connect(host, port)` where host/port is the loopback forwarder.

**Fail-closed, verified.** If the SAM bridge cannot start, `main` prints the
diagnostic and calls `sys.exit(1)`. There is no fallback to
`client.connect()`.

Reconnect re-establishes the SAM forwarder first; if that fails it applies
backoff and retries, and never falls through to a direct connection.

### Voice media
Independent of the XMPP transport. `VoiceCallSession` creates its **own** SAM
session (`SESSION CREATE STYLE=DATAGRAM ... SIGNATURE_TYPE=7`) and its own
transient destination. XMPP carries only signalling: INVITE, ACCEPT, REJECT,
REKEY, REKEYCOMMIT, REKEYACK, MEDIAPATH, END.

The independence cuts both ways. Because the media session is separate, an
XMPP reconnect never disturbs healthy audio — but a network transition that
kills the media session is invisible to the XMPP reconnect that recovers
alongside it. MEDIAPATH is what lets media rebuild its own session and tell
the peer where it moved; `VOICE_MEDIA_PATH.md` has the state machine.

This is why losing XMPP mid-call does not drop audio, and why the keepalive
in `624bbca` says so on the console when it declares a stream dead.

**Voice media is I2P-only.** There is no transport abstraction: the session
speaks SAM directly. `OTRV4PLUS_VOICE_TRANSPORT` selects between SAM
*datagram* and SAM *stream* — both are I2P. Voice over Tor or over clearnet
does not exist.

## Privacy and leakage

| | Server sees your IP | Peer sees your IP | Notes |
|---|---|---|---|
| Clearnet TLS | **yes** | no (server relays) | TLS protects content, not endpoints |
| I2P | no | no | destinations are cryptographically named |
| Tor (XMPP) | n/a | n/a | not implemented |

**Clearnet is not anonymous and must never be described as if it were.**
OTRv4Plus encryption protects message content; it does nothing to hide who is
talking to which server. That distinction is worth restating because the
application-layer crypto is strong enough to invite the wrong conclusion.

### Downgrade paths — checked

| Path | Result |
|---|---|
| I2P selected, SAM fails at startup | `sys.exit(1)` — fail-closed |
| I2P selected, SAM fails at reconnect | backoff and retry — fail-closed |
| I2P selected, `_sam_params` missing | **guarded** — see below |
| TLS failure → plaintext | slixmpp `enable_starttls`; no plaintext path in this code |
| Voice media → clearnet | impossible; the session only speaks SAM |

### Latent hazard found and hardened

In `_reconnect`, the branch was:

```python
if self._is_i2p and self._sam_params:
    ... re-establish SAM ...
else:
    self.connect()          # direct clearnet
```

Unreachable today, because `_is_i2p` and `_sam_params` are set together and
`_on_disconnected` only schedules the loop when `_sam_params` is not `None`.
But the fall-through would open a **direct clearnet connection to the XMPP
server from a session the user asked to run over I2P**, exposing their
address, and it sat one condition away from being live. Anyone later adding
clearnet reconnect — which the code comments note is not implemented — would
arm it without noticing.

Now explicitly guarded: an I2P session with missing SAM parameters refuses to
reconnect and says why. A transport downgrade must not be reachable by one
condition drifting.

## Voice authorization gate

Traced to both entry points:

* outgoing — `VoiceCallManager.start_call`, `otrv4plus_voice.py:4262`
* incoming — INVITE handler, `otrv4plus_voice.py:4503`

Both call `_smp_verified(peer)` and refuse with `_explain_unverified` when it
is false. `_smp_verified` (`:4085`) consults only the engine's own
predicates, and its docstring records what it deliberately does **not**
consult — notably `client._smp_reported`, which is populated by the TUI
matching printed substrings, so peer-influenced text reaching a panel could
otherwise have unlocked a call.

Beyond the manager, the session enforces it structurally: `start_audio`
refuses unless `schedule.ready` and `keys_confirmed.is_set()`, so no audio
can flow before mutual key confirmation regardless of how the call was
reached.

**Transport is not consulted anywhere in that chain.** Authorization derives
from OTR/DAKE/SMP state alone, so it cannot be affected by which transport
carried the signalling.

## Failure states

Present and distinguishable:

* XMPP: connected / degraded (`_keepalive_degraded`) / disconnected /
  reconnecting, reported by `/status` with ticks and round trips separated.
* Voice: `CallState` — IDLE, INVITING, RINGING, MEDIA_CONNECTING, ACTIVE,
  ENDED, with `IllegalTransition` on invalid moves.

The important property holds: **XMPP failure is not voice failure.** The
keepalive says so explicitly when it disconnects.

## Deficiencies

1. **Tor is not supported for XMPP.** The largest gap. IRC has it; XMPP does
   not.
2. **Voice media is I2P-only** with no transport abstraction. Tor cannot
   carry it as designed regardless, because the media path is datagram-based
   and Tor provides TCP streams only — Tor voice would need either a
   TCP-framed media transport (reintroducing the head-of-line blocking that
   made the SAM stream transport unusable, measured at 24 s of queued delay)
   or an onion-service UDP mechanism that does not exist. This is an
   architectural limitation, not an oversight, and it should not be papered
   over with a fallback.
3. **Clearnet has no reconnect.** Deliberate, but undocumented outside a code
   comment.

## Recommended next steps, in order

1. Decide whether XMPP-over-Tor is wanted. If so it is a contained change:
   a SOCKS5 path mirroring `otrv4+.py`'s `NetworkConfig`, fail-closed, with
   `.onion` detection — control plane only, explicitly **without** voice.
2. Leave voice on I2P. It is the only transport of the three that can carry
   datagram media with the anonymity property the project requires.
3. Do not add automatic transport fallback of any kind.
