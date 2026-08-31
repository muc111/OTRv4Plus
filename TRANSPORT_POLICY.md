# Transport Policy

Which networks OTRv4+ is allowed to carry traffic over, how one is chosen, and
what may and may not change once a call is running.

This document is **policy and specification**. It is deliberately ahead of the
implementation: two of the five modes below do not exist yet, and one of them
may never exist. Section 8 states exactly which is which, and every claim in
this document is either enforced by a named test or marked as not implemented.
Writing the rules before the code is the point — the transports that already
exist were each added under a different set of assumptions, and the next one
should not be.

Related: [TRANSPORT_AUDIT.md](TRANSPORT_AUDIT.md) records what the code does
today, traced from the runtime paths. [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md)
holds the machine-checked list, of which INV-17 to INV-19 come from here.
[SPEC.md](SPEC.md) §9.8 is the normative wire-level statement for voice.

---

## 1. Three things that are not the same thing

The single most common error in this area is treating these as one property
measured on one axis:

**Encryption** is confidentiality and integrity of content. OTRv4+ provides it
at the application layer, identically on every transport. It is the same X448 +
ML-KEM-1024 hybrid whether the bytes travel over I2P or over a clearnet TCP
socket.

**Anonymity** is unlinkability of the endpoints. It comes from the network, not
from the cipher. No amount of application-layer cryptography hides which
address contacted which server.

**Routing** is the path the packets take — direct, through a proxy, through a
chain of proxies, through a garlic-routed overlay. Routing can *contribute* to
anonymity, and it can also contribute nothing at all while looking as if it
does.

Consequences that follow, and which this document exists to keep true:

* Clearnet TLS 1.3 is **not weak encryption**. It is strong encryption with no
  anonymity. Describing it as "less secure" is wrong and teaches the wrong
  lesson; describing it as "not anonymous" is right.
* Tor is not "the NSA one" and I2P is not "the most secure one". They are
  different overlay networks with different threat models, different latency
  characteristics, and different suitability for real-time media.
* A SOCKS5 proxy is **routing**. Sending traffic through a host you chose does
  not make it anonymous — that host can log you, identify you, inject traffic,
  or be compromised, and unlike Tor or I2P there is no cryptographic reason it
  cannot. See §6.

---

## 2. The five modes

| # | Mode | Encryption | Anonymity | Who sees your IP | Status |
|---|---|---|---|---|---|
| 1 | **I2P** | OTRv4+ over I2P | garlic-routed, 3 hops each way | neither peer nor server | implemented; live-verified for XMPP and voice |
| 2 | **Tor** | OTRv4+ over Tor | onion-routed | neither peer nor server | XMPP implemented, LIVE-UNVERIFIED; **no voice media** (§7) |
| 3 | **Clearnet TLS 1.3** | OTRv4+ inside TLS 1.3 | none | your server sees your IP | XMPP implemented; **no voice media** |
| 4 | **Clearnet TLS 1.3 + proxy** | OTRv4+ inside TLS 1.3 | none — see §6 | the proxy, and your server sees the proxy | **not implemented** |
| 5 | **Clearnet TLS 1.3 + proxy chain** | OTRv4+ inside TLS 1.3 | none — see §6 | each proxy in the chain | **not implemented** |

Modes 3, 4 and 5 are one cryptographic transport class carrying three different
routes. That is not a presentational choice; it is the structure §3 makes
explicit, and it is why a proxy must never appear in the UI as a fourth privacy
tier alongside I2P and Tor.

---

## 3. Transport class and route are separate

Two independent axes, modelled separately:

```
TransportClass  ::=  I2P | TOR | CLEARNET_TLS      -- security-relevant
Route           ::=  direct | proxy | proxy_chain  -- operational
```

**`TransportClass`** is what the security model depends on. It determines the
anonymity property, it is what the UI reports, and it is the only one of the
two that is bound into the voice cryptographic transcript (§5).

**`Route`** is how the bytes reach the class's entry point. A SOCKS5 proxy, an
HTTP CONNECT proxy, or a chain of them, sit *underneath* `CLEARNET_TLS`. A
route affects who can observe the connection, but it does not change what
cryptographic guarantees the class provides, and it must not be allowed to
masquerade as one.

`Route` is **not** bound into key derivation. Doing so would mean two peers who
chose different proxies could not talk to each other, which is nonsense: the
proxy is a local operational decision, not a shared protocol parameter. Only
`TransportClass` is a shared parameter, because it is the thing both peers must
agree on for the security claim to hold.

The rule stated once, in the form it should be quoted:

> **The transport class is selected before the call and cannot silently change
> during the call. An endpoint may change within a class if the change is
> authenticated. A class change requires ending the call.**

---

## 4. The transition matrix

Once a call is running:

| Transition | Allowed | Why |
|---|---|---|
| I2P → I2P, new destination | **ALLOWED** | Endpoint rebuild within the class. `MEDIAPATH` announces the new destination and it is authenticated from the committed epoch root. This is what recovers a Wi-Fi-to-mobile transition. |
| Tor → Tor, new endpoint | **ALLOWED if authenticated** | Same class, same anonymity property; the new endpoint must be proved to come from the existing session, not merely asserted. |
| TLS → TLS, new endpoint | **ALLOWED if authenticated** | Same class. Also covers a route change (direct → proxy) within `CLEARNET_TLS`, since the class is unchanged. |
| I2P → TLS | **FORBIDDEN** | Anonymity downgrade. A network problem must not become a privacy loss. |
| Tor → TLS | **FORBIDDEN** | As above. |
| TLS → I2P | **FORBIDDEN** | An *upgrade* is still a silent class change mid-call, and the peer did not agree to it. End the call and start a new one. |
| any → any, other pairs | **FORBIDDEN** | The matrix is an allowlist. An unlisted transition is forbidden, not undefined. |

"Authenticated" means the endpoint change is proved to originate from the
existing cryptographic session — for voice, the `MEDIAPATH` construction in
[VOICE_MEDIA_PATH.md](VOICE_MEDIA_PATH.md), which is bound to the committed
epoch root and carries a monotonic counter against rollback. An endpoint change
that merely *arrives on the signalling channel* is not authenticated, and is
exactly the attack that construction exists to stop.

### The two sequences that must never exist

Written out because they are the plausible-sounding ones:

```
I2P fails → try Tor → Tor fails → try clearnet          FORBIDDEN
I2P is slow → switch to direct UDP for latency          FORBIDDEN
```

The first turns a transient network fault into a permanent deanonymisation. The
second is worse, because it triggers on *degraded* rather than *failed*, so it
fires on exactly the congested networks where the user is least likely to be
watching. Failure is closed, not downgraded. If I2P cannot carry the call, the
call does not happen.

This is not a new rule; it is the existing behaviour, stated so that it stays
that way. `tests/test_transport_failclosed.py` already fails if the I2P XMPP
path can reach a direct socket, and it exists because a fall-through in
`_reconnect` sat one drifting condition away from doing so.

---

## 5. What reaches the cryptography

`TransportClass` should be bound into the voice transcript, so that two peers
who believe they are on different classes cannot derive the same media key and
the call simply never keys. That is the strong form of the guarantee: not "the
UI is told the truth" but "a mismatched pair cannot talk at all".

The weak form — the transport layer *reports* its negotiated class into the
security state machine and the UI renders that, rather than rendering what the
user asked for — is strictly less good, because it depends on every future code
path remembering to report honestly. It is what exists implicitly today only
because there is one media class.

**Status: specified, not implemented.** Binding a class byte into the voice key
derivation is a wire break and needs its own voice wire-version bump, protocol
analysis and cross-version tests, in the manner of SMP `0x03`. It is deferred
until the current I2P voice and rekey work has completed live-device
validation, on the explicit principle that the proven transport is not
destabilised to make the matrix symmetrical.

When it is implemented, the shape is:

* one byte, `TRANSPORT_CLASS_I2P = 0x01`, `TRANSPORT_CLASS_TOR = 0x02`,
  `TRANSPORT_CLASS_CLEARNET_TLS = 0x03`;
* included in the voice root derivation transcript, alongside the existing
  session and endpoint fields, with the same 4-byte big-endian length prefixing
  the rest of that transcript uses;
* `Route` absent from the transcript entirely, for the reason in §3.

Until then, §4's matrix is enforced by there being exactly one media transport
class, and by the tests that keep it that way.

---

## 6. Proxies, described honestly

If modes 4 and 5 are implemented, the following is the required framing, in the
UI and in the documentation.

A proxy is a host that sees your traffic's origin and destination. Relative to a
direct clearnet connection it moves who-sees-what; it does not remove it. The
proxy operator can log the connection, correlate it with other traffic, identify
you, inject or drop packets, or simply be compromised or coerced. A chain of
proxies multiplies the number of parties with that position rather than dividing
it, unless the chain has the layered-encryption and path-selection properties
that Tor and I2P are built around — which an arbitrary SOCKS5 chain does not.

Therefore:

* **A proxy mode is never labelled "anonymous".** Not in a mode name, not in a
  status line, not in a tooltip. The honest label is "clearnet, routed through
  a proxy you chose".
* A proxy mode is presented **within** the clearnet row, never as a peer of I2P
  or Tor.
* The user is told what the proxy can see, at the point where they select it.

Selection is explicit — a flag such as `--transport tls --proxy socks5://host:port`,
or a preconfigured choice among Direct / SOCKS5 / HTTP CONNECT / chain — and is
never inferred from an environment variable, a system setting, or a failure.

One implementation note carried forward from the existing Tor work: PySocks is
not used, because it routes by replacing `socket.socket` process-wide, which in
this process would also capture the I2P SAM bridge and every voice media
socket. A proxy is applied to one connection or it is not applied at all.

---

## 7. Voice over Tor: not implemented, deliberately

This is a decision, not a gap.

Tor carries TCP streams. Voice media here is constant-rate datagrams with a
strict latency budget; carrying it over a TCP overlay means head-of-line
blocking, retransmission of frames that are useless by the time they arrive, and
a latency distribution that is not merely worse than I2P's but differently
shaped. The I2P path uses SAM `STYLE=DATAGRAM` precisely because the stream
version was unusable for speech.

Implementing "Tor voice" by tunnelling media over a Tor TCP stream would produce
a mode that technically connects and does not work, which is worse than not
offering it: users would select it, get unusable audio, and reasonably conclude
the application is broken.

The condition for revisiting this is a properly engineered real-time media
transport for Tor, not a demonstration that packets can be made to traverse it.
Until then the matrix stays asymmetric, and that asymmetry is honest.

The same reasoning applies to clearnet UDP media. It is straightforward to
implement and it is not implemented, because the only reason to reach for it is
latency, and trading anonymity for latency is the exact substitution §4
forbids.

---

## 8. What exists today

| Capability | State |
|---|---|
| I2P XMPP control plane | implemented, live-verified |
| I2P voice media (SAM datagram) | implemented, live-verified — 4-hour soak, authenticated recovery across a network transition |
| Tor XMPP control plane | implemented via a hand-rolled SOCKS5 CONNECT to a loopback forwarder; **LIVE-UNVERIFIED** |
| Clearnet TLS XMPP control plane | implemented; no reconnect |
| Tor voice media | **not implemented** — §7 |
| Clearnet TLS voice media | **not implemented** |
| Proxy route (mode 4) | **not implemented** |
| Proxy chain route (mode 5) | **not implemented** |
| `TransportClass` bound into the voice transcript | **not implemented** — §5, deferred |
| `TransportClass` / `Route` as Rust types | **not implemented** — §3 |

"LIVE-UNVERIFIED" means the code path has been traced and unit-tested and has
never carried a real connection. It is recorded as its own state rather than
folded into "implemented", because the difference between those two is where
this project has previously been wrong about itself.

---

## 9. Rules for anyone adding a transport

1. **Selection is explicit.** By address suffix or by flag, checked before the
   connection is attempted, with a refusal — not a guess — when the flags
   contradict the address. `--tor` with a `.i2p` server exits; it does not pick
   one.
2. **Failure is closed.** No transport failure selects a different transport.
   No degradation triggers a switch. There is no fallback ladder.
3. **The class is fixed for the call.** Endpoints may move within a class if
   the move is authenticated; classes may not.
4. **Report what is in use, not what was requested.** A UI that says "private"
   because the user asked for I2P, while something else is carrying the bytes,
   is worse than no indicator at all.
5. **Do not destabilise a proven transport to make the matrix symmetrical.** A
   mode that connects but does not work is not support.
6. **State the anonymity property in the same breath as the encryption
   property**, because they are different properties and users conflate them.
