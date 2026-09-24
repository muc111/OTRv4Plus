<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# OTRv4Plus capability discovery and automatic OTRv4+

**The rule:** never send OTRv4+ protocol traffic to an XMPP resource that has
not first been identified as OTRv4Plus-capable.

OTRv4Plus interoperates only with OTRv4Plus. It does not work with ordinary
XMPP clients, legacy OTRv4, other OTR implementations, or OMEMO. A DAKE is
never used to find out whether a peer is capable.

Code: `otrv4plus_caps.py` is shared by both clients. `android_bridge/transport.py`
and `android_bridge/app.py` hold the Android side. Tests:
`tests/test_otrv4plus_capability.py` and `OtrAvailabilityTest`.

## The identifier

| | Value |
|---|---|
| XEP-0030 feature | `https://github.com/muc111/OTRv4Plus#otrv4plus-1` |
| XEP-0115 node | `https://github.com/muc111/OTRv4Plus` |

The feature is a URI this project controls, as XEP-0030 asks. Only this exact
string counts. `OTR`, `OTRv4`, `urn:xmpp:otr:0`, OMEMO, a near-miss spelling
and the caps node are all rejected (the tests cover each). The client name
and version, the "user agent", are not used.

Both clients advertise it:

- The Android transport, before its first presence.
- The Termux client, in `_on_start`.

## How a resource is identified

1. **Presence.** An available presence arrives from a full JID. If its
   XEP-0115 hash is already known, the cached answer is used. Otherwise the
   client sends disco#info **to that full JID**.
2. **Exact feature.** The resource is capable only if the exact feature is
   listed. A disco that fails or times out counts as not capable (fail
   closed).
3. **In-band.** A resource that itself sends us an OTRv4+ frame is capable,
   because only OTRv4Plus produces that wire format. This lets a build that
   predates advertisement still get an answer to a handshake it started.

Knowledge is per resource, and it is discarded when:

- the resource sends unavailable presence;
- its caps hash changes (a different client on the same resource);
- either side reconnects.

A bare JID that was capable yesterday proves nothing about today's client.

## The wire rule

`XmppTransport.send` checks every payload that starts with `?OTRv4`: DAKE,
data, SMP, fragments, and call and file signalling (which travel inside OTR
data messages). Each one goes to **one full JID**, a confirmed-capable
resource. It never goes to the bare JID, which the server would route to a
resource of its own choosing.

With no capable resource, the frame is refused (`otrv4plus_unavailable`) and
nothing is sent. Every caller is covered, because the check is at the wire
rather than in each caller.

Choosing the target resource:

- An OTRv4+ session lives in one client process, so its resource is
  **pinned**.
- If the pinned resource leaves, the local session is ended without sending
  a TLV (there is nobody to send it to). The conversation stays
  OTR-requested, so the next line waits for a new handshake instead of going
  out in the clear.
- With several capable resources, the highest-priority, most recently seen
  one is chosen. An incapable resource is never chosen, whatever its
  priority.

## Automatic OTRv4+

While a private conversation is open, the app runs `ensure_otr` (retried at
most every 45 s):

| Situation | Result |
|---|---|
| Capability `available` | A DAKE starts |
| Capability `checking`, `offline`, `unavailable` or `unknown` | Nothing is sent, and the screen says which |
| Already encrypted, or a handshake in flight | Nothing new happens |

Capability is **not** trust. Fingerprint trust and SMP stay explicit, and
calls and files still need SMP.

## Plaintext

- **Capable contact:** never sent plaintext. The first message starts OTRv4+
  and is held (QUEUED) until the handshake completes.
- **Contact whose client does not speak OTRv4Plus:** messages can be sent,
  and are reported as plaintext. The conversation says "OTRv4Plus unavailable
  — this contact is using a client that does not support OTRv4Plus. Messages
  here are NOT encrypted." There is no padlock, no SMP, no call and no file.
  That is explicit, not silent.
- **An established or requested session** is never downgraded (`OtrMode`).

## Legacy OTRv4

There is no negotiation down and no fallback. A client that advertises only
legacy OTR features is shown as "OTRv4Plus unavailable".

## Termux

The Termux client advertises the feature, so Android can start OTRv4+ with it
automatically. Termux's own OTR start is still the explicit `/otr` command,
unchanged.
