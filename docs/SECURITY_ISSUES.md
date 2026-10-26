# Tracked security issues

Open issues carried by the OTRv4+ codebase, with current behaviour, impact, and
what would resolve each. This file exists so that known gaps stay visible
instead of being rediscovered, and so that no gap is described as fixed until a
regression test demonstrates it.

Status vocabulary:

- **OPEN** — present in the shipped code, not remediated.
- **MITIGATED** — cannot currently be reached, but the underlying code remains.
- **RESOLVED** — fixed, with a regression test named here.

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| L1 | MAC-key revelation reveals all-zeros; deniability not achieved | Design | **RESOLVED (mechanism; 2026-10-26)** -- an exact retirement rule in the Rust ratchet (SPEC §5.8: R1 received, R2 skipped key deleted, R3 close; never a sender's own key), publication only as the encoded wire field, closing publication on Make Chat Deniable, sign-out, Wipe & Exit, quit, the peer's end and errors, for every session. Gate: `tests/test_l1_revelation_gate.py` (T1-T8), `ratchet::l1_retirement`, `tests/test_mac_revelation_end_to_end.py`. Residual: the retirement rule wants formal expert review, and until then no "deniable messaging" claim is made; first contact stays trust-on-first-use |
| U1 | Signed out, About -> back reached the signed-in chat list, and the device's identity fingerprint could be read before any login | Medium (privacy: device-account binding) | **RESOLVED** (2026-10-26) -- the bridge withholds the fingerprint until a login succeeds (`OtrApp.local_fingerprint`, security details, the desktop host's start-up message); Android shows only public screens while signed out and About goes back to sign-in; sign-out keeps nothing to navigate back to; the desktop and terminal show no fingerprint before login. `tests/test_u1_signed_out_surfaces.py`, `AuthGateTest`. Its residual (one identity shared by accounts) is resolved by F2 |
| F2 | Two accounts used one after the other in one app process (Android, desktop) or on one machine (terminal) presented the same long-term identity key, which every DAKE1 carries past the server: the accounts could be linked | Medium (privacy) | **RESOLVED** (2026-10-26) -- one identity per account (SPEC §3.1): a non-persisted identity is replaced, old handles zeroized in Rust, when a connection is prepared for a different account, before any byte is sent as it; the terminal keeps one sealed record per account, named by a hash. Key generation and sealing unchanged. `tests/test_f2_per_account_identity.py` |
| N1 | The route chosen from the server name (route.py) was followed by the code written to follow it, but not enforced on the process: a library, a mistyped flag or a new feature could open another socket or resolve a name | Medium (anonymity) | **RESOLVED for the app's own code** (2026-10-26) -- a process-wide audit hook (`otrv4plus_egress`) enforces the route from the gate every sign-in, account creation and server test passes first: on I2P and Tor only loopback and the configured bridge are reachable and nothing is resolved; no `.i2p` or `.onion` name reaches DNS on any route. `tests/test_n1_network_isolation.py`. Residual: the bundled i2pd is a separate process with its own reseed and router links; not yet confirmed by a device packet capture |
| M3 | Legacy DAKE path can hand session keys to Python as PyBytes | Medium | **RESOLVED** |
| G1 | `RustDAKEAdapter.is_expired()` is a stub; DAKE handshake timeout absent | Low | **RESOLVED** (2026-10-24) -- `tests/test_dake_timeout.py`; `test_08_dake_timeout` no longer an expected failure |
| G2 | Two divergent copies of `otrv4_testlib.py`; which loads depends on collection order | Low | **RESOLVED** (2026-10-24) -- one copy, `tests/otrv4_testlib.py`; `tests/test_dake_timeout.py::test_there_is_one_test_library` |
| B1-seed | Persisting an identity requires the seed to exist in Python | Design | **RESOLVED** |
| A1 | Ratchet brace key is never folded into root/chain keys (SPEC §5.2 not implemented): no post-quantum post-compromise recovery | Design / High (spec divergence) | **MITIGATED** (2026-10-24) -- mitigated by the new v2 ratchet, which rotates ML-KEM secrets about every round trip once the first DH ratchet step has happened (after 100 messages in one direction or 24 hours; before it the handshake's ML-KEM secret protects the keys) and folds each into the root (SPEC §5.1-5.2; `ratchet::pq_ratchet`, `tests/test_pq_ratchet_v2.py`). A peer without v2 is refused by default (`require_pq_v2`, code `pq_v2_required`), so the v1 derivation is no longer reached; its code remains for that switch and stays pinned by `ratchet::audit_brace_folding`. Kept listed as a known limitation: the combiner and its interleaving with loss want expert review (CRYPTO_AUDIT §7 item 3), and SPEC §5.1 states a residual |
| A2 | DAKE post-quantum authentication is initiator-only and strippable by an active quantum adversary | Design / Medium | **RESOLVED** (2026-10-24; Android rc.159; requires both peers to list `PQ_RATCHET_VERSION` 0x50 and `PQ_AUTH_VERSION` 0x51) -- each identity has one long-term ML-DSA-87 key, sealed beside it; the responder signs the transcript in DAKE2 (`KDF_1(0x06, DAKE1 \|\| DAKE2-to-signature)`: both ephemeral X448 keys, the initiator's ML-KEM key and the responder's ciphertext, both profiles, both ML-DSA keys) and the initiator verifies it before DAKE3 or any data; the initiator signs DAKE3; both mandatory. An older peer is refused outright (`pq_v2_required`), and a known contact's ML-DSA key is pinned, so dropping or changing it under the same Ed448 identity is refused (`pq_downgrade`, `pq_key_changed`) even with the policy relaxed. SPEC §4.3. `dake::pq_auth_tests`, `mldsa::tests`, `tests/test_pq_auth_v2.py`. Residual: first contact is trust-on-first-use. Deniability cost: SPEC §10.1 |
| A3 | Crafted `.otrv` header overflowed `8 * p` before bounding p: process abort (overflow-checks + panic=abort) | Medium (DoS) | **RESOLVED** -- `container::tests::a_huge_lane_count_is_refused_not_an_overflow`; found by `fuzz/container_header` |
| A4 | Ring verifier accepted the identity point as a ring member (signable by anyone) | Low | **RESOLVED** -- `ring_sig::audit_identity_point` |
| A5 | Profile expiry and degenerate identity key enforced only in Python | Low | **RESOLVED** -- `dake::profile_tests` |
| A6 | Ring signature scalars reduced mod Q, so every signature had malleable re-encodings | Low / Info | **RESOLVED** -- `ring_sig::audit_identity_point::a_non_canonical_scalar_is_refused` |
| X1 | With TLS certificate checks off (I2P, .onion), a server reached by a human-readable `.i2p` NAME is bound only by the router's address book; a substituted server can offer only SASL PLAIN and capture the XMPP account password | Medium | **RESOLVED (Android and the terminal client), with stated residuals** -- both options, combined: the resolved destination is pinned per server name and a changed one is refused before STREAM CONNECT (nothing reaches it; explicit, confirmed re-approval of exactly that destination), and SASL is SCRAM-only wherever certificate checks are off. `tests/test_x1_destination_pinning.py`, `tests/test_x1_terminal_client.py`. Residuals: see the X1 section. NOT yet confirmed by a handset login |

---

## L1 — MAC-key revelation reveals all-zeros

**Status: RESOLVED (the mechanism), 2026-10-26. Do not claim deniable
messaging until the retirement rule has had expert review.**

### What was wrong, last

The all-zeros placeholder was fixed on 2026-09-28: the receiver's MAC key
(MKmac, OTRv4 §4.4.2) was revealed in its next message. Three things still
stood between that and a claim this file can mark resolved:

1. **Premature revelation.** At every DH ratchet step the ratchet also queued
   the MAC key of the last message it had SENT. The peer could still be waiting
   for that message, or holding it as a skipped key.
2. **No retirement on deletion or close.** A message that never arrived had
   its MAC key published by nobody, even after its skipped key was evicted;
   and nothing was published when a session ended. Past 50 queued keys the
   oldest were wiped without ever being published.
3. **The boundary.** Retired keys crossed to Python as a list of `bytes`.

### The rule (SPEC §5.8)

A MAC key is retired only when nothing can be verified with it any more:

- **R1** its message was received and authenticated (the replay cache then
  refuses a second copy);
- **R2** its message never arrived and the skipped message key is deleted:
  evicted at `MAX_MESSAGE_KEYS` (2000, the existing bound), or at close;
- **R3** close (`retire_all`): R2 for every skipped key still held, after which
  the ratchet decrypts nothing.

A sender never retires the key of a message it sent: only the receiver knows
when that message is finished with. DH steps use no MAC key, and no key from a
chain position not yet used is ever retired. This is the four-part predicate
the issue asked for: not a current receiving key; no skipped key depends on
it (each MAC key depends only on its own message key); the peer's one message
that used it has been received (R1) or can never be (R2, R3); and no DH step
depends on it.

### What ships

- `Rust/src/ratchet.rs`: a private retired queue (each key boxed, wiped in
  place as it is written into the field, wiped on drop); `retire_all`;
  `encrypt_final` (closing messages of up to 2000 keys, repeated until the
  queue is empty, then the ratchet is closed). The Python result carries only
  `reveal_field`, the encoded wire field; MKmac stays a `MessageMacKey` handle.
- A late message from an older chain whose skipped key is still held is
  decrypted on the skipped path instead of failing as a DH step (it used to
  be refused, so its key was never retired by receipt).
- The engine: `close_with_revelation` runs in `_cleanup_resources`, so every
  path that destroys a ratchet publishes first; `make_deniable`; sign-out,
  quit and Wipe & Exit close every session with DISCONNECTED;
  `take_final_revelations` hands the closing messages to the client; an ended
  session is never reused by a new handshake.
- The clients send them: Android and desktop (`app_deniable.py`; after each
  inbound frame, at sign-out, at Wipe & Exit before the transport closes) and
  the terminal client (`/deniable`, `/quit`). "Make Chat Deniable…" in every
  established 1:1 chat on Android and desktop, `/deniable [jid]` in the
  terminal. Offline, the closing messages are dropped; the keys are retired and
  wiped in Rust all the same.

### Regression gate

`tests/test_l1_revelation_gate.py`:

| | Test |
|-|------|
| T1 | `TestT1PositiveDeniability::test_a_published_key_forges_a_message_really_observed` |
| T2 | `TestT2NoPrematureRevelation::test_a_long_conversation_with_loss_and_dh_steps_publishes_nothing_early`, `::test_a_sender_never_publishes_the_key_of_its_own_message`, `::test_the_check_catches_a_transcript_that_reveals_early` (mutation) |
| T3 | `TestT3SkippedMessages::test_unpublished_while_held_across_a_dh_step_then_published_late`, `::test_a_skipped_key_deleted_at_close_is_published` |
| T4 | `TestT4Zeroization::test_a_published_key_is_no_longer_held`, `::test_close_leaves_nothing_retired_nothing_skipped_and_no_ratchet` |
| T5 | `TestT5MakeChatDeniable::test_final_publication_disconnect_and_a_fresh_unlinked_session`, `::test_no_session_no_action` |
| T6 | `TestT6SignOutWipeQuit::test_every_session_publishes_before_its_keys_go[sign_out]`, `[wipe]`, `::test_the_peers_closing_message_after_our_end_starts_no_handshake`, `::test_offline_the_keys_are_still_retired_and_wiped`, `::test_the_bridge_sends_them_before_the_transport_goes`, `::test_the_bridge_sends_every_message_and_drops_them_offline` |
| T7 | `TestT7WireCompatibility::test_a_peer_reading_the_field_by_shape_only_accepts_real_keys`, `::test_the_field_is_outside_what_the_mac_covers`, `::test_a_peer_implementing_it_accounts_for_every_key_it_is_shown` |
| T8 | `TestT8NoMacKeyBytesInPython::test_the_ratchet_hands_over_the_field_and_handles_only`, `::test_a_mac_key_handle_has_no_bytes`, `::test_no_production_path_unpacks_the_field_into_keys`, `::test_the_deniable_paths_move_wire_text_only` |

Rust: `ratchet::l1_retirement` (R1, no sender reveal across DH steps, skipped
keys held across a DH step, late old-chain message, R2 eviction, R3 close,
closed ratchet, T4 wipe, queue bound). The T4 accessor `holds_mac_key` exists
only in test builds; `tests/test_release_guard.py` asserts a release wheel has
none. Also `tests/test_mac_revelation_end_to_end.py`, `test_reveal_ordering.py`,
`test_revealed_mac_crosscheck.py`, and `DeniableChatTest` (the UI words).

### Residuals

- **Expert review of the retirement rule** (SPEC §5.8) before any claim of
  deniable messaging; the button and its text describe the mechanism and say
  it has not been independently reviewed.
- The MAC key of the outer OTRv4 MAC is published; AES-GCM, the primary
  authenticator, is keyed by the message key, which is never published. A
  third party with a published key can forge the outer MAC of a transcript
  entry, which is the OTR sense of transcript deniability; it cannot produce a
  ciphertext the receiver would have decrypted.
- A message whose outer MAC fails after its AEAD tag verified has its MAC key
  retired anyway (R1 commits at the AEAD); the replay cache refuses any second
  copy, so nothing can be verified with it.
- First contact is trust-on-first-use (A2), and v2's ML-DSA handshake
  signatures are attributable (SPEC §10.1): participation deniability against
  a transcript holder is given up there, independently of this item.

---

## U1 — Signed-out navigation reached signed-in screens and the device fingerprint

**Status: RESOLVED, 2026-10-26.**

### What happened

Device report: signed out (credentials cleared, not wiped), the next launch on
the sign-in screen, overflow -> About & licences, then back: the app landed on
the empty chat list, a signed-in surface, and from there the device's identity
fingerprint could be read. The About screen's back always went to the chat
list. The desktop sign-in screen also showed the fingerprint, and the desktop
host announced it in its start-up message, before any login.

Why it matters: the fingerprint is the device's long-term identity key. Read
before a login, it can later be matched with the server's record of a login
from this device -- "this device was used by that account".

### The fix

- **The bridge is the gate.** `OtrApp.local_fingerprint()` -- and the
  `local_fingerprint` of security details, and the desktop host's `ready`
  message -- is "" until `note_signed_in(account)`, which the connection
  controller calls only after the server accepted the login. `shutdown`
  (sign-out), `disconnect`, and Wipe & Exit clear it first.
- **Android navigation.** Every screen goes through `AuthGate.shown`: while
  signed out only Sign in, About & licences and Debug render; anything else
  shows Sign in. About's back (button and swipe) goes to Sign in while signed
  out. The service's `signedIn` is set only when a connection succeeds and
  cleared at the account boundary (another account, sign-out, wipe); the
  view-model clears it at once on Sign out. When sign-out lands, the open
  chat, the profile shown, the tab and the identity read for the profile are
  dropped (`SignedOutReset`, `ChatViewModel.forgetIdentity`).
- **Desktop.** No fingerprint on the sign-in screen; it is read after a login
  succeeds and cleared before disconnect.
- **Terminal.** `/identity` withholds the fingerprint until the XMPP session
  has started (authenticated) and again from `/quit`.

Sign-out remains distinct from Wipe & Exit, which is unchanged.

### Regression gate

`tests/test_u1_signed_out_surfaces.py`:

| | Test |
|-|------|
| U1-T1 | `test_u1_t1_about_goes_back_to_sign_in_while_signed_out`; `AuthGateTest` `U1-T1 back from About while signed out is sign-in` |
| U1-T2 | `test_u1_t2_only_public_screens_render_while_signed_out`, `test_u1_t2_sign_out_keeps_nothing_to_navigate_back_to`, `test_u1_t2_signed_in_means_a_login_succeeded_for_this_account`; `AuthGateTest` `U1-T2 no signed-in screen can be shown while signed out` |
| U1-T3 | `test_u1_t3_the_bridge_gives_no_fingerprint_while_signed_out`, `test_u1_t3_no_public_screen_reads_a_fingerprint`, `test_u1_t3_the_profile_forgets_what_it_showed` |
| U1-T4 | `test_u1_t4_the_desktop_host_announces_no_fingerprint_before_login`, `test_u1_t4_the_desktop_screens_show_none_before_login`, `test_u1_t4_the_terminal_withholds_it_until_signed_in` |
| U1-T5 | `test_u1_t5_a_successful_login_brings_it_back`, `test_u1_t5_only_a_successful_connect_signs_in`, `test_u1_t5_an_address_that_is_not_an_account_signs_nobody_in`; `AuthGateTest` `U1-T5 signed in everything is reachable` |
| U1-T6 | `test_u1_t6_sign_out_then_another_account`, `test_u1_t6_shutdown_and_wipe_sign_out_first`, `test_u1_t6_the_engine_holds_no_previous_session_for_the_next_account` |

The navigation tests pin the Compose wiring at source level and run the rule
on the JVM; there is no instrumented (on-device) test of the back stack in
this repository. A device check is listed in the release notes.

### Residual

Resolved by F2. (As first written, this said the identity was per device. It
was per app process on Android and desktop -- `OTRConfig()` does not persist
it -- and per machine in the terminal client; either way two accounts could
share one.)

---

## F2 — One identity per account

**Status: RESOLVED, 2026-10-26.**

### What was wrong

The fingerprint is `SHA3-512(Ed448 identity public key)`, and that public key,
with the pinned ML-DSA key, travels in the ClientProfile of every DAKE1 -- an
`?OTRv4` message body the XMPP server relays and can read (on I2P there is no
TLS at all). On Android and the desktop the engine's identity is not persisted
and lives as long as the process; the terminal client keeps one sealed
identity for the machine. Two accounts used one after the other therefore
presented one key, linking them for the server and for any peer of both.

### Why not a derived fingerprint

Proposed first: show `KDF(device key || username)` as the fingerprint. It was
not done: it would change only the string people compare, while the server and
every peer still see the same raw key in DAKE1. A residual marked resolved by
it would have been a false claim.

### The fix (SPEC §3.1)

- **Android, desktop** (identity per process): `OtrApp.bind_identity_account`
  runs in `controller_for`, which every sign-in and account creation calls,
  before anything is sent. The first account takes the start-up identity,
  which nobody has seen; another account gets new Ed448 and ML-DSA identities
  (`EnhancedSessionManager.rotate_identity`, the same generation code), the old
  handles zeroized in Rust, every session and handshake of the old identity
  ended deniably (L1), in-memory pins discarded. The fingerprint stays dark
  until the new account's own login (U1).
- **Terminal** (persistent identity): one sealed record per account,
  `identity.<h>.sealed`, `h` a domain-separated SHA3-256 of the bare JID, so
  the JID is not in the file name. The record from before is kept by the
  first account to sign in afterwards, so its contacts see no key change.

Key generation and sealing are unchanged; only which account an identity
belongs to is. The fingerprint is a hash of a public key: no private or
seed material crosses from Rust.

### Regression gate

`tests/test_f2_per_account_identity.py`: rotation gives a new key and zeroizes
the old handles; the old identity's sessions and pins go; a persisted identity
is never rotated; **two accounts in one process present different keys in
DAKE1, as the peer sees them**; the same account on two devices has two keys;
the same account again keeps its key; a switch hides the old fingerprint until
the new login; junk never rotates; every connection binds before anything is
sent; the terminal's records are per account, named by hash, the old record
claimed once, and two accounts load two real identities while one account
keeps its own across runs. Also `VerificationTest` (the About text says each
account has its own identity).

---

## N1 — The route is enforced on the whole process

**Status: RESOLVED for the app's own code, 2026-10-26.**

### The rules

| Server name | Route | May reach | Name resolution |
|-------------|-------|-----------|-----------------|
| `*.i2p`, `*.b32.i2p` | I2P over SAM | loopback and the configured SAM bridge only | none (the router resolves `.i2p` names, inside I2P) |
| `*.onion` | Tor SOCKS5 | loopback and the configured SOCKS port only | none (the name travels inside SOCKS CONNECT) |
| anything else | TLS, certificate and hostname checked | any | DNS (SRV first) |
| every route | | never a `.i2p` / `.onion` name directly | never a `.i2p` / `.onion` name |

`android_bridge.route` chose this from the name before; nothing enforced it.
Now `otrv4plus_egress` installs a CPython audit hook (PEP 578) that refuses
`socket.connect`, `sendto`, `sendmsg` and every resolver call (forward and
reverse) that the active route does not allow. A refusal is an `OSError`; it
cannot be bypassed from Python, libraries included. slixmpp's aiodns (c-ares,
which resolves outside Python's socket layer) is switched off on the I2P and
Tor routes, and the APK does not ship it at all. The rule is entered in the
route gate that sign-in, account creation and the server test all pass first,
so no authentication or registration byte goes out before it; sign-out leaves
it. The terminal client enters it before opening any tunnel, and refuses
`--no-i2p` for an `.i2p` server rather than sending the name to a resolver.

**Router choice stays localhost-only.** A local I2P app's SAM bridge on
127.0.0.1:7656 is preferred (SAM HELLO probe, loopback only); otherwise the
bundled router, whose SAM listens on 127.0.0.1 only. No LAN address, scan or
discovery is tried. A SAM bridge elsewhere is used only when typed into the
desktop's connection settings, must be an IP address (a name would need DNS),
and the screen warns that SAM has no authentication.

### Regression gate

`tests/test_n1_network_isolation.py`: the rule's table for every route;
hidden names refused on every route; an explicit bridge elsewhere must be an IP
and is the only exception; real `connect`, `sendto`, `getaddrinfo`,
`gethostbyname`, `gethostbyaddr` and asyncio lookups refused on I2P and Tor;
`.i2p` lookups refused on clearnet; aiodns off on hidden routes; the rule in
force before the bridge is even probed, for `.i2p`, `.b32.i2p` and `.onion`;
a hostname bridge refused before any lookup; sign-in, account creation and the
server test all pass the gate first; **the whole SAM path, through the Android
transport and the real forwarder against a scripted SAM bridge, touches only
loopback and resolves nothing**; the Kotlin probe asks only 127.0.0.1:7656,
with no LAN or discovery code; the bundled router listens on loopback with its
HTTP, proxy, control and UPnP interfaces off; sign-out stops it and leaves the
route; the APK carries the rule and no networking library beyond slixmpp and
PySocks. Also `test_i2p_naming_no_dns.py`, `test_tor_transport.py`,
`test_tls_follows_transport.py`, `test_route_parity.py`.

### Scope and residuals

- **The bundled router is its own process.** i2pd reseeds over HTTPS on its
  first start (resolving the reseed hosts through the system resolver) and
  then talks to other I2P routers over UDP/TCP: that is I2P working, and it
  never carries the server's name. None of it happens when a local I2P app on
  127.0.0.1:7656 is used. The rule above binds the app's own code.
- **Not yet confirmed by a device capture.** A PCAPdroid capture of an `.i2p`
  account should show only the router's peer traffic (and its reseed, on a
  first start) and no port 53 from the app. Listed in the release notes.
- Android's own services (for example the location provider behind a shared
  position) are the system's, not the app's.

---

## M3 — Legacy DAKE path can hand session keys to Python

**Status: RESOLVED. Compiled out of production builds.**

Regression tests: `tests/test_release_guard.py::test_production_artifact_exposes_no_legacy_dake_session_keys`
and `::test_production_dakeresult_exposes_no_secret_getters`.

The five `Dakeresult` secret getters and `PyDake::generate_dake2` /
`process_dake2` / `get_session_keys` are behind the `legacy-dake-keys` Cargo
feature, OFF by default. They are **absent from a production artifact**, not
merely undocumented. `Rust/build.rs` refuses to build with the feature unless
`OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1` is set explicitly. The live DAKE
implementation is unchanged — `generate_dake2_output` / `process_dake2_output`
use a different internal path and were not touched.

Verified across three wheels: production (guard passes), legacy without opt-in
(guard **fails**, catching the surface), legacy with opt-in (passes).

The original analysis, retained for the record:

### What exists

`Rust/src/dake.rs` exposes `PyDakeSessionKeys` with PyBytes getters for
`root_key`, `chain_key_a`, `chain_key_b`, `brace_key` and `mac_key`, reachable
through `PyDake.get_session_keys()` and the legacy `generate_dake2` /
`process_dake2`. The safe path — `generate_dake2_output` / `process_dake2_output`
— returns an opaque `DakeOutput` whose keys move Rust-to-Rust via
`consume_into_ratchet()` and never become PyBytes.

### Every caller, checked

Production Python calls `RustDAKEAdapter.generate_dake2` / `process_dake2`
(`otrv4+.py`), each of which runtime-feature-detects:

```python
use_output_api = hasattr(self._rust, "generate_dake2_output")
if use_output_api:
    ...                      # opaque DakeOutput; no key bytes
else:
    result = self._rust.generate_dake2(...)
    self._session_keys = self._unpack_session_keys(result, ...)   # PyBytes
```

`_unpack_session_keys` is the only code that reads those getters. The
`hasattr` check that guards it **cannot be false in any importable build**:
`_check_rust_requirements()` (`otrv4+.py:70`) raises `ImportError` at import
time unless both `generate_dake2_output` and `process_dake2_output` are present
on `RustDAKE`. A build missing them cannot get far enough to reach the fallback.

The legacy branch is therefore **dead code on the live path**, confirmed by
reading the gate rather than inferred.

Outside production, the only callers were `tests/test_attacks.py` and
`tests/test_otrv4_integration.py`, both of which have been migrated (see
`tests/test_otrv4_integration.py::test_04/05/06`, which now assert the opposite
property: that `brace_key`, `root_key`, `chain_key_*` and `mac_key` are *absent*
from the session-keys dict).

### Does Android require it?

No. `android_bridge/app.py` never touches session keys; the bridge's contract
is that no secret crosses into Kotlin, and a test asserts `OtrApp` exposes no
key-shaped accessor.

### Does it expose secrets across the boundary?

Only if executed, which it cannot be. The hazard is latent rather than live: a
future refactor that relaxed the import gate, or added a caller, would silently
re-open a PyBytes path for root and chain keys.

### Disposition

**Recommend (B): gate the legacy entry points behind an explicit test-only
Cargo feature**, reusing the `test-only-kdf` mechanism now enforced by
`Rust/build.rs`, so a production build cannot compile them at all.

Rationale for B over the alternatives:

- **(A) remove outright** — cleanest, but `generate_dake2`/`process_dake2` are
  also the only DAKE entry points some Rust-side tests use, and deleting them
  is a larger change than Phase 2 should make to the crypto core.
- **(C) replace with opaque handles** — already done; `*_output` is that
  replacement. Nothing further to build.

Not executed in Phase 2 because it touches `dake.rs`, and the phase brief
requires the disposition to be documented and agreed rather than applied
unilaterally. It is a small, self-contained change once approved.

---

## G1 — DAKE handshake timeout is a stub

**Status: RESOLVED (2026-10-24).** `is_expired()` now counts from the
handshake's first move out of IDLE (DAKE1 sent or received), on the monotonic
clock, against `timeout` (default `UIConstants.DAKE_TIMEOUT`, 120 s). IDLE,
ESTABLISHED and FAILED never expire: an established session's age remains
`is_session_expired()`'s question. Tests: `tests/test_dake_timeout.py` (in
flight, not started, over, wall clock ignored); `test_08_dake_timeout` passes
and is no longer marked as an expected failure. Removing the check fails both.

The original analysis, retained for the record:

`RustDAKEAdapter.is_expired()` unconditionally returns `False`. The `timeout`
attribute callers may set is never read, and `UIConstants.DAKE_TIMEOUT = 120.0`
is defined but referenced nowhere in the codebase. The pure-Python `OTRv4DAKE`
that carried this mechanism was deleted at v10.7 and the behaviour was not
carried over.

**Impact today is nil**: `is_expired()` has no production callers. The separate
`is_session_expired()` — age of an *established* session — is implemented
correctly and is called (`otrv4+.py:5825`).

The hazard is that a future caller gets a silent "never expired". A half-open
DAKE would then be retained indefinitely, which on a mobile client is a
resource-exhaustion concern rather than a confidentiality one.

Tracked visibly as an expected failure:
`tests/test_otrv4_integration.py::test_08_dake_timeout`. It is marked
`@unittest.expectedFailure` with the reasoning inline, so the gap shows up in
every test run instead of being deleted.

Implementing it is a behaviour change and needs sign-off; it was deliberately
not done as part of a test repair.

---

## G2 — Two divergent copies of `otrv4_testlib.py`

**Status: RESOLVED (2026-10-24).** When the root-level tests moved into
`tests/` (code tidy-up, phase 2), the root copy went with them: there is one
`otrv4_testlib.py`, in `tests/`, and
`tests/test_dake_timeout.py::test_there_is_one_test_library` fails if a
second appears anywhere in the tree.

The original analysis, retained for the record:

`otrv4_testlib.py` exists in both the project root and `tests/`, with
substantially different implementations (~286 differing lines; the root version
uses `_SMPMathStub` classes patched into the namespace, the `tests/` version
defines `SMPMath` directly).

Which one a test imports **depends on collection order**: `tests/conftest.py`
puts the project root ahead of `tests/` on `sys.path`, but
`tests/test_attacks.py` front-loads `tests/` at import time. So a single-file
run and a full-suite run can load different code.

This was found because a repair applied to one copy appeared to work in
isolation and failed in the full suite. It is a correctness hazard for the test
suite rather than for the product.

**Interim mitigation:** the v10.7 migration helper block is kept byte-identical
in both copies, so the suite is deterministic either way.

**Proposed fix:** make one canonical and have the other re-export it, or delete
the unused copy after confirming which symbols each provides. Deferred because
unifying them is a larger change than a test repair should carry, and the two
implementations are not trivially interchangeable.

---

## B1-seed — Persisting an identity requires the seed in Python

**Status: RESOLVED. Option B implemented — sealing happens inside Rust.**

**Now in use beyond Android (v10.12.0).** The XMPP client persists its
identity through this same mechanism via `otrv4plus_identity.py`, so the
seed stays inside Rust on Termux too. What differs from the Android design
is key custody: the DEK is a 0600 file rather than a Keystore-wrapped key,
so the at-rest protection there is filesystem permissions. IRC persists no
identity at all and is unaffected.

Regression tests: `tests/test_rust_identity_sealing.py` (35 tests covering all
nine required proofs).

`Rust/src/identity.rs` seals and unseals the identity using the crate-internal
accessors, so only ciphertext crosses into Python. No `get_seed()` accessor was
added. Writing the proofs found that PyO3 keeps a `#[staticmethod]`
Python-visible regardless of `pub(crate)`, so `from_seed_bytes` was still a seed
*injection* path; it and `from_priv_bytes` are now behind `test-only-kdf`, and
`identity.rs` uses `from_seed_internal` / `from_priv_internal`, which are not
PyO3 methods at all.

Residual, recorded rather than glossed: the DEK itself is still a Python `bytes`
because the provider hands it down to Rust. The **seed** is not, which is what
the decision required. Phase 4 should shorten that path by passing the unwrapped
DEK straight from Kotlin into Rust over JNI.

The original analysis, retained for the record:

Decision B1 (persistent identity) is approved, but there is a boundary in the
way:

`generate_ed448_keypair()` creates the seed **inside Rust** and there is no
PyO3 accessor that returns it — `expose_seed_slice()` is `pub(crate)`. An
identity generated the production way therefore cannot be persisted at all. The
only reconstruction path is `Ed448KeyHandle.from_seed_bytes(seed)`, whose own
docstring describes itself as "test/internal use; production calls
`generate_ed448_keypair` instead so the seed is never observed from Python at
all."

**Option A — generate the seed in Python**, seal it, reconstruct via
`from_seed_bytes`. No Rust change; works today. Costs the documented property
that private key bytes never appear on the Python heap: the seed is a Python
object at creation and again at every load, and CPython offers no reliable
zeroization for it.

**Option B — seal and unseal inside Rust.** An additive `storage.rs` exposing
`seal_ed448_handle(handle, dek) -> bytes` and
`unseal_ed448_handle(blob, dek) -> Ed448KeyHandle`. Only ciphertext crosses the
boundary; the seed never enters Python. Uses the existing AES-256-GCM and
`SecretBytes` — no new primitive. This is what the Phase 1 report proposed.

**Recommendation: B.** It preserves the boundary that is the codebase's main
structural security claim, and the additional work is small and additive.

`android_bridge/identity.py` is written so this is a swap: `IdentityKeyStore`
is the interface, and the package ships no concrete implementation. The test
double in `tests/test_android_identity.py` uses Option A and is explicitly
marked development/test only.

---

## X1 — Password to a substituted `.i2p` server

**Status: RESOLVED on Android (2026-09-28), with the residuals below. Not yet
exercised by a handset login (PHYSICAL_TEST_PLAN.md §0).**

### The defect

A short `.i2p` name is bound to a destination by the router's address book,
which a subscription feed, a jump service or a first registrant can
influence. Over I2P the transport turns TLS certificate checks off, because
there is no CA for `.i2p`. The client then authenticated with whatever SASL
mechanism the server offered -- including PLAIN, which is the password
itself. A substituted destination therefore collected the account password.
Message content was never exposed (DAKE-authenticated, TOFU-pinned end to end).

### The fix: both options, combined

**B. Destination pinning** (`android_bridge/server_pins.py`). The identity of
an I2P server is its destination -- the `.b32.i2p` hash of the full
destination the router returned -- never its name.

* The first destination a name resolves to is pinned when that connection
  (or registration) succeeds: trust on first use.
* Every later attempt is checked inside the SAM connect, between `NAMING
  LOOKUP` and `SESSION CREATE` (`I2PSAMConnection.connect(verify_destination=)`).
  A different destination raises before any session or stream exists, so
  **not one byte -- no credential -- reaches it**. The failure is
  `i2p_destination_changed` (registration: `server_identity_changed`) and
  names both addresses.
* Nothing retries it in the background (`ReconnectPolicy.NEEDS_THE_USER`).
  The connect screen shows a security warning with both addresses; "Trust new
  address" needs a second confirmation, approves only the destination that
  was refused, and does not connect -- the user logs in again, and the new
  destination becomes the pin only if that succeeds.
* A typed `.b32.i2p` is checked against the destination the router returns
  for it. `.onion` v3 names are self-authenticating and not pinned.
* Pins are public data (names and hashes), stored at
  `~/.otrv4plus/server_pins.json` (0600) and destroyed by Wipe & Exit.
* The transport refuses a forwarder that cannot run the check.

**A. SCRAM only where certificate checks are off**
(`transport._restrict_to_scram`). slixmpp's `feature_mechanisms` is limited to
SCRAM-SHA-512/256/1 (with and without -PLUS); `encrypted_plain` and
`unencrypted_plain` are off. Verified on the wire against the real slixmpp
1.17 plugin: a server offering only PLAIN (or LOGIN, DIGEST-MD5) gets no
`<auth>` at all and the attempt fails as `no_safe_auth_mechanism`; with SCRAM
offered, the first message carries `n=<user>,r=<nonce>` and never the
password. slixmpp also refuses SCRAM on a stream without TLS, so an I2P
server that skips STARTTLS gets nothing. SCRAM is mutual: a server that does
not hold the credential cannot complete it.

Clearnet (`clearnet_tls`) keeps slixmpp's default: CA-verified certificate,
hostname checked; PLAIN is allowed only inside that verified TLS, and the
transport refuses to send a password or a registration form if TLS was not
negotiated (`tls_required`).

### Residual risks, stated

1. **First contact is trust-on-first-use.** If the very first resolution of a
   name is already substituted, that destination is pinned. Layer A then
   still keeps the password off the wire, but:
2. **A SCRAM exchange with an impostor permits an offline guessing attack**
   on a weak password: the impostor picks the salt and iteration count and
   receives the client proof, against which it can test guesses offline. It
   never receives the password itself. Use a strong, unique password.
3. **Registration over I2P on first contact** sends the NEW account's
   password inside the XEP-0077 form over TLS to an unpinned destination.
   After the first success the destination is pinned and later
   registrations are protected.
4. ~~The terminal client accepts whatever the server offers.~~ Resolved
   2026-10-24: `otrv4plus_xmpp.py` restricts SASL to SCRAM wherever certificate
   checks are off (I2P, .onion, `--insecure-tls`), and checks every resolved
   I2P destination with the same rule as the app
   (`android_bridge.server_pins.check_destination`), on start-up and on every
   reconnect. A changed destination is shown with both addresses; only typing
   the new address in full approves it, and a reconnect never retries one.
   Residuals 1-3 apply to it as to the app.

### Tests

`tests/test_x1_destination_pinning.py` runs the real forwarder and the real
`I2PSAMConnection` against a scripted SAM bridge that plays the XMPP server
at each destination and records every byte: first use pins A; reconnect to
A is allowed; after the name is re-pointed at B the attempt is refused, no
`SESSION CREATE` or `STREAM CONNECT` follows the lookup, B receives zero
bytes and the password never reaches it; registration is blocked the same
way; approval is only for the refused destination and does not re-pin until
a successful connect; the SCRAM restriction is checked on the real slixmpp
plugin. Disabling either layer fails 15 of those tests (checked by mutation
on 2026-09-28). `ReconnectPolicyTest` pins that the refusal is not retried.

`tests/test_x1_terminal_client.py` covers the terminal client: SCRAM-only on
the real slixmpp plugin for I2P, .onion and `--insecure-tls` (and not for a
verified clearnet server); the shared rule agreeing with the app's own check
in every case; first use pinned only after sign-in, a change refused, and
approval only by typing the new address; reconnects using the same check.
Removing the SCRAM restriction or the change check each fails 3 of them
(checked by mutation on 2026-10-24).

