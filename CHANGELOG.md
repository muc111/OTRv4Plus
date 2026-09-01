# Changelog

OTRv4+ post-quantum messaging client. Solo dev project. AI-assisted (Claude). Each version live-tested between two I2P peers before commit.

---

## v10.14.0 — /sendfile

*2026-09-01.  `VERSION → 10.14.0`, `otrv4_core 0.10.26`.  New capability; the encrypted-file format carries its own version byte, currently `1`.*

**XMPP only.**  The IRC client has no file transfer, imports nothing from the transfer module, and its OTR and TLV behaviour is untouched.  That is not a promise, it is `tests/test_file_transfer_boundary.py::TestTheFeatureIsXmppOnly`, which walks `otrv4+.py`'s AST for the import, greps it for the command and the prefix, and asserts `otrv4plus_xmpp.py` is the only file in the repository that references the module.

**Both peers need this build** to exchange files: a peer without `RustFileSender` cannot key a transfer.  Chat and voice with a v10.13.3 peer are unaffected.

**No second cryptographic system, and that was the main design decision.**  The audit's question was whether the existing session already provides an authenticated secret suitable for a transfer key.  It does: the double ratchet's brace key already folds ML-KEM-1024 shared secrets, so session state is already post-quantum and already DAKE-authenticated.  Running a second KEM exchange would have added a handshake, a transcript and a failure mode to reach a level the session already had.  The transfer key is derived from the session's **extra symmetric key** — the value OTRv4 reserves for exactly this kind of out-of-band use — with domain separation and the transfer id in the derivation.

**That key was being thrown away.**  `DakeSessionKeys.extra_sym_key` existed, was derived at KDF usage `0x1F`, and was zeroized inside `from_dake_keys` along with everything else the ratchet did not need.  It is now retained on the PyO3 wrapper as a `SecretBytes<32>`; the inner `DoubleRatchet` and all its derivations are untouched, so IRC behaviour is bit-identical.

**The Python side of the extra symmetric key was dead code, and weaker than it looked.**  `OTRv4TLV.EXTRA_SYMMETRIC_KEY` (`0x0009`) has a receive handler that derives its own key in Python — `sha3_512(session_id + b"OTRv4-EXTRA-SYM" + tlv.value)[:32]` — with no reference to the DAKE-derived value.  Nothing sends that TLV, `_extra_sym_key_cb` is never assigned, and `_last_extra_sym_key` is never read.  It was **not** built on: a Python-side key derivation is what INV-08 and INV-14 exist to prevent.  It is left in place for now because deleting it would change shared IRC/XMPP code for an XMPP feature; it is recorded here as a follow-up.

**`aead.rs` was the wrong tool and was not used.**  Its AES-256-GCM binding takes the key as a parameter, because it was written to replace `cryptography.AESGCM` in the storage classes where Python already held the key.  Using it here would have put the FileKey across the FFI on every chunk.  The new `Rust/src/filetransfer.rs` follows `voice.rs` instead: a Rust-owned `SecretBytes<32>` with no getter, `seal_chunk`/`open_chunk`, and `zeroize`.  Same `aes-gcm` crate; the difference is who owns the key.

**The format.**  64 KiB plaintext chunks, so a 1 GB file is 16384 chunks rather than 1 GB of RAM.  Nonce is `0x00000000 || UINT64BE(index)` — deterministic rather than random, which is safer here because the key is fresh per transfer and a counter cannot collide, where 96-bit random nonces have a birthday bound a large file could approach.  The AAD binds the format version, the transfer id, the chunk index and a **final flag**, so a chunk cannot be reordered, duplicated at another index, replayed into another transfer, or presented as the last one to truncate the file.  A zero-length file is still one authenticated chunk.

**Verification before placement, in six steps**, and the file is never decrypted into its destination: chunk tags, the final flag, the chunk count, SHA-256 of the ciphertext, SHA-256 of the plaintext, and the size on disk — then an atomic rename.  Any failure deletes the temporary file and drops the transfer.  A chunk that fails its tag aborts immediately rather than leaving a partial file waiting for chunks that can never verify.

**The filename is never a path.**  The output directory is fixed locally (`~/.otrv4plus/files/`, 0700, with `.incoming/` for partial work) and only a sanitised basename comes from the offer, so there is no peer-supplied path to traverse out of.  `../../private.key` becomes a filename, not a location.  A second file of the same name gets a suffix rather than replacing the first.

**Transport-independent by construction.**  The engine takes its byte pump as a parameter and is driven in tests by a plain list, not by XMPP — if that test ever needs slixmpp, the independence has been lost.  Phase A passes the OTR channel; a SAM-stream pump can be substituted later without touching the protocol, the format, the integrity checks or the storage handling.

**The transport boundary is explicit, and that is the part the torrent phase depends on.**  `ChunkTransport` has two methods, deliberately separate: `send_control` for offer/accept/decline/done/cancel, and `send_chunk` for one already-sealed chunk.  Splitting them means a bulk transport cannot accidentally carry signalling, or the reverse.  Inbound, every transport funnels through one `deliver_chunk` seam, so the ordering rule and the authentication are defined once and cannot diverge.  `OtrChunkTransport` is Phase A — both channels on the OTR channel, chunks base64'd into control messages, which is why its chunk size is 16 KiB rather than the format's 64 KiB.  **Replacing that one class is the whole of a transport upgrade.**  `tests/test_file_transfer_boundary.py` drives the same engine through a second transport that shares no framing with it, and asserts the plaintext hash is identical, that no chunk touched the control path, and that the engine's executable code names nothing XMPP.

**Three mutants survived the first pass.**  Two turned out to be equivalent — the separator strip is redundant with the character filter, and the chunk-count check is unreachable because the authenticated final flag fails first — and both are now marked as deliberate redundancy in the code rather than papered over with a contorted test.  The third was a real gap: nothing tested a **lying offer**.  Four tests were added for a sender that seals honestly and then misstates the plaintext hash, the ciphertext hash, the chunk count or the size.  Nine of eleven mutations are killed; the two equivalents are documented.

**Found while writing the tests, not fixed here.**  `DAKE1RateLimiter` documents itself as per-peer, but both call sites invoke `process_dake1(dake1_msg)` without the `peer_key` argument, so every peer shares the default bucket `"unknown"`.  It is a **global** limiter of 5 attempts per 60 seconds, and one peer exhausting it locks out DAKE1 from every other peer.  That is engine-wide behaviour affecting IRC and XMPP alike; file transfer has no business changing session establishment, so it is recorded rather than patched.

**`/sendfile` with no path opens the Android file picker.**  You have `termux-api`, so there is no reason to make anyone type `~/storage/dcim/Camera/20260901_143022.jpg`.  The picker runs in an executor because it waits for a human scrolling a gallery, which is far longer than anything else in this client may block for.  Two honest caveats, both surfaced in the client rather than buried: `termux-storage-get` hands over bytes and **not a name**, so the file is renamed from its magic number and a timestamp — cosmetically worse, marginally better for privacy, and `/sendfile <path>` still preserves a name exactly; and the apt package is only shell shims, so a missing **Termux:API app** is reported as the missing half rather than as a timeout.  The staged copy is plaintext, lives at 0600 under a `.picked/` directory separate from received files, and is unlinked as soon as the file is sealed — including when sealing raises.

**Termux cannot see your photos until you tell it to.**  Termux's home is inside the app's private data directory and has no view of Android storage, so `/sendfile photo.jpg` on a fresh install reports "no such file" and the fix is `termux-setup-storage` — a command a user has no reason to have heard of.  Nothing in the repository mentioned it.  The error now names it, but only on Android and only when `~/storage` is genuinely absent, so it never nags someone who simply mistyped.  `FILE_TRANSFER_TEST_PLAN.md` covers both directions: getting a file in (`~/storage/dcim/Camera/...`, or `termux-storage-get` for the graphical picker) and getting a received one back out — with what that costs, since copying from a 0700 private directory into shared storage makes the file readable by every app holding the storage permission.

**Verification.**  Python 2283 passed, 43 skipped, 1 xfailed (was 2109).  Rust 101 passed (was 87).  `tests/test_file_transfer_crypto.py` runs against real ratchets from a real DAKE, not stubs.  **No live XMPP or device testing** — nothing here has moved a file between two phones.

---

## v10.13.3 — the channel user list, and what its blue marker does not mean

*2026-08-31.  `VERSION → 10.13.3`, `otrv4_core` unchanged at `0.10.25`.  No wire change.*

**`/names` printed "[IRC line suppressed]" for every line.**  Not a policy, a bug: `Pager.display` measured each line, truncated it, and then printed a literal string instead of it.  One wrong argument, present since v10.11.0.  Every pager consumer was affected — **`/list` and `/help` were equally broken**, which is why the fix is one line and covers all three.  The NAMES rendering itself already existed and was never reached; it has been reworked rather than replaced.

**A second bug the first one was hiding.**  The pager truncates at `TERMINAL_WIDTH` using `len()`, which counts ANSI escape bytes as visible characters.  Now that coloured lines actually print, a long one would be cut about ten columns early *and* lose its reset sequence, bleeding colour into the rest of the terminal.  `_truncate_visible` measures visible columns and re-appends the reset.

**The user list.**  A summary line (`🔵 3 OTRv4+ • 94 other clients`), then Operators / Voiced / Users, with detected OTRv4+ users in blue and sorted to the top of their group so the actionable names are together.  **The total is the server's count, not the number of rows drawn** — the list is capped locally at 500 and the header says what it is a slice of.  Multi-prefix entries (`@+nick`) parse correctly; entries carrying a space, a NUL or a newline are dropped individually rather than costing the whole render.

**Selecting a user.**  Detected OTRv4+ users are numbered, and pressing 1–9 in the pager runs the normal `/otr <nick>` entry point.  It is a shortcut for typing the command, and it starts a DAKE like any other — it confers nothing by itself.

**Detection uses the mechanism the project already had, and two gaps in it.**  CTCP VERSION is deliberately refused, so the realname (gecos) sent at USER registration is this client's only identification channel; the server relays it in `RPL_WHOREPLY`, and `/names` sends `WHO` before `NAMES` to collect it.  Two of the three realname paths did not carry the version: a 27 Club nick advertised `Kurt Cobain (Nirvana) - 27 Club` and a NickServ-registered nick advertised the bare nick, so **two whole classes of OTRv4+ user were invisible to their own peers**.  Both now end with VERSION.  A detection mechanism the client does not consistently feed is not a detection mechanism.  The match also tightened from a bare `"OTRv4+" in realname` substring — which fires on `I don't use OTRv4+` typed into a gecos — to the tag plus a dotted version.

**The marker is identification, not authentication, and INV-20 is what keeps it that way.**  Anyone can put `OTRv4+ 10.13.3` in their own gecos; the server does not check it and neither can we.  It answers "is this peer likely to understand `/otr`".  The DAKE authenticates, TOFU pins identity, SMP authorises voice — the marker does none of those.  `format_names_list` is a pure function with no client to promote anything on, the voice module cannot see the map at all, and tests fail if any of that changes.

**`/whois` was reporting a claim it had made up.**  `Client:` printed our own `VERSION` whatever the peer was running, and `Name:` printed `TwentySevenClubNick.real_name(target)` — the *local* formatting of their nick, which returns `<nick> - OTRv4+ <version>` for any nick at all and is never equal to the bare nick, so the peer's actual realname was never displayed.  `/whois` on a mIRC user therefore reported them as an OTRv4+ client, which is precisely the nick-derived inference this release exists to avoid.  Both fields now come off the wire: `Client:` shows the version the peer advertises or `not advertised`, and `Name:` shows their realname.  `RPL_WHOISUSER` is the same reliable metadata as `RPL_WHOREPLY`, so a `/whois` now also refreshes that nick's marker — including clearing a stale one.

**Two smaller correctness fixes.**  A nick change now carries the OTRv4+ marker across (it is keyed by nick, so a rename would strip it from the person and leave it on a name nobody holds), and a QUIT drops it (someone else may take the nick, and a stale entry would mark them as an OTRv4+ client on no evidence).  `RPL_ENDOFNAMES` now clears its accumulator even when it arrives unsolicited on JOIN, where it previously grew for the life of the process and inflated the next `/names` total.

**Three mutants survived the first pass** and each was a real gap: nothing covered the NickServ realname branch, nothing checked that a malformed NAMES token failed to inflate the header count, and the truncation test was passing on a near-equivalent mutant.  Two tests added, one sharpened.  Fifteen mutations, all killed.

**Verification.**  Python 2109 passed, 43 skipped, 1 xfailed (was 2027).  Rust 87 passed, unchanged — no Rust was touched.  `tests/test_irc_names_list.py`, 79 tests.  **Not tested against a live IRC server.**

---

## Unreleased — transport policy

*Documentation, specification and tests only.  No code change, no wire change, no version bump: a peer on v10.13.2 is unaffected.*

**Why now.**  Three transports exist (I2P, Tor, clearnet TLS) and each was added under a different set of assumptions, written down in a different place or not at all.  Two more routes are wanted — a SOCKS5 proxy and a proxy chain under clearnet TLS — and the point of writing the rules before that code is that the rules are what the code will be built against.

**[TRANSPORT_POLICY.md](TRANSPORT_POLICY.md)** is the new authoritative document.  Five modes, a transition matrix, and the separation the rest of it hangs from: `TransportClass {I2P, TOR, CLEARNET_TLS}` is security-relevant and is what the UI reports; `Route {direct, proxy, proxy_chain}` is operational and sits *underneath* a class.  A proxy is not a fourth privacy tier next to I2P and Tor — it is a route beneath clearnet — and only the class would ever reach the cryptographic transcript, because two peers who chose different proxies must still be able to talk.

**The rule, stated once:** the transport class is fixed for the lifetime of a call; an endpoint may change within a class if the change is authenticated; a class change requires ending the call.  `MEDIAPATH` is the authenticated endpoint change, and it is what recovered the Wi-Fi-to-mobile transition — so "nothing may change mid-call" would have been the wrong rule.  I2P→TLS, Tor→TLS and TLS→I2P are forbidden, the last of those included because a silent *upgrade* is still a class change the peer did not agree to.  The matrix is an allowlist: an unlisted transition is forbidden, not undefined.

**Two sequences named so they stay forbidden:** `I2P fails → try Tor → try clearnet`, and `I2P is slow → switch to UDP`.  The second is the more dangerous, because it triggers on degraded rather than failed and therefore fires hardest on exactly the congested networks where nobody is watching.

**Encryption is not anonymity is not routing.**  Clearnet TLS 1.3 is strong encryption with no anonymity; calling it "less secure" is wrong.  Tor is not "the NSA one" and I2P is not "the most secure one".  A proxy operator can log, identify, inject or be compromised, so a proxy mode is never labelled anonymous — INV-19 fails if any document says otherwise.

**Voice over Tor is recorded as a decision with a reason, not as a gap.**  Tor carries TCP; voice here is constant-rate datagrams on a latency budget, and the SAM *stream* version was already unusable for speech.  A mode that connects and does not work is worse than no mode, because users select it and conclude the application is broken.  The condition for revisiting it is a real-time media transport for Tor, not a demonstration that packets traverse it.  Clearnet UDP media is refused on the same grounds in the other direction: the only reason to reach for it is latency, and latency is not worth anonymity.

**Three invariants added.**  INV-17 no fallback ladder (ENFORCED), INV-18 the class is fixed for the call (PARTIAL — enforced today by there being exactly one media class, with the transcript binding specified and deferred), INV-19 honest wording (ENFORCED).  `tests/test_transport_policy.py`, 29 tests.

**One existing test was wrong and is now right for a different reason.**  `test_xmpp_has_no_tor_path` asserted the absence of PySocks and was named for a fact that stopped being true when Tor XMPP landed.  The assertion is correct and the reason is better than the old one: PySocks routes by assigning `socket.socket` process-wide, so in this process it would capture the I2P SAM bridge and every voice media socket — a Tor XMPP session would silently drag the media path through Tor too.  Renamed to `test_tor_is_not_applied_process_wide`.

**Deferred, deliberately:** binding `TransportClass` into the voice key derivation (a wire break, needs its own version bump and cross-version tests), the `TransportClass`/`Route` Rust types, and proxy-chain media.  The proven I2P voice path is not destabilised to make the matrix symmetrical.

---

## v10.13.2 — the voice key path moves into Rust

*2026-08-28.  `VERSION → 10.13.2`, `otrv4_core 0.10.25`.  No wire change.*

**Both peers need this build.**  Not because the format moved — it did not — but because the media path is Rust-only from here: a peer whose `otrv4_core` predates `RustVoiceCipher` cannot make a call, and fails at startup rather than mid-call.  There is deliberately no Python fallback, since falling back would restore the thing this release fixes.

**Media keys.**  `VoiceFrameCrypto` kept its keys in a `bytearray` so they could be wiped, then handed each one to OpenSSL as `AESGCM(bytes(key))` — an immutable copy nothing could overwrite, which the AESGCM object retained anyway.  One per direction per sub-epoch: at `RATCHET_INTERVAL = 500` frames and 60 ms per frame, about 276 unwipeable copies over a 69-minute call.  Calling the existing `aes256gcm_encrypt(key, ...)` helper per frame would have been worse, putting the key into Python on every frame instead of every 500.  The keys are now `SecretBytes<32>` inside `RustVoiceCipher`, which rebuilds its cipher from the single copy that exists and zeroizes on drop.  No getter, and adding one would defeat the module.

**The voice X448 private scalar** was a `cryptography` object Python could neither wipe nor reach — the one private value in the voice path with no cleanup at all.  It is now `SecretBytes<56>` in `RustVoiceKex`: single-use, spent even when the agreement is refused (retrying with a different peer key is the shape of a small-subgroup probe), and carrying every check the Python version had — reflection, all-zero peer key, on-curve validation, and the RFC 7748 requirement that a degenerate shared secret abort rather than be used.

**The SMP passphrase wipe was being defeated one line before it ran.**  `set_smp_secret` built a wipeable bytearray, passed `bytes(raw)` to the vault, and then zeroed the bytearray in a `finally` — wiping the object that no longer mattered while the copy survived.  `RustSMPVault.store_from_bytearray` now takes the bytearray and zeroes the caller's buffer, including on the error path.

**Byte-for-byte compatible.**  Same HKDF-SHA512, same labels, same four-byte length prefixes.  Verified in both directions.

**Two things worth recording about how this went.**  The first Rust draft length-prefixed with eight bytes instead of four; every cross-implementation frame failed its tag, with no error and no clue — just silence on the call.  The parity test caught it.  Then, once `VoiceFrameCrypto` began delegating to Rust, that same test became Rust-against-Rust: a deliberately reintroduced eight-byte prefix passed clean.  Mutation testing found that, not reading.  The reference derivation is now rebuilt inside the test from primitives, and ten of its thirty-five tests fail on that mutant.

**The epoch root moved too.**  It is the input every media key derives from, so a copy of it is a copy of every key for that epoch — and it sat in a Python `bytearray` for the whole call.  `RustVoiceRoot` now owns it as `SecretBytes<64>`: Python holds a handle that can produce a cipher, a confirmation pair or an endpoint tag, and cannot produce the root.  The initial derivation, the rekey chaining, the confirmations and the endpoint tags all happen inside Rust, and the X448 / ML-KEM shared secrets are zeroed by Rust before the call returns rather than by a `finally` the caller has to remember.

**What did NOT move, deliberately.**  The rekey STATE MACHINE stays in Python: it is protocol logic, it owns the convergence properties fixed at v10.13.1, and putting freshly-audited behaviour through an unnecessary rewrite is how stable systems break.  Same for the frame header, AAD construction, replay window, jitter buffer and call state machine — none touch key material, all are proven on real calls.

**Tests that read secrets had to change, and are better for it.**  Assertions like "the committed root is unchanged" used to compare root bytes directly.  They now compare the confirmation pair, which is a deterministic function of the root and travels on the wire anyway — so equal confirmations mean equal roots and nothing else is revealed.  Where even that was not available, the property is asserted through its consequence: two calls that shared a media key would produce identical ciphertext for identical plaintext, so the test seals and compares.

**Verification.**  Python 1992 passed, 43 skipped, 1 xfailed (was 1934).  Rust 87 passed (was 77).  Android 82 passed, 37 skipped.  **No live XMPP or I2P testing** — everything was exercised through the PyO3 boundary and over loopback, and this release changes what encrypts every audio frame.

---

## v10.13.1 — security hardening: input capture, log boundary, rekey divergence

*2026-08-28.  `VERSION → 10.13.1`, `otrv4_core 0.10.24`.  No wire change.*

A hardening pass driven by a repository-wide security inventory.  Five findings, three of them real defects; sixteen invariants now enforced by tests rather than by prose.

**A remote peer could decide what your next keystroke meant.**  Completing a DAKE armed `_pending[peer] = "smp_secret"`, and `dispatch_line` consumed that state ahead of all command parsing with only `/quit` exempt.  The arming path ran from the inbound message handler, so a peer who started an OTR session could make the next line the user typed be swallowed and stored as a passphrase.  Masked and never transmitted, so not exfiltration — but a remote party choosing the meaning of local input.  Supplying the secret now needs `/smp-secret`, typed locally, and the request is single-use.  `tests/test_no_remote_input_capture.py` walks the inbound call graph transitively rather than checking a hand-maintained allow-list, because the previous test allowed `_apply_tofu` in its "local flows" set and passed while the property was false.

**A hand-rolled Python cipher, deleted.**  `otrv4plus_log.py` carried its own AEAD — a SHAKE-256 keystream XORed over the plaintext with a truncated HMAC-SHA3-512 tag — and a `persistent=True` mode that kept every line anyone typed, and its key, across sessions.  No caller ever set it; the docstring said XMPP did.  Deleted rather than re-based onto the Rust AES-256-GCM: in-memory scrollback that dies with the process has nothing to protect at rest, so removing the disk removes the cipher too.  Also removes the crash-remnant case, where ephemeral mode left files behind.

**The session transcript writes only what it recognises.**  It used to redact one line shape and write everything else verbatim, which fails open.  Now an allowlist: message bodies dropped, structural rules and known diagnostic tags kept, anything else recorded as `<unlogged line: N chars>`.  A sweep found no call site printing a secret value, so this closed a latent hole rather than an active leak.  `tests/test_log_boundary.py` drives realistic passphrases, keys, seeds and tokens through nine carrier shapes; a mutant that fails open fails 75 of its 97 tests.

**Credentials were in the config's `repr()`.**  `OTRConfig` is a dataclass, so `repr(cfg)` printed `sasl_pass` and `nickserv_pass`.  Found by a test doing exactly that and printing it in the failure message.  Both fields are now `repr=False`.  The residual limit is unchanged: Python `str` cannot be zeroized, and that is recorded as a limitation rather than papered over.

**Media rejections are classified by cause.**  Every rejection incremented `auth_fail` unless its exception text contained "replay", so `authfail=87` could mean a forged frame, a peer that had rekeyed ahead, a retired epoch, or a lost byte stream.  `FrameError` now carries a `reason` set at the raise site.  Only a failed AES-256-GCM tag counts as authentication failure.  Nothing is accepted that was not accepted before.

**Two rekey defects that could strand a call permanently.**  `abort_rekey` removed the pending epoch's cipher from the *receive* set — but the initiator commits as soon as the responder's tag verifies and only then sends REKEYCOMMIT, so it is already sending on the new epoch while the responder still has it pending.  A responder aborting on a timeout could no longer decrypt anything the peer sent.  Separately, an incoming REKEY had to name exactly `ours + 1`, so a responder that missed one REKEYCOMMIT was rejected forever — including the messages that would have repaired it.  A timeout abort now keeps the receive cipher (silence is not evidence; a failed tag still discards, because that is), and a bounded forward jump is accepted as a catch-up.  Committing still requires a valid confirmation tag, the epoch still only moves forward, and a jump beyond `VOICE_REKEY_MAX_CATCHUP` is still refused.

**Not fixed, and stated as such:** there is no positive acknowledgement proving both peers switched epochs.  Closing that needs a fourth message and therefore a wire change.  What replaces it is convergence rather than proof.

**One premise corrected.**  The brief for this work stated that IRC had Argon2-based SMP protection and XMPP did not.  That asymmetry has never existed: both transports call the same `SMPAutoRespondStorage` and the same `_derive_key`, and no commit in history wrote SMP secrets in plaintext on either.  The real defect was terminal echo, fixed at `a687ff2`.

**New:** `SECURITY_INVARIANTS.md` and `tests/security_invariants.py` — sixteen invariants, each naming the test that enforces it.  `tests/test_invariant_registry.py` fails if an invariant has no test, if a named test module does not exist, or if the document and the registry disagree.

**Verification.**  Python 1932 passed, 43 skipped, 1 xfailed (was 1633).  Rust 77 passed.  Mutation-tested: the input-capture, log-boundary and rekey fixes each fail their tests when reverted.  **No live XMPP or I2P testing** — everything here was exercised through the PyO3 boundary and over loopback.

---

## v10.13.0 — Argon2id SMP secret derivation (wire version 0x03)

*2026-08-26.  `VERSION → 10.13.0`, `otrv4_core 0.10.23`.*

**Both peers must be updated together.**  SMP wire version `0x03` derives a different secret scalar from the same passphrase than `0x02` did.  A pair where one side has pulled and the other has not aborts at the version check with a message that says so — it does **not** report a passphrase mismatch, because the passphrase is probably fine.  There is no negotiation and no downgrade.

**What was wrong.**  The SMP passphrase was stretched by 50,000 rounds of SHAKE-256 over the passphrase **alone**; the session ID and both fingerprints were bound in afterwards by a single HMAC.  Two problems, and the second is the worse one.  The work was CPU-only, so it parallelised freely on a GPU.  And because nothing user-specific entered the expensive part, `stretch(candidate)` was computable once and reusable against every OTRv4Plus user and every session that had ever run — after which testing a candidate against a captured SMP transcript cost one HMAC.  50,000 rounds bought far less than the number suggested.

**What replaced it.**  `Rust/src/smp.rs::stretch_argon2id`: Argon2id, m=64 MiB / t=3 / p=4, salted with `SHA3-512("OTRv4+SMP-ARGON2-SALT-v3" || 0x00 || LEN(session_id) || session_id || LEN(first_fp) || first_fp || LEN(second_fp) || second_fp)`.  Every salt field is length-prefixed, so `(session_id, fp, fp)` triples cannot be re-split into a colliding one.  The salt is deterministic and must be — both peers have to reach the same scalar and SMP has no message in which to carry a salt — but `session_id` is per-DAKE, so even the same two peers re-running SMP derive under a fresh salt.  Argon2 failure does not fall back to the weaker stretch; failing open there would undo the entire point.

**What did NOT change.**  The `0x02` derivation is retained byte-for-byte, pinned by a frozen test vector that was cross-checked against an independent Python implementation rather than against the Rust code.  Message layouts are identical between `0x02` and `0x03` — measured wire sizes unchanged at 5849 / 12096 / 6248 / 5472 bytes.  No other key schedule, no message authentication rule, no replay window, no ratchet, no DAKE, no voice cryptography.  Cost on this hardware: 0.192 s per derivation, run once per verification.

**Documentation retraction.**  `FEATURES.md` and `README.md` had both claimed an "Argon2id KDF protecting the SMP vault" running inside `otrv4_core`, and audit finding 6 was recorded closed on the same premise.  None of it was true: `argon2` was not a crate dependency, no Rust source referenced it, and `src/smp_vault.rs` is an in-memory zeroizing store with no key derivation in it.  The only real Argon2id was Python-side and at-rest.  The claim survived a documentation-synchronisation pass because the table was read and not checked.  Retracted in `dc82681`, then made true where it mattered here.  `tests/test_kdf_claims_are_true.py` now reads `Cargo.toml` and the Rust sources instead of the prose, and SECURITY.md carries the retraction as caveats 14 and 15.

**At-rest KDF downgrade is no longer silent.**  `otrv4+.py::_derive_key` caught every Argon2 failure with a bare `except Exception: pass` and fell through to scrypt, with the only notice an import-time print.  A 64 MiB allocation genuinely can fail on a pressured handset, so this was reachable.  The fallback is kept — losing access to your own SMP secrets is worse than a weaker KDF at rest, and the load path already tries both — but it warns once with the reason, and `kdf_backend()` reports which KDF actually ran.

**Also.**  The SMP wire byte is now pinned by `tests/test_protocol_version.py`, which `VERSIONING.md` had claimed for it without it being true.

**Verification.**  Python 1633 passed, 43 skipped, 1 xfailed.  Rust 77 passed (was 65).  Twelve new Rust tests cover the derivation directly — that the salt binds the session ID, that it binds the fingerprints, that it is role-independent, that field boundaries cannot collide, that Argon2 and the legacy stretch disagree, and that a mixed-version pair aborts with an actionable error.  Sixteen new Python tests in `tests/test_smp_argon2_wire_v3.py` drive the real compiled extension through all four SMP steps, plus three in `tests/test_protocol_version.py` pinning the wire byte.  **Not yet live-tested between two handsets** — the derivation is exercised through the PyO3 boundary and over loopback only.

---

## v10.12.0 — voice media liveness, authenticated endpoint recovery, documentation sync

*2026-08-25.  `VERSION → 10.12.0`, `otrv4_core 0.10.22`.*

**Encrypted voice over I2P now detects, diagnoses and recovers from a media path that stops.**  Before this release a call whose inbound media died stayed "up" indefinitely: the transmit side kept succeeding, because a datagram handed to the local SAM UDP bridge is accepted whether or not the session behind it still exists, so no counter anywhere went wrong.  The call looked healthy and carried nothing.

**Detection.**  A liveness watchdog runs in both transport modes, checking at the media probe cadence (5 s) and measuring silence since the last frame that *authenticated* — not since the last datagram that arrived, which a dead path can still produce.  A new `dgram_in` counter, incremented before every filter, disambiguates the previously ambiguous `rx=0`: `rx=0 dg=0` is a dead path, `rx=0 dg>0` is a live path with the fault above it.

**Recovery.**  When nothing is arriving at all, the endpoint is replaced: the old SAM session is closed, a new one built, and the new destination announced to the peer in a new `MEDIAPATH` control message.  The announcement is authenticated from the committed epoch root (`derive_endpoint_tag` over call_id, epoch, sequence, destination and role), so a stale, forged or rolled-back address is rejected.  No media key derives from the destination, so moving the address invalidates no key: the epoch, replay windows, ratchet and call identity all survive recovery untouched, and a packet already accepted stays rejected afterwards.  Recovery is confirmed by inbound media resuming, never by the clock.

**SAM-session-aware backoff (`b12c802`).**  A SAM session lives exactly as long as its control socket.  Measured on a real Wi-Fi→mobile transition, the diagnosis already read `SAM control socket open` — the session had never been destroyed, the router was rebuilding tunnels under a destination that was still ours — and rebuilding anyway cost 21.2 s plus ~20 s of our own `tx` at zero.  The rebuild is now held for `VOICE_RX_SESSION_HOLD_S` (30 s) while the control socket is open.  The user warning is **not** delayed, the dead horizon moves with the hold so the recovery window can never shorten, a closed or unknown socket is treated as gone and behaves exactly as before, and `OTRV4PLUS_RX_SESSION_HOLD_MS=0` disables it.

**Cold paths are no longer mistaken for broken ones (`09f800d`).**  Media first flowed at t=96 s on a live call while the watchdog fired at 26.6 s and rebuilt an endpoint that was merely still coming up, costing ~70 s of silence.  Until one frame has authenticated, `VOICE_RX_START_GRACE_S` (120 s) replaces the warning threshold and the dead horizon moves with it.

**Bounded.**  Worst case from media death to teardown is 465 s for a proven path and 795 s for one that never carried audio.  All four figures (held and unheld) are computed from the constants by `TestTheWorstCaseIsBounded`, which fails if `VOICE_MEDIA_PATH.md` and the code disagree.

**PyO3 thread-affinity crash fixed (`c98ba9b`).**  `DakeOutput` is `#[pyclass(unsendable)]`: it records its creating thread and panics if touched from another.  The OTR executor was a `ThreadPoolExecutor(max_workers=2)` directly contradicting its own "single thread" comment, so a DAKE could be started on one worker and continued on the other — `DakeOutput is unsendable, but sent to another thread`, a hard crash.  Serialised to one worker.  This protects more than the PyO3 requirement: OTR session processing is stateful, and two messages for one peer must not be processed concurrently regardless — ratchet state, skipped-message-key accounting, SMP state and DAKE state all depend on it.  The dead synchronous fallback `_handle_otr_in`, which would have re-introduced engine calls on the event loop, was deleted in `df7349d`; `tests/test_otr_thread_affinity.py` asserts it stays gone.

**XMPP keepalive no longer disconnects working streams (`5e8d4e8`).**  XEP-0199 IQ pings with a 30 s timeout over three I2P hops were declaring dead a stream that was carrying traffic — proved from logs showing rekeys committing 3.2–22 s before a "dead" verdict.  Quiet threshold 180 s, ping timeout 60 s, two consecutive failures required, and an inbound-stanza filter that counts *any* traffic as liveness.  Field-verified: 0 disconnects and 0 keepalive lines across a 31-minute call.

**Rekey no longer wedges on one lost message (`f129578`).**  A responder that lost a `REKEYACK` previously left both sides unable to rekey for the rest of the call.  Field-verified: 14 rekeys committed, 0 timeouts.

**Termux incoming-call UX (`d0bfa11`).**  Notification, ringtone and ACCEPT/DECLINE actions wired to the existing call state machine over a FIFO, with single-use call-bound tokens.  No UI string is a security predicate.

**Terminal and session UX (`648f089`).**  Mouth-to-ear readout colour-banded against ITU-T G.114 (green ≤400 ms, yellow ≤800 ms, red above); wrong login passwords re-prompt instead of failing the session; an OTR session whose peer leaves and does not return is cleared automatically, so `/otr` works on their return.

**Documentation synchronised and versioning made explicit.**  `VERSIONING.md` added.  Version strings, which had drifted to five different values across `otrv4+.py`, `otrv4plus_xmpp.py`, `Rust/Cargo.toml`, `Rust/pyproject.toml` and the README badge, were reconciled to one.  Stale wire figures corrected across the README (the Opus frame default moved 40 ms → 60 ms and the packet 199 B → 279 B in an earlier cycle without the documentation following).  `FEATURES.md` still listed voice as out of scope and is rewritten.  **Correction:** the "no Python `cryptography` dependency" claim from v10.7 no longer holds — `otrv4plus_voice.py` uses that library for the media AES-256-GCM, HKDF-SHA512 and X448.  The chat path remains Rust-only; the voice path does not, and every document that claimed otherwise now says so.

**XMPP gets a persistent identity and real TOFU; IRC deliberately does not.**  Both protocols regenerated their Ed448 identity every launch, and both wrote to the same `~/.otrv4plus/trust.json`.  For IRC that is correct — a nick is ephemeral, so a fingerprint pinned to one is pinned to nothing.  For XMPP it was not: a JID is durable, so a fingerprint that changed every restart carried no information, and because `add_trust` raises `FingerprintMismatchError` when the stored value differs, the *second* session with any peer you had trusted printed "This may indicate a MITM attack".  Every reconnect.  A warning shown that often is a warning that will be ignored the once it is real.  A complete TOFU implementation, `TrustDatabase.check_or_pin()`, had been sitting in the tree with zero callers because it could not work against an identity that never persisted.

  * **XMPP identity persists.**  One sealed Ed448 identity, reloaded every run.  It reuses the Android B1 mechanism rather than inventing a second one: `Rust/src/identity.rs` seals and unseals inside Rust, so the seed never becomes a Python object and no `get_seed()` accessor exists.  `otrv4plus_identity.py` adds only the Termux-side key custody and file handling.  **The at-rest protection is filesystem permissions, not a passphrase** — the DEK is a 0600 file, because Termux has no keyring — and that limit is stated wherever the feature is described rather than glossed as "encrypted at rest".  Loading fails closed: a record that will not open is never silently replaced, because regenerating would change our fingerprint with no signal and every peer holding a pin would see it as an attack we caused.
  * **XMPP trust is pinned.**  First contact shows the fingerprint and asks once.  A match afterwards asks nothing.  A **change** is reported, does not replace the stored pin, offers no `y`-answerable prompt, does not continue into SMP setup, and refuses voice for that peer until `/trust-reset <jid>` is typed deliberately.  TOFU is identity *continuity*: a matching pin authorises nothing, SMP remains the authentication mechanism, and `_smp_verified` remains the only gate on a call — the mismatch refusal is layered on top of it, never an alternative route through.
  * **IRC is unchanged and now writes nothing.**  Fresh identity every run, trust held in memory for the session so a `y` still sticks across a reconnect within one run, nothing on disk.  Removing the write is also what removes the false mismatch — the warning was not suppressed, the record that caused it stopped being created.
  * **The stores are separate.**  XMPP owns `~/.otrv4plus/xmpp/`; stored SMP passphrases are migrated there once, with the `.smp_seed` that decrypts them, and the legacy copies are left for IRC.

**SMP says why it stopped, without letting a peer capture your typing.**  A responder with no stored passphrase queued `SMP_ABORT` and returned in silence: it told its own user nothing, and the initiator saw a generic abort indistinguishable from a wrong passphrase — so the one failure a user can actually fix looked like the one they cannot.  The responder is now told what happened and which command fixes it, and the abort carries an optional `NOSECRET` reason so the initiator can say "your peer has not stored the passphrase yet" rather than "aborted".  The payload was previously empty and ignored, so an older peer drops it exactly as before; it is a diagnostic that only chooses wording, never a predicate, because it is text a peer controls.

  The obvious fix — prompting the responder for the secret — was deliberately **not** implemented.  `_pending[peer] = "smp_secret"` makes `dispatch_line` swallow the next line typed ahead of every command except `/quit`, so letting an inbound SMP1 arm it would let a peer decide that the user's next sentence, possibly meant for a different conversation, becomes a stored secret.  The secret is supplied only by an explicit local `/smp-secret <secret>`, and tests assert that nothing in the protocol engine can reach the prompt.

**Verification.**  Python `1483 passed, 43 skipped, 1 xfailed` (3.12, repo root).  Rust `65 passed`.  52 new tests across `tests/test_identity_and_tofu.py` and `tests/test_smp_no_secret.py`, mutation-tested with 13 mutations: 12 killed, and the 13th shown to be an equivalent mutant (the ephemeral-trust guard is deliberately duplicated in `__init__` and `_load`; removing *both* is killed, removing either alone changes nothing).  The SAM-session-hold invariants were mutation-tested: removing the hold, applying it when the session is gone, delaying the warning with it, failing to move the dead horizon, removing the rebuild gate, and changing the constant or the documented bound without the other each make the suite fail.

---

## v10.10.0 – v10.11.1 — released without changelog entries

These releases shipped the XMPP transport, its security hardening, the Tor
control-plane route, and the first working encrypted voice path, but no
changelog sections were written at the time.  Rather than reconstruct them after
the fact, they are recorded here as a gap.  The contemporaneous record is:

* **XMPP transport and hardening (v10.10.4)** — README *"XMPP transport"* and *"Security hardening"*.
* **Voice calling, hybrid voice key exchange, two-phase rekey, AAudio backend (v10.11.0)** — README *"Encrypted voice calls"*; `VOICE_AUDIT_REPORT.md`.
* **Voice security fixes (v10.11.1)** — README *"Security fixes in v10.11.1"*.
* Commit range `da691d1..624bbca` and the audit documents dated in that window.

---

## v10.9.2 — formal protocol specification + documentation pass

**`SPEC.md` added.**  A complete byte-level wire specification: exact field offsets and sizes for DAKE1/2/3 and the ClientProfile, the KDF construction with the full usage-ID table, the normative session-key derivation order, the hybrid PQC SMP construction (group params, length-prefixed wire encoding, group-element validation bounds, the 50,000-round secret derivation, the Schnorr ZKP construction, and the PQ binding layer), the fragmentation format, the DAKE/SMP state machines, normative security requirements, and the RFC 3526 prime in full.  The goal is that a qualified developer can write a compatible implementation in any language from this document alone, without reading the source.

**Documentation updated** for the hybrid PQC SMP across `README.md` (added a "Why OTRv4+ vs alternatives" comparison table and a 30-second pitch, and linked `SPEC.md` prominently), `SECURITY.md` (MITM and quantum-adversary rows note hybrid PQC SMP; memory table adds the SMP ML-KEM secret key, ML-DSA signing key, and `pq_binding_key` rows; new caveat documenting the construction and the variable-time ZKP scalar limitation), and `WHY.md` (SMP description rewritten, I2P timing corrected to the measured ~15–16 min).  `termux_install.sh` rewritten Rust-only.

Version strings aligned to 10.9.2 across `otrv4+.py` and `smp.rs`.  No protocol or wire change from v10.9.1.

---

## v10.9.1 — hybrid PQC SMP timeout + I2P transport tuning

**SMP session timeout raised 600 s → 2700 s (45 minutes).**  The hybrid PQC SMP wire overhead over I2P is substantial — SMP2 is 49 fragments of ML-KEM and ML-DSA material — and the initiator was timing out milliseconds before receiving SMP4 on a slow I2P path.  Measured end-to-end: full DAKE + SMP VERIFIED over I2P SAM (irc.postman.i2p) in ~15–16 minutes; under 6 minutes over TLS clearnet.

**I2P transport tuning (live-tested against irc.postman.i2p).**  Fragment payload reduced 450 → 380 bytes after the stricter postman line limit truncated the DAKE1 tail ("Invalid wire format"; reassembled 5310 vs 5940 chars on TLS confirmed truncation).  Send pacing changed from per-fragment delay to a batch strategy — 2 fragments then a 6-second pause (~0.33 lines/sec) — after 200 ms / 600 ms / 1200 ms per-fragment all still triggered Excess Flood disconnection.  Tor stays at 200 ms; TLS uses the token bucket.

**Per-panel scroll fix.**  `_scroll_history` was a single global list mixing all channels' terminal output, so Ctrl+P scrollback in one channel showed another channel's messages.  It is now rebuilt from the active panel's own history on every tab switch.

**IRCv3 typing notifications (P2P).**  `@+typing=active/done TAGMSG` sent on keypress/submit in private panels; received TAGMSG shows a transient "✍ is typing…" line.  Channel panels unaffected.

---

## v10.9.0 — hybrid post-quantum SMP

**The Socialist Millionaire Protocol is now hybrid post-quantum.**  The classical OTRv4 four-step Schnorr ZKP over the 3072-bit MODP group (RFC 3526 Group 15) is preserved verbatim and now runs alongside an ML-KEM-1024 + ML-DSA-87 binding layer.  Forging a false "verified" result requires breaking the 3072-bit discrete log, ML-KEM-1024, and ML-DSA-87 **simultaneously**; the construction is never weaker than classical SMP against a classical adversary.

**Construction.**  In SMP1 the initiator generates an ML-KEM-1024 keypair and an ML-DSA-87 keypair and appends the encapsulation key (1568 B) and ML-DSA-87 public key (2592 B) to the classical payload.  In SMP2 the responder encapsulates to derive `kem_ss`, derives `pq_binding_key = KDF(PQ_BRACE_KEY, domain || kem_ss || transcript_tag, 32)`, generates its own ML-DSA-87 keypair, and signs the entire SMP2 wire body under `pq_binding_key` as context.  SMP3/4 each verify the previous step's ML-DSA-87 signature before processing the classical fields, then sign their own output.  All KEM/DSA secret material is `ZeroizeOnDrop` and wiped immediately after use.

**Wire versioning.**  Byte 0 of each SMP message is `0x01` (classical) or `0x02` (hybrid PQ).  A version mismatch aborts the session — no silent downgrade.

**Critical bug fixed during development — KEM key mixing.**  The first hybrid implementation derived the SMP secret scalar from the KEM key as well as the passphrase.  But the initiator called `set_secret` **before** generating its ML-KEM keypair, so the KEM key was absent on the initiator side, while the responder received it in SMP1 and applied a re-bind step — so the two sides derived **different** secret scalars from the same passphrase and SMP failed with a false negative on every attempt, even though the ML-DSA-87 signatures all verified.  Unit tests missed it because they set up keypairs before `set_secret`; only live two-session testing caught it.  **Fix:** the KEM key was removed from the secret-scalar derivation entirely.  PQ security comes from `pq_binding_key` and the per-step ML-DSA-87 signatures; the secret scalar stays purely classical/symmetric.  After the fix, SMP VERIFIED over both TLS and I2P.

**Tests.**  15 hybrid-PQC SMP unit tests added (classical roundtrip, hybrid roundtrip, mismatched secrets in both modes, version-mismatch rejection, ML-DSA-87 context sign/verify, wrong-context rejection, ML-KEM-1024 encaps/decaps roundtrip, `pq_binding_key` determinism, PQ SMP with question field).  Combined suite 30+ Rust tests.

---

## v10.7.6 — Phase 5.4: constant-time SMP modular exponentiation

**The SMP modular exponentiation is now constant-time.**  SMP's `modpow` migrated from `num-bigint` (whose `modpow` running time depends on the exponent's bit pattern) to `crypto-bigint`'s `DynResidue` (Montgomery-form, constant-time in the exponent).  This closes a timing side-channel on the secret SMP exponents: the blinding scalars (a2/a3/b2/b3), the SMP secret itself, and the ZKP randomisers (r4b/r5b/r6b…).  This was the last open security-hardening item on the ROADMAP.

**Spec unchanged.**  The 3072-bit group (OTRv4 §5.3 — same prime, same order (p-1)/2, same generator g=2) is identical; only the *implementation* of exponentiation changed.  The wire format is byte-for-byte the same and interop with prior OTRv4+ versions is preserved.  Verified live: full DAKE + SMP VERIFIED over I2P with a peer running the previous build.

**Scope.**  All 15 secret-dependent `modpow` call sites now route through a constant-time `mod_exp` that internally uses `DynResidue`; `mod_inv` (Fermat `a^(p-2)`) inherits constant-time from it.  Public-value arithmetic (ZKP challenge/response reconstruction with `*`/`%`/`+`) and random sampling stay on `num-bigint` — there is no secret-dependent timing in those paths, so moving them would add risk for no security gain.  `num-bigint` therefore remains a dependency.

**Dependency.**  `crypto-bigint 0.5` promoted from a transitive dependency (already pulled in by the pqcrypto stack) to a direct `pq-rust`-gated dependency — no new crate compiled into the tree.

**Tests.**  Six SMP unit tests added (the crate had none before): `SMP_PRIME_CT` byte-equality against `SMP_PRIME`; `mod_exp` small known-answer (2¹⁰); `mod_exp` cross-checked against `num-bigint`'s reference `modpow` at full 384-byte width; `mod_inv` roundtrip; full SMP1→4 matching-secret VERIFIES; mismatched-secret FAILS.  These are build-time correctness gates — they caught a wrong-group-size bug during development (see below) before it could reach a live session.

**Bug fixed during development.**  `SMP_PRIME_BYTES` was declared `256` but the SMP prime is 3072-bit = **384 bytes**.  The first migration attempt used a 2048-bit `Uint`, which silently truncated the top 1024 bits of the prime; the `mod_exp` reference-cross-check and full-roundtrip tests failed deterministically and exposed it.  Corrected to `U3072` / `Uint<48>` / 384-byte width throughout.  The prior `num-bigint` code was never affected by the `256` mislabel because its `fixed_bytes` helper only pads up to a floor and never truncates, and real group elements already exceed 256 bytes.

`cargo test`: 26 passed (20 prior + 6 SMP), 0 warnings.  Live: DAKE + SMP VERIFIED over I2P with peer QuartzRoot.  VERSION → 10.7.6, otrv4_core 0.10.23.

---

## v10.7.5 — ClientProfile validity tightened to 14 days

The OTRv4 spec §4.1 recommends short ClientProfile lifetimes (weeks rather than years).  Earlier versions used a 365-day expiry that was inherited from the pre-ephemeral design and never revisited.  For OTRv4+, where the long-term identity key is regenerated at every launch, a 1-year profile validity widened the impersonation window without buying anything — peers see a fresh profile on every DAKE1 anyway.

**Changed.**  `ClientProfile.expires = self.created + 365 * 24 * 3600` → `self.created + self.VALIDITY_SECONDS`, where `VALIDITY_SECONDS = 14 * 24 * 3600`.  Two sites (constructor and `renew()`) now reference the single class-level constant, so they can't drift again.  Matches `otr4j`'s default.

No protocol or wire change.  Existing offline-cached profiles older than 14 days now require a fresh DAKE1 (which OTRv4+ would have done anyway because of session ephemerality).

---

## v10.7.4 — Phase 5.3k + 5.3i-D: Rust-core-only, the architectural finish line

**All C extensions retired.**  OTRv4+ now has a single cryptographic implementation surface: the Rust `otrv4_core` PyO3 module.  No second backend, no compile-time conditionals selecting between paths, no Python-vs-Rust comparison checks at boot.

**Phase 5.3k — file deletions and import removal.**
- `otrv4+.py`: the `otr4_ed448_ct` import block deleted.  A grep for `_ed448_ct.` member access was empty before deletion — the import was a defensive ground-truth that had no live callers anywhere in the codebase.  `ED448_CT_AVAILABLE` removed.  The `_sys.path.insert(...)` line was retained (still needed for `otrv4_core` import resolution).
- `git rm`: `otr4_crypto_ext.c`, `otr4_crypto_ext.so`, `otr4_crypto_ext.cpython-313-aarch64-linux-android.so`, `otr4_ed448_ct.c`, `otr4_ed448_ct.so`, `otr4_mldsa_ext.c`, `otr4_mldsa_ext.so` (the last set was orphaned since v10.6.18), `setup_otr4.py`.
- Test migration: seven test files in `tests/` (`test_mlkem_kat.py`, `test_property.py`, `test_differential.py`, `fuzz_harnesses.py`, `test_ratchet_torture.py`, `test_ring_android.py`, `test_attacks.py`) migrated from `import otr4_crypto_ext as _ossl` to `import otrv4_core as _ossl`.  The Rust module exposes `mlkem1024_keygen` / `_encaps` / `_decaps` with identical signatures, so the migration was a one-line import swap for six of them.  `test_attacks.py` additionally uses `_ossl.cleanse`, so it received a small `_OsslShim` providing the Rust ML-KEM functions plus a `ctypes.memset` cleanse.
- `git rm tests/test_otr.py` — this was a smoke test for all three retired C extensions' surfaces (bignum ops, `ring_sign`, `ed448_scalarmult`, `mldsa87_*`); after the migration it tested only deleted code.
- Documentation updated across `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`, `DEVELOPMENT.md`, `MIGRATION.md`, `CONTRIBUTING.md`, and both `prebuilt/` READMEs.

**Phase 5.3i-D — `aead.rs` warning cleanup.**
The 13 deprecation warnings emitted by `aead.rs` since v10.6.19 were all uses of `aes-gcm 0.10`'s deprecated `GenericArray::from_slice` helper.  Fix: production sites now use `Aes256Gcm::new_from_slice(key)` (from the `KeyInit` trait, takes `&[u8]`, returns `Result<Self, InvalidLength>`) and convert the nonce slice to `&[u8; 12]` via `try_into()` then `Nonce::from(*nonce_arr)` (matching the actual `impl From<[u8; 12]> for GenericArray<u8, U12>` in `generic-array 0.14.7`).  Test sites use `Nonce::from(n)` directly since `n` is already `[u8; 12]`.  Restored the zero-warning Rust build that v10.6.18 originally achieved.

**Verified.**  `cargo test` 20 passed, 0 failed.  `cargo build` 0 warnings.  Live DAKE + SMP VERIFIED + multi-epoch ratchet across an I2P channel with peer `CopperFox`.

---

## v10.7.3 — Phase 5.3i-C: ML-KEM-1024 brace KEM moved to Rust

`MLKEM1024BraceKEM` (the double ratchet's post-quantum brace-key KEM) migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem 0.1.1`.  Same crate that already backs the DAKE KEM in `dake.rs`; the new `src/mlkem.rs` PyO3 module exposes three functions (`mlkem1024_keygen` / `_encaps` / `_decaps`) wrapping it.

**Subtlety.**  pqcrypto's `encapsulate(public_key)` returns `(SharedSecret, Ciphertext)` — the *opposite* tuple ordering from the C extension's `(ciphertext, shared_secret)`.  The Rust wrapper inverts the tuple to match the existing Python contract exactly; the existing Python callers and tests are unchanged.  Three Rust unit tests cover byte sizes against FIPS 203, full keygen→encaps→decaps shared-secret matching, and wrong-key rejection.

After this commit, `otr4_crypto_ext` had no remaining callers anywhere in the codebase.  The import block in `otrv4+.py` was removed; the `.c`/`.so` files were left in place for Phase 5.3k to delete.

`Rust/Cargo.toml`: `otrv4_core` version bumped 0.10.21 → 0.10.22 to reflect the new module.

---

## v10.7.2 — Phase 5.3i-B: `_ossl.cleanse` replaced with `ctypes.memset`

The OpenSSL-backed `_ossl.cleanse(bytearray)` zeroization helper replaced with a module-level `_secure_wipe(bytearray)` using `ctypes.memset` via a `c_char * len` view into the bytearray's buffer.  This is the standard dead-store-resistant wipe technique (memset through a `volatile`-ish indirection so LLVM cannot prove the writes are unobservable and elide them).

**Sites updated.**  Eight `_ossl.cleanse(...)` calls repointed to `_secure_wipe(...)`.  Two were deleted as redundant (`SecureMemory.zeroize` already wiped via `ctypes`; `_secure_file_destroy` already wiped its key buffer manually).

No third-party-library dependency for memory wiping anywhere in the codebase now — `ctypes` is stdlib, `zeroize::Zeroize` is in Rust.

---

## v10.7.1 — Phase 5.3i-A: dead bignum wrappers + `disable_core_dumps` migration

Four dead Python wrappers around the C extension's bignum surface deleted as part of the 5.3i lead-in.  All four were leftovers from the pre-Rust-SMP era when SMP arithmetic lived in Python and called into `otr4_crypto_ext.bn_*`.  Since the v10.6.x Rust SMP migration, SMP modular arithmetic has lived entirely inside `src/smp.rs` (using `num-bigint`); the wrappers had no callers.

- `_ct_mod_exp` (wrapper around `_ossl.bn_mod_exp_consttime`) — deleted.
- `_ct_mod_inv` (wrapper around `_ossl.bn_mod_inverse`) — deleted.
- `_ct_rand_range` (wrapper around `_ossl.bn_rand_range`) — deleted.
- `SHA3_512.hash_to_int` — deleted.  Referenced the long-removed `SMPConstants` class.

`disable_core_dumps()` migrated from `_ossl.disable_core_dumps` to Python `resource.setrlimit(RLIMIT_CORE, (0, 0))`.  Pure stdlib; no C extension call.

Python-only change; no Rust rebuild required.

---

## v10.7 — Phase 5.3h-D complete: Python cryptography library fully removed

**The Python `cryptography` library is no longer imported or used in any code path. Every asymmetric and symmetric cryptographic operation runs in the Rust `otrv4_core` core.**

v10.7 is the final stage of Phase 5.3h-D. Stages 1 and 2 (v10.6.20, v10.6.21) moved the last two live cryptography-library uses — Ed448 verification and the X448 ratchet DH — into Rust. v10.7 removes the dead code that still referenced the library and deletes the import.

### What was removed

**The pure-Python `OTRv4DAKE` fallback class — 863 lines.** This class was the original Python DAKE implementation, kept as a fallback for builds without the Rust core. It was already uninstantiable in practice:

- `RustDAKEAdapter.__init__` either succeeds with the Rust backend or raises `RuntimeError`. It never constructs `OTRv4DAKE`. The `_use_rust` flag was always `True` by the time any adapter method ran.
- The Rust ratchet (`RUST_RATCHET_AVAILABLE`) and Rust SMP have been mandatory since v10.6.11 — a build without the Rust core raises long before any DAKE fallback could matter. The Python DAKE could never actually carry a session to completion.

So `OTRv4DAKE` was ~860 lines of unreachable code plus, in `RustDAKEAdapter`, 12 dead `if not self._use_rust: return self._py_fallback.…` branches. All deleted.

**The `_use_rust` / `_py_fallback` machinery.** 12 dead guard blocks, the `self._use_rust` / `self._py_fallback` field declarations, the dangling end-of-`__init__` fail-fast block, and the `MLDSA87_AVAILABLE and self._use_rust` guard simplified to `MLDSA87_AVAILABLE`. Three debug-tag sites that read `_use_rust` for a "🦀/🐍" label are hardcoded to Rust.

**The cryptography library import.** The top-of-file block

```python
try:
    from cryptography.hazmat.primitives.asymmetric import ed448, x448
    from cryptography.hazmat.primitives import serialization
    ...
```

is gone, replaced by a comment recording that all crypto is now Rust-side.

### What was rescued and rewritten

**`_safe_b64decode`** was a `@staticmethod` on `OTRv4DAKE` with five callers (three inside the deleted class, two elsewhere — `_handle` paths around lines 11116 and 12497). It is lifted to a module-level function defined before `class DAKE1RateLimiter:`. All five callers repointed from `OTRv4DAKE._safe_b64decode(...)` to the bare `_safe_b64decode(...)`.

**`ClientProfile.__init__`** previously accepted legacy `ed448.Ed448PrivateKey` / `x448.X448PrivateKey` arguments and converted them to Rust handles via `isinstance` branches (a test-only path). Those branches are deleted (option B1): `ClientProfile` now accepts only `None` (generate a fresh Rust handle) or an already-constructed handle. The cryptography-library type hints on the `__init__` signature are stripped. Every runtime `ClientProfile()` call site constructs with no arguments, so nothing in production is affected.

**Four `serialization.Raw` sites removed.** `remote_long_term_pub` has held raw 57-byte Ed448 public-key bytes since v10.6.19 (Phase 5.3h-C), so the `.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)` calls in `get_fingerprint()`, `_get_remote_fp()`, and the two `pub_key_data` extraction sites were operating on raw bytes anyway (their surrounding `try/except` swallowed the `AttributeError`). Replaced with direct `bytes(...)` use. The `remote_long_term_pub` type hint changed from `Optional[ed448.Ed448PublicKey]` to `Optional[bytes]`.

### Net effect

883 lines removed from `otrv4+.py`. No Rust changes — the Rust core was already complete at the v10.6.21 state. The crypto surface of the project is now Rust (`otrv4_core`) plus two C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) slated for removal in Phase 5.3i / 5.3k. There is no OpenSSL-backed Python crypto anywhere.

### Files touched

- `otrv4+.py`: deleted `OTRv4DAKE` class and `_use_rust`/`_py_fallback` machinery; rescued `_safe_b64decode` to module scope; rewrote `ClientProfile.__init__` (B1); removed four `serialization.Raw` sites; removed the `from cryptography...` import; VERSION → `10.7`
- `README.md`: chip → v10.7; architecture box notes the library is removed; caveat about the cryptography library replaced; Quick start drops the `pip install cryptography` step
- `SECURITY.md`: known-issue 3 rewritten — the cryptography library is gone, with the v10.6.18→v10.7 removal sequence documented; memory-safety model updated
- `ROADMAP.md`: Phase 5.3h-D marked complete; 5.3i is now the largest remaining hardening item
- `FEATURES.md`: primitive table no longer lists any cryptography-library implementation
- `CHANGELOG.md`: this entry

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (5 ring_sig + 1 RFC 8032 Ed448 + 3 mldsa + 3 aead
#                      + 3 key_handles Ed448 + 2 X448)
```

`python otrv4+.py --debug` boots to the connect screen with no `NameError` or `ImportError` — the boot-check that confirms every reference to the deleted class and removed imports was caught. Live: DAKE + SMP verified over I2P.

---

## v10.6.21 — Phase 5.3h-D stage 2: X448 ratchet DH moved to Rust

**The double ratchet's X448 Diffie-Hellman now runs in the Rust core. No Python cryptography-library X448 remains in the message path.**

`RustBackedDoubleRatchet` performed its DH ratchet steps with `cryptography.x448` — `X448PrivateKey.generate()`, `.exchange()`, `X448PublicKey.from_public_bytes()` — running on every message after the first. These now use the Rust `otrv4_core` `X448KeyHandle`.

**No new Rust crypto.** `generate_x448_keypair()` and `X448KeyHandle.dh()` already existed (used by `ClientProfile` since the v10.6.12 handle work) and were already registered in `lib.rs`. Stage 2 was a Python swap plus two Rust test vectors.

### Python changes (seven edits in `RustBackedDoubleRatchet`)

- `__init__` and `from_dake_output`: `dh_ratchet_local` is now an `X448KeyHandle` from `generate_x448_keypair()`; `dh_ratchet_local_pub` from `handle.public_bytes()`.
- `_decrypt_new_dh`: receive-side and send-side DH via `handle.dh(peer_pub_bytes)`, which takes the raw 56-byte peer key directly.
- `_ratchet`: send-side forced ratchet step, same swap.
- The first-message remote-pub record stores raw 56 bytes only; `dh_ratchet_remote` (the object) is set to `None` — it was never read anywhere, every consumer uses `dh_ratchet_remote_pub` (the bytes).

### Correctness

X448 is RFC 7748 and fully deterministic — a given (clamped scalar, u-coordinate) pair has exactly one correct output. The `x448` crate clamps the scalar inside `Secret::from` (RFC 7748: `byte0 &= 252`, `byte55 |= 128`) and rejects low-order points, matching OpenSSL's behaviour. A v10.6.21 peer and an older cryptography-library peer therefore derive byte-identical DH secrets and the ratchet stays in sync.

Two Rust tests added to `key_handles.rs` as the build-time desync guard:

- `x448_rfc7748_known_answer` — the `x448` crate reproduces RFC 7748 §5.2's published X448 test vector. Since OpenSSL also implements RFC 7748, matching the vector means the two agree.
- `x448_handle_dh_is_symmetric` — two generated handles derive the same shared secret from each other.

### Files touched

- `Rust/src/key_handles.rs`: added `x448_rfc7748_known_answer` and `x448_handle_dh_is_symmetric` tests
- `Rust/Cargo.toml`: version 0.10.20 → 0.10.21
- `otrv4+.py`: seven ratchet edits; VERSION → `10.6.21`

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (15 prior + 2 X448)
```

Live: DAKE + sustained multi-message exchange both directions over I2P, across 5+ DH-ratchet epochs (DATA ratchet counter stepped 0→5). Every message decrypted clean — the proof that the Rust X448 swap is byte-correct against a live peer. The test spanned multiple I2P transport disconnects; the ratchet stayed in sync across them.

---

## v10.6.20 — Phase 5.3h-D stage 1: ClientProfile Ed448 verify moved to Rust

**The last security-critical Ed448 operation that used the Python cryptography library now runs in Rust.**

`ClientProfile.decode()` verified incoming-peer profile signatures with `ed448.Ed448PublicKey.from_public_bytes(pub).verify(sig, signed_data)`. It now calls a new Rust PyO3 function, `otrv4_core.verify_ed448_sig(pub_bytes, msg, sig_bytes) -> bool`.

### Correctness

`verify_ed448_sig` wraps `VerifyingKey::verify_raw` — the inherent pure-Ed448 verifier from `ed448-goldilocks-plus` 0.16. This is the exact counterpart of `Ed448KeyHandle::sign`, which calls `SigningKey::sign_raw`. ClientProfile signatures are produced by that same handle's `sign()` method (`encode()`, the `self.identity_key.sign(...)` call), so signer and verifier now use identical RFC 8032 pure-Ed448 framing with an empty context. A profile signed by any v10.6.x build verifies unchanged.

`verify_ed448_sig` returns `False` on a failed verification (bad signature, public key not a valid curve point) and raises `ValueError` only on structurally malformed input (wrong public-key or signature length), so the Python caller can distinguish a forged profile from malformed bytes.

### Crate API note

The `ed448-goldilocks-plus` 0.16 `VerifyingKey` is constructed via `VerifyingKey::from_bytes(&[u8; 57])`, not a `TryFrom<&[u8; 57]>` impl (the `TryFrom<PublicKeyBytes>` impl the compiler suggests is a pkcs8 wrapper). `Signature` is built from a slice via `Signature::try_from(&[u8])`, which checks length internally. Both were confirmed against the installed crate source rather than assumed.

### Files touched

- `Rust/src/key_handles.rs`: added `verify_ed448_sig` PyO3 function, a `#[cfg(test)]` module with three tests (`ed448_sign_then_verify_roundtrip`, `ed448_verify_rejects_tampered_msg`, `ed448_verify_rejects_bad_lengths`), and the `VerifyingKey` / `Signature` imports
- `Rust/src/lib.rs`: registered `verify_ed448_sig`
- `Rust/Cargo.toml`: version 0.10.19 → 0.10.20
- `otrv4+.py`: `ClientProfile.decode()` swaps to `_RustDAKE_module.verify_ed448_sig`; `_check_rust_requirements` requires it; VERSION → `10.6.20`

The `ed448` cryptography-library import was **not** removed at v10.6.20 — the legacy non-Rust DAKE paths still referenced it. It was removed at v10.7 when the dead `OTRv4DAKE` class that contained those paths was deleted.

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 15 passed (12 prior + 3 key_handles Ed448)
```

Live: DAKE completes; the peer's ClientProfile signature verifies through the Rust path.

---

## v10.6.19 — Phase 5.3h, parts A2 + B + C

**Three of four production `cryptography` library use-classes retired. New Rust AEAD module. Startup migration for legacy orphan files.**

### Phase 5.3h scope reality check

Phase 5.3h was originally scoped as "one focused session, ~100-150 lines." Diagnostic showed this estimate was off by an order of magnitude: the `cryptography` library has 4 use classes (AESGCM, Ed448PublicKey, X448PrivateKey/PublicKey, serialization.Raw), totalling 40+ call sites with deep coupling to the ratchet's DH path.

v10.6.19 ships the three smaller sub-phases (A2 + B + C). The fourth (Part D — drop Ed448 verify, X448, and serialization.Raw) was multi-session and rescheduled; it shipped across v10.6.20, v10.6.21, and v10.7.

### Part A2 — legacy on-disk file cleanup

Startup migration in `main()` securely destroys orphan files from pre-`~/.otrv4plus/` builds:

- `~/.otrv4_vault` (633 bytes, no current code references it)
- `~/.otrv4_smp_secrets.json` (97 bytes, legacy SMP-secrets file at home root)
- `~/.otrv4_keys/` (legacy keys directory)

Uses the existing `_secure_file_destroy()` NIST SP 800-88r1 primitive: encrypt zeros with a fresh AES-256-GCM key, overwrite the file with ciphertext + tag, fsync, zeroize the key via `_ossl.cleanse`, then unlink. No-op for new installs.

### Part B — AES-256-GCM moved to Rust

New `Rust/src/aead.rs` exposes two PyO3 functions:

- `otrv4_core.aes256gcm_encrypt(key, nonce, plaintext, aad) -> bytes`
- `otrv4_core.aes256gcm_decrypt(key, nonce, ct_and_tag, aad) -> bytes`

Wraps the `aes-gcm` 0.10 crate. Wire-identical to `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Three live AESGCM call sites swapped: `SMPAutoRespondStorage._load/_save`, `SecureKeyStorage._encrypt_key/_decrypt_key`, and `_secure_file_destroy`. Files written by v10.6.18 decrypt cleanly under v10.6.19. Three new Rust unit tests.

### Part C — Ed448PublicKey wrap removed at six live sites

Six `Ed448PublicKey.from_public_bytes(...)` call sites (three in `RustDAKEAdapter`, three in `OTRv4IRCClient`) swapped from cryptography-library wrapping to raw bytes. `remote_identity_key` and `remote_long_term_pub` now hold raw bytes; the SHA3-512 fingerprint path uses the bytes mirror directly.

### `cryptography` library import diet

Dropped `AESGCM` (replaced by Rust) and `hashes` (confirmed unused). The `ed448` and `x448` imports remained at v10.6.19; they were removed later in Phase 5.3h-D.

### Files touched

- `Rust/src/aead.rs`: new file, ~165 lines including tests
- `Rust/src/lib.rs`: added `pub mod aead;` and two `add_function` registrations
- `Rust/Cargo.toml`: version 0.10.18 → 0.10.19
- `otrv4+.py`: AESGCM/hashes imports dropped; three AESGCM sites swapped; six Ed448PublicKey wrap sites replaced; `_check_rust_requirements` requires the aead functions; startup orphan-file migration; VERSION → `10.6.19`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 12 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa + 3 aead)
```

---

## v10.6.18 — Phase 5.3j + Phase 5.3g (ephemeral-by-design decided)

**`otr4_mldsa_ext` C extension retired; ML-DSA-87 now runs entirely on `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings.**

The Python `MLDSA87Auth` class is unchanged externally — same `PUB_BYTES = 2592`, `SIG_BYTES = 4627`, same wire-format guards across the four parse sites in `EnhancedOTR.{_handle_dake1, _handle_dake2, _handle_dake3_initiator, _handle_dake3_responder}`. Three call sites internal to the class now delegate to `_RustDAKE_module.mldsa87_keygen / mldsa87_sign / mldsa87_verify` instead of the deleted `_mldsa.mldsa87_*` C extension entry points.

The new Rust module `Rust/src/mldsa.rs` is a thin PyO3 wrapper over `pqcrypto-mldsa::mldsa87::{keypair, detached_sign, verify_detached_signature}`. Three unit tests in the same file: round-trip, tampered-message rejection, FIPS 204 byte-size assertions (2592 / 4896 / 4627).

### Wire format

Byte-identical to v10.6.17. Both v10.6.17 and v10.6.18 peers can DAKE with each other — same FIPS 204 ML-DSA-87 parameter set, same PQClean reference implementation underneath.

### Cargo.toml hardening

`pqcrypto-mldsa` is pinned to `default-features = false, features = ["std"]` to disable AVX2 and NEON SIMD code paths. Same trap that hit `pqcrypto-mlkem` in v10.6.16: the NEON path triggers `SIGILL` on Termux/aarch64 at first `mldsa87_keygen()` call.

### Phase 5.3g — ephemeral identity (DECIDED)

After consideration, OTRv4+ keeps ephemeral identities by design. Fingerprints regenerate at every launch; no persistent vault. Rationale documented in ROADMAP.md and SECURITY.md.

### Files touched
- `Rust/src/mldsa.rs`: new file, ~120 lines including tests
- `Rust/src/lib.rs`: added `pub mod mldsa;` and three `add_function` registrations
- `Rust/Cargo.toml`: pqcrypto-mldsa pinned to `default-features = false`, version 0.10.17 → 0.10.18
- `otrv4+.py`: removed `import otr4_mldsa_ext as _mldsa` block; `MLDSA87_AVAILABLE` reduced to a hardcoded `True`; three `_mldsa.*` calls in `MLDSA87Auth` swapped to `_RustDAKE_module.*`; `_check_rust_requirements` now requires `mldsa87_keygen/sign/verify`; VERSION → `10.6.18`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 9 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa)
```

---

## v10.6.17 — Phase 5.3f-narrow

**Boot-time cross-verify removed; RFC 8032 vectors now build-time gate.**

The Python boot helpers `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()` are deleted. They previously generated a fresh Ed448 keypair via the cryptography library at every program start, signed a test message with both Rust and OpenSSL, and compared byte-for-byte.

Both functions and all four call sites are removed. Replacement: `Rust/src/test_vectors.rs` contains the RFC 8032 §7.4 "Blank" Ed448 vector as `const` arrays and a `#[cfg(test)]` harness that signs with `ed448-goldilocks-plus::SigningKey` and asserts byte-equality.

**Boot is faster** (saves ~200ms). Six obsolete boot-print lines no longer appear.

### Files touched
- `otrv4+.py`: deleted ~150 lines. VERSION → `10.6.17`.
- `Rust/src/test_vectors.rs`: new file, ~100 lines.
- `Rust/src/lib.rs`: added `pub mod test_vectors;`.
- `Rust/Cargo.toml`: version 0.10.16 → 0.10.17.

---

## v10.6.16 — ML-KEM migration

**`pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024).**

NIST finalised FIPS 203 in August 2024. The standard differs from round-3 Kyber in the Fujisaki-Okamoto domain-separator constants; algorithms and parameter sizes are otherwise identical. The `pqcrypto-mlkem` Rust API is drop-in compatible with `pqcrypto-kyber`.

### Cargo.toml carve-out

Pinned to `default-features = false, features = ["std"]` to select the portable PQClean C reference — the NEON path caused SIGILL at first `keypair()` call on Termux/aarch64.

### Wire compatibility

Wire-incompatible with v10.6.15 and earlier. Both peers must run v10.6.16+.

### Files touched
- `Rust/Cargo.toml`: dependency swap, version 0.10.14 → 0.10.16.
- `Rust/src/dake.rs`: 7 call sites renamed `pqcrypto_kyber::kyber1024::` → `pqcrypto_mlkem::mlkem1024::`.

---

## v10.6.15.5 — Cargo.toml: restore signing+pkcs8 features

**Latent silent build break exposed by `cargo clean`.**

An earlier hardening pass had set `ed448-goldilocks-plus` to `default-features = false, features = ["alloc"]`, silently dropping `signing` (which gates `SigningKey`) and `pkcs8`. The break was latent because the live `.so` kept running until a `cargo build` was forced. Fix restored `features = ["alloc", "signing", "pkcs8"]`.

---

## v10.6.15 — SMP race fix

**Tie-break by fingerprint when both peers run `/smp start` simultaneously.**

If both peers run `/smp start` near-simultaneously, each generates SMP1 locally before either receives the other's. Resolution: at SMP1 receive, if the engine is non-Idle, compare identity public bytes — lower fingerprint keeps initiator role, higher fingerprint yields, aborts its own `RustSMP`, rebuilds fresh, rebinds the secret from the `RustSMPVault`, and processes the incoming SMP1 as responder.

---

## v10.6.14 — `lazy_static` → `std::sync::LazyLock`

RustSec lists `lazy_static 1.5` as unmaintained. Replaced with stdlib `LazyLock` (stable since Rust 1.80). Three statics in `smp.rs` converted; all 31 call sites unchanged. MSRV raised to 1.80+.

---

## v10.6.13

**SMP regression fix from v10.6.12.**

v10.6.12 left seven Python call sites using the legacy `.public_key().public_bytes(...)` chain on what was now a Rust handle. One site, `EnhancedOTRSession.set_smp_secret`, read the local fingerprint through the broken chain and silently fell back to an empty bytes literal, diverging the SMP secret hash. All seven sites converted to `bytes(handle.public_bytes())`. No Rust changes.

---

## v10.6.12

**Phase 5.3e: long-term identity keys owned by Rust.**

`ClientProfile.identity_key` and `.prekey` are now `Ed448KeyHandle` and `X448KeyHandle` opaque PyO3 classes. Private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop). New Rust file `src/key_handles.rs` with `Ed448KeyHandle`, `X448KeyHandle`, `generate_ed448_keypair()`, `generate_x448_keypair()`. New `dake::PyDake::sign_profile_body_and_construct_with_handles` takes the handles directly. Wire-compatible with v10.6.11.

---

## v10.6.11

**Phase 5.4: Rust-only, no fallbacks, regression fix.**

OTRv4+ is now a thin Python wrapper around the `otrv4_core` Rust crate. No production codepath falls back to the C extension or the cryptography library for ring sig, Ed448 sign, DAKE, SMP, or ratchet. `_check_rust_requirements()` runs at module load and raises `ImportError` if the Rust core is missing or incomplete.

Note: the pure-Python `OTRv4DAKE` class was retained as nominal fallback code at v10.6.11, but `RustDAKEAdapter` already raised rather than constructing it — it was effectively dead from this version onward. It was formally deleted at v10.7.

---

## v10.6.10

**Phase 5.3d.** Bytearray + wipe in `RingSignature.sign()`. Contained a regression that broke DAKE3 (`_rust_ring_sign` called with a bare bytearray, rejected by PyO3). Fixed in v10.6.11.

---

## v10.6.9

**Phase 5.3c: Rust DAKE3 ring signature.** New file `src/ring_sig.rs` (~407 lines) implementing OTRv4 §4.3.3 Schnorr ring signature in pure Rust using `ed448-goldilocks-plus` and `sha3`.

---

## v10.6.8

**Phase 5.3b: dead-code disk persistence removal.** `_store_identity()` previously wrote encrypted private-key blobs to disk that nothing read back. Removed; one-shot migration overwrites and unlinks legacy `identity.ed448.bin` / `prekey.x448.bin`.

---

## v10.6.7

**Phase 5.3a-cleanup.** Added `ClientProfile.encode_unsigned()`. `RustDAKEAdapter.__init__` uses `sign_profile_body_and_construct` in a single FFI call.

---

## v10.6.6

**Phase 5.3a (Option A2): Ed448 sign via Rust.** Added `sign_profile_body_and_construct` and `ed448_sign_test` to the Rust DAKE class.

---

## v10.6.5

**Phase 5.2: `new_from_bytearrays`.** Rust constructor takes `Bound<PyByteArray>`, copies into `SecretBytes<N>`, then wipes the source bytearray in-place.

---

## v10.6.4

**Phase 5.1.** `RustDAKEAdapter.__init__` extracts identity and prekey private bytes into mutable bytearrays, wipes them after Rust copies into `SecretBytes`.

---

## v10.6.3

**Phase 4: DakeOutput opaque handle. 11/11 audit findings closed.**

DAKE session keys never cross the Python heap. The `DakeOutput` PyO3 handle holds them in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields, taking the actual `is_initiator` flag.

---

## Older versions

Earlier v10.6.x and v10.5.x focused on Rust SMP, Rust double ratchet, X448 ratchet bugs, fragment buffer collision fixes, and the C extension constant-time Ed448 path. See git history for detail.
