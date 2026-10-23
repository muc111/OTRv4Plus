# SMP audit: the `/smp start` regression, and the input-capture paths

Audit only. No code was changed to produce this document. Repository state
`c783967`, client `10.14.0`, `otrv4_core 0.10.26`.

---

## 1. The reported failure, reproduced

```
[smp] start error: SMP start failed: 'builtins.RustSMPVault' object
      has no attribute 'store_from_bytearray'
```

The method named in the brief, `smp_secret_from_bytearray`, does not exist
anywhere in this repository and never has. The wrapped last line of the
screenshot reads `store_from_bytearray`, and that is the method the failure is
about. Everything below is about the real one.

Reproduced by presenting the client with a vault object lacking the method,
which is what an older wheel is:

```
AttributeError: 'StaleVault' object has no attribute 'store_from_bytearray'
re-raised as: SMP start failed: 'StaleVault' object has no attribute 'store_from_bytearray'
```

Byte-for-byte the shape of the reported line, including the `SMP start failed:`
prefix that `otrv4+.py:7173` adds.

## 2. The call path

```
/smp start                       otrv4plus_xmpp.py:3239   smp_start()
  └─ run_in_executor(_otr_executor)                       keeps the loop free
       └─ OTRManager.start_smp                otrv4+.py:8879
            └─ Session.start_smp              otrv4+.py:7132
                 └─ Session.set_smp_secret    otrv4+.py:7342
                      └─ RustSMPVault.store_from_bytearray   ← AttributeError
                           └─ RustSMP.set_secret_from_vault
                                └─ Argon2id + SHAKE-256 derivation, Rust-side
```

The exception is caught at `otrv4+.py:7166`, re-raised as
`RuntimeError("SMP start failed: …")`, caught again in the executor callback
at `otrv4plus_xmpp.py:3276`, and printed. Three frames of wrapping, and the
user is told "start error" for what is an installation problem.

## 3. Why the caller expects that name — the caller is right

`store_from_bytearray` **is** the correct API and it exists in the source
(`Rust/src/smp_vault.rs:198`), ungated, in the production build:

```
$ python3.12 -c "import otrv4_core; print(sorted(m for m in dir(otrv4_core.RustSMPVault()) if not m.startswith('_')))"
['clear', 'count', 'has', 'has_handle', 'names', 'remove', 'remove_handle', 'store', 'store_from_bytearray']
```

It replaced `store(bytes(raw))` deliberately: `bytes(raw)` made an immutable
copy of the passphrase that the caller's careful `finally:` wipe could not
reach, so the wipe cleaned the one object that no longer mattered. The
bytearray form hands the buffer down and Rust zeroes it in place.

`git log -S` puts it in **`62e2c46`, which shipped `otrv4_core 0.10.25`.**
Version `0.10.24` does not contain the string at all.

**So the caller is not stale — the installed wheel is.** The handset is running
client `10.14.0` against a core built before `0.10.25`. `git pull` updates the
Python; only `pip install ./Rust` updates the core, and nothing checks that the
two agree.

### 3.1 This is the actual defect

The client calls into a separately versioned compiled artefact and verifies
nothing before doing so. A missing method surfaces as an `AttributeError` from
inside an executor thread, at the first SMP attempt, wrapped in two layers of
`RuntimeError`, worded as though the protocol failed.

Restoring a `store()` fallback would "fix" the exception by silently
reinstating the unwipeable-copy behaviour that `store_from_bytearray` exists to
remove. That is the wrong fix and it is not proposed.

The right fix is a **core API compatibility check** — the client states which
core methods it requires, the check runs at startup, and a mismatch names the
missing method and the rebuild command instead of failing later inside SMP.
Requirement 26 of the brief is the test form of the same idea.

### 3.2 Why the test suite did not catch it

`tests/test_secret_at_rest.py:187` does call `store_from_bytearray`, so a stale
wheel fails the suite — but the suite is not run on the handset. Two structural
gaps remain:

* `tests/test_release_guard.py` asserts gated methods are **absent** from a
  production wheel. Nothing asserts required methods are **present**.
* `smp_engine_compat.py:176`, the engine the fixtures use, still calls
  `self._vault.store("secret", bytes(raw))` — the old pattern. Tests exercising
  SMP through the compat engine never touch the production vault call at all.

## 4. Secret paths in both clients

| Path | Client | Arms input capture? | Armed by |
|---|---|---|---|
| `/smp-secret` (no arg) → `_request_smp_secret` → `_secret_request` | XMPP | one line, hidden | **local command only** |
| `/smp-secret <s>`, `/smp <s>` | XMPP | no — inline, echoed | local |
| SMP1 with no secret | XMPP | no — prints advice, sends `SMP_ABORT(NOSECRET)` | remote |
| `_set_pending("trust", …)` → `_set_pending("smp_secret", …)` | **IRC** | **next chat line, NOT hidden** | **remote DAKE** |

### 4.1 INV-06 holds for XMPP and does not hold for IRC

`tests/test_no_remote_input_capture.py` walks the inbound call graph of
`otrv4plus_xmpp.py` only. `otrv4+.py` was never covered, and the same defect is
still live there:

```
process_dake3 (remote)                    otrv4+.py:12811
  └─ _handle_session_established          otrv4+.py:12861
       └─ _set_pending("trust", …)        otrv4+.py:12938
            └─ user types y
                 └─ _finish_trust         otrv4+.py:12963
                      └─ _set_pending("smp_secret", …)      otrv4+.py:12993
                           └─ handle_chat_message consumes the NEXT line
                                as the shared secret                13413
```

`EnhancedOTRv4IRCClient` is the production IRC client (`otrv4+.py:14328`). A
peer who completes a DAKE causes the local user's next typed line to be stored
as an SMP secret. Unlike the XMPP defect that INV-06 was written for, this one
does not even mask the input, so the line is echoed and lands in scrollback.

Nothing is transmitted — the value goes into the vault — so this is
input confusion, not exfiltration. It is the same property INV-06 defends and
it is currently unenforced on one of the two clients.

## 5. Wire protocol and state machine, as they stand

Unchanged by any of this, and confirmed before proposing UX work:

* Phases in Rust (`smp.rs:214`): `Idle, AwaitingMsg2, AwaitingMsg3,
  AwaitingMsg4, Verified, Failed, Aborted`. There is **no** state meaning
  "a peer asked and I have no secret" — the engine aborts.
* `check_secret_set()` is the only predicate distinguishing that case.
* `SMP_ABORT` carries an optional reason. `SMP_ABORT_NO_SECRET = b"NOSECRET"`
  already exists (`otrv4+.py:1125`) and is already treated as a diagnostic that
  chooses local wording and is never a security predicate. The initiator
  already prints "This is not a wrong-passphrase failure."
* The tie-break for simultaneous initiation is already implemented and
  deterministic: compare `local_fp` against `remote_fp`, higher yields the
  initiator role (`otrv4+.py:6700`).

So the distinction the brief asks to preserve exists; what is missing is a
local state that lets the responder *pause* instead of abort.

## 6. Baseline

Recorded before any change:

```
tests/test_smp_argon2_wire_v3.py  tests/test_smp_end_to_end.py
tests/test_smp_no_secret.py       tests/test_no_remote_input_capture.py
tests/test_secret_at_rest.py      tests/test_secret_never_echoes.py
tests/test_release_guard.py

120 passed, 3 skipped
```

Full suite at `c783967`: 2336 passed, 43 skipped, 1 xfailed. Rust: 101 passed.

## 7. What the audit says the work is

1. **Core API check.** The client declares the core methods it needs; a startup
   check names what is missing and how to fix it. Restoring `store()` as a
   fallback is rejected.
2. **A real state in the engine.** `SECRET_REQUIRED`, at the Rust/PyO3
   boundary so both clients see the same thing, with the received SMP1 held
   rather than discarded so it can be resumed rather than restarted.
3. **Consent before secret entry.** A remote message may move the local state
   to "awaiting consent"; only local input may move it to "awaiting secret".
   This is the boundary that makes the responder UX safe, and it is what
   `_secret_request` alone cannot express, because that flag consumes whatever
   line arrives next.
4. **IRC.** Remove the remotely-armed generic capture and extend INV-06's test
   to cover `otrv4+.py`.

> **Postscript (v10.23.2).** Item 4 shipped in v10.23.0 and did not work. The
> guided flow went into `OTRv4IRCClient.handle_command`; `EnhancedOTRv4IRCClient`
> — the only class the program instantiates — overrides `handle_command` and
> claims `smp` before delegating, so a user typing `/smp` got
> `Usage: /smp <command> [args]` and the masked prompt was never reached. The
> INV-06 coverage this item asked for *was* added and *did* pass, because it
> called `_smp_verify` on a stub rather than entering through the dispatcher.
>
> Two lessons, both about this audit's own method. First: a call-graph walk
> proves nothing bad is *reachable*; it does not prove the good path is. Both
> questions need asking, and only the first one was. Second: the audit named
> `EnhancedOTRv4IRCClient` as the production client in §4.1 and the fix still
> went into the base class — so naming the right class in prose is not the same
> as testing against it. `tests/test_irc_smp_command_routing.py` enters through
> the real `handle_command` on the real class, and asserts structurally that
> only one class claims the command.

---

## 8. What was built, and the two-handset plan

Written after the audit; the sections above are unchanged.

### 8.1 The shape of it

```
     /smp                                   SMP1 arrives, no passphrase
       │                                              │
  stored? ──yes──▶ verify                    engine HOLDS the message
       │                                     phase = SECRET_REQUIRED
       no                                              │
       │                                    AWAITING_LOCAL_CONSENT
       ▼                                              │
 AWAITING_SECRET  ◀────── y ──────────────────────────┤
  (hidden read)                                       │
       │                                              n / timeout
       ▼                                              ▼
    RUNNING                              SMP_ABORT(DECLINED), nothing stored
```

The left column is entered by a local command; the right by a peer's message.
They meet only at `y`, and that edge is a keypress.

### 8.2 The claims, and what backs each

| Claim | Backed by |
|---|---|
| A peer cannot arm the passphrase read | `test_no_remote_input_capture.py` (call graph), `test_smp_guided_flow.py::TestRemoteCannotCapture` |
| An ordinary message at the consent prompt stays an ordinary message | `test_an_ordinary_message_at_the_consent_prompt_is_just_a_message` |
| The held SMP1 is answered, not restarted | `test_a_full_run_completes_after_a_pause_for_the_passphrase` |
| A wrong passphrase is still a cryptographic failure | `test_a_wrong_passphrase_after_the_pause_is_still_a_failure` |
| An internal error is not reported as a wrong passphrase | `TestFailureClassification` |
| Nothing stores a passphrase on a cancel, decline or teardown | `TestCleanup`, `test_cancelling_stores_nothing` |
| The installed wheel has what the clients call | `TestTheCoreApiContract` |

### 8.3 First device run, 2026-09-04 — and what it found

Two handsets over I2P, both on v10.15.0. **Three defects, all in code the
v10.15.0 test suite covered on paper.** Fixed in v10.15.1; see CHANGELOG.

| What was run | Result |
|---|---|
| Provisioning, SAM tunnel, DAKE, fingerprint pin | **pass** |
| Initiator `/smp` with no stored passphrase → hidden prompt → SMP1 sent | **pass** — the prompt appeared and the passphrase was stored and used |
| Responder with no stored passphrase | **FAIL** — aborted with `NOSECRET` instead of prompting. `smp_guided_prompt` was never set to `True`, so the whole responder flow was unreachable |
| Initiator's report of that abort | **FAIL** — printed "your peer has not stored the passphrase yet… this is not a wrong-passphrase failure" and then "*** SMP FAILED — secrets did NOT match. Possible MITM. ***" |
| Both sides run `/smp` at once | **FAIL** — `SMP race-recovery: vault rebind failed`. Pre-existing; the recovery path has never worked |

The lesson for the tests, recorded because it is the reusable part: every
responder test in v10.15.0 called the client's own display method with a fake
engine. None of them let a real SMP1 reach a real session, which is the only
place all three defects lived. The replacements do, and each was checked by
reverting the fix and confirming the test fails.

### 8.3.1 Second device run, v10.15.1 — glare recovery confirmed

Same two handsets, both rebuilt. Session capture kept.

**Both sides ran `/smp` at once**, which is the case that failed yesterday
with `SMP race-recovery: vault rebind failed`. This time the log shows this
device sending SMP1, receiving Alice's SMP1, yielding the initiator role and
answering hers:

```
step 1/4 · Challenge sent - awaiting response
step 1/4 · Challenge received - computing response      ← yielded, took her SMP1
step 2/4 · Response computed - sending
step 4/4 · Final step - sending verdict
*** IDENTITY VERIFIED with alice@… - shared secret matched (SMP complete). ***
```

So defect 2 of v10.15.1 is **fixed on hardware**, not just in a test. The
deterministic tie-break did what §8.1 says it should.

Neither the initiator prompt nor the responder banner was exercised as a
*separate* case here, because both people typed `/smp`. The responder consent
banner still has not been seen on a device — see §8.4.

A voice call followed on the same verified session: 5½ minutes, two rekeys
(epoch 0→1→2), `drop=0 authfail=0 replay=0 nokey=0` throughout, mouth-to-ear
settling at ~725 ms. Recorded here only because it shares the session; the
voice numbers belong in VOICE_MEDIA_PATH.md.

### 8.3.2 Third device run, v10.15.1 — the responder flow, confirmed

Both handsets on v10.15.1, neither with a stored passphrase. Bob typed `/smp`;
Alice typed nothing. **This is the case the whole feature exists for, and it
had never once run.**

Alice's side, in order:

```
/smp                     → no encrypted session with bob@… Run /otr first.
[otr] handshake: received DAKE1 … DAKE3 → ENCRYPTED, fingerprint PINNED
[otr] receiving 1/2 fragments from bob@…
🔐 SMP · Your peer asked to verify this session. A shared passphrase is
         needed to answer.
════════════════════════════════════════════
🔐 SMP VERIFICATION REQUEST
   bob@… wants to verify this encrypted session using a passphrase you
   agreed in advance.
   Press  y  to enter that passphrase, or  n  to decline.
   Nothing you type now is sent to them, and typing an ordinary message
   here just sends an ordinary message.
════════════════════════════════════════════
y
[smp] Enter the passphrase you agreed with this contact.
[smp] Passphrase (hidden), or Enter to cancel:
[smp] Passphrase stored — answering your peer…
🔐 SMP step 2/4 · Passphrase accepted - answering the challenge…
[smp] Answered — verification in progress…
🔐 SMP step 4/4 · IDENTITY VERIFIED
```

Every link in the chain is visible there: the SMP1 arrived, the engine
**held** it rather than aborting, the banner was raised by a remote message,
the hidden read opened only after a local `y`, and — the point of holding —
step 2/4 says *answering the challenge*, not restarting one. The SMP1 Bob
sent before Alice had any passphrase is the SMP1 she answered.

Bob's side went 1/4 → 2/4 → 3/4 → 4/4 as a plain initiator with no glare, and
both ended VERIFIED.

Also confirmed incidentally: `/smp` before a session exists is refused with
"no encrypted session … Run /otr first" rather than arming anything.

**Status of §8.4's plan after three runs:** steps 1, 2, 3, 5, 6 and 11 have
now been observed. Steps 4 (an ordinary message typed at the banner), 7 (`n`
to decline), 8 (a deliberately wrong passphrase), 9 (letting the request
expire) and 10 (going offline with the banner open) have not.

### 8.4 Still not tested

Step 4 is the one that matters most and is still unrun: it is the security
property the design exists for, and a unit test can be wrong about it in a way
a phone would notice. The following is the plan; the rows marked **done** were
observed in §8.3.1 and §8.3.2.

| # | Step | Pass condition |
|---|---|---|
| 1 | Both phones to v10.15.0 **and** `pip install ./Rust` | `/smp` exists; no `[core]` warning at startup |
| 2 | Start the client with a deliberately stale core | startup names `store_from_bytearray` and the rebuild command, and does not crash |
| 3 | Alice has a passphrase, Bob does not. Alice `/smp` | Alice: "started"; Bob: the verification-request banner |
| 4 | Bob types an ordinary message at that banner | it is **sent to Alice as a message**; the banner is still there; nothing stored |
| 5 | Bob presses `y`, enters the same passphrase | both sides reach verified; voice becomes available |
| 6 | Reverse the roles exactly | identical behaviour |
| 7 | Repeat step 3, Bob presses `n` | Alice: "your peer declined … not a wrong-passphrase failure"; Bob: "no passphrase was requested, stored or sent" |
| 8 | Repeat step 3, Bob enters a **different** passphrase | both sides report verification failed — a real mismatch, reported as one |
| 9 | Repeat step 3, Bob leaves the banner for >3 minutes | the request expires; a later `y` does nothing |
| 10 | Repeat step 3, Bob goes offline while the banner is open | nothing stored; no prompt survives the session |
| 11 | Neither side has a passphrase; Alice `/smp` | Alice is prompted first, then Bob is asked |

Step 4 is the one that matters most: it is the property the design exists for,
and it is the only one a unit test can be wrong about in a way a phone would
notice.
