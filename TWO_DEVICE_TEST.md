# Two-handset test plan — v10.24.0

The automated suite cannot prove any of this. It drives the real Rust SMP
engine and the real command dispatcher, but it does not drive a terminal, a
Termux raw-mode read, an I2P tunnel, or two people. Everything below has to be
seen on the devices.

**Status: not yet run.** v10.24.0 is unverified on hardware.

---

## What the suite genuinely does prove

Worth stating so the gap is the real one and not a bigger one:

- The exact `ValueError` is reproduced against `otrv4_core.RustSMP` and no
  longer occurs. `tests/test_irc_smp_responder_resume.py` holds a real SMP1,
  consents, enters a passphrase through `handle_chat_message`, and drives the
  resulting SMP2 through the remaining PQC rounds until both engines report
  verified.
- Entry is at the production handler, not a helper. The v10.23.0 lesson.
- The reconnect path keeps sessions and drops fragments, prompts and consent
  questions.
- Each DAKE stage prints `OK` only from the result of its own operation.

## What it cannot prove

- That the hidden read works in Termux raw mode on a physical keyboard.
- That the passphrase is invisible on a real screen while being typed.
- That an I2P SAM tunnel dropping produces the disconnect the reconnect path
  expects, rather than a hang.
- That an OTR session resumed after a real tunnel rebuild can still carry
  messages both ways.
- Timing. A 5849-byte SMP1 is ~18 fragments over I2P.

---

## 1. Guided SMP, both directions

The run that failed on v10.23.2 at the last step.

**Device A**

```
/otr <B-nick>
```

Expect, in B's tab:

```
🔐 DAKE 1
🟢 OK
   waiting for their answer…
🔐 DAKE 2
🟢 OK
🔐 DAKE 3
🟢 OK
🟢 OTR SESSION READY
   DAKE 🦀 Rust | Ratchet 🦀 Rust | SMP 🐍 Python
🔑 First contact — fingerprint pinned for this nick.
A change will be reported. Pinning is not verification: run /smp …
```

Then:

```
/smp
```

Expect a hidden prompt. **Type the agreed passphrase and watch the screen** —
nothing should echo, not even asterisk-per-keystroke drift.

**Device B**

Expect the consent prompt, then `y`, then the hidden read, then:

```
🔐 Passphrase stored — verifying…
```

and **not** `Could not answer the held request`.

**Both** should end at SMP VERIFIED with the panel badge going blue (🔵).

### Check while you are there

- [ ] Nothing echoes during either hidden read.
- [ ] The passphrase is not in the scrollback afterwards.
- [ ] `/smpstate` on both sides agrees.
- [ ] Before consenting on B, type an ordinary sentence at the consent prompt.
      It must be **sent as a message**, not swallowed as a passphrase.
      (INV-06 — the property the whole two-step design exists for.)

### If it fails

The failure line now names the engine's own reason. Report that sentence
verbatim; `ValueError` alone is what cost the last session.

---

## 2. Wrong passphrase

Same flow, deliberately different secrets.

- [ ] Both sides reach a **verification failure**, not a Python error.
- [ ] Neither side shows VERIFIED.
- [ ] `/smp` can be run again afterwards without a restart.

---

## 3. Cancel and decline

- [ ] `n` at the consent prompt: A is told, B stores nothing, no prompt opens.
- [ ] Enter at the hidden prompt: nothing stored, nothing sent, mask off, and
      the next line typed is an ordinary message.
- [ ] After either, `/smp` still works.

---

## 4. The reconnect — the second reported failure

With an SMP-verified session live and a few messages exchanged, kill the I2P
SAM tunnel on one device (stop the router, or drop the tunnel).

```
🔄 Reconnecting in 30s (attempt 1)…
```

After it comes back, expect:

```
🔐 N OTR session(s) kept through the reconnect — identity keys and pinned
   fingerprints unchanged.
🔐 Transport reconnected. This session continues — same keys, same
   fingerprint, nothing re-negotiated.
🔐 Anything sent while the connection was down did not arrive and is not
   re-sent.
```

### Then check, in order

- [ ] `/fingerprint` — **your own fingerprint is unchanged.** A reconnect must
      not look like a new person.
- [ ] The peer's pinned fingerprint is unchanged and **no first-contact
      message appears again.**
- [ ] The panel still shows 🔵 (SMP verified), not 🔴.
- [ ] **Send a message each way.** This is the real test: the ratchet either
      survived or it did not. If they decrypt, the fix works.
- [ ] No `/quit` and restart was needed. That was the whole bug.
- [ ] The scrollback from before the drop is gone (INV-24 — deliberately
      still true; the keys survive, the conversation on screen does not).

### And the harder variants

- [ ] Drop the tunnel **while a hidden passphrase prompt is open.** The prompt
      must be cancelled, the mask lifted, and the next line typed after the
      reconnect must be an ordinary message.
- [ ] Drop it **mid-SMP.** Expect the "part-way through" notice naming that
      peer. Then `/smp abort` and `/smp` should recover without a restart.
- [ ] Drop it **mid-fragment**, during a DAKE or an SMP1. Nothing should
      reassemble across the boundary — no corrupt-message errors afterwards.
- [ ] Drop **both** devices at once.

---

## 5. Ordinary use after all that

- [ ] Encrypted chat both ways.
- [ ] `/tabs`, `/switch`, `/clear` behave.
- [ ] `/switch` to the tab you are already on still redraws (v10.23.1), and an
      inbound message does not reprint the tab.
- [ ] `/quit` reports the ratchets zeroized.

---

## What is expected to be imperfect

- **Nick collision on reconnect.** If the server still holds the old nick, the
  client renames and reclaims (v10.19.0). During that window the peer sees a
  different nick. The session is keyed by nick, so a peer who reconnects under
  a *different* nick will not match an existing session — a new DAKE is
  correct there and is what will happen.
- **A nick taken by someone else.** The preserved session cannot be hijacked:
  its keys are the ones from the DAKE, so a squatter's messages will not
  decrypt and ours are ciphertext they cannot read. It will look like a broken
  session rather than a leak. Report it if seen; it needs a clearer message.
- **Cold I2P tunnels.** 60–90s. A DAKE that takes a minute is normal.

---

## Reporting

For anything unexpected, the useful things are: the exact line on screen, both
devices' state at that moment, and whether a restart was needed. **Never paste
a passphrase** — if a line looks like it might contain one, that is itself the
bug worth reporting.
