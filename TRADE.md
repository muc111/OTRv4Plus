# Trading over OTRv4+ — the courier

**OTRv4+ is not a wallet and does not hold your funds.** It carries multisig
coordination blobs between two people who have verified each other, inside the
same encrypted channel that carries their chat. Everything to do with keys,
addresses, signing and money happens in your own Monero wallet, on your own
machine.

Read [MONERO_ESCROW_AUDIT.md](MONERO_ESCROW_AUDIT.md) for why it is built this
way. The short version: putting Monero's cryptography in the Rust core meant
a yanked crate, a FROST multisig that cannot interoperate with
`monero-wallet-cli`, an experimental feature that is off by default, and a
hard fork that removes CLSAG. The courier avoids all four because it has no
opinion about what it carries.

---

## What it does and does not do

| | |
|---|---|
| Moves blobs between two verified peers, encrypted | ✅ |
| Refuses to send anything if the OTR channel is down | ✅ |
| Refuses to act on an unverified or changed peer | ✅ |
| Keeps trade state in memory only, never on disk | ✅ |
| Holds keys, funds or a wallet | ❌ never |
| Checks that a multisig address is the right one | ❌ your wallet does |
| Checks that a payment arrived | ❌ your wallet does |
| Acts as arbitrator or takes part in a dispute | ❌ never |

**There is no arbitration service and no arbitrator key.** If you want 2-of-3,
bring your own third party and run a trade session with them the same way you
run one with your counterparty. This project will not hold one of three keys.

---

## Before your first trade

1. **Verify your counterparty with SMP.** Not optional and not skippable — the
   client refuses every trade command against an unverified peer, and re-checks
   on every message. A trade with an unverified peer is a trade with whoever is
   in the middle.

   ```
   /otr bob@example.i2p
   /smp                       # both sides, same passphrase, agreed out of band
   /smpstate                  # should say verified
   ```

2. **Turn on multisig in your wallet.** Monero's native multisig is
   experimental and disabled by default, and the flag
   [cannot be set over RPC](https://github.com/monero-project/monero/issues/9488):

   ```
   monero-wallet-cli --wallet-file trade-wallet
   [wallet]: set enable-multisig-experimental 1
   ```

3. **Read the warning that comes with it.** Monero multisig had a
   [2021 disclosure](https://www.getmonero.org/2021/12/06/vulnerability-multisig.html)
   covering both wallet creation and transaction signing, where the impact was
   funds stolen by one of the signing parties. Fixes shipped; the experimental
   label did not come off. Trade amounts you can afford to lose, with people
   you have reason to trust, until you have done this enough times to know the
   flow.

4. **Use stagenet first.** `monero-wallet-cli --stagenet`. Do the whole flow
   once with no money involved.

---

## The commands

| Command | What it does |
|---|---|
| `/trade` | list open trades and their state |
| `/trade init <terms>` | propose a trade to the current peer |
| `/trade accept` | agree to a proposal they sent |
| `/trade decline [reason]` | refuse a proposal |
| `/trade blob <base64>` | relay one blob from your wallet to them |
| `/trade confirm [note]` | tell them you consider your side complete |
| `/trade cancel [reason]` | end a trade in any state |

One trade per peer at a time. XMPP only — the IRC client has no trade support,
for the same reason it has no file transfer: 510-byte lines.

---

## A 2-of-2 trade, start to finish

Alice and Bob, already SMP-verified, each with `monero-wallet-cli` open.

### 1. Agree the terms

```
alice> /trade init 0.5 XMR for 120 EUR, SEPA, 2-of-2, 24h
[trade] proposed a3f19c02 to bob@example.i2p
[trade]   terms: 0.5 XMR for 120 EUR, SEPA, 2-of-2, 24h
[trade]   waiting for them to /trade accept
```

```
bob> (sees)
[trade] alice@example.i2p proposes trade a3f19c02
[trade]   terms: 0.5 XMR for 120 EUR, SEPA, 2-of-2, 24h
[trade]   their fingerprint: A1B2 C3D4 …
[trade] /trade accept  or  /trade decline [reason]

bob> /trade accept
```

Both sides hash the terms and compare. If the hashes differ the trade stops —
it does not try to reconcile, because the terms are the trade.

### 2. Build the multisig wallet

Each round is: run a command in your wallet, paste its output into
`/trade blob`, wait for theirs, paste theirs back into your wallet.

**Round 1 — prepare**

```
[wallet]: prepare_multisig
MultisigxV2R1...          <- copy this

alice> /trade blob MultisigxV2R1...
[trade] sent blob #1 to bob@example.i2p (412 bytes)
```

Bob does the same, and each pastes the other's blob into:

```
[wallet]: make_multisig 2 <their blob>
```

**Round 2 — exchange keys**

For 2-of-2, `exchange_multisig_keys` runs **once**. For 2-of-3 it runs
**twice** (the rule is `N - M + 1` rounds: 3 participants, threshold 2).

```
[wallet]: exchange_multisig_keys <their blob>
Multisig wallet has been successfully created. Current address: 5...
```

**Compare the address out loud.** Both wallets must print the *same* multisig
address. This is the one check the courier cannot do for you and the most
important one in the whole flow — read it to each other over the encrypted
chat, or over voice, and stop if they differ.

### 3. Fund and pay

Send the XMR to the multisig address. Wait for it to confirm (~20 minutes).
Watch for it in your own wallet — the courier does not and cannot see the
chain. Then the fiat leg happens by whatever method the terms said.

### 4. Release

```
[wallet]: export_multisig_info
<blob>                    -> /trade blob <blob>
[wallet]: import_multisig_info <their blob>
[wallet]: transfer <destination> <amount>
<partially signed blob>   -> /trade blob <blob>
```

The other side runs `sign_multisig <blob>` and then `submit_multisig`.

```
alice> /trade confirm sent, txid 8f2a...
bob>   /trade confirm received
```

Both confirming is a record of what two people said. It is not proof of
anything on the chain, and the client says so when it reports it.

### 5. Close

```
/trade cancel done
```

Or just disconnect — trade state is dropped on disconnect, `/quit` and
process exit, and never written to disk.

---

## Limits you will hit

**Blob size: 24 KiB.** Bigger blobs are refused with a clear message rather
than sent and then throttled halfway. This is a rate-limit constraint, not a
cryptographic one: the receiving client allows 20 inbound stanzas per 5-second
window, and a 24 KiB blob is about 8 of them. `export_multisig_info` on a
wallet with many outputs, or a large signed transaction set, can exceed this.
The fix is to route large blobs through the file-transfer engine, which
already solved this problem; that is not in this version.

**Speed.** A 2-of-3 setup is four synchronisation barriers between three
people. Over I2P, with 60–90 second cold tunnels, budget tens of minutes. This
is normal and not a fault.

**No resume.** A trade does not survive a restart. Resuming from a file would
mean trusting that file about who your counterparty was and how far you had
got, and there is no file.

**No verification, at all.** Worth repeating because it is the design: the
courier cannot tell you that an address is right, a payment landed, or a
signature is valid. Your wallet tells you. If a message says a blob arrived,
that means bytes arrived — nothing more.

---

## The wire protocol

Every message travels inside the established OTRv4+ session. There is no
plaintext fallback: if the channel is unavailable the message is dropped, not
downgraded.

```
?OTRv4-TRADE:<VERB>:<version>|<trade_id>|<seq>|<fields…>

VERB     INIT | ACCEPT | DECLINE | BLOB | CONFIRM | CANCEL
version  1
trade_id 32 hex chars, chosen by the proposer
seq      strictly increasing per sender, starts at 1
```

| Verb | Fields |
|---|---|
| `INIT` | `b64(terms)` `\|` `sha256(terms) hex` |
| `ACCEPT` | `sha256(terms) hex` — echoed, must match |
| `DECLINE` | `b64(reason)` |
| `BLOB` | `b64(blob)` — opaque, never parsed |
| `CONFIRM` | `b64(note)` |
| `CANCEL` | `b64(reason)` |

Rules a receiver applies, in this order: SMP verified → fingerprint unchanged
→ trade id matches → sequence strictly increasing → state permits the verb.
The order matters: checking the sequence before the trade id would let an
unrelated id burn the replay window. Unknown verbs and unknown versions are
consumed and dropped, never guessed at.

---

## Legal

This software provides encrypted transport for multisig coordination. It does
not hold or control funds, does not custody keys, does not verify transactions
and takes no part in disputes. All financial arrangements are between you and
your counterparty.

The project does not act as an arbitrator. If a trade needs a third party, the
participants choose and trust that person themselves.

Nothing here is legal advice. Rules on non-custodial P2P trading differ by
jurisdiction, and the arbitrator role in particular attracts scrutiny in some
of them. If you intend to trade at scale, or to be somebody's arbitrator, get
advice where you live.
