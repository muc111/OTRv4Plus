"""Encrypted courier for multisig coordination blobs.

WHAT THIS IS
------------
A relay. Two people who have verified each other with SMP agree to a trade,
then pass opaque blobs between their own Monero wallets through the OTRv4+
channel. This module moves those blobs and tracks whose turn it is. That is
all it does.

WHAT THIS IS NOT
----------------
It is not a wallet, and it must never become one.

* It never opens a wallet file, reads a seed, holds a spend key or a view
  key, derives an address, or signs anything.
* It never parses a blob. A blob arrives as base64, is checked for length and
  alphabet, and is handed to the user verbatim. Parsing is the first step
  toward interpreting, and interpreting a Monero structure is precisely what
  this design exists to avoid.
* It never verifies anything about a trade's Monero semantics. It cannot tell
  you that a multisig address was formed from the right keys, that a payment
  landed, or that a partial signature is well formed. Your wallet tells you
  that. This is a genuine limitation and it is the price of the client not
  becoming a wallet -- see MONERO_ESCROW_AUDIT.md §2.2, which states the
  counter-argument as well.

WHY IT IS BUILT THIS WAY
------------------------
`MONERO_ESCROW_AUDIT.md` looked at putting Monero's cryptography in the Rust
core and found four problems: `monero-serai` is yanked, `monero-oxide`'s
multisig is FROST and so cannot interoperate with `monero-wallet-cli`, native
multisig is experimental and off by default, and FCMP++ removes CLSAG. The
courier avoids all four, because it carries whatever format the wallets speak
and has no opinion about it. A hard fork is the wallets' problem.

It also reads the project's own invariant in its strongest form. INV-08 says
Python does not receive key material Rust can own instead; here there is no
key material at all, in Rust or in Python, because the keys never enter this
process. That is INV-25.

WHAT PROTECTS A TRADE
---------------------
Only what already protected the channel, reused rather than reinvented:

* **SMP verification**, checked on every message in both directions, not once
  at the start (INV-26). Fail-closed: an error determining SMP state counts
  as unverified, matching the voice gate's posture in INV-12.
* **Fingerprint binding.** The peer's fingerprint is recorded when the trade
  is created and re-checked on every message. A change aborts the trade and
  never re-pins. Trade identity is cryptographic, never the I2P destination
  -- destinations are `TRANSIENT` and change every session by design.
* **The OTRv4+ ratchet.** Every byte here travels inside the established
  session. There is no plaintext fallback and no separate transport.
* **Strictly increasing sequence numbers** per direction, so a replayed or
  reordered control message cannot re-drive the state machine. The ratchet
  already gives transport-level replay protection; the state machine does not
  delegate its own correctness to a lower layer.
* **Terms-hash echo.** The responder echoes a hash of the terms it read. A
  mismatch means the two sides are looking at different text, and the trade
  stops rather than reconciling silently.

NO ARBITRATION SERVICE
----------------------
This project does not act as an arbitrator and ships no arbitrator key. If
users want 2-of-3 they bring their own third party and run a trade session
with them the same as with each other. That is a deliberate decision by the
maintainer, on legal advice grounds: holding one of three keys is the part of
an escrow design most likely to be read as a financial activity. The client
has no code path that would let it hold such a key.

STATE IS IN MEMORY ONLY
-----------------------
Nothing here is written to disk, ever. `TradeManager.clear()` empties it on
disconnect, `/quit` and process exit, alongside the scrollback purge added in
v10.19.0 (INV-24). A trade does not survive a restart, and that is the
intended behaviour: resuming from persisted state would mean trusting a file
about who you were trading with and how far you had got.
"""

import base64
import hashlib
import re
import secrets
import time
from typing import Callable, Dict, List, Optional

#: Same shape as `?OTRv4-FILE:` and `?OTRv4-CALL:`, and for the same reason:
#: routed before anything renders it as chat, so a blob does not appear as a
#: wall of base64 in the peer's message window.
TRADE_PREFIX = "?OTRv4-TRADE:"

#: The control protocol version. Bumped when the field layout changes.
#: Unknown verbs and unknown versions are dropped, never guessed at.
TRADE_PROTOCOL_VERSION = 1

#: Largest blob accepted, in raw bytes before base64.
#:
#: This is a rate-limit constraint, not a cryptographic one, and the
#: arithmetic is worth stating because getting it wrong is what broke file
#: transfer twice. The receiver's limiter allows `_RATE_MAX` = 20 inbound
#: stanzas per 5 s window. A B-byte blob becomes ~1.37xB of base64, which
#: becomes an OTR frame of roughly 1.9xB after encryption and the frame's own
#: base64, which `send_otr_fragmented` splits at 6000 bytes per stanza:
#:
#:     stanzas ~= ceil(1.9 * B / 6000)
#:
#: At 24 KiB that is about 8 stanzas -- comfortably under 20, leaving room for
#: ordinary chat alongside. Refusing up front is deliberate: a blob that
#: half-arrives and is then throttled is worse than one that was never sent,
#: because the user cannot tell which happened.
#:
#: A wallet CAN emit more than this. `export_multisig_info` on a wallet with
#: many outputs, or a fully signed transaction set, can run to tens or
#: hundreds of KiB. Those do not fit, the user is told so plainly, and the fix
#: is to route large blobs through the file-transfer engine -- which already
#: solved this exact problem with `absorb_transfer_message`. That is
#: deliberately not in this first version.
MAX_BLOB_BYTES = 24 * 1024

#: Free-text caps. Terms are shown to a human and hashed; nothing branches on
#: them.
MAX_TERMS_LEN = 512
MAX_REASON_LEN = 200

#: A trade with no traffic for this long is stale and is dropped on the next
#: sweep. Multisig setup over I2P is slow -- four synchronisation barriers,
#: 60-90 s cold tunnels -- so this is hours, not minutes.
TRADE_IDLE_TIMEOUT_S = 6 * 3600.0

#: How long an unanswered proposal stays live.
PROPOSAL_TIMEOUT_S = 30 * 60.0

#: Strict base64, the alphabet and nothing else. Applied before decoding so a
#: hostile payload cannot reach the decoder with anything exotic.
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")

#: Trade states. There is at most one live trade per peer, which keeps
#: "which trade did you mean" out of the command surface entirely.
PROPOSED = "PROPOSED"      # we asked, they have not answered
OFFERED = "OFFERED"        # they asked, we have not answered
ACTIVE = "ACTIVE"          # both agreed; blobs may flow


class TradeError(Exception):
    """A trade operation failed. The message is safe to show: it names
    sizes, states and reasons, never payload content."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str, what: str, limit: int) -> bytes:
    """Decode strict base64 with a hard ceiling, or raise.

    The ceiling is checked on the ENCODED length first. Decoding a
    multi-megabyte field to find out it is too big is the allocation the
    attacker wanted.
    """
    text = text.strip()
    if len(text) > (limit * 4) // 3 + 8:
        raise TradeError("%s is too large (%d encoded bytes, limit %d)"
                         % (what, len(text), (limit * 4) // 3 + 8))
    if not _B64_RE.match(text):
        raise TradeError("%s is not valid base64" % what)
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except Exception:
        raise TradeError("%s is not valid base64" % what)
    if len(raw) > limit:
        raise TradeError("%s is %d bytes, over the %d byte limit"
                         % (what, len(raw), limit))
    return raw


def terms_hash(terms: str) -> str:
    """The hash both sides compare so they know they read the same text.

    SHA-256 over UTF-8, hex. Not a security boundary against a peer who can
    already write the terms -- it catches disagreement, truncation and
    encoding drift, which is what actually goes wrong between two clients on
    different platforms.
    """
    return hashlib.sha256(terms.encode("utf-8")).hexdigest()


def _clean_text(text: str, limit: int) -> str:
    """Strip control characters and cap the length.

    Terms and reasons come from the peer and are printed to a terminal.
    Escape sequences in a peer-supplied string are an injection, so the
    printable-ASCII-plus-unicode filter runs before anything reaches stdout.
    """
    out = []
    for ch in text:
        if ch in "\r\n\t":
            out.append(" ")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            continue
        else:
            out.append(ch)
    return "".join(out).strip()[:limit]


class TradeSession:
    """One live trade with one peer. In memory only, never serialised."""

    __slots__ = ("trade_id", "peer", "peer_fingerprint", "role", "terms",
                 "terms_digest", "state", "created", "last_activity",
                 "send_seq", "recv_seq", "blobs_sent", "blobs_received",
                 "confirmed_local", "confirmed_remote")

    def __init__(self, trade_id: str, peer: str, peer_fingerprint: str,
                 role: str, terms: str):
        self.trade_id = trade_id
        self.peer = peer
        self.peer_fingerprint = peer_fingerprint
        self.role = role                      # "proposer" | "responder"
        self.terms = terms
        self.terms_digest = terms_hash(terms)
        self.state = PROPOSED if role == "proposer" else OFFERED
        self.created = time.time()
        self.last_activity = self.created
        self.send_seq = 0
        self.recv_seq = 0
        self.blobs_sent = 0
        self.blobs_received = 0
        self.confirmed_local = False
        self.confirmed_remote = False

    def next_send_seq(self) -> int:
        self.send_seq += 1
        return self.send_seq

    def accept_recv_seq(self, seq: int) -> None:
        """Advance the receive counter, or refuse.

        Strictly increasing. A repeated or lower sequence is a replay or a
        reorder, and either way it must not re-drive the state machine: an
        ACCEPT replayed after a CANCEL would otherwise reopen a closed trade.
        """
        if seq <= self.recv_seq:
            raise TradeError("out-of-order message (seq %d, already at %d)"
                             % (seq, self.recv_seq))
        self.recv_seq = seq

    def touch(self) -> None:
        self.last_activity = time.time()

    def age_s(self) -> float:
        return time.time() - self.created

    def idle_s(self) -> float:
        return time.time() - self.last_activity

    def summary(self) -> str:
        return ("%s with %s — %s, %d blob(s) sent, %d received%s"
                % (self.trade_id[:8], self.peer, self.state,
                   self.blobs_sent, self.blobs_received,
                   ", both confirmed" if self.both_confirmed() else ""))

    def both_confirmed(self) -> bool:
        return self.confirmed_local and self.confirmed_remote


class TradeManager:
    """Routes trade control messages and holds trade state for this session.

    Dependencies are injected rather than reached for, so the manager can be
    driven by a test with three small callables and no client:

        send(peer, verb, payload) -> bool   put one control message on the wire
        notify(text)                        show one line to the local user
        verified(peer) -> bool              the SMP gate
        fingerprint(peer) -> str | None     the peer's current fingerprint
    """

    def __init__(self,
                 send: Callable[[str, str, str], bool],
                 notify: Callable[[str], None],
                 verified: Callable[[str], bool],
                 fingerprint: Callable[[str], Optional[str]]):
        self._send = send
        self._notify = notify
        self._verified = verified
        self._fingerprint = fingerprint
        self.trades: Dict[str, TradeSession] = {}

    # -- gates ----------------------------------------------------------

    def _require_verified(self, peer: str) -> None:
        """INV-26. Checked on every message, not once at the start.

        Fail-closed, matching INV-12's posture for voice: an exception while
        determining SMP state is not "probably fine", it is unverified. A
        predicate that raises on failure as readily as on success would
        otherwise report an actively failed session as verified.
        """
        try:
            ok = bool(self._verified(peer))
        except Exception:
            ok = False
        if not ok:
            raise TradeError(
                "%s is not SMP-verified. Run /smp with them first — a trade "
                "with an unverified peer is a trade with whoever is in the "
                "middle." % peer)

    def _require_same_fingerprint(self, trade: TradeSession) -> None:
        """The peer must still be the key the trade was opened with.

        Bound to the fingerprint rather than to the JID or the I2P
        destination: destinations are TRANSIENT and change every session, and
        a JID is a name anyone can present. If the fingerprint has changed
        mid-trade the trade is over — it is never re-pinned, matching INV-11.
        """
        try:
            current = self._fingerprint(trade.peer)
        except Exception:
            current = None
        if not current or current != trade.peer_fingerprint:
            self.trades.pop(trade.peer, None)
            raise TradeError(
                "the fingerprint for %s has changed since this trade opened. "
                "The trade is cancelled and will not be re-pinned. Verify "
                "who you are talking to before starting another."
                % trade.peer)

    def _live(self, peer: str, *, want: Optional[str] = None) -> TradeSession:
        trade = self.trades.get(peer)
        if trade is None:
            raise TradeError("no trade with %s" % peer)
        self._require_verified(peer)
        self._require_same_fingerprint(trade)
        if want is not None and trade.state != want:
            raise TradeError("trade with %s is %s, not %s"
                             % (peer, trade.state, want))
        return trade

    # -- local commands -------------------------------------------------

    def start(self, peer: str, terms: str) -> TradeSession:
        """`/trade init <terms>` — propose a trade to a verified peer."""
        self._require_verified(peer)
        if peer in self.trades:
            raise TradeError(
                "a trade with %s is already open (%s). /trade cancel first."
                % (peer, self.trades[peer].state))
        terms = _clean_text(terms, MAX_TERMS_LEN)
        if not terms:
            raise TradeError(
                "say what the trade is: /trade init 0.5 XMR for 120 EUR, "
                "SEPA, 2-of-2")
        fp = self._peer_fingerprint_or_raise(peer)
        trade = TradeSession(secrets.token_hex(16), peer, fp, "proposer", terms)
        self.trades[peer] = trade
        self._emit(trade, "INIT", "%s|%s"
                   % (_b64(terms.encode("utf-8")), trade.terms_digest))
        self._notify("[trade] proposed %s to %s\n"
                     "[trade]   terms: %s\n"
                     "[trade]   waiting for them to /trade accept"
                     % (trade.trade_id[:8], peer, terms))
        return trade

    def accept(self, peer: str) -> TradeSession:
        """`/trade accept` — agree to a proposal they sent."""
        trade = self._live(peer, want=OFFERED)
        trade.state = ACTIVE
        trade.touch()
        self._emit(trade, "ACCEPT", trade.terms_digest)
        self._notify("[trade] accepted %s with %s — blobs may now flow\n"
                     "[trade] send one with: /trade blob <base64 from your "
                     "wallet>" % (trade.trade_id[:8], peer))
        return trade

    def decline(self, peer: str, reason: str = "") -> None:
        """`/trade decline [reason]` — refuse a proposal."""
        trade = self._live(peer, want=OFFERED)
        reason = _clean_text(reason, MAX_REASON_LEN)
        self._emit(trade, "DECLINE", _b64(reason.encode("utf-8")))
        self.trades.pop(peer, None)
        self._notify("[trade] declined the proposal from %s" % peer)

    def cancel(self, peer: str, reason: str = "") -> None:
        """`/trade cancel [reason]` — end a trade in any state.

        Always removes the local trade, even if telling the peer failed.
        A trade the user has abandoned must not linger in a state where the
        next blob would be accepted.
        """
        trade = self.trades.get(peer)
        if trade is None:
            raise TradeError("no trade with %s" % peer)
        reason = _clean_text(reason, MAX_REASON_LEN)
        try:
            self._emit(trade, "CANCEL", _b64(reason.encode("utf-8")))
        except Exception:
            pass
        self.trades.pop(peer, None)
        self._notify("[trade] cancelled %s with %s"
                     % (trade.trade_id[:8], peer))

    def send_blob(self, peer: str, blob_b64: str) -> int:
        """`/trade blob <base64>` — relay one wallet blob. Returns its index.

        The blob is validated for base64 alphabet and size and then sent
        verbatim. It is NOT decoded into anything, NOT inspected, and NOT
        interpreted. What it means is between the two wallets.
        """
        trade = self._live(peer, want=ACTIVE)
        blob_b64 = "".join(blob_b64.split())
        if not blob_b64:
            raise TradeError("nothing to send")
        raw_len = len(_unb64(blob_b64, "blob", MAX_BLOB_BYTES))
        if raw_len == 0:
            raise TradeError("nothing to send")
        trade.blobs_sent += 1
        trade.touch()
        self._emit(trade, "BLOB", blob_b64)
        self._notify("[trade] sent blob #%d to %s (%d bytes) — their wallet "
                     "consumes it next" % (trade.blobs_sent, peer, raw_len))
        return trade.blobs_sent

    def confirm(self, peer: str, note: str = "") -> None:
        """`/trade confirm` — tell the peer you consider your side done.

        A statement by a human, relayed. The client has not checked anything
        and says so; both sides confirming is a record of what two people
        said, not a verification of what happened on the chain.
        """
        trade = self._live(peer, want=ACTIVE)
        note = _clean_text(note, MAX_REASON_LEN)
        trade.confirmed_local = True
        trade.touch()
        self._emit(trade, "CONFIRM", _b64(note.encode("utf-8")))
        self._notify("[trade] told %s you consider your side complete%s"
                     % (peer, (" — " + note) if note else ""))
        self._maybe_report_both_confirmed(trade)

    def status(self) -> List[str]:
        """`/trade` — one line per live trade, plus the standing caveat."""
        self.sweep()
        if not self.trades:
            return ["[trade] no trades open"]
        lines = ["[trade] %s" % t.summary()
                 for t in sorted(self.trades.values(),
                                 key=lambda t: t.created)]
        lines.append("[trade] this client relays blobs only — it has not "
                     "verified any address, payment or signature")
        return lines

    def sweep(self) -> int:
        """Drop stale trades. Returns how many went."""
        gone = []
        for peer, trade in list(self.trades.items()):
            expired = (trade.state in (PROPOSED, OFFERED)
                       and trade.age_s() > PROPOSAL_TIMEOUT_S)
            idle = trade.idle_s() > TRADE_IDLE_TIMEOUT_S
            if expired or idle:
                self.trades.pop(peer, None)
                gone.append((peer, trade, "unanswered" if expired else "idle"))
        for peer, trade, why in gone:
            self._notify("[trade] dropped %s with %s (%s)"
                         % (trade.trade_id[:8], peer, why))
        return len(gone)

    def clear(self) -> int:
        """Forget every trade. Returns how many there were.

        Called at the same boundaries as the scrollback purge — disconnect,
        /quit, process exit. Trades do not survive a restart by design: state
        restored from disk would mean trusting a file about who the
        counterparty was and how far the trade had got, and there is no file
        because nothing here is ever written to one.
        """
        count = len(self.trades)
        for trade in self.trades.values():
            trade.terms = ""
        self.trades.clear()
        return count

    # -- inbound --------------------------------------------------------

    def handle_control(self, peer: str, body: str) -> bool:
        """Route one decrypted control message. True if consumed.

        Consumed means "this was ours, do not render it as chat" — including
        the error paths. A malformed trade message must not fall through and
        appear as a wall of base64 in the message window.
        """
        if not isinstance(body, str) or not body.startswith(TRADE_PREFIX):
            return False
        remainder = body[len(TRADE_PREFIX):]
        verb, _, payload = remainder.partition(":")
        verb = verb.strip().upper()
        handlers = {
            "INIT": self._on_init,
            "ACCEPT": self._on_accept,
            "DECLINE": self._on_decline,
            "BLOB": self._on_blob,
            "CONFIRM": self._on_confirm,
            "CANCEL": self._on_cancel,
        }
        handler = handlers.get(verb)
        if handler is None:
            return True                       # consumed, unknown verb dropped
        try:
            version, trade_id, seq, rest = self._split_header(payload)
        except TradeError as exc:
            self._notify("[trade] malformed %s from %s: %s"
                         % (verb, peer, exc))
            return True
        if version != TRADE_PROTOCOL_VERSION:
            self._notify("[trade] ignoring %s from %s: protocol v%d, this "
                         "client speaks v%d" % (verb, peer, version,
                                                TRADE_PROTOCOL_VERSION))
            return True
        try:
            self._require_verified(peer)
            handler(peer, trade_id, seq, rest)
        except TradeError as exc:
            self._notify("[trade] %s from %s rejected: %s" % (verb, peer, exc))
        except Exception as exc:
            self._notify("[trade] %s from %s failed: %s"
                         % (verb, peer, type(exc).__name__))
        return True

    def _on_init(self, peer: str, trade_id: str, seq: int,
                 rest: List[str]) -> None:
        if len(rest) < 2:
            raise TradeError("INIT is missing fields")
        if peer in self.trades:
            raise TradeError("a trade with them is already open (%s)"
                             % self.trades[peer].state)
        terms = _clean_text(
            _unb64(rest[0], "terms", MAX_TERMS_LEN).decode("utf-8", "replace"),
            MAX_TERMS_LEN)
        claimed = rest[1].strip().lower()
        computed = terms_hash(terms)
        if claimed != computed:
            # Their hash does not cover the text we read. Either something
            # mangled it in transit or the two clients disagree about
            # encoding. Never reconcile silently: the terms are the trade.
            raise TradeError("terms hash does not match the terms sent")
        fp = self._peer_fingerprint_or_raise(peer)
        trade = TradeSession(trade_id, peer, fp, "responder", terms)
        trade.recv_seq = seq
        self.trades[peer] = trade
        self._notify(
            "[trade] %s proposes trade %s\n"
            "[trade]   terms: %s\n"
            "[trade]   their fingerprint: %s\n"
            "[trade] /trade accept  or  /trade decline [reason]\n"
            "[trade] this client relays blobs only — it verifies no address, "
            "payment or signature"
            % (peer, trade_id[:8], terms, fp))

    def _on_accept(self, peer: str, trade_id: str, seq: int,
                   rest: List[str]) -> None:
        trade = self._match(peer, trade_id, seq, want=PROPOSED)
        echoed = (rest[0].strip().lower() if rest else "")
        if echoed != trade.terms_digest:
            self.trades.pop(peer, None)
            raise TradeError(
                "they accepted different terms from the ones sent. The trade "
                "is cancelled; agree the terms again before retrying.")
        trade.state = ACTIVE
        trade.touch()
        self._notify("[trade] %s accepted %s — blobs may now flow\n"
                     "[trade] send one with: /trade blob <base64 from your "
                     "wallet>" % (peer, trade_id[:8]))

    def _on_decline(self, peer: str, trade_id: str, seq: int,
                    rest: List[str]) -> None:
        trade = self._match(peer, trade_id, seq, want=PROPOSED)
        reason = self._reason(rest)
        self.trades.pop(peer, None)
        self._notify("[trade] %s declined %s%s"
                     % (peer, trade_id[:8], (" — " + reason) if reason else ""))

    def _on_blob(self, peer: str, trade_id: str, seq: int,
                 rest: List[str]) -> None:
        trade = self._match(peer, trade_id, seq, want=ACTIVE)
        if not rest:
            raise TradeError("BLOB is empty")
        blob_b64 = "".join(rest[0].split())
        raw_len = len(_unb64(blob_b64, "blob", MAX_BLOB_BYTES))
        if raw_len == 0:
            raise TradeError("BLOB is empty")
        trade.blobs_received += 1
        trade.touch()
        # Printed verbatim between markers so it can be selected and pasted
        # into a wallet. It is NOT decoded, NOT parsed, and nothing about its
        # content changes what this client does next.
        self._notify(
            "[trade] blob #%d from %s (%d bytes) for trade %s\n"
            "[trade] paste this into your Monero wallet:\n"
            "----- BEGIN OTRv4+ TRADE BLOB -----\n"
            "%s\n"
            "----- END OTRv4+ TRADE BLOB -----\n"
            "[trade] this client has not checked what it means"
            % (trade.blobs_received, peer, raw_len, trade_id[:8], blob_b64))

    def _on_confirm(self, peer: str, trade_id: str, seq: int,
                    rest: List[str]) -> None:
        trade = self._match(peer, trade_id, seq, want=ACTIVE)
        note = self._reason(rest)
        trade.confirmed_remote = True
        trade.touch()
        self._notify("[trade] %s says their side is complete%s"
                     % (peer, (" — " + note) if note else ""))
        self._maybe_report_both_confirmed(trade)

    def _on_cancel(self, peer: str, trade_id: str, seq: int,
                   rest: List[str]) -> None:
        trade = self._match(peer, trade_id, seq)
        reason = self._reason(rest)
        self.trades.pop(peer, None)
        self._notify("[trade] %s cancelled %s%s"
                     % (peer, trade_id[:8], (" — " + reason) if reason else ""))

    # -- plumbing -------------------------------------------------------

    def _split_header(self, payload: str):
        """`version|trade_id|seq|rest…` -> (int, str, int, [str])."""
        parts = payload.split("|")
        if len(parts) < 3:
            raise TradeError("truncated header")
        try:
            version = int(parts[0])
            seq = int(parts[2])
        except ValueError:
            raise TradeError("non-numeric version or sequence")
        trade_id = parts[1].strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", trade_id):
            raise TradeError("bad trade id")
        if seq < 1:
            raise TradeError("bad sequence number")
        return version, trade_id, seq, parts[3:]

    def _match(self, peer: str, trade_id: str, seq: int,
               *, want: Optional[str] = None) -> TradeSession:
        """Find the trade this message belongs to, or refuse it.

        Order matters: verify, then re-check the fingerprint, then check the
        trade id, then the sequence, then the state. Advancing the sequence
        before the id matched would let an unrelated id burn our replay
        window.
        """
        trade = self._live(peer, want=want)
        if trade.trade_id != trade_id:
            raise TradeError("trade id does not match the open trade")
        trade.accept_recv_seq(seq)
        return trade

    def _reason(self, rest: List[str]) -> str:
        if not rest:
            return ""
        try:
            raw = _unb64(rest[0], "reason", MAX_REASON_LEN)
        except TradeError:
            return ""
        return _clean_text(raw.decode("utf-8", "replace"), MAX_REASON_LEN)

    def _peer_fingerprint_or_raise(self, peer: str) -> str:
        try:
            fp = self._fingerprint(peer)
        except Exception:
            fp = None
        if not fp:
            raise TradeError(
                "no fingerprint for %s — there is no established session to "
                "bind this trade to" % peer)
        return str(fp)

    def _emit(self, trade: TradeSession, verb: str, tail: str) -> None:
        payload = "%d|%s|%d|%s" % (TRADE_PROTOCOL_VERSION, trade.trade_id,
                                   trade.next_send_seq(), tail)
        if not self._send(trade.peer, verb, payload):
            raise TradeError(
                "could not send %s — the encrypted channel is unavailable. "
                "Trade messages are never sent in the clear." % verb)

    def _maybe_report_both_confirmed(self, trade: TradeSession) -> None:
        if trade.both_confirmed():
            self._notify(
                "[trade] both sides have confirmed %s.\n"
                "[trade] that is a record of what two people said, not proof "
                "of anything on the chain — check your own wallet."
                % trade.trade_id[:8])


#: Shown once per session the first time a trade command is used. Not a
#: legal opinion and not a substitute for one; it states plainly what the
#: software does so nobody has to infer it from the feature's name.
DISCLAIMER = (
    "[trade] OTRv4+ provides encrypted transport for multisig coordination.\n"
    "[trade] It holds no funds, no keys and no wallet, verifies nothing about\n"
    "[trade] a transaction, and takes no part in disputes. All financial\n"
    "[trade] arrangements are between you and your counterparty. If you want\n"
    "[trade] 2-of-3, bring your own third party — this project does not act\n"
    "[trade] as an arbitrator and ships no arbitrator key."
)
