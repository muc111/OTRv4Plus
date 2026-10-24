"""`/tip` — relay a Monero address between two SMP-verified peers.

WHAT THIS IS
------------
An address exchange. You ask a verified peer for their Monero address, their
client sends the one they configured, and yours shows it as text and as a QR
code you can point a wallet at. Then you send the money from your own wallet,
by hand.

It is a strictly smaller thing than `otrv4plus_trade.py`: that one relays
multisig blobs through a state machine; this one relays a single string.
Neither touches a wallet, an RPC port or a key.

WHAT IT DOES NOT DO
-------------------
* No transaction is constructed, signed, broadcast or verified. `/tip` sends
  no money. The name is short for "ask where to tip you"; the transfer is
  something you do afterwards in your wallet, looking at the address.
* The address is **never validated**. A Monero address is 95 base58
  characters, and this module does not know that. It is user data, carried
  verbatim. Validating it would mean encoding an opinion about Monero's
  address format, which is the kind of opinion that goes stale at a hard fork
  and starts rejecting valid addresses.
* Nothing is checked about whether the address belongs to the peer. It is
  the string their client was configured with. What the OTRv4+ session gives
  you is that it came from the peer whose fingerprint you pinned and whose
  SMP secret you both know -- not that they own the address, which no
  protocol can tell you.

THE INTERACTIVE PROMPT IN THE BRIEF IS NOT IMPLEMENTED, ON PURPOSE
------------------------------------------------------------------
The specification asked that an inbound request from a peer with no address
configured should prompt the local user to type one, reading their next line.

That is the mechanism INV-06 forbids, and `tests/test_no_remote_input_capture.py`
exists because a version of it shipped once: `_apply_tofu` set
`_pending[peer] = "smp_secret"`, so a peer who completed a DAKE could make the
user's next keystrokes mean something they did not choose. The address itself
is public and not worth protecting, but the mechanism is the problem, not the
payload -- once a remote message can arm a capture of the next typed line, the
line it captures might be a passphrase, or a private message meant for someone
else, and here it would be *transmitted* rather than merely stored.

So an inbound request with no address configured is REPORTED and nothing more.
The user answers with an explicit command:

    /setxmr <address>     then      /tipreply

Two deliberate keystrokes, both locally initiated, neither of which a peer can
cause. The cost is one extra command; the alternative is reintroducing the
defect INV-06 was written for.

WHAT IS STORED, AND WHERE
-------------------------
Your own address is persisted (that is the point of `/setxmr`) as JSON at
mode 0600 in the client's state directory. Be clear-eyed about it: your
Monero address next to your OTR identity on the same disk links the two for
anyone who reads that disk. It is your own public address, so this is a
linkage risk rather than a theft risk, but if that linkage matters to you,
do not use `/setxmr` -- reply per-trade instead.

A peer's address is held **in memory only**, is never written anywhere, and
is dropped on disconnect and `/quit` alongside the scrollback purge (INV-24).
"""

import json
import os
import re
import tempfile
import time
from typing import Callable, Dict, Optional

#: TLV type, mirrored from `otrv4+.py`'s `OTRv4TLV.TIP`. Duplicated as a
#: constant rather than imported so this module has no import cycle with the
#: engine; `tests/test_tip_address_relay.py` asserts the two agree.
TIP_TLV_TYPE = 0x0020

#: Wire commands. Unknown commands are dropped, never guessed at.
CMD_REQUEST = "address_request"
CMD_RESPONSE = "address_response"

#: Caps. An address is ~95 base58 chars; the ceiling is generous enough for
#: an integrated address (106) or a future format, and small enough that a
#: hostile peer cannot make the terminal unusable with one TLV.
MAX_ADDRESS_LEN = 256
MAX_NOTE_LEN = 100
MAX_AMOUNT_LEN = 32
#: The whole JSON payload. One TLV, well under any fragmentation threshold.
MAX_PAYLOAD_BYTES = 2048

#: An amount is displayed and put in a `monero:` URI, so it has to be a plain
#: decimal number. Not a validation of what Monero accepts -- a bound on what
#: this module will put in a URI or print.
#:
#: `[0-9]`, NOT `\d`. Python's `\d` is Unicode-aware for `str` patterns, so
#: `\d` accepts Arabic-Indic "\u0661\u0662\u0663" and every other decimal
#: digit range -- which would then be concatenated into a URI and shown to
#: someone as the amount to send. Caught by a test, not by review.
_AMOUNT_RE = re.compile(r"^[0-9]{1,20}(\.[0-9]{1,12})?$")


class TipError(Exception):
    """A tip operation failed. Safe to display: names states and limits."""


def _clean(text: str, limit: int) -> str:
    """Strip control characters and cap the length.

    Everything here is peer-supplied and gets printed to a terminal, so
    escape sequences are an injection and go before anything reaches stdout.
    """
    out = []
    for ch in str(text):
        if ch in "\r\n\t":
            out.append(" ")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            continue
        else:
            out.append(ch)
    return "".join(out).strip()[:limit]


def normalise_amount(raw: str) -> str:
    """Return a plain decimal amount, or raise.

    Rejected rather than coerced: `1e9`, `0x10`, `inf`, `nan` and a leading
    `+` all parse as floats in Python and none of them belongs in a
    `monero:` URI or in a line a human reads to decide what to send.
    """
    amount = _clean(raw, MAX_AMOUNT_LEN)
    if not amount:
        raise TipError("usage: /tip <amount> [note]")
    if not _AMOUNT_RE.match(amount):
        raise TipError("amount must be a plain decimal number, e.g. 0.5 "
                       "(got %r)" % amount[:32])
    return amount


def monero_uri(address: str, amount: str = "") -> str:
    """The `monero:` URI a wallet scanner understands.

    Built by concatenation and nothing else. `urllib.parse.quote` would be
    the reflex, but the address is base58 and the amount has already been
    matched against `_AMOUNT_RE`, so both are URI-safe by construction --
    and importing urllib here would put a network-capable module one typo
    away from a file whose whole claim is that it has none.
    """
    uri = "monero:" + address
    if amount:
        uri += "?tx_amount=" + amount
    return uri


def render_qr(address: str, amount: str = "") -> Optional[str]:
    """An ASCII QR code for the address, or None if `segno` is not installed.

    Optional by design: `segno` is a nicety, and a missing nicety must not
    stop the address being shown. Anything the library raises is caught for
    the same reason -- a QR that fails to render is not a reason to withhold
    the text the user actually needs.
    """
    try:
        import segno
    except ImportError:
        return None
    try:
        # error="l" and compact=True together halve the height on screen.
        # A phone terminal is 40-50 columns tall and a 95-character address
        # makes a large symbol; at "m" and full height it does not fit, and
        # a QR you have to scroll is not scannable. Low error correction is
        # safe here for the same reason it is standard for URLs: a QR either
        # decodes correctly or fails to decode, and the address is printed
        # as text directly above it either way.
        code = segno.make(monero_uri(address, amount), error="l")
        import io
        buf = io.StringIO()
        code.terminal(out=buf, border=1, compact=True)
        return buf.getvalue()
    except Exception:
        return None


def format_address_block(peer: str, address: str, amount: str = "",
                         note: str = "") -> str:
    """The block shown when a peer's address arrives.

    Three ways to use it, because a wallet may support any one of them:

      1. **scan the QR** -- easiest, and it carries the amount;
      2. **copy the address** -- works when the wallet cannot scan;
      3. **copy the payment URI** -- keeps the amount when the wallet
         understands `monero:` URIs but you cannot scan.

    (3) was missing until v10.21.1. The QR encoded the URI and nothing showed
    it, so anyone whose wallet could not scan fell back to the bare address
    and **silently lost the amount** -- they would have had to be told it
    separately and type it in.

    ORDER MATTERS, and it is the reverse of what it was. The copyable text
    now comes AFTER the QR. A 95-character address makes a symbol about 22
    rows tall; with the address above it, the address scrolls off the top of
    a handset terminal and the last thing on screen is a caveat. What you
    want to select is what should still be visible.
    """
    lines = ["\U0001f510 [tip] %s's Monero address:" % peer]

    # The amount reaches the URI only if it is a plain decimal. A peer can
    # put anything in that field and it must not go into a string a wallet's
    # URI parser will read.
    uri_amount = amount if _AMOUNT_RE.match(amount or "") else ""
    qr = render_qr(address, uri_amount)
    if qr:
        lines.append("\U0001f4f8 scan this, or copy the text below:")
        lines.append(qr)
    else:
        lines.append("[tip] pip install segno for a scannable QR code")

    lines.append("\U0001f4ec address:")
    lines.append("   %s" % address)
    if uri_amount:
        # Only worth a line when it carries something the bare address does
        # not. `monero:<address>` with no parameters is just the address
        # again, in a form fewer wallets accept.
        lines.append("\U0001f517 payment URI (keeps the amount):")
        lines.append("   %s" % monero_uri(address, uri_amount))
    if amount:
        lines.append("\U0001f4b0 amount: %s XMR%s"
                     % (amount, "" if uri_amount else
                        "  (not a plain decimal — left out of the QR and URI)"))
    if note:
        lines.append("\U0001f4dd note: %s" % note)
    lines.append("[tip] this client sends nothing — pay from your own "
                 "wallet, and check the address before you do")
    return "\n".join(lines)


class TipManager:
    """Handles `/setxmr`, `/tip` and the inbound TLV.

    Dependencies injected, like the trade courier's, so a test can drive it
    with three callables and no client:

        send(peer, payload_bytes) -> bool    encrypt one TIP TLV to the peer
        notify(text)                         one line to the local user
        verified(peer) -> bool               the SMP gate
    """

    def __init__(self,
                 send: Callable[[str, bytes], bool],
                 notify: Callable[[str], None],
                 verified: Callable[[str], bool],
                 store_path: Optional[str] = None):
        self._send = send
        self._notify = notify
        self._verified = verified
        self._store_path = store_path
        self.address: Optional[str] = None
        #: peer -> {"address", "amount", "at"}. Memory only, never written.
        self.received: Dict[str, dict] = {}
        #: peer -> {"amount", "note", "at"} for requests we could not answer
        #: because no address is configured. What `/tipreply` acts on.
        self.pending_requests: Dict[str, dict] = {}
        self._load()

    # -- the SMP gate ---------------------------------------------------

    def _require_verified(self, peer: str) -> None:
        """Fail-closed, matching INV-12 and INV-26: a predicate that raises
        counts as unverified, because one that throws on failure as readily
        as on success could otherwise report a failed session as verified."""
        try:
            ok = bool(self._verified(peer))
        except Exception:
            ok = False
        if not ok:
            raise TipError(
                "%s is not SMP-verified. Run /smp with them first — an "
                "address from an unverified session is an address from "
                "whoever is in the middle." % peer)

    # -- local commands -------------------------------------------------

    def set_address(self, address: str) -> str:
        """`/setxmr <address>` — store your own address and persist it."""
        address = _clean(address, MAX_ADDRESS_LEN)
        if not address:
            raise TipError("usage: /setxmr <your monero address>")
        if " " in address:
            raise TipError("that has a space in it — paste the address alone")
        self.address = address
        self._save()
        return address

    def forget_address(self) -> None:
        """`/setxmr clear` — stop answering requests, and remove the file."""
        self.address = None
        self._save()

    def request(self, peer: str, amount: str, note: str = "") -> str:
        """`/tip <amount> [note]` — ask a verified peer where to send it."""
        self._require_verified(peer)
        amount = normalise_amount(amount)
        note = _clean(note, MAX_NOTE_LEN)
        payload = {"cmd": CMD_REQUEST, "amount": amount}
        if note:
            payload["note"] = note
        if not self._emit(peer, payload):
            raise TipError(
                "could not send — no encrypted session with %s. Run /otr "
                "first; a tip request is never sent in the clear." % peer)
        self._notify("\U0001f510 [tip] asked %s where to send %s XMR%s"
                     % (peer, amount, (" — " + note) if note else ""))
        return amount

    def reply(self, peer: str) -> None:
        """`/tipreply` — answer a request that arrived with no address set.

        This is the explicit local action that replaces the interactive
        prompt in the brief. See the module docstring: a peer must not be
        able to arm a capture of the user's next typed line.
        """
        self._require_verified(peer)
        pending = self.pending_requests.get(peer)
        if pending is None:
            raise TipError("no unanswered tip request from %s" % peer)
        if not self.address:
            raise TipError("no address configured — /setxmr <address> first")
        self._respond(peer, pending.get("amount", ""))
        self.pending_requests.pop(peer, None)

    def status(self) -> list:
        """`/tip` with no arguments."""
        lines = []
        if self.address:
            lines.append("\U0001f510 [tip] your address: %s" % self.address)
            lines.append("[tip] requests from verified peers are answered "
                         "automatically. /setxmr clear to stop.")
        else:
            lines.append("[tip] no address configured — /setxmr <address>")
        for peer, req in sorted(self.pending_requests.items()):
            lines.append("[tip] %s asked for %s XMR and is unanswered — "
                         "/tipreply to send yours"
                         % (peer, req.get("amount", "?")))
        for peer, got in sorted(self.received.items()):
            lines.append("[tip] have %s's address for %s XMR"
                         % (peer, got.get("amount", "?")))
        if not self.pending_requests and not self.received:
            lines.append("[tip] no requests outstanding")
        return lines

    def clear(self) -> int:
        """Forget every peer address and pending request. Returns the count.

        Your own address is NOT cleared: it is configuration and it is on
        disk. What goes is everything belonging to the session -- called on
        disconnect and /quit, like the scrollback purge (INV-24).
        """
        count = len(self.received) + len(self.pending_requests)
        self.received.clear()
        self.pending_requests.clear()
        return count

    # -- inbound --------------------------------------------------------

    def handle_tlv(self, peer: str, value: bytes) -> None:
        """One decrypted TIP TLV. Never raises: it is called from the
        engine's TLV router, and a feature must not break a session."""
        try:
            self._handle(peer, value)
        except TipError as exc:
            self._notify("[tip] request from %s rejected: %s" % (peer, exc))
        except Exception as exc:
            self._notify("[tip] message from %s failed: %s"
                         % (peer, type(exc).__name__))

    def _handle(self, peer: str, value: bytes) -> None:
        if len(value) > MAX_PAYLOAD_BYTES:
            raise TipError("payload is %d bytes, over the %d limit"
                           % (len(value), MAX_PAYLOAD_BYTES))
        try:
            payload = json.loads(value.decode("utf-8"))
        except Exception:
            raise TipError("payload is not valid JSON")
        if not isinstance(payload, dict):
            raise TipError("payload is not an object")

        # The gate goes here, before any branch: an unverified peer must not
        # reach the request handler OR the response handler. A response is
        # the more interesting of the two -- it is a string this client is
        # about to show the user as somewhere to send money.
        self._require_verified(peer)

        cmd = _clean(str(payload.get("cmd", "")), 32)
        if cmd == CMD_REQUEST:
            self._on_request(peer, payload)
        elif cmd == CMD_RESPONSE:
            self._on_response(peer, payload)
        # Any other cmd is dropped in silence, per the TLV forward-
        # compatibility rule: a peer running a newer client is not an error.

    def _on_request(self, peer: str, payload: dict) -> None:
        amount = _clean(str(payload.get("amount", "")), MAX_AMOUNT_LEN)
        note = _clean(str(payload.get("note", "")), MAX_NOTE_LEN)
        self._notify("\U0001f510 [tip] %s asked for your XMR address%s%s"
                     % (peer,
                        (" for %s XMR" % amount) if amount else "",
                        ("\n[tip]   note: " + note) if note else ""))
        if self.address:
            # Consent was given at /setxmr: configuring an address is the
            # standing instruction to answer verified peers with it. Nothing
            # else is auto-sent, and /setxmr clear withdraws it.
            self._respond(peer, amount)
            return
        self.pending_requests[peer] = {"amount": amount, "note": note,
                                       "at": time.time()}
        self._notify(
            "[tip] no address configured, so nothing was sent.\n"
            "[tip] /setxmr <address> then /tipreply — or ignore this.")

    def _on_response(self, peer: str, payload: dict) -> None:
        address = _clean(str(payload.get("address", "")), MAX_ADDRESS_LEN)
        if not address:
            raise TipError("response carried no address")
        amount = _clean(str(payload.get("amount", "")), MAX_AMOUNT_LEN)
        note = _clean(str(payload.get("note", "")), MAX_NOTE_LEN)
        self.received[peer] = {"address": address, "amount": amount,
                               "at": time.time()}
        self._notify(format_address_block(peer, address, amount, note))

    def _respond(self, peer: str, amount: str) -> None:
        payload = {"cmd": CMD_RESPONSE, "address": self.address}
        if amount:
            payload["amount"] = amount
        if not self._emit(peer, payload):
            self._notify("[tip] could not answer %s — no encrypted session. "
                         "Your address was NOT sent in the clear." % peer)
            return
        self._notify("✅ [tip] sent your address to %s" % peer)

    # -- plumbing -------------------------------------------------------

    def _emit(self, peer: str, payload: dict) -> bool:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise TipError("payload would be %d bytes, over the %d limit"
                           % (len(raw), MAX_PAYLOAD_BYTES))
        try:
            return bool(self._send(peer, raw))
        except Exception:
            return False

    def _load(self) -> None:
        if not self._store_path or not os.path.exists(self._store_path):
            return
        try:
            with open(self._store_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            addr = data.get("xmr_address")
            if isinstance(addr, str):
                self.address = _clean(addr, MAX_ADDRESS_LEN) or None
        except Exception:
            # A corrupt store means no configured address, not a dead
            # client: the whole feature is optional.
            self.address = None

    def _save(self) -> None:
        """Write the store 0600, atomically.

        0600 and an atomic replace for the same reasons as the trust
        database: your Monero address next to your OTR identity links the two
        for anyone who reads the disk, and a half-written file after a crash
        would silently disable the feature.
        """
        if not self._store_path:
            return
        directory = os.path.dirname(self._store_path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        except OSError:
            pass
        if self.address is None:
            try:
                os.unlink(self._store_path)
            except OSError:
                pass
            return
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".xmr-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"xmr_address": self.address}, fh)
            os.replace(tmp, self._store_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise TipError("could not save the address")


#: Printed once per session on first use, like the trade courier's.
DISCLAIMER = (
    "[tip] /tip exchanges Monero ADDRESSES over the encrypted channel.\n"
    "[tip] It sends no money, builds no transaction and verifies nothing:\n"
    "[tip] the address is a string relayed from your peer's client. Check\n"
    "[tip] it, then pay from your own wallet. Prefer a subaddress."
)
