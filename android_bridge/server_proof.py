# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Why the app refused a server: which check, at which step, and nothing by
which the server or the account could be recognised.

`xmlguard` and `sasl_hardening` end a connection when the far end sends XML
this app will not parse, or does not prove it holds the account's keys. The
person at the screen then reads "the server did not prove it knows this
account". This module is what makes that sentence something to act on: a
record of each refusal, held in memory for the diagnostic report and quoted
in one line on the screen.

WHAT A RECORD MAY HOLD. Names from fixed lists, lengths, counts and yes/no
answers. Never a value the server sent or the app derived: no nonce, salt,
proof, signature, key, password, address or account name. That is enforced
here and not asked of the callers: every fact has a validator in `FACTS`, a
fact without one is dropped, and a value its validator does not accept is
recorded as `?`. A caller that hands over a secret by mistake records a
question mark (tests/test_server_proof.py tries it).

Nothing is written to disk. The newest `KEEP` refusals are held until the
process ends or `clear()` is called.
"""
from __future__ import annotations

import re
import textwrap
import threading
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional

#: How many refusals are kept: the last attempt and the few before it.
KEEP = 8
UNKNOWN = "?"

#: The SASL mechanism names a record may carry. A fixed list because the
#: name comes from the server: any token accepted here would be a place for
#: a server to write its own text into a report, or for a caller to leave a
#: secret.
MECHANISMS = frozenset({
    "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS",
    "SCRAM-SHA-512", "SCRAM-SHA-512-PLUS", "SCRAM-SHA3-512",
    "SCRAM-SHA3-512-PLUS", "PLAIN", "LOGIN", "EXTERNAL", "ANONYMOUS",
    "DIGEST-MD5", "CRAM-MD5", "GSSAPI", "GS2-KRB5", "NTLM", "OAUTHBEARER",
    "X-OAUTH2", "X-MESSENGER-OAUTH2", "X-FACEBOOK-PLATFORM",
    "HT-SHA-256-ENDP", "HT-SHA-256-EXPR", "HT-SHA-256-UNIQ",
    "HT-SHA-256-NONE",
})

#: The route kinds of android_bridge/route.py, for the same reason.
ROUTES = frozenset({"i2p_sam", "tor", "clearnet_tls"})


# ── what a fact may look like ───────────────────────────────────────────────

def _matching(pattern: str) -> Callable[[Any], Any]:
    compiled = re.compile(pattern)

    def check(value: Any) -> str:
        text = value if isinstance(value, str) else UNKNOWN
        return text if compiled.fullmatch(text) else UNKNOWN
    return check


def _one_of(allowed) -> Callable[[Any], Any]:
    def check(value: Any) -> str:
        return value if isinstance(value, str) and value in allowed else UNKNOWN
    return check


def _count(limit: int) -> Callable[[Any], Any]:
    """A whole number from 0 to `limit`. True and False are not counts."""
    def check(value: Any):
        if isinstance(value, bool) or not isinstance(value, int):
            return UNKNOWN
        return value if 0 <= value <= limit else UNKNOWN
    return check


def _seconds(value: Any):
    """Elapsed time to the millisecond, up to a day."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return UNKNOWN
    if not 0 <= value <= 86400:
        return UNKNOWN
    return round(float(value), 3)


def _yes_no(value: Any) -> str:
    if value is True or value == "yes":
        return "yes"
    if value is False or value == "no":
        return "no"
    return UNKNOWN


def _mechanisms(value: Any) -> str:
    """What a server offered: the names this module knows, sorted, and how
    many others. A string is refused: it would be free text in one piece."""
    if not isinstance(value, (list, tuple, set, frozenset)):
        return UNKNOWN
    names = [name for name in value if isinstance(name, str)]
    known = sorted(set(name for name in names if name in MECHANISMS))
    other = len(value) - len([name for name in names if name in MECHANISMS])
    text = ", ".join(known)
    if other > 0:
        text = (text + " " if text else "") + "+%d other" % other
    return text or "none"


#: fact -> its validator. This is the whole vocabulary of a record.
FACTS: Dict[str, Callable[[Any], Any]] = {
    # From the transport, which knows what was being attempted.
    "phase": _one_of(("sign-in", "registration", "probe")),
    "route": _one_of(ROUTES),
    "certificate_checked": _yes_no,
    "progress": _matching(r"[a-z_]{1,40}"),
    # From sasl_hardening: the shape of the exchange, never its content.
    "mechanism": _one_of(MECHANISMS),
    "offered": _mechanisms,
    "step": _count(3),
    "proof_sent": _yes_no,
    "channel_binding": _yes_no,
    # `r:59 s:24 i:5`: each attribute's letter and the LENGTH of its value.
    "server_fields": _matching(
        r"empty|unreadable:\d{1,8}|[A-Za-z]:\d{1,8}( [A-Za-z]:\d{1,8}){0,15}"),
    "iterations": _matching(r"\d{1,12}|over 12 digits|not a number"),
    "salt_bytes": _count(65536),
    "nonce_continues_ours": _yes_no,
    # From xmlguard: where the stream was.
    "tls": _matching(r"none|unknown|TLSv1(\.[0-3])?|SSLv[23]"),
    "stream": _count(100000),
    "stream_bytes": _count(10 ** 12),
    "stream_stanzas": _count(10 ** 9),
    "open_stanza_bytes": _count(10 ** 12),
    "parser_state": _matching(r"text|comment|cdata|instruction"),
    "since_connect_s": _seconds,
    "since_stream_s": _seconds,
}

#: reason -> (which check, what it means). Written for the person reading a
#: report, who was not there.
REASONS: Dict[str, tuple] = {
    "success_before_challenge": ("sasl", (
        "The server answered the app's first sign-in message with 'signed "
        "in', without sending its challenge. It never showed that it holds "
        "this account's keys.")),
    "success_without_signature": ("sasl", (
        "The server's 'signed in' carried no signature, so nothing showed "
        "that it holds this account's keys.")),
    "signature_mismatch": ("sasl", (
        "The server's signature did not verify. Whoever answered does not "
        "hold the keys the real server stores for this account.")),
    "success_malformed": ("sasl", (
        "The server's last sign-in message could not be read.")),
    "iteration_count": ("sasl", (
        "The server named a PBKDF2 iteration count outside the range the "
        "app accepts. Too low makes the proof the app sends cheap to "
        "brute-force; too high would stall the app.")),
    "nonce_mismatch": ("sasl", (
        "The server's challenge did not continue the nonce the app had just "
        "sent: it belongs to some other exchange.")),
    "reserved_attribute": ("sasl", (
        "The server's challenge carried the reserved 'm' attribute, which a "
        "client has to refuse (RFC 5802).")),
    "challenge_malformed": ("sasl", (
        "The server's challenge could not be read: a field was missing or "
        "not in the form SCRAM defines.")),
    "declaration": ("xml", (
        "The stream contained an XML declaration (DOCTYPE, ENTITY or the "
        "like). XMPP forbids them, and the app closes before its parser "
        "reads one.")),
    "nul_byte": ("xml", (
        "The stream contained a zero byte, which UTF-8 XMPP never does "
        "(UTF-16 and UTF-32 do).")),
    "stanza_too_large": ("xml", (
        "One stanza grew past the size limit without ending.")),
}

#: What the server's operator can do, for the one refusal a server's own
#: setting causes. Measured 2026-11-15 with this client: a Prosody whose
#: `default_iteration_count` is outside the range gets exactly this refusal
#: for accounts whose password was set under it (0.12.4 below and above the
#: range; 13.0.7 above it, since 13 enforces the lower bound itself), and
#: tests/test_real_prosody.py repeats it on whichever Prosody is installed.
#: No other refusal was produced by any setting tried: the rest mean the far
#: end did not behave as an XMPP server does.
OPERATOR_REMEDY: Dict[str, str] = {
    "iteration_count": (
        "A server set up outside that range does this. Its operator can "
        "correct the setting (on Prosody: default_iteration_count) and must "
        "then set this account's password again, because the count is "
        "stored with each password."),
}

_STEPS = {
    0: "0 of 3: nothing sent yet",
    1: "1 of 3: first message sent, no challenge received",
    2: "2 of 3: the server's challenge received",
    3: "3 of 3: finished",
}

PROOF_SENT = ("By then the app had sent its sign-in proof. That is not the "
              "password, but whoever holds it can test guesses against it "
              "offline.")

_lock = threading.Lock()
_recent: Deque[Dict[str, Any]] = deque(maxlen=KEEP)
_passed: Dict[str, int] = {"streams_guarded": 0, "proofs_verified": 0}


# ── recording ───────────────────────────────────────────────────────────────

def _clean(facts: Dict[str, Any]) -> Dict[str, Any]:
    kept = {}
    for key, value in facts.items():
        check = FACTS.get(key)
        if check is None or value is None:
            continue                 # not a fact this module knows: dropped
        try:
            kept[key] = check(value)
        except Exception:
            kept[key] = UNKNOWN
    return kept


def note(check: str, reason: str, **facts: Any) -> Dict[str, Any]:
    """Record one refusal. Never raises; returns the record."""
    record = {
        "at": time.time(),
        "clock": time.monotonic(),
        "check": check if check in ("sasl", "xml") else UNKNOWN,
        "reason": reason if re.fullmatch(r"[a-z_]{1,40}", str(reason))
        else UNKNOWN,
        "facts": _clean(facts),
    }
    with _lock:
        _recent.append(record)
    return record


def annotate_last(within: float = 15.0, **facts: Any) -> Optional[Dict[str, Any]]:
    """Add facts to the newest refusal if it is recent: the transport knows
    the route and the phase, the guard that refused does not."""
    with _lock:
        if not _recent:
            return None
        record = _recent[-1]
        if time.monotonic() - record["clock"] > within:
            return None
        for key, value in _clean(facts).items():
            record["facts"].setdefault(key, value)
        return record


def passed(what: str) -> None:
    """Count a check in the path: `streams_guarded` (an XML stream opened
    under the guard), `proofs_verified` (a server signature that held)."""
    with _lock:
        if what in _passed:
            _passed[what] += 1


def recent() -> List[Dict[str, Any]]:
    with _lock:
        return [dict(r, facts=dict(r["facts"])) for r in _recent]


def last() -> Optional[Dict[str, Any]]:
    items = recent()
    return items[-1] if items else None


def clear() -> None:
    with _lock:
        _recent.clear()
        for key in _passed:
            _passed[key] = 0


# ── saying it ───────────────────────────────────────────────────────────────

def explain(reason: str) -> str:
    entry = REASONS.get(reason)
    return entry[1] if entry else "The app refused the server (%s)." % reason


def _bounds() -> str:
    try:
        from . import sasl_hardening
        return "%d..%d" % (sasl_hardening.MIN_ITERATIONS,
                           sasl_hardening.MAX_ITERATIONS)
    except Exception:
        return UNKNOWN


def operator_sentence(record: Optional[Dict[str, Any]]) -> str:
    """For the screen, where a server's own setting can be the cause: what
    the server asked for, what the app accepts, and who can change it. Empty
    for every other refusal."""
    if not record or record["reason"] not in OPERATOR_REMEDY:
        return ""
    asked = str(record["facts"].get("iterations", ""))
    accepted = _bounds().replace("..", " to ")
    if asked.isdigit():
        first = ("The server asked for %s rounds of password hashing; this "
                 "app accepts %s." % (asked, accepted))
    else:
        first = ("The server asked for a number of password-hashing rounds "
                 "this app does not accept (%s)." % accepted)
    return first + " " + OPERATOR_REMEDY[record["reason"]]


def guards_line() -> str:
    """Which guards are in force and what they have passed this session."""
    try:
        from . import sasl_hardening
        status = sasl_hardening.status()
        active = sum(1 for on in status.values() if on)
        if not sasl_hardening.applied():
            # Nothing is patched until the first client is built; that is
            # not a fix that failed to take.
            scram = "fixes not applied yet (no connection made this session)"
        else:
            scram = "%d of %d fixes active" % (active, len(status))
            missing = sorted(name for name, on in status.items() if not on)
            if missing:
                scram += " (NOT active: %s)" % ", ".join(missing)
            if not sasl_hardening.describes_challenges():
                # Another slixmpp: the fixes hold, the reasons are coarser.
                scram += " (challenge step not hooked)"
    except Exception:
        scram = "state unknown"
    with _lock:
        counts = dict(_passed)
    return ("streams guarded %d, server proofs verified %d; scram %s, "
            "iterations accepted %s"
            % (counts["streams_guarded"], counts["proofs_verified"],
               scram, _bounds()))


def _where(facts: Dict[str, Any]) -> Optional[str]:
    """Who could have sent it, from whether the stream was encrypted."""
    tls = facts.get("tls")
    if tls is None:
        return None
    if tls == "none":
        return ("before TLS: on clearnet, anyone on the path; over I2P or "
                "Tor, whoever answers at the server's address")
    return "inside TLS: the server, or whoever holds its address"


def summary_line(record: Optional[Dict[str, Any]]) -> str:
    """One line for the screen and the log: enough to quote in a report."""
    if not record:
        return ""
    facts = record["facts"]
    parts = ["check=%s" % record["reason"]]
    for key in ("phase", "mechanism", "step", "proof_sent", "server_fields",
                "iterations", "stream", "tls", "route"):
        if key in facts:
            # One token per fact, so the line can be split on spaces.
            parts.append("%s=%s" % (key, str(facts[key]).replace(" ", ",")))
    return " ".join(parts)


_ORDER = ("phase", "route", "certificate_checked", "progress", "mechanism",
          "offered", "step", "proof_sent", "channel_binding", "server_fields",
          "iterations",
          "salt_bytes", "nonce_continues_ours", "tls", "stream",
          "stream_bytes", "stream_stanzas", "open_stanza_bytes",
          "parser_state", "since_connect_s", "since_stream_s")


def _render_one(index: int, record: Dict[str, Any]) -> List[str]:
    facts = dict(record["facts"])
    if "step" in facts and facts["step"] in _STEPS:
        facts["step"] = _STEPS[facts["step"]]
    if record["reason"] == "iteration_count":
        facts.setdefault("accepted", _bounds())
    sent_by = _where(facts)
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record["at"]))
    lines = ["  %d. %s  refused: %s  (%s check)" % (
        index, when, record["reason"], record["check"])]
    prose = explain(record["reason"])
    if record["reason"] in OPERATOR_REMEDY:
        prose += " " + OPERATOR_REMEDY[record["reason"]]
    if sent_by:
        prose += " Sent %s." % sent_by
    if facts.get("proof_sent") == "yes":
        prose += " " + PROOF_SENT
    # Each line of prose starts with a bar. The report is scrubbed line by
    # line for anything shaped like a secret being reported, and a line
    # whose FIRST word is "password" loses the rest of itself; these
    # sentences are about passwords and wrap wherever they wrap. With the
    # bar first, no wording and no wrap can make one look like a setting.
    lines.extend(textwrap.wrap(prose, width=76, initial_indent="     | ",
                               subsequent_indent="     | "))
    keys = [k for k in _ORDER if k in facts] + sorted(
        k for k in facts if k not in _ORDER)
    width = max((len(k) for k in keys), default=0)
    for key in keys:
        lines.append("       %-*s %s" % (width, key, facts[key]))
    return lines


def render() -> str:
    """The report's section: the guards, then each refusal, newest first."""
    items = recent()
    lines = ["  guards    " + guards_line()]
    if not items:
        lines.append("  refusals  none in this session")
        return "\n".join(lines)
    lines.append("  refusals  %d in this session, newest first. Lengths and "
                 "counts only: no value the server sent is kept."
                 % len(items))
    for index, record in enumerate(reversed(items), start=1):
        lines.append("")
        lines.extend(_render_one(index, record))
    return "\n".join(lines)

