# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Three faults in slixmpp's SCRAM, closed from our side.

Over I2P and Tor the server's certificate is not checked, so SCRAM is what
keeps the password from the far end and proves that end knows the account.
slixmpp 1.17.0's implementation leaves three gaps a hostile or fake server
can use:

1. **Success without proof.** A `<success/>` arriving straight after the
   client's first message, carrying text shaped like a server challenge, is
   run through the challenge step, raises nothing, and the session is marked
   authenticated. The server's signature (the proof it holds the account's
   keys) is never checked. Now `<success/>` is honoured only after the
   challenge step, and only once that signature has verified.

2. **Any iteration count.** The server names the PBKDF2 iteration count and
   slixmpp runs it in a Python loop on the event loop thread. A count of one
   makes the proof the client sends cheap to brute-force offline; a count in
   the billions freezes the app. Counts outside
   `MIN_ITERATIONS..MAX_ITERATIONS` are refused, and the work is done by
   `hashlib.pbkdf2_hmac` (the same function, in C).

3. **A nonce from `random.random()`.** The client nonce is what stops an old
   exchange being replayed; it now comes from the system CSPRNG.

`apply()` patches slixmpp's classes once, before any client is built. Each
patch is applied only if the code it replaces looks as expected, and
`status()` says which took, so a different slixmpp is reported rather than
silently unprotected.

WHEN A SIGN-IN IS REFUSED the person at the screen reads "the server did not
prove it knows this account". Which check failed, at which step, and what the
server's message looked like are recorded in `server_proof` (names, lengths
and counts; never a nonce, salt, proof or signature), and every way the
exchange can go wrong ends in one of its reasons. slixmpp lets several of
them escape its handlers as exceptions (a challenge with no salt, a count
that is not a number, a success with no signature), which answered nothing
and left the sign-in to time out; those are refused here, at once.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any, Dict, Tuple

_log = logging.getLogger(__name__)

# RFC 7677 §4: a server "SHOULD" announce at least 4096; Prosody refuses to
# be configured lower.
MIN_ITERATIONS = 4096
# Above OWASP's figure for PBKDF2-HMAC-SHA1 (1,300,000); about a second of C
# on a handset.
MAX_ITERATIONS = 2_000_000

_status: Dict[str, bool] = {"success_needs_proof": False,
                            "iteration_bounds": False,
                            "csprng_nonce": False}


_applied = False
#: Whether SCRAM's challenge step is hooked (see `apply`). It is what makes
#: a refusal say which part of the challenge was wrong, and what records
#: that the client's answer was built. Not one of the three fixes above:
#: without it they still hold, and refusals are described less exactly.
_describes = False


def status() -> Dict[str, bool]:
    return dict(_status)


def describes_challenges() -> bool:
    """Whether the challenge step could be hooked on this slixmpp."""
    return _describes


def applied() -> bool:
    """Whether `apply()` has patched slixmpp in this process. Nothing is
    patched until the first client is built, and a report written before
    then should say that, not "0 of 3 fixes active"."""
    return _applied


def _trace(event: str, **fields) -> None:
    try:
        from .trace import TRACE
        TRACE.record("auth", event, "error", **fields)
    except Exception:
        pass


def shape(data: Any) -> str:
    """What a SCRAM message looked like, for a report: each attribute's
    letter and the LENGTH of its value (`r:59 s:24 i:5`). Never a value.
    `empty` for nothing; `unreadable:N` for N bytes that are not a list of
    attributes."""
    try:
        raw = bytes(data) if data is not None else b""
    except Exception:
        return "unreadable:0"
    if not raw:
        return "empty"
    parts = []
    for item in raw.split(b",")[:16]:
        key, separator, value = item.partition(b"=")
        if not separator or len(key) != 1 or not key.isalpha():
            return "unreadable:%d" % len(raw)
        parts.append("%s:%d" % (key.decode("ascii"), len(value)))
    return " ".join(parts)


def _value_of(stanza: Any) -> bytes:
    """The payload of a SASL stanza, or nothing."""
    try:
        value = stanza["value"]
    except Exception:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    try:
        return bytes(value)
    except Exception:
        return b""


def _challenge_facts(mech: Any, challenge: Any) -> Tuple[Dict[str, Any], bool]:
    """(facts, reserved) for the server's challenge: its shape, the iteration
    count as a number, the salt's length, and whether its nonce continues
    ours. `reserved` is whether it carried the `m` attribute.

    Read here and not taken from slixmpp, so that a challenge slixmpp cannot
    parse is still described."""
    facts: Dict[str, Any] = {"server_fields": shape(challenge)}
    try:
        raw = bytes(challenge)
    except Exception:
        return facts, False
    fields: Dict[bytes, bytes] = {}
    for item in raw.split(b","):
        key, separator, value = item.partition(b"=")
        if separator and key not in fields:
            fields[key] = value
    count = fields.get(b"i")
    if count is not None:
        try:
            # As slixmpp reads it, so the report names the number acted on.
            digits = str(int(count))
        except Exception:
            digits = ""
        if not digits.isdigit():
            facts["iterations"] = "not a number"
        elif len(digits) > 12:
            facts["iterations"] = "over 12 digits"
        else:
            facts["iterations"] = digits
    salt = fields.get(b"s")
    if salt is not None:
        try:
            facts["salt_bytes"] = len(base64.b64decode(salt))
        except Exception:
            pass
    nonce = fields.get(b"r")
    ours = getattr(mech, "cnonce", None)
    if nonce is not None and ours:
        facts["nonce_continues_ours"] = bytes(nonce).startswith(bytes(ours))
    return facts, b"m" in fields


class _Nonce:
    """Stands in for the `random` module inside slixmpp's SASL code, which
    uses it for one thing: `('%s' % random.random())[2:]` as a nonce."""

    @staticmethod
    def random() -> str:
        return "0." + secrets.token_hex(24)


def apply() -> Dict[str, bool]:
    """Idempotent. Returns `status()`."""
    try:
        from slixmpp.util import sasl
        from slixmpp.util.sasl import mechanisms as mechs
        from slixmpp.features.feature_mechanisms.mechanisms import (
            FeatureMechanisms)
    except Exception:
        _log.warning("slixmpp's SASL code not found; nothing hardened")
        return status()

    scram = getattr(mechs, "SCRAM", None)

    if scram is not None and not getattr(scram.Hi, "_otr_bounded", False):
        def bounded_hi(self, text, salt, iterations):
            if not MIN_ITERATIONS <= int(iterations) <= MAX_ITERATIONS:
                _trace("scram_iterations_refused",
                       iterations=str(iterations)[:12])
                self._otr_refused = "iteration_count"
                raise sasl.SASLCancelled(
                    "SCRAM iteration count %s refused" % str(iterations)[:12])
            return mechs.bytes(hashlib.pbkdf2_hmac(
                self.hash().name, bytes(text), bytes(salt), int(iterations)))
        bounded_hi._otr_bounded = True
        scram.Hi = bounded_hi
    _status["iteration_bounds"] = bool(
        scram is not None and getattr(scram.Hi, "_otr_bounded", False))

    if isinstance(getattr(mechs, "random", None), _Nonce):
        _status["csprng_nonce"] = True
    elif hasattr(getattr(mechs, "random", None), "random"):
        mechs.random = _Nonce()
        _status["csprng_nonce"] = True

    # The challenge step. slixmpp cancels for two reasons (a reserved
    # attribute, a nonce that is not ours) and lets everything else escape
    # as KeyError or ValueError: a missing salt, a count that is not a
    # number. Each now ends in a named refusal.
    process_2 = getattr(scram, "process_2", None) if scram is not None else None
    if process_2 is not None and not getattr(process_2, "_otr_described", False):
        def checked_process_2(self, challenge):
            facts, reserved = _challenge_facts(self, challenge)
            self._otr_facts = facts
            try:
                answer = process_2(self, challenge)
            except sasl.SASLCancelled:
                if not getattr(self, "_otr_refused", None):
                    if reserved:
                        self._otr_refused = "reserved_attribute"
                    elif facts.get("nonce_continues_ours") is False:
                        self._otr_refused = "nonce_mismatch"
                    else:
                        self._otr_refused = "challenge_malformed"
                raise
            except Exception:
                self._otr_refused = "challenge_malformed"
                raise sasl.SASLCancelled("SCRAM challenge could not be read")
            # Only now has the client's proof been built and handed back to
            # be sent; before this line nothing derived from the password
            # has left.
            self._otr_answered = True
            return answer
        checked_process_2._otr_described = True
        scram.process_2 = checked_process_2

    challenge = getattr(FeatureMechanisms, "_handle_challenge", None)
    if challenge is not None and not getattr(challenge, "_otr_checked", False):
        def checked_challenge(self, stanza):
            mech = getattr(self, "mech", None)
            result = challenge(self, stanza)
            why = getattr(mech, "_otr_refused", None)
            if why:
                # Not the next mechanism: the same server names the count.
                return _refuse(self, why, mech)
            return result
        checked_challenge._otr_checked = True
        FeatureMechanisms._handle_challenge = checked_challenge

    original = getattr(FeatureMechanisms, "_handle_success", None)
    if original is not None and not getattr(original, "_otr_checked", False):
        def checked_success(self, stanza):
            mech = getattr(self, "mech", None)
            if scram is None or not isinstance(mech, scram):
                return original(self, stanza)
            # The answered flag is set by the hook on the challenge step.
            # Where that hook could not be installed (a slixmpp whose SCRAM
            # is shaped differently) the flag is never set, and requiring
            # it would refuse every server, blaming each one. There the
            # rule is rc.204's: the step alone. The signature check below
            # does not depend on either.
            answered = getattr(mech, "_otr_answered", False) or not _describes
            if getattr(mech, "step", 0) != 2 or not answered:
                return _refuse(self, "success_before_challenge", mech, stanza)
            try:
                result = original(self, stanza)
            except sasl.SASLFailed:
                # No `v=` at all: an error where the signature belongs, or
                # nothing. (A signature that does not verify is caught
                # inside slixmpp and falls to the check below.)
                self.xmpp.authenticated = False
                return _refuse(self, "success_without_signature", mech, stanza)
            except Exception:
                self.xmpp.authenticated = False
                # An empty success is the plainest "no signature" there is;
                # slixmpp fails to parse it rather than finding no `v=`.
                why = ("success_malformed" if _value_of(stanza)
                       else "success_without_signature")
                return _refuse(self, why, mech, stanza)
            if not getattr(mech, "_mutual_auth", False):
                self.xmpp.authenticated = False
                return _refuse(self, "signature_mismatch", mech, stanza)
            try:
                from . import server_proof
                server_proof.passed("proofs_verified")
            except Exception:
                pass
            return result
        checked_success._otr_checked = True
        FeatureMechanisms._handle_success = checked_success
    _status["success_needs_proof"] = bool(getattr(
        getattr(FeatureMechanisms, "_handle_success", None),
        "_otr_checked", False))
    global _applied, _describes
    _describes = bool(scram is not None and getattr(
        getattr(scram, "process_2", None), "_otr_described", False))
    _applied = True
    return status()


def _facts(plugin: Any, mech: Any, success: Any = None) -> Dict[str, Any]:
    """What is known about the exchange at the moment it is refused. Passed
    through `server_proof`'s validators before anything is kept."""
    facts: Dict[str, Any] = {}
    try:
        from .xmlguard import stream_position
        facts.update(stream_position(plugin.xmpp))
    except Exception:
        pass
    if mech is not None:
        facts.update(getattr(mech, "_otr_facts", None) or {})
        facts["mechanism"] = getattr(mech, "name", None)
        facts["step"] = getattr(mech, "step", None)
        # Known only where the challenge step is hooked; otherwise left
        # out, which the record shows as absent and not as "no".
        if _describes:
            facts["proof_sent"] = bool(getattr(mech, "_otr_answered", False))
        facts["channel_binding"] = bool(
            getattr(mech, "use_channel_binding", False))
        if "tls" not in facts:
            settings = getattr(mech, "security_settings", None) or {}
            facts["tls"] = settings.get("tls_version") or (
                "unknown" if settings.get("encrypted") else "none")
    offered = getattr(plugin, "mech_list", None)
    if offered:
        facts["offered"] = sorted(str(name) for name in offered)
    if success is not None:
        # The message that was refused, in place of the challenge's shape.
        facts["server_fields"] = shape(_value_of(success))
    return facts


def _refuse(plugin: Any, why: str, mech: Any = None, success: Any = None):
    line = why
    kept: Dict[str, Any] = {}
    try:
        from . import server_proof
        record = server_proof.note("sasl", why, **_facts(plugin, mech, success))
        kept = record["facts"]
        line = server_proof.summary_line(record) or why
    except Exception:
        pass
    _log.error("sign-in refused, server not proven: %s", line)
    # Only what the record kept, which has been through its validators.
    _trace("server_not_proven", reason=why,
           mechanism=kept.get("mechanism"), step=kept.get("step"),
           fields=kept.get("server_fields"),
           iterations=kept.get("iterations"), stream=kept.get("stream"))
    xmpp = plugin.xmpp
    try:
        from .xmlguard import REFUSED_EVENT
        xmpp.event(REFUSED_EVENT, why)
    except Exception:
        pass
    try:
        xmpp.disconnect_reason = "server did not prove it knows the account"
    except Exception:
        pass
    for closer in ("abort", "disconnect"):
        try:
            getattr(xmpp, closer)()
            break
        except Exception:
            continue
    return True
