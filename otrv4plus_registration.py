# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Creating an account on the server, and saying what went wrong when it fails.

XEP-0077 IN-BAND REGISTRATION
-----------------------------
The mechanism, because it is easy to assume the wrong one: there is **no web
registration page**. The account is created over the XMPP stream itself,
*before* authentication, using the `jabber:iq:register` namespace:

  1. the client opens a stream and the server offers `<register/>` among its
     stream features;
  2. the client asks for the registration form (`iq type='get'`);
  3. the client submits `username` and `password` (`iq type='set'`);
  4. the server answers with an empty result, or an error.

slixmpp implements steps 1-2 in `xep_0077` and fires a `register` event
carrying the form; the submission in step 3 is the caller's to build. That is
what `XmppTransport.register_account` does, over the same SAM tunnel an
ordinary login uses -- registration is not allowed to be the one operation
that reaches the network some other way.

WHAT THIS MODULE IS
-------------------
The part with no network in it: local validation before a round trip is spent,
and the translation from an XMPP error condition to something a person can act
on. Dependency-free so every rule is tested by being run, which matters here
because the failure cases are the ones a user actually meets and the ones that
are hardest to reproduce against a live server.

The passwords passed to [validate] are never stored, never logged and never
returned in any result. A result carries a code and a sentence; it never echoes
what was submitted.
"""

from __future__ import annotations

from typing import Optional, Tuple

__all__ = ["classify", "validate", "describe", "CODES", "OK",
           "MIN_PASSWORD", "MAX_USERNAME", "RegistrationFailed"]

#: A registration that succeeded.
OK = "ok"

#: Shortest password accepted locally.
#:
#: Not a security claim -- the server sets the real policy and may demand more.
#: This exists so an obviously doomed submission does not cost an I2P round
#: trip, which over three hops is tens of seconds.
MIN_PASSWORD = 8

#: Longest localpart. RFC 7622 §3.3 caps it at 1023 bytes; this is far shorter
#: because a name that long is a mistake rather than a preference, and the
#: error is better delivered here than by the server.
MAX_USERNAME = 64

#: Characters RFC 7622 forbids in a localpart outright.
_FORBIDDEN = set('"&\'/:<>@ \t\r\n')

#: Every code [classify] can return, and what each means for the UI.
#:
#: Stable strings: the Kotlin side branches on them and a renamed code is a
#: silently-unhandled case.
CODES = {
    OK: "The account was created.",
    "conflict": "That username is already taken. Choose another.",
    "not_acceptable": "The server rejected those details. The username or "
                      "password may not meet its rules.",
    "bad_request": "The server could not read the registration request.",
    "forbidden": "The server refused the registration.",
    "not_allowed": "This server does not allow accounts to be created from "
                   "the app.",
    "not_authorized": "The server refused the registration.",
    "resource_constraint": "The server is refusing new accounts right now. "
                           "Try again later.",
    "service_unavailable": "Account creation is not available on this server.",
    "unsupported": "This server does not offer in-app registration.",
    "timeout": "The server did not answer. Over I2P this can be slow -- try "
               "again.",
    "network": "Could not reach the server.",
    "cancelled": "Registration was cancelled.",
    "unknown": "Registration failed.",
}

#: XMPP error conditions mapped to our codes. RFC 6120 §8.3.3 names them; the
#: three that actually occur in practice are the first three.
_CONDITIONS = {
    "conflict": "conflict",
    "not-acceptable": "not_acceptable",
    "bad-request": "bad_request",
    "forbidden": "forbidden",
    "not-allowed": "not_allowed",
    "not-authorized": "not_authorized",
    "resource-constraint": "resource_constraint",
    "service-unavailable": "service_unavailable",
    "feature-not-implemented": "unsupported",
    "internal-server-error": "unknown",
    "remote-server-timeout": "timeout",
}

#: Exception TYPE names that mean the round trip never completed.
#:
#: By name rather than by class so this module needs no slixmpp import -- the
#: same approach `otrv4plus_ping` uses, and for the same reason.
_TIMEOUTS = frozenset({"IqTimeout", "TimeoutError", "asyncio.TimeoutError"})
_NETWORK = frozenset({"ConnectionError", "ConnectionRefusedError", "OSError",
                      "ConnectionResetError"})


class RegistrationFailed(Exception):
    """A failure whose meaning was already known where it was raised.

    For the cases no XMPP error condition describes -- the server never
    offering registration at all, the SAM tunnel not opening -- where the
    caller knows which of [CODES] applies and would otherwise have to encode it
    in a message for [classify] to parse back out. It carries the code, and
    carries no detail: the sentence still comes from the table.
    """

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in CODES else "unknown"


def validate(username: str, password: str) -> Optional[Tuple[str, str]]:
    """Check what can be checked without the network.

    Returns `(code, detail)` for the first problem found, or None when the
    submission is worth sending. The server remains authoritative -- this
    refuses only what no server could accept, so a local pass is not a promise
    of success.
    """
    name = (username or "").strip()
    if not name:
        return ("not_acceptable", "Enter a username.")
    if len(name) > MAX_USERNAME:
        return ("not_acceptable",
                "That username is too long (limit %d characters)."
                % MAX_USERNAME)
    if "@" in name:
        # BEFORE the general character check, not after. "@" is in _FORBIDDEN,
        # so the general rule matches too -- but it answers with "a username
        # cannot contain '@'", which is true and useless. Typing the whole
        # address into the username box is the likeliest mistake there is here
        # and it deserves the sentence that says what to do instead.
        return ("not_acceptable",
                "Enter the username only, without the @ and the server.")
    bad = sorted(_FORBIDDEN & set(name))
    if bad:
        # The space is named separately because "  " renders as nothing in an
        # error message and the user cannot see what is being complained about.
        shown = ", ".join("space" if c == " " else repr(c) for c in bad)
        return ("not_acceptable",
                "A username cannot contain %s." % shown)
    if not password:
        return ("not_acceptable", "Enter a password.")
    if len(password) < MIN_PASSWORD:
        return ("not_acceptable",
                "The password must be at least %d characters." % MIN_PASSWORD)
    return None


def classify(exc: BaseException) -> Tuple[str, str]:
    """Turn a failed registration into a code and a sentence.

    NEVER returns the exception's own text. A slixmpp `IqError` stringifies to
    something containing the stanza, which carries the JID being registered and
    may carry the server's own wording about it -- and this result is shown on
    screen and may be copied into a bug report. The condition is read
    structurally; everything else is chosen from [CODES].
    """
    # A code the raiser already knew wins over anything inferred, but only
    # when it is one of ours: a `TransportError` also has a `.code` and its
    # vocabulary is a different one ("sam_unavailable", "client_build_failed"),
    # so the membership test is what keeps the two from being confused.
    try:
        known = getattr(exc, "code", None)
        if isinstance(known, str) and known in CODES and known != OK:
            return known, CODES[known]
    except Exception:                                        # pragma: no cover
        pass

    condition = _condition_of(exc)
    if condition and condition in _CONDITIONS:
        code = _CONDITIONS[condition]
        return code, CODES[code]

    name = type(exc).__name__
    if name in _TIMEOUTS:
        return "timeout", CODES["timeout"]
    if name in _NETWORK:
        return "network", CODES["network"]
    if name in ("CancelledError",):
        return "cancelled", CODES["cancelled"]
    return "unknown", CODES["unknown"]


def describe(code: str) -> str:
    """The sentence for a code, falling back rather than raising."""
    return CODES.get(code, CODES["unknown"])


def _condition_of(exc: BaseException) -> str:
    """The XMPP error condition, read structurally rather than from text.

    slixmpp puts it on `IqError.condition`, and also inside `.iq['error']`.
    Both are tried because the first is absent on some error paths, and
    neither is allowed to raise: this runs while reporting a failure.
    """
    for attr in ("condition",):
        try:
            value = getattr(exc, attr, None)
            if value:
                return str(value)
        except Exception:                                    # pragma: no cover
            pass
    try:
        iq = getattr(exc, "iq", None)
        if iq is not None:
            value = iq["error"]["condition"]
            if value:
                return str(value)
    except Exception:
        pass
    return ""
