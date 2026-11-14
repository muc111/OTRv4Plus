# SPDX-License-Identifier: AGPL-3.0-or-later
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
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Dict

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


def status() -> Dict[str, bool]:
    return dict(_status)


def _trace(event: str, **fields) -> None:
    try:
        from .trace import TRACE
        TRACE.record("auth", event, "error", **fields)
    except Exception:
        pass


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

    challenge = getattr(FeatureMechanisms, "_handle_challenge", None)
    if challenge is not None and not getattr(challenge, "_otr_checked", False):
        def checked_challenge(self, stanza):
            mech = getattr(self, "mech", None)
            result = challenge(self, stanza)
            why = getattr(mech, "_otr_refused", None)
            if why:
                # Not the next mechanism: the same server names the count.
                return _refuse(self, why)
            return result
        checked_challenge._otr_checked = True
        FeatureMechanisms._handle_challenge = checked_challenge

    original = getattr(FeatureMechanisms, "_handle_success", None)
    if original is not None and not getattr(original, "_otr_checked", False):
        def checked_success(self, stanza):
            mech = getattr(self, "mech", None)
            is_scram = scram is not None and isinstance(mech, scram)
            if is_scram and getattr(mech, "step", 0) != 2:
                return _refuse(self, "success_before_challenge")
            result = original(self, stanza)
            if (is_scram and getattr(self.xmpp, "authenticated", False)
                    and not getattr(mech, "_mutual_auth", False)):
                self.xmpp.authenticated = False
                return _refuse(self, "success_without_signature")
            return result
        checked_success._otr_checked = True
        FeatureMechanisms._handle_success = checked_success
    _status["success_needs_proof"] = bool(getattr(
        getattr(FeatureMechanisms, "_handle_success", None),
        "_otr_checked", False))
    return status()


def _refuse(plugin, why: str):
    _log.error("SASL success refused: %s", why)
    _trace("server_not_proven", reason=why)
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
