# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What every part of the XMPP transport shares: its error, its timeouts and
its log.

XmppTransport (transport.py) is built from mixins in transport_*.py; they
import these from here rather than from transport.py, which imports them.
transport.py re-exports all four.
"""
import logging

_log = logging.getLogger("otrv4plus.bridge.transport")

#: How long a blocking call waits on the loop thread before giving up. Not the
#: same thing as the SAM timeouts: those are how long a tunnel may take to
#: build (SAM_CONNECT_TIMEOUT is 240s), and this has to be larger or a cold
#: tunnel would be reported as a failed connection while it was still working.
#: The number is deliberately generous; the UI shows progress, not a stopwatch.
CONNECT_TIMEOUT = 300.0
CALL_TIMEOUT = 30.0


#: The c2s port on the far side of the SAM stream. 5222 is the XMPP default and
#: the I2P destination speaks it normally -- the tunnel is a pipe, not a proxy
#: that rewrites ports.
DEFAULT_C2S_PORT = 5222


class TransportError(RuntimeError):
    """The transport could not do what was asked.

    Carries a short stable `code` for the UI to branch on and a `detail` for a
    human. The detail never contains the password -- it is built from exception
    types and our own strings, never from the credential.
    """

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


SERVER_NOT_PROVEN_CODE = "server_not_proven"
SERVER_NOT_PROVEN_TEXT = (
    "the server did not prove it knows this account, or sent something this "
    "app refuses to read, so the app disconnected.")

#: What had left the device by then. Said only where it is known: a SCRAM
#: refusal while signing in (SCRAM sends a proof, never the password), and a
#: SCRAM refusal while registering (the registration request, sent just
#: before, carries the new password to that server). For a refused XML
#: stream it depends on when, and nothing is claimed.
_PASSWORD_NOT_SENT = " The password itself was not sent."
_PROOF_WAS_SENT = (
    " The app's sign-in proof was: it is not the password, but if this was "
    "not your server, change the password once you reach the real one.")
_REGISTRATION_SENT_IT = (
    " Registering had already sent this server the password chosen for the "
    "new account: do not use that password anywhere else.")


def server_not_proven_detail(route, phase: str, progress=None) -> str:
    """The sentence above, what is known to have been sent, then which check
    failed and where, in one line a person can copy into a report:
    `[check=... mechanism=... step=...]`.

    The guard that refused knows what the server's message looked like; only
    the transport knows the route and whether this was a sign-in or a
    registration, so those are added to the record here. Names, lengths and
    counts only (android_bridge/server_proof.py).
    """
    said = SERVER_NOT_PROVEN_TEXT
    line = ""
    try:
        from . import server_proof
        record = server_proof.annotate_last(
            phase=phase,
            route=getattr(route, "kind", None),
            certificate_checked=(
                bool(route.verify_certificate)
                if hasattr(route, "verify_certificate") else None),
            progress=progress)
        line = server_proof.summary_line(record)
        if record and record["check"] == "sasl":
            if phase == "registration":
                said += _REGISTRATION_SENT_IT
            else:
                said += _PASSWORD_NOT_SENT
                if record["facts"].get("proof_sent") == "yes":
                    said += _PROOF_WAS_SENT
        # The one refusal a server's own setting causes says so, with the
        # number: the person reading it can then pass on what to change.
        remedy = server_proof.operator_sentence(record)
        if remedy:
            said += " " + remedy
    except Exception:
        pass
    return said + (" [%s]" % line if line else "")
