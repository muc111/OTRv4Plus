"""The XMPP transport, over an I2P SAM stream.

`OtrApp` already owns the protocol. Look at what it asks a transport for --
`send(peer, payload)`, `connect`, `disconnect`, `roster` -- and at what
`send_message` hands over: a string the engine produced, already encrypted,
which the transport is not expected to understand. That is the whole contract,
and it means this module does **not** need `otrv4plus_xmpp.OTRv4PlusXMPP`.

That matters more than it sounds. `OTRv4PlusXMPP` is a seven-thousand-line
terminal program: an ANSI panel manager, a raw-mode line editor, a module-scope
`print` shadow that routes through a session log, argparse, `getpass`,
`readline`. Every bit of it is right for a terminal and wrong inside an
application, and Phase 5 of the original plan was budgeted for tearing it out.
It turns out not to be necessary: an ordinary `slixmpp.ClientXMPP` carries
message bodies, `OtrApp` does the cryptography, and the terminal client stays
a terminal client.

What is reused is `start_i2p_sam_forwarder`, which opens the SAM stream and
exposes it as a local TCP endpoint for slixmpp to connect to. That function is
where the hard-won details live -- the 1 KB write chunking that avoids the SAM
cliff, keeping the session and writer alive on the loop so they are not
collected -- and reimplementing it here would be reimplementing a bug fix.

Threading
---------
slixmpp is asyncio; Android calls in from Kotlin threads, and Chaquopy will
happily hand us the UI thread if we let it. So the transport owns a loop on a
worker thread and every public method is a thread-safe hand-off onto it. The
methods block for a bounded time and raise on failure, because `OtrApp.connect`
is written to expect that.

Secrets
-------
The password is held because SASL needs it again on every reconnect, and
slixmpp holds it too -- but this object is the sort of thing that ends up in a
log line or a diagnostic report, so `__repr__` is written by hand and
`tests/test_android_transport.py` asserts the password is absent from it, from
`str()`, and from the event stream.
"""

from __future__ import annotations

import asyncio
import concurrent.futures as _futures
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import otrv4plus_address as _address
import otrv4plus_caps as _caps
from . import route as _route_mod
from . import welcome as _welcome
import otrv4plus_fragment as _fragment
import otrv4plus_muc as _muc
import otrv4plus_ping as _ping
import otrv4plus_registration as _registration

from .app import Transport
from .settings import ConnectionProfile
from .trace import TRACE as _TRACE

__all__ = ["XmppTransport", "TransportError", "DEFAULT_C2S_PORT",
           "SubscriptionPolicy"]


class SubscriptionPolicy:
    """What happens when someone asks to see your presence.

    Presence is metadata. Approving a subscription tells that account when you
    are online, from which device, and how idle you are -- for as long as they
    keep it. On an anonymity-oriented messenger that is worth a deliberate
    choice rather than an inherited default, which is what slixmpp's
    `auto_authorize = True` would otherwise be.

    ACCEPT is the shipped default because it is what was asked for and because
    on a server you control it is the difference between a contact list that
    works and one that needs a second out-of-band step per person. It is a
    setting, and ASK is one line away for anyone who wants it.

    None of this is an OTR question. A subscription grants presence, not the
    ability to read anything: a message from an approved contact is still
    plaintext until a DAKE has run, and the conversation screen says so.
    """

    #: Approve, and ask for theirs back. slixmpp: auto_authorize=True,
    #: auto_subscribe=True.
    ACCEPT = "accept"
    #: Approve, but do not ask for theirs. auto_authorize=True,
    #: auto_subscribe=False.
    ACCEPT_ONE_WAY = "accept_one_way"
    #: Neither approve nor refuse -- hand it to the UI. auto_authorize=None.
    ASK = "ask"
    #: Refuse. auto_authorize=False.
    REJECT = "reject"

    ALL = (ACCEPT, ACCEPT_ONE_WAY, ASK, REJECT)

    #: (auto_authorize, auto_subscribe) for each, mapped onto the two
    #: properties slixmpp actually has. Verified against basexmpp.py: True
    #: approves, None disables automatic handling, False refuses.
    _SLIXMPP = {
        ACCEPT: (True, True),
        ACCEPT_ONE_WAY: (True, False),
        ASK: (None, False),
        REJECT: (False, False),
    }

    @classmethod
    def apply(cls, client, policy: str) -> str:
        """Set the policy on *client*. Returns the policy actually applied."""
        if policy not in cls._SLIXMPP:
            policy = cls.ACCEPT
        authorize, subscribe = cls._SLIXMPP[policy]
        client.auto_authorize = authorize
        client.auto_subscribe = subscribe
        return policy

_log = logging.getLogger("otrv4plus.bridge.transport")

#: The c2s port on the far side of the SAM stream. 5222 is the XMPP default and
#: the I2P destination speaks it normally -- the tunnel is a pipe, not a proxy
#: that rewrites ports.
DEFAULT_C2S_PORT = 5222

#: How long a blocking call waits on the loop thread before giving up. Not the
#: same thing as the SAM timeouts: those are how long a tunnel may take to
#: build (SAM_CONNECT_TIMEOUT is 240s), and this has to be larger or a cold
#: tunnel would be reported as a failed connection while it was still working.
#: The number is deliberately generous; the UI shows progress, not a stopwatch.
CONNECT_TIMEOUT = 300.0
CALL_TIMEOUT = 30.0

#: How long teardown waits. Short on purpose: `close` is called from Android
#: lifecycle callbacks that must return promptly, and a shutdown that blocks
#: is a worse failure than one that gives up and logs.
CLOSE_TIMEOUT = 5.0

# Keepalive, with the terminal client's numbers.
#
# These are not independently chosen: tests/test_android_keepalive.py binds
# them to OTRv4PlusXMPP's own constants, so the two clients cannot drift into
# disagreeing about how long a silent I2P tunnel may stay silent.
#
#: Whitespace tick. Short enough that an idle tunnel is never idle.
KEEPALIVE_WHITESPACE_S = 8
#: How often to make the server actually answer.
KEEPALIVE_PING_S = 60
#: How long to wait for that answer. Generous: an I2P round trip is slow.
KEEPALIVE_PING_TIMEOUT_S = 60
#: Consecutive unanswered pings before the stream is declared dead. Two, not
#: one: a single missed round trip over I2P is ordinary.
KEEPALIVE_PING_FAILS = 2
#: How recently the stream must have DELIVERED something for that to count as
#: proof of life on its own.
#:
#: Traffic is better evidence than a ping: it proves the whole path end to
#: end without asking the server for anything. While it is arriving there is
#: nothing worth probing, and a probe whose reply is merely slow -- ordinary
#: over three I2P hops -- must not be read as silence.
#:
#: This gate is the terminal client's `KEEPALIVE_QUIET_S` and was missing
#: here. Its absence is why the broken ping (see `otrv4plus_ping`) killed
#: Android sessions and not Termux ones: Termux in an active conversation
#: never reached the probe at all.
KEEPALIVE_QUIET_S = 180

#: The two unrelated CancelledError classes, as a tuple to catch on. They are
#: genuinely different types -- `asyncio.CancelledError is
#: concurrent.futures.CancelledError` is False on 3.12 -- and only one of them
#: derives from Exception, so naming either alone gets the wrong half.
_CANCELLED = (asyncio.CancelledError, _futures.CancelledError)


def _sam_failure(exc: BaseException, server: str) -> "TransportError":
    """The TransportError for a failure opening the I2P stream, by LAYER.

    "Is the router running?" used to be the answer to every failure here,
    including a name the router did not know and a destination that was not
    online -- which sent people to restart a router that was working. The
    SAM layer now says which stage failed (otrv4+.py `SamError`):

      bridge  -> sam_unavailable        the local SAM bridge
      naming  -> i2p_name_not_found     the router could not resolve the name
      session -> i2p_session_failed     the router could not build our tunnels
      stream  -> i2p_destination_unreachable   resolved, but not reachable

    Only the SAM RESULT code is included, never the reply text, which can
    carry a destination.
    """
    stage = getattr(exc, "stage", "")
    result = str(getattr(exc, "result", "") or "")
    if stage == "naming":
        if result == "INVALID_NAME":
            return TransportError(
                "i2p_name_invalid",
                "%s is not a valid I2P address. Use a name ending in .i2p or a "
                "52-character .b32.i2p address." % server)
        return TransportError(
            "i2p_name_not_found",
            "the I2P router could not resolve %s (%s). Short .i2p names come "
            "from the router's address book; add the server to it, or use its "
            ".b32.i2p address. Nothing was looked up in DNS." % (server, result or "no result"))
    if stage == "stream":
        return TransportError(
            "i2p_destination_unreachable",
            "%s resolved, but its I2P destination is not reachable right now "
            "(%s). The server or its I2P tunnel may be down; a cold router can "
            "also need a few minutes." % (server, result or "no result"))
    if stage == "session":
        return TransportError(
            "i2p_session_failed",
            "the I2P router would not create a session (%s). It may still be "
            "starting." % (result or "no result"))
    return TransportError(
        "sam_unavailable",
        "could not reach the I2P router's SAM bridge (%s). Is the router "
        "running and is its SAM bridge enabled?" % type(exc).__name__)


def _accepts(fn: Any, name: str) -> bool:
    """Whether *fn* takes a keyword argument called *name*.

    Asked rather than discovered by catching TypeError, because a TypeError
    raised inside the callee is indistinguishable from one raised by the call.
    """
    try:
        import inspect

        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if name in params:
        return True
    return any(p.kind is p.VAR_KEYWORD for p in params.values())


#: What a transport-level failure means to somebody trying to create an account.
#:
#: Two different vocabularies meeting: `_endpoint` raises TransportError with
#: codes about the transport, and the Register screen renders codes from
#: `otrv4plus_registration`. Anything not named here is "unknown", because
#: guessing at a failure is worse than admitting to one.
_REGISTRATION_CODES = {
    # The router did not answer or the tunnel would not open. From the user's
    # side that is indistinguishable from the server being unreachable, and
    # the remedy -- check the router, try again -- is the same.
    "sam_unavailable": "network",
    "i2p_name_not_found": "network",
    "i2p_name_invalid": "network",
    "i2p_destination_unreachable": "network",
    "i2p_session_failed": "network",
    # A packaging fault. Nothing the user can do, and calling it a network
    # problem would send them to look at their router for no reason.
    "forwarder_import_failed": "unknown",
    # X1 and the Tor route: their own codes, never folded into "network".
    "i2p_destination_changed": "server_identity_changed",
    "tor_unavailable": "tor_unavailable",
    "client_build_failed": "unknown",
    "cancelled": "cancelled",
    "timeout": "timeout",
}


def _localpart(jid: str) -> str:
    """The username out of a JID, tolerating one that is only a username."""
    return str(jid or "").strip().split("@", 1)[0]


#: X1, part A. The mechanisms allowed when TLS certificate checks are off:
#: SCRAM only (RFC 5802/7677), with and without channel binding. With SCRAM
#: the password never crosses the wire -- the server gets a salted proof it
#: cannot replay elsewhere, and a server that does not hold the credential
#: fails SCRAM's mutual authentication. PLAIN (the password itself), LOGIN,
#: DIGEST/CRAM (weak or obsolete) and SCRAM-MD5 are excluded.
SCRAM_ONLY = frozenset({
    "SCRAM-SHA-512-PLUS", "SCRAM-SHA-512",
    "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256",
    "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1",
})


def _restrict_to_scram(client) -> None:
    """Never send the password itself where the certificate is not checked.

    `use_mechs` is enforced by slixmpp's mechanism chooser as a hard limit,
    and `encrypted_plain` False makes PLAIN cancel itself even if it were
    chosen. A server offering none of these fails with `no_auth` and the
    user is told why (`no_safe_auth_mechanism`); nothing falls back.
    """
    try:
        plugins = getattr(client, "plugin", None)
        mech = (plugins["feature_mechanisms"] if plugins is not None
                else client["feature_mechanisms"])
    except Exception:
        raise TransportError(
            "client_build_failed",
            "the XMPP client has no SASL plugin to restrict; refusing to "
            "authenticate without that restriction.")
    mech.use_mechs = set(SCRAM_ONLY)
    mech.encrypted_plain = False
    mech.unencrypted_plain = False


def _tls_in_place(client) -> bool:
    """Whether the stream is TLS-protected (STARTTLS done, or TLS socket)."""
    try:
        if "starttls" in getattr(client, "features", set()):
            return True
        import ssl
        return isinstance(getattr(client, "socket", None),
                          (ssl.SSLSocket, ssl.SSLObject))
    except Exception:
        return False


# ── clearnet: SRV, address order, and how an attempt ended ──────────────────
#
# THE 07f.de / yax.im REPORT (2026-09-28): both registrations ended
# `clearnet_endpoint srv=true -> registration requested -> code=network`.
# Two faults, both here:
#
#  1. No SRV lookup happened. slixmpp asks for `_xmpp-client._tcp.<domain>`
#     only through aiodns, which the APK does not ship; without it it dials
#     `<domain>:5222`. yax.im's SRV points at xmpp.yax.im, a different
#     machine. `_clearnet_dns_records` asks the SRV question itself
#     (android_bridge.dns_srv) and hands slixmpp the ordered targets.
#  2. The first failed ADDRESS ended the attempt. slixmpp tries every
#     resolved address in turn (AAAA first, as slixmpp orders them), firing
#     `connection_failed` for each one that fails; the handler here treated
#     the first as final. Both domains publish AAAA records, so a phone with
#     no working IPv6 gave up before IPv4 was tried. Reproduced against a
#     real STARTTLS server in tests/test_clearnet_registration.py.
#
# `_StreamWatch` now decides when an attempt has failed -- after every
# planned address -- and says at which stage, with nothing secret in it.

#: Safe failure codes, by stage. Clearnet only; I2P and Tor keep theirs.
STAGE_CODES = ("dns_failure", "tcp_failure", "tls_failure",
               "certificate_failure", "xmpp_stream_failure",
               "server_closed_connection")


def _errno_name(exc) -> str:
    import errno as _errno
    num = getattr(exc, "errno", None)
    if isinstance(num, int) and num in _errno.errorcode:
        return _errno.errorcode[num]
    return type(exc).__name__


def _family(address: str) -> str:
    return "IPv6" if ":" in str(address) else "IPv4"


async def _clearnet_dns_records(domain: str, loop, lookup=None, getaddrinfo=None,
                                fallback_port: int = DEFAULT_C2S_PORT):
    """(service, host, address, port) records for slixmpp, SRV first.

    Returns (records, plan) where `plan` is a safe description for the
    trace: the SRV status, the targets and ports, and how many addresses of
    each family. IPv4 before IPv6 within each target: slixmpp has no
    per-address connect timeout, so an IPv6 route that silently drops
    packets would stall the attempt for the OS's TCP timeout (minutes)
    before IPv4 was ever tried; a refused or unreachable IPv4 fails fast.
    """
    from . import dns_srv as _dns
    import socket as _socket
    lookup = lookup or _dns.lookup
    getaddrinfo = getaddrinfo or loop.getaddrinfo
    srv = await loop.run_in_executor(None, lookup, domain)
    if srv.status == "found" and srv.records:
        targets = [("xmpp-client", r.target, r.port) for r in _dns.order(srv.records)]
        fallback = False
    else:
        targets = [("", domain, fallback_port)]
        fallback = True
    records, v4, v6 = [], 0, 0
    for service, host, port in targets:
        for fam in (_socket.AF_INET, _socket.AF_INET6):
            try:
                infos = await getaddrinfo(host, port, family=fam,
                                          type=_socket.SOCK_STREAM)
            except (OSError, _socket.gaierror):
                continue
            for addr in dict.fromkeys(i[4][0] for i in infos):
                records.append((service, host, addr, port))
                if fam == _socket.AF_INET:
                    v4 += 1
                else:
                    v6 += 1
    plan = {"srv": srv.status, "srv_detail": srv.detail,
            "targets": ",".join("%s:%d" % (h, p) for _s, h, p in targets),
            "fallback_used": fallback, "ipv4": v4, "ipv6": v6}
    return records, plan


class _StreamWatch:
    """How one slixmpp connection attempt is going, and when it has failed.

    Fed by slixmpp's own events. `fail(code, detail)` is called at most
    once, with a code from STAGE_CODES (clearnet) and a detail naming the
    stage and the OS/TLS reason -- never a password, a stanza or a key.
    """

    def __init__(self, client, route, fail, label: str):
        self.client, self.route, self._fail, self.label = client, route, fail, label
        self.stage = "resolving"
        self.expected: Optional[int] = None     # planned addresses, if known
        self.failures: List[str] = []
        self.done = False
        #: Stages reached, in order -- the probe reports these.
        self.reached: List[str] = []
        for name, fn in (("connection_failed", self._on_conn_failed),
                         ("reconnect_delay", self._on_reconnect_delay),
                         ("connected", self._on_connected),
                         ("tls_success", self._on_tls),
                         ("ssl_invalid_chain", self._on_invalid_chain),
                         ("stream_error", self._on_stream_error),
                         ("disconnected", self._on_disconnected)):
            client.add_event_handler(name, fn)
        if route.verify_certificate and hasattr(client, "add_filter"):
            client.add_filter("in", self._features_filter)

    def _features_filter(self, stanza):
        """A clearnet server whose first features offer no STARTTLS is
        refused by name, before anything else is negotiated."""
        if type(stanza).__name__ == "StreamFeatures" and not self.done:
            names = [str(c.tag).rsplit("}", 1)[-1] for c in stanza.xml]
            if not _tls_in_place(self.client):
                if "starttls" not in names:
                    self.stage = "xmpp_stream"
                    self._emit("tls_required",
                               "The server was reached but offered no TLS, "
                               "so nothing was sent.")
                    return None
                # slixmpp answers <starttls/> next: the handshake is the
                # stage from here until tls_success.
                self.stage = "tls_handshake"
            elif "xmpp_stream" not in self.reached:
                self.reached.append("xmpp_stream")
                _TRACE.record(self.label, "stream_features", "info",
                              register="register" in names,
                              sasl="mechanisms" in names)
        return stanza

    def finish(self):
        self.done = True

    def _emit(self, code, detail):
        if self.done:
            return
        self.done = True
        _TRACE.record(self.label, "failed_at", "warning", code=code,
                      stage=self.stage, reasons=";".join(self.failures[-6:]))
        self._fail(code, detail)

    def _on_conn_failed(self, event):
        if isinstance(event, BaseException):
            reason = _errno_name(event)
        else:
            reason = "dns"                      # slixmpp passes a string
        self.failures.append(reason)
        _TRACE.record(self.label, "address_failed", "info", reason=reason,
                      attempt=len(self.failures))
        if self.expected is None or len(self.failures) >= self.expected:
            self._all_failed()

    def _on_reconnect_delay(self, _event):
        # slixmpp only reschedules after every address in the round failed.
        if self.failures:
            self._all_failed()

    def _all_failed(self):
        if all(f == "dns" for f in self.failures):
            self._emit("dns_failure",
                       "DNS: the server's name did not resolve to any address.")
        else:
            self._emit("tcp_failure",
                       "TCP: no address of the server accepted a connection "
                       "(%s). The server was not reached; nothing was sent."
                       % ", ".join(dict.fromkeys(self.failures)))

    def _on_connected(self, _event):
        self.stage = "tcp_connected"
        self.reached.append("tcp_connected")
        _TRACE.record(self.label, "tcp_connected", "info",
                      after_failures=len(self.failures))

    def _on_tls(self, _event):
        self.stage = "tls_established"
        self.reached.append("tls_established")
        _TRACE.record(self.label, "tls_established", "info",
                      certificate="verified" if self.route.verify_certificate
                      else "not used")

    def _on_invalid_chain(self, exc):
        import ssl as _ssl
        self.stage = "tls_handshake"
        if isinstance(exc, _ssl.SSLCertVerificationError):
            why = getattr(exc, "verify_message", "") or "not trusted"
            self._emit("certificate_failure",
                       "TLS: the server's certificate was rejected (%s). "
                       "Nothing was sent; certificate checks are never "
                       "switched off for a clearnet server." % why)
        else:
            self._emit("tls_failure",
                       "TLS: the handshake with the server failed (%s)."
                       % type(exc).__name__)
        try:
            self.client.abort()
        except Exception:
            pass

    def _on_stream_error(self, stanza):
        try:
            cond = stanza["condition"]
        except Exception:
            cond = "unknown"
        self._emit("xmpp_stream_failure",
                   "XMPP: the server ended the stream with an error (%s) at "
                   "stage %s." % (cond, self.stage))

    def _on_disconnected(self, _event):
        if self.stage in ("resolving", "tcp_connecting"):
            return
        if self.stage == "tls_handshake":
            # A rejected certificate makes the server drop the connection,
            # and `disconnected` can arrive before slixmpp's
            # `ssl_invalid_chain`. Give the precise event a moment to land.
            try:
                asyncio.get_event_loop().call_later(
                    0.5, self._emit, "tls_failure",
                    "TLS: the connection closed during the handshake.")
            except RuntimeError:
                self._emit("tls_failure",
                           "TLS: the connection closed during the handshake.")
            return
        self._emit("server_closed_connection",
                   "The server closed the connection after %s, before the "
                   "operation finished." % self.stage.replace("_", " "))


def _room_occupant_count(info) -> Optional[int]:
    """`muc#roominfo_occupants` from a room's disco#info, or None.

    Read from the XML rather than through a form plugin, so it works whether
    or not XEP-0128 is registered. Only a plain non-negative integer is
    accepted; anything else is "not given"."""
    try:
        xml = info["disco_info"].xml
    except Exception:
        try:
            xml = info.xml
        except Exception:
            return None
    for form in xml.iter("{jabber:x:data}x"):
        for field in form.iter("{jabber:x:data}field"):
            if field.get("var") != "muc#roominfo_occupants":
                continue
            value = field.find("{jabber:x:data}value")
            text = (value.text or "").strip() if value is not None else ""
            if text.isdigit() and len(text) <= 7:
                return int(text)
            return None
    return None


def _form_field_names(form) -> str:
    """The NAMES of the fields a registration form asks for -- never values."""
    names = []
    try:
        query = form["register"]
        for n in ("username", "password", "email", "name"):
            if query.xml.find("{jabber:iq:register}%s" % n) is not None:
                names.append(n)
        xform = query["form"]
        if xform is not None:
            names.extend(k for k in (xform.get_fields() or {}) if k not in names)
    except Exception:
        pass
    return ",".join(names[:12]) or "none"


def _safe_condition(exc) -> str:
    """An XMPP error condition name (RFC 6120 vocabulary), or the type."""
    try:
        cond = getattr(exc, "condition", None) or exc.iq["error"]["condition"]
        if cond and str(cond).replace("-", "").isalpha():
            return str(cond)
    except Exception:
        pass
    return type(exc).__name__


def _registration_blocker(form) -> Optional[str]:
    """Why this XEP-0077 form cannot be filled with a username and password
    alone, or None. Read BEFORE the password is sent: a CAPTCHA or an extra
    required field means the submission would be refused anyway."""
    try:
        query = form["register"]
    except Exception:
        return None
    try:
        xform = query["form"]
        fields = xform.get_fields() if xform is not None else {}
    except Exception:
        fields = {}
    names = set(fields or {})
    try:
        ftype = fields["FORM_TYPE"].get_value() if "FORM_TYPE" in names else ""
    except Exception:
        ftype = ""
    if "urn:xmpp:captcha" in str(ftype) or names & {"ocr", "captcha", "qa",
                                                   "audio_recog", "picture_recog",
                                                   "speech_recog", "video_recog"}:
        return "registration_captcha_required"
    extra = []
    for name, field in (fields or {}).items():
        if name in ("FORM_TYPE", "username", "password"):
            continue
        try:
            required = field["required"]
        except Exception:
            required = False
        if required and field["type"] not in ("hidden", "fixed"):
            extra.append(name)
    if extra:
        return "registration_fields_required"
    return None


def _stream_failure_text(route, what: str) -> str:
    """Which layer a stream failure belongs to, by route."""
    if route.kind == _route_mod.CLEARNET_TLS:
        return ("the XMPP stream could not be established (%s): DNS, the TCP "
                "connection or the TLS handshake with the server failed. If "
                "TLS failed, the server's certificate may not be valid for "
                "its domain; nothing insecure was attempted instead." % what)
    if route.kind == _route_mod.TOR:
        return ("the XMPP stream could not be established (%s). The Tor "
                "circuit was open, so this is the server or the TLS "
                "handshake rather than Tor." % what)
    return ("the XMPP stream could not be established (%s). The SAM tunnel "
            "was open, so this is the server or the TLS handshake rather "
            "than I2P." % what)


def _enable_registration(client) -> None:
    """Turn a client into one that will create an account.

    XEP-0077 happens during stream negotiation, before authentication, so the
    plugin has to be registered on a client that has not connected yet -- a
    plugin added later never sees the feature go past.

    `force_registration` is set because without it slixmpp only attempts
    registration when the server has offered nothing else to do; a server that
    advertises SASL alongside `<register/>` would go straight to authenticating
    an account that does not exist, and the user would be told their password
    was wrong. With it, `xep_0077` filters the stream features so registration
    is negotiated first.

    Raises rather than warning, unlike the XEP-0199 registration in
    `_default_client_factory`. A keepalive that could not be registered
    degrades; a registration that could not be registered silently logs in
    instead, which is the failure this whole path exists to avoid.
    """
    client.register_plugin("xep_0077")
    plugin = client["xep_0077"]
    plugin.create_account = True
    plugin.force_registration = True


def _forwarder_log(message: str) -> None:
    """Where the forwarder's progress lines go on Android.

    Not `print`. Chaquopy routes stdout into logcat, and these lines name the
    I2P destination -- which CONTRIBUTING.md's rejection list puts alongside
    keys and plaintext as a thing that must not be logged. In a terminal the
    same string is feedback to the person who typed the address; in a system
    log that `adb logcat` reads, it is a record of who this device talks to.

    The stage is still worth knowing, so the message is reduced to whether a
    tunnel is being opened or is up, with the destination dropped.
    """
    text = str(message)
    if "established" in text:
        _log.info("i2p: SAM stream established")
    elif "local bridge ready" in text:
        _log.info("i2p: local bridge ready")
    elif "opening SAM stream" in text:
        _log.info("i2p: opening a SAM stream (a cold tunnel can take 30-90s)")


#: The steps of a connection over I2P or Tor, in order, each recorded in the
#: diagnostic log as it is reached ("connection" / <step>), and what it means
#: when the 300 s wait expires after that step and before the next. A device
#: report (2026-10-02) said only "did not finish within 300s": nothing
#: between "building tunnels" and "connected" was recorded, so a tunnel that
#: never opened and a server that never answered looked the same.
_PROGRESS_HINTS = {
    "starting": "the connection had not started",
    "sam_opening": (
        "the I2P tunnel to the server was never built. Usually the server's "
        "I2P tunnel is down or not yet published, or this phone's router has "
        "not integrated into the network yet (a freshly started router can "
        "need 5-10 minutes)"),
    "sam_established": "the I2P tunnel opened but the local bridge to it did not start",
    "tunnel_open": (
        "the I2P tunnel to the server opened, but the XMPP server never "
        "answered over it. Check that the server's XMPP service is running "
        "and that this is the address of its XMPP (port 5222) tunnel"),
    "stream_features": (
        "the XMPP server answered, but the encrypted (TLS) handshake or "
        "sign-in did not finish"),
    "tls": "the encrypted (TLS) connection was set up, but signing in did not finish",
    "signed_in": "signed in, but the session was not completed by the server",
}


#: What a server's stream error means for someone signing in, by RFC 6120
#: condition. Anything else is named as the condition.
_STREAM_ERROR_MEANINGS = {
    "host-unknown": (
        "the server does not host %(domain)s, the domain in your address. "
        "The account's domain must be one the server serves (Prosody: a "
        "VirtualHost \"%(domain)s\" in its configuration), or use an address "
        "on a domain it does serve"),
    "host-gone": "the server no longer hosts %(domain)s",
    "see-other-host": "the server sent this client to another host",
    "policy-violation": "the server refused this connection by its policy",
    "not-authorized": "the server refused this connection before sign-in",
    "system-shutdown": "the server is shutting down",
    "connection-timeout": "the server timed the connection out",
    "unsupported-version": "the server does not support this XMPP version",
}


def _tls_failure_text(reason: str, profile) -> str:
    """A TLS handshake failure over I2P/Tor, for a person. The certificate
    is never the cause there: it is not checked."""
    try:
        domain = str(profile.jid).rsplit("@", 1)[-1].split("/", 1)[0]
    except Exception:
        domain = "the server's domain"
    r = reason.upper()
    head = ("the TLS handshake with the server failed (%s). Any certificate "
            "is accepted over I2P, so this is not a certificate check: " % reason)
    if "HANDSHAKE_FAILURE" in r or "NO_SHARED_CIPHER" in r:
        return head + (
            "the server refused the handshake, which is what a server with "
            "no usable certificate and key for %s does. On the server: "
            "`prosodyctl check certs`, and make sure the prosody user can "
            "read the key file." % domain)
    if "UNRECOGNIZED_NAME" in r:
        return head + ("the server has no certificate configured for %s."
                       % domain)
    if "PROTOCOL_VERSION" in r or "UNSUPPORTED_PROTOCOL" in r:
        return head + ("the server offers only TLS versions older than 1.2.")
    if "INTERNAL_ERROR" in r:
        return head + ("the server reported an internal TLS error; its log "
                       "will say which.")
    return head + "the server's log will say why."


def _stream_error_text(condition: str, profile) -> str:
    try:
        domain = str(profile.jid).rsplit("@", 1)[-1].split("/", 1)[0]
    except Exception:
        domain = "the address's domain"
    meaning = _STREAM_ERROR_MEANINGS.get(condition)
    if meaning:
        return ("the server ended the stream with an error (%s): %s."
                % (condition, meaning % {"domain": domain}))
    return ("the server ended the stream with an error (%s) before sign-in."
            % condition)


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


class XmppTransport(Transport):
    """Carries OTR payloads between `OtrApp` and an XMPP server over I2P."""

    def __init__(
        self,
        profile: ConnectionProfile,
        password: str,
        *,
        on_payload: Callable[[str, str], None],
        on_presence: Optional[Callable[..., None]] = None,
        on_state: Optional[Callable[[str, str], None]] = None,
        on_subscription_request: Optional[Callable[[str], None]] = None,
        subscription_policy: str = SubscriptionPolicy.ACCEPT,
        client_factory: Optional[Callable[..., Any]] = None,
        forwarder: Optional[Callable[..., Any]] = None,
        tor_forwarder: Optional[Callable[..., Any]] = None,
        server_pins: Optional[Any] = None,
    ):
        profile.validate()
        if not profile.is_complete:
            raise TransportError(
                "profile_incomplete",
                "the connection profile has no account or no server")
        self._profile = profile
        self._password = password
        self._on_payload = on_payload
        #: Set by `set_room_handler`; None drops room messages.
        self._on_room_message: Optional[Callable[..., None]] = None
        self._on_presence = on_presence
        #: The route, decided once from the name (android_bridge.route).
        self._route = profile.route
        self._tor_forwarder = tor_forwarder
        #: X1: the I2P destination each human-readable name is trusted at.
        self._server_pins = server_pins
        #: Which resources speak OTRv4Plus. See otrv4plus_caps: OTRv4+
        #: traffic goes only to a resource this has confirmed.
        self._caps = _caps.CapabilityBook()
        #: The OTRv4Plus Welcome room: discovery only. See android_bridge.welcome.
        self._welcome = _welcome.WelcomeDirectory()
        #: bare room JID (lower case) -> the nickname we joined with.
        self._room_nicks: Dict[str, str] = {}
        #: Rooms whose join is in flight -> room messages held until the join
        #: completes. See `_begin_join`: without this, a room's history burst
        #: arriving in the same read as our self-presence reached the app
        #: before the room was registered, and was silently dropped.
        self._joining: Dict[str, list] = {}
        #: `handler(room)` once ANY room join succeeds, called on the loop
        #: thread before that room's held messages are delivered.
        self._on_room_joined: Optional[Callable[[str], None]] = None
        #: Called with a bare JID whenever its capability may have changed,
        #: and whether the resource an OTRv4+ session was pinned to left.
        self._on_capability: Optional[Callable[[str, bool], None]] = None
        self._on_state = on_state
        self._on_subscription_request = on_subscription_request
        self._subscription_policy = subscription_policy
        # Injected so the tests can drive the whole state machine without
        # slixmpp, a SAM bridge, or a network. Defaulted lazily rather than
        # here, because importing the real ones costs the engine.
        self._client_factory = client_factory
        self._forwarder = forwarder

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._client: Any = None
        self._connected = threading.Event()
        #: When the stream last DELIVERED something, on the monotonic clock.
        #:
        #: The keepalive's primary liveness evidence. Traffic proves the whole
        #: path without asking the server anything, so while it is arriving
        #: there is nothing worth probing -- and a probe whose reply is merely
        #: slow must not be read as silence. Initialised at construction so a
        #: session that has just started is not instantly "quiet".
        self._last_inbound = time.monotonic()
        self._lock = threading.RLock()
        #: Set by close(). After this the object is finished and no call may
        #: start a loop again -- see _ensure_loop.
        self._closed = False
        #: The in-flight connect, so another thread can cancel it. Android's
        #: Back button and a rotation both need to stop a four-minute tunnel
        #: build, and the Kotlin coroutine that called in cannot: a blocking
        #: JNI call is not interruptible by cancelling the coroutine around it.
        self._connect_future: Any = None
        #: What the SAM forwarder opened, so it can be closed again. Without
        #: this the sockets live on `loop._i2p_keep`, which is a keep-alive
        #: with no release.
        self._i2p_resources: List[Any] = []
        #: Outbound fragment-set counter, and the inbound partial sets. Both
        #: use otrv4plus_fragment -- the same code the terminal client calls,
        #: not a second implementation of the same wire format. That is the
        #: whole point: a phone and a laptop have to produce identical bytes
        #: or they cannot complete a DAKE with each other.
        #:
        #: No logging hooks. The terminal client passes its `_dbg` and a
        #: progress printer; here the equivalent would be logcat, and a
        #: fragment count is a statement about a specific message from a
        #: specific peer.
        self._frag_seq = 0
        self._reassembler = _fragment.Reassembler()
        #: The keepalive task, so a reconnect cannot leave two running.
        self._keepalive_task: Any = None

    # -- what this object says about itself -----------------------------------

    def __repr__(self) -> str:
        # Written out, never derived. A default repr on a class holding a
        # credential is one logging call away from putting it in a file.
        return ("<XmppTransport jid=%r server=%r route=%s connected=%s>"
                % (self._profile.jid, self._profile.effective_server,
                   getattr(getattr(self, "_route", None), "kind", "?"),
                   self.is_connected))

    __str__ = __repr__

    @property
    def profile(self) -> ConnectionProfile:
        return self._profile

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    # -- the loop thread ------------------------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Start the worker loop if it is not already running.

        A dedicated loop rather than whatever loop happens to be current:
        Chaquopy calls in from Kotlin threads that have none, and the one place
        this must never run is the Android main thread, where a tunnel build
        would be an ANR.
        """
        with self._lock:
            if self._closed:
                # A closed transport must never start a thread. It used to:
                # close() cleared _loop but left _client set, so the next
                # call -- and on Android there is always a next call, because
                # the chat screen polls every 500ms and shutdown races it --
                # went through _ensure_loop and got a brand new loop thread
                # that nothing would ever join. Verified before the fix: a
                # disconnect() after close() left one running.
                raise TransportError(
                    "closed", "this transport has been closed")
            if self._loop is not None and self._loop.is_running():
                return self._loop
            ready = threading.Event()
            loop = asyncio.new_event_loop()

            def run():
                asyncio.set_event_loop(loop)
                loop.call_soon(ready.set)
                loop.run_forever()

            thread = threading.Thread(
                target=run, name="otrv4plus-transport", daemon=True)
            thread.start()
            if not ready.wait(timeout=10):
                raise TransportError("loop_start_failed",
                                     "the transport's event loop did not start")
            self._loop, self._thread = loop, thread
            return loop

    def _run(self, coro, timeout: float):
        """Run *coro* on the loop thread and wait for it."""
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout)
        except TransportError:
            raise
        except TimeoutError:
            # Builtin TimeoutError, which since 3.11 is what both
            # concurrent.futures.TimeoutError and asyncio.TimeoutError alias.
            # This is the "no underlying exception" case: nothing raised, the
            # work simply never finished, and saying so is different from
            # saying it failed.
            future.cancel()
            raise TransportError(
                "timeout",
                "the operation did not finish within %gs and nothing raised. "
                "The connection was still in progress when the wait expired."
                % timeout)
        except Exception as exc:
            # The type, not the message. An exception raised inside slixmpp's
            # SASL path can quote what it was given.
            #
            # "unexpected_error" rather than "failed": anything reaching here
            # is a bug rather than a diagnosable condition, and it must not be
            # confusable with the `failed` STAGE, which is where every other
            # error also ends up.
            raise TransportError("unexpected_error", type(exc).__name__)

    # -- Transport ------------------------------------------------------------

    def connect(self) -> None:
        """Bring the stream up. Blocks; must not be called on a UI thread.

        Kept out of `_run` because this is the one call another thread needs to
        be able to stop: a cold tunnel is minutes, and Android will rotate the
        screen or send Back inside that window.

        IDEMPOTENT ON A LIVE STREAM, and that is not tidiness. `_connect_inner`
        builds a client and assigns `self._client` unconditionally, so a second
        call on a connected transport used to build a second slixmpp client and
        a second SAM tunnel and ORPHAN the first -- the reference was
        overwritten, so nothing would ever abort it or close its sockets.
        Measured:

            after 1st connect: clients=1 tunnels=1 connected=True
            after 2nd connect: clients=2 tunnels=2 connected=True
            the FIRST client was told to stop: False
            tunnel 0 sockets closed          : False

        The orphan is not merely a leak. It is still wired to `on_payload`, so
        inbound stanzas arrive twice; it is still authenticated, so the account
        stays present on a stream nobody is watching; and its I2P tunnel stays
        up for the life of the process.

        `_abandon` already gives back all three for a FAILED attempt -- "a
        connect that timed out left all three running ... so pressing Connect a
        second time built a second tunnel on top of the first". That fix did
        not cover the path where the first attempt SUCCEEDED, which is this
        one.

        Guarded on `is_connected` rather than on `_client`, so a stream the
        keepalive has found dead can still be reconnected: the keepalive clears
        that flag precisely when the link stops answering.
        """
        with self._lock:
            if self._connected.is_set() and self._client is not None:
                return
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._connect(), loop)
        with self._lock:
            self._connect_future = future
        try:
            future.result(timeout=CONNECT_TIMEOUT)
        except TransportError:
            raise
        except _CANCELLED:
            # BOTH CancelledErrors, because they are not the same class and
            # which one arrives depends on where the cancellation was noticed.
            # `asyncio.CancelledError` derives from BaseException (3.8+), so
            # `except Exception` would miss it; `concurrent.futures`' one does
            # derive from Exception, so `except Exception` would swallow it and
            # report `unexpected_error`. It did: the first cut of this method
            # named only the asyncio class and every cancelled connect came
            # back as an unexpected error.
            raise TransportError(
                "cancelled", "the connection attempt was cancelled")
        except TimeoutError:
            # Builtin TimeoutError, which since 3.11 is what both
            # concurrent.futures.TimeoutError and asyncio.TimeoutError alias.
            # Nothing raised; the work simply never finished. Cancelling is
            # what makes that true rather than merely reported -- without it
            # slixmpp's _connect_loop keeps rescheduling against a tunnel
            # nobody is waiting on any more.
            future.cancel()
            step = getattr(self, "_progress", "starting")
            _TRACE.record("connection", "timed_out", "error", last_step=step)
            raise TransportError(
                "timeout",
                "the operation did not finish within %gs and nothing raised. "
                "The connection was still in progress when the wait expired. "
                "Last step reached: %s -- %s."
                % (CONNECT_TIMEOUT, step, _PROGRESS_HINTS.get(step, step)))
        except Exception as exc:
            raise TransportError("unexpected_error", type(exc).__name__)
        finally:
            with self._lock:
                self._connect_future = None

    def cancel(self) -> None:
        """Stop an in-flight connect from another thread.

        The reason this exists rather than relying on the caller: Kotlin calls
        `connect` through Chaquopy, which is a blocking JNI call. Cancelling
        the coroutine that wrapped it does not interrupt the thread inside
        Python, so without this a rotation during a four-minute tunnel build
        leaves the old attempt running while the recreated screen starts a
        second one.

        Safe at any time, including when nothing is connecting.
        """
        with self._lock:
            future = self._connect_future
        if future is not None:
            future.cancel()

    # -- account creation -----------------------------------------------------

    def register_account(self) -> "tuple[str, str]":
        """Create the account named by this transport's profile. Blocks.

        Returns `(code, detail)` from `otrv4plus_registration` -- `("ok", ...)`
        when the server accepted, a classified failure otherwise. It does NOT
        raise: every outcome here is something the Register screen shows, and a
        TransportError would have to be translated at the call site anyway.

        WHY IT REGISTERS THE PROFILE'S OWN CREDENTIALS rather than taking a
        username and password of its own: the next thing the user does is sign
        in, and a transport that could register one account while being
        configured for another is a way to create an account nobody can then
        log into. Build the transport with what was typed on the form; this
        registers exactly that.

        WHY IT GOES THROUGH `_endpoint` AND `_make_client`: registration is not
        allowed to be the one operation that reaches the network some other
        way. Same SAM tunnel, same TLS decision, same local-end host and port
        -- a separate path here would be a second network policy with nothing
        holding it to the first, and the credential being sent is the one that
        matters most.

        The stream is always torn down before returning. Registration leaves
        slixmpp authenticated on some servers, and keeping that would mean two
        ways to arrive at a live session; `connect()` stays the only one.
        """
        problem = _registration.validate(
            _localpart(self._profile.jid), self._password)
        if problem is not None:
            _TRACE.record("registration", "refused_locally", "info",
                          code=problem[0])
            return problem

        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._register(), loop)
        # Recorded in the same slot a connect uses so `cancel()` stops this
        # too. A cold tunnel is minutes and Android will rotate the screen
        # inside that window whatever the screen happens to be.
        with self._lock:
            self._connect_future = future
        try:
            future.result(timeout=CONNECT_TIMEOUT)
        except BaseException as exc:                 # noqa: BLE001 -- see below
            # Deliberately everything, CancelledError included: `classify` is
            # total and answers "cancelled" for that case, and an exception
            # escaping here would reach Kotlin as a Chaquopy PyException with
            # the stanza still inside its message.
            code, detail = _registration.classify(exc)
            _TRACE.record("registration", "failed", "warn", code=code)
            return code, detail
        finally:
            with self._lock:
                self._connect_future = None
        _TRACE.record("registration", "succeeded", "info")
        return _registration.OK, _registration.describe(_registration.OK)

    async def _register(self) -> None:
        try:
            await self._register_inner()
        finally:
            # Unconditional, unlike `_connect`'s teardown which only runs on
            # failure. There is no session to keep here even when it worked.
            await self._abandon()

    async def _register_inner(self) -> None:
        try:
            host, port = await self._endpoint()
        except TransportError as exc:
            # `_endpoint` speaks the transport's vocabulary; the Register
            # screen speaks the registration module's. Translated here, where
            # both meanings are in scope, rather than by teaching `classify`
            # about transport codes it has no business knowing.
            raise _registration.RegistrationFailed(
                _REGISTRATION_CODES.get(exc.code, "unknown"))
        try:
            client = self._make_client()
        except Exception:
            raise _registration.RegistrationFailed("unknown")
        _enable_registration(client)
        self._client = client

        loop = asyncio.get_event_loop()
        done = loop.create_future()
        offered = {"register": False}

        async def on_register(form):
            """Submit the form XEP-0077 asked us to fill in.

            slixmpp fetches the form and fires this; the submission is ours to
            build. Errors are caught and put on `done` rather than allowed to
            escape, because this coroutine is awaited by slixmpp's feature
            negotiation and an exception in it is logged and dropped -- which
            is how a rejected registration turns into a silent wait for the
            300s timeout instead of "that username is taken".
            """
            offered["register"] = True
            blocker = _registration_blocker(form)
            _TRACE.record("registration", "form_received", "info",
                          fields=_form_field_names(form),
                          blocker=blocker or "none")
            if blocker is not None:
                # A CAPTCHA or an extra required field: the server would
                # refuse a username-and-password submission, so the password
                # is not sent at all.
                if not done.done():
                    done.set_exception(_registration.RegistrationFailed(blocker))
                return
            if self._route.verify_certificate and not _tls_in_place(client):
                # Clearnet (or a clearnet name over Tor): the form carries the
                # new password, and without TLS it would travel in the clear.
                # slixmpp does not insist on STARTTLS, so this does.
                if not done.done():
                    done.set_exception(
                        _registration.RegistrationFailed("tls_required"))
                return
            try:
                iq = client.Iq()
                iq["type"] = "set"
                iq["register"]["username"] = _localpart(self._profile.jid)
                iq["register"]["password"] = self._password
                _TRACE.record("registration", "submitted", "info")
                await iq.send()
            except Exception as exc:
                _TRACE.record("registration", "rejected", "info",
                              condition=_safe_condition(exc))
                if not done.done():
                    done.set_exception(exc)
            else:
                _TRACE.record("registration", "accepted", "info")
                if not done.done():
                    done.set_result(True)

        def on_session(_event):
            # Registration succeeded and slixmpp carried straight on into
            # SASL. Also the path on a server that never offered registration,
            # which `_register_inner` distinguishes below.
            if not done.done():
                done.set_result(True)

        def on_failed_auth(_event):
            if done.done():
                return
            # The account was not created and the server let us try to log in
            # as it anyway. That is the shape of a server with no in-band
            # registration, so say that rather than "wrong password" -- there
            # is no password to be wrong yet.
            done.set_exception(
                _registration.RegistrationFailed("unsupported"))

        watch = None
        if self._route.kind == _route_mod.CLEARNET_TLS:
            # Clearnet: every address is tried before giving up, and the
            # failure names its stage (see _StreamWatch).
            def fail(code, detail):
                if not done.done():
                    done.set_exception(
                        _registration.RegistrationFailed(code, detail))
            watch = _StreamWatch(client, self._route, fail, "registration")
            self._plan_clearnet_dns(client, watch, host)
        else:
            def on_connection_failed(event):
                if not done.done():
                    done.set_exception(ConnectionError(type(event).__name__))
            client.add_event_handler("connection_failed", on_connection_failed)
        self._watch_registration_discovery(client, done)

        client.add_event_handler("register", on_register)
        client.add_event_handler("session_start", on_session)
        client.add_event_handler("failed_auth", on_failed_auth)

        _TRACE.record("registration", "requested", "info")
        client.connect(host=host, port=port)
        try:
            await done
        finally:
            if watch is not None:
                watch.finish()

        if not offered["register"]:
            # The stream came up and authentication was reached without the
            # register feature ever appearing. Nothing was created, and
            # reporting success here would send the user to a sign-in screen
            # for an account that does not exist.
            raise _registration.RegistrationFailed("unsupported")
        # The server answered the registration as this name's server: pin
        # the destination it was reached at (X1; I2P names only).
        self._confirm_destination()

    def _plan_clearnet_dns(self, client, watch, host) -> None:
        """SRV-first address plan for a clearnet name (see dns_srv).

        Only when slixmpp was left to resolve (no explicit host): an explicit
        host:port is one attempt, and asyncio tries that host's addresses
        itself."""
        if host is not None or not hasattr(client, "get_dns_records"):
            watch.expected = 1
            return
        domain = self._route.host

        async def get_dns_records(_domain, port=None):
            loop = asyncio.get_event_loop()
            try:
                records, plan = await _clearnet_dns_records(
                    domain, loop, lookup=getattr(self, "_srv_lookup", None),
                    getaddrinfo=getattr(self, "_getaddrinfo", None),
                    fallback_port=int(getattr(client, "default_port",
                                              DEFAULT_C2S_PORT) or DEFAULT_C2S_PORT))
            except Exception as exc:                 # never let DNS code raise
                _TRACE.record("transport", "dns_plan_failed", "warning",
                              error=type(exc).__name__)
                records, plan = [], {}
            _TRACE.record("transport", "dns_plan", "info", **plan)
            watch.expected = max(1, len(records))
            if records:
                watch.stage = "tcp_connecting"
            return records

        client.get_dns_records = get_dns_records

    def _watch_registration_discovery(self, client, done) -> None:
        """The registration GET (XEP-0077 discovery) is sent by slixmpp's
        feature handler, where an error is logged and dropped -- a refused
        discovery used to be a silent wait for the timeout. Wrapped so its
        failure ends the attempt with its own code."""
        try:
            plugin = client["xep_0077"]
            original = plugin.get_registration
        except Exception:
            return

        async def get_registration(*args, **kwargs):
            _TRACE.record("registration", "discovery_requested", "info")
            try:
                return await original(*args, **kwargs)
            except Exception as exc:
                code, _ = _registration.classify(exc)
                if code == "unknown":
                    code = "registration_protocol_error"
                _TRACE.record("registration", "discovery_failed", "info",
                              code=code, condition=_safe_condition(exc))
                if not done.done():
                    done.set_exception(_registration.RegistrationFailed(code))
                raise

        plugin.get_registration = get_registration

    # -- probe: reach the server, sign in to nothing ----------------------------

    def probe_server(self) -> Dict[str, Any]:
        """DNS, TCP, TLS (certificate verified), the XMPP stream and its
        features, and XEP-0077 registration DISCOVERY -- then stop. Never
        authenticates and never submits a registration: the client carries an
        empty password and the SASL feature is removed before slixmpp sees
        it. Answers "unreachable" / "reached, registration offered or not" /
        "reached, then closed" / "reached, form needs a CAPTCHA". Blocks."""
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._probe(), loop)
        with self._lock:
            self._connect_future = future
        try:
            return future.result(timeout=CONNECT_TIMEOUT)
        except BaseException as exc:                 # noqa: BLE001
            code = getattr(exc, "code", None) or type(exc).__name__
            return {"ok": False, "code": str(code),
                    "detail": getattr(exc, "detail", "") or "", "reached": []}
        finally:
            with self._lock:
                self._connect_future = None

    async def _probe(self) -> Dict[str, Any]:
        try:
            return await self._probe_inner()
        finally:
            await self._abandon()

    async def _probe_inner(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"ok": False, "code": "", "detail": "",
                                  "route": self._route.kind, "reached": [],
                                  "register_offered": None,
                                  "registration_fields": "", "blocker": ""}
        try:
            host, port = await self._endpoint()
        except TransportError as exc:
            result.update(code=exc.code, detail=exc.detail)
            return result
        password, self._password = self._password, ""
        try:
            client = self._make_client()
        finally:
            self._password = password
        _enable_registration(client)
        self._client = client
        done = asyncio.get_event_loop().create_future()

        def finish(code, detail="", ok=False):
            if not done.done():
                result.update(ok=ok, code=code, detail=detail)
                done.set_result(True)

        watch = None
        if self._route.kind == _route_mod.CLEARNET_TLS:
            watch = _StreamWatch(client, self._route, finish, "probe")
            self._plan_clearnet_dns(client, watch, host)
        else:
            client.add_event_handler(
                "connection_failed",
                lambda e: finish("stream_failed", _stream_failure_text(
                    self._route, type(e).__name__)))

        def features(stanza):
            if type(stanza).__name__ != "StreamFeatures":
                return stanza
            names = [str(c.tag).rsplit("}", 1)[-1] for c in stanza.xml]
            for child in list(stanza.xml):
                if str(child.tag).endswith("}mechanisms"):
                    stanza.xml.remove(child)       # never authenticate
            if _tls_in_place(client):
                result["reached"].append("xmpp_stream")
                result["register_offered"] = "register" in names
                _TRACE.record("probe", "features", "info",
                              register="register" in names,
                              sasl="mechanisms" in names)
                if "register" not in names:
                    finish("registration_not_offered",
                           "Reached; TLS verified; the server does not "
                           "offer in-app registration.", ok=True)
            elif "starttls" not in names:
                finish("tls_required",
                       "Reached, but the server offered no TLS.")
            return stanza

        async def on_register(form):
            blocker = _registration_blocker(form)
            result["registration_fields"] = _form_field_names(form)
            result["blocker"] = blocker or ""
            result["reached"].append("registration_form")
            finish(blocker or "registration_available",
                   "Reached; TLS verified; registration form received "
                   "(%s)." % result["registration_fields"], ok=True)

        client.add_filter("in", features)
        client.add_event_handler("register", on_register)
        self._watch_registration_discovery(client, done)
        _TRACE.record("probe", "requested", "info", route=self._route.kind)
        client.connect(host=host, port=port)
        try:
            await done
        except _registration.RegistrationFailed as exc:
            result.update(code=exc.code, detail=_registration.describe(exc.code))
        finally:
            if watch is not None:
                watch.finish()
                result["reached"] = watch.reached + [
                    r for r in result["reached"] if r not in watch.reached]
        _TRACE.record("probe", "result", "info", code=result["code"],
                      reached=",".join(result["reached"]))
        return result

    async def _connect(self) -> None:
        try:
            await self._connect_inner()
        except BaseException:
            # Every failure path, cancellation included, gives back what it
            # took: the SAM tunnel, the local listening socket, and slixmpp's
            # retry loop. Before this, a connect that timed out left all three
            # running -- verified -- so pressing Connect a second time built a
            # second tunnel on top of the first, and the app degraded with
            # every attempt instead of recovering.
            await self._abandon()
            raise

    def _reached(self, step: str, **fields: Any) -> None:
        """Record a connection step (see _PROGRESS_HINTS). Never the
        destination, the password or a stanza."""
        self._progress = step
        _TRACE.record("connection", step, "info", **fields)

    def _forwarder_progress(self, message: str) -> None:
        """The forwarder's progress lines, as connection steps.

        `_forwarder_log` still decides what reaches logcat (never the
        destination); this records the step in the diagnostic log, which a
        report carries, and remembers it for a timeout message."""
        _forwarder_log(message)
        text = str(message)
        if "opening SAM stream" in text:
            self._reached("sam_opening")
        elif "ships for it" in text:
            # The project's server name, dialled at the address this version
            # ships for it (otrv4plus_address.SHIPPED_SERVERS). The step
            # stays sam_opening.
            _TRACE.record("connection", "shipped_address_used", "info")
        elif "established" in text:
            self._reached("sam_established")
        elif "I2P stream ended" in text:
            self._stream_ended(text)

    #: What the end of the I2P stream means, by (who ended it, bytes
    #: received, first byte kind). Recorded with the counts; never content.
    _STREAM_END_HINTS = {
        "silent": ("server sent nothing: its I2P server tunnel reaches nothing "
                   "that answers. Needs type=server, host 127.0.0.1, port "
                   "5222, and the XMPP server running"),
        "tls": ("server answered in TLS, not XMPP: its I2P tunnel points at "
                "the direct-TLS port (5223). Point it at 5222"),
        "other": ("server answered with something other than XMPP: the I2P "
                  "tunnel is the wrong type (needs type=server) or the wrong "
                  "port"),
    }

    def _stream_ended(self, text: str) -> None:
        import re
        m = re.search(r"ended by the (\w+): sent=(\d+) received=(\d+) "
                      r"first=(\w+)", text)
        if not m:
            return
        by, sent, got, first = m.group(1), int(m.group(2)), int(m.group(3)), \
            m.group(4)
        verdict = ("silent" if by == "server" and got == 0
                   else first if first in ("tls", "other") else "")
        fields = dict(ended_by=by, sent=sent, received=got, first=first)
        if verdict:
            fields["meaning"] = self._STREAM_END_HINTS[verdict]
        _TRACE.record("connection", "i2p_stream_ended",
                      "warning" if verdict else "info", **fields)

    def _watch_stages(self, client: Any) -> None:
        """Steps of the XMPP handshake over I2P/Tor, for the diagnostic
        record: the server answered (stream features), TLS is up, the account
        is signed in."""
        def features(stanza):
            if (type(stanza).__name__ == "StreamFeatures"
                    and getattr(self, "_progress", "") == "tunnel_open"):
                # Recorded, not emitted: the controller maps the transport's
                # later "connected" to its own "connecting", so a stage here
                # would make the screen step backwards.
                self._reached("stream_features")
            return stanza

        if hasattr(client, "add_filter"):
            client.add_filter("in", features)
        client.add_event_handler("tls_success", lambda _e: self._reached("tls"))
        client.add_event_handler("auth_success",
                                 lambda _e: self._reached("signed_in"))

    async def _connect_inner(self) -> None:
        self._progress = "starting"
        host, port = await self._endpoint()
        if self._route.kind != _route_mod.CLEARNET_TLS:
            # The tunnel is up; what is left is the XMPP handshake over it.
            self._reached("tunnel_open")
            self._emit_state("connecting")
        # Separately coded for the same reason as the forwarder above: a
        # slixmpp that will not import is a packaging fault, and reporting it
        # as a generic connect failure sends someone to look at their router.
        try:
            client = self._make_client()
        except Exception as exc:
            self._emit_state("failed")
            raise TransportError(
                "client_build_failed",
                "the XMPP client could not be built (%s)."
                % type(exc).__name__)
        self._wire(client)
        self._client = client
        started = asyncio.get_event_loop().create_future()

        def on_session(_event):
            if not started.done():
                started.set_result(True)

        def on_failed(_event):
            if started.done():
                return
            if self._route.verify_certificate and not _tls_in_place(client):
                started.set_exception(TransportError(
                    "tls_required",
                    "the server did not offer TLS, so no password was sent. "
                    "This app does not sign in over an unencrypted stream."))
                return
            started.set_exception(
                TransportError("auth_failed",
                               "the server rejected the account or password"))

        def on_no_auth(_event):
            # No mechanism this app allows was offered. Over I2P and Tor that
            # set is SCRAM only: a server (or an impostor) offering only
            # PLAIN would receive the password itself, so nothing is sent.
            if not started.done():
                started.set_exception(TransportError(
                    "no_safe_auth_mechanism",
                    "the server offers no sign-in method that keeps the "
                    "password off the wire (SCRAM). Nothing was sent."
                    if not self._route.verify_certificate else
                    "the server offers no sign-in method this app accepts."))

        def on_connection_failed(event):
            # slixmpp reschedules a failed connection rather than giving up
            # ("If everything fails, the connection is rescheduled for
            # later" -- XMLStream._connect_loop), so without this the retry
            # loop spins silently and the only thing that ever ends the wait
            # is the 300s timeout. An interactive Connect should say what
            # happened at the first failure, not five minutes later.
            if not started.done():
                started.set_exception(TransportError(
                    "stream_failed",
                    _stream_failure_text(self._route, type(event).__name__)))

        def on_stream_error(stanza):
            # Over I2P/Tor the server's own refusal -- `host-unknown` for a
            # domain it does not serve, above all -- was dropped: slixmpp
            # closed the stream, nothing failed the wait, and the attempt sat
            # until the 300 s timeout with the reason thrown away (device
            # report, 2026-10-02: 492 bytes of XMPP received, then nothing).
            # _StreamWatch does this on clearnet only. The condition is a
            # fixed RFC 6120 word and is traced; the server's free text is
            # not -- it can name hosts.
            try:
                cond = str(stanza["condition"] or "") or "unknown"
            except Exception:
                cond = "unknown"
            _TRACE.record("connection", "stream_error", "error",
                          condition=cond,
                          last_step=getattr(self, "_progress", ""))
            if not started.done():
                started.set_exception(TransportError(
                    "xmpp_stream_failure",
                    _stream_error_text(cond, self._profile)))

        def on_tls_error(exc):
            # slixmpp raises EVERY TLS failure as `ssl_invalid_chain` and logs
            # "Invalid certificate trust chain" -- wrongly here: over I2P/Tor
            # the certificate is not checked at all (CERT_NONE), so any
            # certificate is accepted. What fails is the handshake itself, and
            # the OpenSSL reason says which side and why. Device report,
            # 2026-10-02: STARTTLS offered and accepted, the client's hello
            # sent, a few bytes back, closed -- with no reason recorded.
            reason = (getattr(exc, "reason", None) or type(exc).__name__)
            _TRACE.record("connection", "tls_failed", "error",
                          reason=str(reason)[:80])
            if not started.done():
                started.set_exception(TransportError(
                    "tls_failed", _tls_failure_text(str(reason),
                                                    self._profile)))

        def on_early_disconnect(_event):
            # The stream ended before sign-in finished and nothing above said
            # why: say where it stopped now rather than after the timeout.
            # slixmpp signals `disconnected` BEFORE the `ssl_invalid_chain`
            # that carries a failed TLS handshake's reason (the device report
            # got the vague message, not the reason), so a precise event gets
            # half a second to land first -- as _StreamWatch does on clearnet.
            if started.done():
                return
            try:
                asyncio.get_event_loop().call_later(0.5, closed_before_sign_in)
            except RuntimeError:
                closed_before_sign_in()

        def closed_before_sign_in():
            if not started.done():
                step = getattr(self, "_progress", "starting")
                started.set_exception(TransportError(
                    "server_closed_connection",
                    "the server closed the connection before sign-in "
                    "finished. Last step reached: %s -- %s."
                    % (step, _PROGRESS_HINTS.get(step, step))))

        client.add_event_handler("session_start", on_session)
        client.add_event_handler("failed_auth", on_failed)
        client.add_event_handler("no_auth", on_no_auth)
        watch = None
        if self._route.kind == _route_mod.CLEARNET_TLS:
            # Every address before giving up, and the stage named -- the same
            # fault as registration had (see _StreamWatch).
            def fail(code, detail):
                if not started.done():
                    started.set_exception(TransportError(code, detail))
            watch = _StreamWatch(client, self._route, fail, "connection")
            self._plan_clearnet_dns(client, watch, host)
        else:
            client.add_event_handler("connection_failed", on_connection_failed)
            client.add_event_handler("stream_error", on_stream_error)
            client.add_event_handler("ssl_invalid_chain", on_tls_error)
            client.add_event_handler("disconnected", on_early_disconnect)
            self._watch_stages(client)

        # host= and port= point slixmpp at the local end of the SAM tunnel
        # rather than at a DNS lookup of the JID's domain. getaddrinfo is never
        # called on a .i2p name -- TRANSPORT_POLICY.md is emphatic about that,
        # and this is the line that keeps it true. slixmpp only skips its SRV
        # lookup when BOTH are given, so they must stay together.
        #
        # This said `address=(host, port)` until the first handset test, which
        # is an older slixmpp API that no longer exists: 1.17's signature is
        # connect(host, port). It raised TypeError before a socket was opened,
        # and the unit tests passed anyway because the fake client accepted
        # `address=` -- the fake encoded the same wrong assumption as the code
        # it was standing in for. tests/test_android_transport.py now binds
        # this call against the real slixmpp signature so a fake cannot agree
        # with a mistake again.
        client.connect(host=host, port=port)
        try:
            await started
        finally:
            if watch is not None:
                watch.finish()
        self._connected.set()
        _TRACE.record("auth", "allowed", "info", route=self._route.kind)
        self._confirm_destination()

        # WHAT A CLIENT OWES THE SERVER ONCE THE SESSION IS UP.
        #
        # None of this was here, and the symptom was reported from a handset:
        # a Termux user logged in as alice saw "bob went offline" over and
        # over while bob was sitting in the app, connected and authenticated.
        #
        # Authenticating is not the same as being present. RFC 6121 §4.2: a
        # client becomes an available resource by SENDING initial presence,
        # and until it does the server neither broadcasts it to contacts nor
        # delivers theirs. So the app was logged in and invisible -- to
        # everyone, permanently, with nothing on either side saying why.
        #
        # The terminal client has always done these three in `_on_start`.
        # This is the same three, in the same order.
        self._announce()

        _TRACE.record("transport", "session_started", "info",
                      jid=self._profile.jid,
                      server=self._profile.effective_server)
        self._emit_state("connected")

    def _announce(self) -> None:
        """Initial presence, the roster, and the keepalive.

        Ordered as the terminal client orders them: presence first, because
        it is what makes the account visible and costs one stanza; the roster
        second, because the contact list is empty without it; the keepalive
        last, because it is only worth running once there is a session to
        keep.

        Each is guarded separately. A server that refuses a roster fetch has
        not ended the session, and treating it as a connection failure would
        throw away a stream that works for messaging.
        """
        client = self._client
        if client is None:
            return
        # BEFORE the first presence, so the caps hash in it already carries
        # the OTRv4Plus feature: peers learn we speak it without asking twice.
        self._advertise(client)
        try:
            client.send_presence()
            _TRACE.record("presence", "initial_sent", "info")
        except Exception as exc:
            _log.warning("could not send initial presence")
            # RFC 6121 4.2: without this the account is logged in and
            # INVISIBLE -- the server broadcasts nothing and delivers no
            # contact presence. "Everyone shows offline" starts here.
            _TRACE.record_exception("presence", "initial_send_failed", exc)
        try:
            # Returns a Future rather than a coroutine in slixmpp 1.17, so
            # this schedules the IQ without awaiting its reply. The reply
            # populates client_roster, which `roster()` reads; the UI polls,
            # so it picks the contacts up on the next tick rather than
            # blocking the connect on a round trip.
            client.get_roster()
            _TRACE.record("roster", "requested", "info")
        except Exception as exc:
            _log.warning("could not request the roster")
            _TRACE.record_exception("roster", "request_failed", exc)
        self._start_keepalive()

    # -- keepalive ------------------------------------------------------------

    def _start_keepalive(self) -> None:
        """Start the keepalive task, replacing any predecessor.

        Cancelled first rather than reassigned: this runs on every session
        start, and orphaning a live loop would leave two probing the same
        stream and counting the same failures, reaching the threshold in half
        the time for no reason. That exact bug is documented in the terminal
        client's `_on_start`.
        """
        task, self._keepalive_task = self._keepalive_task, None
        if task is not None and not task.done():
            task.cancel()
        # The loop is named rather than inherited. `ensure_future` reaches for
        # whatever loop happens to be current, which on 3.12 is a
        # DeprecationWarning when there is not one -- and this object exists
        # precisely because Chaquopy calls in from threads that have no loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = self._loop
        if loop is None:
            _log.warning("no loop to run the keepalive on")
            return
        if loop.is_running() and threading.current_thread() is not self._thread:
            # Off the loop thread, so hand it over rather than touching the
            # loop's task set from here.
            self._keepalive_task = asyncio.run_coroutine_threadsafe(
                self._keepalive_loop(), loop)
        else:
            self._keepalive_task = loop.create_task(self._keepalive_loop())

    def _stop_keepalive(self) -> None:
        """Stop the keepalive task, unless it is the one asking.

        NEVER CANCELS ITSELF. `_declare_stream_dead` runs inside the keepalive
        loop and tears the stream down through `_abandon`, which stops the
        keepalive as one of the things it gives back. Cancelling the current
        task there would raise CancelledError at the next await INSIDE the
        teardown, so which of the three resources actually came back would
        depend on where that await happened to fall. The loop returns on its
        own line after the teardown, so nothing is left running.
        """
        task, self._keepalive_task = self._keepalive_task, None
        if task is None or task.done():
            return
        try:
            current = asyncio.current_task()
        except RuntimeError:                                 # pragma: no cover
            current = None                                   # no running loop
        if task is not current:
            task.cancel()

    async def _keepalive_loop(self) -> None:
        """Keep the stream alive, and notice when it is not.

        TWO MECHANISMS, because they answer different questions. This is the
        terminal client's design and its numbers; the reasoning there is worth
        repeating rather than re-deriving.

        **Whitespace, every 8 s.** Stops an idle I2P tunnel being torn down
        during the long silences of a DAKE, an SMP exchange, or a
        conversation where nobody is typing.

        **A round trip, every 60 s.** This is the one that matters. Writing
        to the socket succeeds whether or not anything is still listening at
        the far end, and over I2P that is not a corner case: the SAM stream
        can be gone while the local socket accepts writes indefinitely. A
        whitespace-only keepalive therefore reports a healthy stream forever,
        and -- in the terminal client's own words -- "the first symptom is the
        peer appearing to go offline".

        Which is precisely what was reported from the handset. The app had no
        keepalive of either kind.

        A XEP-0199 ping makes the server answer, so it proves the whole path
        rather than the first hop. An IqError counts as ALIVE: a server
        replying `service-unavailable` has demonstrated the stream works,
        which is the only thing being asked.

        Silent while it is working. A heartbeat line every 8 s reports
        nothing after the second one and buries the conversation it exists to
        protect.
        """
        failures = 0
        next_probe = asyncio.get_event_loop().time() + KEEPALIVE_PING_S
        try:
            while True:
                await asyncio.sleep(KEEPALIVE_WHITESPACE_S)
                client = self._client
                if client is None or not self.is_connected:
                    return

                try:
                    client.send_raw(" ")
                except Exception:
                    # The write itself failed, which the socket only reports
                    # when it is genuinely gone. Nothing to do here: the
                    # round trip below is the real detector, and slixmpp's
                    # own `disconnected` event clears `_connected`.
                    _log.info("keepalive whitespace write failed")

                # TRAFFIC OUTRANKS A PING. Anything the stream delivered
                # proves the whole path end to end without asking the server
                # for something, so while it is arriving there is nothing
                # worth probing. This gate is the terminal client's and was
                # missing here -- which is why the broken ping killed Android
                # sessions and never Termux ones.
                if self._stream_quiet_for() < KEEPALIVE_QUIET_S:
                    if failures:
                        _log.info("keepalive: the stream is delivering again")
                    failures = 0
                    continue

                now = asyncio.get_event_loop().time()
                if now < next_probe:
                    continue
                next_probe = now + KEEPALIVE_PING_S

                if await self._probe_stream():
                    if failures:
                        _log.info("keepalive: the stream answered again")
                    failures = 0
                    continue
                if self._stream_quiet_for() < KEEPALIVE_QUIET_S:
                    # The reply never came, but something else arrived while
                    # we waited. The path works and the ping was merely slow,
                    # which over three I2P hops is ordinary, not a fault.
                    failures = 0
                    continue
                failures += 1
                _log.info("keepalive: no answer (%d/%d)",
                          failures, KEEPALIVE_PING_FAILS)
                _TRACE.record("keepalive", "probe_unanswered", "warning",
                              failures=failures,
                              threshold=KEEPALIVE_PING_FAILS,
                              quiet_for=round(self._stream_quiet_for()))
                if failures >= KEEPALIVE_PING_FAILS:
                    await self._declare_stream_dead()
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.warning("the keepalive loop stopped unexpectedly")

    async def _probe_stream(self) -> bool:
        """Round-trip liveness against our own server. True if it answered.

        The round trip itself is `otrv4plus_ping.round_trip`, shared with the
        terminal client, because this is where the handset bug lived: the call
        was `async_ping`, which **slixmpp 1.17 does not have**. The
        AttributeError was classified as "no answer", so every probe failed and
        the keepalive tore down a healthy session about two minutes after it
        connected. See the module docstring there for the full chain.

        The three outcomes are kept distinct on purpose:

          * answered (including an IqError) -> alive;
          * nothing came back within the timeout -> dead;
          * we could not ask at all -> **alive**, because a client that cannot
            pose the question has learned nothing, and inventing a disconnect
            out of its own ignorance is the bug being fixed.
        """
        client = self._client
        if client is None:
            return False
        try:
            ping = client["xep_0199"]
        except Exception:
            # The plugin is not loaded, so there is no round trip to make.
            # Reporting "alive" is right: this must not manufacture a
            # disconnect out of a missing plugin.
            return True
        try:
            return await _ping.round_trip(
                ping, client.boundjid.host, KEEPALIVE_PING_TIMEOUT_S)
        except _ping.PingUnsupported:
            _log.warning("no usable XEP-0199 ping; "
                         "treating the stream as alive")
            return True
        except _CANCELLED:
            raise

    async def _declare_stream_dead(self) -> None:
        """Take the stream down so the app stops believing it is connected.

        Breaking out of the loop is not enough: it only stops pinging. The
        session has to actually end, or the UI shows a connection that cannot
        carry a message and the user retries into silence.

        AND IT HAS TO GIVE BACK WHAT IT TOOK. This called `client.disconnect()`
        and stopped there: the client reference stayed, and the I2P tunnel and
        its local listening socket stayed open. So every death-and-reconnect
        cycle -- which on a handset is every walk out of coverage -- left one
        behind. Measured:

            connected                  : clients=1 tunnels=1
            after the stream died      : tunnel 0 sockets closed: False
            after the reconnect        : clients=2 tunnels=2
                                         sockets still open: 6

        `_abandon` is the method that already returns all three, and it is
        what the FAILED-attempt path uses for exactly this reason. Using it
        here also upgrades the stop from `disconnect()` to `abort()`, which is
        the call that ends slixmpp's retry loop rather than merely closing the
        socket.
        """
        _log.info("keepalive: the stream is dead; disconnecting")
        # The single most important line in an export. An unexplained
        # DISCONNECTING on a handset is either this or an explicit user
        # action, and until now nothing on the device could tell them apart.
        _TRACE.record("keepalive", "stream_declared_dead", "error",
                      quiet_for=round(self._stream_quiet_for()),
                      consecutive_failures=KEEPALIVE_PING_FAILS,
                      server=self._profile.effective_server)
        await self._abandon()
        self._emit_state("disconnected")

    async def _abandon(self) -> None:
        """Give back everything a failed or cancelled attempt took.

        Runs on the loop thread. Three distinct things, and leaving any of them
        is its own bug:

        1. **slixmpp's retry loop.** `XMLStream._connect_loop` reschedules a
           failed connection rather than giving up, so a client that is simply
           dropped keeps dialling for the life of the process. `abort()` is the
           call that stops it; `disconnect()` is the fallback for a client that
           has not got one.
        2. **The I2P tunnel and the local listening socket.** Opened by the
           forwarder, and previously parked on `loop._i2p_keep` where nothing
           could reach them.
        3. **The reference to the client**, so a later call cannot find a
           half-dead one and believe it is usable.
        """
        self._connected.clear()
        self._stop_keepalive()
        # Partial sets belong to a session that is ending. They are fragments
        # of decrypted-to-be plaintext and there is nothing left to complete
        # them with, so they go rather than sitting in memory.
        self._reassembler.clear()
        client, self._client = self._client, None
        if client is not None:
            for method in ("abort", "disconnect"):
                fn = getattr(client, method, None)
                if fn is None:
                    continue
                try:
                    result = fn()
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    _log.warning("could not stop the XMPP client cleanly")
                break
            # slixmpp keeps the password in `credentials` for SASL. Drop it
            # with the client: a `str` cannot be wiped, but a reference that
            # outlives the connection is one more copy for no reason.
            try:
                creds = getattr(client, "credentials", None)
                if isinstance(creds, dict):
                    creds.clear()
            except Exception:
                pass
        self._release_i2p()

    def _release_i2p(self) -> None:
        """Close the forwarder's sockets. Safe to call more than once.

        Deliberately imports nothing. The first version called a helper in
        `otrv4plus_xmpp`, which is a twelve-thousand-line module that pulls in
        the Rust core -- so on the one path where the import was not already
        warm, teardown sat behind it and the sockets were still open when the
        caller looked. Measured, not feared: the timeout test closed nothing
        while the cancel test closed everything, and the only difference was
        whether that import had happened yet.

        Teardown runs when something has already gone wrong. It gets to depend
        on nothing.
        """
        resources, self._i2p_resources = self._i2p_resources, []
        # Reverse order: the writer before the SAM session that owns it.
        for obj in reversed(resources):
            for method in ("close", "disconnect"):
                fn = getattr(obj, method, None)
                if fn is None:
                    continue
                try:
                    fn()
                except Exception:
                    pass
                break

    def _pins(self):
        pins = getattr(self, "_server_pins", None)
        if pins is None:
            from . import server_pins as _pins_mod
            pins = self._server_pins = _pins_mod.default_store()
        return pins

    def _verify_destination(self, dest_b64: str) -> None:
        """X1: runs between NAMING LOOKUP and STREAM CONNECT (SAM worker
        thread). Raising here means no stream to that destination exists, so
        nothing -- no credential -- is ever sent to it."""
        from . import server_pins as _pins_mod
        route = self._route
        seen = _pins_mod.b32_of_destination(dest_b64)
        shipped = _address.shipped_server_address(route.host)
        if shipped:
            # The project's server: dialled at its shipped b32, which is the
            # key hash, so it is checked like a typed b32 and no pin is
            # consulted -- a pin left by an address book that mapped the name
            # elsewhere must not block the right server.
            if seen != shipped:
                _TRACE.record("i2p", "destination_mismatch", "error")
                raise _pins_mod.DestinationChanged(route.host, shipped, seen)
            _TRACE.record("i2p", "destination_accepted", "info",
                          basis="shipped address")
            return
        if route.self_authenticating:
            # A typed .b32.i2p IS the key hash: the router must hand back the
            # destination that hashes to it.
            if seen != route.host:
                _TRACE.record("i2p", "destination_mismatch", "error")
                raise _pins_mod.DestinationChanged(route.host, route.host, seen)
            _TRACE.record("i2p", "destination_accepted", "info",
                          basis="b32 address")
            return
        _TRACE.record("i2p", "hostname_resolved", "info")
        pins = self._pins()
        verdict = pins.check(route.host, seen)
        if verdict == "changed":
            _TRACE.record("i2p", "destination_changed", "error")
            _TRACE.record("auth", "blocked", "error",
                          reason="i2p destination changed")
            raise _pins_mod.DestinationChanged(
                route.host, pins.pinned(route.host) or "", seen)
        _TRACE.record("i2p", "destination_accepted", "info",
                      basis="pinned" if verdict == "match" else "first use")

    def _confirm_destination(self) -> None:
        """The attempt succeeded: pin a first-use or approved destination."""
        route = getattr(self, "_route", None)
        if route is None or route.kind != _route_mod.I2P_SAM \
                or route.self_authenticating:
            return
        if self._pins().confirm(route.host):
            _TRACE.record("i2p", "destination_pinned", "info")

    def _explicit_host(self) -> bool:
        """Whether a server other than the JID's own domain was given."""
        server = (self._profile.server or "").strip().lower()
        if not server:
            return False
        return self._route.host != _address.jid_domain(
            self._profile.jid).strip().lower()

    async def _endpoint(self):
        """Where slixmpp should point, by route (android_bridge.route).

        clearnet_tls: (None, None) when the server is the JID's own domain,
            so slixmpp does the standard SRV lookup and falls back to the
            domain on 5222; the server and port otherwise. System DNS, TCP,
            STARTTLS, a CA-valid certificate for the JID's domain.
        tor: a local forwarder into a SOCKS5 CONNECT; the name travels only
            inside the CONNECT and Tor resolves it. Never DNS.
        i2p_sam: a local forwarder into a SAM stream, after the destination
            check (X1). Never DNS.
        """
        route = self._route
        if route.kind == _route_mod.CLEARNET_TLS:
            srv = route.port is None and not self._explicit_host()
            _TRACE.record("transport", "clearnet_endpoint", "info", srv=srv)
            if srv:
                return None, None
            return route.host, route.port or DEFAULT_C2S_PORT
        if route.kind == _route_mod.TOR:
            try:
                forward = self._tor_forwarder or _default_tor_forwarder()
            except Exception as exc:
                self._emit_state("failed")
                raise TransportError(
                    "forwarder_import_failed",
                    "the Tor forwarder could not be loaded (%s)."
                    % type(exc).__name__)
            self._emit_state("building_tunnels")
            try:
                return await forward(
                    route.host, route.port or DEFAULT_C2S_PORT,
                    getattr(self._profile, "socks_host", "127.0.0.1"),
                    getattr(self._profile, "socks_port", 9050),
                    resources=self._i2p_resources, log=self._forwarder_progress)
            except Exception as exc:
                self._emit_state("failed")
                raise TransportError(
                    "tor_unavailable",
                    "Tor did not open a circuit to the server (%s). Nothing "
                    "was sent any other way." % type(exc).__name__)

        # Inside its own try, and separately coded. This import pulls in
        # otrv4plus_xmpp and therefore the whole engine, and it sat outside the
        # try below -- so a failure here escaped as a bare exception and was
        # reported as "failed: ModuleNotFoundError", which names neither the
        # stage nor the module. "The forwarder would not import" and "the
        # router would not answer" are different problems with different
        # remedies and they must not share a code.
        try:
            forward = self._forwarder or _default_forwarder()
        except Exception as exc:
            self._emit_state("failed")
            raise TransportError(
                "forwarder_import_failed",
                "the I2P forwarder could not be loaded (%s). This is a "
                "packaging fault, not a router problem."
                % type(exc).__name__)

        # Ask the signature rather than calling and catching TypeError. A
        # TypeError raised *inside* the forwarder looks identical from out
        # here, and retrying on one would open a second tunnel while the first
        # was still being built -- the precise failure this module exists to
        # avoid.
        extra = {}
        if _accepts(forward, "resources"):
            extra["resources"] = self._i2p_resources
        if _accepts(forward, "log"):
            extra["log"] = self._forwarder_progress
        if _accepts(forward, "aliases"):
            # The app reads no alias file: a name means what the router says.
            extra["aliases"] = False
        if _accepts(forward, "verify"):
            extra["verify"] = self._verify_destination
        else:
            # A forwarder that cannot check the destination could hand the
            # password to a substituted server (X1). Refuse rather than go on.
            self._emit_state("failed")
            raise TransportError(
                "forwarder_import_failed",
                "the I2P forwarder cannot verify the server's destination; "
                "refusing to connect without that check.")
        if "resources" not in extra:
            _log.info("the I2P forwarder does not accept resource handover; "
                      "its sockets will not be released on teardown")

        self._emit_state("building_tunnels")
        try:
            return await forward(
                route.host, route.port or DEFAULT_C2S_PORT,
                self._profile.sam_host, self._profile.sam_port, **extra)
        except Exception as exc:
            self._emit_state("failed")
            from . import server_pins as _pins_mod
            if isinstance(exc, _pins_mod.DestinationChanged):
                raise TransportError(
                    "i2p_destination_changed",
                    "SECURITY: %s now resolves to a DIFFERENT I2P destination "
                    "than the one this device trusted.\n"
                    "  trusted: %s\n  now:     %s\n"
                    "Nothing was sent to the new destination and you were not "
                    "signed in. If the server's operator confirms it moved, "
                    "trust the new address explicitly; otherwise someone may "
                    "be impersonating the server." % (exc.name, exc.pinned, exc.seen))
            raise _sam_failure(exc, route.host)

    # -- rooms: plaintext group chat ---------------------------------------------
    #
    # XEP-0045 group chat is NOT end-to-end encrypted, here or anywhere this
    # app runs: every occupant and the server read every message. It is kept
    # entirely apart from the OTR path -- a separate handler in, a separate
    # sender out -- so that no room message is ever handed to the engine and
    # no OTR frame is ever sent into a room.

    #: Longest nickname carried to the UI; a room controls this string.
    MAX_NICK = 64
    #: Longest room message carried to the UI.
    MAX_ROOM_BODY = 16 * 1024

    def set_room_handler(self, handler: Optional[Callable[..., None]]) -> None:
        """`handler(room, nick, body, timestamp)` for each room message."""
        self._on_room_message = handler

    def set_room_joined_handler(self,
                                handler: Optional[Callable[[str], None]]) -> None:
        """`handler(room)` when a join succeeds, BEFORE any of that room's
        messages are delivered. The app registers the room here, so nothing
        the room sends on arrival can reach it as an unknown room."""
        self._on_room_joined = handler

    #: Messages held per joining room. A room's history on join is bounded by
    #: the service (Prosody: 20 by default); this caps a hostile one.
    MAX_HELD_ROOM_MESSAGES = 200

    @staticmethod
    def _room_key(room) -> str:
        return str(room).split("/", 1)[0].strip().lower()

    def _held(self) -> Dict[str, list]:
        # getattr: several tests build a transport without __init__.
        held = getattr(self, "_joining", None)
        if held is None:
            held = self._joining = {}
        return held

    def _begin_join(self, room) -> None:
        """Hold this room's messages until `_end_join`. Idempotent."""
        self._held().setdefault(self._room_key(room), [])

    def _end_join(self, room, ok: bool) -> None:
        """Finish a join. On success: register the room with the app (on
        this, the loop thread), THEN deliver what arrived meanwhile, in
        order. On failure: drop it -- we are not in that room."""
        held = self._held().pop(self._room_key(room), None)
        if not ok:
            return
        handler = getattr(self, "_on_room_joined", None)
        if handler is not None:
            try:
                handler(str(room))
            except Exception:
                _log.warning("the room-joined handler raised")
        for args, kwargs in held or ():
            self._deliver_room_message(*args, **kwargs)

    def _deliver_room_message(self, *args, **kwargs) -> None:
        if getattr(self, "_on_room_message", None) is None:
            return
        try:
            self._on_room_message(*args, **kwargs)
        except Exception:
            _log.warning("the room message handler raised")

    @classmethod
    def _clean(cls, text: str, limit: int) -> str:
        """Drop control characters (other than newline and tab) and cap length.

        A nickname and a body are chosen by other people. Neither may carry
        a bidi override or a terminal escape into a screen that renders it.
        """
        out = []
        for ch in str(text or "")[:limit]:
            code = ord(ch)
            if ch in "\n\t" or (code >= 0x20 and code != 0x7F
                                  and not 0x202A <= code <= 0x202E
                                  and not 0x2066 <= code <= 0x2069):
                out.append(ch)
        return "".join(out)

    def _our_nick(self, room: str) -> str:
        """Our nickname in *room*, or "".

        slixmpp keeps it as `our_nicks[pfrom][room]` -- TWO levels, with
        pfrom None for a client -- and the room key may be a JID or a string
        in whatever case it was joined with. Reading one level (as this
        did) always found nothing, so our own reflected room messages were
        shown again as if somebody else had sent them: "hello" from Alice,
        on Alice's phone. The nickname we joined with is also recorded here
        on every successful join, as the first answer.
        """
        want = str(room).split("/", 1)[0].lower()
        mine = getattr(self, "_room_nicks", {}).get(want)
        try:
            table = self._client["xep_0045"].our_nicks
        except Exception:
            return mine or ""

        def scan(mapping):
            for key, value in dict(mapping or {}).items():
                if isinstance(value, dict):
                    found = scan(value)
                    if found:
                        return found
                elif str(key).split("/", 1)[0].lower() == want and value:
                    return str(value)
            return ""

        try:
            # slixmpp's current nickname wins: the service may have changed it.
            return scan(table) or mine or ""
        except Exception:
            return mine or ""

    def _on_groupchat(self, stanza) -> None:
        """One room message, up to the handler. Our own echo is dropped.

        XEP-0045 §7.2.3 reflects every message back to its sender. The UI
        already shows what we sent, so the reflection would be a duplicate.
        A subject change carries no body and is skipped.
        """
        if self._on_room_message is None:
            return
        try:
            sender = stanza["from"]
            room = str(sender.bare)
            nick = self._clean(str(sender.resource), self.MAX_NICK)
            body = self._clean(stanza["body"] or "", self.MAX_ROOM_BODY)
        except Exception:
            _log.warning("could not read a room message")
            return
        if not body or not nick:
            return
        own = nick == self._our_nick(room)
        # Our own reflection is dropped -- except a secure group's MLS frames,
        # which need it: a commit learns it won the epoch by coming back
        # first (android_bridge.groups). Plain text of ours stays dropped.
        if own and not body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            return
        stamp = 0.0
        try:
            delay = stanza["delay"]["stamp"]
            if delay:
                stamp = delay.timestamp()
        except Exception:
            stamp = 0.0
        if own:
            args, kwargs = (room, nick, body, stamp or time.time()), {"own": True}
        else:
            args, kwargs = (room, nick, body, stamp or time.time()), {}
        held = self._held().get(self._room_key(room))
        if held is not None:
            # Our join is still completing: hold it, bounded, for _end_join.
            if len(held) < self.MAX_HELD_ROOM_MESSAGES:
                held.append((args, kwargs))
            return
        self._deliver_room_message(*args, **kwargs)

    def send_room_message(self, room: str, body: str) -> None:
        """Send plaintext to a room we are in. Raises TransportError."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._send_room(room, body), CALL_TIMEOUT)

    async def _send_room(self, room: str, body: str) -> None:
        self._client.send_message(mto=room, mbody=body, mtype="groupchat")

    def room_occupants(self, room: str) -> "tuple[str, str, list]":
        """Who is in a room: `[{nick, role, affiliation}]`, moderators first."""
        return self._room_call(self._room_occupants(room))

    async def _room_occupants(self, room: str):
        muc = self._client["xep_0045"]
        order = {_muc.MODERATOR: 0, _muc.PARTICIPANT: 1, _muc.VISITOR: 2}
        people = []
        for nick in list(muc.get_roster(room) or []):
            def prop(name, nick=nick):
                try:
                    return str(muc.get_jid_property(room, nick, name) or "")
                except Exception:
                    return ""
            people.append({
                "nick": self._clean(nick, self.MAX_NICK),
                "role": prop("role") or _muc.NO_ROLE,
                "affiliation": prop("affiliation") or _muc.NONE,
            })
        people.sort(key=lambda p: (order.get(p["role"], 3), p["nick"].casefold()))
        return people

    def send(self, peer: str, payload: str) -> None:
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        # THE WIRE-LEVEL RULE. OTRv4+ protocol traffic goes to one full JID
        # that has been identified as OTRv4Plus-capable, never to the bare
        # JID (the server would pick a resource) and never to a resource that
        # has not said it speaks the protocol. Enforced here, where every
        # frame passes -- DAKE, data, SMP, call and file signalling -- so no
        # caller can get around it by forgetting to ask.
        if _caps.is_otr_protocol(payload):
            target = self._caps.target(_caps.split_jid(peer)[0])
            if target is None:
                _TRACE.record("otr", "refused_no_capable_resource", "warning",
                              jid=peer,
                              state=self._caps.state(_caps.split_jid(peer)[0]))
                raise TransportError(
                    "otrv4plus_unavailable",
                    "no resource of this contact is known to support OTRv4Plus")
            self._caps.pin(peer, _caps.split_jid(target)[1])
            peer = target
        self._run(self._send(peer, payload), CALL_TIMEOUT)

    # -- OTRv4Plus capability -------------------------------------------------

    def set_capability_handler(self, handler) -> None:
        """`handler(bare_jid, pinned_resource_left)` on any capability change."""
        self._on_capability = handler

    def otr_capability(self, peer: str) -> str:
        """One of otrv4plus_caps.STATES for *peer*'s bare JID."""
        return self._caps.state(_caps.split_jid(peer)[0])

    def inbound_progress(self, peer: str):
        """(parts received, parts expected) of a frame still arriving from
        *peer* in fragments, or None. For the handshake progress bar."""
        try:
            return self._reassembler.progress(peer) or \
                self._reassembler.progress(str(peer).lower())
        except Exception:
            return None

    def otr_resources(self, peer: str) -> Dict[str, Optional[bool]]:
        return self._caps.resources(_caps.split_jid(peer)[0])

    def _advertise(self, client) -> None:
        """Add the OTRv4Plus feature to our disco#info (and so our caps)."""
        try:
            client["xep_0030"].add_feature(_caps.FEATURE)
        except Exception:
            _log.warning("could not advertise OTRv4Plus in service discovery")
            return
        try:
            caps = client["xep_0115"]
            caps.caps_node = _caps.CAPS_NODE
            # Async: it computes the new hash and, with broadcast, sends our
            # presence again carrying it. The first presence may carry the
            # old hash; the re-broadcast corrects it.
            result = caps.update_caps()
            if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                asyncio.ensure_future(result)
        except Exception:
            # Without XEP-0115 peers still find the feature by asking our
            # disco#info directly; they only lose the cache.
            _log.warning("could not publish entity capabilities")

    def _notify_capability(self, bare: str, pinned_left: bool = False) -> None:
        handler = self._on_capability
        if handler is None:
            return
        try:
            handler(bare, pinned_left)
        except Exception:
            _log.warning("the capability handler raised")

    async def _query_caps(self, full_jid: str) -> None:
        """Ask one resource's disco#info whether it speaks OTRv4Plus."""
        bare = _caps.split_jid(full_jid)[0]
        try:
            info = await self._client["xep_0030"].get_info(
                jid=full_jid, timeout=CALL_TIMEOUT)
            features = [str(f) for f in info["disco_info"]["features"]]
            self._caps.disco_result(full_jid, features)
        except Exception:
            self._caps.disco_failed(full_jid)
        _TRACE.record("otr", "capability_checked", "info", jid=bare,
                      state=self._caps.state(bare))
        self._notify_capability(bare)

    async def _send(self, peer: str, payload: str) -> None:
        """One stanza per fragment, through the shared wire format.

        This used to send the payload whole, which is why an Android peer and
        a Termux peer could not complete a DAKE. A DAKE2 is about 11.7 KB
        after base64 -- 1568 bytes of ML-KEM ciphertext, a 2592-byte ML-DSA-87
        public key and a 4627-byte signature -- and that goes straight at the
        ~8 KB I2P cliff that `otrv4plus_fragment.MAX_FRAGMENT` exists to stay
        under.

        `fragment` returns `[payload]` unchanged for anything at or below the
        threshold, so an ordinary message still goes out exactly as it did.
        """
        parts, self._frag_seq = _fragment.fragment(payload, self._frag_seq)
        for part in parts:
            self._client.send_message(mto=peer, mbody=part, mtype="chat")

    def disconnect(self) -> None:
        if self._client is None or self._closed:
            # Closed is not an error to report here: disconnecting something
            # already finished with is what a lifecycle callback does, and
            # raising would turn tidy shutdown into a crash.
            return
        try:
            self._run(self._disconnect(), CALL_TIMEOUT)
        except TransportError:
            # Tearing down is best effort: a disconnect that raises would
            # leave the app believing it is still connected, which is worse
            # than a socket that closes untidily.
            _log.warning("transport disconnect did not complete cleanly")
        finally:
            self._connected.clear()
            self._emit_state("disconnected")

    async def _disconnect(self) -> None:
        client = self._client
        if client is not None:
            client.disconnect()
        # The tunnel goes with the session it carried. Leaving it open would
        # hold an I2P lease and a listening local socket for a connection that
        # no longer exists, and the next connect would build a second one.
        self._release_i2p()

    def roster(self) -> List[Dict[str, Any]]:
        if self._client is None:
            return []
        # On the loop thread like everything else. slixmpp mutates the roster
        # from its own coroutines as presence and roster pushes arrive, and
        # iterating it from a Kotlin thread is a data race that would show up
        # as an occasional empty contact list rather than as a crash.
        try:
            entries = self._run(self._roster(), CALL_TIMEOUT)
            # The screen polls this about twice a second. Recorded on every
            # call, it filled the 4000-entry diagnostic ring in minutes and a
            # report lost the connection steps it was sent to explain (57568
            # events dropped, device report 2026-10-02). Only a change now.
            if len(entries) != getattr(self, "_roster_traced", None):
                self._roster_traced = len(entries)
                _TRACE.record("roster", "read", "info", entries=len(entries))
            return entries
        except TransportError as exc:
            _log.warning("could not read the roster")
            _TRACE.record_exception("roster", "read_failed", exc)
            return []

    #: What a roster entry is asked for, and what it means when absent.
    #:
    #: SUBSCRIPTED BY KEY, NEVER `.get()`. `slixmpp.roster.RosterItem` has no
    #: `.get` -- it defines `__getitem__` over a fixed `_state` and raises
    #: KeyError for anything else. `entry.get("name")` therefore raised
    #:
    #:     AttributeError: 'RosterItem' object has no attribute 'get'
    #:
    #: on the FIRST entry, the blanket `except` below returned [], and every
    #: poll produced an empty contact list. On a handset that was "no contacts,
    #: no online users, adding somebody does nothing" -- and the only way
    #: anybody ever appeared was an inbound message, which reaches the screen
    #: through the message store instead of the roster.
    #:
    #: Subscripting works on a RosterItem AND on a plain dict, so it is
    #: correct for the real object and for any stand-in.
    _ROSTER_FIELDS = (("name", ""), ("subscription", ""), ("pending_out", False))

    @staticmethod
    def _roster_field(entry, key, default):
        """One field of a roster entry, or *default*.

        KeyError is the documented answer for a key `RosterItem` does not
        carry, and TypeError covers a stand-in that is not subscriptable at
        all. Neither is a reason to lose the contact, let alone the roster.
        """
        try:
            value = entry[key]
        except (KeyError, TypeError, IndexError):
            return default
        return default if value is None else value

    async def _roster(self) -> List[Dict[str, Any]]:
        """The roster as plain dicts, per entry.

        GUARDED PER ENTRY, not once around the loop. It used to be the latter,
        so the first entry that raised anything discarded the whole contact
        list -- which is exactly what happened: one AttributeError on entry
        one, and the user had no contacts at all.

        `OtrApp.contacts()` already guards per entry for this reason and says
        so ("losing the whole contact list to one awkward peer is how a
        working roster renders as an empty screen"). That reasoning was right
        and this layer did not follow it.

        A failure is still RECORDED, per entry and by JID, so a roster that is
        partly unreadable says so in the diagnostics instead of looking empty.
        """
        out: List[Dict[str, Any]] = []
        client = self._client
        if client is None:
            return out
        try:
            jids = list(client.client_roster)
        except Exception as exc:
            # The roster object itself is unusable. Distinct from an entry
            # failing, and the only case where returning [] is honest.
            _log.warning("could not iterate the roster")
            _TRACE.record_exception("roster", "iterate_failed", exc)
            return out

        for jid in jids:
            try:
                entry = client.client_roster[jid]
                out.append({
                    "jid": str(jid),
                    "name": self._roster_field(entry, "name", "") or "",
                    "subscription":
                        self._roster_field(entry, "subscription", "") or "",
                    # Separate from `subscription`: a request that has been
                    # sent and not yet answered leaves the subscription at
                    # "none", so without this "added, waiting for them" and
                    # "on the roster, not subscribed" look identical.
                    "pending": bool(
                        self._roster_field(entry, "pending_out", False)),
                })
            except Exception as exc:
                _log.warning("could not read one roster entry")
                _TRACE.record_exception("roster", "entry_failed", exc)
                continue
        if (len(out), len(jids)) != getattr(self, "_roster_iter_traced", None):
            self._roster_iter_traced = (len(out), len(jids))
            _TRACE.record("roster", "iterated", "info",
                          entries=len(out), seen=len(jids))
        return out

    def run_on_loop_thread(self, fn, timeout: float = CALL_TIMEOUT):
        """Run a plain callable on the loop thread, or here if there is none.

        For work that must happen on the thread that processes inbound OTR --
        the engine wipe, above all. `DakeOutput` is `unsendable`: PyO3 lets
        only its creating thread touch it, and dropping it anywhere else LEAKS
        it instead of zeroizing it. Inbound frames are handled on this loop,
        so that is where a pending DAKE output was made and where it must be
        destroyed.

        Never STARTS a loop to do it: a transport whose loop is gone has no
        thread-bound objects left to honour, so the callable runs inline.
        """
        with self._lock:
            loop = self._loop
        if loop is None or loop.is_closed() or not loop.is_running():
            return fn()

        async def _call():
            return fn()

        future = asyncio.run_coroutine_threadsafe(_call(), loop)
        return future.result(timeout=timeout)

    def close(self) -> None:
        """Finish with this transport. Safe to call more than once.

        After this the object is spent: every method raises `closed` rather
        than starting a loop. That is the point. It used to leave `_client`
        set and `_loop` cleared, so the next call -- and on Android the chat
        screen polls every 500ms, so there is always a next call -- went
        through `_ensure_loop` and got a fresh worker thread nothing would
        ever join.
        """
        with self._lock:
            already = self._closed
            self._closed = True
            future = self._connect_future
            loop = self._loop
            thread = self._thread
            self._loop = None
            self._thread = None
        if already and loop is None:
            return

        # Stop an attempt that is still running, or the teardown below waits
        # behind a tunnel build.
        if future is not None:
            future.cancel()

        if loop is not None and loop.is_running():
            # On the loop thread, and bounded: teardown that hangs is a worse
            # failure than teardown that gives up, because the caller is
            # usually a lifecycle callback that must return.
            done = threading.Event()

            async def shut():
                try:
                    await self._abandon()
                finally:
                    done.set()

            try:
                asyncio.run_coroutine_threadsafe(shut(), loop)
                done.wait(timeout=CLOSE_TIMEOUT)
            except Exception:
                _log.warning("the transport did not shut down cleanly")
            loop.call_soon_threadsafe(loop.stop)
        else:
            # No loop to do it on; do what can be done from here.
            self._release_i2p()

        if thread is not None:
            thread.join(timeout=CLOSE_TIMEOUT)
            if thread.is_alive():
                _log.warning("the transport's worker thread did not stop")
        self._connected.clear()
        # Spent: nothing will reconnect with this object again, so it no longer
        # needs the password it kept for SASL on reconnect. Dropping the
        # reference is all Python allows -- a str cannot be overwritten -- and
        # is the difference between one copy for the connection's life and
        # one for the process's.
        self._password = ""
        self._emit_state("disconnected")

    # -- slixmpp wiring -------------------------------------------------------

    def _make_client(self):
        factory = self._client_factory or _default_client_factory()
        client = factory(self._profile.jid, self._password)
        self._apply_tls_policy(client)
        return client

    def _apply_tls_policy(self, client) -> None:
        """Relax certificate checking where the address is already the key.

        Without this the app hung. slixmpp's default context is
        `check_hostname=True, verify_mode=CERT_REQUIRED` with the system trust
        store, and it validates against `default_domain` -- the JID's domain.
        Over I2P nothing in that path is CA-signed, so STARTTLS failed; and
        `XMLStream._connect_loop` reschedules a failed connection rather than
        giving up, so neither `session_start` nor `failed_auth` ever fired and
        the connect sat until its 300s timeout with nothing to report.

        The terminal client has always done this -- see
        `endpoint_authenticated_by` -- and it does it automatically, precisely
        so nobody has to type a flag with "insecure" in its name for a link
        that is not insecure. The transport reimplemented everything around
        this and quietly omitted it.

        This is NOT a weakening. The `.b32.i2p` address is the hash of the
        server's key; the SAM stream reaches that key-holder or it fails, and
        I2P encrypts it end to end. On clearnet this does nothing at all and
        the certificate is still required.
        """
        by = endpoint_authenticated_by(self._profile)
        self._tls_policy = ("certificate required"
                            if by is None
                            else "certificate checks off, endpoint "
                                 "authenticated by %s" % by)
        if by is None:
            # Clearnet (or a clearnet name over Tor): slixmpp's default
            # context, CERT_REQUIRED with hostname checking against the JID's
            # domain and the system trust store. Nothing here relaxes it.
            return
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        client.ssl_context = ctx
        _restrict_to_scram(client)
        self._tls_policy += "; SCRAM only (no PLAIN)"

    @property
    def tls_policy(self) -> str:
        """What was actually decided, for the report to state rather than claim."""
        return getattr(self, "_tls_policy", "not yet decided")

    # -- roster ---------------------------------------------------------------

    def add_contact(self, jid: str, name: str = "") -> None:
        """Ask *jid* to let us see their presence, and put them on the roster.

        Two separate things in XMPP and worth keeping separate here: the roster
        entry is local bookkeeping, the subscription is a request the other
        side answers. `add_contact` does both because a contact you cannot see
        is not what anyone means by adding one.
        """
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._add_contact(jid, name), CALL_TIMEOUT)

    async def _add_contact(self, jid: str, name: str) -> None:
        self._client.update_roster(jid, name=name or None)
        self._client.send_presence_subscription(pto=jid, ptype="subscribe")

    def remove_contact(self, jid: str) -> None:
        """Drop the roster entry and both directions of subscription."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._remove_contact(jid), CALL_TIMEOUT)

    async def _remove_contact(self, jid: str) -> None:
        self._client.send_presence_subscription(pto=jid, ptype="unsubscribe")
        self._client.update_roster(jid, subscription="remove")

    def answer_subscription(self, jid: str, approve: bool) -> None:
        """Answer a request that `SubscriptionPolicy.ASK` handed to the UI.

        Only meaningful under ASK. Under ACCEPT slixmpp has already answered
        before the UI sees anything, which is the point of that policy.
        """
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._answer_subscription(jid, approve), CALL_TIMEOUT)

    async def _answer_subscription(self, jid: str, approve: bool) -> None:
        self._client.send_presence_subscription(
            pto=jid, ptype="subscribed" if approve else "unsubscribed")

    @property
    def subscription_policy(self) -> str:
        return self._subscription_policy

    # -- discovery and rooms --------------------------------------------------
    #
    # XEP-0030 and XEP-0045, neither of which was registered on this client
    # before. Every method here returns a `(code, detail, value)` triple rather
    # than raising, for the same reason `register_account` does: the caller is
    # Kotlin through a controller, and an exception crossing Chaquopy arrives
    # as a PyException whose message -- which for a MUC error contains the room
    # and the nickname -- is the only thing that survives.
    #
    # The timeout is CONNECT_TIMEOUT rather than CALL_TIMEOUT. Joining a room
    # is a presence round trip plus the room's history, over three I2P hops;
    # slixmpp's own default for `join_muc_wait` is 300s, and a shorter one here
    # would report a timeout for something still in flight.

    def discover_services(self) -> "tuple[str, str, list]":
        """What the server hosts: its disco#items, each with its identity.

        The MUC service is what this is really for -- it is conventionally
        `conference.<domain>` and conventionally is not, and guessing wrong
        costs an I2P round trip to find out.
        """
        return self._room_call(self._discover_services())

    async def _discover_services(self):
        disco = self._client["xep_0030"]
        domain = str(self._client.boundjid.domain)
        items = await disco.get_items(jid=domain, timeout=CALL_TIMEOUT)
        out = []
        for jid, _node, name in items["disco_items"].get_items():
            entry = {"jid": str(jid), "name": str(name or ""),
                     "category": "", "type": ""}
            try:
                # Asked per item, because disco#items gives a name and nothing
                # about what the thing IS. Failures are swallowed per item: one
                # component that will not answer must not empty the list.
                info = await disco.get_info(jid=jid, timeout=CALL_TIMEOUT)
                for category, itype, _lang, iname in \
                        info["disco_info"]["identities"]:
                    entry["category"] = str(category)
                    entry["type"] = str(itype)
                    if not entry["name"]:
                        entry["name"] = str(iname or "")
                    break
                entry["features"] = [str(f) for f
                                     in info["disco_info"]["features"]]
            except Exception:
                _log.info("a service did not answer a disco#info")
            out.append(entry)
        return out

    def discover_rooms(self, service: str) -> "tuple[str, str, list]":
        """The public rooms a MUC service lists.

        Only the public ones: disco#items is what a service chooses to
        advertise, and a room configured as hidden is absent by design. An
        empty list is not evidence that a service has no rooms.
        """
        return self._room_call(self._discover_rooms(service))

    #: Rooms whose occupant count is asked for, and how many at once. One
    #: disco#info per room: bounded so a service listing thousands of rooms
    #: costs a few seconds, not a flood.
    ROOM_INFO_LIMIT = 100
    ROOM_INFO_PARALLEL = 8
    ROOM_INFO_TIMEOUT = 8

    async def _discover_rooms(self, service: str):
        disco = self._client["xep_0030"]
        items = await disco.get_items(jid=service, timeout=CALL_TIMEOUT)
        rooms = [{"jid": str(jid), "name": str(name or ""), "occupants": None}
                 for jid, _node, name in items["disco_items"].get_items()]
        # XEP-0045 §6.4: disco#info on a room carries a muc#roominfo form
        # with `muc#roominfo_occupants`. Optional for the service, so a room
        # whose count is not given shows none -- never a guessed zero.
        gate = asyncio.Semaphore(self.ROOM_INFO_PARALLEL)

        async def count(room):
            async with gate:
                try:
                    info = await disco.get_info(
                        jid=room["jid"], timeout=self.ROOM_INFO_TIMEOUT)
                    room["occupants"] = _room_occupant_count(info)
                except Exception:
                    pass

        await asyncio.gather(*(count(r) for r in rooms[:self.ROOM_INFO_LIMIT]))
        # Occupied rooms first, then the service's own order.
        order = {id(r): i for i, r in enumerate(rooms)}
        rooms.sort(key=lambda r: (-(r["occupants"] or 0), order[id(r)]))
        return rooms

    def join_room(self, room: str, nick: str,
                  password: str = "") -> "tuple[str, str, dict]":
        """Enter a room, and report what we are in it.

        The privileges come back with the join because they are in the
        presence the service sends us on arrival, and asking for them
        separately would be a second round trip for something we already have.
        """
        return self._room_call(self._join_room(room, nick, password))

    async def _join_room(self, room: str, nick: str, password: str):
        muc = self._client["xep_0045"]
        # ALREADY IN IT. A join presence from an account that is already an
        # occupant is, to the service, a presence update: Prosody runs its
        # password check only for a NEW occupant, so it succeeds with no
        # password -- which read as "joined without being asked". Say what is
        # true instead: we are in it already.
        try:
            joined = {str(r).lower() for r in (muc.get_joined_rooms() or ())}
        except Exception:
            joined = set()
        if str(room).lower() in joined:
            raise TransportError("already_in_room", "already in this room")
        # PASSWORD FIRST. The room's disco#info says whether it is
        # password-protected (muc_passwordprotected). Asking for the
        # password before joining makes the prompt appear whatever the
        # service would do with a password-less join. If the room will not
        # answer disco, the join goes ahead and the service decides.
        if not password and await self._room_wants_password(room):
            raise TransportError("not_authorized", "this room needs a password")
        await self._join_muc(room, nick, password)
        self._room_nicks[str(room).split("/", 1)[0].lower()] = nick
        return self._room_standing(room, nick)

    async def _room_wants_password(self, room: str) -> bool:
        try:
            info = await self._client["xep_0030"].get_info(
                jid=room, timeout=CALL_TIMEOUT)
            return "muc_passwordprotected" in {
                str(f) for f in info["disco_info"]["features"]}
        except Exception:
            return False

    async def _join_muc(self, room: str, nick: str, password: str = ""):
        """`join_muc_wait`, plus ANY error presence from the room.

        slixmpp recognises a join refusal only when the error presence
        echoes `<x xmlns='http://jabber.org/protocol/muc'/>`. A service that
        omits it (RFC 6120 allows that) left the join waiting for its full
        timeout and then reported a timeout -- never "wrong password". The
        room's error presence is caught here as well, and raised as the
        PresenceError slixmpp would have raised.
        """
        muc = self._client["xep_0045"]
        loop = asyncio.get_event_loop()
        refused = loop.create_future()
        bare = str(room).split("/", 1)[0].lower()

        def on_error(pres):
            try:
                if str(pres["from"]).split("/", 1)[0].lower() == bare and \
                        not refused.done():
                    refused.set_result(pres)
            except Exception:
                pass

        add = getattr(self._client, "add_event_handler", None)
        remove = getattr(self._client, "del_event_handler", None)
        if add is not None:
            add("presence_error", on_error)
        self._begin_join(room)
        ok = False
        join = asyncio.ensure_future(muc.join_muc_wait(
            room, nick, password=password or None, timeout=CONNECT_TIMEOUT))
        try:
            done, _ = await asyncio.wait(
                [join, refused], timeout=CONNECT_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED)
            if join in done:
                result = join.result()
                ok = True
                return result
            join.cancel()
            if refused in done:
                from slixmpp.exceptions import PresenceError
                raise PresenceError(refused.result())
            raise TimeoutError()
        finally:
            self._end_join(room, ok)
            if not refused.done():
                refused.cancel()
            if remove is not None:
                try:
                    remove("presence_error", on_error)
                except Exception:
                    pass

    def create_room(self, room: str, nick: str,
                    password: str = "") -> "tuple[str, str, dict]":
        """Create a room and accept the service's default configuration.

        XEP-0045 §10.1.2's "instant room": joining a room that does not exist
        creates it in a locked state, and an owner who sends the empty
        configuration form unlocks it. WITHOUT THAT SECOND STEP THE ROOM STAYS
        LOCKED -- the creator is in it and nobody else can get in, which looks
        exactly like a room that works until somebody is invited.

        The alternative, a full configuration form, is a screen of checkboxes
        in front of somebody who asked for a room. It can come later; a room
        that exists is the thing being asked for here.

        PASSWORD. With [password], the submitted form sets exactly two
        XEP-0045 fields -- `muc#roomconfig_passwordprotectedroom` and
        `muc#roomconfig_roomsecret` -- and the room's disco#info is then read
        back. A service that accepted the form but did not protect the room
        would leave an OPEN room the user believes is closed, so that room is
        destroyed and the create reported as failed (`password_not_applied`).
        The password is never logged, traced or kept here. A room password
        controls who may ENTER; it is not end-to-end encryption -- the server
        still reads the room.
        """
        return self._room_call(self._create_room(room, nick, password))

    ROOMCONFIG = "http://jabber.org/protocol/muc#roomconfig"

    async def _create_room(self, room: str, nick: str, password: str = ""):
        # Messages are held from the join until the room is known to be kept:
        # a room destroyed below for want of its password is never
        # registered with the app, so nothing it said is shown.
        self._begin_join(room)
        ok = False
        try:
            result = await self._create_room_held(room, nick, password)
            ok = True
            return result
        finally:
            self._end_join(room, ok)

    async def _create_room_held(self, room: str, nick: str, password: str = ""):
        muc = self._client["xep_0045"]
        await muc.join_muc_wait(room, nick, timeout=CONNECT_TIMEOUT)
        # The empty form. `set_room_config` with a form carrying no fields is
        # the "accept the defaults" submission §10.1.2 describes.
        form = self._client["xep_0004"].make_form(ftype="submit")
        if password:
            form.add_field(var="FORM_TYPE", ftype="hidden",
                           value=self.ROOMCONFIG)
            form.add_field(var="muc#roomconfig_passwordprotectedroom",
                           ftype="boolean", value=True)
            form.add_field(var="muc#roomconfig_roomsecret",
                           ftype="text-private", value=password)
        await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
        self._room_nicks[str(room).split("/", 1)[0].lower()] = nick
        if password:
            protected = False
            try:
                info = await self._client["xep_0030"].get_info(
                    jid=room, timeout=CALL_TIMEOUT)
                protected = "muc_passwordprotected" in {
                    str(f) for f in info["disco_info"]["features"]}
            except Exception:
                protected = False
            if not protected:
                try:
                    await muc.destroy(room, reason="password could not be set",
                                      timeout=CALL_TIMEOUT)
                except Exception:
                    pass
                raise TransportError(
                    "password_not_applied",
                    "the service did not password-protect the room")
        return self._room_standing(room, nick)

    def leave_room(self, room: str, nick: str) -> "tuple[str, str, dict]":
        """Leave a room. The room continues to exist without us."""
        return self._room_call(self._leave_room(room, nick))

    async def _leave_room(self, room: str, nick: str):
        muc = self._client["xep_0045"]
        # No nickname from the caller -- "Delete and leave" on the chat list,
        # which never saw the join -- means the one this session joined with.
        # Not joined this session: there is no presence to withdraw, and the
        # server has already dropped us with the old stream.
        nick = nick or self._our_nick(room)
        if nick:
            muc.leave_muc(room, nick)
        getattr(self, "_room_nicks", {}).pop(str(room).split("/", 1)[0].lower(), None)
        return {}

    def destroy_room(self, room: str,
                     reason: str = "") -> "tuple[str, str, dict]":
        """Delete a room. OWNERS ONLY, and the service is what enforces it.

        `otrv4plus_muc.privileges` is what stops the button being offered to
        somebody who cannot; this does not check, deliberately. A client-side
        permission check that disagreed with the service would be a second
        opinion in a place with no way to be right, and the one that matters
        is the service's.
        """
        return self._room_call(self._destroy_room(room, reason))

    async def _destroy_room(self, room: str, reason: str):
        await self._client["xep_0045"].destroy(room, reason=reason,
                                               timeout=CALL_TIMEOUT)
        return {}

    #: XEP-0133 node Prosody's mod_admin_adhoc serves for "list online users".
    ONLINE_USERS_NODE = "http://jabber.org/protocol/admin#get-online-users-list"
    COMMANDS_NODE = "http://jabber.org/protocol/commands"

    def discover_online_users(self) -> "tuple[str, str, dict]":
        """Who is online on this server, if the SERVER will say. Never guessed.

        A roster is not a server directory, and XMPP has no standard way for
        an ordinary account to list every online user. The one real
        mechanism is XEP-0133 `get-online-users-list`, which Prosody serves
        through `mod_admin_adhoc` to ADMIN accounts only. So:

          1. ask the server which ad-hoc commands it offers THIS account
             (XEP-0050 disco#items on the commands node);
          2. if the online-users command is among them, run it and return
             the JIDs it lists -- the server's answer, as given;
          3. otherwise return code "unavailable" and say what the server
             would need. Nothing is invented, probed or brute-forced.

        value: {"mechanism": str, "users": [bare jid], "offered": [nodes]}.
        """
        return self._room_call(self._discover_online_users())

    async def _discover_online_users(self):
        client = self._client
        domain = str(client.boundjid.domain)
        items = await client["xep_0030"].get_items(
            jid=domain, node=self.COMMANDS_NODE, timeout=CALL_TIMEOUT)
        offered = [str(node) for _jid, node, _name in
                   items["disco_items"].get_items()]
        if self.ONLINE_USERS_NODE not in offered:
            return {"mechanism": "none", "users": [], "offered": offered}
        users = await self._run_online_users_command(domain)
        return {"mechanism": "xep-0133", "users": users, "offered": offered}

    async def _run_online_users_command(self, domain: str):
        """Execute the XEP-0133 command; submit its form with its own defaults."""
        commands = self._client["xep_0050"]
        first = await commands.send_command(
            domain, self.ONLINE_USERS_NODE, action="execute",
            timeout=CALL_TIMEOUT)
        users = self._jids_from_command(first)
        if users is not None:
            return users
        # A form to fill: accept its defaults (Prosody asks for max_items).
        form = first["command"]["form"]
        submit = self._client["xep_0004"].make_form(ftype="submit")
        for var, field in form.get_fields().items():
            value = field["value"]
            if var == "max_items":
                options = [o["value"] for o in (field["options"] or [])]
                if "all" in options:
                    value = "all"
            if var:
                submit.add_field(var=var, ftype=field["type"], value=value)
        done = await commands.send_command(
            domain, self.ONLINE_USERS_NODE, action="complete",
            payload=submit, sessionid=first["command"]["sessionid"],
            timeout=CALL_TIMEOUT)
        return self._jids_from_command(done) or []

    @staticmethod
    def _jids_from_command(iq):
        """The online JIDs from a completed command, or None if not complete."""
        try:
            command = iq["command"]
            if command["status"] != "completed":
                return None
            # get_fields(), not ["fields"]: slixmpp answers the latter
            # with a list of field stanzas, not a mapping.
            fields = command["form"].get_fields()
        except Exception:
            return None
        out = []
        for var, field in fields.items():
            if var in ("onlineuserjids", "onlineusers", "online-users"):
                values = field["value"] or []
                if isinstance(values, str):
                    values = values.split()
                for jid in values:
                    bare = str(jid).split("/", 1)[0].strip().lower()
                    if bare and "@" in bare and bare not in out:
                        out.append(bare)
        return out

    # -- the OTRv4Plus Welcome room ---------------------------------------------

    def start_welcome(self, nick: str) -> None:
        """Find and join the Welcome room in the background. Never blocks.

        Called once the stream is up. Joining is an I2P round trip plus the
        room's presences; the caller must not wait for it.
        """
        if not self.is_connected or not nick:
            return
        try:
            loop = self._ensure_loop()
            asyncio.run_coroutine_threadsafe(self._welcome_flow(nick), loop)
        except Exception:
            self._welcome.failed("unexpected_error")

    async def _welcome_flow(self, nick: str) -> None:
        """disco the server -> its MUC services -> their public rooms ->
        the one named ROOM_NAME -> its disco#info -> join. Nothing else is
        asked of anybody: no occupant is queried, no JID is tried."""
        self._welcome.searching()
        try:
            services = await self._discover_services()
            rooms = {}
            for service in services:
                if service.get("category") != "conference":
                    continue
                try:
                    rooms[service["jid"]] = await self._discover_rooms(
                        service["jid"])
                except Exception:
                    rooms[service["jid"]] = []
            room, reason = _welcome.find_room(services, rooms)
            if room is None:
                self._welcome.not_found(reason)
                _TRACE.record("welcome", reason, "info")
                return
            info = await self._client["xep_0030"].get_info(
                jid=room, timeout=CALL_TIMEOUT)
            features = [str(f) for f in info["disco_info"]["features"]]
            self._welcome.joining(room, features, nick)
            muc = self._client["xep_0045"]
            try:
                await self._join_muc(room, nick)
            except Exception as exc:
                code, _detail = _muc.classify(exc)
                if code != "conflict":
                    raise
                # Our nickname is taken (another of our own resources, or
                # somebody else). One retry with a random suffix: this picks
                # OUR name, it does not probe anybody else's.
                import secrets as _secrets
                nick = "%s-%s" % (nick, _secrets.token_hex(2))
                self._welcome.nick = nick
                await self._join_muc(room, nick)
            self._welcome.joined(nick)
            self._room_nicks[str(room).lower()] = nick
            self._notify_welcome(room)
            # Occupants whose presence arrived before our own self-presence
            # are already in slixmpp's room roster; read them from there.
            for other in list(muc.get_roster(room) or []):
                if other == nick:
                    continue
                real = muc.get_jid_property(room, other, "jid") or ""
                self._welcome.occupant(other, str(real), True)
            _TRACE.record("welcome", "joined", "info",
                          anonymity=self._welcome.props.get("anonymity"))
        except Exception as exc:
            code, _detail = _muc.classify(exc)
            self._welcome.failed(code)
            _TRACE.record("welcome", "failed", "warning", code=code)

    def create_welcome(self, nick: str) -> "tuple[str, str, dict]":
        """Create the OTRv4Plus Welcome room, when the server has none.

        Only on the user's explicit request (the app asks first and says
        what the room reveals). Refuses when a room with ROOM_NAME already
        exists (it is joined instead) or when the chosen address is taken by
        some other room (never taken over). After creating, the room's
        disco#info is read back and every setting the server did NOT apply
        is reported -- a Prosody may refuse `persistent` or `public` to an
        ordinary account, and a room that is not public cannot be found by
        anybody else.

        value: {"room", "created": bool, "missing": [descriptions]}.
        """
        return self._room_call(self._create_welcome(nick))

    async def _create_welcome(self, nick: str):
        disco = self._client["xep_0030"]
        services = await self._discover_services()
        muc_services = [s for s in services if s.get("category") == "conference"]
        if not muc_services:
            raise TransportError("unsupported", "this server offers no rooms")
        rooms = {}
        for service in muc_services:
            try:
                rooms[service["jid"]] = await self._discover_rooms(service["jid"])
            except Exception:
                rooms[service["jid"]] = []
        existing, _reason = _welcome.find_room(muc_services, rooms)
        if existing is not None:
            # Somebody made it since we last looked: join, do not create.
            await self._welcome_flow(nick)
            return {"room": existing, "created": False, "missing": []}
        room = "%s@%s" % (_welcome.ROOM_LOCALPART, muc_services[0]["jid"])
        try:
            await disco.get_info(jid=room, timeout=CALL_TIMEOUT)
            taken = True
        except Exception:
            taken = False
        if taken:
            raise TransportError(
                "welcome_address_taken",
                "a room already uses that address under another name")
        muc = self._client["xep_0045"]
        await self._join_muc(room, nick)
        form = self._client["xep_0004"].make_form(ftype="submit")
        form.add_field(var="FORM_TYPE", ftype="hidden", value=self.ROOMCONFIG)
        for var, ftype, value in _welcome.ROOM_CONFIG:
            form.add_field(var=var, ftype=ftype, value=value)
        await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
        self._room_nicks[room.lower()] = nick
        missing = []
        features = []
        try:
            info = await disco.get_info(jid=room, timeout=CALL_TIMEOUT)
            features = [str(f) for f in info["disco_info"]["features"]]
            missing = _welcome.missing_features(features)
        except Exception:
            missing = [why for _f, why in _welcome.REQUIRED_FEATURES]
        self._welcome.joining(room, features, nick)
        self._welcome.joined(nick)
        self._notify_welcome(room)
        _TRACE.record("welcome", "created", "info", missing=len(missing))
        return {"room": room, "created": True, "missing": missing}

    def set_welcome_handler(self, handler) -> None:
        """`handler(room)` once the Welcome room is joined, so the app treats
        its traffic as room chat (and delivers it) like any joined room."""
        self._on_welcome = handler

    def _notify_welcome(self, room: str) -> None:
        handler = getattr(self, "_on_welcome", None)
        if handler is None:
            return
        try:
            handler(room)
        except Exception:
            _log.warning("the welcome handler raised")

    def welcome_view(self) -> dict:
        """The Welcome room's state and discoverable people, for the UI."""
        return self._welcome.view(self._profile.jid)

    #: disco#info features that bear on deleting history from a SERVER.
    #: Read, never acted on: see `archive_support`.
    ARCHIVE_FEATURES = {
        "urn:xmpp:mam:2": "mam",                       # XEP-0313 archive
        "urn:xmpp:mam:1": "mam",
        "urn:xmpp:message-retract:1": "retract",       # XEP-0424
        "urn:xmpp:message-retract:0": "retract",
        "urn:xmpp:message-moderate:1": "moderate",     # XEP-0425 (rooms)
        "urn:xmpp:message-moderate:0": "moderate",
    }

    def archive_support(self, jid: str = "") -> "tuple[str, str, dict]":
        """What [jid] -- our own account when empty, or a room -- advertises
        about keeping and deleting history.

        A QUESTION, NOT A CAPABILITY. No XEP lets a client delete a server's
        message archive: XEP-0313 (MAM) defines query only; XEP-0424
        retraction asks the other side's clients to hide one message by its
        archive id, which this app does not record; XEP-0425 moderation is
        per message and for room moderators. So this reports, and "Delete
        chat" tells the user what the server said, instead of implying the
        server's copy went with the local one.
        """
        return self._room_call(self._archive_support(jid))

    async def _archive_support(self, jid: str):
        target = jid or str(self._client.boundjid.bare)
        info = await self._client["xep_0030"].get_info(
            jid=target, timeout=CALL_TIMEOUT)
        found = {"mam": False, "retract": False, "moderate": False}
        for feature in info["disco_info"]["features"]:
            key = self.ARCHIVE_FEATURES.get(str(feature))
            if key:
                found[key] = True
        return found

    def room_standing(self, room: str, nick: str) -> "tuple[str, str, dict]":
        """Our affiliation and role in a room we are already in."""
        try:
            return ("ok", _muc.CODES["ok"], self._room_standing(room, nick))
        except Exception as exc:
            code, detail = _muc.classify(exc)
            return (code, detail, {})

    def joined_rooms(self) -> "tuple[str, str, list]":
        """The rooms this session is in, as slixmpp has them."""
        try:
            rooms = self._client["xep_0045"].get_joined_rooms()
            return ("ok", _muc.CODES["ok"], [str(r) for r in rooms])
        except Exception as exc:
            code, detail = _muc.classify(exc)
            return (code, detail, [])

    def _room_standing(self, room: str, nick: str) -> Dict[str, Any]:
        """Read affiliation and role out of slixmpp's room roster.

        Both, always, and never one inferred from the other: they are
        different questions -- see `otrv4plus_muc` -- and an owner who joined
        as a visitor cannot speak.
        """
        muc = self._client["xep_0045"]

        def prop(name):
            try:
                return str(muc.get_jid_property(room, nick, name) or "")
            except Exception:
                return ""

        affiliation = prop("affiliation") or _muc.NONE
        role = prop("role") or _muc.NO_ROLE
        rights = _muc.privileges(affiliation, role)
        out = rights.as_dict()
        out["room"] = str(room)
        out["nick"] = str(nick)
        return out

    def _room_call(self, coro) -> "tuple[str, str, Any]":
        """Run a room operation and classify whatever it does.

        Every failure becomes a `(code, detail)` from `otrv4plus_muc`, and the
        detail is chosen from that module's table rather than built from the
        exception -- a MUC error stringifies to something carrying the room,
        the service and the nickname.

        NOT `_run`. That one flattens every exception into
        `TransportError("unexpected_error", type(exc).__name__)`, which is
        right for a send and destroys exactly what matters here: the condition
        inside the stanza is how "that nickname is taken" is told apart from
        "you are banned", and a type name is neither.
        """
        if not self.is_connected:
            coro.close()
            return ("network", _muc.CODES["network"], None)
        try:
            loop = self._ensure_loop()
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            value = future.result(timeout=CONNECT_TIMEOUT)
        except TimeoutError:
            # Builtin TimeoutError: nothing raised, the work simply never
            # finished. Cancelled rather than abandoned, so a join nobody is
            # waiting on stops occupying the room's presence.
            future.cancel()
            return ("timeout", _muc.CODES["timeout"], None)
        except BaseException as exc:
            # BaseException for CancelledError, which does not derive from
            # Exception on the asyncio side. `classify` is total.
            code, detail = _muc.classify(exc)
            return (code, detail, None)
        return ("ok", _muc.CODES["ok"], value)

    def _wire(self, client) -> None:
        # Applied explicitly rather than inherited. slixmpp defaults both
        # auto_authorize and auto_subscribe to True, so "we accept everyone"
        # would otherwise be true by accident rather than by decision, and
        # would silently change if upstream changed its mind.
        self._subscription_policy = SubscriptionPolicy.apply(
            client, self._subscription_policy)
        # Before any handler, and for EVERY stanza -- presence, message, IQ,
        # the roster result. This is the keepalive's primary evidence, and it
        # has to see everything: a session where only presence arrives is just
        # as alive as one carrying messages.
        try:
            client.add_filter("in", self._note_inbound)
        except Exception:
            # An older slixmpp without stream filters still works; the probe
            # is then the only liveness signal, which is what this used to be.
            _log.warning("could not install the inbound filter")
        client.add_event_handler("presence_subscribe", self._on_subscribe)
        client.add_event_handler("message", self._on_message)
        # Room messages arrive as type="groupchat", which `_on_message`
        # deliberately ignores: a room is not a peer, and its traffic must
        # never reach the OTR engine as though it were.
        client.add_event_handler("groupchat_message", self._on_groupchat)
        client.add_event_handler("presence_available",
                                 lambda p: self._presence(p, True))
        client.add_event_handler("presence_unavailable",
                                 lambda p: self._presence(p, False))
        client.add_event_handler("disconnected", self._on_disconnected)

    def _note_inbound(self, stanza):
        """Record that the stream delivered something. Returns it unchanged.

        A slixmpp inbound filter, so it sees presence, messages, IQs and
        everything else before any handler runs. It must never drop or alter a
        stanza -- returning it unchanged is the contract, and a filter that
        returns None discards the stanza.
        """
        self._last_inbound = time.monotonic()
        return stanza

    def _stream_quiet_for(self) -> float:
        """Seconds since the stream last delivered anything."""
        return max(0.0, time.monotonic() - self._last_inbound)

    #: Longest single 1:1 body accepted. Every OTRv4+ sender -- this app and
    #: both terminal clients -- fragments anything over
    #: `otrv4plus_fragment.MAX_FRAGMENT` (6000), so no legitimate frame comes
    #: near this; only a plaintext message from some other client could, and
    #: 64 KiB of it is more than any screen shows. Without a bound a single
    #: stanza of whatever size the server allows went to the engine and then
    #: across the JNI boundary into the UI.
    MAX_DIRECT_BODY = 64 * 1024

    def _on_message(self, stanza) -> None:
        """Hand the body up, whatever it is.

        No filtering for OTR framing here. The transport does not know what an
        OTR frame looks like and should not learn: `OtrApp.receive_message`
        gives it to the engine, which is the one thing entitled to decide
        whether a payload is a DAKE frame, an SMP frame, ciphertext, or a
        plaintext message from someone with no session.
        """
        try:
            if stanza.get("type") not in ("chat", "normal", None, ""):
                return
            body = stanza.get("body") or ""
            if not body:
                return
            sender = stanza.get("from")
            peer = str(sender).split("/", 1)[0] if sender else ""
            full_sender = str(sender) if sender else ""
        except Exception:
            _log.warning("could not read an inbound stanza")
            return
        if not peer or peer == "None":
            # No sender, no conversation to put it in -- and str(None) used
            # to make one called "None".
            return
        if len(body) > self.MAX_DIRECT_BODY:
            # Dropped, not truncated: a cut OTR frame is garbage, and a cut
            # plaintext message is a different message from the one sent.
            _log.warning("dropped an oversized inbound body (%d chars)", len(body))
            return
        # Reassembly BEFORE the engine, and before any decision about what the
        # body is. A Termux peer fragments anything over 6000 bytes, which
        # includes every DAKE2 and every SMP frame; handing those to the
        # engine one at a time is handing it gibberish, which is why the two
        # clients could not complete a handshake with each other.
        #
        # `feed` returns None for an incomplete set, so nothing reaches the
        # engine until the last fragment lands. Malformed and out-of-range
        # fragments also return None and are dropped, which is the same
        # fail-closed behaviour the terminal client has.
        # In-band evidence: only OTRv4Plus produces this wire format, so the
        # RESOURCE that sent it speaks the protocol and is where the session
        # it belongs to lives.
        if _caps.is_otr_protocol(body) and "/" in full_sender:
            before = self._caps.state(peer.lower())
            self._caps.inband_otr(full_sender)
            if before != _caps.AVAILABLE:
                self._notify_capability(peer.lower())
        if _fragment.is_fragment(body):
            body = self._reassembler.feed(peer, body)
            if body is None:
                return

        try:
            self._on_payload(peer, body)
        except Exception:
            # A callback that raises must not take the connection down: it is
            # UI code across a language boundary, and a screen bug is not a
            # reason to drop a session. Same rule as OtrApp._emit.
            _log.warning("the inbound payload handler raised")

    def _on_subscribe(self, stanza) -> None:
        """Someone asked to see our presence.

        Reported even under ACCEPT, where slixmpp has already said yes. The
        user is entitled to know a stranger is now watching their presence,
        and finding out only because a name appeared in a list is not the
        same as being told.
        """
        if self._on_subscription_request is None:
            return
        try:
            jid = str(stanza["from"]).split("/", 1)[0]
        except Exception:
            _log.warning("could not read a subscription request")
            return
        try:
            self._on_subscription_request(jid)
        except Exception:
            _log.warning("the subscription handler raised")

    def _track_caps(self, stanza, online: bool) -> None:
        """Per-resource OTRv4Plus capability from a presence stanza."""
        try:
            full = str(stanza["from"])
        except Exception:
            return
        bare, resource = _caps.split_jid(full)
        if not bare or not resource or bare == _caps.split_jid(
                self._profile.jid)[0] and resource == self._own_resource():
            return
        if not online:
            left = self._caps.presence_unavailable(full)
            self._notify_capability(bare, left)
            return
        ver, priority = "", 0
        try:
            ver = str(stanza["caps"]["ver"] or "")
        except Exception:
            ver = ""
        try:
            priority = int(stanza["priority"] or 0)
        except Exception:
            priority = 0
        if self._caps.presence_available(full, ver, priority):
            self._notify_capability(bare)          # CHECKING
            try:
                asyncio.ensure_future(self._query_caps(full))
            except Exception:
                self._caps.disco_failed(full)
                self._notify_capability(bare)
        else:
            self._notify_capability(bare)

    def _own_resource(self) -> str:
        try:
            return str(self._client.boundjid.resource or "")
        except Exception:
            return ""

    MUC_USER_NS = "http://jabber.org/protocol/muc#user"

    def _is_room_presence(self, stanza) -> bool:
        """A presence from a ROOM occupant (`room@service/nick`), not a peer.

        Recognised by the `<x xmlns='muc#user'/>` every MUC service adds, or
        by coming from a room this session joined. Such a presence is about a
        nickname in a room: its `from` is the room's JID, so it must never be
        read as a contact coming online, and never feed the OTRv4Plus
        capability book -- which would otherwise record the ROOM as a peer
        and send a disco#info through the room to every occupant.
        """
        try:
            if stanza.xml.find("{%s}x" % self.MUC_USER_NS) is not None:
                return True
        except Exception:
            pass
        try:
            bare = str(stanza["from"]).split("/", 1)[0]
            if self._welcome.is_room(bare):
                return True
            joined = self._client["xep_0045"].get_joined_rooms()
            return bare in {str(r) for r in (joined or ())}
        except Exception:
            return False

    def _room_presence(self, stanza, online: bool) -> None:
        """Feed a Welcome-room occupant presence to the directory."""
        try:
            full = str(stanza["from"])
        except Exception:
            return
        room, _, nick = full.partition("/")
        if not self._welcome.is_room(room):
            return
        real, is_self = "", False
        try:
            x = stanza.xml.find("{%s}x" % self.MUC_USER_NS)
            if x is not None:
                item = x.find("{%s}item" % self.MUC_USER_NS)
                if item is not None:
                    # Written by the MUC service, present only when the room
                    # reveals real JIDs to us. Never derived from the nick.
                    real = str(item.get("jid") or "")
                is_self = any(str(s.get("code")) == "110" for s in
                              x.findall("{%s}status" % self.MUC_USER_NS))
        except Exception:
            real = ""
        if nick and nick == self._welcome.nick:
            is_self = True
        self._welcome.occupant(nick, real, online, is_self=is_self)

    def _presence(self, stanza, online: bool) -> None:
        if self._is_room_presence(stanza):
            try:
                self._room_presence(stanza, online)
            except Exception:
                _log.warning("could not read a room presence")
            return
        try:
            self._track_caps(stanza, online)
        except Exception:
            _log.warning("could not track capability from a presence")
        if self._on_presence is None:
            return
        try:
            # The FULL JID: presence is tracked per resource (see
            # otrv4plus_presence.PresenceBook.note).
            full = str(stanza["from"])
            peer = full.split("/", 1)[0]
        except Exception:
            return
        # RFC 6121 4.7.2.1. Carried because a UI that has it can tell "online"
        # from "away" without another round trip; it never DECIDES
        # availability, which the stanza type already did.
        show = ""
        if online:
            try:
                show = str(stanza["show"] or "")
            except Exception:
                show = ""
        _TRACE.record("presence", "available" if online else "unavailable",
                      "info", peer=peer, show=show)
        try:
            self._on_presence(full, online, show)
        except TypeError:
            # A handler from before `show` existed. Better than dropping the
            # event: availability is the part that matters.
            try:
                self._on_presence(peer, online)
            except Exception as exc:
                _log.warning("the presence handler raised")
                _TRACE.record_exception("presence", "handler_raised", exc,
                                        peer=peer)
        except Exception as exc:
            _log.warning("the presence handler raised")
            _TRACE.record_exception("presence", "handler_raised", exc,
                                    peer=peer)

    def _on_disconnected(self, _event) -> None:
        # Distinct from `stream_declared_dead`: this is slixmpp telling us the
        # stream ended, rather than us deciding it had. Which of the two fired
        # first is exactly what separates "the network went" from "we killed
        # a healthy session".
        _TRACE.record("transport", "stream_closed_by_slixmpp", "warning",
                      quiet_for=round(self._stream_quiet_for()))
        self._connected.clear()
        # Every resource's presence is unknown now; capability goes with it,
        # and so does who was in the Welcome room.
        self._caps.clear()
        self._welcome.clear()
        self._room_nicks.clear()
        self._emit_state("disconnected")

    def _emit_state(self, state: str) -> None:
        if self._on_state is None:
            return
        try:
            self._on_state(state, self._profile.effective_server)
        except Exception:
            _log.warning("the state handler raised")


def endpoint_authenticated_by(profile) -> Optional[str]:
    """Whether the ADDRESS already authenticates the endpoint, and by what.

    "I2P", "Tor", or None for clearnet.

    This is the rule `otrv4plus_xmpp.main()` applies around line 7170, and the
    reasoning there is worth repeating rather than re-deriving: a `.b32.i2p`
    label is the hash of the destination's key, and a v3 onion name is the key
    itself. Reaching that address means reaching that key-holder, with the
    transport's own end-to-end encryption in between. There is no certificate
    authority in the path and no MITM position for one to defend against, so
    demanding a CA-valid certificate there is asking for a weaker second name
    for a server already named by its key.

    None means clearnet, and clearnet still demands a real certificate.
    """
    try:
        route = profile.route
    except Exception:
        # Undecidable names never reach the network; answer by suffix so a
        # caller asking about policy is never told "clearnet" for them.
        name = str(getattr(profile, "effective_server", "")).lower()
        return "I2P" if name.endswith(".i2p") else (
            "Tor" if name.endswith(".onion") else None)
    if route.verify_certificate:
        return None
    return "I2P" if route.kind == _route_mod.I2P_SAM else "Tor"


def _default_client_factory():
    """slixmpp, imported late.

    Late because a settings screen, a unit test and the diagnostics report all
    touch this module without ever connecting, and slixmpp costs about a second
    to import on a handset.
    """
    from slixmpp import ClientXMPP

    def factory(jid: str, password: str):
        client = ClientXMPP(jid, password)
        # STARTTLS, never direct TLS: the far end of a SAM stream is a normal
        # c2s port. This mirrors what the terminal client sets in main().
        if hasattr(client, "enable_direct_tls"):
            client.enable_direct_tls = False
        if hasattr(client, "enable_starttls"):
            client.enable_starttls = True
        # XEP-0199, for the keepalive's round trip. Without it `_probe_stream`
        # has nothing to ping with and reports "alive" unconditionally, which
        # is the failure this keepalive exists to detect. Registered here
        # rather than asked for later because a plugin added after the stream
        # is up does not get its handlers wired.
        try:
            client.register_plugin("xep_0199")
        except Exception:
            _log.warning("could not register xep_0199; the keepalive will "
                         "fall back to whitespace only")
        # Service discovery and rooms. NEITHER WAS REGISTERED, which is why
        # there was nothing behind a rooms screen: `client["xep_0045"]` on a
        # client that has not registered it raises, and discovery had no way
        # to find the MUC service at all.
        #
        # Registered here, before the stream, for the same reason xep_0199 is:
        # a plugin added after the session is up does not get its handlers
        # wired, and xep_0045's handlers are how joining a room ever completes.
        #
        # Each separately, so one that is missing from a slimmed-down slixmpp
        # does not take the other with it. xep_0004 is named explicitly
        # because `create_room` submits a data form and a dependency being
        # pulled in implicitly is one that can stop being pulled in.
        # xep_0115: entity capabilities, so peers learn we speak OTRv4Plus
        # from our presence and we learn theirs without asking each time.
        # xep_0050: ad-hoc commands, for the one server-supported way to list
        # online users (XEP-0133, admins only on Prosody).
        for plugin in ("xep_0030", "xep_0004", "xep_0045", "xep_0115",
                       "xep_0050"):
            try:
                client.register_plugin(plugin)
            except Exception:
                _log.warning("could not register %s; rooms and service "
                             "discovery will not work", plugin)
        return client

    return factory


def _default_tor_forwarder():
    """The terminal client's Tor SOCKS5 forwarder, imported late."""
    import otrv4plus_xmpp

    return otrv4plus_xmpp.start_tor_socks_forwarder


def _default_forwarder():
    """The terminal client's SAM forwarder, imported late.

    Late for the same reason and one more: importing `otrv4plus_xmpp` pulls in
    the whole OTR engine, and this module is imported by things that have no
    business loading it.
    """
    import otrv4plus_xmpp

    return otrv4plus_xmpp.start_i2p_sam_forwarder
