# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Which transport a server is reached over. The one place that decides.

WHY THIS EXISTS
---------------
A handset asked to register on `07f.de`, an ordinary clearnet XMPP server,
and got `registration started -> checking_router -> failed` within three
milliseconds: no DNS, no TCP, no TLS. The profile Kotlin builds
(`connection.controller_for`) never set `use_i2p`, whose default was True, so
EVERY server was treated as an I2P server: the SAM bridge was probed, there
was no router on the phone, and the attempt ended before it began. Nothing
looked at the name.

The decision now comes from the name, here, before anything touches the
network:

    *.b32.i2p      -> i2p_sam   (SAM, the address is the key hash)
    *.i2p          -> i2p_sam   (SAM NAMING LOOKUP; see X1 pinning)
    *.onion        -> tor       (Tor SOCKS5; the name travels inside CONNECT)
    anything else  -> clearnet_tls (DNS, TCP 5222/SRV, STARTTLS, a CA-valid
                                    certificate for the domain)

An explicit override is honoured where it is safe, and refused where it would
leak a name: `.i2p` and `.onion` names are never sent to DNS, whatever the
override says. There is no fallback between routes -- a route that cannot be
used fails with its own reason.

Nothing here opens a socket or resolves a name. `www.` or its absence means
nothing; only the suffix does.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

__all__ = ["CLEARNET_TLS", "I2P_SAM", "TOR", "AUTO", "OVERRIDES", "ROUTE_CODES", "Route",
           "RouteError", "classify"]

CLEARNET_TLS = "clearnet_tls"
I2P_SAM = "i2p_sam"
TOR = "tor"
AUTO = "auto"
OVERRIDES = (AUTO, CLEARNET_TLS, I2P_SAM, TOR)
#: Every RouteError code.
ROUTE_CODES = ("bad_transport", "no_server", "malformed_server", "route_refused")

_B32 = re.compile(r"^[a-z2-7]{52}\.b32\.i2p$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_ONION_V3 = re.compile(r"^([a-z0-9-]+\.)*[a-z2-7]{56}\.onion$")


class RouteError(ValueError):
    """The name cannot be routed as asked. `code` is for the UI."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Route:
    kind: str                   # CLEARNET_TLS, I2P_SAM or TOR
    host: str                   # normalised: lower case, no port, no dot
    port: Optional[int]         # None = the XMPP default / SRV
    #: The address itself names the key: a .b32.i2p hash or a v3 onion.
    #: A human-readable .i2p name is NOT -- the router's address book binds it
    #: (SECURITY_ISSUES X1) -- and a clearnet name is bound by a CA.
    self_authenticating: bool
    #: Whether TLS certificate checks apply. Only off where the transport
    #: authenticates the endpoint by its address (I2P, onion).
    verify_certificate: bool
    #: Where a human-readable name is resolved: "dns", "sam", "tor".
    resolver: str
    reason: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "host": self.host, "port": self.port,
                "self_authenticating": self.self_authenticating,
                "verify_certificate": self.verify_certificate,
                "resolver": self.resolver, "reason": self.reason}


def _split_port(text: str):
    """(host, port) from `host`, `host:port` or `[v6]:port`."""
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise RouteError("malformed_server", "Unclosed '[' in the server address.")
        host, rest = text[1:end], text[end + 1:]
        if rest and not rest.startswith(":"):
            raise RouteError("malformed_server", "Unexpected text after ']'.")
        port_text = rest[1:] if rest else ""
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host, port_text = text, ""
    port = None
    if port_text:
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise RouteError("malformed_server",
                             "The port must be a number from 1 to 65535.")
        port = int(port_text)
    return host, port


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _check_dns_name(host: str) -> None:
    if _is_ip(host) or host == "localhost":
        return
    if len(host) > 253 or "." not in host:
        raise RouteError("malformed_server",
                         "%r is not a server name." % (host,))
    for label in host.split("."):
        if not _LABEL.match(label):
            raise RouteError("malformed_server",
                             "%r is not a valid server name." % (host,))


def classify(server: str, override: str = AUTO) -> Route:
    """The route for `server`, or RouteError. Pure: no I/O."""
    override = (override or AUTO).strip().lower()
    if override not in OVERRIDES:
        raise RouteError("bad_transport",
                         "Unknown transport %r; use one of %s."
                         % (override, ", ".join(OVERRIDES)))
    text = (server or "").strip().lower()
    if not text:
        raise RouteError("no_server", "No server to connect to.")
    if "@" in text or "/" in text or any(c.isspace() for c in text):
        raise RouteError("malformed_server",
                         "The server is a host name, not an account or a URL.")
    host, port = _split_port(text)
    host = host.rstrip(".")
    if not host:
        raise RouteError("malformed_server", "No host name before the port.")

    if host.endswith(".i2p"):
        if host.endswith(".b32.i2p"):
            if not _B32.match(host):
                raise RouteError("malformed_server",
                                 "A .b32.i2p address is 52 characters of a-z "
                                 "and 2-7 before '.b32.i2p'.")
            b32 = True
        else:
            _check_dns_name(host)
            b32 = False
        if override not in (AUTO, I2P_SAM):
            raise RouteError(
                "route_refused",
                "%s is an I2P address. It can only be reached through I2P; "
                "sending it to %s would disclose it to a resolver that cannot "
                "answer." % (host, "DNS" if override == CLEARNET_TLS else "Tor"))
        return Route(I2P_SAM, host, port, self_authenticating=b32,
                     verify_certificate=False, resolver="sam",
                     reason="the name ends in .b32.i2p" if b32
                     else "the name ends in .i2p")

    if host.endswith(".onion"):
        if not _ONION_V3.match(host):
            raise RouteError("malformed_server",
                             "An .onion address is a 56-character v3 name.")
        if override not in (AUTO, TOR):
            raise RouteError(
                "route_refused",
                "%s is an onion address. It can only be reached through Tor; "
                "it is never looked up in DNS." % host)
        return Route(TOR, host, port, self_authenticating=True,
                     verify_certificate=False, resolver="tor",
                     reason="the name ends in .onion")

    _check_dns_name(host)
    if override == I2P_SAM:
        raise RouteError(
            "route_refused",
            "%s is not an I2P address; the I2P router cannot reach it." % host)
    if override == TOR:
        # A clearnet server reached through a Tor exit. The exit resolves the
        # name; the certificate is still checked, because nothing about the
        # address authenticates the server.
        return Route(TOR, host, port, self_authenticating=False,
                     verify_certificate=True, resolver="tor",
                     reason="Tor was selected explicitly")
    return Route(CLEARNET_TLS, host, port, self_authenticating=False,
                 verify_certificate=True, resolver="dns",
                 reason="an ordinary DNS name"
                 if override == AUTO else "clearnet was selected explicitly")
