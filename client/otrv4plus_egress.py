# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the network may be used for, enforced for the whole process (N1).

`android_bridge.route` decides the transport from the server name. This makes
the decision binding on every socket the Python side opens and every name it
resolves -- not only on the code that was written to follow it. It is a
CPython audit hook (`sys.addaudithook`, PEP 578): `socket.connect`,
`socket.sendto` and the resolver functions raise their audit events before
they touch the network, and a hook that raises aborts the call. Nothing in the
process can opt out, including libraries.

The policy, by the route of the account signed in to:

  i2p_sam  only loopback (127.0.0.0/8, ::1) and the configured SAM endpoint;
           no name resolution at all except "localhost" and literal IPs.
  tor      only loopback and the configured Tor SOCKS endpoint; no name
           resolution (the onion name travels inside SOCKS CONNECT).
  clearnet_tls  any address; DNS allowed.
  none     (no account signed in) any address; DNS allowed.

In EVERY mode a name ending in `.i2p` or `.onion` is never resolved: such a
name in a DNS query is a leak whatever the route.

A refusal raises `EgressRefused` (an `OSError`, so callers treat it as the
network failure it is) and is counted. The rule covers the Python side --
the engine, the bridge and every library they load. The I2P router the app
bundles is a separate native process: its reseed and its links to other
routers are its own (docs/SECURITY_ISSUES.md N1), and none of them exists
when a local I2P app's SAM bridge on 127.0.0.1 is used instead.
"""
from __future__ import annotations

import ipaddress
import sys
import threading
from typing import Optional, Set, Tuple

__all__ = ["EgressRefused", "install", "enter", "leave", "mode", "refusals",
           "check_connect", "check_resolve", "check_reverse", "NONE", "LOOPBACK_ONLY"]

NONE = "none"
#: Routes whose traffic may leave only through a local bridge.
LOOPBACK_ONLY = ("i2p_sam", "tor")
_HIDDEN_SUFFIXES = (".i2p", ".onion")
_RESOLVE_EVENTS = ("socket.getaddrinfo", "socket.gethostbyname",
                   "socket.gethostbyname_ex")
#: Reverse lookups: a DNS query even for a literal IP (a PTR record).
_REVERSE_EVENTS = ("socket.gethostbyaddr", "socket.getnameinfo")
_SEND_EVENTS = ("socket.connect", "socket.sendto", "socket.sendmsg")


class EgressRefused(OSError):
    """A connection or lookup the active route does not allow."""


_lock = threading.Lock()
_state = {"mode": NONE, "allowed": set(), "refused": 0}
_installed = False


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(str(host).split("%", 1)[0])
        return True
    except ValueError:
        return False


def _hidden_name(host) -> bool:
    if not isinstance(host, (str, bytes)):
        return False
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    return name.rstrip(".").lower().endswith(_HIDDEN_SUFFIXES)


def check_resolve(host, mode: Optional[str] = None) -> None:
    """Raise EgressRefused if resolving [host] is not allowed now."""
    mode = mode or _state["mode"]
    if _hidden_name(host):
        raise EgressRefused("an .i2p or .onion name is never sent to DNS")
    if mode in LOOPBACK_ONLY:
        name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
        if name is None or name == "" or name.lower() == "localhost" or _is_ip(name):
            return
        raise EgressRefused("no name resolution on the %s route" % mode)


def check_reverse(target, mode: Optional[str] = None) -> None:
    """Raise EgressRefused if a reverse lookup of [target] is not allowed:
    on a loopback-only route, only of a loopback address."""
    mode = mode or _state["mode"]
    host = target[0] if isinstance(target, tuple) and target else target
    if _hidden_name(host):
        raise EgressRefused("an .i2p or .onion name is never sent to DNS")
    if mode in LOOPBACK_ONLY and not _is_loopback(host):
        raise EgressRefused("no reverse lookup on the %s route" % mode)


def check_connect(address, mode: Optional[str] = None,
                  allowed: Optional[Set[Tuple[str, int]]] = None) -> None:
    """Raise EgressRefused if connecting or sending to [address] is not
    allowed now. A non-tuple address (a Unix socket path) is local."""
    mode = mode or _state["mode"]
    if not isinstance(address, tuple) or len(address) < 2:
        return
    host, port = address[0], address[1]
    if _hidden_name(host):
        raise EgressRefused("an .i2p or .onion name is never connected to directly")
    if mode not in LOOPBACK_ONLY:
        return
    allowed = _state["allowed"] if allowed is None else allowed
    if _is_loopback(host) or (str(host), int(port)) in allowed:
        return
    raise EgressRefused("only the local %s bridge may be reached on this route" % mode)


def _hook(event: str, args) -> None:
    try:
        if event in _SEND_EVENTS:
            check_connect(args[1] if len(args) > 1 else None)
        elif event in _RESOLVE_EVENTS:
            check_resolve(args[0] if args else None)
        elif event in _REVERSE_EVENTS:
            check_reverse(args[0] if args else None)
    except EgressRefused:
        with _lock:
            _state["refused"] += 1
        raise


def install() -> None:
    """Install the hook, once per process. Idempotent; cannot be removed."""
    global _installed
    with _lock:
        if _installed:
            return
        sys.addaudithook(_hook)
        _installed = True


def enter(route_kind: str, bridge: Optional[Tuple[str, int]] = None) -> None:
    """The account's route is decided: from now, its rules. [bridge] is the
    configured SAM or Tor endpoint, allowed in addition to loopback; a
    non-loopback bridge must be a literal IP (a name would need DNS)."""
    install()
    allowed: Set[Tuple[str, int]] = set()
    if bridge is not None and route_kind in LOOPBACK_ONLY:
        host, port = str(bridge[0]), int(bridge[1])
        if not (_is_loopback(host) or host.lower() == "localhost"):
            if not _is_ip(host):
                raise EgressRefused("a SAM or Tor bridge off this machine must be an IP address")
            allowed.add((host, port))
    with _lock:
        _state["mode"] = route_kind
        _state["allowed"] = allowed
    _resolver_through_python(route_kind not in LOOPBACK_ONLY)


def leave() -> None:
    """Signed out: no account, no route."""
    with _lock:
        _state["mode"] = NONE
        _state["allowed"] = set()
    _resolver_through_python(True)


_AIODNS = {"saved": None}


def _resolver_through_python(allow_aiodns: bool) -> None:
    """slixmpp resolves with aiodns (c-ares) when it is installed, and c-ares
    sends its queries itself, outside Python's socket layer, where this hook
    cannot see them. On a loopback-only route that path is switched off, so
    every lookup slixmpp makes is a `socket.getaddrinfo` -- and refused. The
    Android app ships no aiodns at all; a desktop or terminal Python may."""
    try:
        from slixmpp.xmlstream import resolver
    except Exception:
        return
    if _AIODNS["saved"] is None:
        _AIODNS["saved"] = bool(resolver.AIODNS_AVAILABLE)
    resolver.AIODNS_AVAILABLE = _AIODNS["saved"] and allow_aiodns


def mode() -> str:
    return _state["mode"]


def refusals() -> int:
    """How many calls the hook has refused in this process."""
    return int(_state["refused"])
