# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""DNS SRV lookup for clearnet XMPP (RFC 6120 §3.2.1), without aiodns.

WHY THIS EXISTS
---------------
slixmpp looks up `_xmpp-client._tcp.<domain>` only through `aiodns`, which
the APK deliberately does not ship (a C extension, pycares, dropped from the
closure). Without it slixmpp silently skips SRV and dials `<domain>:5222`.
For many real servers that is a different machine: `yax.im`'s SRV record
points at `xmpp.yax.im` (another address entirely), so registration from the
handset reached a host that is not the XMPP server and ended as
`code=network` (device report, 2026-09-28).

This module asks the SRV question itself: one query, over UDP to the resolvers
the platform names (TCP when the answer is truncated), parsed with every
length checked. Android has no /etc/resolv.conf, so the Kotlin bridge hands the
active network's DNS servers to `set_system_resolvers` before a connect; a
terminal falls back to resolv.conf.

SECURITY: an SRV answer is not trusted for identity. It only says where to
dial; TLS is still verified against the JID's own domain, so a forged SRV
record yields a certificate failure, never a silent impostor. Nothing here
touches a `.i2p` or `.onion` name -- only clearnet routes reach this module.
"""
from __future__ import annotations

import os
import random
import secrets
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

__all__ = ["SrvRecord", "SrvResult", "lookup", "order", "parse_response",
           "build_query", "set_system_resolvers", "system_resolvers"]

TYPE_SRV = 33
CLASS_IN = 1
DNS_PORT = 53
#: Per server, per transport. Two servers, UDP then maybe TCP: a failed
#: lookup costs seconds, not the minutes a tunnel does.
TIMEOUT = 3.0


@dataclass(frozen=True)
class SrvRecord:
    priority: int
    weight: int
    port: int
    target: str


@dataclass(frozen=True)
class SrvResult:
    """What the lookup found. `status` is safe to put in a diagnostic:

    found        records (possibly empty only if every target was ".")
    none         the name exists with no SRV records, or NXDOMAIN -> RFC 6120
                 says fall back to the domain itself on 5222
    unavailable  "." target: the service is decidedly not offered there
    no_resolver  the platform named no DNS server to ask
    failed       every resolver timed out or answered with an error
    """
    status: str
    records: tuple = ()
    detail: str = ""


class _Malformed(ValueError):
    pass


# -- resolvers -----------------------------------------------------------------

_LOCK = threading.Lock()
_RESOLVERS: List[str] = []


def set_system_resolvers(servers: Sequence[str]) -> int:
    """The DNS servers of the active network, from the platform (Kotlin).
    Only IP literals are kept. Returns how many were accepted."""
    good = []
    for s in servers or ():
        s = str(s).strip().split("%")[0]
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in s else socket.AF_INET, s)
        except (OSError, ValueError):
            continue
        if s not in good:
            good.append(s)
    with _LOCK:
        _RESOLVERS[:] = good[:4]
    return len(good[:4])


def system_resolvers() -> List[str]:
    with _LOCK:
        if _RESOLVERS:
            return list(_RESOLVERS)
    found = []
    for path in (os.path.join(os.environ.get("PREFIX", ""), "etc", "resolv.conf"),
                 "/etc/resolv.conf"):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        found.append(parts[1])
        except OSError:
            continue
        if found:
            break
    return found[:4]


# -- wire format -----------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError("bad DNS label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)   # RD set
    return header + _encode_name(name) + struct.pack("!HH", TYPE_SRV, CLASS_IN)


def _read_name(msg: bytes, off: int, depth: int = 0) -> "tuple[str, int]":
    labels, jumped, end = [], False, off
    for _ in range(128):
        if off >= len(msg):
            raise _Malformed("name runs off the end")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg) or depth > 16:
                raise _Malformed("bad compression pointer")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if ptr >= len(msg):
                raise _Malformed("pointer out of range")
            if not jumped:
                end = off + 2
            name, _ = _read_name(msg, ptr, depth + 1)
            if name:
                labels.append(name)
            jumped = True
            off = end
            return ".".join(labels), end
        if n & 0xC0:
            raise _Malformed("reserved label type")
        off += 1
        if off + n > len(msg):
            raise _Malformed("label runs off the end")
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n
    else:
        raise _Malformed("too many labels")
    return ".".join(labels), (end if jumped else off)


def parse_response(msg: bytes, qid: int) -> "tuple[int, bool, list]":
    """(rcode, truncated, [SrvRecord]). Raises _Malformed on nonsense."""
    if len(msg) < 12:
        raise _Malformed("short header")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid:
        raise _Malformed("id mismatch")
    if not flags & 0x8000:
        raise _Malformed("not a response")
    rcode, truncated = flags & 0x000F, bool(flags & 0x0200)
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    records = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        if off + 10 > len(msg):
            raise _Malformed("answer header runs off the end")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if off + rdlen > len(msg):
            raise _Malformed("rdata runs off the end")
        if rtype == TYPE_SRV and rclass == CLASS_IN:
            if rdlen < 7:
                raise _Malformed("short SRV rdata")
            pri, wei, port = struct.unpack("!HHH", msg[off:off + 6])
            target, _ = _read_name(msg, off + 6)
            records.append(SrvRecord(pri, wei, port, target.lower()))
        off += rdlen
    return rcode, truncated, records


def _ask(server: str, query: bytes, qid: int, timeout: float,
         opener: Optional[Callable] = None):
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = (opener or socket.socket)(fam, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(query, (server, DNS_PORT))
        for _ in range(4):                       # ignore stray datagrams
            data, _addr = s.recvfrom(4096)
            try:
                rcode, tc, recs = parse_response(data, qid)
            except _Malformed:
                continue
            if not tc:
                return rcode, recs
            break
        else:
            raise _Malformed("no matching answer")
    finally:
        s.close()
    # Truncated: the same question over TCP.
    t = (opener or socket.socket)(fam, socket.SOCK_STREAM)
    try:
        t.settimeout(timeout)
        t.connect((server, DNS_PORT))
        t.sendall(struct.pack("!H", len(query)) + query)
        head = _recv_exact(t, 2)
        data = _recv_exact(t, struct.unpack("!H", head)[0])
        rcode, _tc, recs = parse_response(data, qid)
        return rcode, recs
    finally:
        t.close()


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise _Malformed("TCP answer cut short")
        buf += chunk
    return buf


def lookup(domain: str, service: str = "xmpp-client", *,
           servers: Optional[Sequence[str]] = None, timeout: float = TIMEOUT,
           opener: Optional[Callable] = None) -> SrvResult:
    """`_<service>._tcp.<domain>` SRV, asked of the platform's resolvers."""
    name = "_%s._tcp.%s" % (service, domain.rstrip(".").lower())
    servers = list(servers) if servers is not None else system_resolvers()
    if not servers:
        return SrvResult("no_resolver", (), "no DNS server known")
    problems = []
    for server in servers:
        qid = secrets.randbelow(0x10000)
        try:
            rcode, recs = _ask(server, build_query(name, qid), qid, timeout, opener)
        except (OSError, _Malformed, struct.error) as exc:
            problems.append(type(exc).__name__)
            continue
        if rcode == 3 or (rcode == 0 and not recs):         # NXDOMAIN / NODATA
            return SrvResult("none", (), "no SRV record")
        if rcode != 0:
            problems.append("rcode%d" % rcode)
            continue
        if len(recs) == 1 and recs[0].target in ("", "."):
            return SrvResult("unavailable", (), "service decidedly not offered")
        recs = [r for r in recs if r.target not in ("", ".") and 0 < r.port]
        return SrvResult("found", tuple(recs), "%d record(s)" % len(recs))
    return SrvResult("failed", (), ",".join(problems) or "no answer")


def order(records: Sequence[SrvRecord], rng: Optional[random.Random] = None
          ) -> List[SrvRecord]:
    """RFC 2782 order: ascending priority, weighted random within one."""
    rng = rng or random.SystemRandom()
    out = []
    for pri in sorted({r.priority for r in records}):
        group = [r for r in records if r.priority == pri]
        while group:
            total = sum(r.weight for r in group)
            if total == 0:
                out.append(group.pop(0))
                continue
            pick = rng.uniform(0, total)
            acc = 0
            for i, r in enumerate(group):
                acc += r.weight
                if acc >= pick:
                    out.append(group.pop(i))
                    break
    return out
