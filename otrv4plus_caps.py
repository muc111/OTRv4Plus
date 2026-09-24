# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Which XMPP resources speak OTRv4Plus. Discovered, per resource, first.

THE RULE THIS EXISTS FOR
========================
Never send OTRv4+ protocol traffic to an XMPP resource that has not first
been identified as OTRv4Plus-capable.

OTRv4Plus interoperates only with OTRv4Plus: not with ordinary XMPP clients,
not with legacy OTRv4, not with other OTR implementations. Starting a DAKE to
find out would be sending an 11 KB handshake to somebody's phone app that
renders it as garbage -- and a bare JID is not one client: `alice@x/phone`
may run OTRv4Plus while `alice@x/laptop` runs something else, and the server
routes a bare-JID message to whichever it chooses.

HOW A RESOURCE IS IDENTIFIED
============================
Standard XMPP, nothing invented:

  * both OTRv4Plus clients advertise `FEATURE` in XEP-0030 service discovery,
    and so in their XEP-0115 entity-capabilities hash;
  * on each available presence from a full JID, the other side asks that
    JID's disco#info (unless its caps hash is already known) and looks for
    `FEATURE` -- exactly `FEATURE`. "OTR", "OTRv4", OMEMO or anything else is
    not accepted as a substitute;
  * a peer RESOURCE that itself sends us an OTRv4+ protocol frame is also
    OTRv4Plus-capable: only OTRv4Plus produces that wire format. This is how
    an older build that predates advertisement can still answer a handshake
    it started, and it is per resource like everything else.

Capability is NOT identity. A resource that advertises `FEATURE` has claimed
to speak the protocol, nothing more: it is not trusted, not verified, and
earns no call or file. The DAKE, the fingerprint and SMP decide those.

STALENESS
=========
Knowledge is per resource and dies with it: an unavailable presence, a new
caps hash, a reconnect of either side, or `clear()` forgets it. A bare JID
that supported OTRv4Plus yesterday from one client proves nothing about the
client it connects from today.

Pure logic, no I/O: the transport feeds it events and asks it questions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple

__all__ = ["FEATURE", "CAPS_NODE", "AVAILABLE", "UNAVAILABLE", "CHECKING",
           "OFFLINE", "UNKNOWN", "STATES", "CapabilityBook", "is_otr_protocol",
           "split_jid"]

#: The OTRv4Plus service-discovery feature. A URI this project controls, as
#: XEP-0030 asks; the fragment names the protocol generation. Changing it is
#: a protocol break: both clients must agree on it exactly.
FEATURE = "https://github.com/muc111/OTRv4Plus#otrv4plus-1"

#: The XEP-0115 node both clients advertise.
CAPS_NODE = "https://github.com/muc111/OTRv4Plus"

# States, as stable codes for the UI. Deliberately strings, not an enum: they
# cross into Kotlin.
UNKNOWN = "unknown"          # never heard from any resource of this JID
OFFLINE = "offline"          # no resource online
CHECKING = "checking"        # online, discovery not finished
AVAILABLE = "available"      # at least one online resource speaks OTRv4Plus
UNAVAILABLE = "unavailable"  # online, and no resource speaks OTRv4Plus
STATES = (UNKNOWN, OFFLINE, CHECKING, AVAILABLE, UNAVAILABLE)


def split_jid(jid: str) -> Tuple[str, str]:
    """(bare, resource), bare case-folded. Resource kept exactly."""
    jid = str(jid or "")
    bare, _, resource = jid.partition("/")
    return bare.strip().lower(), resource


def is_otr_protocol(payload: str) -> bool:
    """Whether *payload* is OTRv4+ protocol traffic (whole or fragment)."""
    return isinstance(payload, str) and payload.startswith("?OTRv4")


@dataclass
class _Resource:
    caps_ver: str = ""
    #: None = not yet known (a disco#info is due or in flight).
    supports: Optional[bool] = None
    #: How it was learned: "disco", "caps-cache", "in-band", or "".
    source: str = ""
    priority: int = 0
    seen: float = field(default_factory=time.monotonic)


class CapabilityBook:
    """Per-bare-JID, per-resource OTRv4Plus capability."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._jids: Dict[str, Dict[str, _Resource]] = {}
        #: The resource an OTRv4+ session was established with. OTRv4+ state
        #: lives in ONE client process; frames must keep going to it.
        self._pinned: Dict[str, str] = {}
        #: caps ver -> supports, learned from disco#info. XEP-0115's point.
        self._by_ver: Dict[str, bool] = {}
        self._ever_seen: set = set()

    # -- events --------------------------------------------------------------

    def presence_available(self, full_jid: str, caps_ver: str = "",
                           priority: int = 0) -> bool:
        """An available presence. Returns whether disco#info must be asked."""
        bare, resource = split_jid(full_jid)
        if not bare:
            return False
        self._ever_seen.add(bare)
        resources = self._jids.setdefault(bare, {})
        known = resources.get(resource)
        caps_ver = str(caps_ver or "")
        if known is not None and known.supports is not None and \
                (not caps_ver or caps_ver == known.caps_ver):
            known.priority = int(priority or 0)
            known.seen = self._clock()
            return False
        info = _Resource(caps_ver=caps_ver, priority=int(priority or 0),
                         seen=self._clock())
        if caps_ver and caps_ver in self._by_ver:
            info.supports, info.source = self._by_ver[caps_ver], "caps-cache"
        resources[resource] = info
        if known is not None and known.caps_ver != caps_ver and \
                self._pinned.get(bare) == resource:
            # The client behind the resource changed: its session is not ours.
            self._pinned.pop(bare, None)
        return info.supports is None

    def presence_unavailable(self, full_jid: str) -> bool:
        """An unavailable presence. Returns whether the PINNED resource left."""
        bare, resource = split_jid(full_jid)
        resources = self._jids.get(bare, {})
        if resource:
            resources.pop(resource, None)
        else:
            resources.clear()
        if self._pinned.get(bare) is not None and \
                self._pinned[bare] not in resources:
            self._pinned.pop(bare, None)
            return True
        return False

    def disco_result(self, full_jid: str, features: Iterable[str],
                     caps_ver: str = "") -> None:
        """disco#info answered. Exactly `FEATURE`, nothing else, counts."""
        bare, resource = split_jid(full_jid)
        supports = FEATURE in {str(f) for f in (features or ())}
        info = self._jids.setdefault(bare, {}).setdefault(resource, _Resource())
        if info.source != "in-band":
            info.supports, info.source = supports, "disco"
        ver = caps_ver or info.caps_ver
        if ver:
            self._by_ver[ver] = supports

    def disco_failed(self, full_jid: str) -> None:
        """No answer. Fail closed: not capable until something says so."""
        bare, resource = split_jid(full_jid)
        info = self._jids.get(bare, {}).get(resource)
        if info is not None and info.supports is None:
            info.supports, info.source = False, "disco"

    def inband_otr(self, full_jid: str) -> None:
        """This resource sent us an OTRv4+ frame: it speaks OTRv4Plus."""
        bare, resource = split_jid(full_jid)
        if not bare:
            return
        self._ever_seen.add(bare)
        info = self._jids.setdefault(bare, {}).setdefault(resource, _Resource())
        info.supports, info.source, info.seen = True, "in-band", self._clock()
        if resource:
            self._pinned[bare] = resource

    def pin(self, bare_jid: str, resource: str) -> None:
        self._pinned[split_jid(bare_jid)[0]] = resource

    def clear(self) -> None:
        """Our own stream went: every resource's presence is now unknown.

        The caps-hash cache survives: a hash names a feature set, whoever
        presents it, so it stays true across our reconnects.
        """
        self._jids.clear()
        self._pinned.clear()
        self._ever_seen.clear()

    def forget_jid(self, bare_jid: str) -> None:
        bare = split_jid(bare_jid)[0]
        self._jids.pop(bare, None)
        self._pinned.pop(bare, None)

    # -- questions -----------------------------------------------------------

    def target(self, bare_jid: str) -> Optional[str]:
        """The full JID OTRv4+ traffic for *bare_jid* must go to, or None.

        The pinned resource while it is online and capable. Otherwise the
        best capable resource (highest priority, then most recently seen).
        Never an incapable or unknown one, and never the bare JID -- the
        server would route that to whichever resource it likes.
        """
        bare = split_jid(bare_jid)[0]
        resources = self._jids.get(bare, {})
        pinned = self._pinned.get(bare)
        if pinned is not None:
            info = resources.get(pinned)
            if info is not None and info.supports:
                return "%s/%s" % (bare, pinned) if pinned else None
            return None
        capable = [(r, i) for r, i in resources.items() if i.supports and r]
        if not capable:
            return None
        capable.sort(key=lambda ri: (ri[1].priority, ri[1].seen), reverse=True)
        return "%s/%s" % (bare, capable[0][0])

    def pinned(self, bare_jid: str) -> Optional[str]:
        return self._pinned.get(split_jid(bare_jid)[0])

    def state(self, bare_jid: str) -> str:
        bare = split_jid(bare_jid)[0]
        resources = self._jids.get(bare, {})
        if not resources:
            return OFFLINE if bare in self._ever_seen else UNKNOWN
        values = [i.supports for i in resources.values()]
        if any(v is True for v in values):
            return AVAILABLE
        if any(v is None for v in values):
            return CHECKING
        return UNAVAILABLE

    def resources(self, bare_jid: str) -> Dict[str, Optional[bool]]:
        """resource -> supports, for display and tests. A copy."""
        return {r: i.supports for r, i in
                self._jids.get(split_jid(bare_jid)[0], {}).items()}
