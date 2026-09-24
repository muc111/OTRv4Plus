# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Names for people and places that a diagnostic may carry.

WHAT CHANGED, AND WHY IT CHANGED
--------------------------------
The first diagnostic log recorded JIDs and server names on purpose, and said
so: a roster, presence or routing fault is *about* those values, and a report
without them is hard to diagnose. That trade is now withdrawn. A diagnostic is
shared -- that is its whole purpose -- and what it carried was the user's
account name, everybody they talk to, and the I2P destination they talk
through. On a project whose reason for existing is that those three facts are
nobody else's business, a file that collects them into one place and invites
the user to post it into a bug tracker is the wrong side of the trade however
useful it is.

What replaces it costs almost nothing diagnostically. Every identity becomes a
short label -- `user-A`, `address-B` -- assigned in first-seen order and reused
for the rest of the run. The timeline still reads: "we asked for `user-A`'s
presence, `user-A` never answered, `user-A` was removed from the roster". What
it no longer says is who `user-A` is.

WHY THE LABEL IS A COUNTER AND NOT A HASH
-----------------------------------------
A hash of a short identity is not a one-way function in practice. Localparts
are short, domains are guessable and `.b32.i2p` addresses come from a published
set; anybody holding a candidate can hash it and compare. A counter has no
relationship to the value at all -- the mapping exists only in the memory of
the running process, is never written down and never exported, and dies with
it. There is nothing to invert.

The cost is that labels are not stable between runs, so two reports from the
same user cannot be correlated. That is a property, not a defect.

HOW IT IS APPLIED
-----------------
Centrally, in `android_bridge.trace`, over every field of every event. Not by
asking each call site to remember -- the call sites are the transport's inbound
handler, the keepalive, the roster and the Kotlin bridge, and the first one to
forget is the one whose fault ends up in the file. Two rules, in this order:

  1. **A key that names an identity has its whole value replaced.** `jid`,
     `peer`, `server`, `destination` and their relatives are aliased wholesale
     whatever shape the value has, because the key already says what it is.
  2. **Everything else is swept for identity SHAPES.** A JID, a `.i2p` or
     `.onion` address, an IPv4 or IPv6 literal embedded in a sentence is
     replaced in place. That is what catches an exception message quoting a
     host, which is the path nobody remembers.

No Android import, no slixmpp import, no I/O: every rule here is tested by
being run.
"""

from __future__ import annotations

import re
import threading
from typing import Dict, Optional

__all__ = ["AliasBook", "ALIASES", "alias", "scrub", "kind_for_key",
           "IDENTITY_KEY_HINTS", "KINDS"]

#: The kinds of thing that get a label, and the prefix each one uses.
#:
#: Distinguished so a report still reads: confusing a peer with a server is
#: exactly the sort of fault these logs exist to find, and one undifferentiated
#: `id-A` namespace would hide it.
KINDS = ("user", "address", "room", "id")

#: Substrings of a field name that mean the WHOLE value is an identity.
#:
#: Ordered longest-first where one contains another, because the kind is chosen
#: by the first hint that matches and `jid` appearing inside `barejid` must not
#: beat `room` inside `roomjid`.
_KEY_KINDS = (
    ("roomjid", "room"),
    ("room", "room"),
    ("muc", "room"),
    ("occupant", "user"),
    ("nick", "user"),
    ("barejid", "user"),
    ("fulljid", "user"),
    ("jid", "user"),
    ("peer", "user"),
    ("contact", "user"),
    ("username", "user"),
    ("user", "user"),
    ("account", "user"),
    ("sender", "user"),
    ("recipient", "user"),
    ("resource", "user"),
    ("mto", "user"),
    ("destination", "address"),
    ("dest", "address"),
    ("endpoint", "address"),
    ("hostname", "address"),
    ("server", "address"),
    ("domain", "address"),
    ("host", "address"),
    ("address", "address"),
    ("addr", "address"),
    ("tunnel", "id"),
    ("circuit", "id"),
    ("session_id", "id"),
)

#: Every hint, for callers that only want to ask "is this key an identity".
IDENTITY_KEY_HINTS = frozenset(hint for hint, _ in _KEY_KINDS)

# -- the shapes, most specific first ------------------------------------------
#
# Order is load-bearing. A JID pattern must run before the bare-host patterns,
# or `alice@example.i2p` is scrubbed to `alice@address-A` and the localpart --
# the part that names a person -- survives.

#: `localpart@domain` with an optional `/resource`.
#:
#: The localpart excludes the characters RFC 7622 forbids, so this does not run
#: backwards over a sentence -- and also `=`, `,` and `;`, which it does not.
#: Without `=` the pattern matched `jid=alice@host` as a whole, ate the field
#: name, and labelled it as a DIFFERENT identity from `alice@host` seen
#: elsewhere -- so the same account appeared twice under two labels, which is
#: the one thing that makes a timeline unreadable. RFC 7622 does allow `=` in a
#: localpart; in a diagnostic log a `key=value` pair is overwhelmingly more
#: likely, and the cost of being wrong that way round is a label rather than a
#: leak.
_JID = re.compile(
    r"[^\s@/:<>'\"&=,;()\[\]]+@[A-Za-z0-9][A-Za-z0-9.-]*(?:/\S+)?")

#: A 52-character base32 I2P destination hash, and any other `.i2p` name.
_I2P = re.compile(r"(?i)\b[A-Za-z0-9.-]+\.i2p\b")

#: Tor. Listed because TRANSPORT_POLICY.md allows it for messaging, so a
#: report from a Tor session must not name the circuit's far end either.
_ONION = re.compile(r"(?i)\b[A-Za-z0-9.-]+\.onion\b")

#: A base32 destination standing on its own, without the `.b32.i2p` suffix --
#: which is how SAM itself reports one.
_B32 = re.compile(r"(?i)\b[A-Z2-7]{52}\b")

#: A full I2P destination, which SAM gives as ~516 characters of base64.
#:
#: DELIBERATELY BROADER than "a destination". It matches any unbroken run of 80
#: or more base64-ish characters, so it will also swallow a long opaque token
#: that is not one. That is the right way round to be wrong: in a log whose
#: lines are stages, codes, counts and stack frames, an eighty-character word
#: with no spaces in it is overwhelmingly likely to be an address or a key. The
#: cost of a false positive is a label where a meaningless blob used to be; the
#: cost of a false negative is the destination this device talks to, in a file
#: the user is about to share.
_DEST64 = re.compile(r"\b[A-Za-z0-9~-]{80,}={0,2}\b")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: IPv6, with THREE colon-separated groups required rather than two.
#:
#: Two would match `12:34:56`, and this runs over rendered field values where
#: a duration or a clock time is entirely plausible. Three does not, and a
#: real address has seven -- or contains `::`, which is matched separately
#: because a compressed address can be as short as `::1`.
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){3,}[0-9A-Fa-f]{1,4}(?![\w:])"
    r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:?)*(?![\w:])")

#: Each shape and the kind of label it becomes, in the order they are applied.
_SHAPES = (
    (_JID, "user"),
    (_DEST64, "address"),
    (_I2P, "address"),
    (_ONION, "address"),
    (_B32, "address"),
    (_IPV4, "address"),
    (_IPV6, "address"),
)


def kind_for_key(name: str) -> Optional[str]:
    """Which kind of label a field called *name* should get, or None.

    None means the value is not an identity by virtue of its NAME. It is still
    swept for identity shapes; this only decides wholesale replacement.
    """
    lowered = str(name or "").lower()
    for hint, kind in _KEY_KINDS:
        if hint in lowered:
            return kind
    return None


class AliasBook:
    """Stable labels for identities, for the life of this process.

    Thread-safe. Written from the transport's asyncio loop thread, from Kotlin
    threads through the bridge, and read from whichever thread pressed Export.
    """

    def __init__(self) -> None:
        self._labels: Dict[str, str] = {}
        self._counts: Dict[str, int] = {}
        self._lock = threading.Lock()

    def alias(self, value: str, kind: str = "id") -> str:
        """The label for *value*, assigning one on first sight.

        The same value always gets the same label within a run, which is what
        makes a timeline readable. Case is folded and surrounding whitespace
        dropped first, so `Alice@Host` and `alice@host ` are one person rather
        than two.
        """
        text = str(value or "").strip()
        if not text:
            return ""
        if kind not in KINDS:
            kind = "id"
        key = "%s\x00%s" % (kind, text.lower())
        with self._lock:
            existing = self._labels.get(key)
            if existing is not None:
                return existing
            self._counts[kind] = self._counts.get(kind, 0) + 1
            label = "%s-%s" % (kind, _letters(self._counts[kind]))
            self._labels[key] = label
            return label

    def scrub(self, text: str) -> str:
        """Replace every identity SHAPE found in *text* with its label.

        For free text -- an exception's detail, a stage description -- where
        a host or a JID can appear in the middle of a sentence and no key name
        gives it away.
        """
        try:
            out = str(text)
        except Exception:                                    # pragma: no cover
            return ""
        for pattern, kind in _SHAPES:
            out = pattern.sub(lambda m: self.alias(m.group(0), kind), out)
        return out

    def field(self, name: str, value: str) -> str:
        """Alias a whole field, by name first and then by shape."""
        kind = kind_for_key(name)
        if kind is not None:
            return self.alias(value, kind)
        return self.scrub(value)

    def known(self) -> int:
        """How many distinct identities have been labelled. For the report's
        header, which says what was withheld rather than hiding that it was."""
        with self._lock:
            return len(self._labels)

    def clear(self) -> None:
        with self._lock:
            self._labels.clear()
            self._counts.clear()

    def __repr__(self) -> str:                               # pragma: no cover
        # Counts only. A repr listing the map would undo the entire module.
        with self._lock:
            return "<AliasBook labelled=%d>" % len(self._labels)


def _letters(n: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA. Spreadsheet columns.

    Letters rather than numbers because `user-3` and a count of 3 read alike in
    a table, and because a label that cannot be mistaken for a quantity is one
    fewer thing to misread at the moment somebody is trying to follow a fault.
    """
    out = ""
    while n > 0:
        n, rem = divmod(n - 1, 26)
        out = chr(ord("A") + rem) + out
    return out or "A"


#: The one book every component aliases against.
#:
#: A module singleton for the same reason `trace.TRACE` is one: the labels are
#: only useful if every component agrees on them, and threading a book through
#: the transport, the controller, the app and the bridge means the first
#: component that forgets is the one that leaks.
ALIASES = AliasBook()


def alias(value: str, kind: str = "id") -> str:
    """[AliasBook.alias] on the shared book."""
    return ALIASES.alias(value, kind)


def scrub(text: str) -> str:
    """[AliasBook.scrub] on the shared book."""
    return ALIASES.scrub(text)
