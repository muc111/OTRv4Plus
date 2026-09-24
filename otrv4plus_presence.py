# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What we actually know about a peer's availability, and when we know nothing.

THE BUG THIS REPLACES
---------------------
Presence was a `Dict[str, bool]` read with `.get(jid, False)`. That has two
states and the problem has three, so "we have never heard anything about this
peer" and "this peer is offline" were the same value — `False`.

The visible symptom was the opposite of what you would expect from that
description. A contact added a moment ago, whose presence the server had not
sent yet, was reported with `online=False`; the Kotlin layer refuses to claim
knowledge it does not have, so it rendered "presence unknown" and kept
rendering it. Replacing that string with "online" would have been a lie in the
other direction: the fix is for the model to be able to say *which of the three
things is true*.

A second defect sat behind it. The map was never cleared, and it lives on
`OtrApp`, which outlives the transport — so after a disconnect and reconnect a
contact who had gone offline in the meantime still read as ONLINE until they
happened to send another stanza. Availability learned over a stream that has
since died is not knowledge, it is a memory, and [forget_all] is what draws
that line.

THE THREE STATES
----------------
* **UNKNOWN** — we have heard nothing about this peer on this stream. The
  honest default, and the only correct answer before the first stanza.
* **ONLINE** — a presence stanza said so.
* **OFFLINE** — a presence stanza said so.

UNKNOWN is not a failure state and is not an error to be smoothed over. On a
subscription that does not carry presence (`none`, `from`), or before a peer
has approved a request, it is the permanently correct answer and the UI is
expected to say why.

`show` (away / dnd / xa / chat) rides along because RFC 6121 puts it in the
same stanza and a UI that has it can distinguish "online" from "away" without
another round trip. It is never used to *infer* availability: a peer is
available because the stanza type said so, not because it carried a show.

No Android import, no slixmpp import, no I/O: every rule here is tested by
being run.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Dict, Iterable, Tuple

__all__ = ["UNKNOWN", "ONLINE", "OFFLINE", "STATES", "PresenceBook"]

#: We have heard nothing about this peer on this stream.
UNKNOWN = "unknown"
#: A presence stanza said they are available.
ONLINE = "online"
#: A presence stanza said they are not.
OFFLINE = "offline"

#: Every state this module will ever return. The UI maps exactly these.
STATES = (UNKNOWN, ONLINE, OFFLINE)

#: RFC 6121 §4.7.2.1 show values, plus "" for plain available.
_SHOWS = frozenset({"", "away", "chat", "dnd", "xa"})


class PresenceBook:
    """Per-peer availability, keyed by bare JID.

    Thread-safe: written from the transport's asyncio loop thread and read
    from whichever thread the UI polls on, which on Android is a Kotlin
    thread with no loop of its own.

    BOUNDED, because what goes in here is chosen by other people. Every
    inbound presence stanza reaches `note`, and the sender's JID is the key.
    Unbounded, that is a memory-growth path a remote party drives; measured
    on the Android facade, twenty thousand distinct senders produced twenty
    thousand entries and nothing reclaimed them. `otrv4+.py`'s
    `DAKE1RateLimiter` took the same bound for the same reason and this
    follows it rather than inventing a second answer.
    """

    #: How many peers to remember. A handset roster is tens to hundreds, so
    #: this is far above any real contact list and only a flood reaches it.
    #:
    #: Eviction is LEAST-RECENTLY-NOTED, and the consequence is stated
    #: plainly: under a flood, a contact nobody has heard from in a while can
    #: fall out and read UNKNOWN. That is the direction this module already
    #: chose -- "we have heard nothing" is an answer it can give, and a
    #: forgotten entry says exactly that rather than making a stale claim.
    MAX_TRACKED = 2048

    def __init__(self) -> None:
        # Ordered so the bound has something to evict BY. Insertion order is
        # refreshed on every `note`, which makes it least-recently-noted.
        self._state: "OrderedDict[str, str]" = OrderedDict()
        self._show: Dict[str, str] = {}
        self._lock = threading.RLock()

    def _prune(self) -> None:
        """Drop the least recently noted peers down to [MAX_TRACKED].

        Called with the lock held. Both maps together, so `_show` cannot
        outlive the state it describes.
        """
        while len(self._state) > self.MAX_TRACKED:
            jid, _ = self._state.popitem(last=False)
            self._show.pop(jid, None)

    # -- writing -------------------------------------------------------------

    def note(self, peer: str, online: bool, show: str = "") -> None:
        """Record what a presence stanza said.

        `peer` is expected bare; the transport strips the resource before
        calling, because availability is a property of the account here and
        not of one of its devices.
        """
        jid = _bare(peer)
        if not jid:
            return
        show = show if show in _SHOWS else ""
        with self._lock:
            self._state[jid] = ONLINE if online else OFFLINE
            # Hearing about a peer makes them the most recently noted, so a
            # contact the server keeps broadcasting is not the one evicted.
            self._state.move_to_end(jid)
            # A show belongs to an available peer. Keeping a stale "away" on
            # somebody who has since gone offline would render as "offline
            # (away)", which is not a thing.
            self._show[jid] = show if online else ""
            self._prune()

    def forget(self, peer: str) -> None:
        """Drop one peer back to UNKNOWN.

        For a contact being removed, or a subscription being cancelled: what
        we learned under a subscription we no longer hold is not something we
        are entitled to keep showing.
        """
        jid = _bare(peer)
        with self._lock:
            self._state.pop(jid, None)
            self._show.pop(jid, None)

    def forget_all(self) -> None:
        """Every peer back to UNKNOWN. Called when the stream goes.

        NOT an optimisation and not tidying. Availability is knowledge about a
        peer *on a stream*, and when the stream dies the knowledge dies with
        it — the server stops telling us about changes, so anything still in
        here is a claim about the past presented as the present.
        """
        with self._lock:
            self._state.clear()
            self._show.clear()

    # -- reading -------------------------------------------------------------

    def state(self, peer: str) -> str:
        """One of [STATES]. UNKNOWN until a stanza says otherwise."""
        with self._lock:
            return self._state.get(_bare(peer), UNKNOWN)

    def show(self, peer: str) -> str:
        """The RFC 6121 show value, or "" for plain available/unknown."""
        with self._lock:
            return self._show.get(_bare(peer), "")

    def is_online(self, peer: str) -> bool:
        """Convenience, and deliberately NOT the whole answer.

        False for both OFFLINE and UNKNOWN, which is exactly the collapse this
        module exists to undo — so anything that needs to tell those apart must
        call [state]. It is kept because a caller that genuinely only wants
        "can I expect an answer right now" is asking a boolean question.
        """
        return self.state(peer) is ONLINE or self.state(peer) == ONLINE

    def known(self) -> Tuple[str, ...]:
        """Peers we have heard anything about, in insertion order."""
        with self._lock:
            return tuple(self._state)

    def online(self) -> Tuple[str, ...]:
        """Peers currently believed available.

        The discovery view's "who is online" list. Derived rather than stored,
        so it cannot drift from [state].
        """
        with self._lock:
            return tuple(j for j, s in self._state.items() if s == ONLINE)

    def snapshot(self) -> Dict[str, str]:
        """A copy of the whole book. For diagnostics and tests."""
        with self._lock:
            return dict(self._state)

    def __len__(self) -> int:
        with self._lock:
            return len(self._state)

    def __repr__(self) -> str:                               # pragma: no cover
        # Counts only. A repr that listed JIDs would be one `%r` away from a
        # log line naming everybody this account talks to.
        with self._lock:
            online = sum(1 for s in self._state.values() if s == ONLINE)
            return "<PresenceBook known=%d online=%d>" % (len(self._state),
                                                          online)


def _bare(peer: str) -> str:
    """The bare JID: no resource, lower-cased domain-insensitively.

    Presence arrives per-resource. Availability here is a property of the
    account, so `alice@host/phone` and `alice@host/desktop` are one peer — and
    without this the same person appears twice with different states.

    THE CASE HALF WAS DOCUMENTED AND NOT IMPLEMENTED. The line above has said
    "lower-cased domain-insensitively" since this module was written; the code
    split the resource off and left the case alone. Measured:

        note("alice@Host", online)
        state("alice@Host")       = online
        state("alice@host")       = unknown     <-- the same person
        forget("alice@host")      -> keys held: {'alice@Host': 'online'}

    The second line is the duplicate this function exists to prevent. The
    third is worse: [PresenceBook.forget] is the method that drops what we
    learned under a subscription we no longer hold, and a spelling it does not
    match means it silently drops nothing and the application goes on
    displaying the availability of somebody who revoked it.

    `casefold` rather than `lower`, deliberately, because
    `android_bridge.app.OtrApp.canonical_peer` uses `casefold` and the two
    have to produce the same key. Folding is one-way safe: it can merge two
    spellings of one account, never split one or join two accounts.
    """
    try:
        text = str(peer or "").strip()
    except Exception:                                        # pragma: no cover
        return ""
    return text.split("/", 1)[0].casefold()
