# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The `?OTRv4F|` fragmentation wire format, in one place.

WHY THIS MODULE EXISTS
----------------------
An OTRv4+ DAKE2 carries 1568 bytes of ML-KEM ciphertext, a 2592-byte ML-DSA-87
public key and a 4627-byte ML-DSA-87 signature -- 8787 bytes of post-quantum
material before the base64 armour, about 11.7 KB after it. I2P drops a stream
when a large message is written as one burst (the "SAM cliff", around 8 KB), so
anything that size has to go as several stanzas.

That was implemented in `otrv4plus_xmpp.py` as two methods on the terminal
client, and the Android transport had neither. The consequence was not a
degraded experience, it was a hard interoperability failure in both directions:
a Termux peer sent fragments the Android side handed to the engine as gibberish,
and an Android peer sent an 11.7 KB stanza straight at the cliff. Neither side
could complete a DAKE with the other, so no OTR session, no SMP, and no calls.

This module is that code, moved. It is the reference implementation and the only
one: the terminal client calls it and so does `android_bridge`, which is what
makes a phone and a laptop able to talk.

WHAT IS DELIBERATELY NOT HERE
-----------------------------
Any printing. `otrv4plus_xmpp.py` shadows `print` at module scope to route
through its session log, and the terminal's progress lines go through
`_sanitise` and are suppressed in probe mode. Moving those here would either
change what a terminal user sees or drag the terminal's I/O policy into a
module Android imports. So the logic is pure and the callers keep their own
voices, through the `on_debug` and `on_progress` hooks.

THE FORMAT
----------
One `<body>` per fragment::

    ?OTRv4F|<msg_id>|<n>|<total>|<chunk>

`msg_id` is eight lowercase hex digits from a monotonic per-sender counter,
`n` is 1-based, and `chunk` is a raw slice of the payload -- it may itself
contain `|`, which is why parsing splits with a maxsplit of 4.

A payload of `MAX_FRAGMENT` bytes or fewer is sent AS ITSELF, with no header
at all. That is not an optimisation to be tidied away later: it is what makes
an ordinary message indistinguishable on the wire from one sent by a client
that has never heard of fragmentation.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "MAX_FRAGMENT", "FRAGMENT_PREFIX", "MAX_FRAGMENTS",
    "MAX_INFLIGHT", "MAX_INFLIGHT_PER_PEER", "MAX_BUFFER_BYTES", "MAX_TOTAL_BYTES",
    "fragment", "is_fragment", "Reassembler",
]

#: Bytes per fragment, safely under the ~8 KB I2P cliff. Raising this to make
#: something fit is the one change that must never be made here: the number is
#: a property of the transport, not a tuning knob.
MAX_FRAGMENT = 6000

#: What a fragment starts with. Also the marker the receive path tests for.
FRAGMENT_PREFIX = "?OTRv4F|"

#: Ceiling on `total`. A payload needing more than this is not a message.
MAX_FRAGMENTS = 4096

#: How many reassembly sets one peer may have in flight. A peer -- a contact,
#: or one nickname in a room -- normally has one; a few cover a burst.
#:
#: FIXED (2026-10-16), formerly a known weakness: the budget was 64 sets
#: shared by everyone, evicted oldest-first. A peer could open 65 sets and
#: evict another peer's half-received DAKE2. The owner's 100-user stress test
#: hit it without an attacker: ~90 members' two-piece messages interleaved in
#: the room, more than 64 were in flight, and ~65% of messages were silently
#: dropped. A peer over its own budget now loses ITS oldest set, never
#: anyone else's.
MAX_INFLIGHT_PER_PEER = 16

#: How many sets may be in flight across all peers. Past it, the peer holding
#: the most sets loses its oldest one, so a flood costs the flooder first.
MAX_INFLIGHT = 1024

#: Cap on one reassembly set, and on all of them together. Without these a
#: peer could hold memory open by starting sets and never finishing them.
MAX_BUFFER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024


#: What an OTRv4+ PROTOCOL frame starts with -- DAKE, SMP, and DATA alike.
#:
#: The trailing space is part of it and is load-bearing: it is what stops
#: `?OTRv4F|` (a fragment) matching, and what stops a user typing "?OTRv4" from
#: being mistaken for protocol traffic.
#:
#: Lives here rather than in either client because BOTH have to agree about it,
#: and because getting it wrong is not a cosmetic bug. `otrv4plus_xmpp.py` had
#: the only copy; `android_bridge` had none, so the Android side rendered DAKE
#: frames into the chat window as text and never answered them -- which is a
#: handshake that cannot complete, presented to the user as gibberish from
#: their contact.
OTR_PREFIX = "?OTRv4 "


def is_fragment(body: str) -> bool:
    """Whether *body* is a fragment rather than a whole payload."""
    return body.startswith(FRAGMENT_PREFIX)


def is_otr_protocol(body) -> bool:
    """Whether *body* is OTR protocol traffic rather than something to show.

    THE CLASSIFICATION THE UI MUST NOT MAKE FOR ITSELF.

    Used on both ends of the engine:

      * INBOUND, before handing a payload up -- though the engine is the real
        arbiter there, since only it can tell ciphertext from a plaintext
        message that merely looks odd;
      * on the engine's OUTPUT, which is the case that matters, because
        `handle_incoming_message` returns EITHER decrypted text to display OR a
        protocol response to send, and telling them apart is the caller's job.

    Accepts `str` or `bytes` so a caller need not normalise first; anything
    else is not protocol traffic.
    """
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).startswith(OTR_PREFIX.encode("utf-8"))
    if isinstance(body, str):
        return body.startswith(OTR_PREFIX)
    return False


#: Fragment size for a MUC room. Prosody's mod_muc_limits refuses a room
#: message over `muc_max_char_count`, 5664 characters by default, and every
#: MLS frame is bigger than that (an ML-DSA-87 signature alone is ~4.6 KB;
#: "hi" is 6311 characters on the wire). At MAX_FRAGMENT each piece was 6021
#: characters, so a stock server refused every one -- the commit adding a
#: member never landed, the sender's group sat on a pending commit that
#: refuses every send, and the new member never got its Welcome (device test,
#: 2026-10-02). 4000 plus the "?OTRv4F|id|n|k|" header stays well under it.
#: The receiver is unchanged: a Reassembler takes any piece size.
ROOM_FRAGMENT = 4000


def fragment(payload: str, seq: int,
             size: int = MAX_FRAGMENT) -> Tuple[List[str], int]:
    """Split *payload* for the wire. Returns `(parts, new_seq)`.

    `parts` is the list of `<body>` strings to send, in order. For a payload of
    `MAX_FRAGMENT` or fewer it is `[payload]` -- the original string, unchanged
    and unwrapped.

    *seq* is the sender's monotonic fragment-set counter, and the returned
    `new_seq` replaces it.

    **The counter is consumed only when the payload actually fragments.** That
    is the behaviour of the code this was moved from, and it is load-bearing
    rather than incidental: a `msg_id` burned on a message that was never
    fragmented would shift every later id, so the two implementations would
    have produced different bytes for the same sequence of sends. The
    allocation lives in here, with the threshold it depends on, so a caller
    cannot get the order wrong.
    """
    size = max(1, min(int(size), MAX_FRAGMENT))
    if len(payload) <= size:
        return [payload], seq

    chunks = [
        payload[i:i + size]
        for i in range(0, len(payload), size)
    ]
    total = len(chunks)
    seq = (seq + 1) & 0xFFFFFFFF
    msg_id = "%08x" % seq
    parts = [
        "?OTRv4F|%s|%d|%d|%s" % (msg_id, i, total, chunk)
        for i, chunk in enumerate(chunks, 1)
    ]
    return parts, seq


class Reassembler:
    """Inbound fragments in, whole payloads out.

    One instance per receiving session. Holds partial sets keyed by
    `(peer, msg_id, total)`, so two peers -- or one peer with two messages in
    flight -- cannot contaminate each other's buffers.

    *on_debug* and *on_progress* are how a caller keeps its own voice. The
    terminal client passes its `_dbg` and a printer that respects probe mode;
    Android passes neither, because a message body's provenance is not
    something to write into logcat. Both are optional and neither is allowed
    to break reassembly: a hook that raises is swallowed.
    """

    def __init__(self,
                 on_debug: Optional[Callable[[str], None]] = None,
                 on_progress: Optional[Callable[[str, int, int], None]] = None):
        self._buffers: Dict[tuple, dict] = {}
        self._on_debug = on_debug
        self._on_progress = on_progress

    # -- the hooks, contained ------------------------------------------------

    def _debug(self, message: str) -> None:
        if self._on_debug is None:
            return
        try:
            self._on_debug(message)
        except Exception:
            pass

    def _progress(self, peer: str, have: int, total: int) -> None:
        if self._on_progress is None:
            return
        try:
            self._on_progress(peer, have, total)
        except Exception:
            pass

    # -- state ---------------------------------------------------------------

    @property
    def buffers(self) -> Dict[tuple, dict]:
        """The partial sets. Exposed for the tests and for diagnostics."""
        return self._buffers

    def pending(self) -> int:
        """How many incomplete sets are being held."""
        return len(self._buffers)

    def progress(self, peer: str) -> Optional[Tuple[int, int]]:
        """(parts held, parts expected) of the largest incomplete set from
        *peer*, or None. Counts only -- never the parts themselves."""
        best = None
        for (who, _msg_id, total), buf in self._buffers.items():
            if who != peer:
                continue
            if best is None or total > best[1]:
                best = (len(buf["parts"]), total)
        return best

    def clear(self) -> None:
        """Drop every partial set.

        Called when a session ends: fragments of a conversation that is over
        are not going to be completed, and holding them is holding plaintext
        fragments in memory for no reason.
        """
        self._buffers.clear()

    def _evict_from_busiest(self, by_bytes: bool = False) -> None:
        """Drop the oldest set of the peer holding the most sets (or bytes)."""
        load: Dict[str, int] = {}
        for (who, _m, _t), buf in self._buffers.items():
            load[who] = load.get(who, 0) + (buf["bytes"] if by_bytes else 1)
        busiest = max(load, key=lambda w: load[w])
        for k in self._buffers:
            if k[0] == busiest:
                del self._buffers[k]
                self._debug("[otr-recv] reassembly budget full; dropped the "
                            "oldest set from %s" % busiest)
                return

    # -- the work ------------------------------------------------------------

    def feed(self, peer: str, body: str) -> Optional[str]:
        """Take one inbound fragment.

        Returns the reassembled payload when this fragment completes a set,
        and `None` otherwise -- including for anything malformed, out of
        range, or over a limit. Never raises, and never returns a partial
        payload: an incomplete set stays incomplete, because handing half a
        frame to the decoder is worse than handing it nothing.
        """
        try:
            _, msg_id, n_s, total_s, chunk = body.split("|", 4)
            n = int(n_s)
            total = int(total_s)
        except Exception:
            self._debug("[otr-recv] malformed fragment from %s; dropping" % peer)
            return None

        # Reject nonsensical indices before they can corrupt a buffer.
        if total < 1 or total > MAX_FRAGMENTS or n < 1 or n > total:
            self._debug(
                "[otr-recv] fragment index out of range from %s; dropping" % peer)
            return None

        key = (peer, msg_id, total)
        if key not in self._buffers:
            # Room for a new set: first within this peer's own budget, then
            # within the shared one -- taken from whoever holds the most.
            mine = [k for k in self._buffers if k[0] == peer]
            while len(mine) >= MAX_INFLIGHT_PER_PEER:
                del self._buffers[mine.pop(0)]
            while len(self._buffers) >= MAX_INFLIGHT:
                self._evict_from_busiest()
        buf = self._buffers.setdefault(
            key, {"parts": {}, "total": total, "bytes": 0})
        # Adjust byte tally for a resent fragment so a peer cannot inflate it.
        prev = buf["parts"].get(n)
        if prev is not None:
            buf["bytes"] -= len(prev)
        buf["parts"][n] = chunk
        buf["bytes"] += len(chunk)

        if buf["bytes"] > MAX_BUFFER_BYTES:
            self._buffers.pop(key, None)
            self._debug(
                "[otr-recv] reassembly from %s exceeded %d bytes; dropping"
                % (peer, MAX_BUFFER_BYTES))
            return None
        while (sum(b["bytes"] for b in self._buffers.values()) > MAX_TOTAL_BYTES
               and self._buffers):
            self._evict_from_busiest(by_bytes=True)
        if key not in self._buffers:
            return None

        have = len(buf["parts"])
        self._debug(
            "[otr-recv]   fragment %d/%d from %s (id %s; have %d/%d)"
            % (n, total, peer, msg_id, have, total))

        if have < total:
            self._progress(peer, have, total)
            return None
        # Verify every index present before stitching.
        if any(i not in buf["parts"] for i in range(1, total + 1)):
            return None
        ordered = "".join(buf["parts"][i] for i in range(1, total + 1))
        self._buffers.pop(key, None)
        self._debug(
            "[otr-recv] reassembled %d fragments (%d bytes, id %s) from %s"
            % (total, len(ordered), msg_id, peer))
        return ordered
