# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the voice diagnostics are allowed to claim.

WHY THIS MODULE EXISTS
----------------------
A 41-minute call reported `0.0% of audio delivered` while both people were
talking to each other, and `6 I2P hops` from a program that has never asked
the router how many hops it is using. Both numbers were printed by format
strings with no way to test them, so neither had ever been wrong in a way
anything could notice.

Everything here is dependency-free and pure, so the claims can be EXECUTED.

THE THREE FINDINGS, AND WHAT EACH ONE COST
------------------------------------------
**`0.0% of audio delivered` was an integer-overflow-shaped bug, not a
measurement.** `JitterBuffer.sequence()` packs the rekey epoch into the top
bits of the ordering key, so subtracting two keys is a frame count only within
one epoch; across a rekey the difference is 2**62. The gap counter added that
to `gaps` at every rekey, and delivery was computed as `queued/(queued+gaps)`.
One rekey therefore drove a perfectly healthy call to 0.0%. Fixed in
`otrv4plus_voice.JitterBuffer.pop`; [delivery_line] exists so the reported
figure is never again a bare ratio with no sanity check.

**`6 I2P hops` was a string literal.** The application issued
`SESSION CREATE ... DESTINATION=TRANSIENT` and set NO tunnel-length option
anywhere -- no `inbound.length`, no `outbound.length`, no `i2cp.*`. Tunnel
length was therefore whatever the router defaulted to, and the number 6 was an
assumption typed into a format string. The client now **requests** its tunnel
length ([TUNNEL_OPTIONS]), and [hop_note] says only what is true about it --
which stops short of "enforced", for the reason in [hops_are_confirmed].

**A recovery is not a rebuild.** The state machine could say "recovered"
because it had finished rebuilding, which is a statement about the state
machine rather than about audio. [recovery_verdict] requires that inbound
media actually resumed.

WHAT MUST NOT APPEAR HERE
-------------------------
No destinations, no JIDs, no addresses. Everything is counters, durations and
opaque call-local labels -- see `ANDROID_ENCRYPTION_ARCHITECTURE.md` §7 and
`otrv4plus_alias` for why hashing an identity does not make it safe.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

__all__ = [
    "REQUIRED_HOPS", "LENGTH_VARIANCE", "TUNNEL_OPTIONS", "tunnel_options",
    "hop_note", "hops_are_configured", "hops_are_confirmed", "hop_range",
    "MediaCounters", "delivery_line", "outage_line",
    "recovery_verdict", "budget_is_consistent", "Outage",
]

#: The required per-direction tunnel length: three hops inbound, three hops
#: outbound, as two independent tunnels.
#:
#: NOT "6 hops". Six is the number you get by adding two tunnels together, and
#: it describes a different architecture -- one six-hop path -- with a
#: different and worse anonymity story than this one has.
REQUIRED_HOPS = 3

#: Pinned to zero so [REQUIRED_HOPS] is a floor rather than a midpoint.
#:
#: WHY THIS IS HERE AT ALL, since the brief said not to touch unrelated tunnel
#: parameters: `length` on its own does not mean "at least this many hops" in
#: either router. It is the centre of a range, and `lengthVariance` sets the
#: width. From i2pd `TunnelPool.cpp:645-660`:
#:
#:     numHops = m_NumInboundHops;
#:     if (m_InboundVariance) {
#:         int offset = rng() % (std::abs(m_InboundVariance) + 1);
#:         if (m_InboundVariance < 0) offset = -offset;
#:         numHops += offset;
#:     }
#:
#: so `inbound.length=3` with `inbound.lengthVariance=-2` builds 1, 2 or 3
#: hops. Java I2P documents the same latitude on
#: `TunnelPoolSettings.getLengthVariance`. Requesting a length while leaving
#: the variance to the router would therefore be exactly the silent reduction
#: this is meant to close, so the variance is part of the length request and
#: not an unrelated parameter.
#:
#: Zero is also both routers' own client default
#: (i2pd `DEFAULT_INBOUND_TUNNELS_LENGTH_VARIANCE = 0`, Java I2P
#: `DEFAULT_LENGTH_VARIANCE = 0`), so on a stock router this changes nothing.
#: It only removes a non-default router's ability to vary. The cost is real
#: and small: a router configured for `+1` would have built an occasional
#: 4-hop tunnel, and now builds 3. The requirement is 3.
LENGTH_VARIANCE = 0

#: The I2CP options this client puts on `SESSION CREATE`, in order.
#:
#: Both tunnels are named separately and deliberately. Length and variance are
#: the only tunnel parameters here: quantity, backup quantity and the rest are
#: left to the router.
TUNNEL_OPTIONS = (
    ("inbound.length", REQUIRED_HOPS),
    ("outbound.length", REQUIRED_HOPS),
    ("inbound.lengthVariance", LENGTH_VARIANCE),
    ("outbound.lengthVariance", LENGTH_VARIANCE),
)


def tunnel_options() -> str:
    """The options as they go on the wire, space-separated.

    SAM v3 carries I2CP options as bare `key=value` fields on the
    `SESSION CREATE` line. i2pd's parser splits the line on spaces and keeps
    every field containing `=` (`SAM.cpp` `ExtractParams`), handing the lot to
    `CreateNewLocalDestination`, where `Destination.cpp` reads
    `inbound.length` / `outbound.length` and passes them to the `TunnelPool`
    constructor as hop counts. That is the whole path from this string to the
    number of routers in the tunnel, and it is why these names and no others.

    No quoting, because none of these values contains a space and i2pd's
    parser does not implement the quoted form.
    """
    return " ".join("%s=%d" % (name, value) for name, value in TUNNEL_OPTIONS)


def hops_are_configured() -> bool:
    """Whether this build asks the router for a tunnel length. It does.

    Derived from [TUNNEL_OPTIONS] rather than returning a literal, so it
    cannot claim a configuration the wire does not carry: delete the options
    and this goes false on its own, and [hop_note] drops back to the weaker
    sentence without anybody having to remember to change it.
    """
    options = dict(TUNNEL_OPTIONS)
    return (options.get("inbound.length") == REQUIRED_HOPS
            and options.get("outbound.length") == REQUIRED_HOPS)


def hops_are_confirmed() -> bool:
    """Whether the router told us what it actually built. It did not.

    THE LIMITATION, stated rather than papered over. SAM's reply to
    `SESSION CREATE` is

        SESSION STATUS RESULT=OK DESTINATION=$privkey

    and that is all of it -- `SAMSocket::SendSessionCreateReplyOk` formats the
    private key and nothing else. There is no accepted-options echo anywhere
    in the SAM v3 grammar, so a router that clamped, ignored or never
    understood `inbound.length` answers exactly like one that honoured it.

    Java I2P can also lower the length after the fact: `lengthOverride` is
    "a temporary length to be used due to network conditions", set by the
    router, and the client is not consulted.

    So this client **requests** three hops each way and cannot **verify**
    three hops each way. Reading the count back would need an I2CP-level
    session the SAM bridge does not expose. Until something does verify it,
    every sentence this module produces says "requested".
    """
    return False


def hop_range(length: int, variance: int) -> Tuple[int, int]:
    """(fewest, most) hops a router may build for one direction.

    The point of this function is that the security property is a *floor*,
    and a floor is not what `length` alone buys -- see [LENGTH_VARIANCE].
    Written out so the rule can be executed against numbers instead of
    asserted in a comment.

    The two routers agree on the low end and differ on the high end for a
    negative variance: i2pd draws an offset in `[0, |variance|]` and negates
    it, so the range is `length-|variance| .. length`, while Java I2P
    documents `length-variance .. length+variance`. The wider upper bound is
    reported. The lower bound -- the one that decides whether the requirement
    holds -- is the same in both.
    """
    spread = abs(int(variance))
    low = int(length) - spread if int(variance) < 0 else int(length)
    return (max(0, low), int(length) + spread)


def hop_note() -> str:
    """How to describe the path, without claiming more than was done.

    The old wording was `(6 I2P hops)`, a literal. Two things were wrong with
    it: nothing had asked for or counted anything, and "6 hops" reads as one
    six-hop path rather than two three-hop ones, which is a different and much
    worse anonymity story than the architecture actually has.

    The wording now separates the two tunnels, and separates *requesting* a
    length from *knowing* one -- because [hops_are_confirmed] is false and a
    diagnostic that blurred those two would be the same class of mistake as
    the literal it replaced.
    """
    if not hops_are_configured():
        return ("I2P: a tunnel each way, %d hops each at the router's default "
                "(this client does not set tunnel length)" % REQUIRED_HOPS)
    note = ("I2P: %d-hop inbound + %d-hop outbound, requested by this client"
            % (REQUIRED_HOPS, REQUIRED_HOPS))
    if not hops_are_confirmed():
        note += " (SAM does not report the length the router applied)"
    return note


class MediaCounters:
    """What actually happened to the audio, as counts rather than a verdict.

    Every field is a plain integer a stage increments. Nothing here is a
    ratio: §18's requirement is that the summary corresponds to measurements,
    and a percentage is where the measurement stops being checkable.

    The names are the pipeline stages, so a gap between two adjacent counters
    localises a fault to one stage instead of to "the network".
    """

    __slots__ = ("captured", "encoded", "encrypted", "sent",
                 "received", "decrypted", "queued", "played",
                 "concealed", "shed", "gaps", "underruns")

    def __init__(self, **counts):
        for name in self.__slots__:
            setattr(self, name, int(counts.get(name, 0)))

    def as_dict(self) -> Dict[str, int]:
        return {name: getattr(self, name) for name in self.__slots__}

    @property
    def is_empty(self) -> bool:
        """Nothing was measured at all.

        Distinguished from "everything was zero", because a call that never
        started and a call that lost all its audio need different sentences
        and the old summary gave them the same one.
        """
        return not any(getattr(self, n) for n in self.__slots__)

    def __repr__(self):                                      # pragma: no cover
        return "<MediaCounters sent=%d played=%d>" % (self.sent, self.played)


def delivery_line(counters: MediaCounters) -> str:
    """What was received and played, in frames.

    NOT "x% of audio delivered". That phrasing is what let a rekey-corrupted
    counter print `0.0%` to somebody who had just finished a working
    conversation, and even uncorrupted it invites the reading "zero audio was
    received" for a number that never meant that.

    Explicit counts instead, per §18, and only the ones that were actually
    measured: a counter that was never wired prints nothing rather than a
    confident zero.
    """
    if counters.is_empty:
        return "no media counters were recorded"
    parts = []
    if counters.received:
        parts.append("%d received" % counters.received)
    if counters.played:
        parts.append("%d played" % counters.played)
    if counters.concealed:
        parts.append("%d concealed" % counters.concealed)
    if counters.gaps:
        parts.append("%d missing" % counters.gaps)
    if counters.shed:
        parts.append("%d shed locally" % counters.shed)
    if counters.underruns:
        parts.append("%d underrun(s)" % counters.underruns)
    if not parts:
        return "no media counters were recorded"
    return ", ".join(parts) + " (frames)"


class Outage:
    """One period with no inbound media, and what ended it.

    `resumed_frames` is the evidence. A rebuild that finished is not a
    recovery; frames arriving after it is.
    """

    __slots__ = ("started_s", "ended_s", "rebuilt", "resumed_frames")

    def __init__(self, started_s: float, ended_s: Optional[float] = None,
                 rebuilt: bool = False, resumed_frames: int = 0):
        self.started_s = float(started_s)
        self.ended_s = None if ended_s is None else float(ended_s)
        self.rebuilt = bool(rebuilt)
        self.resumed_frames = int(resumed_frames)

    @property
    def duration_s(self) -> Optional[float]:
        if self.ended_s is None:
            return None
        return max(0.0, self.ended_s - self.started_s)

    @property
    def recovered(self) -> bool:
        """Media actually came back.

        Requires frames, not a state transition. §27: "media path recovered"
        must mean datagrams were received and processed again.
        """
        return self.ended_s is not None and self.resumed_frames > 0

    def __repr__(self):                                      # pragma: no cover
        return "<Outage %.0fs recovered=%s>" % (self.duration_s or 0.0,
                                                self.recovered)


def recovery_verdict(outages: Sequence[Outage]) -> Tuple[str, str]:
    """Whether the recovery machinery actually helped. Returns (code, text).

    §16 asks this directly, and the honest answer needs the distinction the
    old code could not make: a rebuild that completed while no media resumed
    is a failed recovery reported as a success.
    """
    if not outages:
        return ("none", "no media outages")
    total = len(outages)
    recovered = sum(1 for o in outages if o.recovered)
    rebuilds = sum(1 for o in outages if o.rebuilt)
    unresolved = total - recovered

    text = "%d outage(s)" % total
    if rebuilds:
        text += ", %d path rebuild(s)" % rebuilds
    text += ", %d recovered" % recovered
    durations = [o.duration_s for o in outages if o.duration_s is not None]
    if durations:
        text += ", longest %.0fs" % max(durations)

    if unresolved and recovered:
        return ("partial", text)
    if unresolved:
        return ("failed", text)
    return ("recovered", text)


def budget_is_consistent(
    mouth_to_ear_ms: float,
    network_ms: float,
    jitter_ms: float,
    playout_ms: float,
    tolerance_ms: float = 60.0,
) -> bool:
    """Whether the latency budget adds up.

    §19: the summary must be internally consistent, and a component that does
    not add up is usually a counter reading from a different call rather than
    a surprising network. The tolerance is generous because each part is a
    median of a different sample window, so they are not required to sum
    exactly -- only to fail to sum by an amount that would indicate a stale
    or unwired value.

    The observed call: 706 + 190 + 52 = 948, and the reported mouth-to-ear was
    ~948 ms. Consistent.
    """
    try:
        total = float(network_ms) + float(jitter_ms) + float(playout_ms)
        return abs(float(mouth_to_ear_ms) - total) <= float(tolerance_ms)
    except (TypeError, ValueError):                          # pragma: no cover
        return False


def outage_line(outages: Sequence[Outage]) -> str:
    """One line about interruptions, or nothing when there were none."""
    code, text = recovery_verdict(outages)
    if code == "none":
        return ""
    return text
