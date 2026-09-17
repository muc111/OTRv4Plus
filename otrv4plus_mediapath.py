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

**`6 I2P hops` was a string literal.** The application issues
`SESSION CREATE ... DESTINATION=TRANSIENT` and sets NO tunnel-length option
anywhere -- there is no `inbound.length`, no `outbound.length` and no `i2cp.*`
in this codebase. Tunnel length is therefore whatever the router defaults to,
and the number 6 was an assumption typed into a format string. [hop_note] says
only what is true.

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
    "REQUIRED_HOPS", "hop_note", "hops_are_configured",
    "MediaCounters", "delivery_line", "outage_line",
    "recovery_verdict", "budget_is_consistent", "Outage",
]

#: The documented per-direction tunnel length.
#:
#: NOT a setting this application applies -- see [hops_are_configured]. It is
#: recorded here because it is the project's stated requirement and because a
#: diagnostic that mentions hops must be able to say where the number came
#: from.
REQUIRED_HOPS = 3


def hops_are_configured() -> bool:
    """Whether this build asks the router for a tunnel length. It does not.

    A function rather than a constant so the answer has somewhere to be
    tested, and so the day somebody adds `inbound.length` to `SESSION CREATE`
    this returns True and [hop_note] starts making the stronger claim.

    THE FINDING: `SESSION CREATE STYLE=DATAGRAM ID=... DESTINATION=TRANSIENT
    SIGNATURE_TYPE=7 PORT=... HOST=...` carries no I2CP tunnel options at all.
    The 3-hop requirement is inherited from the router's configuration, not
    asserted by the client, so a router set to 1 hop would silently give a
    1-hop path while the old diagnostic claimed six.
    """
    return False


def hop_note() -> str:
    """How to describe the path, without claiming a measurement.

    The old wording was `(6 I2P hops)`, a literal. Two things were wrong with
    it: nothing had counted anything, and "6 hops" reads as one six-hop path
    rather than two three-hop ones, which is a different and much worse
    anonymity story than the architecture actually has.
    """
    if hops_are_configured():
        return ("I2P: %d-hop tunnel each direction, requested by this client"
                % REQUIRED_HOPS)
    return ("I2P: a tunnel each way, %d hops each at the router's default "
            "(this client does not set tunnel length)" % REQUIRED_HOPS)


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
