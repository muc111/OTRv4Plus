# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group verification: every member proves they know the group's passphrase.

CHANGED 2026-10-25 (owner): the creator, not every pair. Every pair meant
n(n-1)/2 SMPs -- 4,950 for 100 members, roughly 40,000 room messages that
every member downloads (~250-300 MB over I2P, hours). Now the group's
coordinator (its creator: the first MLS leaf; the longest-standing member
once they have left) alone starts a run and runs one SMP with each member
who joins it -- 99 for 100 members, minutes. Each success is VOUCHED for to
the group ({"t": "vouch"}, an MLS application message, so authenticated to
the coordinator) with the member's group-key fingerprint; a member accepts a
vouch only from the coordinator and only for the key the group holds for
that person now. What members trust: the coordinator's word about each
other, which they already trust with who is in the group at all. The text
below describes the SMP itself, which is unchanged.

ONE ATTEMPT (owner, 2026-10-25: "verify must only be once ... anyone who got
it wrong can be excluded and kicked from group by creator"). Each member key
gets one SMP; a failure is recorded against that key (SecureGroups, kept
across restarts) and is never retried -- a passphrase cannot be guessed at
one try per run -- until the creator removes them (one commit for all who
failed) or they are invited back with a new key. A run ends, and its
passphrase is zeroed, once every member is verified or failed.

Owner design (2026-10-10): whoever creates a secure group sets a passphrase,
told to the members out of band (in person, on a call -- never in a chat).
Any member starts a verification; each member who joins it types the
passphrase; every pair of members who both joined then runs the OTRv4+ SMP
(the Rust core's hybrid ML-KEM-1024 + ML-DSA-87 + ZKP SMP, `RustSMP`) with
it. A pair whose SMP succeeds is verified in the group -- which is what a
group call requires -- and a member who typed the wrong passphrase fails
with everyone and stays out of calls.

WHAT IS PROVED. That the other member knows the passphrase. SMP reveals
nothing about it, and a wrong guess costs a live exchange the other side
sees (and that is capped, MAX_FAILURES). It is weaker than pairwise SMP,
where every pair has its own secret: anyone who learns the group passphrase
passes. It is an extra gate on top of being an invited member, which an
outsider is not.

WHAT IT IS BOUND TO. Each SMP's secret is derived (in Rust) from the
passphrase, a session id of this group and this run, and the two members'
GROUP keys (their MLS leaf signature fingerprints) -- so a success verifies
exactly the key the group holds for them, and nothing else: their 1:1
OTRv4+ conversation is untouched.

TRANSPORT. Control messages inside the group (MLS application messages with
VERIFY_PREFIX: encrypted, authenticated to a member, never shown as chat).
SMP steps are addressed to one member; the others ignore them.

The passphrase: held in a bytearray only while a run needs it, handed to Rust
by `set_secret_from_bytearray` (which copies it and zeroes the copy given),
and zeroed when the run ends or expires. Never written to disk, never sent.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .events import GroupChanged

__all__ = ["VERIFY_PREFIX", "GroupVerify"]

#: Prefix of a verification control message inside the MLS plaintext.
VERIFY_PREFIX = "\x00OTRv4GV1:"
#: A run is forgotten (and its passphrase zeroed) after this long.
RUN_SECONDS = 30 * 60.0
#: SMPs with one member per run: one (see ONE ATTEMPT above).
MAX_FAILURES = 1
#: One pair's SMP over I2P before any has been measured: four ~6-12 KB
#: messages through the room, each paced and relayed. Measured runs replace it.
PAIR_SECONDS_GUESS = 90.0
MAX_CONTROL_LEN = 64 * 1024
MAX_PASSPHRASE = 512
MIN_PASSPHRASE = 8


@dataclass
class _Run:
    run_id: str                         # 32 hex
    starter: str
    started_at: float
    secret: Optional[bytearray] = None  # set when we join
    ready: set = field(default_factory=set)          # members who joined
    smp: Dict[str, Any] = field(default_factory=dict)  # peer -> RustSMP
    result: Dict[str, str] = field(default_factory=dict)  # peer -> verified/failed
    failures: Dict[str, int] = field(default_factory=dict)
    #: When each pair's SMP began, and how long finished ones took (ETA).
    began: Dict[str, float] = field(default_factory=dict)
    took: list = field(default_factory=list)
    finished_said: bool = False
    #: Members this run has been announced to (members of the group when it
    #: was started or re-announced). Someone added later has not heard of it.
    announced: set = field(default_factory=set)
    reannounced_at: float = -1e18


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


class GroupVerify:
    """Shared-passphrase verification for this account's secure groups."""

    RUN_SECONDS = RUN_SECONDS
    MAX_FAILURES = MAX_FAILURES

    def __init__(self, groups: Any, *, emit: Callable[[Any], None],
                 core: Any = None, clock: Callable[[], float] = time.time):
        self._groups = groups
        self._emit = emit
        self._core = core
        self._clock = clock
        self._lock = threading.RLock()
        self._runs: Dict[str, _Run] = {}                 # room -> run
        #: Set at creation by the group's creator: room -> passphrase.
        self._preset: Dict[str, bytearray] = {}
        groups.set_verify_handler(self._on_control)
        # A member added while a run is going did not hear its "start" (it
        # was sent before they could read the group): told again on the
        # commit that adds them. Device test, 2026-10-11: a laptop invited
        # back was never asked, and its own /smp reached nobody.
        adder = getattr(groups, "add_epoch_listener", None)
        if adder is not None:
            adder(self._on_epoch)

    # -- what the user does ---------------------------------------------------

    @staticmethod
    def check_passphrase(secret: bytes) -> Optional[str]:
        if len(secret) < MIN_PASSPHRASE:
            return "passphrase_too_short"
        if len(secret) > MAX_PASSPHRASE:
            return "passphrase_too_long"
        return None

    def set_passphrase(self, room: str, secret: bytearray) -> None:
        """The creator's passphrase, kept in memory for their first run."""
        problem = self.check_passphrase(bytes(secret))
        if problem:
            raise ValueError(problem)
        with self._lock:
            old = self._preset.pop(room, None)
            if old is not None:
                _zero(old)
            self._preset[room] = bytearray(secret)
        _zero(secret)

    def has_passphrase(self, room: str) -> bool:
        with self._lock:
            return room in self._preset

    def pending(self, room: str) -> Optional[Dict[str, Any]]:
        """A run another member started that we have not joined, if any."""
        with self._lock:
            run = self._live(room)
            if run is None or run.secret is not None:
                return None
            return {"run": run.run_id, "starter": run.starter}

    def coordinator(self, room: str) -> str:
        """Who starts this group's verification (owner, 2026-10-25): its
        creator, the member at the first leaf of the MLS tree -- the group's
        own authenticated membership, not the room's say-so. Once the creator
        has left, the longest-standing member, so a group never loses the
        ability to be verified. "" when the group cannot be read."""
        ids = self._member_ids(room)
        return ids[0] if ids else ""

    def may_start(self, room: str) -> bool:
        """Whether this device may START a run (anyone may JOIN one)."""
        return bool(self._me()) and self._me() == self.coordinator(room)

    def start(self, room: str, secret: Optional[bytearray] = None) -> str:
        """Start a verification (the coordinator only) or join the one that
        is running, with `secret`, or the passphrase set at creation.
        Returns the run id."""
        with self._lock:
            run = self._live(room)
            if run is None and not self.may_start(room):
                if secret is not None:
                    _zero(secret)
                # Everyone is verified or has had their one attempt: there
                # is nothing left to join (the creator removes who failed).
                if self.settled(room):
                    return ""
                raise ValueError("only_the_creator_starts")
            if secret is None:
                preset = self._preset.get(room)
                if preset is None:
                    raise ValueError("passphrase_needed")
                secret = bytearray(preset)
            problem = self.check_passphrase(bytes(secret))
            if problem:
                _zero(secret)
                raise ValueError(problem)
            fresh = run is None
            if fresh:
                run = _Run(run_id=os.urandom(16).hex(), starter=self._me(),
                           started_at=self._clock(),
                           announced=set(self._member_ids(room)))
                self._runs[room] = run
            if run.secret is not None:
                _zero(run.secret)
            run.secret = bytearray(secret)
            _zero(secret)
            run.ready.add(self._me())
            run_id = run.run_id
        if fresh:
            # Ours: said to us, but not announced as somebody else's request.
            self._emit(GroupChanged(peer=room, change="verify_begun",
                                    detail=self._me()))
        # "start" every time, not only for a new run: a member who missed it
        # (added since, or whose copy was replaced) learns of it here, and
        # one who knows it ignores it.
        self._send(room, {"t": "start", "run": run_id, "by": run.starter})
        self._send(room, {"t": "ready", "run": run_id})
        self._pair_up(room)
        return run_id

    def status(self, room: str) -> Dict[str, str]:
        """Each other member: verified / failed / running / waiting."""
        out: Dict[str, str] = {}
        with self._lock:
            run = self._live(room)
        try:
            members = self._groups.members(room)
        except Exception:
            return out
        for m in members:
            if m["me"]:
                continue
            jid = m["jid"]
            if m["verified"]:
                out[jid] = "verified"
            elif m.get("failed"):
                out[jid] = "failed"
            elif run is None:
                out[jid] = "not_verified"
            elif run.result.get(jid) == "failed":
                out[jid] = "failed"
            elif jid in run.smp:
                out[jid] = "running"
            else:
                out[jid] = "waiting"
        return out

    def progress(self, room: str) -> Dict[str, Any]:
        """Where a verification stands, from this member's side: every other
        member is verified, excluded (the passphrase did not match), running,
        or not joined yet; `eta` estimates the seconds left for those who
        joined (measured per pair on this run, a fixed guess until then)."""
        status = self.status(room)
        with self._lock:
            run = self._live(room)
            took = list(run.took) if run else []
            began = dict(run.began) if run else {}
            active = run is not None
            joined = run is not None and run.secret is not None
        verified = sorted(j for j, s in status.items() if s == "verified")
        excluded = sorted(j for j, s in status.items() if s == "failed")
        running = sorted(j for j, s in status.items() if s == "running")
        waiting = sorted(j for j, s in status.items()
                         if s in ("waiting", "not_verified"))
        total = len(status)
        per_pair = (sum(took) / len(took)) if took else PAIR_SECONDS_GUESS
        now = self._clock()
        left = [max(0.0, per_pair - (now - began[j])) for j in running if j in began]
        # Pairs run side by side, but their messages share one paced room.
        eta = int(max(left) if left else 0) + int(per_pair * len(waiting) / 2) \
            if (running or waiting) else 0
        return {
            "active": active, "joined": joined, "total": total,
            "done": len(verified) + len(excluded),
            "verified": verified, "excluded": excluded,
            "running": running, "waiting": waiting, "eta": eta,
        }

    def active_rooms(self) -> list:
        with self._lock:
            return [r for r in list(self._runs) if self._live(r) is not None]

    def all_verified(self, room: str) -> bool:
        st = self.status(room)
        return bool(st) and all(v == "verified" for v in st.values())

    def settled(self, room: str) -> bool:
        """Every other member is verified or has failed their one attempt."""
        st = self.status(room)
        return bool(st) and all(v in ("verified", "failed") for v in st.values())

    def failed(self, room: str) -> list:
        return sorted(j for j, v in self.status(room).items() if v == "failed")

    def cancel(self, room: str) -> None:
        with self._lock:
            run = self._runs.pop(room, None)
        if run is not None:
            self._end(run)

    def forget(self, room: str) -> None:
        """The group is gone (left, deleted, wiped): nothing of it stays."""
        self.cancel(room)
        with self._lock:
            preset = self._preset.pop(room, None)
        if preset is not None:
            _zero(preset)

    def tick(self) -> None:
        """Expire old runs (their passphrase is zeroed)."""
        with self._lock:
            rooms = list(self._runs)
        for room in rooms:
            with self._lock:
                self._live(room)

    # -- from the group -------------------------------------------------------

    def _on_control(self, room: str, sender: str, verified: bool, payload: str) -> None:
        if len(payload) > MAX_CONTROL_LEN or sender == self._me():
            return
        try:
            msg = json.loads(payload)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        kind, run_id = msg.get("t"), msg.get("run")
        if not isinstance(run_id, str) or len(run_id) != 32 or not all(
                c in "0123456789abcdef" for c in run_id):
            return
        if kind in ("start", "ready"):
            by = msg.get("by")
            run = self._reconcile(room, sender, run_id,
                                  by if isinstance(by, str) and by else sender)
            if run is None or kind == "start":
                return
        else:
            with self._lock:
                run = self._live(room)
                if run is None or run.run_id != run_id:
                    return
        if kind == "ready":
            with self._lock:
                run.ready.add(sender)
                # They just joined: an exchange we began before that (which
                # they could not answer) starts again.
                stale = run.smp.pop(sender, None) if run.result.get(sender) != "verified" else None
            if stale is not None:
                try:
                    stale.destroy()
                except Exception:
                    pass
            self._pair_up(room)
        elif kind == "smp" and msg.get("to") == self._me():
            self._on_step(room, run, sender, msg)
        elif kind == "vouch":
            self._on_vouch(room, sender, run, msg)

    #: At most one re-announcement of our run per room in this many seconds.
    REANNOUNCE_SECONDS = 10.0

    def _reconcile(self, room: str, sender: str, run_id: str,
                   by: str = "") -> Optional[_Run]:
        """Settle which run the room is in, given `sender` speaks of
        `run_id` ("start" or "ready"). Returns the run when it is that one.

        Two runs at once (one started before a member could read the group,
        another started by that member) used to talk past each other: each
        side ignored the other's run, and nobody was asked or verified. Now
        the run with the LOWER id wins everywhere: a member in the higher
        one moves to the lower (keeping the passphrase its user typed for
        this group, so it joins at once), and a member in the lower one says
        so again. A run we had not heard of is one we were not told about:
        we are asked to join it."""
        reannounce = adopt_with = None
        emit_started = False
        with self._lock:
            run = self._live(room)
            if run is not None and run.run_id == run_id:
                return run
            # A run is adopted only if the coordinator started it: a member
            # starting their own is not followed (an older build that sends
            # no "by" is taken as its sender, so its creator's runs still are).
            if (by or sender) != self.coordinator(room):
                return None
            if run is not None and run.run_id < run_id:
                now = self._clock()
                if now - run.reannounced_at >= self.REANNOUNCE_SECONDS:
                    run.reannounced_at = now
                    reannounce = run
                run = None
                result = None
            else:
                secret = bytearray(run.secret) if run is not None and run.secret is not None else None
                if run is not None:
                    self._end(run)
                new = _Run(run_id=run_id, starter=by or sender, started_at=self._clock(),
                           announced=set(self._member_ids(room)))
                self._runs[room] = new
                result = new
                if secret is not None:
                    adopt_with = secret
                else:
                    emit_started = True
        if reannounce is not None:
            self._send(room, {"t": "start", "run": reannounce.run_id,
                              "by": reannounce.starter})
            if reannounce.secret is not None:
                self._send(room, {"t": "ready", "run": reannounce.run_id})
            return None
        if emit_started:
            self._emit(GroupChanged(peer=room, change="verify_started", detail=sender))
        if adopt_with is not None:
            # Our user already gave this group's passphrase: join it.
            self.start(room, adopt_with)
        return result

    def _on_epoch(self, room: str) -> None:
        """A commit: anyone added since our run was announced is told now."""
        with self._lock:
            run = self._live(room)
            if run is None or run.secret is None:
                return
            members = set(self._member_ids(room))
            new = members - run.announced - {self._me()}
            run.announced |= members
            if not new:
                return
        self._send(room, {"t": "start", "run": run.run_id, "by": run.starter})
        self._send(room, {"t": "ready", "run": run.run_id})

    def _member_ids(self, room: str) -> list:
        try:
            return [m["jid"] for m in self._groups.members(room)]
        except Exception:
            return []

    # -- the pairs ----------------------------------------------------------

    def _pair_up(self, room: str) -> None:
        """The coordinator starts SMP with each member who joined; nobody
        else starts any (see the module docstring). Never twice with a key
        that failed."""
        me = self._me()
        if me != self.coordinator(room):
            return
        try:
            failed = {m["jid"] for m in self._groups.members(room) if m.get("failed")}
        except Exception:
            failed = set()
        with self._lock:
            run = self._live(room)
            if run is None or run.secret is None:
                return
            todo = [p for p in sorted(run.ready)
                    if p != me and p not in run.smp
                    and run.result.get(p) != "verified" and p not in failed
                    and run.failures.get(p, 0) < self.MAX_FAILURES]
        for peer in todo:
            try:
                smp = self._new_smp(room, run, peer, initiator=True)
                step1 = bytes(smp.generate_smp1(None))
            except Exception:
                self._fail(room, run, peer)
                continue
            with self._lock:
                run.smp[peer] = smp
                run.began[peer] = self._clock()
            self._send(room, {"t": "smp", "run": run.run_id, "to": peer,
                              "step": 1, "d": _b64e(step1)})
            self._emit(GroupChanged(peer=room, change="verify_running", detail=peer))

    def _on_step(self, room: str, run: _Run, peer: str, msg: Dict[str, Any]) -> None:
        step = msg.get("step")
        try:
            data = _b64d(msg.get("d") or "")
        except (ValueError, binascii.Error):
            return
        with self._lock:
            smp = run.smp.get(peer)
            have_secret = run.secret is not None
        try:
            if step == 1:
                if not have_secret or run.failures.get(peer, 0) >= self.MAX_FAILURES:
                    return                 # we have not joined: nothing to answer
                if peer != self.coordinator(room):
                    return                 # only the coordinator verifies with us
                smp = self._new_smp(room, run, peer, initiator=False)
                with self._lock:
                    run.smp[peer] = smp
                    run.began[peer] = self._clock()
                reply, nxt = bytes(smp.process_smp1_generate_smp2(data)), 2
            elif smp is None:
                return
            elif step == 2:
                reply, nxt = bytes(smp.process_smp2_generate_smp3(data)), 3
            elif step == 3:
                reply, nxt = bytes(smp.process_smp3_generate_smp4(data)), 4
            elif step == 4:
                ok = bool(smp.process_smp4(data))
                self._done(room, run, peer, ok)
                return
            else:
                return
        except Exception:
            self._fail(room, run, peer)
            return
        self._send(room, {"t": "smp", "run": run.run_id, "to": peer,
                          "step": nxt, "d": _b64e(reply)})
        if step == 3:
            # The responder knows the answer once SMP3 is processed.
            self._done(room, run, peer, bool(smp.is_verified()))
        elif step == 1:
            self._emit(GroupChanged(peer=room, change="verify_running", detail=peer))

    def _new_smp(self, room: str, run: _Run, peer: str, *, initiator: bool):
        core = self._core_module()
        smp = core.RustSMP(initiator)
        ours = bytes.fromhex(self._groups.own_fingerprint(room))
        theirs = bytes.fromhex(self._groups.member_fingerprint(room, peer))
        sid = hashlib.sha3_256(b"OTRv4+/GroupSMP/v1\x00" + room.encode() + b"\x00"
                               + bytes.fromhex(run.run_id)).digest()
        with self._lock:
            secret = bytearray(run.secret or b"")
        smp.set_secret_from_bytearray(secret, sid, ours, theirs)   # zeroes `secret`
        return smp

    def _done(self, room: str, run: _Run, peer: str, ok: bool) -> None:
        if not ok:
            self._fail(room, run, peer)
            return
        with self._lock:
            run.smp.pop(peer, None)
            run.result[peer] = "verified"
            self._took(run, peer)
        self._groups.mark_member_verified(room, peer)
        if self._me() == self.coordinator(room):
            self._vouch(room, run)
        self._emit(GroupChanged(peer=room, change="verify_progress"))
        self._maybe_finish(room, run)

    def _fail(self, room: str, run: _Run, peer: str) -> None:
        with self._lock:
            smp = run.smp.pop(peer, None)
            run.result[peer] = "failed"
            run.failures[peer] = run.failures.get(peer, 0) + 1
            self._took(run, peer)
        if smp is not None:
            try:
                smp.destroy()
            except Exception:
                pass
        # Recorded against their key, on both sides: never tried again with
        # it (a member whose passphrase did not match the creator's cannot
        # trust the creator's key either).
        try:
            self._groups.mark_member_failed(room, peer)
        except Exception:
            pass
        self._emit(GroupChanged(peer=room, change="member_verify_failed", detail=peer))
        if self._me() == self.coordinator(room):
            self._vouch(room, run)
        self._emit(GroupChanged(peer=room, change="verify_progress"))
        self._maybe_finish(room, run)

    def _vouch(self, room: str, run: _Run) -> None:
        """The coordinator tells the group who is verified (with the group
        key each was verified on) and whose passphrase did not match. The
        whole list each time, so a member who joined late learns everyone."""
        verified, failed = [], []
        try:
            for m in self._groups.members(room):
                if m["me"]:
                    continue
                if m["verified"]:
                    verified.append([m["jid"], m["fingerprint"]])
                elif m.get("failed"):
                    failed.append([m["jid"], m["fingerprint"]])
        except Exception:
            return
        self._send(room, {"t": "vouch", "run": run.run_id, "ok": verified,
                          "failed": failed, "by": self._me()})

    def _on_vouch(self, room: str, sender: str, run: _Run, msg: Dict[str, Any]) -> None:
        """A member's side: accept the coordinator's word, key by key."""
        if sender != self.coordinator(room):
            return
        me = self._me()
        ok = msg.get("ok")
        if isinstance(ok, list):
            for item in ok[:4096]:
                if (isinstance(item, list) and len(item) == 2
                        and all(isinstance(x, str) for x in item)
                        and item[0] not in (me, sender)
                        and len(item[1]) <= 256):
                    if self._groups.mark_member_verified(room, item[0], expected_fp=item[1]):
                        with self._lock:
                            run.result[item[0]] = "verified"
        failed = msg.get("failed")
        if isinstance(failed, list):
            for item in failed[:4096]:
                # [jid, fingerprint]; a bare jid from an older build is
                # taken for this run only, bound to no key.
                if isinstance(item, list) and len(item) == 2 \
                        and all(isinstance(x, str) for x in item) and len(item[1]) <= 256:
                    jid, fp = item
                elif isinstance(item, str):
                    jid, fp = item, None
                else:
                    continue
                if jid in (me, sender):
                    continue
                with self._lock:
                    if run.result.get(jid) == "verified":
                        continue
                    run.result[jid] = "failed"
                if fp is not None:
                    try:
                        self._groups.mark_member_failed(room, jid, expected_fp=fp)
                    except Exception:
                        pass
        self._emit(GroupChanged(peer=room, change="verify_progress"))
        self._maybe_finish(room, run)

    def _took(self, run: _Run, peer: str) -> None:
        """Lock held."""
        began = run.began.pop(peer, None)
        if began is not None:
            run.took.append(max(0.0, self._clock() - began))

    def _maybe_finish(self, room: str, run: _Run) -> None:
        # Everyone who joined is settled: say who is in and who is out once.
        prog = self.progress(room)
        if (run.secret is not None and not prog["running"] and not run.finished_said
                and prog["done"] and not prog["waiting"]):
            run.finished_said = True
            self._emit(GroupChanged(peer=room, change="verify_finished",
                                    detail="verified=%s;excluded=%s" % (
                                        ",".join(prog["verified"]),
                                        ",".join(prog["excluded"]))))
        if self.all_verified(room):
            self._emit(GroupChanged(peer=room, change="group_verified"))
        if self.settled(room):
            # Nothing left to try: the run (and its passphrase) ends.
            with self._lock:
                if self._runs.get(room) is run:
                    self._runs.pop(room, None)
            self._end(run)

    # -- inside -------------------------------------------------------------

    def _live(self, room: str) -> Optional[_Run]:
        """The room's run, unless it expired (then it is ended). Lock held."""
        run = self._runs.get(room)
        if run is not None and self._clock() - run.started_at > self.RUN_SECONDS:
            self._runs.pop(room, None)
            self._end(run)
            return None
        return run

    def _end(self, run: _Run) -> None:
        if run.secret is not None:
            _zero(run.secret)
            run.secret = None
        for smp in list(run.smp.values()):
            try:
                smp.destroy()
            except Exception:
                pass
        run.smp.clear()

    def _send(self, room: str, msg: Dict[str, Any]) -> None:
        try:
            self._groups.send_control(room, VERIFY_PREFIX + json.dumps(
                msg, separators=(",", ":")))
        except Exception:
            pass

    def _me(self) -> str:
        return self._groups.account

    def _core_module(self):
        if self._core is None:
            import otrv4_core as core
            self._core = core
        return self._core


def _zero(b: bytearray) -> None:
    for i in range(len(b)):
        b[i] = 0
