# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group voice calls in the app: `GroupCalls` (keys, who is in) plus the
media side the terminal client uses (`otrv4plus_groupcall.GroupCallMedia`:
one I2P datagram session, AAudio, the core's Opus), bound the same way the
app's 1:1 calls bind it (`voice.CallBridge`: SAM helpers, Android codec,
AAudio only).

Owner design (2026-10-10): once a group is verified, pressing Call rings it
and every verified member's app joins by itself; each can pause (stop
sending, keep hearing) or hang up. Joining by itself opens the microphone,
so it happens only when the user has granted the microphone to the app
(`auto_join` is set by the app from the permission); otherwise the ring is
shown with a Join button that asks for it first.

`GroupCalls` is built when the groups open (not on first use), so a ring that
arrives before anyone pressed anything is not lost.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

from .events import ErrorOccurred, GroupChanged
from .trace import TRACE as _TRACE

__all__ = ["GroupCallBridge"]

_log = logging.getLogger(__name__)

#: How long building the I2P datagram session may take (a cold tunnel).
OPEN_TIMEOUT = 240.0

# -- the receive watchdog ------------------------------------------------------
#
# Device report (2026-10-15, rc.73): a two-phone group call carried audio one
# way only. The phone that joined sent 1088 frames; it received 3, in the
# first ten seconds, and none after -- none refused (rx_bad=0), so nothing was
# arriving at all, for the rest of the call. Its sending leg worked; its
# receiving leg died and nothing noticed. 1:1 calls have had a watchdog and
# endpoint recovery for this since September (otrv4plus_voice, VOICE_RX_*);
# group calls had neither.
#
# Every participant sends continuously (constant-rate Opus) unless paused, and
# a pause is now announced, so a member we have not heard from is evidence of
# a dead path. Our side of that path is our destination: its inbound tunnels,
# or the route the peer's router cached to them. A NEW destination replaces
# both; it is announced inside MLS ("here") and the peer sends to it. Bounded,
# like 1:1 (VOICE_RECOVER_ATTEMPTS), because a tunnel build costs 30-120 s and
# an unbounded retry is a build storm.
#
#: A newly seen participant gets this long for their first frame (their
#: router still has to find our destination; 1:1 allows 120 s, but a group
#: call's destination is published before anyone sends to it).
RX_START_GRACE = 60.0
#: Silence from an unpaused participant we HAVE heard: the path died.
RX_SILENT = 20.0
#: Rebuilds per call, and the least time between them.
MAX_REOPENS = 2
REOPEN_GAP = 60.0
#: A session opened when a ring arrives is closed again if nobody joins.
PREWARM_HOLD = 90.0


class GroupCallBridge:
    """Group calls for one `OtrApp`."""

    def __init__(self, app: Any, *, sam: Callable[[], Tuple[str, int]],
                 emit: Callable[[Any], None]):
        self._app = app
        self._sam = sam
        self._emit_out = emit
        self._lock = threading.RLock()
        self._media = None
        self._tick = None
        self._loop = None
        self._traced_at = 0.0
        self._open_lock = threading.Lock()
        #: Watchdog state for the current call (see RX_* above).
        self._seen: Dict[str, float] = {}
        self._reopens = 0
        self._reopened_at = 0.0
        self._reopening = False
        #: Set by the app from the microphone permission.
        self.auto_join = False
        from .group_call import GroupCalls
        self.calls = GroupCalls(
            app.groups,
            send_datagram=lambda dest, packet: (
                self._media.send_datagram(dest, packet) if self._media else None),
            local_destination=lambda: self._media.destination if self._media else "",
            on_audio=lambda room, who, frame: (
                self._media.on_audio(room, who, frame) if self._media else None),
            emit=self._emit, clock=time.time)

    # -- what the user does ---------------------------------------------------

    def start(self, room: str) -> str:
        """Ring the group and join. Returns "ok" or a reason code."""
        return self._go(room, start=True)

    def join(self, room: str) -> str:
        return self._go(room, start=False)

    def pause(self) -> bool:
        return self.calls.pause()

    def hangup(self) -> None:
        room = self.calls.active()
        if room is not None:
            self.calls.hangup(room)
        with self._lock:
            media, self._media = self._media, None
            tick, self._tick = self._tick, None
            self._reset_watch()
        if tick is not None:
            try:
                tick.cancel()
            except Exception:
                pass
        if media is not None:
            self._trace_media(media, "call_ended", force=True)
            try:
                media.close()
            except Exception:
                pass

    def _trace_media(self, media, event: str = "media", force: bool = False) -> None:
        """Every 10 s while in a call, and at its end: which leg is silent.
        Counters and device names only -- no destination, no identity."""
        now = time.monotonic()
        if not force and now - self._traced_at < 10.0:
            return
        self._traced_at = now
        try:
            info = media.describe()
            room = self.calls.active()
            info["peers"] = len(self.calls.participants(room)) if room else 0
            info["paused"] = bool(self.calls.paused)
            _TRACE.record("group_call", event, "info", **info)
        except Exception:
            pass

    def status(self, room: str) -> Dict[str, Any]:
        active = self.calls.active()
        ringing = [r for r in self.calls.ringing() if r["room"] == room]
        return {
            "in_call": active == room,
            "paused": bool(self.calls.paused) if active == room else False,
            "participants": self.calls.participants(room),
            "ringing_from": ringing[0]["from"] if ringing else "",
        }

    def shutdown(self) -> None:
        self.hangup()

    # -- inside -------------------------------------------------------------

    def _emit(self, ev: Any) -> None:
        self._emit_out(ev)
        if (isinstance(ev, GroupChanged) and ev.change == "call_ringing"
                and self.calls.active() is None
                and self._verified(ev.peer, ev.detail or "")):
            if self.auto_join:
                # Joined in the background: the open can take a minute on I2P.
                threading.Thread(target=self.join, args=(ev.peer,),
                                 name="group-call-join", daemon=True).start()
            else:
                # Not joining by ourselves: build the I2P session NOW anyway,
                # while the user decides, so Join does not then wait a minute
                # for tunnels ("it took a long time for calls to establish").
                # A transient destination, announced to nobody until we join;
                # closed again if nobody does.
                threading.Thread(target=self._prewarm, name="group-call-prewarm",
                                 daemon=True).start()

    def _prewarm(self) -> None:
        try:
            self._ensure_media()
        except Exception:
            return
        _TRACE.record("group_call", "prewarmed", "info")
        timer = threading.Timer(PREWARM_HOLD, self._drop_prewarm)
        timer.daemon = True
        timer.start()

    def _drop_prewarm(self) -> None:
        if self.calls.active() is not None:
            return
        with self._lock:
            media, self._media = self._media, None
        if media is not None:
            try:
                media.close()
            except Exception:
                pass

    # -- the receive watchdog -------------------------------------------------

    def _reset_watch(self) -> None:
        self._seen = {}
        self._reopens = 0
        self._reopened_at = 0.0
        self._reopening = False

    def silent_participants(self, room: str, media: Any, now: float) -> list:
        """Unpaused participants whose audio is not arriving (RX_* above)."""
        peers = self.calls.participants(room)
        for who in peers:
            self._seen.setdefault(who, now)
        for who in [w for w in self._seen if w not in peers]:
            del self._seen[who]
        paused = set(self.calls.paused_peers(room))
        silent = []
        for who in peers:
            if who in paused:
                continue
            heard = media.last_heard(who)
            since = max(heard, self._seen[who])
            limit = RX_SILENT if heard else RX_START_GRACE
            if now - since > limit:
                silent.append(who)
        return silent

    def _watch(self, media: Any) -> None:
        room = self.calls.active()
        if room is None or self._reopening:
            return
        now = time.monotonic()
        silent = self.silent_participants(room, media, now)
        if not silent or self._reopens >= MAX_REOPENS:
            return
        if self._reopened_at and now - self._reopened_at < REOPEN_GAP:
            return
        self._reopening = True
        self._reopens += 1
        self._reopened_at = now
        _TRACE.record("group_call", "receive_stalled", "warning",
                      silent=len(silent), attempt=self._reopens)
        loop = self._loop

        async def rebuild():
            try:
                await media.reopen()
            except Exception as exc:
                _TRACE.record("group_call", "reopen_failed", "warning",
                              error=type(exc).__name__)
            else:
                if self._media is media and self.calls.active() == room:
                    try:
                        self.calls.announce(room)
                    except Exception:
                        pass
                    # Everyone gets the start grace again on the new path.
                    t = time.monotonic()
                    for who in list(self._seen):
                        self._seen[who] = t
                    _TRACE.record("group_call", "reopened", "info",
                                  attempt=self._reopens)
            finally:
                self._reopening = False

        if loop is not None:
            asyncio.run_coroutine_threadsafe(rebuild(), loop)
        else:
            self._reopening = False

    def _verified(self, room: str, who: str) -> bool:
        try:
            return any(m["jid"] == who and m["verified"]
                       for m in self._app.groups.members(room))
        except Exception:
            return False

    def _go(self, room: str, *, start: bool) -> str:
        # Before any tunnel is built: a group over the limit is text only.
        if self.calls.too_large(room):
            self._emit_out(ErrorOccurred(peer=room, code="group_too_large"))
            return "group_too_large"
        try:
            self._ensure_media()
        except Exception as exc:
            _log.warning("group call media unavailable")
            self._emit_out(ErrorOccurred(peer=room, code="call_audio_unavailable",
                                         detail=type(exc).__name__))
            return "call_audio_unavailable"
        try:
            if start:
                self.calls.start(room)
            else:
                self.calls.join(room)
        except ValueError as exc:
            return str(exc)
        try:
            self._media.start_audio(self.calls)
        except Exception as exc:
            _TRACE.record("group_call", "audio_failed", "warning",
                          error=type(exc).__name__)
            self._emit_out(ErrorOccurred(peer=room, code="call_audio_unavailable",
                                         detail=type(exc).__name__))
        else:
            self._trace_media(self._media, "joined" if not start else "started",
                              force=True)
        self._schedule_tick()
        return "ok"

    def _ensure_media(self) -> None:
        # One builder at a time: a ring's prewarm and a Join pressed during
        # it must end with one session, not two.
        with self._open_lock:
            self._ensure_media_locked()

    def _ensure_media_locked(self) -> None:
        with self._lock:
            if self._media is not None:
                return
        # The app's 1:1 call machinery binds the SAM helpers, the Android
        # codec and AAudio into otrv4plus_voice, and owns a loop thread.
        bridge = self._app.calls
        if bridge._ensure_manager() is None:
            raise RuntimeError("voice unavailable")
        with bridge._lock:
            loop = bridge._ensure_loop()
        import otrv4plus_groupcall
        host, port = self._sam()
        media = otrv4plus_groupcall.GroupCallMedia(
            loop=loop, sam_host=host, sam_port=port,
            printer=lambda *a, **k: None)
        future = asyncio.run_coroutine_threadsafe(media.open(), loop)
        future.result(timeout=OPEN_TIMEOUT)
        with self._lock:
            self._media, self._loop = media, loop

    def _schedule_tick(self) -> None:
        loop = self._loop
        if loop is None:
            return

        def tick():
            with self._lock:
                self._tick = None
            try:
                self.calls.tick()
            except Exception:
                pass
            media = self._media
            if media is not None:
                self._trace_media(media)
                try:
                    self._watch(media)
                except Exception:
                    pass
            if self.calls.active() is not None:
                with self._lock:
                    self._tick = loop.call_later(1.0, tick)

        with self._lock:
            if self._tick is None:
                self._tick = loop.call_soon_threadsafe(tick)
