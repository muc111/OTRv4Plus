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

__all__ = ["GroupCallBridge"]

_log = logging.getLogger(__name__)

#: How long building the I2P datagram session may take (a cold tunnel).
OPEN_TIMEOUT = 240.0


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
        if tick is not None:
            try:
                tick.cancel()
            except Exception:
                pass
        if media is not None:
            try:
                media.close()
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
                and self.auto_join and self.calls.active() is None
                and self._verified(ev.peer, ev.detail or "")):
            # Joined in the background: the open can take a minute on I2P.
            threading.Thread(target=self.join, args=(ev.peer,),
                             name="group-call-join", daemon=True).start()

    def _verified(self, room: str, who: str) -> bool:
        try:
            return any(m["jid"] == who and m["verified"]
                       for m in self._app.groups.members(room))
        except Exception:
            return False

    def _go(self, room: str, *, start: bool) -> str:
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
            self._emit_out(ErrorOccurred(peer=room, code="call_audio_unavailable",
                                         detail=type(exc).__name__))
        self._schedule_tick()
        return "ok"

    def _ensure_media(self) -> None:
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
            if self.calls.active() is not None:
                with self._lock:
                    self._tick = loop.call_later(1.0, tick)

        with self._lock:
            if self._tick is None:
                self._tick = loop.call_soon_threadsafe(tick)
