# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A call's I2P path, built BEFORE the call.

Owner (2026-10-15): "the audio call icon ... a phone, red, which turns green
to indicate that the tunnels are ready for audio calls". The wait users feel
in a call over I2P is the SAM datagram session's tunnel build -- 30 to 120 s,
longer on a cold router -- and both 1:1 and group calls paid it after the
button was pressed. This module builds ONE such session ahead of time (the
"spare"), while a conversation that can call is open, and hands it to the
next call, 1:1 or group, which then skips the build.

  * One spare at a time, built on request (`warm`), never on its own.
  * Kept for KEEP_SECONDS (10 min) after the last `warm` -- each time a
    callable conversation is opened or looked at, the window restarts --
    then closed: a phone is not asked to hold tunnels nobody is going to use.
  * A spare is a TRANSIENT destination exactly like the one a call would
    build: fresh, announced to nobody until the call that takes it announces
    it (inside OTR or MLS), used for that one call, and never reused. Taking
    it starts the next one, so a second call in the window is quick too.
  * `state()` is what the phone icon shows: "cold" (red), "warming" (amber),
    "ready" (green).

Nothing here touches a key: it is a socket and a SAM control connection.
"""
from __future__ import annotations

import secrets
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

__all__ = ["WarmPath", "Spare", "WARM", "KEEP_SECONDS", "BUILD_TIMEOUT"]

#: How long a spare is kept after the last request for one.
KEEP_SECONDS = 600.0
#: How long one build may take before it counts as failed (a cold tunnel).
BUILD_TIMEOUT = 240.0
#: After a failed build, wait this long before the next request may retry.
RETRY_AFTER = 30.0


class Spare:
    """One pre-built SAM datagram session: the UDP socket the router
    forwards to, the control connection that keeps the session alive, its id
    and our public destination."""

    __slots__ = ("sock", "control", "session_id", "dest", "built_at", "endpoint")

    def __init__(self, sock, control, session_id: str, dest: str, endpoint=None):
        self.sock, self.control = sock, control
        self.session_id, self.dest = session_id, dest
        self.built_at = time.monotonic()
        self.endpoint = endpoint

    def close(self) -> None:
        for thing in (self.control, self.sock):
            try:
                thing.close()
            except Exception:
                pass


def _sam_build(sam_host: str, sam_port: int) -> Spare:
    """Build one session through the SAM helpers `otrv4plus_voice` binds,
    with the same tunnel options as every call (3 hops each way)."""
    import otrv4plus_voice as voice
    import otrv4plus_mediapath as mediapath
    host = voice._HOST
    sam_open, read_line, parse = host["sam_open"], host["sam_read_line"], host["sam_parse"]
    if not all((sam_open, read_line, parse)):
        raise RuntimeError("SAM helpers not bound")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        port = sock.getsockname()[1]
        ctrl = sam_open(sam_host, sam_port, voice.SAM_HELLO_TIMEOUT)
        try:
            sid = "otrv4warm_%s" % secrets.token_hex(6)
            ctrl.sendall(("SESSION CREATE STYLE=DATAGRAM ID=%s DESTINATION=TRANSIENT "
                          "SIGNATURE_TYPE=7 PORT=%d HOST=127.0.0.1 %s\n"
                          % (sid, port, mediapath.tunnel_options())).encode("ascii"))
            fields = parse(read_line(ctrl, BUILD_TIMEOUT), "SESSION STATUS ")
            blob = fields.get("DESTINATION")
            if not blob:
                raise RuntimeError("SESSION STATUS carried no DESTINATION")
            ctrl.settimeout(None)
            # Only the public half is kept; the private blob goes now.
            return Spare(sock, ctrl, sid, voice.i2p_public_destination(blob),
                         (sam_host, int(sam_port)))
        except BaseException:
            ctrl.close()
            raise
    except BaseException:
        sock.close()
        raise


class WarmPath:
    """The spare, its build and its expiry. Thread-safe."""

    def __init__(self, build: Callable[[str, int], Spare] = _sam_build,
                 clock: Callable[[], float] = time.monotonic,
                 keep: float = KEEP_SECONDS):
        self._build = build
        self._clock = clock
        self._keep = keep
        self._lock = threading.Lock()
        self._spare: Optional[Spare] = None
        self._building = False
        self._wanted_until = 0.0
        self._failed_at = 0.0
        self._endpoint: Optional[Tuple[str, int]] = None
        self.stats = {"built": 0, "taken": 0, "expired": 0, "failed": 0}

    # -- asked by the app ---------------------------------------------------

    def warm(self, sam_host: str, sam_port: int) -> str:
        """Want a spare for the next KEEP_SECONDS; build one if there is
        none. Returns the state after asking."""
        with self._lock:
            now = self._clock()
            self._endpoint = (sam_host, int(sam_port))
            self._wanted_until = now + self._keep
            start = (self._spare is None and not self._building
                     and now - self._failed_at >= RETRY_AFTER)
            if start:
                self._building = True
        if start:
            self._start_build()
        return self.state()

    def state(self) -> str:
        """"ready", "warming" or "cold" (and expires a stale spare)."""
        self._expire()
        with self._lock:
            if self._spare is not None:
                return "ready"
            return "warming" if self._building else "cold"

    def describe(self) -> Dict[str, Any]:
        """For the UI and diagnostics: the state, and seconds the spare is
        still kept for (0 when cold). No destination."""
        state = self.state()
        with self._lock:
            left = max(0.0, self._wanted_until - self._clock()) if state != "cold" else 0.0
        return {"state": state, "seconds_left": int(left)}

    # -- asked by a call ------------------------------------------------------

    def take(self, endpoint: Optional[Tuple[str, int]] = None) -> Optional[Spare]:
        """The spare, for the call about to start; None if there is none, or
        if it was built on a different SAM bridge than [endpoint].
        The call owns it from here. A new spare is started while the window
        is still open, so a second call is quick too."""
        self._expire()
        with self._lock:
            spare = self._spare
            if spare is None:
                return None
            if (endpoint is not None and spare.endpoint is not None
                    and (str(endpoint[0]), int(endpoint[1])) != spare.endpoint):
                return None
            self._spare = None
            self.stats["taken"] += 1
            again = (self._endpoint is not None and not self._building
                     and self._clock() < self._wanted_until)
            if again:
                self._building = True
        if again:
            self._start_build()
        return spare

    def close(self) -> None:
        """Drop the spare and stop wanting one (sign out, Wipe & Exit)."""
        with self._lock:
            spare, self._spare = self._spare, None
            self._wanted_until = 0.0
        if spare is not None:
            spare.close()

    # -- inside -------------------------------------------------------------------

    def _expire(self) -> None:
        with self._lock:
            if self._spare is None or self._clock() < self._wanted_until:
                return
            spare, self._spare = self._spare, None
            self.stats["expired"] += 1
        spare.close()

    def _start_build(self) -> None:
        threading.Thread(target=self._run_build, name="otrv4plus-warmpath",
                         daemon=True).start()

    def _run_build(self) -> None:
        endpoint = self._endpoint
        spare = None
        try:
            if endpoint is not None:
                spare = self._build(*endpoint)
        except Exception:
            spare = None
        with self._lock:
            self._building = False
            if spare is None:
                self.stats["failed"] += 1
                self._failed_at = self._clock()
                return
            if self._spare is not None or self._clock() >= self._wanted_until:
                extra = spare                    # not wanted any more
            else:
                self._spare, extra = spare, None
                self.stats["built"] += 1
        if extra is not None:
            extra.close()


#: The one spare for the whole process: 1:1 and group calls share it.
WARM = WarmPath()
