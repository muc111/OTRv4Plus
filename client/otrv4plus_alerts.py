# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Sounds and one-key answers for the terminal client.

Owner (2026-10-14): "simple prompts y/n for accepting for end users, less
typing in terminal the better" and "Notification sounds for incoming
messages, calls etc".

Two small pieces, both free of any peer content:

``Alerts``
    A new message rings the terminal bell and, on Termux, posts the same
    content-free notification the Android app shows: "New message", never
    who or what. Throttled, so a burst of messages is one sound. A group call
    starting rings once. ``OTRV4PLUS_QUIET=1`` (or ``/sound off``) silences
    all of it; 1:1 call ringing is the voice module's ``Ringer`` and is not
    affected, because a call nobody hears is a missed call.

``QuickAnswer``
    One open question that a bare ``y`` or ``n`` answers: "Accept the file?",
    "Answer the call?". Only an exact y/yes/n/no answers it -- anything else
    is typed as usual -- and the question lapses when what it asked about
    is gone (the call stopped ringing, the offer was cancelled) or after ten
    minutes. The newest question wins; the older one still has its
    /command, which the prompt line names.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Callable, Optional, Tuple

__all__ = ["Alerts", "QuickAnswer", "YES", "NO"]

YES = ("y", "yes")
NO = ("n", "no")


class QuickAnswer:
    """At most one y/n question, answered by the next exact y or n."""

    SECONDS = 600.0

    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 on_ask: Optional[Callable[[], None]] = None):
        self._clock = clock
        self._on_ask = on_ask
        self._open: Optional[Tuple[str, Callable[[], None], Callable[[], None],
                                   Callable[[], bool], float]] = None

    def ask(self, kind: str, on_yes: Callable[[], None],
            on_no: Callable[[], None],
            still_open: Callable[[], bool] = lambda: True) -> None:
        """Make `kind` the question a bare y/n answers."""
        self._open = (kind, on_yes, on_no, still_open, self._clock())
        if self._on_ask is not None:
            self._on_ask()

    def pending(self) -> Optional[str]:
        """The kind of question a y/n would answer now, if any."""
        if self._open is None:
            return None
        kind, _yes, _no, still_open, at = self._open
        try:
            alive = still_open()
        except Exception:
            alive = False
        if not alive or self._clock() - at > self.SECONDS:
            self._open = None
            return None
        return kind

    def answer(self, line: str) -> bool:
        """True if `line` was a y/n that answered the open question."""
        word = (line or "").strip().lower()
        if word not in YES + NO or self.pending() is None:
            return False
        _kind, on_yes, on_no, _still, _at = self._open
        self._open = None
        (on_yes if word in YES else on_no)()
        return True

    def clear(self, kind: Optional[str] = None) -> None:
        if self._open is not None and (kind is None or self._open[0] == kind):
            self._open = None


class Alerts:
    """Content-free sounds: the bell, and on Termux a notification."""

    #: One message sound per this many seconds, however many arrive.
    MESSAGE_GAP = 3.0
    NOTIFICATION_ID = "otrv4plus-message"

    def __init__(self, *, out=None, clock: Callable[[], float] = time.monotonic,
                 run: Optional[Callable[[list], None]] = None,
                 which: Callable[[str], Optional[str]] = shutil.which,
                 enabled: Optional[bool] = None):
        self._out = out
        self._clock = clock
        self._run = run or self._spawn
        self._which = which
        self.enabled = (os.environ.get("OTRV4PLUS_QUIET", "") not in ("1", "true", "yes")
                        if enabled is None else enabled)
        self._last_message = -1e9
        self._unseen = 0

    # -- what the client calls ---------------------------------------------

    def message(self) -> None:
        """A new message arrived. Never says from whom or what."""
        if not self.enabled:
            return
        self._unseen += 1
        now = self._clock()
        if now - self._last_message < self.MESSAGE_GAP:
            return
        self._last_message = now
        self._bell()
        self._notify("New message" if self._unseen == 1
                     else "%d new messages" % self._unseen)

    def ring_once(self) -> None:
        """A group call started: one ring, one notification."""
        if not self.enabled:
            return
        self._bell()
        self._bell()
        self._notify("Incoming call", ident="otrv4plus-group-call")

    def seen(self) -> None:
        """The user typed something: they are looking. Reset the count."""
        if self._unseen == 0:
            return
        self._unseen = 0
        if self._which("termux-notification-remove"):
            self._run(["termux-notification-remove", self.NOTIFICATION_ID])

    # -- how --------------------------------------------------------------

    def _bell(self) -> None:
        out = self._out or sys.stdout
        try:
            if out.isatty():
                out.write("\a")
                out.flush()
        except Exception:
            pass

    def _notify(self, content: str, ident: Optional[str] = None) -> None:
        # Fixed strings only: nothing a peer sent reaches this argv.
        if not self._which("termux-notification"):
            return
        self._run(["termux-notification", "--id", ident or self.NOTIFICATION_ID,
                   "--title", "Off The Record v4 Plus", "--content", content,
                   "--priority", "high", "--sound"])

    @staticmethod
    def _spawn(argv: list) -> None:
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, close_fds=True)
        except Exception:
            pass
