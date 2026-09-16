# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A bounded record of what the connection did, safe to hand to a stranger.

WHY
---
The handset bugs that cost the most were not crashes. They were a connection
that said DISCONNECTING for no stated reason, contacts that read "presence
unknown", and an Add Contact button that appeared inert. Every one of them had
an exact cause a few layers down, and none of it reached the screen -- so
diagnosing them meant ADB, logcat and a developer.

This is the alternative: an in-memory ring of what each component did, which
the user exports from Diagnostics and sends back. The sequence immediately
before an unexpected transition is usually the whole answer.

NOT THE EVENT QUEUE
-------------------
`eventlog.EventQueue` carries `MessageReceived.body` -- decrypted plaintext,
on its way to the screen. It is the one structure in the bridge that
legitimately holds message content, and its docstring says it must never reach
diagnostics. This is a SECOND, separate ring, and the separation is the
safety property: there is no path from a message body into this object.

WHAT MAY BE RECORDED, AND WHAT MAY NOT
--------------------------------------
The rule is structural rather than a matter of care at each call site.

  * **Field values are redacted by KEY NAME.** Anything whose name looks like
    a secret -- password, key, secret, token, seed, credential -- is replaced
    with `[REDACTED]`, not dropped: a field that vanished tells the reader
    nothing, and one that says REDACTED tells them the code was asked and
    refused.
  * **Content-shaped keys are banned outright.** `body`, `message`, `text`,
    `plaintext` and friends are redacted whatever they hold, because chat
    content does not belong in a diagnostic even when the user consents to
    share one -- the peer did not consent.
  * **Exception messages are chosen by TYPE, never printed blindly.** This
    defers to `failure.describe`, which is the project's existing rule: our
    own messages are written in this repository and are safe; a third party's
    may quote a path, a URL with a token in it, or an argument. The type and
    the frame list carry the diagnosis without the values.

  * **Identities become labels.** JIDs, contact names, server addresses, I2P
    destinations and IP literals are replaced with `user-A`, `address-B` and
    so on -- centrally, in [_safe], by key name where the key says what the
    value is and by SHAPE everywhere else.

THAT LAST RULE REVERSES AN EARLIER DECISION, deliberately. The first version
of this module recorded JIDs and server names and argued for it: a roster,
presence or routing fault is *about* those values. It is, and the labels
preserve that -- "we asked for `user-A`'s presence, `user-A` never answered"
is the same diagnosis. What the old version also did was collect the user's
account, everybody they talk to and the destination they talk through into one
file, and then invite them to post it into a bug tracker. On this project that
is the wrong side of the trade however useful it is. `otrv4plus_alias` holds
the mechanism and the reasoning.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from otrv4plus_alias import ALIASES as _ALIASES

from .diagnostics import SENSITIVE_KEY_HINTS

__all__ = ["TraceLog", "TRACE", "DEFAULT_CAPACITY", "BANNED_KEYS",
           "REDACTED", "MAX_VALUE", "LONG_KEYS"]

#: How many events to keep. Several thousand, as asked: at the rates these
#: components actually produce, this is hours of a session and comfortably
#: spans a connect, a conversation and whatever went wrong afterwards.
DEFAULT_CAPACITY = 4000

#: What a refused value looks like. A marker rather than an omission, so a
#: reader can tell "we did not record this" from "this did not happen".
REDACTED = "[REDACTED]"

#: Hard ceiling on any single rendered value. A field that grew unexpectedly
#: must not turn the export into something unopenable on a phone.
MAX_VALUE = 200

#: Keys allowed to be longer, and how long.
#:
#: A stack trace truncated at 200 characters loses the innermost frames, which
#: are the ones worth having. These two are produced by `failure.describe`,
#: which already caps its own output and emits no values -- so a longer
#: allowance costs nothing in safety.
LONG_KEYS = {"stack_trace": 1200, "exception_detail": 500}

#: Keys that are redacted whatever they contain, because their CONTENT is the
#: problem rather than their name.
#:
#: Chat content is the case that matters. A diagnostic is shared -- that is
#: its purpose -- and the person who wrote the message did not agree to that.
#: `SENSITIVE_KEY_HINTS` covers credentials and key material; this covers the
#: other half.
BANNED_KEYS = frozenset({
    "body", "message", "text", "plaintext", "content", "payload",
    "msg", "line", "stanza",
})


def _is_sensitive(name: str) -> bool:
    lowered = str(name).lower()
    if lowered in BANNED_KEYS:
        return True
    return any(hint in lowered for hint in SENSITIVE_KEY_HINTS)


def _safe(name: str, value: Any) -> str:
    """One field, rendered so it cannot carry a secret, a body or an identity.

    Three passes, in this order, and each one is load-bearing:

      1. a key that names a secret becomes `[REDACTED]` outright;
      2. the value is rendered to a single line;
      3. identities become labels -- `user-A`, `address-B` -- by key name
         where the key says what the value is, and by SHAPE everywhere else.

    Three runs before the length cap, not after. Truncating first could cut a
    JID in half and leave the localpart -- the part that names a person --
    standing at the end of a line that looks redacted.
    """
    if _is_sensitive(name):
        return REDACTED
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    try:
        text = str(value)
    except Exception:
        return "<unprintable %s>" % type(value).__name__
    text = text.replace("\n", " ").replace("\r", " ").strip()
    # CENTRAL, rather than asked of each call site. The call sites are the
    # inbound handler, the keepalive, the roster and the Kotlin bridge, and
    # the first one to forget is the one whose fault ends up in a file the
    # user posts into a bug tracker.
    try:
        text = _ALIASES.field(name, text)
    except Exception:                                        # pragma: no cover
        # A diagnostic must not be able to break the thing it is diagnosing.
        # Failing closed rather than open: an unaliased value is the exact
        # thing this pass exists to prevent.
        return REDACTED
    cap = LONG_KEYS.get(str(name).lower(), MAX_VALUE)
    if len(text) > cap:
        text = text[:cap] + "...(%d more)" % (len(text) - cap)
    return text


class TraceLog:
    """A thread-safe ring of structured events.

    Every component writes to one of these; the exporter renders it. Written
    from the transport's asyncio loop thread, from Kotlin threads through the
    bridge, and read from whichever thread pressed Export -- so the lock is
    not optional.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self._capacity = max(1, int(capacity))
        self._events: deque = deque(maxlen=self._capacity)
        self._dropped = 0
        self._lock = threading.Lock()
        self._started = time.time()

    # -- writing -------------------------------------------------------------

    def record(self, component: str, event: str, severity: str = "info",
               **fields: Any) -> None:
        """Record one thing that happened.

        Never raises. A diagnostic that can break the thing it is diagnosing
        is worse than no diagnostic, and this is called from the connect path,
        the keepalive and the inbound handler.
        """
        self.record_at(None, component, event, severity, **fields)

    def record_at(self, at: Optional[float], component: str, event: str,
                  severity: str = "info", **fields: Any) -> None:
        """[record], but with the time supplied by the caller.

        For events that happen on one thread and are WRITTEN on another.
        Kotlin's lifecycle callbacks run on the main thread, where a blocking
        Chaquopy call would be an ANR, so they hand the note to a worker --
        and a timeline is worthless if half its entries are stamped with the
        moment they were flushed rather than the moment they happened.
        """
        try:
            entry = {
                "at": time.time() if at is None else float(at),
                "component": str(component),
                "event": str(event),
                "severity": str(severity),
                "fields": {str(k): _safe(k, v) for k, v in fields.items()},
            }
        except Exception:
            return
        with self._lock:
            if len(self._events) == self._capacity:
                self._dropped += 1
            self._events.append(entry)

    def transition(self, component: str, before: Any, after: Any,
                   severity: str = "info", **fields: Any) -> None:
        """A state change, which is what most of these reports are about.

        Recorded as its own event type so `state_before` and `state_after` are
        always present together. "It became DISCONNECTING" is not a diagnosis;
        "it became DISCONNECTING from CONNECTED, in the keepalive, because two
        round trips went unanswered" is.
        """
        self.record(component, "state_change", severity,
                    state_before=before, state_after=after, **fields)

    def record_exception(self, component: str, event: str,
                         exc: BaseException, **fields: Any) -> None:
        """An exception, described by TYPE rather than printed.

        Defers to `failure.describe`, which selects the detail by exception
        type: our own messages are written in this repository and are safe,
        while a third party's may quote a path or an argument. The frame list
        is `basename:lineno in function` and carries no values.
        """
        described: Dict[str, Any] = {}
        try:
            from .failure import describe
            described = describe(exc) or {}
        except Exception:
            described = {}
        frames = described.get("frames") or []
        if isinstance(frames, (list, tuple)):
            frames = " <- ".join(str(f) for f in reversed(list(frames)))
        self.record(
            component, event, "error",
            exception_type=described.get("code") or type(exc).__name__,
            exception_detail=described.get("detail") or "",
            # Innermost FIRST, which is where a reader looks. `describe`
            # returns them outermost-first for a stack listing; a one-line
            # field reads better the other way round.
            stack_trace=frames,
            caused_by=described.get("caused_by") or "",
            **fields)

    # -- reading -------------------------------------------------------------

    def events(self, limit: int = 0) -> List[Dict[str, Any]]:
        """A copy of the ring, oldest first. `limit` keeps the NEWEST n."""
        with self._lock:
            out = list(self._events)
        if limit and limit > 0:
            out = out[-limit:]
        return out

    def dropped(self) -> int:
        """How many events fell off the front. A gap is worth saying."""
        with self._lock:
            return self._dropped

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._dropped = 0

    # -- rendering -----------------------------------------------------------

    def render(self, limit: int = 0) -> str:
        """The event table, as text. One line per event.

        Fixed columns rather than JSON: this is read by a person in whatever
        app they shared it to, often on the phone that produced it.
        """
        events = self.events(limit)
        lines = []
        dropped = self.dropped()
        if dropped:
            lines.append("... %d earlier event(s) dropped (ring is %d long)"
                         % (dropped, self._capacity))
        for entry in events:
            stamp = time.strftime("%H:%M:%S",
                                  time.localtime(entry.get("at", 0)))
            millis = int((entry.get("at", 0) % 1) * 1000)
            fields = entry.get("fields") or {}
            rendered = " ".join("%s=%s" % (k, fields[k])
                                for k in sorted(fields))
            lines.append("%s.%03d  %-9s %-22s %-24s %s" % (
                stamp, millis,
                entry.get("severity", "info")[:9],
                str(entry.get("component", "?"))[:22],
                str(entry.get("event", "?"))[:24],
                rendered))
        if not lines:
            return "(no events recorded)"
        return "\n".join(lines)


#: The one log every component writes to.
#:
#: A module singleton rather than something threaded through every
#: constructor: the alternative is a parameter on the transport, the
#: controller, the app and the bridge, and the first component that forgets to
#: pass it on is the one whose fault goes unrecorded.
TRACE = TraceLog()
