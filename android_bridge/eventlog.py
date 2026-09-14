"""Getting engine events across to Kotlin, without a callback into Kotlin.

`OtrApp` emits typed events to an `EventSink`. Kotlin needs them: a message
arrives, a DAKE completes, SMP advances. The obvious implementation is to hand
Python a Kotlin object and let it call `on_event` -- Chaquopy proxies Java
objects and it would work.

It is not what this does, for one reason. Those events fire on the transport's
asyncio loop thread. A Kotlin callback invoked from there is on a thread
Compose must not be updated from, so every handler would have to marshal to the
main looper, and a handler that forgot would produce a crash that appears only
under load and only sometimes. Pushing a thread-safety obligation across a
language boundary, into code a future screen will write, is a bad trade for the
latency it saves in a chat app.

So Python queues and Kotlin drains. The UI pulls on its own thread, on its own
schedule, and there is no way to get the thread wrong.

What is in here
---------------
`MessageReceived.body` is **plaintext** -- the decrypted message the user is
about to read. That is the whole point of it, and it means this queue is the
one structure in the bridge that legitimately holds plaintext. It must never be
logged, never reach `diagnostics`, and never be written to disk by anything
here. `drain()` hands it to the UI and forgets it.

Bounded on purpose. A UI that stops draining -- backgrounded, wedged, a screen
that forgot to poll -- must cost a fixed amount of memory rather than growing
until the process is killed. When the bound is hit the OLDEST events go, and a
counter records how many, because silently losing events and silently keeping
the wrong ones are different kinds of wrong and the UI is entitled to know a
gap happened.
"""

from __future__ import annotations

import dataclasses
import enum
import threading
from collections import deque
from typing import Any, Dict, List

__all__ = ["EventQueue", "DEFAULT_CAPACITY"]

#: Enough for a long conversation's worth of backlog while a screen is away,
#: small enough that a wedged UI cannot grow the process without bound.
DEFAULT_CAPACITY = 512


class EventQueue:
    """Collects `OtrApp` events until something asks for them.

    Satisfies the `EventSink` protocol (`on_event`), so it is installed the
    same way any other sink would be.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        self._events: deque = deque(maxlen=max(1, capacity))
        self._lock = threading.Lock()
        self._dropped = 0
        self._seq = 0

    # -- the sink side, called on the transport's loop thread ----------------

    def on_event(self, event: Any) -> None:
        """Record an event. Never raises.

        Never raises because `OtrApp._emit` treats a sink that throws as a UI
        bug it must not die of, and a sink that relies on that forbearance
        rather than simply not failing is borrowing someone else's safety net.
        """
        try:
            item = self._describe(event)
        except Exception:
            return
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self._dropped += 1
            self._seq += 1
            item["seq"] = self._seq
            self._events.append(item)

    # -- the drain side, called from Kotlin ----------------------------------

    def drain(self, limit: int = 0) -> List[Dict[str, Any]]:
        """Take up to *limit* events (0 = all), oldest first.

        Removes what it returns: an event delivered twice would put a message
        on screen twice, and the UI has no way to tell a duplicate from a peer
        who really did send the same text again.
        """
        with self._lock:
            if limit and limit > 0:
                out = [self._events.popleft()
                       for _ in range(min(limit, len(self._events)))]
            else:
                out, self._events = list(self._events), deque(
                    maxlen=self._events.maxlen)
            return out

    def pending(self) -> int:
        with self._lock:
            return len(self._events)

    def dropped(self) -> int:
        """How many events were lost to the bound, ever.

        Reported rather than hidden. A gap in a conversation is worth a line on
        screen; a gap nobody mentions is a bug report about missing messages.
        """
        with self._lock:
            return self._dropped

    # -- conversion ----------------------------------------------------------

    @staticmethod
    def _describe(event: Any) -> Dict[str, Any]:
        """One event as a flat dict of primitives.

        Flat and primitive because this crosses into Kotlin: a nested object
        graph would be a PyObject tree to walk on the other side, and every
        walk is a place to get a null wrong. Enums become their names, which is
        what the Kotlin `fromName` helpers already expect.
        """
        item: Dict[str, Any] = {"type": type(event).__name__}
        fields = (dataclasses.fields(event)
                  if dataclasses.is_dataclass(event) else ())
        for field in fields:
            value = getattr(event, field.name, None)
            if isinstance(value, enum.Enum):
                # `.name` for the Kotlin enums, `.value` where the engine's
                # numeric level is what Kotlin maps from.
                item[field.name] = value.name
                if isinstance(getattr(value, "value", None), int):
                    item[field.name + "_level"] = value.value
            elif isinstance(value, (str, int, float, bool)) or value is None:
                item[field.name] = value
            else:
                item[field.name] = str(value)
        return item
