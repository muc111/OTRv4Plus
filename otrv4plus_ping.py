# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One XEP-0199 round trip, against whichever slixmpp is installed.

WHY THIS MODULE EXISTS
----------------------
Both clients called `self["xep_0199"].async_ping(...)`. **slixmpp 1.17 has no
`async_ping`.** The plugin exposes `ping` (a coroutine) and `send_ping`; the
name `async_ping` belonged to an older release and was removed.

So the call raised `AttributeError`, and both callers classified any exception
that was not `IqError` as "the server did not answer". Every probe therefore
reported a dead stream, forever, on a connection that was perfectly healthy.

On the terminal client this was masked: it skips the probe entirely while the
stream is delivering traffic, so an active conversation never pings at all. On
Android there was no such gate, so the probe ran every 60 s, failed every time,
and after two failures the keepalive tore down a working session -- roughly two
minutes after connecting, whatever the user was doing.

That one defect produced three separate handset symptoms, because everything
downstream keys off `is_connected`:

  * an unexplained drop into DISCONNECTING a couple of minutes in;
  * every contact rendering "presence unknown", because the UI will not claim
    to know anyone's presence while the link is down;
  * Add Contact appearing to do nothing, because the roster call is refused
    with `not_connected`.

FAILING SAFE
------------
The rule here is that **a missing or unusable ping API must never look like a
dead stream.** A client that cannot ask the question has learned nothing, and
manufacturing a disconnect out of its own ignorance is exactly the bug above.
So [PingUnsupported] is raised as a distinct signal, and both callers treat it
as "alive" rather than folding it in with a timeout.

No slixmpp import: this is a leaf module so it can be tested by running it
against fakes, which is how the missing method would have been caught.
"""

import asyncio
import inspect

__all__ = ["PING_METHODS", "PingUnsupported", "ping_method", "round_trip"]

#: Candidate method names, in the order they are tried.
#:
#: `async_ping` first for the older releases that have it, then `ping`, which
#: is the coroutine slixmpp 1.17 provides. `send_ping` is deliberately absent:
#: it returns a Future for a stanza rather than performing the round trip, so
#: awaiting it would answer a different question.
PING_METHODS = ("async_ping", "ping")

#: Exception type NAMES that prove the server answered.
#:
#: By name rather than by class so this module needs no slixmpp import. An
#: `IqError` means the server replied -- with `service-unavailable`, say --
#: and a reply is the entire question being asked. Treating it as death would
#: reconnect against a working session.
ANSWERED = frozenset({"IqError"})


class PingUnsupported(RuntimeError):
    """This slixmpp exposes no usable XEP-0199 round trip.

    Distinct from a failed ping on purpose. The caller must treat it as
    "no information", never as "the stream is dead".
    """


def ping_method(plugin):
    """The round-trip callable this plugin actually has, and its name.

    Returns `(name, callable)`, or `(None, None)` when there is none. Exposed
    separately so a diagnostic can report which API was found without
    performing a round trip.
    """
    for name in PING_METHODS:
        fn = getattr(plugin, name, None)
        if callable(fn):
            return name, fn
    return None, None


async def round_trip(plugin, jid, timeout):
    """Ping *jid*. True if the server answered AT ALL.

    False means nothing came back within *timeout* -- the only evidence of a
    dead stream this can produce.

    Raises [PingUnsupported] when there is no usable ping method, or when the
    one found will not accept this call. Both are "we could not ask", and the
    caller must not read them as a failed round trip.

    `asyncio.CancelledError` propagates. A cancelled probe is a shutdown, not
    a verdict about the server.
    """
    name, fn = ping_method(plugin)
    if fn is None:
        raise PingUnsupported(
            "no XEP-0199 round trip on %s; tried %s"
            % (type(plugin).__name__, ", ".join(PING_METHODS)))

    try:
        result = fn(jid, timeout=timeout)
    except TypeError as exc:
        # The method exists but not with this signature. Same class of problem
        # as it not existing at all, and the same fail-safe answer.
        raise PingUnsupported("%s has an unexpected signature: %s"
                              % (name, exc))
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if type(exc).__name__ in ANSWERED:
            return True
        return False

    if not inspect.isawaitable(result):
        # An old blocking `ping` returned the round-trip time. It has already
        # answered, so this IS an answer -- but there is nothing to await, and
        # a non-awaitable from a method we expected to be a coroutine is worth
        # reporting rather than silently accepting.
        raise PingUnsupported("%s returned %s, which is not awaitable"
                              % (name, type(result).__name__))

    try:
        await result
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if type(exc).__name__ in ANSWERED:
            return True
        return False
    return True
