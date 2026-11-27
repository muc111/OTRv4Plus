# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Starting a coroutine in the background, and keeping it alive.

`asyncio.ensure_future(coro)` and `loop.create_task(coro)` return a task
the event loop holds only weakly. Nothing else in this code kept the
result, so a task waiting on something that no one else referenced could
be garbage-collected half way and simply never finish (the asyncio
documentation warns about exactly this). A task that failed was reported,
if at all, as "Task exception was never retrieved" at some later
collection, with no hint of which one.

`spawn()` holds every task until it is done and logs a failure with the
task's name and the exception's type -- never its message, which may carry
peer data or key material. If the task cannot be started (no event loop in
this thread), the coroutine is closed and the error raised, so the caller's
own fallback runs and no "coroutine was never awaited" is left behind.

Used by the terminal clients and android_bridge alike.
"""
import asyncio
import logging
from typing import Awaitable, Optional, Set

_log = logging.getLogger("otrv4plus.tasks")

#: Tasks started here and not yet finished.
_RUNNING: Set[asyncio.Future] = set()


def spawn(coro: Awaitable, *, loop: Optional[asyncio.AbstractEventLoop] = None,
          name: Optional[str] = None) -> asyncio.Future:
    """Run `coro` in the background on `loop` (default: as
    asyncio.ensure_future would) and keep it alive until it finishes."""
    try:
        task = loop.create_task(coro) if loop is not None else asyncio.ensure_future(coro)
    except BaseException:
        close = getattr(coro, "close", None)    # a coroutine; a future has none
        if close is not None:
            close()
        raise
    _RUNNING.add(task)
    label = name or getattr(coro, "__qualname__", "task")
    task.add_done_callback(lambda t, label=label: _finished(t, label))
    return task


def _finished(task: asyncio.Future, label: str) -> None:
    _RUNNING.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        _log.warning("background task %s failed: %s", label, type(exc).__name__)


def running() -> int:
    """How many tasks started here have not finished (for tests)."""
    return len(_RUNNING)
