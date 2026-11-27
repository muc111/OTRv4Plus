# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Background coroutines are started through otrv4plus_tasks.spawn.

A task from ensure_future / create_task that nobody keeps can be garbage-
collected before it finishes, and its failure surfaced, if at all, as an
anonymous "Task exception was never retrieved". spawn keeps it, and says
which task failed without saying what the error held.
"""
import ast
import asyncio
import gc
import logging
import os
import sys
import warnings

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))

import otrv4plus_tasks as tasks  # noqa: E402


def test_a_task_runs_to_the_end_with_no_other_reference():
    done = []

    async def slow():
        fut = asyncio.get_running_loop().create_future()
        asyncio.get_running_loop().call_later(0.05, fut.set_result, None)
        gc.collect()
        await fut
        done.append(True)

    async def main():
        tasks.spawn(slow())
        for _ in range(3):
            gc.collect()
            await asyncio.sleep(0.03)
        await asyncio.sleep(0.1)

    asyncio.run(main())
    assert done == [True]
    assert tasks.running() == 0


def test_a_failure_names_the_task_not_the_secret(caplog):
    async def leaks():
        raise ValueError("passphrase=hunter2")

    async def main():
        tasks.spawn(leaks(), name="restrictions query")
        await asyncio.sleep(0.01)

    with caplog.at_level(logging.WARNING, logger="otrv4plus.tasks"):
        asyncio.run(main())
    text = caplog.text
    assert "restrictions query" in text and "ValueError" in text
    assert "hunter2" not in text


def test_no_loop_closes_the_coroutine_and_raises():
    async def never():
        pass

    coro = never()
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with pytest.raises(Exception):
            tasks.spawn(coro, loop=_ClosedLoop())
        gc.collect()
    assert coro.cr_frame is None, "the coroutine was left open"


class _ClosedLoop:
    def create_task(self, coro):
        raise RuntimeError("Event loop is closed")


def test_nothing_starts_a_task_and_drops_it():
    """Every ensure_future / create_task whose result is thrown away goes
    through spawn instead."""
    offenders = []
    for folder in ("client", "android_bridge"):
        for name in sorted(os.listdir(os.path.join(ROOT, folder))):
            path = os.path.join(ROOT, folder, name)
            if not name.endswith(".py") or os.path.islink(path) or name == "otrv4plus_tasks.py":
                continue
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Attribute)
                        and node.value.func.attr in ("ensure_future", "create_task")):
                    offenders.append("%s/%s:%d" % (folder, name, node.lineno))
    assert not offenders, offenders
