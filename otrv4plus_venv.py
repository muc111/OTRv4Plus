# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Run the terminal clients with the project interpreter, whatever started them.

`Rust/build.sh` installs otrv4_core into ~/OTRv4Plus/.venv and removes older
copies from the system Python. Started as `python otrv4+.py`, a client then
found no core at all -- and said the core "was not built with the dake
module", which sent people rebuilding something that was fine (device
report, 2026-10-05). So the clients call `ensure()` first: when the project
virtualenv exists and this is not its interpreter, the same command is run
again with `.venv/bin/python`, once.

Standard library only; the terminal clients' entry points only (the app
never runs a client as a script).
"""
from __future__ import annotations

import os
import sys

__all__ = ["ensure", "venv_python"]

#: Set in the environment of the re-run, so it can never loop.
GUARD = "OTRV4PLUS_VENV_REEXEC"
#: Set to 1 to keep the interpreter you started with.
OPT_OUT = "OTRV4PLUS_NO_VENV"


def venv_python(script: str) -> str:
    """The project interpreter beside `script`, or "" if there is none."""
    root = os.path.dirname(os.path.realpath(script))
    for name in ("python", "python3"):
        path = os.path.join(root, ".venv", "bin", name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return ""


def ensure(script: str, argv=None, *, execv=os.execve) -> None:
    """Re-run `script` under .venv/bin/python unless that is this interpreter.

    Does nothing when there is no .venv, when this already is it, after one
    re-run, or when OTRV4PLUS_NO_VENV=1."""
    if os.environ.get(GUARD) or os.environ.get(OPT_OUT) == "1":
        return
    target = venv_python(script)
    if not target:
        return
    venv = os.path.realpath(os.path.dirname(os.path.dirname(target)))
    if os.path.realpath(sys.prefix) == venv:
        return
    env = dict(os.environ)
    env[GUARD] = "1"
    # The documented launch: the system allocator, so freed buffers are not
    # kept in Python's pools (the clients warn without it).
    env.setdefault("PYTHONMALLOC", "malloc")
    args = [target, os.path.realpath(script)] + list(sys.argv[1:] if argv is None else argv)
    sys.stderr.write("[otrv4+] using the project interpreter %s\n" % target)
    sys.stderr.flush()
    execv(target, args, env)
