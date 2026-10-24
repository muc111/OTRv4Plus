# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client says why it closed, after the exit wipe, on a terminal.

Owner report (2026-10-24, Termux): with no I2P router running the IRC client
"just closed"; it used to warn that it could not connect. The warning was
still printed, but the exit purge then wiped the screen and scrollback
(ESC[3J ESC[H ESC[2J), so only "Clean shutdown" was left. This runs the real
client in a pseudo-terminal with no router and reads what is left on screen
after the last wipe.
"""

import os
import select
import shutil
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_in_pty(argv, env, seconds=60.0):
    pid, fd = os.forkpty()  # not pty.fork: conftest stubs the pty module
    if pid == 0:  # child
        os.chdir(ROOT)
        os.execve(argv[0], argv, env)
    out = b""
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            elif os.waitpid(pid, os.WNOHANG)[0]:
                break
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(fd)
    return out.decode("utf-8", "replace")


@pytest.mark.skipif(sys.platform != "linux", reason="pty test")
def test_the_reason_survives_the_exit_wipe():
    home = tempfile.mkdtemp(prefix="irc-exit-")
    try:
        env = dict(os.environ, HOME=home, PYTHONMALLOC="malloc", TERM="xterm")
        out = _run_in_pty([sys.executable, os.path.join(ROOT, "otrv4+.py")], env)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    assert "Clean shutdown" in out, out[-2000:]
    if "\x1b[2J" not in out:
        pytest.skip("the terminal was not wiped in this environment")
    after = out[out.rindex("\x1b[2J"):]
    assert "Failed to connect via I2P - is i2pd running?" in after, after[:500]
    assert "SAM port 7656" in after


def test_a_pipe_gets_the_reason_once():
    """The repeat is for a wiped terminal only; a log has it once already."""
    with open(os.path.join(ROOT, "client", "otrv4plus_irc.py"), encoding="utf-8") as fh:
        src = fh.read()
    purge = src[src.index("def _purge_on_exit"):src.index("atexit.register(_purge_on_exit)")]
    assert 'if notice and sys.stdout.isatty():' in purge
    assert purge.index("_purge_scrollback(") < purge.index("safe_print(notice)")
