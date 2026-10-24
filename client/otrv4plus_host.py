# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The machine the terminal client runs on: Termux or not, where its state
lives, finding and running programs.

Shared by otrv4plus_xmpp.py and the modules its class is mixed from. Read
IS_TERMUX and XMPP_STATE_DIR as attributes of this module (`_host.IS_TERMUX`)
so that one setting is seen everywhere.
"""
import os


TERMUX_PREFIX = "/data/data/com.termux/files/usr"
IS_TERMUX = os.path.isdir("/data/data/com.termux")


def _which(binary: str) -> "str | None":
    """Locate an executable, honouring the Termux prefix explicitly.

    shutil.which() alone is unreliable inside Termux when PATH has been
    trimmed by a wrapper script, so the canonical prefix is checked too.
    """
    import shutil as _shutil
    found = _shutil.which(binary)
    if found:
        return found
    candidate = os.path.join(TERMUX_PREFIX, "bin", binary)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


# ---------------------------------------------------------------------------
# XMPP-private state directory
# ---------------------------------------------------------------------------
#
# XMPP and IRC used to share ~/.otrv4plus/trust.json, and that was not merely
# untidy. IRC regenerates its Ed448 identity every run by design, so every IRC
# fingerprint written there is stale the moment the process exits; on the next
# run `add_trust` raised FingerprintMismatchError and the user was told "This
# may indicate a MITM attack" for what was actually normal IRC behaviour.
#
# The two protocols have opposite identity contracts, so they get separate
# stores. XMPP owns everything under ~/.otrv4plus/xmpp/ and IRC keeps the
# legacy paths for its SMP secrets while persisting no trust at all.
XMPP_STATE_DIR = os.path.expanduser(
    os.environ.get("OTRV4PLUS_XMPP_STATE_DIR", "~/.otrv4plus/xmpp"))


def _xmpp_state_path(name: str) -> str:
    return os.path.join(XMPP_STATE_DIR, name)


def _run(argv, timeout=120, env=None, detach=False):
    """Run a command with no shell. Returns (rc, stdout, stderr).

    Never raises: a missing binary, a timeout and a crash all return a
    non-zero rc so callers can branch uniformly.

    detach=True is REQUIRED for any command that forks a daemon and exits
    (pulseaudio --start, i2pd --daemon). Capturing output from such a command
    deadlocks: the foreground process exits immediately, but the daemon it
    forked inherits the stdout and stderr pipes and holds them open for its
    entire lifetime, so communicate() never observes EOF and blocks until the
    timeout — which then kills the very daemon we were trying to start.
    Measured: 8 s timeout with capture, 0.01 s without.
    """
    import subprocess
    try:
        if detach:
            completed = subprocess.run(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                env=env or os.environ,
                check=False,
            )
            return completed.returncode, "", ""
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as exc:
        return 1, "", str(exc)
