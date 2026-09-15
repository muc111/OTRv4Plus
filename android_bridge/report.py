# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The file the user shares when something goes wrong.

Composes three things into one text document:

  1. the environment (`diagnostics.collect` -- versions, ABI, Rust core);
  2. what the connection thinks its state is right now;
  3. the event trace (`trace.TRACE`) -- what each component actually did.

The third is the reason this exists. "It says Not connected" is not
diagnosable; a table showing `controller connected -> failed`, preceded by
`keepalive probe_unanswered failures=2`, is diagnosable in one read.

WHY IN PYTHON
-------------
The same reason `diagnostics.as_text` is: the rule being enforced is about
CONTENT, and content is decided here. A renderer on the Kotlin side would be a
second place that decides what a diagnostic may say, and the first time
somebody adds a field it would be the place that forgot the rule. Kotlin
supplies the device facts it alone knows, writes the bytes, and hands the file
to the Sharesheet.

THE FINAL SWEEP
---------------
[build] runs `_scrub` over the FINISHED string, line by line, regardless of
what produced each line. Everything upstream is already supposed to be safe;
this is the belt to that pair of braces. The cost is nothing and the cost of
being wrong is a credential in a file the user is about to post into a bug
tracker.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional

from .diagnostics import SENSITIVE_KEY_HINTS
from .trace import REDACTED, TRACE

__all__ = ["build", "summary", "HEADER"]

HEADER = "OTRv4+ diagnostic report"

_HINTS = "|".join(re.escape(h) for h in SENSITIVE_KEY_HINTS)

#: `key: value` or `key=value` where the key trips a hint.
#:
#: The key class excludes the separators themselves, so the match cannot run
#: past the `=` into the value. An earlier version began with a mandatory
#: `[A-Za-z_]`, which ATE THE FIRST LETTER OF THE HINT -- `password=x` did not
#: match, because the leading class consumed the `p` and the alternation was
#: then looking at `assword`. It was caught by reading the rendered output of
#: a real report, which is the only reason this comment exists.
_ASSIGNMENT = re.compile(
    r"(?i)([^\s:=]*(?:%s)[^\s:=]*)(\s*[:=]\s*)(\S.*)$" % _HINTS)

#: `  key        value`, which is how [_kv] aligns its columns -- no separator
#: at all, so [_ASSIGNMENT] cannot see it.
_ALIGNED = re.compile(
    r"(?i)^(\s+[^\s:=]*(?:%s)[^\s:=]*\s+)(\S.*)$" % _HINTS)


def _scrub(text: str) -> str:
    """Redact anything that still looks like a secret being reported.

    Line by line over the FINISHED document, whichever layer wrote it. This is
    the belt to everything upstream's braces: the trace already redacts by key
    name and the collectors are curated, and this runs anyway because the cost
    is nothing and the cost of being wrong is a credential in a file the user
    is about to attach to a bug report.

    It replaces the VALUE rather than dropping the line. A reader who sees
    `password: [REDACTED]` knows the field existed and was withheld; a missing
    line tells them nothing.
    """
    out = []
    for line in text.splitlines():
        line = _ASSIGNMENT.sub(r"\1\2" + REDACTED, line)
        line = _ALIGNED.sub(r"\1" + REDACTED, line)
        out.append(line)
    return "\n".join(out)


def _section(title: str) -> str:
    return "\n%s\n%s" % (title, "-" * len(title))


def _kv(pairs: Dict[str, Any]) -> str:
    if not pairs:
        return "  (nothing to report)"
    width = max(len(str(k)) for k in pairs)
    return "\n".join("  %-*s %s" % (width, k, pairs[k])
                     for k in sorted(pairs))


def build(status: Optional[Dict[str, Any]] = None,
          device: Optional[Dict[str, Any]] = None,
          environment: Optional[Dict[str, Any]] = None,
          trace=None,
          limit: int = 0) -> str:
    """The whole report, as text, ready to be written to a file.

    Every argument is optional and every one is guarded: this is called
    precisely when things are broken, and a reporter that raises while
    explaining a failure leaves the user with nothing.
    """
    trace = TRACE if trace is None else trace
    parts = [
        HEADER,
        "generated  %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "This file contains connection state, timings and error types. It "
        "contains NO",
        "passwords, keys or other secrets, and NO message contents. It DOES "
        "contain the",
        "account and server addresses involved, because a roster, presence or "
        "routing",
        "fault cannot be diagnosed without them.",
    ]

    if device:
        parts.append(_section("Device"))
        parts.append(_kv(device))

    parts.append(_section("Connection"))
    try:
        parts.append(_kv(_connection_fields(status or {})))
    except Exception as exc:                                # pragma: no cover
        parts.append("  (could not read: %s)" % type(exc).__name__)

    if environment:
        parts.append(_section("Environment"))
        try:
            parts.append(_kv(_environment_fields(environment)))
        except Exception as exc:                            # pragma: no cover
            parts.append("  (could not read: %s)" % type(exc).__name__)

    parts.append(_section("Events (oldest first)"))
    try:
        parts.append(trace.render(limit))
    except Exception as exc:                                # pragma: no cover
        parts.append("(the trace could not be rendered: %s)"
                     % type(exc).__name__)

    return _scrub("\n".join(parts)) + "\n"


def _connection_fields(status: Dict[str, Any]) -> Dict[str, Any]:
    """The live connection view, flattened.

    `last` is unpacked rather than printed as a dict, because `last.code` and
    `last.detail` are the two fields a reader wants and a nested repr on a
    phone screen is unreadable.
    """
    last = status.get("last") or {}
    fields = {
        "stage": status.get("stage", "-"),
        "connected": status.get("connected", False),
        "jid": status.get("jid", "-"),
        "server": status.get("server", "-"),
        "default_server": status.get("is_default_server", "-"),
        "sam": status.get("sam", "-"),
        "worker_alive": status.get("worker_alive", "-"),
        "last_code": last.get("code", "-"),
        "last_detail": last.get("detail", "-"),
        "last_stage": last.get("stage", "-"),
    }
    inputs = status.get("inputs")
    if inputs:
        # Rendered by the controller, which already reports the password as
        # present/absent rather than as a value or even a length.
        fields["inputs"] = inputs
    return fields


def _environment_fields(env: Dict[str, Any]) -> Dict[str, Any]:
    """The handful of environment facts worth having, flattened.

    A subset, deliberately. `diagnostics.collect` produces a large nested
    report that is right for the Diagnostics screen and wrong for the top of
    a bug report; what matters here is which Python, which ABI and whether the
    Rust core loaded.
    """
    def get(group, key, default="-"):
        try:
            section = env.get(group) or {}
            return section.get(key, default)
        except Exception:
            return default

    return {
        "python": get("python", "version"),
        "abi": get("abi", "android_abi"),
        "rust_core_loaded": get("rust_core", "loaded"),
        "rust_core_version": get("rust_core", "version"),
        "engine_initialized": get("otrv4plus", "initialized"),
        "slixmpp": get("transport_deps", "slixmpp"),
    }


def summary(status: Optional[Dict[str, Any]] = None,
            device: Optional[Dict[str, Any]] = None,
            trace=None,
            events: int = 12) -> str:
    """A short report for the clipboard.

    The current state plus the last few events -- enough to paste into a
    message and often enough to identify the problem. The full export stays
    the authoritative artefact.
    """
    trace = TRACE if trace is None else trace
    status = status or {}
    lines = ["%s (summary)" % HEADER]
    if device:
        lines.append("device  %s / Android %s"
                     % (device.get("model", "?"), device.get("release", "?")))
    lines.append("stage   %s (connected=%s)"
                 % (status.get("stage", "-"), status.get("connected", False)))
    last = status.get("last") or {}
    if last.get("code") and last.get("code") != "ok":
        lines.append("last    %s: %s" % (last.get("code"),
                                         last.get("detail", "")))
    lines.append("")
    lines.append("last %d events:" % events)
    try:
        lines.append(trace.render(events))
    except Exception:                                       # pragma: no cover
        lines.append("(the trace could not be rendered)")
    return _scrub("\n".join(lines)) + "\n"
