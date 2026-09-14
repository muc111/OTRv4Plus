"""Describe a startup failure well enough to fix it, without leaking anything.

THE PROBLEM THIS SOLVES
-----------------------
The first APK ever run on a handset reported its failure as, in full:

    Failure    PyException

That is the Java class name of "a Python exception happened", and it is all
the device could say. The bridge dropped the message deliberately -- Python
exception text can embed data the engine was handling -- and the screen sets
FLAG_SECURE, so the failure could not even be photographed. The app was
undiagnosable by construction.

The reflex fix is to print `str(exc)` in debug builds. That is the wrong fix:
it makes the safety of the diagnostic depend on which build someone is running
and on nobody ever calling this from a path where a secret is in flight.

WHAT THIS DOES INSTEAD
----------------------
It classifies. Each exception type gets a stable `code` and a `detail` built
from values that are safe BY CONSTRUCTION rather than by inspection:

  * `RuntimeUnsupported` -- our own message, written in bootstrap.py, naming
    Python versions and module names. Safe because we wrote every character.
  * `ImportError` raised BY THE IMPORTER -- the `name` attribute only, never
    the message, which for a failed extension load quotes the full .so path.
    The importer always sets `.name`, so its errors are identifiable.
  * `ImportError` raised BY CODE (no `.name`) -- the message. In this project
    those come from otrv4+.py's fail-closed `_check_rust_requirements`, and
    they are the sentence that says which Rust entry point is missing.
    Bounded by MAX_DETAIL; this is the one branch that surfaces a message we
    did not necessarily write, and it is deliberate, because suppressing it
    reduced a real handset failure to "cannot import an unnamed module".
  * `SystemExit` -- the exit code, an integer.
  * anything else -- the type name and NOTHING else.

Plus a compact traceback: `basename:lineno in function`, for frames in this
project only. A file and a line number cannot carry a passphrase; they are
also the single most useful thing for finding the fault. No source text, no
locals, no repr of any value.

The result is safe in every build, which is why there is no debug gate on it.
A diagnostic that is only safe in debug is a diagnostic waiting to be promoted.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

__all__ = ["describe", "MAX_FRAMES", "MAX_DETAIL"]

#: Traceback frames kept. Enough to see the call path, not a wall of text on a
#: phone screen.
MAX_FRAMES = 12

#: Hard ceiling on the detail string, in case one of our own messages grows.
MAX_DETAIL = 400

def _frames(exc: BaseException) -> List[str]:
    """`basename:lineno in function`, innermost last.

    Walks __traceback__ directly rather than using the traceback module, so
    there is no chance of a formatter including source lines or locals.

    EVERY frame, not just this project's. An earlier version filtered to files
    whose names looked like ours, which had two faults: it dropped the frames
    for a fault inside slixmpp or CPython's importlib -- exactly the cases
    where the location is the whole answer -- and it relied on a path
    heuristic that silently matched nothing in some layouts. Keeping the
    innermost MAX_FRAMES is simpler and strictly more informative; the
    directory is stripped, and a bare source filename is not sensitive.
    """
    out: List[str] = []
    tb = getattr(exc, "__traceback__", None)
    while tb is not None:
        code = tb.tb_frame.f_code
        out.append("%s:%d in %s" % (os.path.basename(code.co_filename or "?"),
                                    tb.tb_lineno, code.co_name))
        tb = tb.tb_next
    return out[-MAX_FRAMES:]


def _detail(exc: BaseException) -> str:
    """A safe description of what went wrong, by exception type."""
    name = type(exc).__name__

    # Ours, from bootstrap.py. Every character of these messages is written in
    # this repository: Python versions, module names, candidate filenames.
    if name == "RuntimeUnsupported":
        return str(exc)

    # Two different things wear the ImportError name, and conflating them cost
    # a diagnosis on the first handset that got this far.
    #
    # CPython's import machinery ALWAYS sets `.name` (and `.path`) on the
    # errors it raises, including the dlopen failure for a bad extension --
    # whose message quotes the full .so path, which on Android sits inside the
    # package's private data directory. For those, the module name is the part
    # worth having and the message is the part to drop.
    #
    # An ImportError with NO `.name` was therefore raised by code rather than
    # by the importer -- in this project, by otrv4+.py's fail-closed
    # `_check_rust_requirements`, whose messages are written in this
    # repository and name Rust entry points. Those are the sentence that says
    # what is actually wrong, and suppressing them reported only "cannot
    # import an unnamed module".
    if isinstance(exc, ImportError):
        missing = getattr(exc, "name", None)
        if missing:
            return "cannot import %s" % missing
        raised_by_code = str(exc).strip()
        if raised_by_code:
            return raised_by_code
        return "an ImportError with neither a module name nor a message"

    if isinstance(exc, SystemExit):
        # otrv4plus_xmpp.py and otrv4+.py exit(1) when a dependency is absent.
        # Inside an APK there is no terminal for the message they printed, so
        # the code is all that survives -- worth saying plainly.
        return "the module called sys.exit(%r) during import" % (exc.code,)

    # The parser's own message, plus where. Safe, and on this project the most
    # diagnostic failure there is: otrv4+.py uses PEP 701 f-strings, so a
    # SyntaxError from it means the interpreter is older than 3.12 -- which on
    # Android means the Chaquopy runtime is not what the build asked for.
    #
    # `exc.text` is deliberately NOT included. It is the offending source LINE,
    # and while that is our own source rather than user data, a rule of "print
    # the source" is one that ages badly the moment this classifier is reused
    # somewhere a line of source has a literal in it.
    if isinstance(exc, SyntaxError):
        where = os.path.basename(exc.filename or "?")
        return "%s at %s:%s -- if this is otrv4+.py, the interpreter is " \
               "older than 3.12" % (exc.msg or "invalid syntax", where,
                                    exc.lineno)

    if isinstance(exc, (MemoryError, RecursionError)):
        return "resource exhaustion"

    # Everything else: the type, and not one word more. An OSError's message
    # carries paths; a ValueError raised deep in the engine can quote the value
    # it rejected.
    return "no detail is shown for %s, by design" % name


def describe(exc: BaseException) -> Dict[str, Any]:
    """Classify a startup failure into JSON-safe, displayable fields.

    Returns `code`, `detail` and `frames`. Never raises: a reporter that
    crashes while explaining a crash leaves nothing at all.
    """
    try:
        code = type(exc).__name__
    except Exception:                                    # pragma: no cover
        return {"code": "unknown", "detail": "", "frames": []}

    try:
        detail = _detail(exc)[:MAX_DETAIL]
    except Exception:
        detail = ""

    try:
        frames = _frames(exc)
    except Exception:
        frames = []

    # The cause is often the real answer -- `load_orchestration` re-raises, and
    # an ImportError chained onto a RuntimeUnsupported is the common shape.
    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    caused_by = ""
    if cause is not None and cause is not exc:
        try:
            caused_by = "%s: %s" % (type(cause).__name__,
                                    _detail(cause)[:MAX_DETAIL])
        except Exception:
            caused_by = ""

    return {"code": code, "detail": detail, "frames": frames,
            "caused_by": caused_by}
