"""Import the OTRv4+ orchestration layer on Android.

This is platform glue.  It changes no security logic and patches nothing in the
engine -- it only solves the mechanical problem that `otrv4+.py` cannot be
imported by name.

Why a loader is needed at all
-----------------------------
The orchestration layer lives in a file called `otrv4+.py`.  `+` is not legal in
a Python identifier, so `import otrv4+` is a syntax error.  The repository works
around this with two symlinks (`otrv4_.py`, `otrv4plus.py`) and the test suite
loads the file explicitly via importlib.  Neither is reliable inside an APK:
asset packaging does not preserve symlinks, and Chaquopy's importer works from
its own source set rather than the repository layout.  So the Android host loads
it the explicit way, once, under the same `otrv4_` alias the rest of the
codebase already expects.

Android facts this module encodes
---------------------------------
Measured against the actual module-scope imports of otrv4+.py:

  * Required third-party: `socks` (PySocks, pure Python) and `otrv4_core` (our
    Rust wheel, built per ABI).
  * Optional: `argon2` (argon2-cffi).  Absent, the engine falls back to scrypt
    and prints a warning.  It is wanted on Android for the at-rest KDF, and it
    needs a native build, so it is reported rather than assumed.
  * `resource` is imported at module scope but is already wrapped in try/except;
    it is used to set RLIMIT_CORE to 0, which disables core dumps.  That is a
    property worth keeping on Android, not a problem to work around.
  * `termios`, `tty`, `readline`, `pty` are imported inside TUI functions only.
    Android never calls those paths, so they need no stubs.

Python 3.12 is a hard requirement: otrv4+.py uses PEP 701 f-string syntax
(`f"{x !r }"`) that does not parse on 3.11 or earlier.  `ensure_runtime()`
checks this first, because the failure would otherwise surface as a confusing
SyntaxError deep in an import.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from typing import Any, List, Optional, Tuple

__all__ = ["ensure_runtime", "load_orchestration", "RuntimeUnsupported",
           "MIN_PYTHON", "REQUIRED_MODULES", "OPTIONAL_MODULES"]

MIN_PYTHON: Tuple[int, int] = (3, 12)
REQUIRED_MODULES = ("otrv4_core", "socks")
OPTIONAL_MODULES = ("argon2",)

_ORCHESTRATION_ALIASES = ("otrv4_", "otrv4plus")
_CANDIDATE_FILENAMES = ("otrv4+.py", "otrv4_.py", "otrv4plus.py")


class RuntimeUnsupported(RuntimeError):
    """The runtime cannot host the orchestration layer."""


def ensure_runtime() -> None:
    """Fail fast, and clearly, on an unsupported runtime."""
    if sys.version_info[:2] < MIN_PYTHON:
        raise RuntimeUnsupported(
            f"OTRv4+ requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ "
            f"(PEP 701 f-strings in otrv4+.py); this is "
            f"{sys.version_info.major}.{sys.version_info.minor}. "
            f"Do not lower the requirement -- rebuild the Chaquopy runtime."
        )
    missing = [m for m in REQUIRED_MODULES if importlib.util.find_spec(m) is None]
    if missing:
        raise RuntimeUnsupported(
            f"missing required modules: {missing}. otrv4_core is the Rust wheel "
            f"for this ABI; socks is PySocks."
        )


def missing_optional() -> List[str]:
    """Optional dependencies that are absent.  Reported, never fatal."""
    return [m for m in OPTIONAL_MODULES if importlib.util.find_spec(m) is None]


def _find_source(search_paths: Optional[List[str]] = None) -> Optional[str]:
    paths = list(search_paths or [])
    paths.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    paths.extend(p for p in sys.path if isinstance(p, str) and p)
    for directory in paths:
        for name in _CANDIDATE_FILENAMES:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate):
                return candidate
    return None


def load_orchestration(search_paths: Optional[List[str]] = None) -> Any:
    """Import otrv4+.py under the `otrv4_` alias and return the module.

    Idempotent: a second call returns the already-imported module rather than
    executing it twice.  That matters -- the module has import-time side effects
    (the fail-closed Rust requirement check, and RLIMIT_CORE).
    """
    for alias in _ORCHESTRATION_ALIASES:
        existing = sys.modules.get(alias)
        if existing is not None:
            return existing

    ensure_runtime()

    source = _find_source(search_paths)
    if source is None:
        raise RuntimeUnsupported(
            f"could not locate the orchestration source; looked for "
            f"{list(_CANDIDATE_FILENAMES)}"
        )

    directory = os.path.dirname(source)
    if directory not in sys.path:
        # Sibling modules (otrv4plus_log, otrv4plus_voice, otrv4plus_audio) are
        # imported by plain name from inside otrv4+.py.
        sys.path.insert(0, directory)

    spec = importlib.util.spec_from_file_location(_ORCHESTRATION_ALIASES[0], source)
    if spec is None or spec.loader is None:
        raise RuntimeUnsupported(f"cannot build an import spec for {source}")

    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module imports itself by alias in places, and a
    # failure part-way through must not leave a half-initialised entry behind.
    sys.modules[_ORCHESTRATION_ALIASES[0]] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(_ORCHESTRATION_ALIASES[0], None)
        raise

    for alias in _ORCHESTRATION_ALIASES[1:]:
        sys.modules.setdefault(alias, module)
    return module
