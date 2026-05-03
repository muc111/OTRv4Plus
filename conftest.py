"""
conftest.py — pytest configuration for OTRv4+ test suite.

Sets up the module search path so all test files can do:
    import otrv4_ as otr
    import otrv4_testlib as otr
    import otrv4plus

without caring about the actual filename (otrv4+.py has an illegal Python
identifier character).  Also loads the Rust extension if present so Rust
tests are not skipped unnecessarily.
"""

import os
import sys
import types
import importlib.util

# ── 1. Add the project root to sys.path ──────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# ── 2. Stub non-crypto imports that fail outside Termux ──────────────────────
def _stub(name):
    if name in sys.modules:
        return sys.modules[name]
    mod = types.ModuleType(name)

    class _Any:
        def __call__(self, *a, **kw): return _Any()
        def __getattr__(self, k):    return _Any()
        def __enter__(self):         return self
        def __exit__(self, *a):      pass
        def __iter__(self):          return iter([])
        def __bool__(self):          return False
        def __int__(self):           return 0
        def __str__(self):           return ''

    _a = _Any()
    mod.__getattr__ = lambda k: _a
    mod.__file__ = os.devnull
    mod.__spec__ = None
    sys.modules[name] = mod
    return mod

for _m in ['socks', 'termios', 'tty', 'readline', 'pty',
           'resource', 'fcntl', 'grp', 'pwd']:
    _stub(_m)

# socks needs a couple of real attrs
_socks = sys.modules['socks']
_socks.PROXY_TYPE_SOCKS5 = 2
_socks.setdefaultproxy = lambda *a, **kw: None
import socket as _rsock
class _SS(_rsock.socket): pass
_socks.socksocket = _SS

# ── 3. Load otrv4+.py as both "otrv4_" and "otrv4plus" ───────────────────────
def _load_main():
    """Find otrv4+.py (or otrv4_.py) and load it under both aliases."""
    candidates = ['otrv4+.py', 'otrv4_.py', 'otrv4_combined.py']
    path = None
    for c in candidates:
        p = os.path.join(HERE, c)
        if os.path.exists(p):
            path = p
            break
    if path is None:
        return  # nothing to load

    if 'otrv4_' not in sys.modules:
        spec = importlib.util.spec_from_file_location('otrv4_', path)
        mod  = importlib.util.module_from_spec(spec)
        sys.modules['otrv4_'] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            # Tolerate import-time errors (missing extensions handled per-test)
            print(f"[conftest] Warning loading {path}: {e}")

    # Make otrv4plus an alias
    if 'otrv4plus' not in sys.modules and 'otrv4_' in sys.modules:
        sys.modules['otrv4plus'] = sys.modules['otrv4_']

_load_main()

# ── 4. Ensure otrv4_core Rust extension is importable if present ─────────────
try:
    import otrv4_core  # noqa: F401
except ImportError:
    pass

# ── 5. Inject SMPEngine into otrv4_ namespace ─────────────────────────────────
# SMPEngine was removed in v10.5.10 (replaced by Rust). Re-inject a thin
# wrapper so existing test references (otr.SMPEngine) continue to work.
try:
    import smp_engine_compat as _smp_compat
    _otrv4_mod = sys.modules.get('otrv4_')
    if _otrv4_mod is not None and not hasattr(_otrv4_mod, 'SMPEngine'):
        _otrv4_mod.SMPEngine = _smp_compat.SMPEngine
except Exception as _e:
    print(f"[conftest] Warning: could not inject SMPEngine: {_e}")
