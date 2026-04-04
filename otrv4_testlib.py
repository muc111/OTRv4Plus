import os
"""
otrv4_testlib.py — import shim for the test suite.

otrv4_.py imports `socks`, `termios`, `tty`, `resource` etc. at module level.
These are unavailable / irrelevant when running tests.  This shim stubs them
out before importing the real module, then re-exports every crypto class the
tests need.

Usage in test files:
    from otrv4_testlib import *        # or import otrv4_testlib as otr
"""

import sys
import types

def _stub(name):
    """Return (or create) a stub module that accepts any attribute access."""
    if name in sys.modules:
        return sys.modules[name]
    mod = types.ModuleType(name)
    # Make any attribute access return a no-op callable / object
    class _Anything:
        def __call__(self, *a, **kw): return _Anything()
        def __getattr__(self, k):     return _Anything()
        def __enter__(self):          return self
        def __exit__(self, *a):       pass
        def __iter__(self):           return iter([])
        def __bool__(self):           return False
        def __int__(self):            return 0
        def __str__(self):            return ''
    _any = _Anything()
    mod.__getattr__ = lambda k: _any
    mod.__file__     = os.devnull   # hypothesis scans __file__ — must be a real str
    mod.__spec__     = None
    sys.modules[name] = mod
    return mod

# Stub every non-crypto import that fails in Termux test context
for _m in ['socks', 'termios', 'tty', 'readline', 'pty',
           'resource', 'fcntl', 'grp', 'pwd']:
    _stub(_m)

# socket needs to look real enough for isinstance checks
import socket as _real_socket
# socks already stubbed above — but setdefaultproxy etc. must not crash
import sys as _sys
_socks = _sys.modules['socks']
_socks.PROXY_TYPE_SOCKS5 = 2
_socks.setdefaultproxy = lambda *a, **kw: None
class _SockSocket(_real_socket.socket): pass
_socks.socksocket = _SockSocket

# Now import the real module — all top-level import errors are suppressed
import importlib, os
_otrv4_path = os.path.join(os.path.dirname(__file__), 'otrv4+.py')
if not os.path.exists(_otrv4_path):
    # Try alternate names
    for _name in ['otrv4_.py', 'otrv4+.py', 'pop3_work.py', 'otrv4_combined.py']:
        _p = os.path.join(os.path.dirname(__file__), _name)
        if os.path.exists(_p):
            _otrv4_path = _p
            break

import importlib.util as _ilu
_spec = _ilu.spec_from_file_location('otrv4_', _otrv4_path)
_mod  = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# Re-export everything tests need
kdf_1            = _mod.kdf_1
KDFUsage         = _mod.KDFUsage
SHA3_512         = _mod.SHA3_512
OTRv4TLV         = _mod.OTRv4TLV
OTRv4Payload     = _mod.OTRv4Payload
OTRv4DataMessage = _mod.OTRv4DataMessage
RatchetHeader    = _mod.RatchetHeader
RingSignature    = _mod.RingSignature
DoubleRatchet    = _mod.DoubleRatchet
SecureMemory     = _mod.SecureMemory
SMPMath          = _mod.SMPMath
SMPConstants     = _mod.SMPConstants
SMPProtocolCodec = _mod.SMPProtocolCodec
ClientProfile    = _mod.ClientProfile
OTRConstants     = _mod.OTRConstants
NetworkConstants = _mod.NetworkConstants
MLKEM1024BraceKEM = _mod.MLKEM1024BraceKEM
MLDSA87Auth       = _mod.MLDSA87Auth
MLDSA87_AVAILABLE = _mod.MLDSA87_AVAILABLE
