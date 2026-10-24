"""android_bridge — Android integration layer for OTRv4+.

Nothing in this package implements a cryptographic primitive.  It composes the
existing OTRv4+ components (otrv4+.py orchestration, otrv4_core Rust engine) and
exposes a narrow, typed, structured-event surface for a Kotlin host to drive.

Package layout:

    secure_store.py   at-rest sealing interfaces + versioned AES-256-GCM record
                      framing.  Key custody is abstract; the Android
                      Keystore/StrongBox implementation is Phase 4.
    identity.py       long-term identity lifecycle: create, seal, reload,
                      reconstruct Rust key handles, stable fingerprint.
    events.py         structured state enums and events -- the replacement for
                      scraping terminal output.
    app.py            OtrApp facade: the only surface Kotlin talks to.

Design rules this package must keep:

  * No secret is ever returned to the caller.  Handles and opaque blobs only.
  * No secret is ever converted to `str`.
  * No English status string is load-bearing; callers switch on enums.
  * Every module here is import-safe without an Android runtime, so the whole
    package is testable on a desktop CI machine.
"""

import os as _os
import sys as _sys

# The engine modules (otrv4plus_*.py) live in client/ in the repository. In
# the APK they sit flat beside this package and there is no client/.
_CLIENT = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "client")
if _os.path.isdir(_CLIENT) and _CLIENT not in _sys.path:
    _sys.path.insert(0, _CLIENT)

__all__ = ["secure_store", "identity", "events", "app"]
