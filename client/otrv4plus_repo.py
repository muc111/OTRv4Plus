# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Make the repository's android_bridge importable from client/.

Several client modules reuse the bridge's code (secure groups, the sealed
identity store, metadata scrubbing). In a clone, client/ and android_bridge/
are siblings, and a client started as `python otrv4plus_xmpp.py` has only
client/ on its import path -- so those imports failed and, being optional,
quietly turned secure groups off (found 2026-10-24, broken since rc.134).
Imported first by every module that needs the bridge. In the APK and the
Qubes package the files are flat, android_bridge is already beside them,
and this does nothing.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if (os.path.isdir(os.path.join(_ROOT, "android_bridge"))
        and _ROOT not in sys.path):
    # Appended, not inserted: client/ stays first, so the top-level
    # symlinks never shadow the modules they point at.
    sys.path.append(_ROOT)
