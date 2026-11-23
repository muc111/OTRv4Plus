# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal clients' debug switches, in one place.

`FLAGS.debug` (--debug / -d, or /debug at run time) shows the debug panel
and the protocol trace; `FLAGS.smp` (--smp-debug, implied by --debug)
traces SMP. Read them as `FLAGS.debug`, set them the same way: one object,
so every module sees a change at once. otrv4+.py's old names (DEBUG_MODE,
SMP_DEBUG) still read these values.
"""
import sys


class Flags:
    def __init__(self, argv):
        self.debug: bool = "--debug" in argv or "-d" in argv
        self.smp: bool = self.debug or "--smp-debug" in argv


FLAGS = Flags(sys.argv)
