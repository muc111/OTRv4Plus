# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Source of a class together with the project mixins it is built from.

OTRv4PlusXMPP is split across modules (otrv4plus_xmpp_admin.py and others
mixed in). `inspect.getsource(cls)` returns the class body only, so a test
asking "does any method of the client set X" would stop seeing the methods
that moved. This reads every class in the MRO that is ours.
"""
import inspect


def class_source(cls) -> str:
    """The class and each of its otrv4plus_* bases, in MRO order."""
    return "\n".join(inspect.getsource(c) for c in cls.__mro__
                     if c.__module__.startswith("otrv4plus")
                     or c.__module__ == "__main__")
