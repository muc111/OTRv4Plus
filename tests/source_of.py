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


def client_files() -> list:
    """The XMPP client's source files: otrv4plus_xmpp.py and the modules its
    class is mixed from (otrv4plus_xmpp_*.py)."""
    import glob
    import os
    client = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
    return ([os.path.join(client, "otrv4plus_xmpp.py")]
            + sorted(glob.glob(os.path.join(client, "otrv4plus_xmpp_*.py"))))


def client_source() -> str:
    """All of the XMPP client's source, one file after another."""
    return "\n".join(open(p, encoding="utf-8").read() for p in client_files())


def irc_and_engine_source() -> str:
    """What otrv4+.py held before the IRC client moved out: the engine
    (otrv4+.py) and the IRC client (otrv4plus_irc.py). For the IRC tests
    that scan the whole program rather than one method."""
    import os
    client = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
    return "\n".join(open(os.path.join(client, name), encoding="utf-8").read()
                     for name in ("otrv4+.py", "otrv4plus_irc.py"))


def open_irc_and_engine(*_args, **_kwargs):
    """`open()` stand-in returning irc_and_engine_source() as a file."""
    import io
    return io.StringIO(irc_and_engine_source())
