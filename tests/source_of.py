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
    (otrv4+.py) and the IRC client (otrv4plus_irc.py and the
    otrv4plus_irc_*.py modules it is mixed from). For the IRC tests that
    scan the whole program rather than one method."""
    import glob
    import os
    client = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
    names = ["otrv4+.py", "otrv4plus_irc.py"] + sorted(
        os.path.basename(p) for p in glob.glob(os.path.join(client, "otrv4plus_irc_*.py")))
    return "\n".join(open(os.path.join(client, name), encoding="utf-8").read()
                     for name in names)


def open_irc_and_engine(*_args, **_kwargs):
    """`open()` stand-in returning irc_and_engine_source() as a file."""
    import io
    return io.StringIO(irc_and_engine_source())


def transport_files() -> list:
    """The Android/desktop XMPP transport: android_bridge/transport.py and
    the transport_*.py modules XmppTransport is built from."""
    import glob
    import os
    bridge = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "android_bridge")
    return ([os.path.join(bridge, "transport.py")]
            + sorted(glob.glob(os.path.join(bridge, "transport_*.py"))))


def transport_source() -> str:
    """All of the transport's source, one file after another."""
    return "\n".join(open(p, encoding="utf-8").read() for p in transport_files())


def app_files() -> list:
    """OtrApp's source: android_bridge/app.py and the app_*.py modules it is
    built from."""
    import glob
    import os
    bridge = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "android_bridge")
    return ([os.path.join(bridge, "app.py")]
            + sorted(glob.glob(os.path.join(bridge, "app_*.py"))))


def app_source() -> str:
    """All of OtrApp's source, one file after another."""
    return "\n".join(open(p, encoding="utf-8").read() for p in app_files())


def connection_files() -> list:
    """ConnectionController's source: android_bridge/connection.py and the
    connection_*.py modules it is built from."""
    import glob
    import os
    bridge = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "android_bridge")
    return ([os.path.join(bridge, "connection.py")]
            + sorted(glob.glob(os.path.join(bridge, "connection_*.py"))))


def connection_source() -> str:
    """All of the controller's source, one file after another."""
    return "\n".join(open(p, encoding="utf-8").read() for p in connection_files())


def voice_files() -> list:
    """The voice subsystem: client/otrv4plus_voice.py and the
    otrv4plus_voice_*.py modules split out of it (params, crypto, jitter)."""
    import glob
    import os
    client = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
    return ([os.path.join(client, "otrv4plus_voice.py")]
            + sorted(glob.glob(os.path.join(client, "otrv4plus_voice_*.py"))))


def voice_source() -> str:
    """All of the voice subsystem's source, one file after another."""
    return "\n".join(open(p, encoding="utf-8").read() for p in voice_files())


def main_source(module) -> str:
    """`module.main` followed by each of the module's own functions it calls,
    in the order it first calls them. `main` is a list of steps; a test about
    what start-up does reads the steps too."""
    import ast
    import textwrap
    parts, seen, queue = [], {"main"}, [module.main]
    while queue:                     # the steps, and the steps they call
        src = textwrap.dedent(inspect.getsource(queue.pop(0)))
        parts.append(src)
        for node in ast.walk(ast.parse(src)):
            name = getattr(getattr(node, "func", None), "id", None)
            fn = getattr(module, name, None) if isinstance(node, ast.Call) and name else None
            if (inspect.isfunction(fn) and fn.__module__ == module.__name__
                    and name not in seen):
                seen.add(name)
                queue.append(fn)
    return "\n".join(parts)


def init_source(cls) -> str:
    """`cls.__init__` followed by the `_init_*` steps it is made of."""
    steps = [getattr(cls, n) for n in vars(cls) if n.startswith("_init_")]
    return "\n".join(inspect.getsource(f) for f in [cls.__init__] + steps)


#: ConversationScreen.kt and the files split from it, in that order.
CONVERSATION_SCREEN_PARTS = ("ConversationScreen.kt", "ConversationGroupUi.kt",
                             "ConversationSecurityUi.kt", "ConversationMediaUi.kt")


def conversation_screen_source() -> str:
    """The conversation screen: ConversationScreen.kt and its Conversation*Ui.kt
    parts, so a check on "the screen" keeps reading every composable on it."""
    import os
    ui = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "android", "app", "src", "main", "java", "org", "otrv4plus",
                      "android", "ui")
    return "\n".join(open(os.path.join(ui, n), encoding="utf-8").read()
                     for n in CONVERSATION_SCREEN_PARTS)


def irc_source() -> str:
    """The IRC client's source: otrv4plus_irc.py and the otrv4plus_irc_*.py
    modules it is mixed from, one file after another."""
    import glob
    import os
    client = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "client")
    paths = [os.path.join(client, "otrv4plus_irc.py")] + sorted(
        glob.glob(os.path.join(client, "otrv4plus_irc_*.py")))
    return "\n".join(open(p, encoding="utf-8").read() for p in paths)
