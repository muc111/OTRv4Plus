"""Address rules for XMPP-over-I2P, in one place.

These checks lived inside `main()` in `otrv4plus_xmpp.py` as a nested
`_check_jid` that called `sys.exit` on the first problem. That is exactly right
for a command line and useless to anything else: a phone cannot exit the
process because a text field is half-typed, and it wants every problem at once
rather than the first one.

So the rules move here and return their complaint instead of acting on it.
`main()` still exits, and with the same words -- it just gets them from a
function now. The Android connection screen shows them next to the field.

Pure standard library on purpose. The settings screen validates as the user
types, long before slixmpp, the engine or the Rust core are loaded, and none of
them should have to be present for "that address has two @ signs" to be
sayable.

The wording is preserved verbatim from the command line, including the phrasing
that was arrived at by watching someone paste an abbreviated address out of a
chat window and spend a session wondering why nothing connected. See
`tests/test_peer_address_mistakes.py` for what that cost.
"""

import re
from typing import List, Optional

__all__ = [
    "jid_error", "server_error", "sam_host_error", "sam_port_error",
    "jid_domain", "profile_errors", "b32_error",
    "B32_LABEL_LENGTH", "B32_SUFFIX",
]

#: A `.b32.i2p` label is the destination hash itself, base32-encoded: 52
#: characters over the lowercase base32 alphabet. Not a name that resolves to
#: one -- `TRANSPORT_POLICY.md` is explicit that nothing resolves it, the label
#: *is* the address.
#:
#: Which is why this check is worth having. Every other kind of wrong address
#: fails fast: a bad hostname gets a NAMING LOOKUP failure, a bad JID gets
#: rejected by the server. A `.b32.i2p` with one character changed is a
#: perfectly well-formed address for a destination that does not exist, and the
#: only symptom is SAM_CONNECT_TIMEOUT -- 240 seconds of a progress spinner
#: before anything is said. Fifty-two random characters is exactly the kind of
#: thing that arrives truncated by a chat client's line wrapping.
B32_LABEL_LENGTH = 52
B32_SUFFIX = ".b32.i2p"
_B32_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz234567")
_B32_LABEL = re.compile(r"[a-z2-7]{%d}" % B32_LABEL_LENGTH, re.IGNORECASE)

#: SAM's registered port. The bundled router will not necessarily use it -- see
#: ANDROID_I2P_ARCHITECTURE.md §5, which argues for an abstract unix socket
#: because a loopback TCP port is visible to every app on the device -- but it
#: is the right default for an external router, which is what the app talks to
#: until the router is bundled.
DEFAULT_SAM_PORT = 7656
DEFAULT_SAM_HOST = "127.0.0.1"


def jid_error(value: str, label: str = "--jid") -> Optional[str]:
    """Return why *value* is not a usable JID, or None if it is.

    An empty value is not an error here. The command line treats "not given" as
    a separate case from "given wrongly", and so does the settings screen: a
    field the user has not reached yet should not be shouting at them.
    """
    if not value:
        return None
    if "@" not in value or value.count("@") != 1:
        return ("Invalid %s: %r\n"
                "  Expected  user@server.b32.i2p" % (label, value))
    local, _, domain = value.partition("@")
    if not local or not domain:
        return ("Invalid %s: %r\n"
                "  Both a username and a server are required." % (label, value))
    if "..." in value or ".." in domain:
        return ("Invalid %s: %r\n"
                "  This looks like an abbreviated address. Use the full "
                "server name, not one shortened with '...'." % (label, value))
    for part in domain.split("."):
        if not part:
            return ("Invalid %s: %r\n"
                    "  The server name has an empty part — check for a "
                    "stray or doubled dot." % (label, value))
    return None


def jid_domain(value: str) -> str:
    """The server half of a JID, or "" if there isn't one.

    Used to default the c2s address to the JID's own domain, which is what the
    command line does when `--server` is not given.
    """
    if not value or "@" not in value:
        return ""
    return value.partition("@")[2]


def b32_error(value: str, label: str = "--server") -> Optional[str]:
    """Return why *value* is a malformed `.b32.i2p` address, or None.

    None for anything that does not end in `.b32.i2p` -- a short `.i2p` name is
    resolved by the hosts file or a SAM NAMING LOOKUP and has no shape to
    check, so this is not the function to ask about one.

    Case is accepted either way. Base32 is case-insensitive and a router takes
    both; the address is not normalised here because silently rewriting what
    someone typed is how a mismatch becomes invisible.
    """
    if not value or not value.lower().endswith(B32_SUFFIX):
        return None
    labels = value[:-len(B32_SUFFIX)]
    if "." in labels:
        return ("Invalid %s: %r\n"
                "  A .b32.i2p address is one label before the suffix, not "
                "several." % (label, value))
    if len(labels) != B32_LABEL_LENGTH:
        return ("Invalid %s: %r\n"
                "  A .b32.i2p address has exactly %d characters before "
                "'.b32.i2p'; this one has %d. %s"
                % (label, value, B32_LABEL_LENGTH, len(labels),
                   "It looks truncated — check nothing was lost to a line "
                   "break when it was copied."
                   if len(labels) < B32_LABEL_LENGTH
                   else "Check nothing was appended when it was copied."))
    if not _B32_LABEL.fullmatch(labels):
        bad = sorted({c for c in labels if c.lower() not in _B32_ALPHABET})
        return ("Invalid %s: %r\n"
                "  A .b32.i2p address uses only a-z and 2-7. This one "
                "contains %s. Note that 0, 1, 8 and 9 are not in the "
                "alphabet and are easily confused with O, l, B and g."
                % (label, value, ", ".join(repr(c) for c in bad)))
    return None


def server_error(value: str, label: str = "--server") -> Optional[str]:
    """Return why *value* is not a usable c2s address, or None.

    Deliberately weaker than `jid_error`: this is a host, not a JID, and the
    one thing that is always wrong is putting a JID here. That mistake is worth
    catching by name, because "server" and "address" are close enough in
    ordinary use that a user pasting their own JID into both fields is a
    reasonable thing to do and produces a failure that explains nothing.
    """
    if not value:
        return None
    if "@" in value:
        return ("Invalid %s: %r\n"
                "  This is a server address, not an account. Give the host "
                "only, with no user@ in front of it." % (label, value))
    if value.strip() != value:
        return ("Invalid %s: %r\n"
                "  There is whitespace at the start or end of the address."
                % (label, value))
    if ".." in value:
        return ("Invalid %s: %r\n"
                "  The server name has an empty part — check for a stray or "
                "doubled dot." % (label, value))
    for part in value.split("."):
        if not part:
            return ("Invalid %s: %r\n"
                    "  The server name has an empty part — check for a stray "
                    "or doubled dot." % (label, value))
    # Last, because the checks above catch the shapes that would make the b32
    # rules report something confusing about an address that is wrong for a
    # simpler reason.
    return b32_error(value, label)


def sam_host_error(value: str, label: str = "--sam-host") -> Optional[str]:
    """Return why *value* is not a usable SAM host, or None.

    No check that it is loopback. It usually should be -- a SAM bridge is an
    unauthenticated control channel and pointing it across a network is a bad
    idea -- but the command line has always allowed it, some people do run a
    router on another machine on purpose, and a settings field is not the place
    to start refusing configurations that the rest of the program accepts.
    """
    if not value:
        return ("Invalid %s: the SAM bridge needs a host, normally %s"
                % (label, DEFAULT_SAM_HOST))
    if value.strip() != value:
        return ("Invalid %s: %r\n"
                "  There is whitespace at the start or end of the host."
                % (label, value))
    return None


def sam_port_error(value, label: str = "--sam-port") -> Optional[str]:
    """Return why *value* is not a usable SAM port, or None.

    Accepts a string, because that is what a text field produces, and an int,
    because that is what a stored profile produces. `bool` is rejected on
    purpose: `True` is an int in Python and would otherwise validate as port 1.
    """
    if isinstance(value, bool):
        return "Invalid %s: %r is not a port number" % (label, value)
    if isinstance(value, str):
        if not value.strip():
            return ("Invalid %s: the SAM bridge needs a port, normally %d"
                    % (label, DEFAULT_SAM_PORT))
        try:
            value = int(value.strip(), 10)
        except ValueError:
            return "Invalid %s: %r is not a number" % (label, value)
    if not isinstance(value, int):
        return "Invalid %s: %r is not a port number" % (label, value)
    if not (1 <= value <= 65535):
        return ("Invalid %s: %d is outside the range of port numbers (1-65535)"
                % (label, value))
    return None


def profile_errors(jid: str, server: str, sam_host: str, sam_port) -> List[str]:
    """Every problem with a connection profile, not just the first.

    A list rather than an exception, because the settings screen shows all of
    them at once. Order follows the screen, so the first entry is the first
    field.
    """
    found = []
    for err in (jid_error(jid),
                server_error(server),
                sam_host_error(sam_host),
                sam_port_error(sam_port)):
        if err is not None:
            found.append(err)
    return found
