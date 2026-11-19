# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the server's administrator has restricted on this account, told in
the app's own words.

A server running XMPP Guard (or anything that speaks the same way) can mute
an account, stop its file transfers, suspend it, put the whole server into
maintenance, sign it out, or remove it. It says so with an ordinary XMPP
error: a fixed condition (RFC 6120) and a free-text sentence.

    muted        message error  cancel/not-allowed
                 "Messaging is temporarily restricted on your account"
    no files     iq error       cancel/not-allowed
                 "File transfers are temporarily restricted on your account"
                 ("... temporarily disabled on this server" for everyone)
    suspended    stream error   policy-violation
                 "Access temporarily restricted by server administration"
    maintenance  stream error   not-authorized
                 "Server maintenance in progress, please try again later"
                 ("Server entering lockdown, ..." when everyone is closed)
    signed out   stream error   not-authorized
                 "Disconnected by server administration"
    removed      stream error   not-authorized
                 "Account removed by server administration"

THE SERVER'S TEXT IS NEVER SHOWN. It is matched against these fixed phrases
and a known one becomes a sentence written here; an unknown one is nothing
this module recognises. A server (or whoever controls it) cannot write its
own words onto the screen this way, and the condition must match too, so a
contact cannot fake a restriction by typing the phrase into a message.

Standard library only: the Android app, the desktop app and the terminal
client all use it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

#: Kinds, in the order a person would rank them.
REMOVED = "account_removed"
SUSPENDED = "account_banned"            # transport.BANNED_CODE, unchanged
SIGNED_OUT = "signed_out_by_admin"
MAINTENANCE = "server_maintenance"
MUTED = "account_muted"
FILES_RESTRICTED = "files_restricted"
FILES_DISABLED = "files_disabled_on_server"


@dataclass(frozen=True)
class Restriction:
    kind: str
    #: Whether a fresh attempt could succeed without anyone acting. False:
    #: stop reconnecting and wait for the person (or the administrator).
    retry: bool
    #: The sentence for the screen, written here.
    text: str


_TEXTS = {
    REMOVED: (False,
              "This account was removed from the server by its administrator. "
              "Sign-in will not work again."),
    SUSPENDED: (False,
                "Your account has been suspended by the server's administrator. "
                "The app will not sign in again until the suspension is lifted."),
    SIGNED_OUT: (False,
                 "You were signed out by the server's administrator. Press "
                 "Connect to sign in again."),
    MAINTENANCE: (True,
                  "The server is in maintenance mode. The app tries again by "
                  "itself; you can also press Connect."),
    MUTED: (False,
            "Not sent: the server's administrator has temporarily restricted "
            "messaging on your account. Messages and files cannot be sent "
            "until the restriction ends. Nothing is retried automatically."),
    FILES_RESTRICTED: (False,
                       "Not sent: the server's administrator has temporarily "
                       "restricted file transfers on your account."),
    FILES_DISABLED: (False,
                     "Not sent: file transfers are temporarily disabled on "
                     "this server."),
}


def _make(kind: str) -> Restriction:
    retry, text = _TEXTS[kind]
    return Restriction(kind=kind, retry=retry, text=text)


def _norm(text: Optional[str]) -> str:
    return " ".join(str(text or "").lower().split())


def of_stream_error(condition: Optional[str],
                    text: Optional[str]) -> Optional[Restriction]:
    """The restriction a stream error announces, or None for any other.

    `policy-violation` with "banned" is mod_otrv4plus_moderation's ban, and
    is the same kind as XMPP Guard's suspension."""
    cond = str(condition or "").strip().lower()
    said = _norm(text)
    if cond == "policy-violation":
        if "restricted by server administration" in said or "banned" in said:
            return _make(SUSPENDED)
        return None
    if cond == "not-authorized":
        if "account removed by server administration" in said:
            return _make(REMOVED)
        if "disconnected by server administration" in said:
            return _make(SIGNED_OUT)
        if "maintenance" in said or "lockdown" in said:
            return _make(MAINTENANCE)
    return None


def of_stanza_error(error_type: Optional[str], condition: Optional[str],
                    text: Optional[str]) -> Optional[Restriction]:
    """The restriction a message or IQ error announces, or None.

    Only `cancel/not-allowed`: anything else (a contact's server refusing,
    a room's limits) is not a restriction on this account."""
    if str(error_type or "").strip().lower() not in ("cancel", ""):
        return None
    if str(condition or "").strip().lower() != "not-allowed":
        return None
    said = _norm(text)
    if "file transfers are temporarily disabled on this server" in said:
        return _make(FILES_DISABLED)
    if "file transfers" in said and "restricted on your account" in said:
        return _make(FILES_RESTRICTED)
    if "messaging" in said and "restricted on your account" in said:
        return _make(MUTED)
    return None


def text_for(kind: str) -> str:
    """The sentence for a kind, for a caller that only kept the kind."""
    return _TEXTS[kind][1] if kind in _TEXTS else ""


def is_server_announcement(sender: str, own_domain: str) -> bool:
    """A message from the server itself: a bare domain with no local part
    and no resource, equal to the domain this account is on. That is how
    XMPP Guard's announce (type headline) and notify (type chat) arrive.

    A contact cannot send from a bare domain: the server stamps the sender
    of everything a client sends. A remote server could, so the domain must
    be our own."""
    s = str(sender or "").strip().lower()
    d = str(own_domain or "").strip().lower()
    return bool(s) and bool(d) and s == d and "@" not in s and "/" not in s


# ── asking the server (XMPP Guard with the restriction query) ───────────────
#
#   <iq type='get' to='DOMAIN'><query xmlns='xmppguard:restrictions'/></iq>
#
# answered, by a server that has it, with one child per restriction in force
# on THIS account (until = unix time, 0 = until lifted):
#
#   <query xmlns='xmppguard:restrictions'>
#     <muted until='...'/> <no-files until='...'/> <files-disabled/>
#     <maintenance until='...'/>
#   </query>
#
# A server without it answers with an error, or not at all: nothing is shown.

QUERY_NS = "xmppguard:restrictions"

#: Latest "until" taken as a time: anything past this is not one.
_MAX_UNTIL = 2 ** 40


def _until(value) -> int:
    try:
        n = int(str(value).strip())
    except Exception:
        return 0
    return n if 0 <= n < _MAX_UNTIL else 0


def parse_query(query) -> dict:
    """What a `query` element says, as
    {"muted": until|None, "no_files": until|None, "files_disabled": bool,
     "maintenance": until|None}. `query` is an ElementTree element (or None:
    nothing known). Unknown children are ignored."""
    found = {"muted": None, "no_files": None, "files_disabled": False,
             "maintenance": None}
    if query is None:
        return found
    for child in list(query):
        tag = str(getattr(child, "tag", "")).rsplit("}", 1)[-1]
        if tag == "muted":
            found["muted"] = _until(child.get("until"))
        elif tag == "no-files":
            found["no_files"] = _until(child.get("until"))
        elif tag == "files-disabled":
            found["files_disabled"] = True
        elif tag == "maintenance":
            found["maintenance"] = _until(child.get("until"))
    return found


def _when(until: int) -> str:
    import time as _time
    if not until:
        return "until the administrator lifts it"
    return "until " + _time.strftime("%Y-%m-%d %H:%M UTC", _time.gmtime(until))


def summary(found: dict) -> str:
    """One sentence for the screen, or "" when nothing is restricted."""
    parts = []
    if found.get("muted") is not None:
        parts.append("messaging is restricted %s" % _when(found["muted"]))
    if found.get("no_files") is not None:
        parts.append("file transfers are restricted %s" % _when(found["no_files"]))
    elif found.get("files_disabled"):
        parts.append("file transfers are disabled on this server")
    if found.get("maintenance") is not None:
        parts.append("the server is in maintenance mode")
    if not parts:
        return ""
    text = "; ".join(parts)
    return ("Your account is temporarily restricted by the server's "
            "administrator: " + text + ".")
