# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms: what you are in one, and what that lets you do.

XEP-0045 MULTI-USER CHAT
------------------------
A room is a JID -- `general@conference.example.i2p` -- and you are in it under
a nickname, which makes your presence in the room `room@service/nick`. Two
separate things decide what you may do, and conflating them is the commonest
way to get this wrong:

  * **Affiliation** is your long-term standing with the room: owner, admin,
    member, none, outcast. It survives leaving and it is what a ban is.
  * **Role** is your standing in this visit: moderator, participant, visitor,
    none. It is assigned when you join and lost when you leave.

Owning a room does not by itself let you speak in it -- an owner who joined as
a visitor in a moderated room has to be given voice like anybody else -- and a
moderator who is not an owner cannot destroy the room however much of it they
run. The UI has to ask both questions, which is what [privileges] is for.

WHY THIS IS A SEPARATE MODULE
-----------------------------
So the rules can be EXECUTED. A "Destroy room" button that is enabled for
somebody the server will refuse is worse than no button: it teaches the user
that the app is unreliable, and the error it produces arrives minutes later
over I2P. Every rule here is derived from XEP-0045 §5.1.1 and §5.1.2, is
tested by being run, and imports nothing.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not decide whether a room is encrypted. It is not, and nothing here
should be read as suggesting otherwise: OTRv4+ is a two-party protocol and a
MUC message is fanned out by the server to everybody in the room. A room in
this client is plaintext to the server that hosts it, and the UI says so.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

__all__ = ["AFFILIATIONS", "ROLES", "Privileges", "privileges",
           "validate_room", "validate_nick", "classify", "describe",
           "CODES", "room_of", "nick_of", "service_of", "MAX_NICK"]

# -- the two vocabularies -----------------------------------------------------

#: Long-term standing with the room, strongest first. Survives leaving.
OWNER = "owner"
ADMIN = "admin"
MEMBER = "member"
NONE = "none"
OUTCAST = "outcast"
AFFILIATIONS = (OWNER, ADMIN, MEMBER, NONE, OUTCAST)

#: Standing in this visit. Assigned on join, lost on leave.
MODERATOR = "moderator"
PARTICIPANT = "participant"
VISITOR = "visitor"
NO_ROLE = "none"
ROLES = (MODERATOR, PARTICIPANT, VISITOR, NO_ROLE)

#: Longest nickname accepted locally. XEP-0045 defers to the service, which
#: commonly caps around here; a name longer than this is a mistake rather than
#: a preference and the error is better delivered before the round trip.
MAX_NICK = 64

#: Characters a resourcepart cannot carry, plus the ones that would make the
#: nickname unaddressable in a room JID.
_BAD_NICK = set('/@\t\r\n')


class Privileges:
    """What a person may do in a room, given their affiliation and role.

    Every field is a plain bool so the UI can bind straight to it. Nothing
    here is a guess: a False means XEP-0045 says the service will refuse, and
    a True means it will not refuse *for this reason* -- a room's own
    configuration can still say no, which is why the app reports what the
    server actually answers rather than treating these as promises.
    """

    __slots__ = ("affiliation", "role", "speak", "change_subject", "invite",
                 "kick", "ban", "configure", "destroy", "grant_membership")

    def __init__(self, affiliation, role, speak, change_subject, invite,
                 kick, ban, configure, destroy, grant_membership):
        self.affiliation = affiliation
        self.role = role
        self.speak = speak
        self.change_subject = change_subject
        self.invite = invite
        self.kick = kick
        self.ban = ban
        self.configure = configure
        self.destroy = destroy
        self.grant_membership = grant_membership

    def as_dict(self):
        return {name: getattr(self, name) for name in self.__slots__}

    def __eq__(self, other):
        return isinstance(other, Privileges) and \
            self.as_dict() == other.as_dict()

    def __repr__(self):                                      # pragma: no cover
        # Affiliation and role only. A repr listing the room or the nickname
        # would be one `%r` away from a log line naming a person and a place.
        return "<Privileges %s/%s>" % (self.affiliation, self.role)


def privileges(affiliation: str, role: str) -> Privileges:
    """What this affiliation and this role allow, per XEP-0045 §5.1.

    Unrecognised values are treated as the weakest of their kind rather than
    raising. A server that answers something this module has not heard of must
    not produce a UI in which every button is enabled: not knowing is a reason
    to offer less, never more.
    """
    aff = affiliation if affiliation in AFFILIATIONS else NONE
    rol = role if role in ROLES else NO_ROLE

    # An outcast is banned. They are not in the room and nothing else applies
    # -- checked first so no later rule can accidentally grant something.
    if aff == OUTCAST:
        return Privileges(aff, NO_ROLE, False, False, False, False, False,
                          False, False, False)

    # ROLE decides what happens in the room now.
    speak = rol in (MODERATOR, PARTICIPANT)
    # §8.1: a moderator always may; whether a participant may is a room
    # setting. True here means "the protocol does not forbid it" -- the
    # service is still entitled to refuse, and the app reports what it says.
    change_subject = rol in (MODERATOR, PARTICIPANT)
    kick = rol == MODERATOR

    # AFFILIATION decides standing, which outlives the visit.
    ban = aff in (OWNER, ADMIN)
    grant_membership = aff in (OWNER, ADMIN)
    # Only an owner. §10.9: destroying is an owner-only use case, and an admin
    # who runs the room day to day still cannot delete it.
    configure = aff == OWNER
    destroy = aff == OWNER

    # Inviting is the one that is genuinely a room setting rather than a rank:
    # an open room lets anybody invite, a members-only room commonly does not.
    # Anybody present may try; a refusal is reported rather than predicted.
    invite = rol in (MODERATOR, PARTICIPANT, VISITOR)

    return Privileges(aff, rol, speak, change_subject, invite, kick, ban,
                      configure, destroy, grant_membership)


# -- addresses ----------------------------------------------------------------

def room_of(jid: str) -> str:
    """The bare room JID, with any nickname removed."""
    return str(jid or "").strip().split("/", 1)[0]


def nick_of(jid: str) -> str:
    """The nickname out of an occupant JID, or "" when there is none."""
    text = str(jid or "").strip()
    return text.split("/", 1)[1] if "/" in text else ""


def service_of(jid: str) -> str:
    """The MUC service hosting a room: the domain of the room's JID."""
    room = room_of(jid)
    return room.split("@", 1)[1] if "@" in room else ""


_ROOM = re.compile(r"^[^\s@/:<>'\"&]+@[A-Za-z0-9][A-Za-z0-9.-]*$")


def validate_room(jid: str) -> Optional[Tuple[str, str]]:
    """Check a room address without the network.

    Returns `(code, detail)` for the first problem, or None. The service is
    authoritative; this refuses only what no service could accept.
    """
    text = str(jid or "").strip()
    if not text:
        return ("bad_request", "Enter a room address.")
    if "/" in text:
        return ("bad_request",
                "Enter the room address only, without the /nickname.")
    if "@" not in text:
        return ("bad_request",
                "A room address looks like general@rooms.example.i2p.")
    if not _ROOM.match(text):
        return ("bad_request", "That is not a valid room address.")
    return None


def validate_nick(nick: str) -> Optional[Tuple[str, str]]:
    """Check a nickname without the network."""
    text = str(nick or "").strip()
    if not text:
        return ("bad_request", "Choose a nickname for the room.")
    if len(text) > MAX_NICK:
        return ("bad_request",
                "That nickname is too long (limit %d characters)." % MAX_NICK)
    bad = sorted(_BAD_NICK & set(text))
    if bad:
        shown = ", ".join(repr(c) for c in bad)
        return ("bad_request", "A nickname cannot contain %s." % shown)
    return None


# -- what the service said ----------------------------------------------------

#: Every code the room operations can return, and what each means.
#:
#: Stable strings: Kotlin branches on them.
CODES = {
    "ok": "Done.",
    "conflict": "That nickname is already taken in this room.",
    "not_authorized": "This room needs a password.",
    "forbidden": "You are banned from this room.",
    "registration_required": "This room is members only.",
    "not_allowed": "This service does not let you create rooms.",
    "not_acceptable": "The room refused that.",
    "service_unavailable": "The room is full.",
    "item_not_found": "There is no such room.",
    "bad_request": "The request was not valid.",
    "unsupported": "This server does not offer rooms.",
    "timeout": "The room did not answer. Over I2P this can be slow -- try "
               "again.",
    "network": "Could not reach the server.",
    "cancelled": "Cancelled.",
    "unknown": "That did not work.",
}

#: RFC 6120 conditions, mapped. XEP-0045 §7.2.x gives each one a MUC meaning
#: that is much more specific than its generic one, which is why the sentences
#: above say "already taken in this room" rather than "conflict".
_CONDITIONS = {
    "conflict": "conflict",
    "not-authorized": "not_authorized",
    "forbidden": "forbidden",
    "registration-required": "registration_required",
    "not-allowed": "not_allowed",
    "not-acceptable": "not_acceptable",
    "service-unavailable": "service_unavailable",
    "item-not-found": "item_not_found",
    "bad-request": "bad_request",
    "feature-not-implemented": "unsupported",
    "remote-server-timeout": "timeout",
    "internal-server-error": "unknown",
}

#: Exception TYPE names that mean the round trip never completed.
#:
#: `PresenceError` is deliberately NOT here, although a failed join raises one.
#: slixmpp's contract for `join_muc_wait` is explicit: a PresenceError means
#: "the MUC returned a presence error" -- the service answered -- and an
#: `asyncio.TimeoutError` means "neither success nor presence error". Treating
#: a refusal as a timeout would tell somebody who has been banned to try again.
_TIMEOUTS = frozenset({"IqTimeout", "TimeoutError"})
_NETWORK = frozenset({"ConnectionError", "ConnectionRefusedError", "OSError",
                      "ConnectionResetError"})


def classify(exc: BaseException) -> Tuple[str, str]:
    """Turn a failed room operation into a code and a sentence.

    NEVER returns the exception's own text, for the reason
    `otrv4plus_registration.classify` does not: a slixmpp error stringifies to
    something containing the stanza, which here carries the room, the service
    and the nickname -- three things the diagnostic rules put alongside a JID.
    """
    try:
        known = getattr(exc, "code", None)
        if isinstance(known, str) and known in CODES and known != "ok":
            return known, CODES[known]
    except Exception:                                        # pragma: no cover
        pass

    condition = _condition_of(exc)
    if condition and condition in _CONDITIONS:
        code = _CONDITIONS[condition]
        return code, CODES[code]

    name = type(exc).__name__
    if name in _TIMEOUTS:
        return "timeout", CODES["timeout"]
    if name in _NETWORK:
        return "network", CODES["network"]
    if name == "CancelledError":
        return "cancelled", CODES["cancelled"]
    return "unknown", CODES["unknown"]


def describe(code: str) -> str:
    """The sentence for a code, falling back rather than raising."""
    return CODES.get(code, CODES["unknown"])


def _condition_of(exc: BaseException) -> str:
    """The XMPP error condition, read structurally rather than from text.

    slixmpp puts it on `.condition` for an IqError and inside the stanza for
    both that and a `PresenceError` -- joining fails by presence, not by iq,
    which is the case a lookup that only knew about `.iq` would miss.
    """
    try:
        value = getattr(exc, "condition", None)
        if value:
            return str(value)
    except Exception:                                        # pragma: no cover
        pass
    for attr in ("iq", "presence", "stanza"):
        try:
            stanza = getattr(exc, attr, None)
            if stanza is None:
                continue
            value = stanza["error"]["condition"]
            if value:
                return str(value)
        except Exception:
            continue
    return ""
