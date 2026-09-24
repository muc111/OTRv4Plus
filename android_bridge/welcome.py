# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4Plus Welcome room: who is discoverable, from what the room says.

WHAT IT IS
==========
A public, persistent XEP-0045 room named exactly `ROOM_NAME`. Joining it is
how an ordinary account finds other OTRv4Plus users without any server-admin
rights: its occupants are the discoverable people. It is a DISCOVERY room,
not a secure channel -- room traffic is ordinary MUC, and being in it grants
nothing: no OTR trust, no fingerprint, no SMP, no call, no file.

HOW THE ROOM IS FOUND -- NEVER GUESSED
======================================
No room JID is written anywhere in this project. The transport asks the
account's own server for its services (XEP-0030 disco#items), keeps those
whose disco#info identity is a MUC service (category "conference"), asks
each for its PUBLIC rooms, and takes the one whose advertised name is exactly
`ROOM_NAME` (`find_room`). None found, or more than one: nothing is joined,
and the state says which.

WHERE AN ADDRESS COMES FROM
===========================
Only from the `<item jid='...'/>` the MUC SERVICE puts in an occupant's
presence -- the service writes it, an occupant cannot forge it. A room shows
it to ordinary occupants only when it is non-anonymous (Prosody:
`whois = "anyone"`); in a semi-anonymous room occupants see nicknames only,
and a nickname is NOT an address. Those occupants are counted, never turned
into JIDs: no guessing, no probing, no enumeration.

Pure logic, no I/O. The transport feeds it events and asks it questions.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

__all__ = ["ROOM_NAME", "WelcomeDirectory", "find_room", "room_properties",
           "STATES"]

#: The room's advertised name, as the server lists it. Exact match.
ROOM_NAME = "OTRv4Plus Welcome"

#: The address used when a user CREATES the room (never when looking for
#: one: an existing room is found by its name). Plain ASCII, as a room
#: localpart must be.
ROOM_LOCALPART = "otrv4plus-welcome"

#: What the room is created with. Every field is XEP-0045 §15.5.3
#: muc#roomconfig. whois=anyone is what makes addresses visible to ordinary
#: occupants -- the only way "Add" can work -- and is the privacy cost the
#: creator is warned about before this is sent.
ROOM_CONFIG = (
    ("muc#roomconfig_roomname", "text-single", ROOM_NAME),
    ("muc#roomconfig_roomdesc", "text-single",
     "Discovery room for OTRv4Plus users. Not end-to-end encrypted: the "
     "server can read it, and everyone here sees each other's address."),
    ("muc#roomconfig_persistentroom", "boolean", True),
    ("muc#roomconfig_publicroom", "boolean", True),
    ("muc#roomconfig_whois", "list-single", "anyone"),
    ("muc#roomconfig_membersonly", "boolean", False),
    ("muc#roomconfig_passwordprotectedroom", "boolean", False),
)

#: disco#info features the created room must show, and what each means.
REQUIRED_FEATURES = (
    ("muc_public", "listed, so other users can find it"),
    ("muc_persistent", "kept when empty"),
    ("muc_nonanonymous", "members' addresses visible, so Add works"),
)


def missing_features(features) -> list:
    """Which of REQUIRED_FEATURES the room does NOT show, as descriptions."""
    have = {str(f) for f in (features or ())}
    return [why for feature, why in REQUIRED_FEATURES if feature not in have]

MUC_FEATURE = "http://jabber.org/protocol/muc"

# States, as stable strings for Kotlin.
NOT_CONNECTED = "not_connected"   # our stream is down: nothing is known
SEARCHING = "searching"           # asking the server for its rooms
NOT_FOUND = "not_found"           # no public room with ROOM_NAME
AMBIGUOUS = "ambiguous"           # more than one: refused, not picked
JOINING = "joining"
JOINED = "joined"
LEFT = "left"                     # we were removed from / left the room
FAILED = "failed"                 # discovery or join failed; code in detail
STATES = (NOT_CONNECTED, SEARCHING, NOT_FOUND, AMBIGUOUS, JOINING, JOINED,
          LEFT, FAILED)

# Anonymity, from the room's disco#info (XEP-0045 §6.4 / §15.6 features).
NON_ANONYMOUS = "non_anonymous"   # every occupant sees real JIDs
SEMI_ANONYMOUS = "semi_anonymous"  # only moderators see real JIDs
FULLY_ANONYMOUS = "fully_anonymous"
UNKNOWN = "unknown"


def _bare(jid: str) -> str:
    return str(jid or "").split("/", 1)[0].strip().lower()


def find_room(services: Iterable[dict],
              rooms_by_service: Dict[str, List[dict]],
              name: str = ROOM_NAME) -> Tuple[Optional[str], str]:
    """(room JID, "") or (None, NOT_FOUND | AMBIGUOUS).

    Only rooms listed by a service whose identity is a MUC ("conference")
    service, and only an EXACT name match: a room called "otrv4plus welcome
    (unofficial)" is somebody else's room.
    """
    matches = []
    for service in services or ():
        if str(service.get("category", "")) != "conference":
            continue
        for room in rooms_by_service.get(str(service.get("jid", "")), []):
            if str(room.get("name", "")).strip() == name and room.get("jid"):
                matches.append(_bare(room["jid"]))
    matches = sorted(set(matches))
    if not matches:
        return None, NOT_FOUND
    if len(matches) > 1:
        return None, AMBIGUOUS
    return matches[0], ""


def room_properties(features: Iterable[str]) -> dict:
    """What the room's disco#info says about it."""
    f = {str(x) for x in (features or ())}
    if "muc_nonanonymous" in f:
        anonymity = NON_ANONYMOUS
    elif "muc_semianonymous" in f:
        anonymity = SEMI_ANONYMOUS
    elif "muc_fullyanonymous" in f:
        anonymity = FULLY_ANONYMOUS
    else:
        anonymity = UNKNOWN
    return {
        "anonymity": anonymity,
        "public": "muc_public" in f,
        "persistent": "muc_persistent" in f,
        "is_muc": MUC_FEATURE in f,
    }


class WelcomeDirectory:
    """The Welcome room's state and who in it has a visible address."""

    def __init__(self) -> None:
        self.room: str = ""
        self.state: str = NOT_CONNECTED
        self.detail: str = ""
        self.props: dict = room_properties(())
        self.nick: str = ""
        #: nick -> real bare JID, or "" when the room did not reveal it.
        self._occupants: Dict[str, str] = {}

    # -- lifecycle -----------------------------------------------------------

    def searching(self) -> None:
        self.state, self.detail = SEARCHING, ""
        self._occupants.clear()

    def not_found(self, reason: str) -> None:
        self.room, self.state, self.detail = "", reason, ""
        self._occupants.clear()

    def joining(self, room: str, features: Iterable[str], nick: str) -> None:
        self.room = _bare(room)
        self.props = room_properties(features)
        self.nick = nick
        self.state, self.detail = JOINING, ""
        self._occupants.clear()

    def joined(self, nick: str) -> None:
        self.nick = nick
        self.state = JOINED

    def failed(self, code: str) -> None:
        self.state, self.detail = FAILED, str(code or "")
        self._occupants.clear()

    def clear(self) -> None:
        """Our stream went: nobody's presence is known any more."""
        self.state, self.detail = NOT_CONNECTED, ""
        self._occupants.clear()

    # -- presence ------------------------------------------------------------

    def is_room(self, jid: str) -> bool:
        return bool(self.room) and _bare(jid) == self.room

    def occupant(self, nick: str, real_jid: str, available: bool,
                 is_self: bool = False) -> None:
        """One occupant presence from the room."""
        nick = str(nick or "")
        if is_self:
            if not available and self.state == JOINED:
                self.state = LEFT
                self._occupants.clear()
            return
        if not nick:
            return
        if available:
            self._occupants[nick] = _bare(real_jid) if "@" in str(
                real_jid or "") else ""
        else:
            self._occupants.pop(nick, None)

    # -- questions -----------------------------------------------------------

    def people(self, self_bare: str = "") -> List[str]:
        """Bare JIDs of occupants whose address the room revealed. One each,
        however many resources or nicknames they have; never our own."""
        if self.state != JOINED:
            return []
        me = _bare(self_bare)
        return sorted({j for j in self._occupants.values() if j and j != me})

    def hidden(self) -> int:
        """Occupants with no revealed address (semi-anonymous room)."""
        if self.state != JOINED:
            return 0
        return sum(1 for j in self._occupants.values() if not j)

    def view(self, self_bare: str = "") -> dict:
        return {
            "state": self.state,
            "room": self.room,
            "detail": self.detail,
            "anonymity": self.props.get("anonymity", UNKNOWN),
            "public": bool(self.props.get("public")),
            "persistent": bool(self.props.get("persistent")),
            "people": self.people(self_bare),
            "hidden": self.hidden(),
        }
