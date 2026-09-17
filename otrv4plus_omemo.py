# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OMEMO 2: who a message has to be encrypted TO, and what the server said.

XEP-0384, `urn:xmpp:omemo:2`
----------------------------
OMEMO has two halves. One is cryptography -- XEdDSA, X3DH, a Double Ratchet
per device -- and this module contains none of it and must never contain any:
see WHERE THE CRYPTOGRAPHY IS below.

The other half is XMPP, and it is the half that decides whether a message
reaches everybody it should:

  * every account publishes a DEVICE LIST at `urn:xmpp:omemo:2:devices` over
    PEP, and a BUNDLE per device at `urn:xmpp:omemo:2:bundles`;
  * a sender fetches the device list of every recipient, fetches a bundle for
    each device it has no session with, and encrypts the message key once per
    device;
  * that includes the sender's OWN other devices, or the message is unreadable
    on their laptop.

THE MISTAKE THIS MODULE EXISTS TO PREVENT
-----------------------------------------
Encrypting to whoever happens to be online. Presence is not membership: a
member of a room who is offline now will read the message later, and a device
that has not sent a stanza recently is still a device. A recipient set built
from the occupant list a UI is showing is a set that silently excludes people,
and the failure is invisible to the sender -- their message simply never
arrives for someone, with no error anywhere.

So the recipient set is derived from MEMBERSHIP and device lists, never from
presence. [recipients_for_room] is that rule, and it is tested by being run.

WHERE THE CRYPTOGRAPHY IS
-------------------------
Not here, and not hand-written anywhere in this project. OMEMO 2's key
agreement and ratchet are implemented by `python-omemo` and `twomemo`, which
are the reference implementations; writing a second Double Ratchet for a
security product would be the worst kind of wheel to reinvent.

Those libraries are not yet reachable on Android -- `xeddsa` binds to a C
library with no Android wheel, and nothing in this module can fix that. What
this module does is make everything ELSE ready, so the remaining work is a
build problem rather than a protocol one. `ANDROID_ENCRYPTION_ARCHITECTURE.md`
records exactly what is missing.

No slixmpp import, no Android import, no I/O.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "NAMESPACE", "DEVICES_NODE", "BUNDLES_NODE", "SCE_NAMESPACE",
    "Device", "DeviceList", "recipients_for_direct", "recipients_for_room",
    "bundles_needed", "validate_device_id", "classify", "describe", "CODES",
    "MIN_DEVICE_ID", "MAX_DEVICE_ID",
]

#: The OMEMO 2 namespace. NOT `eu.siacs.conversations.axolotl`, which is
#: OMEMO 0.3 ("oldmemo") -- a different protocol with a different key exchange
#: that this project does not implement.
NAMESPACE = "urn:xmpp:omemo:2"

#: PEP node carrying an account's device list.
DEVICES_NODE = NAMESPACE + ":devices"

#: PEP node carrying one bundle per device.
BUNDLES_NODE = NAMESPACE + ":bundles"

#: XEP-0420 Stanza Content Encryption, which OMEMO 2 uses to wrap the payload.
#: Named so the wire format is checkable rather than assumed.
SCE_NAMESPACE = "urn:xmpp:sce:1"

#: A device id is a positive 31-bit integer (XEP-0384 §4.1).
MIN_DEVICE_ID = 1
MAX_DEVICE_ID = 2 ** 31 - 1


class Device:
    """One device of one account.

    `label` is optional and user-supplied. It is carried for the UI and is
    never used to decide anything: a device is identified by its id, and a
    client that trusted a label would be trusting a string the far end chose.
    """

    __slots__ = ("jid", "device_id", "label")

    def __init__(self, jid: str, device_id: int, label: str = ""):
        self.jid = _bare(jid)
        self.device_id = int(device_id)
        self.label = str(label or "")

    def __eq__(self, other):
        return (isinstance(other, Device) and other.jid == self.jid
                and other.device_id == self.device_id)

    def __hash__(self):
        return hash((self.jid, self.device_id))

    def __repr__(self):                                      # pragma: no cover
        # The device id only. A repr carrying the JID would put an account
        # name into any log line that ever formatted one.
        return "<Device #%d>" % self.device_id


class DeviceList:
    """An account's devices, as its PEP node last said.

    Carries *when* it was read, because a stale list is the commonest way an
    OMEMO message goes missing: somebody adds a phone, and every sender who
    has not refetched encrypts to everything except the phone.
    """

    __slots__ = ("jid", "devices", "at")

    def __init__(self, jid: str, devices: Iterable[Device], at: float = 0.0):
        self.jid = _bare(jid)
        self.devices = tuple(devices)
        self.at = float(at)

    @property
    def ids(self) -> Tuple[int, ...]:
        return tuple(d.device_id for d in self.devices)

    def is_stale(self, now: float, max_age: float) -> bool:
        """Whether this should be refetched before it is used to encrypt.

        A list read once at login and never again is how a newly-added device
        stops receiving. Cheap to re-ask: it is a PEP fetch, not a handshake.
        """
        return self.at <= 0.0 or (now - self.at) > max_age

    def __len__(self):
        return len(self.devices)

    def __repr__(self):                                      # pragma: no cover
        return "<DeviceList n=%d>" % len(self.devices)


def recipients_for_direct(
    peer_list: DeviceList,
    own_list: DeviceList,
    own_device_id: int,
) -> Tuple[Device, ...]:
    """Every device a 1:1 message must be encrypted to.

    BOTH sides. Leaving out the sender's own other devices is the classic
    OMEMO bug: the message is delivered and readable by the recipient, and
    unreadable on the sender's own laptop, which looks like data loss rather
    than a protocol mistake.

    The sending device itself is excluded -- it has the plaintext, and a
    session with oneself is not a thing.
    """
    out: List[Device] = []
    seen: Set[Tuple[str, int]] = set()
    for device in tuple(peer_list.devices) + tuple(own_list.devices):
        if device.jid == own_list.jid and device.device_id == own_device_id:
            continue
        key = (device.jid, device.device_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(device)
    return tuple(out)


def recipients_for_room(
    members: Sequence[str],
    device_lists: Dict[str, DeviceList],
    own_jid: str,
    own_device_id: int,
) -> Tuple[Tuple[Device, ...], Tuple[str, ...]]:
    """Every device a group message must be encrypted to, and who is missing.

    `members` is ROOM MEMBERSHIP -- the real JIDs of people entitled to read
    the room -- not the occupant list. In a non-anonymous MUC those are
    obtainable; in a semi-anonymous one they are not, which is why
    [room_can_use_omemo] exists and why this returns the gaps rather than
    quietly dropping them.

    Returns `(devices, missing)`. `missing` names the members whose device list
    we do not have, and the CALLER must not send until it is empty or the user
    has been told: a message encrypted to everyone-we-happen-to-know-about is
    a message that silently excludes somebody.
    """
    own_bare = _bare(own_jid)
    out: List[Device] = []
    missing: List[str] = []
    seen: Set[Tuple[str, int]] = set()

    # The sender's own other devices count, exactly as in a 1:1 -- a group
    # message unreadable on your own laptop is the same defect in a room.
    ordered = list(dict.fromkeys([_bare(m) for m in members] + [own_bare]))

    for member in ordered:
        if not member:
            continue
        listing = device_lists.get(member)
        if listing is None or len(listing) == 0:
            missing.append(member)
            continue
        for device in listing.devices:
            if member == own_bare and device.device_id == own_device_id:
                continue
            key = (device.jid, device.device_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(device)
    return tuple(out), tuple(missing)


def bundles_needed(
    recipients: Iterable[Device],
    established: Iterable[Tuple[str, int]],
) -> Tuple[Device, ...]:
    """Which recipients we must fetch a bundle for before encrypting.

    A bundle is only needed for a device we have no session with. Refetching
    one per message would be an I2P round trip per device per message, which
    on this transport is the difference between a chat and a spinner.
    """
    have = {(_bare(jid), int(device_id)) for jid, device_id in established}
    return tuple(d for d in recipients
                 if (d.jid, d.device_id) not in have)


def validate_device_id(device_id) -> Optional[Tuple[str, str]]:
    """Check a device id without the network. XEP-0384 §4.1."""
    try:
        value = int(device_id)
    except (TypeError, ValueError):
        return ("bad_device_id", "That is not a device identifier.")
    if value < MIN_DEVICE_ID or value > MAX_DEVICE_ID:
        return ("bad_device_id", "That device identifier is out of range.")
    return None


def room_can_use_omemo(
    anonymity: str,
    membership_known: bool,
) -> Tuple[bool, str]:
    """Whether a room's configuration lets OMEMO work at all.

    Not a preference. OMEMO encrypts to each member's DEVICES, which requires
    their real JIDs; a semi-anonymous MUC deliberately hides those from
    ordinary occupants, so there is nobody to encrypt to. Offering OMEMO there
    would produce a message that cannot be sent, minutes after the user chose
    it.

    Returns `(usable, reason)`. The reason is shown when it is not.
    """
    if str(anonymity).lower() in ("semi-anonymous", "semi_anonymous",
                                  "anonymous"):
        return (False,
                "This room hides members' addresses, so there is nobody to "
                "encrypt to.")
    if not membership_known:
        return (False,
                "The room's membership could not be read, so a message might "
                "not reach everyone.")
    return (True, "")


# -- what went wrong ----------------------------------------------------------

#: Every code this layer can return. Stable: Kotlin branches on them.
CODES = {
    "ok": "Done.",
    "no_devices": "This contact has published no OMEMO devices.",
    "no_bundle": "A device's key material could not be fetched.",
    "stale_devices": "The device list changed; it is being refreshed.",
    "no_session": "No encrypted session could be established.",
    "not_encrypted": "This message was not encrypted.",
    "undecryptable": "This message could not be decrypted.",
    "not_for_us": "This message was not encrypted for this device.",
    "unsupported": "This server does not support OMEMO 2.",
    "room_anonymous": "This room hides members' addresses, so OMEMO cannot "
                      "be used in it.",
    "incomplete_membership": "The room's membership could not be read, so a "
                             "message might not reach everyone.",
    "timeout": "The server did not answer. Over I2P this can be slow -- try "
               "again.",
    "network": "Could not reach the server.",
    "no_backend": "OMEMO is not available in this build.",
    "unknown": "OMEMO failed.",
}

_CONDITIONS = {
    "item-not-found": "no_devices",
    "feature-not-implemented": "unsupported",
    "service-unavailable": "unsupported",
    "forbidden": "unknown",
    "not-allowed": "unknown",
    "remote-server-timeout": "timeout",
    "internal-server-error": "unknown",
}

_TIMEOUTS = frozenset({"IqTimeout", "TimeoutError"})
_NETWORK = frozenset({"ConnectionError", "ConnectionRefusedError", "OSError",
                      "ConnectionResetError"})


def classify(exc: BaseException) -> Tuple[str, str]:
    """Turn a failure into a code and a sentence.

    NEVER the exception's own text, for the reason every other `classify` in
    this project refuses it: the stanza carries JIDs, and an OMEMO error can
    carry a device id and key material besides. The condition is read
    structurally and the sentence comes from [CODES].
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
    return "unknown", CODES["unknown"]


def describe(code: str) -> str:
    """The sentence for a code, falling back rather than raising."""
    return CODES.get(code, CODES["unknown"])


def _condition_of(exc: BaseException) -> str:
    try:
        value = getattr(exc, "condition", None)
        if value:
            return str(value)
    except Exception:                                        # pragma: no cover
        pass
    for attr in ("iq", "stanza", "message"):
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


def _bare(jid) -> str:
    """Bare and case-folded, as everything else in this project keys on."""
    try:
        return str(jid or "").strip().split("/", 1)[0].lower()
    except Exception:                                        # pragma: no cover
        return ""
