"""The connection profile: where the app connects, and who may change it.

The command line takes this as eight `argparse` flags typed afresh every run.
A phone has to remember it, show it, let it be edited, and survive being
edited wrongly -- so it becomes a value with rules rather than a pile of
strings.

What this module is careful about
---------------------------------

**The default server is a default, not a policy.** The app ships pointing at a
server so that a new user can install it and talk to someone without first
learning what a c2s destination is. Every field of that default is replaceable,
and `ConnectionProfile.is_default_server` exists so the UI can say plainly which
one is in use. A messenger that silently pins you to its operator's server is
not the thing this project is trying to be.

**Not configured is a real state, not a missing value.** If no default server
has been compiled in, `default_profile()` returns None and the app asks the
user. It does not invent a placeholder address, and there is no sentinel string
that could be mistaken for a host. See `DEFAULT_SERVER` below.

**The password is not here.** It is a secret, it belongs in `SecureStore` under
the app's own key custody, and a profile is something that gets logged,
exported in a diagnostic report, and shown on screen. Keeping the two apart is
what makes it safe to treat this object as ordinary data everywhere else.
`tests/test_android_connection_profile.py` asserts the absence rather than
trusting it.

**Validation is shared, not reimplemented.** The rules live in
`otrv4plus_address`, which the command line uses too, so an address the phone
accepts is an address the CLI accepts and the error text is the same sentence.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

import otrv4plus_address as _address

__all__ = [
    "ConnectionProfile", "DEFAULT_SERVER", "default_profile",
    "ProfileError",
]


#: The server the app points at out of the box, or "" for none.
#:
#: Empty ships an app that asks the user where to connect on first run, which
#: is correct behaviour rather than a missing feature -- so this file is
#: honest whether or not a default is configured, and there is no placeholder
#: that could reach a user as if it were a real address.
#:
#: Set it to the c2s destination of the server the app should use, for example
#: "xmpp-elite.i2p" or a full "<52 chars>.b32.i2p". The JID domain a user types
#: does not have to match it: `server` is the host the SAM stream is opened to,
#: `jid`'s domain is the XMPP virtual host, and a server can front several --
#: which is why a profile carries both and why `effective_server` exists.
#:
#: This is a destination hash, not a name: nothing resolves it, the label *is*
#: the address (`TRANSPORT_POLICY.md`). It is therefore not a trust anchor
#: either, and does not become one by being compiled in. The server is a relay
#: the DAKE authenticates *through*: the peer's identity key is pinned by TOFU
#: end to end, so a substituted or hostile server at this address costs
#: availability and metadata, and cannot read a message or impersonate a
#: contact.
DEFAULT_SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


class ProfileError(ValueError):
    """A profile was asked to become something it cannot be.

    Carries every complaint, not the first: a settings screen shows all the
    bad fields at once, and raising on the earliest one makes the user fix
    them one round trip at a time.
    """

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors) if errors else "invalid profile")
        self.errors = list(errors)


@dataclasses.dataclass(frozen=True)
class ConnectionProfile:
    """Everything needed to open a connection, and nothing secret.

    Frozen because a live connection holds one: a profile that could be edited
    underneath a running transport would mean the screen and the socket
    disagree about where they are connected. Editing produces a new profile
    (`replace`), and reconnecting is what applies it.
    """

    #: The full account address, user@host.
    jid: str = ""
    #: The c2s destination the SAM stream is opened to. Empty means "use the
    #: JID's own domain", which is what the command line does when --server is
    #: not given -- kept as empty rather than eagerly filled in so that
    #: `is_default_server` can tell a deliberate choice from an inherited one.
    server: str = ""
    sam_host: str = _address.DEFAULT_SAM_HOST
    sam_port: int = _address.DEFAULT_SAM_PORT
    #: False only for a clearnet server. The app is an I2P messenger; this
    #: exists because the transport has to know, not as an invitation.
    use_i2p: bool = True

    # -- derived --------------------------------------------------------------

    @property
    def effective_server(self) -> str:
        """The host a SAM stream will actually be opened to.

        `server` when set, the JID's domain otherwise. This is the value the
        transport uses, and the one worth showing on a confirmation screen --
        a user who leaves `server` blank should still be able to see where
        they are about to connect.
        """
        return self.server or _address.jid_domain(self.jid)

    @property
    def is_default_server(self) -> bool:
        """Whether this profile uses the shipped default rather than the user's.

        False when no default is configured, because then there is nothing to
        be using. The UI reads this to say "connecting via the default server"
        or to name the user's own -- which is a thing a person should be able
        to check without reading a settings form field by field.
        """
        return bool(DEFAULT_SERVER) and self.effective_server == DEFAULT_SERVER

    @property
    def is_complete(self) -> bool:
        """Whether this profile has enough to attempt a connection.

        Distinct from valid: an empty profile is not *wrong*, it is unfinished,
        and the two want different things on screen.
        """
        return bool(self.jid and self.effective_server and self.sam_host
                    and self.sam_port)

    # -- validation -----------------------------------------------------------

    def errors(self) -> List[str]:
        """Every problem with this profile, in the order the fields appear."""
        found = _address.profile_errors(
            self.jid, self.server, self.sam_host, self.sam_port)
        # Checked here rather than in otrv4plus_address, which validates fields
        # and does not know what a profile is for. A JID with no domain and no
        # explicit server leaves nothing to connect to, and the per-field
        # checks all pass because each field is individually fine.
        if self.jid and not self.effective_server:
            found.append(
                "No server to connect to: %r has no domain and no server was "
                "given." % (self.jid,))
        return found

    def validate(self) -> "ConnectionProfile":
        """Return self, or raise ProfileError listing everything wrong."""
        found = self.errors()
        if found:
            raise ProfileError(found)
        return self

    def replace(self, **changes: Any) -> "ConnectionProfile":
        """A copy with *changes* applied. Does not validate -- editing a form
        goes through invalid states on the way to a valid one, and a setter
        that refuses them cannot be typed into."""
        return dataclasses.replace(self, **changes)

    # -- persistence ----------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """A plain dict for storage, with no secret in it by construction.

        Built by listing the fields rather than by `asdict`, so that a field
        added later has to be added here consciously. If a secret is ever put
        on this class, the omission will be deliberate instead of accidental.
        """
        return {
            "jid": self.jid,
            "server": self.server,
            "sam_host": self.sam_host,
            "sam_port": self.sam_port,
            "use_i2p": self.use_i2p,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ConnectionProfile":
        """Rebuild a profile from storage.

        Tolerant of missing keys and of unknown ones: stored settings outlive
        the version that wrote them, and a profile from an older build should
        open with its fields defaulted rather than crash the app on launch.
        Values are *not* validated here for the same reason -- a stored profile
        that has become invalid should be shown to the user for correction, not
        thrown away on their behalf.
        """
        data = data or {}
        port = data.get("sam_port", _address.DEFAULT_SAM_PORT)
        if isinstance(port, str) and port.strip().isdigit():
            port = int(port.strip(), 10)
        return cls(
            jid=str(data.get("jid", "") or ""),
            server=str(data.get("server", "") or ""),
            sam_host=str(data.get("sam_host", _address.DEFAULT_SAM_HOST) or ""),
            sam_port=port,
            use_i2p=bool(data.get("use_i2p", True)),
        )


def default_profile(jid: str = "") -> Optional[ConnectionProfile]:
    """The profile a fresh install starts from, or None if none is configured.

    None is the honest answer when `DEFAULT_SERVER` is empty, and the app's
    first-run screen is expected to handle it: ask for a server. Returning a
    profile with an empty server instead would push the same question one
    screen later, wearing a disguise.
    """
    if not DEFAULT_SERVER:
        return None
    return ConnectionProfile(jid=jid, server=DEFAULT_SERVER)
