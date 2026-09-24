# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Whether a conversation is in OTR mode, and when a body may go in the clear.

WHY THIS EXISTS
---------------
`EnhancedSessionManager.handle_outgoing_message` is *opportunistic*: the first
message to a peer with no session does not go out as typed. The engine creates
a session, starts a DAKE, queues the text, and returns DAKE1 for the caller to
send. That is a deliberate and defensible design for a client whose whole
purpose is encryption, and it is not being changed here.

But it means neither client could send an ordinary XMPP message. A Termux user
typing "hello" to a contact sent an 11 KB `?OTRv4 ...` handshake frame instead,
and the "hello" sat in the engine's queue waiting for a DAKE the other end
might never complete. Against a plain XMPP client -- or against an OTRv4+ build
that could not yet answer a DAKE -- the message simply never arrived.

So the decision of WHEN to involve OTR moves up to the clients, and lives here
so that both make it identically. Drift between two copies of this rule is not
a cosmetic bug: one direction of the drift sends plaintext where the user
expected encryption.

THE RULE
--------
A body may go in the clear only when BOTH are true:

  * nobody has asked for OTR on this conversation -- not the local user, and
    not the peer; and
  * the engine reports no encrypted session.

Which means, stated as the properties that matter:

  * An established session is NEVER downgraded. Once `is_otr` is true it stays
    true until the session is explicitly ended, so a dropped or half-built
    session cannot silently turn the next message into plaintext. That is the
    failure this class exists to make impossible.
  * A DAKE in flight is not a window. The peer's first protocol frame marks the
    conversation as OTR before the handshake completes.
  * Plaintext is never promoted to encrypted by accident either: sending in the
    clear does not start a DAKE, so a user who has not asked for OTR does not
    suddenly emit a handshake.

WHAT THIS IS NOT
----------------
It is not a security state and must never be displayed as one. `is_otr` means
"OTR has been asked for here", not "this is encrypted" and certainly not "this
is verified". The engine remains the only authority on that, and the UI reads
it from there.
"""

from __future__ import annotations

from typing import Set

__all__ = ["OtrMode"]


class OtrMode:
    """Per-peer record of whether OTR has been asked for.

    Deliberately tiny and deliberately not persisted: it describes a live
    conversation, and a restarted client with no session should start from
    "nobody has asked", not inherit a claim it cannot back up.
    """

    def __init__(self) -> None:
        self._otr: Set[str] = set()

    def request(self, peer: str) -> None:
        """Mark this conversation as OTR.

        Called when the local user starts OTR, and when a protocol frame
        arrives from the peer -- either is somebody asking, and the second is
        why a responder does not send the next line in the clear.
        """
        if peer:
            self._otr.add(peer)

    def clear(self, peer: str) -> None:
        """Forget the request, for an explicitly ended session.

        Only from an explicit end. A failed handshake or a dropped transport
        must NOT reach this: "the session broke" is not consent to continue in
        the clear.
        """
        self._otr.discard(peer)

    def is_otr(self, peer: str) -> bool:
        """Whether OTR has been asked for here. NOT a security state."""
        return peer in self._otr

    def may_send_plaintext(self, peer: str, encrypted: bool) -> bool:
        """Whether *peer* may be sent an unencrypted body right now.

        `encrypted` is the ENGINE's answer about this peer, passed in rather
        than looked up, so this module needs nothing from the engine and stays
        importable by both clients.

        Fails closed on both inputs: an unknown peer with `encrypted=True` is
        refused, and so is a known-OTR peer with `encrypted=False`.
        """
        return not encrypted and not self.is_otr(peer)

    def peers(self) -> Set[str]:
        """The conversations currently in OTR mode. A copy."""
        return set(self._otr)
