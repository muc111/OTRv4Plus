# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's end-of-session revelation (L1, SPEC §5.8).

A mixin of OtrApp (app.py). The keys themselves are retired and wiped in the
Rust ratchet; what reaches this module is only the closing messages the
engine built -- wire text whose `revealed_mac_keys` field is meant to be
public. They are sent wherever a session ends: Make Chat Deniable, the peer
ending it, sign-out, Wipe & Exit, quit. Without a network they are dropped,
and nothing secret is lost with them: the keys are already retired.
"""
from __future__ import annotations

from .events import ErrorOccurred, SessionStateChanged
from .trace import TRACE as _TRACE


class DeniableMixin:
    """Closing messages, and the Make Chat Deniable action. Mixed into OtrApp."""

    def _send_final_revelations(self) -> int:
        """Send every closing message the engine holds. Returns how many
        went. Never raises: this runs on teardown and inbound paths."""
        take = getattr(self._engine, "take_final_revelations", None)
        if take is None:
            return 0
        try:
            waiting = take()
        except Exception:
            return 0
        transport = self._transport
        sent = 0
        for peer, wire in waiting:
            if transport is None or not getattr(transport, "is_connected", True):
                continue                    # offline: published nowhere, retired anyway
            try:
                transport.send(peer, wire)
                sent += 1
            except Exception:
                pass
        if waiting:
            _TRACE.record("otr", "final_revelation", "info", messages=len(waiting), sent=sent)
        return sent

    def make_chat_deniable(self, peer: str, restart: bool = True) -> str:
        """"Make Chat Deniable" for [peer]: every MAC key of the session is
        published, the peer is told it has ended, the session is forgotten
        and, with [restart], a fresh one is started -- with no cryptographic
        link to the transcript that is now forgeable by anyone.
        Returns "made_deniable", or "no_session"."""
        peer = self.canonical_peer(peer)
        before = self.security_state(peer)
        try:
            done = bool(self._engine.make_deniable(peer))
        except Exception as exc:
            _TRACE.record_exception("otr", "make_deniable_failed", exc, jid=peer)
            done = False
        if not done:
            return "no_session"
        self._send_final_revelations()
        after = self.security_state(peer)
        if after != before:
            self._emit(SessionStateChanged(peer=peer, security=after))
        if restart:
            try:
                self.ensure_otr(peer)
            except Exception:
                self._emit(ErrorOccurred(peer=peer, code="dake_generate_failed"))
        return "made_deniable"
