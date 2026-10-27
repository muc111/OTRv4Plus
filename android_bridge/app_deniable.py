# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's end-of-session revelation (L1, SPEC §5.8).

A mixin of OtrApp (app.py). The keys themselves are retired and wiped in the
Rust ratchet; what reaches this module is only the closing messages the
engine built -- wire text whose `revealed_mac_keys` field is meant to be
public. They are sent wherever a session ends: Make Chat Deniable, the peer
ending it, sign-out, Wipe & Exit, quit. Without a network they are kept, in
memory only, and sent when it is back (up to CLOSING_MAX_TRIES sends); if
the process ends first they are lost, and nothing secret with them: the
keys are already retired.
"""
from __future__ import annotations

import threading
import time

from .events import ErrorOccurred, KeysPublished, SessionStateChanged
from .trace import TRACE as _TRACE

#: Sent inside the session just before "End chat & publish keys" closes it,
#: so the contact's app knows the person pressed it (a session also ends at
#: sign-out or quit, and that clears nothing). A group-setup verb: an app or
#: terminal that does not know it drops it silently (`SecureGroups.on_signal`
#: counts it as malformed), and never shows it.
KEYS_PUBLISHED_SIGNAL = "?OTRv4-MLS:PUBLISHED:"


class DeniableMixin:
    """Closing messages, and the Make Chat Deniable action. Mixed into OtrApp."""

    #: Closing messages kept until the server confirms them (bounded), in
    #: memory only: never written to disk, where one would record whom a
    #: chat was made deniable with (TestCrashDuringClose).
    MAX_UNCONFIRMED_CLOSINGS = 256
    #: How often `resend_unconfirmed_closings` tries, and how many times.
    CLOSING_RETRY_SECONDS = 30.0
    CLOSING_MAX_TRIES = 40

    _closing_lock = threading.Lock()

    def _key_marks(self) -> dict:
        """peer -> [before_ms, by, state] for a chat whose keys someone chose
        to publish: "open" until the session it came over has ended (the
        contact's side), then "confirm" until our closing messages for it are
        confirmed by our server, when KeysPublished goes to the app."""
        book = getattr(self, "_published_marks", None)
        if book is None:
            book = self._published_marks = {}
        return book

    def on_keys_published_signal(self, peer: str) -> None:
        """The contact pressed "End chat & publish keys": what we have of
        this chat until now goes once our own keys for it are published and
        confirmed (our app publishes them as the session ends)."""
        if not self._engine.has_encrypted_session(peer):
            return                              # only from inside the session
        self._key_marks()[peer] = [int(time.time() * 1000), peer, "open"]
        _TRACE.record("otr", "keys_published_signal", "info")

    def _advance_marks(self, closed: set) -> None:
        """After the closing messages of [closed] peers were taken: a marked
        chat whose session has now ended waits for their confirmation, or,
        with nothing of ours to publish, is done."""
        done = []
        for peer, mark in list(self._key_marks().items()):
            if mark[2] != "open":
                continue
            if peer in closed:
                mark[2] = "confirm"
            elif not self._engine.has_encrypted_session(peer):
                done.append(peer)
        for peer in done:
            self._marks_done(peer)

    def _marks_done(self, peer: str) -> None:
        mark = self._key_marks().pop(peer, None)
        if mark is not None:
            self._emit(KeysPublished(peer=peer, before_ms=mark[0], group=False, by=mark[1]))

    def _closings(self) -> list:
        book = getattr(self, "_unconfirmed_closings", None)
        if book is None:
            book = self._unconfirmed_closings = []
        return book

    def _send_final_revelations(self) -> int:
        """Send every closing message the engine holds. Returns how many
        went. Never raises: this runs on teardown and inbound paths.

        Each is also kept -- `[peer, wire, sent, tries]` -- until the server
        confirms it (`confirm_closings`), so one sent while offline, or to a
        peer with no capable resource yet, or lost on the way, goes again
        (`resend_unconfirmed_closings`). They hold nothing secret: the
        revealed keys are meant to be public, the rest is ciphertext."""
        take = getattr(self._engine, "take_final_revelations", None)
        if take is None:
            return 0
        try:
            waiting = take()
        except Exception:
            return 0
        book = self._closings()
        sent = 0
        entries = [[peer, wire, False, 0] for peer, wire in waiting]
        with self._closing_lock:
            book.extend(entries)
            del book[:max(0, len(book) - self.MAX_UNCONFIRMED_CLOSINGS)]
        for entry in entries:
            if self._send_closing(entry):
                sent += 1
        if waiting:
            _TRACE.record("otr", "final_revelation", "info", messages=len(waiting), sent=sent)
        if self._key_marks():
            self._advance_marks({peer for peer, _ in waiting})
        return sent

    def _send_closing(self, entry) -> bool:
        transport = self._transport
        if transport is None or not getattr(transport, "is_connected", True):
            return False                    # offline: kept (in memory), sent when back
        entry[3] += 1
        try:
            transport.send(entry[0], entry[1])
        except Exception:
            return False
        entry[2] = True
        if len(entry) > 4:
            # The "keys published" message: once is enough (the server's
            # confirmation of the closing messages after it covers it), and a
            # second copy, from a session the contact has closed, makes their
            # app start a new one.
            with self._closing_lock:
                book = self._closings()
                if entry in book:
                    book.remove(entry)
        return True

    def confirm_closings(self) -> bool:
        """Whether every closing message sent so far is confirmed received
        by our server (`XmppTransport.confirm_received`); the confirmed ones
        are then forgotten. True when none is waiting."""
        book = self._closings()
        with self._closing_lock:
            if not book:
                return True
            sent = [e for e in book if e[2]]
        confirm = getattr(self._transport, "confirm_received", None)
        if confirm is None or not sent:
            return False
        try:
            ok = bool(confirm())
        except Exception:
            ok = False
        with self._closing_lock:
            if ok:
                for e in sent:
                    if e in book:
                        book.remove(e)
            left = bool(book)
            waiting_for = {e[0] for e in book}
        if ok:
            _TRACE.record("otr", "closing_confirmed", "info", messages=len(sent))
            for peer, mark in list(self._key_marks().items()):
                if mark[2] == "confirm" and peer not in waiting_for:
                    self._marks_done(peer)
        return ok and not left

    def resend_unconfirmed_closings(self) -> None:
        """Closing messages the server has not confirmed: sent again and
        confirmed, in the background (the UI's event tick calls this and
        must not wait on a round trip). Every CLOSING_RETRY_SECONDS at most;
        a message is given up after CLOSING_MAX_TRIES sends."""
        book = self._closings()
        if not book or getattr(self, "_wiped", False):
            return
        now = time.monotonic()
        if now - getattr(self, "_closing_retry_at", -1e9) < self.CLOSING_RETRY_SECONDS:
            return
        if getattr(self, "_closing_retry_busy", False):
            return
        self._closing_retry_at = now
        self._closing_retry_busy = True

        def run():
            try:
                self._resend_closings_now()
            finally:
                self._closing_retry_busy = False

        threading.Thread(target=run, name="otr-closing-retry", daemon=True).start()

    def _resend_closings_now(self) -> bool:
        """One round of `resend_unconfirmed_closings`, on this thread."""
        book = self._closings()
        with self._closing_lock:
            entries = list(book)
            for entry in entries:
                if entry[3] >= self.CLOSING_MAX_TRIES:
                    book.remove(entry)
                    _TRACE.record("otr", "closing_abandoned", "warning", jid=entry[0])
        for entry in entries:
            if entry in book:
                self._send_closing(entry)
        return self.confirm_closings()

    def make_chat_deniable(self, peer: str, restart: bool = True) -> str:
        """"Make Chat Deniable" for [peer]: every MAC key of the session is
        published, the peer is told it has ended, the session is forgotten
        and, with [restart], a fresh one is started that shares no key with
        the old one.

        The new session starts after our server has been asked to confirm
        the closing messages that publish the keys (`confirm_closings`),
        whatever it answers. Returns "made_deniable" (confirmed),
        "made_deniable_unconfirmed" (the session is closed and its keys are
        retired, but the server did not confirm in time: the closing messages
        are kept in memory and sent again, up to CLOSING_MAX_TRIES times),
        or "no_session"."""
        peer = self.canonical_peer(peer)
        before = self.security_state(peer)
        # Tell the contact's app first, inside the session: its copy of this
        # chat goes too, once its keys are published (KEYS_PUBLISHED_SIGNAL).
        # Encrypted now, while the session is up, and kept with the closing
        # messages, ahead of them: offline, it waits and goes with them.
        marker = None
        try:
            if self._engine.has_encrypted_session(peer):
                frame, ok = self._engine.handle_outgoing_message(peer, KEYS_PUBLISHED_SIGNAL)
                if ok and frame:
                    marker = frame if isinstance(frame, str) else frame.decode("utf-8")
        except Exception:
            _TRACE.record("otr", "keys_published_signal_not_sent", "warning")
        pressed = [int(time.time() * 1000), "", "confirm"]
        try:
            done = bool(self._engine.make_deniable(peer))
        except Exception as exc:
            _TRACE.record_exception("otr", "make_deniable_failed", exc, jid=peer)
            done = False
        if not done:
            return "no_session"
        self._key_marks()[peer] = pressed
        if marker:
            entry = [peer, marker, False, 0, "keys_published"]
            with self._closing_lock:
                self._closings().append(entry)
            self._send_closing(entry)
        self._send_final_revelations()
        confirmed = self.confirm_closings()
        if confirmed and peer in self._key_marks():
            self._marks_done(peer)              # nothing of ours left unconfirmed
        _TRACE.record("otr", "made_deniable", "info", jid=peer, confirmed=confirmed)
        after = self.security_state(peer)
        if after != before:
            self._emit(SessionStateChanged(peer=peer, security=after))
        if restart:
            try:
                self.ensure_otr(peer)
            except Exception:
                self._emit(ErrorOccurred(peer=peer, code="dake_generate_failed"))
        return "made_deniable" if confirmed else "made_deniable_unconfirmed"
