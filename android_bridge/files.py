# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Android half of a file transfer. None of the transfer logic lives here.

WHAT WAS ALREADY BUILT
======================
All of it. `otrv4plus_filetransfer` holds the FileKey, the AEAD, the chunk
format, the hashes, the offer/accept semantics, filename sanitising, the
temporary-file lifecycle and the atomic commit -- and the SMP gate, on BOTH
sides: `offer_file` refuses to send to an unverified peer and `on_offer`
refuses to receive from one. It is packaged into the APK.

What did not exist was any way for Android to reach it, and an inbound
defect that came with that. Measured through two real bridges with a live
OTR session, the peer sending one control message:

    file signalling returned as a displayable body: True
      returned: '?OTRv4-FILE:OFFER:deadbeef|secret.pdf|1024'

-- handed to the UI as a chat message. Worse for DATA: every chunk is
base64 of a sealed chunk, so a transfer would have rendered as hundreds of
walls of base64 in the conversation.

ONE GATE, ONE DEFINITION OF VERIFIED
====================================
`otrv4plus_xmpp._file_peer_verified` reads the VOICE manager's
`_smp_verified` and says why: "Reads the voice manager's `_smp_verified`,
which consults only the engine's published predicates -- not display state,
not a trust pin, not the blue OTRv4+ marker. One gate, one definition of
verified." This does the same, through `CallBridge`, so Android has one
verification predicate rather than a second one that could drift.

SAF, NOT THE TERMUX PICKER
==========================
`otrv4plus_filetransfer.pick_file` shells out to a Termux file picker. That
is the right answer on Termux and the wrong one in an APK, so it is never
called here: Android picks through the Storage Access Framework, in Kotlin,
and hands down a path it has already resolved. The engine takes a path and
does not care who chose it.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Optional

from .events import ErrorOccurred, Event

__all__ = ["FileBridge", "FileOutcome", "is_file_signal"]


class FileOutcome:
    """What a transfer request did, as a stable code for Kotlin.

    Codes, never sentences, and never engine exception text -- the same rule
    the roster and call results follow.
    """

    #: Handed to the transfer engine. NOT "the file arrived".
    STARTED = "started"
    #: The peer's identity is not SMP-verified. The gate, reported honestly.
    UNVERIFIED = "unverified"
    #: No OTR session that can key a transfer. Run the handshake first.
    NO_SESSION = "no_session"
    #: The path is not a readable file, or is too large.
    BAD_FILE = "bad_file"
    #: Nothing to accept or decline under that id.
    NO_TRANSFER = "no_transfer"
    #: The transfer subsystem could not be loaded on this device.
    UNAVAILABLE = "unavailable"
    #: There is no transport, so nothing can leave the device.
    NOT_CONNECTED = "not_connected"


#: Kept identical to `otrv4plus_filetransfer.FILE_PREFIX` and asserted equal
#: by `tests/test_android_files.py`, so the two cannot drift into disagreeing
#: about what file signalling looks like.
FILE_PREFIX_FALLBACK = "?OTRv4-FILE:"


def is_file_signal(body: Any) -> bool:
    """Whether a decrypted body is file signalling rather than a message.

    Reads the prefix from `otrv4plus_filetransfer` once it is imported and
    falls back to the constant before that, so this never becomes a second
    definition of the wire format.
    """
    if not isinstance(body, str):
        return False
    import sys
    module = sys.modules.get("otrv4plus_filetransfer")
    prefix = getattr(module, "FILE_PREFIX", None) if module else None
    return body.startswith(prefix or FILE_PREFIX_FALLBACK)


class FileBridge:
    """One transfer manager for one `OtrApp`, built on first use."""

    def __init__(self, app):
        self._app = app
        self._lock = threading.RLock()
        self._manager = None
        self._pumps = []

    # -- construction ---------------------------------------------------------

    def _ensure_manager(self):
        """The transfer manager, built on first use, or None.

        Returns None rather than raising: "this build cannot do file
        transfer" is an answer the UI renders, not an exception to surface as
        a crash.
        """
        with self._lock:
            if self._manager is not None:
                return self._manager
            try:
                # Inside the function, like the voice import and for the same
                # reason: `otrv4plus_filetransfer` pulls in the Rust core, and
                # a settings screen has no business loading it.
                import otrv4plus_filetransfer as ft
            except Exception:
                return None
            try:
                self._manager = ft.FileTransferManager(
                    transport=ft.OtrChunkTransport(self._send_signal),
                    notify=self._notify,
                    verified=self._verified,
                    spawn=self._spawn,
                )
            except Exception:
                # The engine refuses to construct without `otrv4_core`, and
                # says so rather than offering a Python fallback. Honoured
                # here: no manager means no transfers, not a weaker one.
                return None
            return self._manager

    # -- what the engine needs from us ----------------------------------------

    def _send_signal(self, peer: str, verb: str, payload: str) -> bool:
        """One control message inside the OTR channel.

        The only thing tying the transfer engine to a transport. An offer or
        a chunk sent in the clear would tell the server who is sending what
        to whom and let an off-session party inject a transfer, so this
        refuses rather than downgrading: if the engine will not encrypt it,
        it does not go.
        """
        import otrv4plus_filetransfer as ft
        body = ft.FILE_PREFIX + verb + ((":" + payload) if payload else "")
        try:
            frame, should_send = self._app._engine.handle_outgoing_message(
                peer, body)
        except Exception:
            return False
        if not (should_send and frame):
            return False
        try:
            self._app._send_protocol(peer, frame)
        except Exception:
            return False
        return True

    def _verified(self, peer: str) -> bool:
        """The gate, read from the ONE place Android defines it.

        `otrv4plus_xmpp._file_peer_verified` reads the voice manager's
        `_smp_verified` for exactly this reason -- "One gate, one definition
        of verified" -- and this does the same through `CallBridge`. A second
        predicate here could drift from the one voice uses, and then a peer
        could be callable but not sendable, or worse the other way round.

        FAILS CLOSED. Anything that cannot be answered is not verified.
        """
        try:
            manager = self._app.calls._ensure_manager()
            if manager is None:
                return False
            return bool(manager._smp_verified(peer))
        except Exception:
            return False

    def _notify(self, text: str) -> None:
        """Where the engine's progress lines go.

        Swallowed rather than emitted as events, deliberately. These are
        sentences written for a terminal -- they name files and embed
        transfer ids -- and the Android UI renders structured state from
        `transfers()` instead. Routing them to a screen would be putting
        engine text in front of a user, which this bridge does not do.
        """
        return None

    def _spawn(self, transfer) -> None:
        """Send the file on a thread of its own.

        NOT INLINE, and the engine's own docstring says why: `on_accept` is
        reached from inside the inbound message handler, so pumping 300 KB
        there blocks the loop -- "keepalives stop, the stream is declared
        dead, and the transfer takes the connection down with it. Found on a
        device, not by reading."
        """
        manager = self._manager
        if manager is None:
            return
        thread = threading.Thread(
            target=lambda: self._pump(manager, transfer),
            name="otrv4plus-file-send", daemon=True)
        with self._lock:
            self._pumps.append(thread)
        thread.start()

    @staticmethod
    def _pump(manager, transfer) -> None:
        try:
            manager._pump(transfer)
        except Exception:
            # The engine reports its own failures through `notify` and marks
            # the transfer. A raise here would only kill a daemon thread.
            pass

    # -- the actions ----------------------------------------------------------

    def send_file(self, peer: str, path: str) -> str:
        """Offer [path] to [peer]. Returns a `FileOutcome` code.

        Every refusal that matters is the ENGINE's: `offer_file` checks the
        SMP gate first, then that the path is a readable file within the size
        limit. The codes below distinguish them for the UI without deciding
        any of them here.
        """
        manager = self._ensure_manager()
        if manager is None:
            return FileOutcome.UNAVAILABLE
        if self._app._transport is None:
            return FileOutcome.NOT_CONNECTED
        ratchet = self._ratchet(peer)
        if ratchet is None:
            return FileOutcome.NO_SESSION
        try:
            manager.offer_file(peer, path, ratchet)
        except Exception as exc:
            return self._classify(peer, exc, path)
        return FileOutcome.STARTED

    def accept(self, transfer_id: str) -> str:
        """Accept an offered transfer, by the id the UI was given."""
        manager = self._ensure_manager()
        if manager is None:
            return FileOutcome.UNAVAILABLE
        transfer = self._incoming(transfer_id)
        if transfer is None:
            return FileOutcome.NO_TRANSFER
        ratchet = self._ratchet(transfer.peer)
        if ratchet is None:
            return FileOutcome.NO_SESSION
        try:
            manager.accept(transfer.offer.transfer_id, ratchet)
        except Exception as exc:
            return self._classify(transfer.peer, exc, "")
        return FileOutcome.STARTED

    def decline(self, transfer_id: str) -> str:
        """Decline an offered transfer."""
        manager = self._ensure_manager()
        if manager is None:
            return FileOutcome.UNAVAILABLE
        transfer = self._incoming(transfer_id)
        if transfer is None:
            return FileOutcome.NO_TRANSFER
        try:
            manager.decline(transfer.offer.transfer_id)
        except Exception:
            return FileOutcome.NO_TRANSFER
        return FileOutcome.STARTED

    # -- inbound --------------------------------------------------------------

    def handle_signal(self, peer: str, body: str) -> bool:
        """Route one decrypted file control message. True if it was one.

        Returning True is what keeps signalling OUT of the conversation.
        Before this existed a peer's `?OTRv4-FILE:OFFER:...` was handed to
        the UI as a chat message, and each DATA chunk would have been a wall
        of base64 from the user's contact.

        The engine validates everything, including refusing an offer from an
        unverified peer before a transfer exists.
        """
        if not is_file_signal(body):
            return False
        manager = self._ensure_manager()
        if manager is None:
            # Transfers cannot run here. Still not a message: displaying it
            # would put protocol text in the conversation.
            return True
        try:
            manager.handle_control(peer, body)
        except Exception:
            self._app._emit(ErrorOccurred(peer=peer, code="file_signal_failed"))
        return True

    # -- what the UI reads ----------------------------------------------------

    def transfers(self) -> list:
        """Every live transfer, as plain dicts.

        STRUCTURED, never the engine's progress sentences: those are written
        for a terminal and embed transfer ids and filenames. The filename is
        passed through `sanitise_filename`, which is the engine's own rule
        for what a peer-chosen name may contain -- a name arrives from
        somebody else and is about to be rendered.
        """
        manager = self._manager
        if manager is None:
            return []
        import otrv4plus_filetransfer as ft
        rows = []
        for key, transfer in list(getattr(manager, "outgoing", {}).items()):
            rows.append(self._row(ft, key, transfer, outgoing=True))
        for key, transfer in list(getattr(manager, "incoming", {}).items()):
            rows.append(self._row(ft, key, transfer, outgoing=False))
        return rows

    @staticmethod
    def _row(ft, key, transfer, outgoing: bool) -> dict:
        offer = transfer.offer
        return {
            "id": str(key),
            "peer": str(transfer.peer),
            "filename": ft.sanitise_filename(getattr(offer, "filename", "")),
            "size": int(getattr(offer, "plaintext_size", 0) or 0),
            "outgoing": bool(outgoing),
            "accepted": bool(getattr(transfer, "accepted", False)),
            "cancelled": bool(getattr(transfer, "cancelled", False)),
            "progress": float(getattr(transfer, "progress", 0.0) or 0.0),
        }

    def received_dir(self) -> str:
        """Where a FINISHED file lands. The engine's own answer.

        `state_dir`, NOT `incoming_dir`. They are two directories and the
        engine keeps them apart on purpose: `incoming_dir` is "where partial
        work lives ... separate from the finished directory so a partial file
        can never be mistaken for a complete one". Pointing the user at it
        would be pointing them at exactly the files that are not theirs yet.

        The finished directory is application-private and 0700 -- a received
        file is the output of an authenticated private session and is not
        dropped into a shared Downloads folder.
        """
        try:
            import otrv4plus_filetransfer as ft
            return str(ft.state_dir())
        except Exception:
            return ""

    # -- teardown -------------------------------------------------------------

    def shutdown(self) -> None:
        """Forget every transfer. Safe to call more than once.

        In-memory only: the engine writes a received file to a temporary
        path and commits it atomically, so an abandoned transfer leaves a
        temporary file the engine owns rather than a half-file in the user's
        storage. What goes here is the state belonging to the account that
        is signing out.
        """
        with self._lock:
            manager, self._manager = self._manager, None
            self._pumps = []
        if manager is None:
            return
        for attribute in ("outgoing", "incoming", "_abandoned"):
            try:
                getattr(manager, attribute).clear()
            except Exception:
                pass

    # -- internals ------------------------------------------------------------

    def _ratchet(self, peer: str):
        """The peer's live ratchet, or None.

        The transfer key is derived from it INSIDE Rust; Python passes the
        handle along and never sees anything derived from it. Copied in shape
        from `otrv4plus_xmpp._file_transfer_ratchet` because it is the same
        question with the same answer.
        """
        try:
            session = self._app._engine.get_session(peer)
            ratchet = getattr(session, "ratchet", None)
            rust = getattr(ratchet, "_rust", None)
            if rust is None or not rust.supports_file_transfer:
                return None
            return rust
        except Exception:
            return None

    def _incoming(self, transfer_id: str):
        manager = self._manager
        if manager is None:
            return None
        return getattr(manager, "incoming", {}).get(str(transfer_id))

    @staticmethod
    def _classify(peer: str, exc: Exception, path: str) -> str:
        """Turn the engine's refusal into a code, WITHOUT echoing its text.

        `TransferError` messages are written for a person and name the file,
        so they are read here and discarded -- what crosses to Kotlin is one
        of a fixed set of codes. The UI writes its own sentences.
        """
        text = str(exc)
        if "SMP verification is required" in text:
            return FileOutcome.UNVERIFIED
        if "no such file" in text or "larger than" in text:
            return FileOutcome.BAD_FILE
        if path and not os.path.isfile(os.path.expanduser(path)):
            return FileOutcome.BAD_FILE
        return FileOutcome.NO_TRANSFER
