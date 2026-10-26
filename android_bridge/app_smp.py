# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's identity verification: SMP (start, answer, abort), and what a
changed fingerprint means.

A mixin of OtrApp (app.py). The protocol is the engine's and the Rust
core's; this is the app-facing surface and its events."""
from __future__ import annotations

from .app_base import BridgeError, _log
from .events import (ErrorOccurred, FingerprintChanged, SecurityState,
                     SmpResult, SmpState)
from .trace import TRACE as _TRACE


class SmpMixin:
    """SMP and fingerprints. Mixed into OtrApp."""

    def _announce_smp_change(self, peer: str, before: SmpState) -> None:
        """Emit an event when an inbound frame moved this peer's verification
        state.

        Needed because an SMP1 on an already-encrypted session does not change the
        security level, so no `SessionStateChanged` would announce it. Emitted only
        on a real transition: a resent SMP1 must not stack prompts. This reports the
        state only; the UI asks for the secret in its own dialog (see
        `smp_respond`).
        """
        after = self.smp_state(peer)
        if after == before:
            return
        if after in (SmpState.VERIFIED, SmpState.FAILED, SmpState.CANCELLED):
            self._emit(SmpResult(peer=peer, state=after))
            if after is SmpState.VERIFIED and self._groups is not None:
                # Verified now: the groups we share with them learn it, and
                # each side sends its group key (calls need verified members).
                try:
                    self._groups.on_peer_verified(peer)
                except Exception:
                    _log.warning("group verification update failed")
        else:
            self._emit(self.smp_progress(peer))

    def _send_protocol(self, peer: str, payload) -> None:
        """Put the engine's protocol response back on the wire.

        Fragmented by the transport, which is what makes an 11.7 KB DAKE2
        survive the I2P size cliff. Failures are reported as an error event
        rather than raised: this runs on the transport's own inbound path, and
        an exception there would take down the callback that delivers every
        other message.
        """
        if self._transport is None:
            self._emit(ErrorOccurred(peer=peer, code="no_transport"))
            return
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        try:
            self._transport.send(peer, text)
        except Exception:
            # The handshake cannot continue, and saying nothing would leave
            # the UI showing a session that is quietly stuck.
            self._emit(ErrorOccurred(peer=peer, code="protocol_send_failed"))

    # -- verification ----------------------------------------------------------

    #: The engine's own rule, restated at this boundary rather than guessed.
    #: `EnhancedOTRSession.set_smp_secret` raises below 8, and `otrv4+.py`
    #: defines both constants; the cap keeps an unbounded UI field from
    #: reaching the Argon2id stretch.
    SMP_MIN_LEN = 8
    SMP_MAX_LEN = 512

    def _require_encrypted(self, peer: str, code: str) -> None:
        """Refuse an SMP operation on a conversation that is not encrypted.

        SMP proves you are talking to who you think you are. Running it
        outside an established session would prove it about nothing -- there
        is no session binding to tie the proof to -- so this is a
        precondition, not a nicety.

        PLAINTEXT is the only refusal. ENCRYPTED, FINGERPRINT and SMP_VERIFIED
        all mean a DAKE completed. FINGERPRINT_MISMATCH is deliberately NOT
        refused here: that conversation IS encrypted, to somebody, and running
        SMP is one of the few things that can tell the user WHICH somebody.
        """
        if self.security_state(peer) is SecurityState.PLAINTEXT:
            self._emit(ErrorOccurred(peer=peer, code=code))
            raise BridgeError(code, "there is no encrypted session to verify")

    def smp_start(self, peer: str, secret: str, question: str = "") -> None:
        """Begin SMP.  `secret` is passed straight through and never retained.

        THE PASSPHRASE DOES NOT STOP HERE. It goes to the engine, which copies
        it into a Rust-owned zeroizing buffer (`RustSMPVault`) and derives
        from it there. This method holds a reference for the length of one
        call and drops it; nothing on this object stores it, no event carries
        it, and `redacting_logger` is not given it.
        """
        peer = self.canonical_peer(peer)
        self._refuse_room(peer, 'room_not_verifiable')
        self._require_encrypted(peer, "smp_not_encrypted")
        try:
            payload = self._engine.start_smp(peer, secret, question)
        except Exception as exc:
            code = self._smp_start_refusal(exc)
            self._emit(ErrorOccurred(peer=peer, code=code))
            raise BridgeError(code)
        finally:
            del secret
        if not payload:
            # The engine produced no SMP1. Saying nothing would leave the UI
            # showing a verification that never started -- the same silence
            # that made `start_session` look like it worked.
            self._emit(ErrorOccurred(peer=peer, code="smp_not_produced"))
            raise BridgeError("smp_not_produced",
                              "the verification request could not be built")
        try:
            self._send_protocol_or_raise(peer, payload, "smp_send_failed")
        except BridgeError:
            self._emit(self.smp_progress(peer))
            raise
        self._emit(self.smp_progress(peer))

    @staticmethod
    def _smp_start_refusal(exc: BaseException) -> str:
        """Name why the engine would not start a run (cooldown, attempts used
        up, ...), so the UI can say "wait" instead of "failed". The engine's
        text is matched here and never shown: only the code leaves."""
        text = str(exc)
        if "cooldown" in text:
            return "smp_cooldown"
        if "max attempt limit" in text:
            return "smp_attempts_exhausted"
        if "already verified" in text:
            return "smp_already_verified"
        if "already in progress" in text:
            return "smp_in_progress"
        return "smp_start_failed"

    def smp_respond(self, peer: str, secret: str) -> None:
        """Answer a peer's verification challenge: set the secret, resume the
        SMP1 the core is holding (`resume_held_smp1`) and send the resulting SMP2.

        Safe under INV-06 (docs/SECURITY_INVARIANTS.md: a peer may cause the client to
        ASK for the secret, never cause the next thing typed to BECOME it). Here
        that separation is structural: this is reached only from a dialog with its
        own secret field, while chat text goes to `send_user_text`.
        """
        peer = self.canonical_peer(peer)
        self._refuse_room(peer, 'room_not_verifiable')
        self._require_encrypted(peer, "smp_not_encrypted")
        if not self.smp_secret_required(peer):
            # Nothing is being asked. Storing a passphrase here would leave a
            # secret bound to a session with no run to spend it on, and the
            # user would be told they had answered a request that does not
            # exist.
            raise BridgeError("smp_not_requested",
                              "there is no verification request to answer")
        try:
            # `bind_smp_secret`, NOT `set_smp_secret`: the latter is the
            # terminal auto-respond setter, which persists the secret and
            # re-binds it into later sessions so the NEXT challenge is
            # answered without asking anyone.
            self._engine.bind_smp_secret(peer, secret)
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="smp_respond_failed"))
            raise BridgeError("smp_respond_failed")
        finally:
            del secret

        resume = getattr(self._engine, "resume_held_smp1", None)
        if resume is None:
            self._emit(ErrorOccurred(peer=peer, code="smp_resume_unsupported"))
            raise BridgeError("smp_resume_unsupported")
        try:
            smp2 = resume(peer)
        except Exception:
            # NOT SmpState.FAILED, and the terminal client makes the same
            # point: no proof was attempted, so this is not an SMP failure and
            # must not be shown as one.
            self._emit(ErrorOccurred(peer=peer, code="smp_resume_failed"))
            raise BridgeError("smp_resume_failed")
        if not smp2:
            self._emit(ErrorOccurred(peer=peer, code="smp_held_request_gone"))
            raise BridgeError("smp_held_request_gone",
                              "the verification request is no longer waiting")

        self._send_protocol_or_raise(peer, smp2, "smp_send_failed")
        self._emit(self.smp_progress(peer))

    def _send_protocol_or_raise(self, peer: str, payload, code: str) -> None:
        """Send an SMP frame, or fail loudly.

        `_send_protocol` swallows a send failure into an error event, which is
        right on the INBOUND path -- an exception there would take down the
        callback that delivers every other message. It is wrong here: these
        calls are driven by a user pressing Verify, and a proof that never
        left the socket is not a stage that completed.
        """
        if self._transport is None:
            self._emit(ErrorOccurred(peer=peer, code="no_transport"))
            raise BridgeError("no_transport")
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        try:
            self._transport.send(peer, text)
        except Exception as exc:
            _TRACE.record_exception("smp", code, exc, jid=peer)
            self._emit(ErrorOccurred(peer=peer, code=code))
            raise BridgeError(code, "the verification message could not be sent")

    def smp_abort(self, peer: str) -> None:
        peer = self.canonical_peer(peer)
        abort = getattr(self._engine, "abort_smp", None)
        if abort is None:
            raise BridgeError("smp_abort_unsupported")
        payload = self._safe(lambda: abort(peer))
        # Tell the peer. Without the SMP_ABORT their side waits out its own
        # timeout, still showing a verification in progress.
        if isinstance(payload, (str, bytes, bytearray)) and payload:
            self._send_protocol(peer, payload)
        self._emit(SmpResult(peer=peer, state=self.smp_state(peer)))

    def note_fingerprint_mismatch(self, peer: str, stored: str, received: str) -> None:
        """Raised by the engine as TrustDatabase.FingerprintMismatch.

        Surfaced as its own event because the UI must block on it rather than
        fold it into the ordinary security state.
        """
        peer = self.canonical_peer(peer)
        self._emit(FingerprintChanged(peer=peer, stored_fingerprint=stored,
                                      received_fingerprint=received))

    def trust_peer(self, peer: str, fingerprint: str) -> bool:
        peer = self.canonical_peer(peer)
        return bool(self._safe(lambda: self._engine.trust_fingerprint(peer, fingerprint),
                               default=False))

    def reset_trust(self, peer: str) -> bool:
        """Forget the contact's pinned fingerprint and post-quantum key, so
        the next handshake pins what it sees: the deliberate way past a
        `pq_downgrade` / `pq_key_changed` refusal (A2). The user is asked
        first, on the screen, to check with the contact in person."""
        peer = self.canonical_peer(peer)
        return bool(self._safe(lambda: self._engine.trust_db.remove_trust(peer),
                               default=False))

    # -- identity --------------------------------------------------------------

    def note_signed_in(self, account: str) -> None:
        """U1: the server accepted the login for [account]. Called by the
        connection controller only after authentication, never on an
        attempt."""
        if account and "@" in account and not getattr(self, "_wiped", False):
            self._signed_in = True

    def bind_identity_account(self, account: str) -> bool:
        """F2: the identity is the ACCOUNT's, not the process's.

        Called when a connection (sign-in or account creation) is prepared for
        [account], before anything is sent. The first account in this process
        takes the identity generated at start-up, which nobody has seen yet;
        a different account afterwards gets a new one
        (`EnhancedSessionManager.rotate_identity`) -- the old key wiped in
        Rust, its sessions ended -- so no two accounts ever present the same
        long-term key. The same account again keeps it. Returns whether the
        identity was rotated."""
        bare = str(account or "").split("/", 1)[0].strip().lower()
        if "@" not in bare or getattr(self, "_wiped", False):
            return False
        current = getattr(self, "_identity_account", None)
        if current == bare:
            return False
        rotated = False
        if current is not None:
            self._signed_in = False
            self._engine.rotate_identity("account changed")
            rotated = True
        self._identity_account = bare
        return rotated

    def note_signed_out(self) -> None:
        """U1: no authenticated session any more (disconnect, sign-out)."""
        self._signed_in = False

    @property
    def signed_in(self) -> bool:
        return bool(getattr(self, "_signed_in", False))

    def local_fingerprint(self) -> str:
        """This device's identity fingerprint -- but only while signed in
        (U1). Signed out, it is "" on every path: the About screen, the
        desktop host's start-up message, security details. A fingerprint is
        device-binding material: one read before login could later be
        matched to the server's record of a login from this device."""
        if not self.signed_in:
            return ""
        return self._safe(self._engine.get_fingerprint, default="")
