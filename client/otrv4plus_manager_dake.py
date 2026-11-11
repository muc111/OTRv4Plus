# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The session manager's side of the DAKE (the OTRv4 key exchange).

`EnhancedSessionManager` (otrv4+.py) is built from this mixin. The DAKE's
cryptography -- the X448 / ML-KEM exchange, the ring signature, the ML-DSA
identity signature and every key it produces -- runs in the Rust core
(`RustDAKE`, through `RustDAKEAdapter`). What is here is what Python still
decides: which DAKE message is answered in which state (glare, a restarted
peer, a stale handshake), when a peer is refused (`_refused_old_protocol`,
`_refused_pq_identity`, both the manager's), and when a session becomes
ENCRYPTED.

Moved out of otrv4+.py unchanged (2026-11-11), so a reviewer can read the
handshake on its own.
"""
import secrets
from typing import Optional

from otrv4plus_states import DAKEState, SessionState, StateMachineError, UIConstants
from otrv4plus_tlv import _safe_b64decode


class ManagerDakeMixin:
    """DAKE handling for EnhancedSessionManager, which owns the state it
    reads (`sessions`, `dake_engines`, `client_profile`, `tracer`, ...)."""

    @staticmethod
    def _dake1_key(dake1_msg: str) -> bytes:
        """What glare is decided on: the decoded DAKE1, compared as bytes."""
        try:
            return _safe_b64decode(dake1_msg[7:].strip())
        except Exception:
            return b""

    def _reset_handshake(self, peer: str, session: "EnhancedOTRSession") -> None:
        """Forget a half-finished handshake on `session`, zeroizing its engine."""
        engine = self.dake_engines.pop(peer, None)
        if engine is not None:
            try:
                engine.zeroize()
            except Exception:
                pass
        self._answering_dake1.pop(peer, None)
        session.session_state = SessionState.PLAINTEXT
        if hasattr(session, "dake_state"):
            session.dake_state = DAKEState.IDLE
        session.dake_engine = None
        self._sent_dake1.pop(peer, None)

    def _handle_dake1(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        """Answer a DAKE1 -- in every state, which is what makes recovery work.

        THE DEFECT THIS FIXES
        ---------------------
        A DAKE1 was answered only from PLAINTEXT, FAILED or FINISHED. In any
        other state it was dropped, and each of those states is one a real
        network produces (measured through two bridges, and reported from
        handsets after a VPN switch):

          * DAKE2 lost: the responder sat in DAKE_IN_PROGRESS waiting for a
            DAKE3 that could never come, and refused the initiator's retry.
          * DAKE3 lost: the initiator was ENCRYPTED, the responder waiting.
            Neither side's retry was accepted by the other.
          * Peer restarted: every launch is a new identity, so the restarted
            peer starts from PLAINTEXT and sends DAKE1 -- to a side still
            ENCRYPTED with the old keys, which refused it for good.

        WHAT HAPPENS NOW, BY STATE
        --------------------------
          * Waiting for DAKE3 (responder): the new DAKE1 supersedes the old
            run. That run's keys are zeroized and this one is answered.
          * Waiting for DAKE2 (initiator), i.e. GLARE -- both sent DAKE1: the
            two DAKE1s are compared as bytes. The side whose own DAKE1 is
            greater keeps the initiator role and resends it; the other yields
            and answers. Both run the same comparison on the same two values,
            so exactly one yields. No JID is needed, which is why this lives
            here and not in each client.
          * ENCRYPTED: answered by a PENDING session. The live one keeps
            encrypting and decrypting until DAKE3 verifies; only then is it
            replaced, and its keys destroyed. There is no plaintext gap and a
            DAKE1 that goes nowhere changes nothing. The replacement is a new
            session: its SMP state starts unverified, so a verification never
            carries over to keys it did not check.

        The per-peer DAKE1 rate limit in `process_dake1` still applies in
        every case, so none of this makes a DAKE1 flood any cheaper to send.
        """
        if len(self.sessions) >= getattr(self, "MAX_SESSIONS", 50) and peer not in self.sessions:
            self.debug("session limit reached - dropping DAKE1")
            return None
        with self.lock:
            # Looked at before anything is changed: `get_or_create_session`
            # rewrites the role flag, and a live ENCRYPTED session's role must
            # not move because somebody sent a DAKE1.
            existing = self.sessions.get(peer)
            if existing is not None and existing.session_state.name == "ENCRYPTED":
                return self._answer_dake1_pending(peer, dake1_msg)
            if existing is not None and existing.session_state.name == "DAKE_IN_PROGRESS":
                session = existing
            else:
                session = self.get_or_create_session(peer, is_initiator=False)
            state = session.session_state.name

            if state == "DAKE_IN_PROGRESS":
                ours = self._sent_dake1.get(peer)
                if session.is_initiator and ours and peer not in self._pending_sessions:
                    if self._dake1_key(ours) > self._dake1_key(dake1_msg):
                        self.tracer.trace(peer, "DAKE", "DAKE1", "GLARE_KEEP",
                                          "keeping initiator role; resending DAKE1")
                        return ours.encode("utf-8")
                    self.tracer.trace(peer, "DAKE", "DAKE1", "GLARE_YIELD",
                                      "yielding initiator role")
                else:
                    self.tracer.trace(peer, "DAKE", "DAKE1", "RESTART",
                                      "new DAKE1 supersedes the handshake in progress")
                self._reset_handshake(peer, session)
                session.is_initiator = False
            elif state not in ("PLAINTEXT", "FAILED", "FINISHED"):
                self.tracer.trace(peer, "ERROR", "DAKE1", "REJECTED",
                                  f"session in state: {state }")
                return None

            if (
                session.dake_engine is not None
                and self._answering_dake1.get(peer) == self._dake1_key(dake1_msg)
            ):
                # Already answered. Restarting on a duplicate is what made a
                # glare resend cross two runs and leave one side stranded.
                self.tracer.trace(peer, "DAKE", "DAKE1", "DUPLICATE", "already answered")
                return None
            if (
                session.session_state.name in ("FAILED", "FINISHED")
                or session.dake_engine is not None
            ):
                self._reset_handshake(peer, session)
            self._answering_dake1[peer] = self._dake1_key(dake1_msg)
            dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=False)
            self.dake_engines[peer] = dake_engine

            # `peer`, not the default. This is the live path -- both terminal
            # clients and the Android bridge reach DAKE1 through
            # EnhancedSessionManager -- and without the key every sender
            # shared one allowance.
            success = dake_engine.process_dake1(dake1_msg, peer)
            if not success:
                return None
            if self._refused_old_protocol(peer, dake_engine):
                self.dake_engines.pop(peer, None)
                return None

            dake2 = dake_engine.generate_dake2()
            if dake2:
                self.tracer.trace(peer, "DAKE", "DAKE1_PROCESSED", "DAKE2_READY", "")
                return dake2.encode("utf-8")

            return None

    def _answer_dake1_pending(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        """Answer a DAKE1 on an ENCRYPTED session without touching it."""
        previous = self._pending_sessions.pop(peer, None)
        if previous is not None:
            try:
                previous.terminate("superseded by a newer DAKE1")
            except Exception:
                pass
        engine = self.dake_engines.pop(peer, None)
        if engine is not None:
            try:
                engine.zeroize()
            except Exception:
                pass
        pending = self._new_session(peer, is_initiator=False)
        dake_engine = pending.initialize_dake(self.client_profile, explicit_initiator=False)
        if not dake_engine.process_dake1(dake1_msg, peer) or self._refused_old_protocol(
                peer, dake_engine):
            try:
                pending.terminate("DAKE1 rejected")
            except Exception:
                pass
            return None
        dake2 = dake_engine.generate_dake2()
        if not dake2:
            return None
        self._pending_sessions[peer] = pending
        self.dake_engines[peer] = dake_engine
        self.tracer.trace(peer, "DAKE", "DAKE1_PROCESSED", "PENDING_DAKE2_READY",
                          "live session kept until the new handshake completes")
        return dake2.encode("utf-8")

    def _handle_dake2(self, peer: str, dake2_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE2 (initiator side).
        """
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_SESSION", "")
                return None
            session = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE2", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake2(dake2_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE2", "PROCESS_FAILED", "")
                    return None
                if self._refused_pq_identity(peer, dake_engine):
                    self.dake_engines.pop(peer, None)
                    return None

                dake3_msg = dake_engine.generate_dake3()
                if not dake3_msg:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "GEN_FAILED", "")
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE2", "NO_KEYS", "")
                    return None

                session.session_id = session_keys.get("session_id") or secrets.token_bytes(32)
                session.root_key = session_keys.get("root_key")
                session._dake_chain_key_send = session_keys.get("chain_key_send")
                session._dake_chain_key_recv = session_keys.get("chain_key_recv")
                session._dake_brace_key = session_keys.get("brace_key")

                session._dake_output = session_keys.get("_dake_output")

                pub_key_data = session_keys.get("peer_long_term_pub")
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data

                    session.remote_long_term_pub = None
                    self.tracer.trace(
                        peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey (bytes)"
                    )
                elif pub_key_data is not None:

                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE2→DAKE3 initiator")

                self.dake_engines.pop(peer, None)
                self._sent_dake1.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "INITIATOR_ENCRYPTED", "")
                return dake3_msg.encode("utf-8")

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE2", "EXCEPTION", str(exc))
                pass
                return None

    def _handle_dake3(self, peer: str, dake3_msg: str) -> Optional[bytes]:
        """
        Handle incoming DAKE3 (responder side).
        """
        with self.lock:
            pending = self._pending_sessions.get(peer)
            if peer not in self.sessions and pending is None:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_SESSION", "")
                return None
            session = pending if pending is not None else self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, "ERROR", "DAKE3", "NO_ENGINE", "")
                return None
            try:
                if not dake_engine.process_dake3(dake3_msg):
                    self.tracer.trace(peer, "ERROR", "DAKE3", "PROCESS_FAILED", "")
                    return None
                if self._refused_pq_identity(peer, dake_engine):
                    self.dake_engines.pop(peer, None)
                    return None

                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, "ERROR", "DAKE3", "NO_KEYS", "")
                    return None

                session.session_id = session_keys.get("session_id") or secrets.token_bytes(32)
                session.root_key = session_keys.get("root_key")
                session._dake_chain_key_send = session_keys.get("chain_key_send")
                session._dake_chain_key_recv = session_keys.get("chain_key_recv")
                session._dake_brace_key = session_keys.get("brace_key")

                session._dake_output = session_keys.get("_dake_output")

                pub_key_data = session_keys.get("peer_long_term_pub")
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data

                    session.remote_long_term_pub = None
                    self.tracer.trace(
                        peer, "KEY", "PUBKEY", "PARSED", "Successfully parsed remote pubkey (bytes)"
                    )
                elif pub_key_data is not None:

                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, "ERROR", "PUBKEY", "BYTES_FAILED", str(e))
                        session._remote_long_term_pub_bytes = None

                self._establish_session(session, peer, "DAKE3 responder")
                self._answering_dake1.pop(peer, None)

                if pending is not None:
                    # The new handshake is complete and authenticated: only
                    # now does it replace the live session, whose keys go.
                    self._pending_sessions.pop(peer, None)
                    old = self.sessions.get(peer)
                    self.sessions[peer] = pending
                    if old is not None and old is not pending:
                        try:
                            old.terminate("replaced by a completed DAKE")
                        except Exception:
                            pass
                    self.tracer.trace(peer, "DAKE", "COMPLETE", "SESSION_REPLACED", "")

                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, "DAKE", "COMPLETE", "RESPONDER_ENCRYPTED", "")
                return None

            except Exception as exc:
                self.tracer.trace(peer, "ERROR", "DAKE3", "EXCEPTION", str(exc))
                pass
                return None

    def take_pq_refusal(self, peer: str) -> Optional[str]:
        """The A2 refusal code for the last handshake with `peer`, once."""
        return self.__dict__.get("pq_refusals", {}).pop(peer, None)

    def _establish_session(self, session: "EnhancedOTRSession", peer: str, reason: str) -> None:
        """
        Drive EnhancedOTRSession from PLAINTEXT/DAKE_IN_PROGRESS → ENCRYPTED
        and initialise the double ratchet.
        """
        if session.session_state == SessionState.PLAINTEXT:
            try:
                session.transition_session(
                    SessionState.DAKE_IN_PROGRESS, f"{reason }: fast-path to DAKE_IN_PROGRESS"
                )
            except StateMachineError:
                pass

        if session.session_state == SessionState.DAKE_IN_PROGRESS:
            try:
                session.transition_session(SessionState.ENCRYPTED, reason)
            except StateMachineError as e:
                self.tracer.trace(peer, "ERROR", "ESTABLISH", "STATE_ERR", str(e))
                session.session_state = SessionState.ENCRYPTED
                session.security_level = UIConstants.SecurityLevel.ENCRYPTED
        elif session.session_state == SessionState.ENCRYPTED:
            pass
        else:
            session.session_state = SessionState.ENCRYPTED
            session.security_level = UIConstants.SecurityLevel.ENCRYPTED

        if session.ratchet is None:
            try:
                session._initialize_ratchet()
            except Exception as e:
                self.tracer.trace(peer, "ERROR", "RATCHET", "INIT_FAILED", str(e))

    def handle_dake1(self, peer: str, payload: str) -> Optional[str]:
        result = self.handle_incoming_message(peer, payload)
        if result and isinstance(result, (bytes, str)):
            r = result if isinstance(result, str) else result.decode("utf-8", errors="replace")
            return r if r.startswith("?OTRv4 ") else None
        return None

    def handle_dake2(self, peer: str, payload: str) -> Optional[str]:
        return self.handle_dake1(peer, payload)

    def handle_dake3(self, peer: str, payload: str) -> bool:
        result = self.handle_incoming_message(peer, payload)
        return self.has_session(peer)
