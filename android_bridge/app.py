"""OtrApp — the only Python surface the Kotlin host talks to.

Design constraints this file exists to satisfy:

  * Narrow.  Kotlin gets these methods, not `otrv4+.py`.  Every one of them maps
    onto an EnhancedSessionManager call that already exists; nothing here is a
    new API invented to make a UI convenient.
  * Structured.  Returns enums and dataclasses.  No caller ever parses a status
    string, and no security decision is ever taken on displayed text.
  * Secret-free.  No method returns key material, a seed, an SMP secret, or a
    ratchet state.  Secrets that must be passed IN (the SMP secret) go straight
    to the engine and are not retained, logged, or echoed back.
  * Transport-agnostic.  The XMPP client is injected as `Transport`, so the
    facade is importable and testable without slixmpp, and so the I2P decision
    (blocker B3) can be settled without touching this layer.

Threading: `EnhancedSessionManager` takes an RLock internally and the XMPP
client runs SMP on its own executor, because SMP performs multi-minute 3072-bit
computations.  This facade does not add locking of its own; it must be driven
from the service thread that owns the engine, never from the Android main
thread.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .events import (
    CallState, CallStateChanged, ConnectionState, ConnectionStateChanged,
    ErrorOccurred, Event, EventSink, FingerprintChanged, MessageReceived,
    SecurityState, SessionStateChanged, SmpProgress, SmpResult, SmpState,
    call_state_from_engine, security_state_from_level, smp_state_from_status,
)

__all__ = ["OtrApp", "Transport", "ContactView", "SecurityDetails",
           "redacting_logger", "BridgeError"]


class BridgeError(RuntimeError):
    """A bridge-level failure.  Carries a code, never engine exception text."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


# ── Logging ───────────────────────────────────────────────────────────────────

class _RedactingFilter(logging.Filter):
    """Drops any record that could carry sensitive material.

    The bridge logs identifiers, enum names and counts.  It never logs message
    bodies, SMP secrets, seeds, or key material.  Rather than trusting every
    future call site to remember that, this filter refuses records carrying a
    `sensitive` marker and truncates everything else.

    This is defence in depth, not the primary control: the primary control is
    that no call site in this package passes such values to the logger at all,
    which tests/test_android_bridge.py asserts directly.
    """

    MAX = 200

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "sensitive", False):
            return False
        try:
            msg = record.getMessage()
        except Exception:
            return False
        if len(msg) > self.MAX:
            record.msg = msg[: self.MAX] + "...<truncated>"
            record.args = ()
        return True


def redacting_logger(name: str = "otrv4plus.bridge") -> logging.Logger:
    """A logger safe for the bridge to use.

    On Android the release build should attach no handler at all; this exists so
    development builds have something structured, and so the filter is present
    even if a handler is attached later.
    """
    log = logging.getLogger(name)
    if not any(isinstance(f, _RedactingFilter) for f in log.filters):
        log.addFilter(_RedactingFilter())
    return log


_log = redacting_logger()


# ── Value types returned to Kotlin ────────────────────────────────────────────

@dataclass(frozen=True)
class ContactView:
    """Everything the contacts list needs, and nothing else."""

    jid: str
    display_name: str
    online: bool
    security: SecurityState
    smp: SmpState
    last_activity: Optional[float] = None
    call_available: bool = False


@dataclass(frozen=True)
class SecurityDetails:
    """Backing data for the advanced security screen.

    Public and derived values only: fingerprints are of public keys, and the
    protocol phase strings are engine state names, not secrets.
    """

    peer: str
    security: SecurityState
    smp: SmpState
    smp_phase: str
    local_fingerprint: str
    peer_fingerprint: Optional[str]
    trusted: bool
    session_state: Optional[str] = None


class Transport:
    """What OtrApp needs from a transport.  Implemented by the XMPP client.

    Kept to four methods so the I2P/SAM question (blocker B3) and the choice of
    transport stay entirely outside this facade.
    """

    def send(self, peer: str, payload: str) -> None:            # pragma: no cover
        raise NotImplementedError

    def connect(self) -> None:                                   # pragma: no cover
        raise NotImplementedError

    def disconnect(self) -> None:                                # pragma: no cover
        raise NotImplementedError

    def roster(self) -> List[Dict[str, Any]]:                    # pragma: no cover
        raise NotImplementedError


# ── The facade ────────────────────────────────────────────────────────────────

class OtrApp:
    """Typed facade over EnhancedSessionManager + Transport."""

    def __init__(self, engine: Any, transport: Optional[Transport] = None,
                 event_sink: Optional[EventSink] = None,
                 clock: Callable[[], float] = time.time):
        if engine is None:
            raise BridgeError("engine_required",
                              "OtrApp needs an EnhancedSessionManager instance")
        self._engine = engine
        self._transport = transport
        self._sink = event_sink
        self._clock = clock
        self._connection = ConnectionState.DISCONNECTED
        self._presence: Dict[str, bool] = {}
        self._last_activity: Dict[str, float] = {}
        self._call_states: Dict[str, CallState] = {}

    # -- event plumbing --------------------------------------------------------

    def set_event_sink(self, sink: Optional[EventSink]) -> None:
        self._sink = sink

    def _emit(self, event: Event) -> None:
        """Deliver an event.

        A sink that raises must never take the engine down with it: the sink is
        Kotlin code across a language boundary, and a UI bug is not a reason to
        lose a session.
        """
        sink = self._sink
        if sink is None:
            return
        try:
            sink.on_event(event)
        except Exception:
            _log.warning("event sink raised on %s", type(event).__name__)

    # -- lifecycle -------------------------------------------------------------

    def connect(self) -> None:
        if self._transport is None:
            raise BridgeError("no_transport")
        self._connection = ConnectionState.CONNECTING
        self._emit(ConnectionStateChanged(state=ConnectionState.CONNECTING))
        try:
            self._transport.connect()
        except Exception:
            self._connection = ConnectionState.FAILED
            self._emit(ConnectionStateChanged(state=ConnectionState.FAILED))
            raise BridgeError("connect_failed")

    def disconnect(self) -> None:
        if self._transport is not None:
            try:
                self._transport.disconnect()
            except Exception:
                _log.warning("transport disconnect failed")
        self._connection = ConnectionState.DISCONNECTED
        self._emit(ConnectionStateChanged(state=ConnectionState.DISCONNECTED))

    def shutdown(self) -> None:
        """Tear down every session.  Safe to call more than once."""
        try:
            self._engine.clear_all_sessions("shutdown")
        except Exception:
            _log.warning("session teardown reported a problem")
        self.disconnect()

    def note_connected(self) -> None:
        """Called by the transport once the stream is usable."""
        self._connection = ConnectionState.CONNECTED
        self._emit(ConnectionStateChanged(state=ConnectionState.CONNECTED))

    def note_presence(self, peer: str, online: bool) -> None:
        self._presence[peer] = bool(online)

    @property
    def connection_state(self) -> ConnectionState:
        return self._connection

    # -- security state --------------------------------------------------------

    def security_state(self, peer: str) -> SecurityState:
        return security_state_from_level(self._engine.get_security_level(peer))

    def smp_state(self, peer: str) -> SmpState:
        try:
            return smp_state_from_status(self._engine.get_smp_status(peer))
        except Exception:
            return SmpState.IDLE

    def smp_progress(self, peer: str) -> SmpProgress:
        """Drives the verification progress UI.

        SMP takes minutes on mobile -- a 50,000-round SHAKE-256 chain plus
        3072-bit work, ~1 minute measured over XMPP/I2P -- so this is a real
        progress indicator, not a spinner.
        """
        try:
            step, total = self._engine.get_smp_progress(peer)
        except Exception:
            step, total = 0, 4
        return SmpProgress(peer=peer, step=int(step), total=int(total),
                           state=self.smp_state(peer))

    def security_details(self, peer: str) -> SecurityDetails:
        try:
            status = self._engine.get_smp_status(peer) or {}
        except Exception:
            status = {}
        try:
            session_state = self._engine.get_session_state(peer)
        except Exception:
            session_state = None
        return SecurityDetails(
            peer=peer,
            security=self.security_state(peer),
            smp=smp_state_from_status(status),
            smp_phase=str(status.get("state", "IDLE")),
            local_fingerprint=self._safe(self._engine.get_fingerprint, default=""),
            peer_fingerprint=self._safe(lambda: self._engine.get_peer_fingerprint(peer)),
            trusted=bool(self._safe(lambda: self._engine.is_peer_trusted(peer),
                                    default=False)),
            session_state=(session_state or {}).get("state") if session_state else None,
        )

    @staticmethod
    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default

    # -- contacts --------------------------------------------------------------

    def contacts(self) -> List[ContactView]:
        entries = self._safe(self._transport.roster, default=[]) if self._transport else []
        out: List[ContactView] = []
        for entry in entries or []:
            jid = entry.get("jid") if isinstance(entry, dict) else str(entry)
            if not jid:
                continue
            security = self.security_state(jid)
            out.append(ContactView(
                jid=jid,
                display_name=(entry.get("name") if isinstance(entry, dict) else None) or jid,
                online=self._presence.get(jid, False),
                security=security,
                smp=self.smp_state(jid),
                last_activity=self._last_activity.get(jid),
                # Calls are gated on cryptographic verification by the engine
                # (VoiceCallManager._smp_verified).  This flag is for enabling a
                # button, and must never be treated as the gate itself.
                call_available=security is SecurityState.SMP_VERIFIED,
            ))
        return out

    # -- messaging -------------------------------------------------------------

    def start_session(self, peer: str) -> None:
        """Begin the DAKE.  Completes in roughly 20s over XMPP/I2P."""
        payload = self._safe(lambda: self._engine.handle_outgoing_message(peer, ""))
        try:
            self._engine.get_or_create_session(peer, is_initiator=True)
        except Exception:
            raise BridgeError("session_start_failed")
        self._emit(SessionStateChanged(peer=peer, security=self.security_state(peer)))

    def send_message(self, peer: str, body: str) -> bool:
        """Encrypt and send.  Returns whether it went out encrypted.

        Refuses to fall back to plaintext: if the engine reports the message was
        not encrypted, the payload is dropped and an error is raised rather than
        silently leaking the body onto the wire.
        """
        if self._transport is None:
            raise BridgeError("no_transport")
        try:
            payload, encrypted = self._engine.handle_outgoing_message(peer, body)
        except Exception:
            raise BridgeError("encrypt_failed")

        if payload is None:
            raise BridgeError("encrypt_failed")
        if not encrypted:
            # Never silently downgrade.
            raise BridgeError("not_encrypted",
                              "refusing to send: no encrypted session")
        self._transport.send(peer, payload)
        self._last_activity[peer] = self._clock()
        return True

    def receive_message(self, peer: str, payload: str) -> Optional[str]:
        """Feed an inbound frame to the engine; emit a MessageReceived if it was one.

        Returns the plaintext for the caller that wants it inline; the same value
        is delivered as an event.  Nothing here is logged.
        """
        # Sample BEFORE the engine runs: a DAKE or SMP frame changes the
        # security level as a side effect of this call, and comparing against a
        # post-call reading would always find them equal.
        before = self.security_state(peer)
        try:
            result = self._engine.handle_incoming_message(peer, payload)
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="decrypt_failed"))
            return None

        if result is None:
            # Protocol frame (DAKE/SMP), not user text: surface any state change.
            after = self.security_state(peer)
            if after != before:
                self._emit(SessionStateChanged(peer=peer, security=after))
            return None

        body = result.decode("utf-8", errors="replace") if isinstance(result, (bytes, bytearray)) else str(result)
        self._last_activity[peer] = self._clock()
        self._emit(MessageReceived(peer=peer, body=body, timestamp=self._clock()))
        return body

    # -- verification ----------------------------------------------------------

    def smp_start(self, peer: str, secret: str, question: str = "") -> None:
        """Begin SMP.  `secret` is passed straight through and never retained."""
        try:
            payload = self._engine.start_smp(peer, secret, question)
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="smp_start_failed"))
            raise BridgeError("smp_start_failed")
        finally:
            del secret
        if payload and self._transport is not None:
            self._transport.send(peer, payload)
        self._emit(self.smp_progress(peer))

    def smp_respond(self, peer: str, secret: str) -> None:
        """Answer a peer's verification challenge."""
        try:
            self._engine.set_smp_secret(peer, secret)
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="smp_respond_failed"))
            raise BridgeError("smp_respond_failed")
        finally:
            del secret
        self._emit(self.smp_progress(peer))

    def smp_abort(self, peer: str) -> None:
        abort = getattr(self._engine, "abort_smp", None)
        if abort is None:
            raise BridgeError("smp_abort_unsupported")
        self._safe(lambda: abort(peer))
        self._emit(SmpResult(peer=peer, state=self.smp_state(peer)))

    def note_fingerprint_mismatch(self, peer: str, stored: str, received: str) -> None:
        """Raised by the engine as TrustDatabase.FingerprintMismatch.

        Surfaced as its own event because the UI must block on it rather than
        fold it into the ordinary security state.
        """
        self._emit(FingerprintChanged(peer=peer, stored_fingerprint=stored,
                                      received_fingerprint=received))

    def trust_peer(self, peer: str, fingerprint: str) -> bool:
        return bool(self._safe(lambda: self._engine.trust_fingerprint(peer, fingerprint),
                               default=False))

    # -- identity --------------------------------------------------------------

    def local_fingerprint(self) -> str:
        return self._safe(self._engine.get_fingerprint, default="")

    # -- calls -----------------------------------------------------------------

    def note_call_state(self, peer: str, engine_state: Any,
                        duration_seconds: int = 0, muted: bool = False) -> None:
        """Project the voice engine's CallState onto a UI event.

        The call state machine stays in otrv4plus_voice.py, which already
        validates every transition; the bridge only mirrors it.
        """
        state = call_state_from_engine(engine_state)
        self._call_states[peer] = state
        self._emit(CallStateChanged(peer=peer, state=state,
                                    duration_seconds=duration_seconds, muted=muted))

    def call_state(self, peer: str) -> CallState:
        return self._call_states.get(peer, CallState.IDLE)
