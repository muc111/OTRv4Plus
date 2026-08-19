"""Structured state and events for the Android bridge.

This module exists to kill one specific pattern.  The terminal client infers UI
state by substring-matching printed English: `otrv4plus_xmpp.py` shadows the
`print()` builtin, and `_latch_smp_from_trace` / `_tui_route_output` look for
strings like "SMP VERIFIED" flowing past.  Peer-influenced text can reach those
matchers, and the source itself warns that nothing security-relevant may depend
on them.

Android must never do that.  Everything here is an enum or a typed event, and
every mapping below is derived from a value the engine actually returns -- not
from a display string, and not from a parallel state model invented for the UI.

Provenance of each mapping:

  SecurityState  <- UIConstants.SecurityLevel (otrv4+.py), plus one extra member
                    for the fingerprint-change case, which the engine signals by
                    raising TrustDatabase.FingerprintMismatch rather than by
                    returning a level.
  SmpState       <- the `state` field of EnhancedOTRSession.get_smp_status(),
                    which is RustSMP.get_phase() verbatim.
  CallState      <- otrv4plus_voice.CallState string constants.
  ConnectionState is the one genuinely new enum: transport connectivity has no
                    single existing representation (slixmpp events and I2P SAM
                    state are separate), so the bridge defines it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol

__all__ = [
    "SecurityState", "SmpState", "ConnectionState", "CallState",
    "security_state_from_level", "smp_state_from_status", "call_state_from_engine",
    "Event", "ConnectionStateChanged", "SessionStateChanged", "MessageReceived",
    "MessageDelivered", "SmpProgress", "SmpResult", "FingerprintChanged",
    "CallStateChanged", "ErrorOccurred", "EventSink",
]


class SecurityState(enum.IntEnum):
    """Per-peer security state.  Values match UIConstants.SecurityLevel."""

    PLAINTEXT = 0            # no encrypted session
    ENCRYPTED = 1            # DAKE done, identity unconfirmed
    FINGERPRINT = 2          # fingerprint pinned (TOFU), SMP not run
    SMP_VERIFIED = 3         # identity confirmed via SMP
    FINGERPRINT_MISMATCH = 4 # pinned fingerprint changed -- show a blocking warning


class SmpState(enum.Enum):
    """Coarse SMP state for UI.

    The engine exposes six protocol phases; a user needs four outcomes.  The
    exact phase stays available via `OtrApp.security_details()` for the advanced
    screen, so collapsing here loses nothing a user should see.
    """

    IDLE = "idle"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    FAILED = "failed"


class ConnectionState(enum.Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"


class CallState(enum.Enum):
    """Mirrors otrv4plus_voice.CallState, which is already a validated machine."""

    IDLE = "IDLE"
    INVITING = "INVITING"
    RINGING = "RINGING"
    CONNECTING = "CONNECTING"
    KEY_CONFIRMING = "KEY_CONFIRMING"
    MEDIA_CONNECTING = "MEDIA_CONNECTING"
    ACTIVE = "ACTIVE"
    ENDING = "ENDING"
    ENDED = "ENDED"


# ── Mappings from engine values ───────────────────────────────────────────────

def security_state_from_level(level: Any) -> SecurityState:
    """Map UIConstants.SecurityLevel (or its int value) to SecurityState.

    Unknown values fail safe to PLAINTEXT: an unrecognised level must never be
    shown to the user as more secure than it is.
    """
    try:
        return SecurityState(int(level))
    except (ValueError, TypeError):
        return SecurityState.PLAINTEXT


# RustSMP.get_phase() values, plus the sentinels the manager substitutes when
# there is no session or the lookup fails.
_SMP_PHASE_MAP = {
    "IDLE": SmpState.IDLE,
    "NONE": SmpState.IDLE,
    "no_session": SmpState.IDLE,
    "unknown": SmpState.IDLE,
    "UNAVAILABLE": SmpState.IDLE,
    "AWAITING_MSG2": SmpState.IN_PROGRESS,
    "AWAITING_MSG3": SmpState.IN_PROGRESS,
    "AWAITING_MSG4": SmpState.IN_PROGRESS,
    "VERIFIED": SmpState.VERIFIED,
    "FAILED": SmpState.FAILED,
}


def smp_state_from_status(status: Optional[Dict[str, Any]]) -> SmpState:
    """Map EnhancedOTRSession.get_smp_status() onto SmpState.

    The explicit `verified` / `failed` booleans win over the phase string: the
    session sets `verified` from `is_verified() or auto_smp_completed`, so a
    completed auto-SMP reports VERIFIED even when the phase has moved on or the
    Rust SMP object has already been destroyed.
    """
    if not status:
        return SmpState.IDLE
    if status.get("verified"):
        return SmpState.VERIFIED
    if status.get("failed"):
        return SmpState.FAILED
    return _SMP_PHASE_MAP.get(str(status.get("state", "IDLE")), SmpState.IDLE)


def call_state_from_engine(state: Any) -> CallState:
    try:
        return CallState(str(state))
    except ValueError:
        return CallState.IDLE


# ── Events ────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Event:
    """Base event.

    Subclasses carry only values safe to hand to a UI process: identifiers,
    enums, counters, public fingerprints.  No key material, no plaintext bodies,
    no SMP secrets.  `MessageReceived` is the one event that carries user text,
    and its payload is the already-decrypted message destined for the screen --
    it must never be logged (see android_bridge.app.redacting_logger).
    """

    peer: Optional[str] = None


@dataclass(frozen=True)
class ConnectionStateChanged(Event):
    state: ConnectionState = ConnectionState.DISCONNECTED
    retry_in_seconds: Optional[int] = None


@dataclass(frozen=True)
class SessionStateChanged(Event):
    security: SecurityState = SecurityState.PLAINTEXT


@dataclass(frozen=True)
class MessageReceived(Event):
    body: str = ""
    timestamp: float = 0.0
    message_id: Optional[str] = None


@dataclass(frozen=True)
class MessageDelivered(Event):
    message_id: str = ""


@dataclass(frozen=True)
class SmpProgress(Event):
    step: int = 0
    total: int = 4
    state: SmpState = SmpState.IDLE


@dataclass(frozen=True)
class SmpResult(Event):
    state: SmpState = SmpState.IDLE


@dataclass(frozen=True)
class FingerprintChanged(Event):
    """The pinned fingerprint for this peer no longer matches.

    Both values are public keys' fingerprints, safe to display; the UI must treat
    this as blocking rather than informational.
    """

    stored_fingerprint: str = ""
    received_fingerprint: str = ""


@dataclass(frozen=True)
class CallStateChanged(Event):
    state: CallState = CallState.IDLE
    duration_seconds: int = 0
    muted: bool = False


@dataclass(frozen=True)
class ErrorOccurred(Event):
    """A failure the user may need to know about.

    `code` is a stable machine-readable identifier the UI switches on; `detail`
    is a short non-sensitive hint. Engine exception text is NOT propagated here,
    because it can embed peer-controlled data and occasionally state material.
    """

    code: str = "unknown"
    detail: str = ""


class EventSink(Protocol):
    """What the Kotlin host implements (via Chaquopy) to receive events."""

    def on_event(self, event: Event) -> None: ...
