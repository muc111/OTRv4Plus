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
    "CallStateChanged", "ErrorOccurred", "SubscriptionRequested", "EventSink",
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

    The engine exposes eight protocol phases; a user needs these five.  The
    exact phase stays available via `OtrApp.security_details()` for the advanced
    screen, so collapsing here loses nothing a user should see.

    SECRET_REQUIRED IS NOT A COLLAPSE, AND ADDING IT FIXED A REAL GAP
    ----------------------------------------------------------------
    `Rust/src/smp.rs` has had `SmpPhase::SecretRequired` since 0.10.27. It is
    the state a responder is in when a peer's SMP1 has ARRIVED and is being
    HELD by the core because no passphrase is set -- the core deliberately
    holds rather than aborts, "lets the responder supply it and answer the
    SMP1 that already arrived, so the run continues rather than restarting".

    It was not in this map. `SECRET_REQUIRED` fell through to the default and
    was reported as IDLE, so the one state that means "the other person is
    waiting on you right now" was indistinguishable from "nothing is
    happening". On the terminal that did not show, because the IRC and XMPP
    clients read `smp_secret_required(peer)` off the session manager directly
    and never went through this enum. On Android there was no other route.

    CANCELLED IS NOT FAILED, AND THE DIFFERENCE IS THE WHOLE POINT OF SMP
    --------------------------------------------------------------------
    FAILED means the proof ran and the secrets did not match -- which, on this
    protocol, is what an impersonation looks like. CANCELLED means nobody
    proved anything: an abort, a declined request, an expired prompt. Showing
    a cancel as a failure would tell a user their peer may be an impostor
    because they closed a dialog.
    """

    #: No verification has happened. The resting state, and the honest one:
    #: an OTR session is encrypted TO SOMEBODY, and until SMP passes nobody
    #: has checked who. Named NOT_VERIFIED rather than IDLE for that reason.
    NOT_VERIFIED = "not_verified"
    #: A peer's SMP1 is held by the core, waiting for this side's passphrase.
    SECRET_REQUIRED = "secret_required"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    #: The proof ran and the secrets did not match.
    FAILED = "failed"
    #: Aborted or declined. Nothing was proved, and nothing failed.
    CANCELLED = "cancelled"


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
#: Every phase string `Rust/src/smp.rs::get_phase` can return, plus the
#: "there is no session" spellings Python adds, and nothing else. A phase that
#: is not here is a phase this map has not been taught -- which is exactly how
#: SECRET_REQUIRED was silently reported as IDLE for two releases -- so
#: `test_android_bridge` asserts the Rust source's arms are all covered.
_SMP_PHASE_MAP = {
    "IDLE": SmpState.NOT_VERIFIED,
    "NONE": SmpState.NOT_VERIFIED,
    "no_session": SmpState.NOT_VERIFIED,
    "unknown": SmpState.NOT_VERIFIED,
    "UNAVAILABLE": SmpState.NOT_VERIFIED,
    # A peer's SMP1 is parked in the core waiting for our passphrase.
    "SECRET_REQUIRED": SmpState.SECRET_REQUIRED,
    "AWAITING_MSG2": SmpState.IN_PROGRESS,
    "AWAITING_MSG3": SmpState.IN_PROGRESS,
    "AWAITING_MSG4": SmpState.IN_PROGRESS,
    "VERIFIED": SmpState.VERIFIED,
    "FAILED": SmpState.FAILED,
    # ABORTED is the core's terminal state for `destroy()` and for an explicit
    # abort. Nothing was proved, so it is not FAILED.
    "ABORTED": SmpState.CANCELLED,
}


def smp_state_from_status(status: Optional[Dict[str, Any]]) -> SmpState:
    """Map EnhancedOTRSession.get_smp_status() onto SmpState.

    The explicit `verified` / `failed` booleans win over the phase string: the
    session sets `verified` from `is_verified() or auto_smp_completed`, so a
    completed auto-SMP reports VERIFIED even when the phase has moved on or the
    Rust SMP object has already been destroyed.

    An UNKNOWN phase falls back to NOT_VERIFIED, and that is the safe
    direction: a state this map has not been taught must never be read as
    VERIFIED. It is also why the map above is asserted complete against the
    Rust source rather than trusted -- a fallback that is safe is still a
    fallback that hides a phase, which is what happened to SECRET_REQUIRED.
    """
    if not status:
        return SmpState.NOT_VERIFIED
    if status.get("verified"):
        return SmpState.VERIFIED
    if status.get("failed"):
        return SmpState.FAILED
    return _SMP_PHASE_MAP.get(str(status.get("state", "IDLE")),
                              SmpState.NOT_VERIFIED)


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
    state: SmpState = SmpState.NOT_VERIFIED


@dataclass(frozen=True)
class SmpResult(Event):
    state: SmpState = SmpState.NOT_VERIFIED


@dataclass(frozen=True)
class FingerprintChanged(Event):
    """The pinned fingerprint for this peer no longer matches.

    Both values are public keys' fingerprints, safe to display; the UI must treat
    this as blocking rather than informational.
    """

    stored_fingerprint: str = ""
    received_fingerprint: str = ""


@dataclass(frozen=True)
class SubscriptionRequested(Event):
    """Someone asked to see our presence.

    WHY THIS IS AN EVENT AND NOT A LOG LINE. It used to be the latter, with a
    comment explaining that a plain dict arrives in Kotlin as `{"type":
    "dict"}` because `EventQueue._describe` only walks dataclass fields -- true,
    and the reason it is a dataclass now.

    Presence is metadata. Approving tells that account when this device is
    online, from which resource, and how idle it is, for as long as they keep
    it. On an anonymity-oriented messenger the user is entitled to know that
    happened, and under ASK to be the one who decides.

    `policy` is carried because it changes what the UI is allowed to say. Under
    ASK nothing has been answered and the honest words are "allow or decline".
    Under ACCEPT slixmpp answered before this was raised, so a prompt offering
    to decline would be offering to undo something already done -- the honest
    words there are "they can now see you", with revoking as the remedy. One
    field, because a screen that got this wrong would be lying about whether
    the user still has a choice.

    No display name, no roster metadata: the JID is already the most
    identifying thing that can be here, and it is here because the user cannot
    answer a question that does not say who is asking.
    """

    policy: str = "accept"

    @property
    def is_question(self) -> bool:
        """Whether the user still has a decision to make."""
        return self.policy == "ask"


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
