# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's voice calls: their state, starting, answering and ending them,
the gate a call must pass, and keeping the I2P call path warm.

A mixin of OtrApp (app.py). The call itself is voice.py (CallBridge) over
the engine's voice manager."""
from __future__ import annotations

from typing import Any, Dict

from .app_base import BridgeError
from .events import CallState, CallStateChanged, SecurityState, call_state_from_engine
from .trace import TRACE as _TRACE
from .voice import CallBridge, CallOutcome


class CallsMixin:
    """Voice calls. Mixed into OtrApp."""

    # -- calls -----------------------------------------------------------------

    def note_call_state(self, peer: str, engine_state: Any,
                        duration_seconds: int = 0, muted: bool = False) -> None:
        """Project the voice engine's CallState onto a UI event.

        The call state machine stays in otrv4plus_voice.py, which already
        validates every transition; the bridge only mirrors it.
        """
        peer = self.canonical_peer(peer)
        state = call_state_from_engine(engine_state)
        self._call_states[peer] = state
        self._emit(CallStateChanged(peer=peer, state=state,
                                    duration_seconds=duration_seconds, muted=muted))

    def call_state(self, peer: str) -> CallState:
        """This peer's call state.

        THE LIVE SESSION WINS. `_call_states` is fed by `note_call_state`,
        which was the only way a state could ever get in here -- a mirror of
        a machine nothing could enter, because no `start_call` existed. Now
        that calls can actually be placed, the manager's own session is the
        answer and the mirror is the fallback for anything that still reports
        through `note_call_state`.
        """
        peer = self.canonical_peer(peer)
        # Read only if a bridge exists. Asking must not be what CREATES one:
        # the conversation list polls this for every row, and a device that
        # has never placed a call has no business building a call manager to
        # be told there is no call.
        if self._calls_bridge is not None:
            live = self._calls_bridge.state(peer)
            if live is not CallState.IDLE:
                return live
        return self._call_states.get(peer, CallState.IDLE)

    # -- placing and answering -------------------------------------------------
    #
    # Thin on purpose. Every one of these delegates to `CallBridge`, which
    # delegates to `otrv4plus_voice.VoiceCallManager` -- the same state
    # machine, signalling and SMP gate the terminal client drives. Nothing
    # here decides whether a call may happen.

    @property
    def calls(self) -> "CallBridge":
        """The call bridge, built once per app. See android_bridge.voice."""
        if self._wiped:
            # Building one would build a VoiceCallManager: a wiped app must
            # not grow a new call stack because a late UI poll asked.
            raise BridgeError("wiped", "this app has been wiped")
        if self._calls_bridge is None:
            self._calls_bridge = CallBridge(self)
        return self._calls_bridge

    def start_call(self, peer: str) -> str:
        """Place a call. Returns a `CallOutcome` code, never a sentence.

        Returns as soon as the request is handed over: placing a call builds
        I2P tunnels, which takes 30-120 s, and a bridge method that waited
        for that would freeze whatever called it. The UI follows `call_state`
        and the events that follow.

        THE VERIFICATION GATE IS NOT HERE. `VoiceCallManager.start_call`
        refuses an unverified peer before anything else happens, reading the
        engine's own predicate. Restating that check at this layer would
        create a second gate that could disagree with the real one -- and the
        one that matters is the real one.
        """
        if self._wiped or self.is_room(peer):
            return CallOutcome.UNAVAILABLE
        return self.calls.start_call(self.canonical_peer(peer))

    def answer_call(self, peer: str) -> str:
        """Answer a ringing call. Returns a `CallOutcome` code."""
        if self._wiped:
            return CallOutcome.UNAVAILABLE
        return self.calls.answer_call(self.canonical_peer(peer))

    def end_call(self, peer: str, notify_peer: bool = True) -> str:
        """End an active call, or reject a ringing one. One verb for both,
        because the state machine has one."""
        if self._wiped:
            return CallOutcome.NO_CALL
        return self.calls.end_call(self.canonical_peer(peer), notify_peer)

    def call_duration_seconds(self, peer: str) -> int:
        """Seconds since this call became ACTIVE, or 0. Never counts the
        tunnel build: dialling is not talking."""
        if self._wiped:
            return 0
        return self.calls.duration_seconds(self.canonical_peer(peer))

    #: Why a call control is not offered. A FIXED SET, and the order in
    #: `call_gate` is the order they are checked in, so one state has one
    #: answer. Kotlin renders a sentence per code (`CallUi.Gate`).
    CALL_GATES = ("available", "wiped", "room", "not_connected",
                  "otrv4plus_unavailable", "no_session",
                  "fingerprint_changed", "not_verified", "voice_unavailable")

    def call_gate(self, peer: str) -> Dict[str, Any]:
        """Whether a call may be offered to [peer], and if not, why.

        The same checks `start_call` makes, asked of the engine rather than the
        last roster poll:

          * an encrypted OTR session exists and its fingerprint has not changed;
          * the peer is SMP-verified (`otrv4plus_voice._smp_query_default`, the
            definition calls and files share);
          * this device can run voice.

        Returns `{"gate": code, "reason": str}`; `reason` is set only for
        "voice_unavailable". No secrets.
        """
        def answer(gate: str, reason: str = "") -> Dict[str, Any]:
            return {"gate": gate, "reason": reason}

        if self._wiped:
            return answer("wiped")
        peer = self.canonical_peer(peer)
        if peer in self._rooms:
            return answer("room")
        transport = self._transport
        if transport is None or not bool(getattr(transport, "is_connected", True)):
            return answer("not_connected")
        try:
            encrypted = bool(self._engine.has_encrypted_session(peer))
        except Exception:
            encrypted = False
        if not encrypted and self._capability_enforced() and \
                self.otr_capability(peer) == "unavailable":
            # Nothing to establish: this contact's client does not speak
            # OTRv4Plus. Said as such, not as "start encryption".
            return answer("otrv4plus_unavailable")
        if not encrypted:
            return answer("no_session")
        security = self.security_state(peer)
        if security is SecurityState.FINGERPRINT_MISMATCH:
            return answer("fingerprint_changed")
        if security is SecurityState.PLAINTEXT:
            return answer("no_session")
        try:
            import otrv4plus_voice as _voice
            verified, _state = _voice._smp_query_default(self._engine, peer)
        except Exception:
            verified = False
        if not verified:
            return answer("not_verified")
        reason = self.voice_unavailable_reason()
        if reason:
            return answer("voice_unavailable", reason)
        return answer("available")

    def warm_call_path(self) -> Dict[str, Any]:
        """Build the next call's I2P path now, while a conversation that can
        call is open (otrv4plus_warmpath), and say how far it is:
        {"state": "cold" | "warming" | "ready", "seconds_left": n}. The phone
        icon is red, amber or green from it. Kept 10 minutes after the last
        ask; nothing is built where no call could be made."""
        cold = {"state": "cold", "seconds_left": 0}
        if self._wiped or self.voice_unavailable_reason():
            return cold
        try:
            if self.calls._ensure_manager() is None:      # binds the SAM helpers
                return cold
            import otrv4plus_warmpath
            host, port = self.sam_endpoint
            otrv4plus_warmpath.WARM.warm(host, int(port))
            return otrv4plus_warmpath.WARM.describe()
        except Exception:
            return cold

    def keep_call_path_ready(self) -> Dict[str, Any]:
        """From sign-in until disconnect: keep the next call's I2P path built
        and replace it when it dies or a call takes it
        (`otrv4plus_warmpath.WarmPath.hold`), so a call starts without a
        tunnel build. Nothing where voice cannot run."""
        cold = {"state": "cold", "seconds_left": 0}
        if self._wiped or self.voice_unavailable_reason():
            return cold
        try:
            if self.calls._ensure_manager() is None:
                return cold
            import otrv4plus_warmpath
            host, port = self.sam_endpoint
            otrv4plus_warmpath.WARM.hold(host, int(port))
            _TRACE.record("calls", "call_path_held", "info")
            return otrv4plus_warmpath.WARM.describe()
        except Exception:
            return cold

    def call_path_state(self) -> Dict[str, Any]:
        """The same answer as `warm_call_path`, without asking for a build."""
        try:
            import otrv4plus_warmpath
            return otrv4plus_warmpath.WARM.describe()
        except Exception:
            return {"state": "cold", "seconds_left": 0}

    def voice_unavailable_reason(self) -> str:
        """Why voice cannot run on this device, or "" when it can.

        Asked of `otrv4plus_voice`'s own host hook -- the same question
        `start_call` asks before doing anything -- so the screen cannot say
        something different from what the engine decides.
        """
        if self._wiped:
            return "wiped"
        return self.calls.unavailable_reason()

    def poll_calls(self) -> None:
        """Emit an event for any call whose state moved.

        The manager publishes no state callback, so movement is noticed by
        reading. Driven from the host's existing drain rather than a timer of
        its own, so there is one observer and nothing to leak.
        """
        if self._calls_bridge is not None and not self._wiped:
            self._calls_bridge.poll()
