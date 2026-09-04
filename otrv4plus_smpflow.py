#!/usr/bin/env python3
"""The SMP verification flow as an explicit state machine.

THE PROPERTY THIS FILE EXISTS TO ENFORCE
========================================
A remote peer may cause the local client to ASK the user for the shared
passphrase.  A remote peer may never cause the next thing the user types to
BECOME the passphrase.

Those two are one step apart, and the step is consent.  The transition a
remote message is allowed to drive stops at AWAITING_LOCAL_CONSENT; the
transition into AWAITING_SECRET -- the state in which a hidden read is armed
and the next line is treated as a passphrase -- is reachable only from local
input.  `remote_smp1_arrived()` cannot produce it; `local_consent()` is the
only door, and it is called from a keypress the user made.

This was not a hypothetical.  `_apply_tofu` used to end by setting
`_pending[peer] = "smp_secret"` and the inbound handler could reach it, so a
peer who completed a DAKE decided that the user's next sentence was a shared
secret.  See SECURITY_INVARIANTS.md INV-06.  The state machine makes the same
mistake structurally impossible rather than merely absent: there is no edge to
take.

WHAT THIS IS NOT
================
It holds no secret.  The passphrase never enters this object -- callers take
it from the hidden read and hand it straight to the engine, which copies it
into Rust-owned zeroizing memory.  What lives here is which question the user
is being asked, for which peer, and whether the answer may be a passphrase.

Shared by both front ends deliberately: the IRC client had the defect INV-06
describes long after the XMPP client stopped having it, because each had its
own ad-hoc flags.  One state machine, one set of edges, tested once.
"""

import threading
import time
from typing import Optional

# ── states ───────────────────────────────────────────────────────────────────
IDLE = "IDLE"
AWAITING_LOCAL_CONSENT = "AWAITING_LOCAL_CONSENT"
AWAITING_SECRET = "AWAITING_SECRET"
RUNNING = "RUNNING"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
DECLINED = "DECLINED"

#: How the state was entered.  Only LOCAL may arm a secret read directly.
LOCAL = "local"
REMOTE = "remote"

#: A consent request left open forever would mean a "y" typed much later, for
#: some other reason, opened a passphrase prompt.  Bounded instead.
CONSENT_TIMEOUT_SECS = 180.0


class SmpFlowError(RuntimeError):
    """An illegal transition was attempted.  Always a bug, never user input."""


class SmpFlow:
    """One peer's verification flow.  Thread-safe; the OTR executor and the
    input reader both touch it."""

    def __init__(self, peer: str, clock=time.monotonic):
        self.peer = peer
        self._clock = clock
        self._lock = threading.RLock()
        self._state = IDLE
        self._origin: Optional[str] = None
        self._deadline: Optional[float] = None
        #: True when the engine is holding an SMP1 that this flow must answer.
        self.has_held_smp1 = False

    # ── inspection ───────────────────────────────────────────────────────────
    @property
    def state(self) -> str:
        with self._lock:
            self._expire_if_due()
            return self._state

    @property
    def origin(self) -> Optional[str]:
        with self._lock:
            return self._origin

    def awaiting_secret(self) -> bool:
        """True only while a hidden read may legitimately consume a line."""
        return self.state == AWAITING_SECRET

    def awaiting_consent(self) -> bool:
        return self.state == AWAITING_LOCAL_CONSENT

    def _expire_if_due(self):
        if (self._state == AWAITING_LOCAL_CONSENT
                and self._deadline is not None
                and self._clock() >= self._deadline):
            self._state = IDLE
            self._origin = None
            self._deadline = None

    # ── edges a REMOTE message may drive ─────────────────────────────────────
    def remote_smp1_arrived(self) -> str:
        """SMP1 came in and no passphrase is stored.

        The furthest a peer can move this machine.  Returns the new state so a
        caller cannot mistake "already asking" for "ask again": a second SMP1
        while the prompt is open is idempotent, which is what stops a peer
        stacking prompts by resending.
        """
        with self._lock:
            self._expire_if_due()
            if self._state in (AWAITING_LOCAL_CONSENT, AWAITING_SECRET):
                # Already asking.  Do not re-arm, do not extend, do not stack.
                return self._state
            if self._state == RUNNING:
                raise SmpFlowError("SMP already running for %s" % self.peer)
            self._state = AWAITING_LOCAL_CONSENT
            self._origin = REMOTE
            self._deadline = self._clock() + CONSENT_TIMEOUT_SECS
            self.has_held_smp1 = True
            return self._state

    # ── edges only LOCAL input may drive ─────────────────────────────────────
    def local_secret_needed(self) -> str:
        """The user asked to verify and has no stored passphrase.

        Goes straight to AWAITING_SECRET with no consent step, because the
        consent already happened: the user typed the command on the previous
        line.  This is the `passwd` shape and it is why the local path is safe
        without a prompt-before-the-prompt.
        """
        with self._lock:
            self._expire_if_due()
            if self._state == RUNNING:
                raise SmpFlowError("SMP already running for %s" % self.peer)
            self._state = AWAITING_SECRET
            self._origin = LOCAL
            self._deadline = None
            return self._state

    def local_consent(self, agreed: bool) -> str:
        """The user answered the consent prompt.

        THE security-relevant edge: the only route into AWAITING_SECRET from a
        remotely-originated request, and it is called from a keypress.
        """
        with self._lock:
            self._expire_if_due()
            if self._state != AWAITING_LOCAL_CONSENT:
                raise SmpFlowError(
                    "no consent was being asked for %s (state=%s)"
                    % (self.peer, self._state))
            if not agreed:
                self._state = DECLINED
                self._deadline = None
                return self._state
            self._state = AWAITING_SECRET
            self._deadline = None
            return self._state

    def secret_supplied(self) -> str:
        """A passphrase came back from the dedicated hidden read."""
        with self._lock:
            if self._state != AWAITING_SECRET:
                raise SmpFlowError(
                    "no secret was being requested for %s (state=%s)"
                    % (self.peer, self._state))
            self._state = RUNNING
            self._deadline = None
            return self._state

    def secret_cancelled(self) -> str:
        """The hidden read came back empty, or the user typed cancel."""
        with self._lock:
            if self._state != AWAITING_SECRET:
                raise SmpFlowError(
                    "no secret was being requested for %s (state=%s)"
                    % (self.peer, self._state))
            self._state = DECLINED
            self._deadline = None
            return self._state

    def running(self) -> str:
        """SMP started without needing to ask for anything."""
        with self._lock:
            self._expire_if_due()
            if self._state in (AWAITING_LOCAL_CONSENT, AWAITING_SECRET):
                raise SmpFlowError(
                    "cannot start SMP for %s while asking the user for a "
                    "passphrase" % self.peer)
            self._state = RUNNING
            self._origin = None
            self._deadline = None
            return self._state

    # ── terminal ─────────────────────────────────────────────────────────────
    def verified(self) -> str:
        with self._lock:
            self._state = VERIFIED
            self._deadline = None
            self.has_held_smp1 = False
            return self._state

    def failed(self) -> str:
        with self._lock:
            self._state = FAILED
            self._deadline = None
            self.has_held_smp1 = False
            return self._state

    def reset(self) -> str:
        """Back to IDLE.  Used on teardown, disconnect and after a terminal
        state has been shown to the user."""
        with self._lock:
            self._state = IDLE
            self._origin = None
            self._deadline = None
            self.has_held_smp1 = False
            return self._state


class SmpFlowRegistry:
    """Flows by peer, with the invariant that only one may be asking at once.

    One-at-a-time is a UI property, not a protocol one: two hidden prompts
    competing for one stdin is how a passphrase ends up answering the wrong
    question.
    """

    def __init__(self, clock=time.monotonic):
        self._lock = threading.RLock()
        self._flows = {}
        self._clock = clock

    def get(self, peer: str) -> SmpFlow:
        with self._lock:
            flow = self._flows.get(peer)
            if flow is None:
                flow = SmpFlow(peer, clock=self._clock)
                self._flows[peer] = flow
            return flow

    def drop(self, peer: str) -> None:
        """Forget a peer entirely -- session torn down, or disconnected."""
        with self._lock:
            self._flows.pop(peer, None)

    def asking(self) -> Optional[SmpFlow]:
        """The flow currently asking the user something, if any."""
        with self._lock:
            for flow in self._flows.values():
                if flow.state in (AWAITING_LOCAL_CONSENT, AWAITING_SECRET):
                    return flow
            return None

    def awaiting_secret(self) -> Optional[SmpFlow]:
        with self._lock:
            for flow in self._flows.values():
                if flow.state == AWAITING_SECRET:
                    return flow
            return None
