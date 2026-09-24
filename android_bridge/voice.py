# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Android half of a voice call. None of the call logic lives here.

WHAT WAS ALREADY BUILT
======================
All of it, except the wiring:

  * `otrv4plus_voice.VoiceCallManager` -- the call state machine, the
    signalling, the key schedule, the rekeying and the SMP gate;
  * `otrv4plus_audio` -- an AAudio backend bound through ctypes against
    `libaaudio.so`, written to load inside an APK;
  * both packaged into the APK, with `minSdk` already at API 26 for AAudio.

What did not exist was any way for the Android application to reach them.
`android_bridge.app` exposed `note_call_state` and `call_state` -- two
mirrors of a state nothing could enter -- and no `start_call`, `answer_call`
or `end_call`. `ContactView.call_available` fed no action.

This module is that wiring and nothing else. Every policy question --
whether the peer is verified, whether a session exists, whether the rate
limit allows another invite, what a legal state transition is -- is answered
by `VoiceCallManager`, which already answers it for the terminal client. A
second copy of any of those would be a second thing to get wrong, and the
one that matters is the SMP gate.

WHY THE TERMINAL CLIENT IS IMPORTED, AND WHAT IS REPLACED AFTERWARDS
====================================================================
`otrv4plus_voice` reaches its platform through `_HOST`, a dict of injected
helpers. `otrv4plus_xmpp` binds all of them at module scope. Most are the same
on both platforms and are kept: SAM open/read/parse and release, which make up
the I2P datagram transport, and the sanitiser.

THREE ARE NOT THE SAME, and `android_audio.bind` replaces them right after the
import: the codec (`opus`, `load_opus`) and the availability answer. The
Termux ones are `opuslib` over Termux's libopus.so, and an APK has neither.
Leaving them bound is what put "Call unavailable — opuslib not installed (pip
install ...)" on a handset, and it would have failed every Android call at
`_build_codec`. Android uses the Rust Opus codec in `otrv4_core` and AAudio;
see `android_audio`.

It is imported INSIDE a function. `tests/test_android_transport.py` bans
`otrv4plus_xmpp` at module scope in `android_bridge.transport` and
`android_bridge.app` -- "importing it drags in the engine, argparse, getpass
and a terminal" -- and names the remedy: "the import has to move back inside
a function". Measured at 0.61 s here, paid once, on the first call-related
action, on a worker thread.

WHY THIS OWNS ITS OWN EVENT LOOP
================================
`start_call` awaits `session.create_session()`, which builds I2P tunnels.
That is 30-120 s and longer on a busy phone -- the manager says so itself.
Running it on the transport's loop would stall the XMPP stream for the
duration: no keepalive, no messages, no presence, for the length of a tunnel
build. So calls get their own loop thread, and the two cannot starve each
other.

Signalling still goes out through the transport, which marshals onto its own
loop, so nothing here touches slixmpp from the wrong thread.

NOTHING BLOCKS THE CALLER
=========================
`start_call` submits and returns; it does not wait for the tunnel. Kotlin
polls `state()` exactly as it polls everything else, and the coroutine's own
answer arrives as an event. A bridge method that blocked for two minutes
would be an ANR on the main thread and a frozen screen anywhere else.
"""

from __future__ import annotations

import asyncio
import threading
from time import monotonic as _monotonic
from typing import Any

from .events import (CallState, CallStateChanged, ErrorOccurred,
                     call_state_from_engine)

__all__ = ["CallBridge", "CallOutcome"]


class CallOutcome:
    """What a call request did, as a stable code for Kotlin to branch on.

    Never a sentence and never engine exception text. The UI maps these; a
    string that could vary with the engine's wording would be a UI that
    decides what to show by matching substrings, which is the mistake the
    voice manager's own docs call out about its v2.
    """

    #: The request was handed to the call manager. NOT "the call connected".
    STARTED = "started"
    #: Nothing to act on: no call in that state for this peer.
    NO_CALL = "no_call"
    #: A call is already live with this peer.
    ALREADY = "already"
    #: The voice subsystem could not be loaded at all on this device.
    UNAVAILABLE = "unavailable"
    #: There is no transport, so signalling cannot leave the device.
    NOT_CONNECTED = "not_connected"


class _VoiceClient:
    """The four attributes `VoiceCallManager` actually uses from a client.

    Enumerated from the manager's own source rather than guessed -- it
    touches `client.otr`, `client.send_otr_fragmented`, `client._local_fp`
    and `client._remote_fp`, and nothing else. `_smp_query_fn` is left unset
    so the manager falls back to `_smp_query_default`, which reads the same
    engine predicate the terminal client reads.

    This is an ADAPTER, not a client. It answers questions; it makes no
    decisions.
    """

    def __init__(self, app):
        self._app = app

    @property
    def otr(self):
        return self._app._engine

    def send_otr_fragmented(self, peer: str, payload) -> None:
        """Put an already-encrypted call signal on the wire.

        `_send_protocol` is the bridge's existing path for exactly this --
        an engine frame going out, fragmented by the transport so it
        survives the I2P size cliff. Call signalling is ordinary OTR
        ciphertext and has no business having a second send path.
        """
        self._app._send_protocol(peer, payload)

    def _local_fp(self, peer=None) -> str:
        return self._app._safe(self._app._engine.get_fingerprint,
                               default="unavailable") or "unavailable"

    def _remote_fp(self, peer: str) -> str:
        return self._app._safe(
            lambda: self._app._engine.get_peer_fingerprint(peer),
            default="unavailable") or "unavailable"


class CallBridge:
    """One call manager for one `OtrApp`, built on first use.

    Lifecycle-safe by construction: the manager, its loop and its thread are
    created together and torn down together, and `shutdown` is idempotent
    because it is reached from Android lifecycle callbacks that can fire more
    than once.
    """

    #: How long to wait for a synchronous manager call. These are the SHORT
    #: ones -- answering and ending -- which do no tunnel work on the calling
    #: path. `start_call` is never waited for.
    CALL_TIMEOUT = 30.0

    #: How long to wait for a cancelled coroutine to actually stop. Short --
    #: a task that ignores cancellation for this long is not going to honour
    #: it, and teardown has to finish regardless.
    CANCEL_TIMEOUT = 5.0

    def __init__(self, app):
        self._app = app
        self._lock = threading.RLock()
        self._manager = None
        self._loop = None
        self._thread = None
        #: The last state announced per peer, so an event is emitted on a
        #: TRANSITION rather than on every poll. A UI that got an event per
        #: poll would redraw forever and could not tell movement from noise.
        self._announced = {}
        #: When each peer's call became ACTIVE. See `duration_seconds` for
        #: why this is not read off the session object.
        self._active_since = {}
        #: Coroutines handed to the loop and not yet finished. Held so
        #: `shutdown` can cancel them: a `start_call` that is still building
        #: tunnels is not in the manager's `_calls` yet, so ending the calls
        #: would not reach it and stopping the loop underneath it leaves a
        #: pending task and an unawaited coroutine.
        self._pending = set()

    # -- construction ---------------------------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """The call loop, started if it is not running. Caller holds the lock."""
        if self._loop is not None:
            return self._loop
        ready = threading.Event()
        loop = asyncio.new_event_loop()

        def run():
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        thread = threading.Thread(target=run, name="otrv4plus-voice",
                                  daemon=True)
        thread.start()
        ready.wait(timeout=10)
        self._loop, self._thread = loop, thread
        return loop

    def _ensure_manager(self):
        """The call manager, built on first use, or None if voice cannot run.

        Returns None rather than raising: "this device cannot do voice" is an
        answer the UI has to render, not an exception to surface as a crash.
        """
        with self._lock:
            if self._manager is not None:
                return self._manager
            try:
                # Inside the function on purpose -- see the module docstring.
                # Importing the terminal client is what binds `_HOST`, so the
                # Android side gets the same SAM, pipe and opus helpers the
                # terminal client uses instead of a second set.
                import otrv4plus_xmpp                      # noqa: F401
                import otrv4plus_voice as voice
            except Exception:
                return None
            # AFTER that import, which binds the TERMUX codec and
            # availability hooks (opuslib). The APK has its own: see
            # android_bridge.android_audio.
            from . import android_audio
            android_audio.bind(voice)
            loop = self._ensure_loop()
            try:
                self._manager = voice.VoiceCallManager(_VoiceClient(self._app),
                                                       loop)
            except Exception:
                return None
            return self._manager

    # -- availability ---------------------------------------------------------

    def unavailable_reason(self) -> str:
        """Why voice cannot run here, or "" when it can.

        ANDROID'S answer: the APK's codec and AAudio
        (`android_audio.unavailable_reason`), which is also what `bind`
        installs as the hook `start_call` asks -- one answer, not two.

        NOT `otrv4plus_xmpp.voice_available`. That is the Termux client's
        question ("is opuslib installed?") with the Termux remedy, and asking
        it here is what put "opuslib not installed (pip install ...)" on an
        Android conversation screen.
        """
        from . import android_audio
        return android_audio.unavailable_reason()

    # -- the three actions ----------------------------------------------------

    def start_call(self, peer: str) -> str:
        """Place a call. Returns immediately; the tunnel build does not.

        DELIBERATELY NOT AWAITED. `start_call` builds I2P tunnels, which the
        manager itself describes as 30-120 s and longer on a busy phone.
        Waiting for it here would block a Kotlin worker thread for two
        minutes and the UI would have nothing to show in the meantime, which
        is the exact experience the connection screen's staged progress
        exists to avoid.

        Every refusal -- unverified peer, no session, rate limit, no audio
        backend -- stays inside `start_call`, which already decides all of
        them. Its answer comes back as an event.
        """
        manager = self._ensure_manager()
        if manager is None:
            return CallOutcome.UNAVAILABLE
        # The one refusal worth answering synchronously. `start_call` asks
        # the same host hook first thing and would refuse anyway -- but it
        # would do it two frames later, through an event, and "this device
        # cannot do voice" is a permanent fact the button should never have
        # offered. Asked of the hook rather than re-decided here.
        if self.unavailable_reason():
            return CallOutcome.UNAVAILABLE
        if self._app._transport is None:
            # Signalling rides the OTR channel over XMPP. Without a transport
            # the INVITE cannot leave, and a call that silently never rings
            # is worse than a refusal that says why.
            return CallOutcome.NOT_CONNECTED
        if self._live(peer):
            return CallOutcome.ALREADY
        self._submit(manager.start_call(peer), peer, "call_not_placed")
        return CallOutcome.STARTED

    def answer_call(self, peer: str) -> str:
        """Answer a ringing call.

        Refused here only when there is nothing ringing -- the manager's own
        `answer_call` returns silently for a peer with no RINGING session,
        and the UI needs to know the difference between "answered" and
        "there was nothing to answer".
        """
        manager = self._ensure_manager()
        if manager is None:
            return CallOutcome.UNAVAILABLE
        if self.state(peer) is not CallState.RINGING:
            return CallOutcome.NO_CALL
        self._submit(manager.answer_call(peer), peer, "call_not_answered")
        return CallOutcome.STARTED

    def end_call(self, peer: str, notify_peer: bool = True) -> str:
        """End or reject a call. The same verb for both, as the manager has it.

        Rejecting a ringing call and hanging up an active one are one
        operation in the state machine; splitting them here would invent a
        distinction the protocol does not have.
        """
        manager = self._ensure_manager()
        if manager is None:
            return CallOutcome.UNAVAILABLE
        if not self._live(peer):
            return CallOutcome.NO_CALL
        self._submit(manager.end_call(peer, notify_peer), peer,
                     "call_not_ended")
        return CallOutcome.STARTED

    # -- inbound --------------------------------------------------------------

    def handle_signal(self, peer: str, body: str) -> bool:
        """Route one decrypted call control message. True if it was one.

        Called from the bridge's inbound path for any body carrying
        `CALL_PREFIX`. Returning True is what keeps signalling OUT of the
        conversation: before this existed, a peer's `?OTRv4-CALL:INVITE:...`
        was handed to the UI as a chat message and rendered as text.

        The manager validates everything. `parse_signal` is structural only,
        `handle_signal` rate-limits before any work, and `_on_invite` applies
        the SMP gate before a session exists -- so an unverified peer cannot
        make this device ring.
        """
        if not is_call_signal(body):
            return False
        manager = self._ensure_manager()
        if manager is None:
            # Voice cannot run here. Swallowed rather than displayed: the
            # peer's control message is still not a message, and showing it
            # would put protocol text in the conversation.
            return True
        self._submit(manager.handle_signal(peer, body), peer, "call_signal_failed")
        return True

    # -- state ----------------------------------------------------------------

    def state(self, peer: str) -> CallState:
        """This peer's call state, read from the live session.

        Read rather than cached. The manager mutates `session.state` through
        a validated transition table and publishes no callback, so a cache
        here would be a second copy of the truth that could only ever be
        staler than the first.
        """
        manager = self._manager
        if manager is None:
            return CallState.IDLE
        session = manager._calls.get(self._bare(peer))
        if session is None:
            return CallState.IDLE
        return call_state_from_engine(getattr(session, "state", "IDLE"))

    def duration_seconds(self, peer: str) -> int:
        """How long this call has been ACTIVE, or 0.

        MEASURED FROM THE TRANSITION INTO ACTIVE, not from the session
        object. `VoiceCallSession._call_t0` is set in its constructor -- it
        is the frame-timestamp origin, and the manager's own call summary
        uses it for the WHOLE call's length, correctly. Using it for a live
        on-screen timer would be wrong in a way the user would see: the
        tunnel build is 30-120 s, so the moment a call connected the timer
        would already read a minute and a half of talking that never
        happened.

        Zero until the call is actually up, so dialling is never presented as
        talking. Recorded by [poll], which is already watching for exactly
        this transition.
        """
        started = self._active_since.get(self._bare(peer))
        if not started:
            return 0
        return max(0, int(_monotonic() - started))

    def poll(self) -> None:
        """Emit an event for any peer whose call state moved.

        The manager has no state callback, so movement is noticed by reading.
        Called from the bridge's existing drain, so there is one place the UI
        learns about anything and no second observer to leak.

        Emitted on a TRANSITION only. A peer whose state has not moved
        produces nothing, so a poll loop does not become an event flood.
        """
        manager = self._manager
        if manager is None:
            return
        seen = set()
        for peer in list(getattr(manager, "_calls", {}).keys()):
            seen.add(peer)
            state = self.state(peer)
            # The clock starts on the transition INTO active and stops on the
            # way out, so it measures conversation rather than tunnel build.
            if state is CallState.ACTIVE:
                self._active_since.setdefault(peer, _monotonic())
            else:
                self._active_since.pop(peer, None)
            if self._announced.get(peer) is state:
                continue
            self._announced[peer] = state
            self._app._emit(CallStateChanged(
                peer=peer, state=state,
                duration_seconds=self.duration_seconds(peer)))
        # A peer whose session has gone entirely is IDLE now, and the UI has
        # to be told once. Without this the last state announced for a
        # finished call stays on the screen.
        for peer in [p for p in self._announced if p not in seen]:
            self._active_since.pop(peer, None)
            if self._announced[peer] is not CallState.IDLE:
                self._announced[peer] = CallState.IDLE
                self._app._emit(CallStateChanged(peer=peer,
                                                 state=CallState.IDLE))

    # -- teardown -------------------------------------------------------------

    def shutdown(self) -> None:
        """End every call and give the loop back. Safe to call twice.

        Reached from `OtrApp.shutdown`, which a logout drives, so a second
        call must be harmless. Ending the calls FIRST matters: the manager
        owns SAM sessions and audio devices, and dropping the loop from under
        it would leave an I2P lease and an open microphone belonging to an
        account that has signed out.
        """
        with self._lock:
            manager, self._manager = self._manager, None
            loop, self._loop = self._loop, None
            thread, self._thread = self._thread, None
            pending, self._pending = set(self._pending), set()
            self._announced.clear()
            self._active_since.clear()
        if manager is not None and loop is not None and not loop.is_closed():
            for peer in list(getattr(manager, "_calls", {}).keys()):
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        manager.end_call(peer, notify_peer=True), loop)
                    future.result(timeout=self.CALL_TIMEOUT)
                except Exception:
                    # Teardown is best effort. A call that will not end
                    # cleanly must not stop the rest of the sign-out.
                    pass
        # THEN THE AUTHORITATIVE PASS. A graceful end can time out or raise,
        # and "best effort" is not good enough for the keys: whatever is still
        # in the table is force-closed synchronously, which stops the audio
        # streams and zeroizes the key schedule and any key exchange -- the
        # same routine the terminal client runs when its loop is already gone.
        if manager is not None:
            try:
                manager.cleanup_sync()
            except Exception:
                pass
        # Anything still in flight -- most likely a `start_call` part way
        # through a tunnel build -- is cancelled before the loop stops.
        # Stopping the loop with a task still pending leaves the coroutine
        # unawaited and the task destroyed mid-flight, which is a warning at
        # best and a leaked SAM session at worst.
        #
        # CANCELLED AND THEN WAITED FOR. `Future.cancel` only REQUESTS it:
        # the task learns at its next await point, and stopping the loop
        # before it gets there is the same abandonment cancelling was meant
        # to avoid. Bounded, because teardown must finish either way.
        if pending and loop is not None and not loop.is_closed():
            # ONE TURN OF THE LOOP FIRST. `run_coroutine_threadsafe` only
            # SCHEDULES; until the loop picks the callback up there is no
            # task, and cancelling then discards the coroutine without ever
            # awaiting it. Scheduling a trivial coroutine after the others
            # and waiting for it guarantees the loop has adopted them all,
            # so the cancellations below reach real tasks.
            try:
                asyncio.run_coroutine_threadsafe(
                    _noop(), loop).result(timeout=self.CANCEL_TIMEOUT)
            except Exception:
                pass
        for future in pending:
            future.cancel()
        # AND THEN WAIT FOR THE LOOP, not for the wrappers.
        #
        # `run_coroutine_threadsafe` hands back a `concurrent.futures.Future`
        # that becomes CANCELLED the moment `cancel()` is called, while the
        # asyncio task it stands for is still unwinding -- so waiting on the
        # wrapper returns immediately and the loop is stopped out from under
        # a task that is mid-cancellation. Draining the loop's own tasks is
        # what actually waits.
        if loop is not None and not loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    _drain(), loop).result(timeout=self.CANCEL_TIMEOUT)
            except Exception:
                # Bounded on purpose: a call that will not let go must not
                # hold up the sign-out.
                pass
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=5)
        # AND CLOSED. Stopping a loop does not release it: its selector and
        # self-pipe stay open until somebody calls `close`, and until this
        # line nobody did -- the loop was left for the garbage collector,
        # which reported it as "Exception ignored in BaseEventLoop.__del__".
        # One leaked pipe pair per sign-out. Only once the thread has
        # actually finished: closing a loop that is still running raises.
        if (loop is not None and not loop.is_closed()
                and (thread is None or not thread.is_alive())):
            try:
                loop.close()
            except Exception:
                pass

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _bare(peer: str) -> str:
        """The manager keys its calls by bare JID and folds with `_bare`.

        `OtrApp.canonical_peer` folds harder -- it case-folds too, per INV-27
        -- so this deliberately matches the MANAGER's key rather than the
        bridge's, because this is a lookup into the manager's own dict.
        """
        return (peer or "").split("/", 1)[0]

    def _live(self, peer: str) -> bool:
        return self.state(peer) not in (CallState.IDLE, CallState.ENDED)

    def _submit(self, coro, peer: str, error_code: str) -> None:
        """Run a manager coroutine on the call loop, reporting a failure once.

        Fire and forget with a done-callback, never a blocking wait: the
        coroutines here range from instant to a two-minute tunnel build, and
        the caller is a Kotlin worker thread that must come back.
        """
        loop = self._loop
        if loop is None or loop.is_closed():
            coro.close()
            self._app._emit(ErrorOccurred(peer=peer, code=error_code))
            return

        def done(future):
            try:
                result = future.result()
            except Exception:
                # The manager logs its own reason through the host print
                # hook. What reaches the UI is a CODE -- engine exception
                # text is not something this bridge puts on a screen.
                self._app._emit(ErrorOccurred(peer=peer, code=error_code))
                return
            # `start_call` answers False for every refusal it decides:
            # unverified peer, no session, rate limit, no audio backend.
            if result is False:
                self._app._emit(ErrorOccurred(peer=peer, code=error_code))

        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except Exception:
            coro.close()
            self._app._emit(ErrorOccurred(peer=peer, code=error_code))
            return
        self._pending.add(future)
        future.add_done_callback(self._pending.discard)
        future.add_done_callback(done)


async def _noop() -> None:
    """A turn of the loop, used only to flush scheduled work. See shutdown."""
    return None


async def _drain() -> None:
    """Wait for every other task on this loop to finish unwinding.

    Runs ON the loop, so `all_tasks` sees the real tasks rather than the
    thread-safe wrappers around them -- which is the whole point: a cancelled
    wrapper reports done while its task is still cancelling.
    """
    others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if not others:
        return
    await asyncio.wait(others, timeout=CallBridge.CANCEL_TIMEOUT)


def is_call_signal(body: Any) -> bool:
    """Whether a decrypted body is call signalling rather than a message.

    The prefix is read from `otrv4plus_voice` when it is already imported and
    matched against the constant otherwise, so this never becomes a second
    definition of the wire format that could drift from the first.
    """
    if not isinstance(body, str):
        return False
    import sys
    module = sys.modules.get("otrv4plus_voice")
    prefix = getattr(module, "CALL_PREFIX", None) if module else None
    return body.startswith(prefix or CALL_PREFIX_FALLBACK)


#: Used only before `otrv4plus_voice` has been imported. Kept identical to it
#: and asserted equal by `tests/test_android_calls.py`, so the two cannot
#: drift into disagreeing about what a call signal looks like.
CALL_PREFIX_FALLBACK = "?OTRv4-CALL:"
