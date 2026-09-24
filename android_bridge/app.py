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
import threading
import time
from dataclasses import dataclass
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional

# The shared wire format. A dependency-free leaf, which is why importing it at
# module scope does not breach the transport boundary from 22fc255 -- see
# tests/test_android_transport.py::test_any_shared_module_it_imports_is_a_leaf.
# Both clients classify and fragment
# with this module and nothing has a second copy.
import otrv4plus_fragment as _fragment

from .trace import TRACE as _TRACE
from .files import FileBridge, FileOutcome, is_file_signal
from .voice import CallBridge, CallOutcome, is_call_signal
import otrv4plus_presence as _presence
from otrv4plus_mode import OtrMode

from .events import (
    CallState, CallStateChanged, ConnectionState, ConnectionStateChanged,
    ErrorOccurred, Event, EventSink, FingerprintChanged, MessageReceived,
    RoomMessageReceived,
    SecurityState, SessionStateChanged, SmpProgress, SmpResult, SmpState,
    call_state_from_engine, security_state_from_level, smp_state_from_status,
)

__all__ = ["OtrApp", "Transport", "ContactView", "SecurityDetails",
           "redacting_logger", "BridgeError"]



#: The trade control prefix, read from `otrv4plus_trade` when it is loaded.
#:
#: Kept as a constant rather than importing the module: trade is not wired up
#: on Android, and importing a twelve-thousand-line dependency to recognise a
#: twelve-character prefix would be paying for a feature this build does not
#: have. Asserted equal to the real one by `tests/test_android_files.py`.
TRADE_PREFIX_FALLBACK = "?OTRv4-TRADE:"


def _is_trade_signal(body: Any) -> bool:
    """Whether a decrypted body is trade signalling rather than a message."""
    if not isinstance(body, str):
        return False
    import sys
    module = sys.modules.get("otrv4plus_trade")
    prefix = getattr(module, "TRADE_PREFIX", None) if module else None
    return body.startswith(prefix or TRADE_PREFIX_FALLBACK)


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
    #: One of otrv4plus_presence.STATES: "unknown", "online", "offline".
    #:
    #: The field that replaced a bare `online: bool`. That bool could not say
    #: "we have not heard", so a freshly added contact was reported offline and
    #: the UI -- correctly refusing to claim knowledge it did not have --
    #: rendered "presence unknown" forever.
    presence: str
    security: SecurityState
    smp: SmpState
    last_activity: Optional[float] = None
    call_available: bool = False
    #: RFC 6121 show: "", "away", "chat", "dnd", "xa". Empty unless online.
    presence_show: str = ""
    #: The XMPP roster subscription, verbatim: "none", "to", "from", "both",
    #: or "" when the roster did not say.
    #:
    #: Carried because a contact you have added but who has not yet approved
    #: you is a REAL and common state, and one the user has to be able to see:
    #: their presence will read as unknown for hours or days, and "the app is
    #: broken" is the wrong conclusion to leave available. It was being read
    #: from the roster and then dropped here.
    subscription: str = ""
    #: Whether we have asked and not yet been answered. slixmpp exposes this
    #: separately from `subscription`, because a pending request does not
    #: change the subscription until it is approved.
    pending: bool = False

    @property
    def online(self) -> bool:
        """Kept for callers that genuinely want a boolean.

        DERIVED, never stored: a second field would be a second thing to keep
        in step, and disagreeing with `presence` is exactly the failure this
        replaced. False covers both OFFLINE and UNKNOWN, so anything that has
        to tell those apart must read `presence`.
        """
        return self.presence == _presence.ONLINE


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
        #: What we know about each peer's availability, and when we know
        #: nothing. A PresenceBook rather than a dict of bools because
        #: `.get(jid, False)` cannot tell "offline" from "never heard" -- see
        #: otrv4plus_presence for the bug that produced.
        self._presence = _presence.PresenceBook()
        #: When we last saw traffic with each peer, for the contact row's
        #: "last seen". Ordered and bounded -- see `_touch`.
        self._last_activity: "OrderedDict[str, float]" = OrderedDict()
        # Which conversations have had OTR asked for. Never a security state;
        # see otrv4plus_mode.OtrMode.
        self._mode = OtrMode()
        self._call_states: Dict[str, CallState] = {}
        #: Built on the first call-related action, never at construction: see
        #: `android_bridge.voice` for why loading the voice stack is deferred.
        self._calls_bridge: Optional["CallBridge"] = None
        #: Same deferral, same reason: the transfer engine pulls in the Rust
        #: core, and a device that never sends a file never loads it.
        self._files_bridge: Optional["FileBridge"] = None
        #: Rooms this session is in (canonical JIDs). A room is not a peer:
        #: its text goes out as plaintext group chat and it never gets an OTR
        #: session, SMP, a call or a file. See `note_room_joined`.
        self._rooms: set = set()
        #: Set by `wipe` and never cleared. See `wipe` for what it refuses.
        self._wiped = False
        self._wipe_lock = threading.Lock()
        self._enable_guided_smp()

    #: How many peers' last-seen times to keep.
    #:
    #: BOUNDED BECAUSE THE KEY IS CHOSEN BY SOMEBODY ELSE. `receive_message`
    #: records one for every inbound frame, under the sender's JID, so an
    #: unbounded map is a memory-growth path a remote party drives. Measured
    #: before the bound: twenty thousand distinct senders, twenty thousand
    #: entries, nothing reclaimed. `otrv4+.py`'s `DAKE1RateLimiter` bounds
    #: itself for the same reason and this matches it rather than inventing a
    #: second answer.
    #:
    #: Far above any real contact list, so only a flood reaches it, and what
    #: is lost when it does is a "last seen" caption -- never a security
    #: state, a session or a trust decision, none of which are kept here.
    MAX_TRACKED_ACTIVITY = 2048

    def _touch(self, peer: str) -> None:
        """Record that we just exchanged something with *peer*.

        The single write point for `_last_activity`, so the bound cannot be
        bypassed by a future call site that assigns to the map directly.
        Eviction is least-recently-active, which is what the value already
        means.
        """
        self._last_activity[peer] = self._clock()
        self._last_activity.move_to_end(peer)
        while len(self._last_activity) > self.MAX_TRACKED_ACTIVITY:
            self._last_activity.popitem(last=False)

    def _enable_guided_smp(self) -> None:
        """Declare that this front end CAN ask the user for a passphrase.

        THE DEFECT THIS FIXES, AND IT MADE THE WHOLE RESPONDER PATH DEAD
        ----------------------------------------------------------------
        `EnhancedSessionManager.smp_guided_prompt` defaults to False, and its
        own comment says what that means:

            "False means the old behaviour: an SMP1 with no secret is aborted
             with a reason, because a front end that cannot ask must not leave
             the peer waiting for an answer that will never come."

        Both terminal clients set it to True -- `otrv4plus_xmpp.py:1727` and
        `otrv4_.py:14684`. NOTHING IN android_bridge EVER DID. So on Android
        an arriving SMP1 with no stored passphrase took the abort branch, and
        every piece of the responder flow downstream was unreachable:

          * the core never called `hold_smp1`, so nothing was parked;
          * `get_phase()` never returned SECRET_REQUIRED;
          * `smp_secret_required()` was permanently False;
          * `_announce_smp_change` therefore never fired for an incoming
            request, so no prompt could open;
          * `smp_respond` would refuse with `smp_not_requested`.

        Measured, not deduced. Two real `EnhancedSessionManager`s with a real
        DAKE, one SMP1 delivered:

            guided=False -> replied=True   secret_required=False  phase=IDLE
            guided=True  -> replied=False  secret_required=True   phase=SECRET_REQUIRED

        A LATENT DEFECT THE UNIT TESTS COULD NOT SEE. The fake engine answered
        `smp_secret_required` from a flag the test set, so it agreed with
        whatever the test wanted. That is the fourth time in this project a
        fake has encoded the same assumption as the code it stood in for --
        after `connect(address=...)`, the SSL context, and `RosterItem.get`.
        `tests/test_smp_android_interop.py` drives the real engine instead.

        WHY HERE AND NOT IN `ChaquopyOtrCore.initialize`. Setting it in Kotlin
        would work and would be invisible to every Python test. The flag is a
        claim about the FRONT END -- "this one can ask" -- and `OtrApp` is the
        front end's entire contract with the engine. Anything holding an
        OtrApp has the dialog, so anything holding an OtrApp can ask.

        Tolerant of an engine that has no such attribute: `smp_engine_compat`
        exists because this project supports builds that predate a call, and
        an engine without the flag is one that cannot park an SMP1 anyway.
        """
        try:
            self._engine.smp_guided_prompt = True
        except Exception:
            _log.debug("engine does not accept smp_guided_prompt")

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
        if sink is None or self._wiped:
            # After a wipe nothing reaches the UI: no late message, no state
            # change from a frame that was in flight, nothing a screen could
            # render about sessions that no longer exist.
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
        """Tear down every session.  Safe to call more than once.

        THE CALLS GO FIRST, and the order is not cosmetic. A live call holds
        a SAM session, an I2P lease and an open microphone, and its signalling
        rides the OTR session this is about to destroy -- so ending the calls
        after the sessions would mean the END the peer is owed can no longer
        be encrypted, and they would sit on a call nobody is on.
        """
        if self._calls_bridge is not None:
            try:
                self._calls_bridge.shutdown()
            except Exception:
                _log.warning("call teardown reported a problem")
            self._calls_bridge = None
        if self._files_bridge is not None:
            try:
                self._files_bridge.shutdown()
            except Exception:
                _log.warning("transfer teardown reported a problem")
            self._files_bridge = None
        try:
            self._engine.clear_all_sessions("shutdown")
        except Exception:
            _log.warning("session teardown reported a problem")
        self.disconnect()

    @property
    def wiped(self) -> bool:
        return self._wiped

    # -- rooms -----------------------------------------------------------------

    def note_room_joined(self, room: str) -> None:
        """We are in [room]: its text is group chat from now on."""
        self._rooms.add(self.canonical_peer(room))

    def note_room_left(self, room: str) -> None:
        self._rooms.discard(self.canonical_peer(room))

    def forget_rooms(self) -> None:
        """The stream went; so did every room membership it carried."""
        self._rooms.clear()

    def is_room(self, peer: str) -> bool:
        return self.canonical_peer(peer) in self._rooms

    def joined_room_list(self) -> List[str]:
        return sorted(self._rooms)

    def _refuse_room(self, peer: str, code: str) -> None:
        """Rooms get no OTR, no SMP, no calls and no files.

        OTR is a two-party protocol: a DAKE sent into a room would be read by
        every occupant and answered by none of them, or by the wrong one.
        """
        if peer in self._rooms:
            raise BridgeError(code, "rooms are not end-to-end encrypted")

    def receive_room_message(self, room: str, nick: str, body: str,
                             timestamp: float = 0.0) -> None:
        """A room message from the transport. Emitted as its own event type,
        never as `MessageReceived`: nothing downstream may confuse a room's
        plaintext with a peer's decrypted text."""
        room = self.canonical_peer(room)
        if room not in self._rooms:
            return
        self._emit(RoomMessageReceived(peer=room, sender=nick, body=body,
                                       timestamp=timestamp))

    def wipe(self) -> Dict[str, Any]:
        """Wipe & Exit, Python side. Idempotent; the app is spent afterwards.

        NOT `shutdown` with more steps. `shutdown` is a logout: sessions end,
        the facade stays usable for the next account, and pinned fingerprints
        survive. This destroys, and refuses to be used again.

        THE ORDER, and why each step is where it is:

          1. Refuse. `_wiped` is set first, so from here no event reaches the
             UI (`_emit`) and no call or transfer bridge can be rebuilt
             (`calls`, `files`, and the methods on them). The engine refuses
             in its own right once step 4 runs.
          2. Calls. They hold a microphone, a SAM session and media keys, and
             their END rides the OTR session step 4 destroys -- so they go
             while it still exists. `CallBridge.shutdown` ends each call, then
             force-closes whatever is left, which zeroizes the key schedule;
             then it drains, stops and CLOSES its event loop.
          3. Transfers. Each FileKey holder is told to zeroize and each
             partial file is closed and unlinked, before the session is gone.
          4. The engine, ON THE TRANSPORT'S LOOP THREAD. `DakeOutput` is
             unsendable and is created while an inbound frame is processed,
             which happens there; dropped from any other thread it would leak
             un-zeroized. `EnhancedSessionManager.wipe` zeroizes every
             ratchet, SMP state, vault, handshake and the identity handles in
             Rust, then refuses all further use.
          5. The transport. `close`, not `disconnect`: the XMPP stream, the
             I2P tunnel and the loop thread all go, and the object is spent.
          6. What this facade remembered: presence, last activity, the OTR
             mode, call states.
          7. Disk. Everything the Python side persists -- see
             `android_bridge.wipe` for exactly what that is on Android, and
             what an overwrite on flash does and does not achieve.

        Returns counts for the caller's report. Never raises: a step that
        fails is recorded and the rest still run, because a wipe that stops
        at the first problem is worse than one that reports it.
        """
        with self._wipe_lock:
            already = self._wiped
            self._wiped = True
        report: Dict[str, Any] = {"already_wiped": already, "errors": []}

        calls, self._calls_bridge = self._calls_bridge, None
        if calls is not None:
            try:
                calls.shutdown()
            except Exception:
                report["errors"].append("calls")
        files, self._files_bridge = self._files_bridge, None
        if files is not None:
            try:
                files.shutdown()
            except Exception:
                report["errors"].append("transfers")

        engine_wipe = getattr(self._engine, "wipe", None)

        def _wipe_engine():
            if engine_wipe is not None:
                return engine_wipe("wipe and exit")
            self._engine.clear_all_sessions("wipe and exit")
            return {}

        transport = self._transport
        runner = getattr(transport, "run_on_loop_thread", None)
        try:
            counts = runner(_wipe_engine) if runner is not None else _wipe_engine()
        except Exception:
            # The loop could not run it (stopped mid-teardown, timed out).
            # Here, then: an output made on that thread may leak rather than
            # zeroize, which is worse than the right thread and far better
            # than leaving every session alive.
            report["errors"].append("engine_off_thread")
            try:
                counts = _wipe_engine()
            except Exception:
                report["errors"].append("engine")
                counts = {}
        report.update({k: v for k, v in (counts or {}).items()
                       if k != "already_wiped"})

        self._transport = None
        if transport is not None:
            closer = getattr(transport, "close", None) or transport.disconnect
            try:
                closer()
            except Exception:
                report["errors"].append("transport")
        self._connection = ConnectionState.DISCONNECTED

        self._presence.forget_all()
        self._last_activity.clear()
        self._mode = OtrMode()
        self._call_states.clear()

        from . import wipe as _disk
        destroyed = failed = 0
        for root in _disk.python_state_roots():
            d, f = _disk.destroy_tree(root)
            destroyed += d
            failed += f
        report["files_destroyed"] = destroyed
        report["files_unlinked_only"] = failed
        self._sink = None
        return report

    @staticmethod
    def canonical_peer(peer: str) -> str:
        """One contact, one key, however their address is spelled.

        WHY THIS EXISTS, AND IT IS NOT TIDINESS
        ---------------------------------------
        Every per-peer thing this facade owns is keyed by the string it was
        handed: `OtrMode` (whether a conversation may send in the clear), the
        presence book, last-activity, call state, and -- through the engine --
        the session table itself. Two spellings of one contact are two
        entries.

        That is a downgrade, not an inconvenience. Measured before this
        existed, after OTR had been requested for `bob@x.test`:

            may_send_plaintext(bob@x.test       ) = False
            may_send_plaintext(Bob@X.test       ) = True   <-- LEAK
            may_send_plaintext(bob@x.test/phone ) = True   <-- LEAK

        And it is reachable. slixmpp normalises an inbound stanza's `from`,
        so a PEER starting OTR marks the mode under `bob@x.test`; the Android
        UI's conversation key is whatever was typed into Add Contact, which
        `ChatState.bare` stripped of its resource but did not case-fold. Send
        into that conversation and the mode lookup misses -- so a message
        goes out in the clear on a conversation the other side has encrypted.

        DONE HERE, at the boundary, for the same reason `DAKE1RateLimiter`
        does it in the limiter rather than at its call sites: a future caller
        that forgets cannot split state, and one place cannot drift from
        eighteen. Folding is always the safe direction -- it can only merge
        two keys into one, never turn one into two.

        Matches how the rest of the project identifies a peer:
        `msg["from"].bare` in the XMPP client, `split("/", 1)[0]` in the
        Android transport, `AccountScope.normalise` and `ChatState.bare` in
        Kotlin, and `DAKE1RateLimiter._canonical` in the engine.

        A value that is not a JID is returned trimmed and folded rather than
        rejected: this is a key normaliser, not a validator, and refusing
        here would turn a malformed peer into an exception on a path that
        already has honest answers for one.
        """
        return str(peer or "").strip().split("/", 1)[0].casefold()

    def note_connected(self) -> None:
        """Called by the transport once the stream is usable."""
        self._connection = ConnectionState.CONNECTED
        self._emit(ConnectionStateChanged(state=ConnectionState.CONNECTED))

    def note_presence(self, peer: str, online: bool, show: str = "") -> None:
        """A presence stanza arrived. Called from the transport's loop thread."""
        peer = self.canonical_peer(peer)
        self._presence.note(peer, online, show)

    def note_presence_lost(self) -> None:
        """The stream went. Everything we knew about availability goes too.

        Availability is knowledge about a peer ON A STREAM: once it dies the
        server stops telling us about changes, so anything retained is a claim
        about the past presented as the present. Without this a contact who
        went offline during a reconnect kept reading ONLINE until they next
        sent a stanza.
        """
        self._presence.forget_all()

    def forget_peer_state(self, peer: str) -> None:
        """Drop what a subscription entitled us to know about one peer.

        Called when the ROSTER ENTRY GOES, not when the stream does.
        `PresenceBook.forget` has documented this since it was written --
        "what we learned under a subscription we no longer hold is not
        something we are entitled to keep showing" -- and until now it had no
        caller at all. Measured before it did:

            before remove: presence=online last_activity=True
            remove_contact: {'ok': True, ...}
            after remove : presence=online last_activity=True

        So a contact the user had just removed went on reading as online,
        indefinitely, from a subscription that no longer existed.

        WHAT IS DELIBERATELY LEFT ALONE
        -------------------------------
        The OTR session, the trust database and the message history. None of
        those came from the subscription:

          * a pinned fingerprint is long-term identity about a PEER, and
            dropping it would turn the next conversation into a fresh
            trust-on-first-use decision -- the moment this project most wants
            to be visible;
          * history outlives the roster entry, because deleting what was said
            because somebody was unsubscribed destroys data the user did not
            ask to lose;
          * a live encrypted session is not made less safe by the roster
            changing, and tearing it down mid-conversation would be a
            surprise, not a protection.

        This drops availability and last-seen: the two things the server was
        telling us only because we were subscribed.
        """
        peer = self.canonical_peer(peer)
        if not peer:
            return
        self._presence.forget(peer)
        self._last_activity.pop(peer, None)

    def presence_state(self, peer: str) -> str:
        """One of otrv4plus_presence.STATES."""
        peer = self.canonical_peer(peer)
        return self._presence.state(peer)

    def online_peers(self) -> List[str]:
        """Peers currently believed available. For the discovery view."""
        return list(self._presence.online())

    @property
    def connection_state(self) -> ConnectionState:
        return self._connection

    # -- security state --------------------------------------------------------

    def security_state(self, peer: str) -> SecurityState:
        """The engine's view of this peer, or PLAINTEXT if it cannot answer.

        GUARDED, and this is not defensive decoration. It is called from
        `contacts()` for every roster entry on every UI poll -- twice a second
        -- and from `receive_message` for every inbound frame. Unguarded, a
        single raise from the engine propagated all the way out of
        `contacts()`, which on the Android side discarded the entire poll and
        left the screen asserting "Not connected" about a live stream. Every
        neighbour here (`smp_state`, `smp_progress`, `security_details`) was
        already guarded; this one was not, and the omission looks accidental.

        PLAINTEXT is the fail-safe direction and the only defensible one: a
        state we could not read must never be rendered as more secure than it
        is. `security_state_from_level` already takes that position for an
        unrecognised level; this extends it to an engine that raised.
        """
        peer = self.canonical_peer(peer)
        try:
            return security_state_from_level(
                self._engine.get_security_level(peer))
        except Exception:
            return SecurityState.PLAINTEXT

    def smp_state(self, peer: str) -> SmpState:
        """This peer's verification state.

        An engine that raises reports NOT_VERIFIED, which is the safe
        direction: a state we could not read must never be shown as VERIFIED.
        """
        peer = self.canonical_peer(peer)
        try:
            return smp_state_from_status(self._engine.get_smp_status(peer))
        except Exception:
            return SmpState.NOT_VERIFIED

    def smp_secret_required(self, peer: str) -> bool:
        """Whether a peer's SMP1 is held by the core, waiting for our answer.

        The SAME predicate both terminal clients use -- `otrv4+.py:9669` on
        EnhancedSessionManager, which reads `RustSMP.get_phase() ==
        "SECRET_REQUIRED"`. Not a second notion of "a request is pending":
        there is one, it lives in Rust, and this asks it.

        A manager without the method answers False rather than raising. That
        is not defensive padding -- `smp_engine_compat` exists because this
        project supports engine builds that predate a call, and reporting
        "nobody is waiting on you" is the correct answer from an engine that
        cannot hold an SMP1 in the first place.
        """
        peer = self.canonical_peer(peer)
        ask = getattr(self._engine, "smp_secret_required", None)
        if ask is None:
            return self.smp_state(peer) is SmpState.SECRET_REQUIRED
        return bool(self._safe(lambda: ask(peer), default=False))

    def smp_progress(self, peer: str) -> SmpProgress:
        """Drives the verification progress UI.

        SMP takes minutes on mobile -- a 50,000-round SHAKE-256 chain plus
        3072-bit work, ~1 minute measured over XMPP/I2P -- so this is a real
        progress indicator, not a spinner.
        """
        peer = self.canonical_peer(peer)
        try:
            step, total = self._engine.get_smp_progress(peer)
        except Exception:
            step, total = 0, 4
        return SmpProgress(peer=peer, step=int(step), total=int(total),
                           state=self.smp_state(peer))

    def security_details(self, peer: str) -> SecurityDetails:
        peer = self.canonical_peer(peer)
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
            # Per entry, because losing the whole contact list to one awkward
            # peer is how a working roster renders as an empty screen.
            try:
                view = self._contact_view(entry)
            except Exception:
                continue
            if view is not None:
                out.append(view)
        return out

    def _contact_view(self, entry) -> Optional[ContactView]:
        """One roster entry as the UI sees it, keyed canonically.

        THE JID IS CANONICALISED HERE, and the raw spelling is not kept. This
        method reads two maps DIRECTLY -- `self._presence` and
        `self._last_activity` -- rather than through the public accessors that
        canonicalise for it, and both of those maps are WRITTEN under
        `canonical_peer` keys by `note_presence`, `receive_message` and
        `send_message`. A roster entry spelled any other way therefore missed
        its own state. Measured, with a session live and a message just in:

            roster entry jid emitted : 'Bob@Example.TEST'
            presence for that row    : unknown            <-- it is known
            last_activity for the row: None               <-- one just arrived
            internal presence keys   : ['bob@example.test']

        Worse than the blank fields: `jid` is the key the whole UI then uses,
        so the Kotlin side got a contact row under one spelling while its
        message history sat under another, and `conversations()` -- which
        unions the roster with the message store -- showed the person twice.

        slixmpp normalises the roster it hands us, so this is not reachable
        through the live XMPP path today; it is reachable through any other
        `Transport`, and the split it produces is the same one
        `canonical_peer` exists to prevent. One contact, one key, at the only
        place a JID enters this class from outside.
        """
        jid = entry.get("jid") if isinstance(entry, dict) else str(entry)
        if not jid:
            return None
        jid = self.canonical_peer(jid)
        if not jid:
            return None
        security = self.security_state(jid)
        subscription = ""
        pending = False
        if isinstance(entry, dict):
            subscription = str(entry.get("subscription") or "")
            pending = bool(entry.get("pending"))
        return ContactView(
            jid=jid,
            display_name=(entry.get("name") if isinstance(entry, dict) else None) or jid,
            presence=self._presence.state(jid),
            presence_show=self._presence.show(jid),
            subscription=subscription,
            pending=pending,
            security=security,
            smp=self.smp_state(jid),
            last_activity=self._last_activity.get(jid),
            # Calls are gated on cryptographic verification by the engine
            # (VoiceCallManager._smp_verified).  This flag is for enabling a
            # button, and must never be treated as the gate itself.
            call_available=security is SecurityState.SMP_VERIFIED,
        )

    # -- messaging -------------------------------------------------------------

    def start_session(self, peer: str) -> None:
        """Begin the DAKE.  Completes in roughly 20s over XMPP/I2P.

        This is the EXPLICIT request, and from here on nothing in this
        conversation goes out in the clear -- including if the handshake
        fails, because a failed handshake is not consent to continue without
        one.

        THE DEFECT THIS FIXES
        ---------------------
        It used to read

            payload = self._safe(
                lambda: self._engine.handle_outgoing_message(peer, ""))

        and then never mention `payload` again. The engine produced DAKE1 --
        correctly, every time -- and this method dropped it on the floor.
        Nothing was ever handed to the transport, so no stanza left the
        device.

        On a handset that was: tap OTRv4+, no visible change, no DAKE, and
        nothing at all arriving at the other end. Every layer above reported
        success, because every layer above HAD succeeded: the tap ran, the
        launcher ran, the provider ran, Python ran, a session was created and
        `SessionStateChanged` was emitted. The only thing that did not happen
        was the send.

        The terminal client has always done this properly, and its comment is
        the one that applies here:

            "OK is reported from the result of the send, not from having
             attempted it: a DAKE1 that never left the socket is not a
             completed stage."

        `handle_outgoing_message` returns `(payload, should_send)`, which is
        why assigning it to a single name and reading it as a payload was easy
        to miss -- the tuple is truthy either way.

        Fragmentation is the transport's, not ours: `XmppTransport._send`
        splits on `otrv4plus_fragment.MAX_FRAGMENT`, which exists because a
        DAKE2 is ~11.7 KB after base64 and goes straight at the ~8 KB I2P
        cliff.
        """
        peer = self.canonical_peer(peer)
        self._refuse_room(peer, 'room_not_encryptable')
        if self._transport is None:
            raise BridgeError("no_transport")

        # BEFORE the send, and deliberately. From here this conversation is
        # OTR-requested, so a failure below leaves it refusing plaintext
        # rather than quietly reverting -- a failed handshake is not consent
        # to continue without one.
        self._mode.request(peer)
        _TRACE.record("otr", "dake_requested", "info", jid=peer)

        # NOT `self._safe`. An engine that RAISES here and an engine that
        # DECLINES to produce DAKE1 are different answers, and swallowing the
        # first into the second would send an OTR query on behalf of an engine
        # that is in an unknown state.
        try:
            result = self._engine.handle_outgoing_message(peer, "")
        except Exception as exc:
            _TRACE.record_exception("otr", "dake_generate_failed", exc, jid=peer)
            raise BridgeError("dake_generate_failed",
                              "the handshake could not be built")

        try:
            self._engine.get_or_create_session(peer, is_initiator=True)
        except Exception as exc:
            _TRACE.record_exception("otr", "session_start_failed", exc, jid=peer)
            raise BridgeError("session_start_failed")

        # `(payload, should_send)`. An engine that hands back something else
        # is treated as having declined, not as a payload: a 2-tuple is truthy
        # either way, which is exactly how the original defect hid.
        payload, should_send = None, False
        try:
            payload, should_send = result
        except (TypeError, ValueError):
            pass

        if payload and should_send:
            outbound, stage = payload, "dake_sent"
            _TRACE.record("otr", "dake_generated", "info", jid=peer,
                          length=len(payload))
        else:
            # NOT AN ERROR, and the first version of this fix got that wrong.
            #
            # The engine declines to produce DAKE1 when a handshake is already
            # in flight or a session exists. The terminal client's `else`
            # branch sends the OTR QUERY here -- `?OTRv4 ` -- which invites the
            # peer to begin one, and `test_android_chat_ux` already pins that
            # `start_session` must not raise in this state (a mid-handshake
            # send reports QUEUED, not failed).
            #
            # Raising instead broke three of those tests, which is how the
            # over-strictness was caught. Doing nothing would be worse: the
            # user asked for encryption and nothing would leave the device.
            outbound, stage = _fragment.OTR_PREFIX, "query_sent"
            _TRACE.record("otr", "dake_not_produced", "info", jid=peer,
                          produced=bool(payload),
                          should_send=bool(should_send))

        try:
            self._transport.send(peer, outbound)
        except Exception as exc:
            # A DAKE1 that never left the socket is not a completed stage.
            _TRACE.record_exception("otr", "dake_send_failed", exc, jid=peer)
            raise BridgeError("dake_send_failed",
                              "the handshake could not be sent")
        _TRACE.record("otr", stage, "info", jid=peer)

        self._emit(SessionStateChanged(peer=peer, security=self.security_state(peer)))

    def send_message(self, peer: str, body: str) -> bool:
        """Encrypt and send.  Returns whether it went out encrypted.

        Refuses to fall back to plaintext: if the engine reports the message was
        not encrypted, the payload is dropped and an error is raised rather than
        silently leaking the body onto the wire.
        """
        peer = self.canonical_peer(peer)
        self._refuse_room(peer, 'room_not_encryptable')
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
        self._touch(peer)
        return True

    #: What `send_user_text` did. Four outcomes, and each is a different thing
    #: to tell the user. QUEUED is neither success nor failure; PLAINTEXT is a
    #: success that must never be described as a secure one.
    SEND_ENCRYPTED = "encrypted"
    SEND_QUEUED = "queued"
    SEND_FAILED = "failed"
    SEND_PLAINTEXT = "plaintext"

    def send_user_text(self, peer: str, body: str) -> str:
        """Send one typed line the way the terminal client does.

        Returns SEND_ENCRYPTED, SEND_QUEUED or SEND_FAILED.

        WHY THIS EXISTS ALONGSIDE `send_message`
        ----------------------------------------
        `send_message` raises `not_encrypted` when the engine has no session,
        and that behaviour is deliberate and tested -- it is the guarantee that
        this facade never downgrades to plaintext. What it is NOT is an
        accurate report of what happened, because the engine does not discard
        the text: `handle_outgoing_message` returns `should_send=False` and
        keeps it, then flushes it when the DAKE completes. The terminal client
        has always reported that as `[queued] will send once OTR with <peer>
        is ready`.

        So the Android side was treating a normal, expected, recoverable state
        as a send failure. A user typing before a session exists would be told
        their message failed, when in fact it is waiting and will go.

        PLAINTEXT BEFORE OTR
        --------------------
        An ordinary XMPP message, to a conversation where nobody has asked for
        OTR, goes out as typed. It does NOT go through
        `handle_outgoing_message`, because that call is opportunistic: it would
        create a session, start a DAKE, queue the text and hand back DAKE1 --
        so typing "hello" would emit an 11 KB handshake and deliver nothing.

        `OtrMode` decides, and it fails closed: an established or requested
        session is never downgraded, and a peer's own protocol frame marks the
        conversation before the handshake finishes. The result is reported as
        SEND_PLAINTEXT, distinct from SEND_ENCRYPTED, so nothing downstream can
        mistake one for the other.
        """
        peer = self.canonical_peer(peer)
        if self._transport is None:
            raise BridgeError("no_transport")

        # A ROOM, and never the OTR path. Group chat is plaintext by design
        # (XEP-0045 has no end-to-end encryption) and is labelled so on every
        # message; sending it as type="chat" to the room's JID -- what this
        # method did before rooms were routed -- is rejected by the server
        # while the UI reported it sent.
        if peer in self._rooms:
            sender = getattr(self._transport, "send_room_message", None)
            if sender is None:
                return self.SEND_FAILED
            try:
                sender(peer, body)
            except Exception:
                return self.SEND_FAILED
            return self.SEND_PLAINTEXT

        if self._mode.may_send_plaintext(
                peer, self.security_state(peer) is not SecurityState.PLAINTEXT):
            try:
                self._transport.send(peer, body)
            except Exception:
                return self.SEND_FAILED
            self._touch(peer)
            return self.SEND_PLAINTEXT

        try:
            payload, should_send = self._engine.handle_outgoing_message(
                peer, body)
        except Exception:
            return self.SEND_FAILED

        if not should_send:
            # The engine is holding it until there is a session. Not an error.
            return self.SEND_QUEUED
        if not payload:
            return self.SEND_FAILED

        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        try:
            self._transport.send(peer, text)
        except Exception:
            # It was encrypted but did not leave. Distinct from queued: there
            # is nothing holding it and nothing will retry.
            return self.SEND_FAILED
        self._touch(peer)
        return self.SEND_ENCRYPTED

    def receive_message(self, peer: str, payload: str) -> Optional[str]:
        """Feed an inbound frame to the engine; emit a MessageReceived if it was one.

        Returns the plaintext for the caller that wants it inline; the same value
        is delivered as an event.  Nothing here is logged.
        """
        peer = self.canonical_peer(peer)
        # The PEER asking counts as asking. Marked before the engine runs, so
        # a message typed while a DAKE is arriving cannot slip out in the clear
        # in the gap between their first frame and a completed session.
        if _fragment.is_otr_protocol(payload):
            self._mode.request(peer)

        # Sample BEFORE the engine runs: a DAKE or SMP frame changes the
        # security level as a side effect of this call, and comparing against a
        # post-call reading would always find them equal.
        before = self.security_state(peer)
        before_smp = self.smp_state(peer)
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
            self._announce_smp_change(peer, before_smp)
            return None

        # THE ENGINE'S OUTPUT IS NOT NECESSARILY SOMETHING TO DISPLAY.
        #
        # `handle_incoming_message` returns either decrypted user text OR a
        # protocol frame that the CALLER is expected to put back on the wire.
        # `otrv4plus_xmpp._on_otr_message` has always made that distinction --
        # `if out_b.startswith(OTR_PREFIX_B): send_otr_fragmented(...)` -- and
        # this facade did not.
        #
        # The consequence was physical and was reported from a handset: a
        # `?OTRv4 NvM3G22w...` DAKE frame appeared in the conversation as a
        # wall of base64 from the user's contact, AND the reply it represented
        # was never sent, so the handshake could not complete in either
        # direction. One missing branch produced both symptoms.
        if _fragment.is_otr_protocol(result):
            self._send_protocol(peer, result)
            after = self.security_state(peer)
            if after != before:
                self._emit(SessionStateChanged(peer=peer, security=after))
            self._announce_smp_change(peer, before_smp)
            return None

        body = result.decode("utf-8", errors="replace") if isinstance(result, (bytes, bytearray)) else str(result)

        # CALL SIGNALLING IS NOT A MESSAGE, and this branch is what keeps it
        # out of the conversation. The terminal client tests `CALL_PREFIX` in
        # three places on its decrypted bodies; this facade tested it nowhere,
        # so a peer's control message was handed to the UI as chat text.
        # Measured through two real bridges with a live session:
        #
        #     receive_message returned: '?OTRv4-CALL:INVITE:aa|bb|cc|dd'
        #
        # -- rendered to the user as a message from their contact. Routed
        # here instead, where `VoiceCallManager` validates it: `parse_signal`
        # is structural only, `handle_signal` rate-limits before any work,
        # and `_on_invite` applies the SMP gate before a session exists, so an
        # unverified peer cannot make this device ring.
        #
        # Returns None like every other protocol frame: nothing to display.
        if is_call_signal(body):
            self._touch(peer)
            self.calls.handle_signal(peer, body)
            self._announce_smp_change(peer, before_smp)
            return None

        # FILE SIGNALLING IS NOT A MESSAGE EITHER, and this one is louder
        # when it goes wrong: every DATA chunk is base64 of a sealed chunk,
        # so a transfer would have rendered as hundreds of walls of base64
        # from the user's contact. Measured before this branch existed:
        #
        #     returned: '?OTRv4-FILE:OFFER:deadbeef|secret.pdf|1024'
        #
        # The engine validates it, including refusing an offer from a peer
        # who is not SMP-verified before a transfer exists at all.
        if is_file_signal(body):
            self._touch(peer)
            self.files.handle_signal(peer, body)
            self._announce_smp_change(peer, before_smp)
            return None

        # AND THE THIRD ONE. `otrv4plus_trade` carries `?OTRv4-TRADE:` in a
        # body exactly as voice and file transfer do, and Android has no
        # trade support at all -- so without this branch a peer's trade
        # signalling would reach the screen as a message from their contact,
        # which is the same defect the two above fix.
        #
        # SUPPRESSED, NOT HANDLED, and the difference is stated because it
        # matters: this does not make trading work on Android. It stops
        # protocol text being rendered as something a person said. Wiring
        # `TradeManager` up is separate work with its own gate to honour.
        if _is_trade_signal(body):
            self._touch(peer)
            return None

        self._touch(peer)
        self._emit(MessageReceived(peer=peer, body=body, timestamp=self._clock()))
        # A decrypted message means a session exists; the level may have moved
        # on this very frame (a DATA message completing a rekey, say).
        after = self.security_state(peer)
        if after != before:
            self._emit(SessionStateChanged(peer=peer, security=after))
        self._announce_smp_change(peer, before_smp)
        return body

    def _announce_smp_change(self, peer: str, before: SmpState) -> None:
        """Emit when an inbound frame moved this peer's verification state.

        THE DEFECT THIS FIXES
        ---------------------
        `receive_message` emitted `SessionStateChanged` only when the SECURITY
        LEVEL changed. An SMP1 arriving on a session that is already ENCRYPTED
        does not change the level -- it stays ENCRYPTED until SMP passes, which
        is the whole point of having SMP -- so an incoming verification request
        produced NO EVENT AT ALL.

        The Rust core was doing its part: it parks the peer's SMP1 in
        `SmpPhase::SecretRequired` and waits. The terminal clients notice
        because they call `smp_secret_required(peer)` on their own inbound
        path (`otrv4+.py:15404`, `otrv4plus_xmpp.py:2934`). Android had no
        equivalent, so Bob's device knew a request was held and never said so.

        WHY A TRANSITION AND NOT A POLL
        -------------------------------
        Emitted only when the state actually MOVED. A resent SMP1 lands in
        SECRET_REQUIRED again, and re-announcing it would let a peer stack
        prompts by resending -- the same idempotence `SmpFlow
        .remote_smp1_arrived` enforces for the terminal, applied at the point
        the Android UI actually learns about the request.

        NOTHING HERE DECIDES WHAT THE USER'S NEXT INPUT MEANS. It reports a
        state change; the UI opens a dialog with its own passphrase field. See
        `smp_respond` for why that separation is what keeps INV-06.
        """
        after = self.smp_state(peer)
        if after == before:
            return
        if after in (SmpState.VERIFIED, SmpState.FAILED, SmpState.CANCELLED):
            self._emit(SmpResult(peer=peer, state=after))
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
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="smp_start_failed"))
            raise BridgeError("smp_start_failed")
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

    def smp_respond(self, peer: str, secret: str) -> None:
        """Answer a peer's verification challenge.

        THE DEFECT THIS FIXES
        ---------------------
        This method used to be `set_smp_secret` and nothing else. Setting the
        secret is half the operation: the peer's SMP1 is HELD by the Rust core
        in `SmpPhase::SecretRequired`, and answering it means calling
        `resume_held_smp1` to consume the held message and produce SMP2 -- and
        then PUTTING SMP2 ON THE WIRE.

        Neither happened. The secret was stored, a progress event was emitted,
        and the responder's answer never left the device. Both terminal
        clients do this properly (`otrv4+.py:15312`,
        `otrv4plus_xmpp.py:3661`); this facade did not, so an Android
        responder could only ever hang.

        WHY THIS IS SAFE UNDER INV-06
        -----------------------------
        SECURITY_INVARIANTS.md INV-06: a remote peer may cause the client to
        ASK for the passphrase, but may never cause the next thing the user
        types to BECOME the passphrase. On a terminal those are one step apart
        because there is ONE input channel, which is why `SmpFlow` puts a
        consent edge between them.

        On Android the separation is structural instead. This is reached only
        from a dialog with its OWN password field: a chat message typed into
        the composer goes to `send_user_text` and cannot arrive here, whatever
        a peer does. The peer chooses when a dialog appears; they cannot
        choose what any other input means. That is the property INV-06 names,
        obtained from the widget boundary rather than from a state machine.
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

    def voice_unavailable_reason(self) -> str:
        """Why voice cannot run on this device, or "" when it can.

        Asked of `otrv4plus_voice`'s own host hook -- the same question
        `start_call` asks before doing anything -- so the screen cannot say
        something different from what the engine decides.
        """
        if self._wiped:
            return "wiped"
        return self.calls.unavailable_reason()

    # -- files -----------------------------------------------------------------
    #
    # Thin, like the calls. Every decision -- the SMP gate on both sides, the
    # size limit, the filename rules, the chunk format, the atomic commit --
    # belongs to `otrv4plus_filetransfer`, which already makes them for the
    # terminal client.

    @property
    def files(self) -> "FileBridge":
        """The transfer bridge, built once per app. See android_bridge.files."""
        if self._wiped:
            raise BridgeError("wiped", "this app has been wiped")
        if self._files_bridge is None:
            self._files_bridge = FileBridge(self)
        return self._files_bridge

    def send_file(self, peer: str, path: str,
                  strip_metadata: bool = False) -> str:
        """Offer a file. Returns a `FileOutcome` code, never a sentence.

        THE VERIFICATION GATE IS NOT HERE. `offer_file` refuses an unverified
        peer before it reads a byte of the file, using the same predicate the
        call gate uses. Restating it would create a second answer that could
        disagree with the one that actually refuses.

        [path] is resolved by Android through the Storage Access Framework
        before it arrives. The engine takes a path and does not care who
        chose it, which is why the Termux picker is never reached here.
        """
        if self._wiped or self.is_room(peer):
            return FileOutcome.UNAVAILABLE
        return self.files.send_file(self.canonical_peer(peer), path,
                                    bool(strip_metadata))

    def inspect_file(self, path: str) -> Dict[str, Any]:
        """Whether [path] carries metadata the app can remove.

        Asked BEFORE sending, so the user can choose. See
        `android_bridge.metadata` for exactly what counts and what is kept.
        """
        return self.files.inspect(path)

    def accept_file(self, transfer_id: str) -> str:
        """Accept an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.UNAVAILABLE
        return self.files.accept(transfer_id)

    def decline_file(self, transfer_id: str) -> str:
        """Decline an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.NO_TRANSFER
        return self.files.decline(transfer_id)

    def transfers(self) -> List[Dict[str, Any]]:
        """Every live transfer, structured. Never the engine's own sentences."""
        if self._wiped:
            return []
        return self.files.transfers()

    def received_file_dir(self) -> str:
        """Where a FINISHED file lands, as the engine decides it.

        Not the partial-work directory, which the engine keeps separate so a
        partial file can never be mistaken for a complete one.
        """
        return self.files.received_dir()

    def poll_calls(self) -> None:
        """Emit an event for any call whose state moved.

        The manager publishes no state callback, so movement is noticed by
        reading. Driven from the host's existing drain rather than a timer of
        its own, so there is one observer and nothing to leak.
        """
        if self._calls_bridge is not None and not self._wiped:
            self._calls_bridge.poll()
