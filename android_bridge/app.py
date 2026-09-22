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
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional

# The shared wire format. A dependency-free leaf, which is why importing it at
# module scope does not breach the transport boundary from 22fc255 -- see
# tests/test_android_transport.py::test_any_shared_module_it_imports_is_a_leaf.
# Both clients classify and fragment
# with this module and nothing has a second copy.
import otrv4plus_fragment as _fragment

from .trace import TRACE as _TRACE
import otrv4plus_presence as _presence
from otrv4plus_mode import OtrMode

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
        self._require_encrypted(peer, "smp_not_encrypted")
        if not self.smp_secret_required(peer):
            # Nothing is being asked. Storing a passphrase here would leave a
            # secret bound to a session with no run to spend it on, and the
            # user would be told they had answered a request that does not
            # exist.
            raise BridgeError("smp_not_requested",
                              "there is no verification request to answer")
        try:
            self._engine.set_smp_secret(peer, secret)
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
        self._safe(lambda: abort(peer))
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
        peer = self.canonical_peer(peer)
        return self._call_states.get(peer, CallState.IDLE)
