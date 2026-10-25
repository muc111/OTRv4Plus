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
    facade is importable and testable without slixmpp.

Threading: `EnhancedSessionManager` takes an RLock internally and the XMPP
client runs SMP on its own executor, because SMP performs multi-minute 3072-bit
computations.  This facade does not add locking of its own; it must be driven
from the service thread that owns the engine, never from the Android main
thread.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

# The shared wire format, used by both clients. A dependency-free leaf, so a
# module-level import keeps the transport boundary intact
# (test_android_transport.py::test_any_shared_module_it_imports_is_a_leaf).
import otrv4plus_fragment as _fragment
import otrv4plus_actions as _actions

from .trace import TRACE as _TRACE
from .app_base import BridgeError, _log, _new_message_id, redacting_logger  # noqa: F401
from .app_calls import CallsMixin
from .app_files import FilesMixin
from .app_rooms import RoomChatMixin
from .app_smp import SmpMixin
from .app_wipe import WipeMixin
from .files import FileBridge, is_file_signal
from .voice import CallBridge, is_call_signal
from .groups import GroupError, SecureGroups, is_group_signal
import otrv4plus_presence as _presence
from otrv4plus_mode import OtrMode

from .events import (
    CallState, ConnectionState, ConnectionStateChanged, ChatStateChanged,
    ErrorOccurred, Event, EventSink, HistorySynced, MessageChanged,
    MessageDelivered, MessageDisplayed, MessageReceived, MessageSentElsewhere,
    OtrCapabilityChanged, QueuedSent, SecurityState, SessionStateChanged,
    SmpProgress, SmpState, security_state_from_level, smp_state_from_status,
)

__all__ = ["OtrApp", "Transport", "ContactView", "SecurityDetails",
           "redacting_logger", "BridgeError"]


#: The trade control prefix. A constant, not an import: trade is not wired up
#: on Android and the module is large. test_android_files.py checks it matches.
TRADE_PREFIX_FALLBACK = "?OTRv4-TRADE:"


def _is_trade_signal(body: Any) -> bool:
    """Whether a decrypted body is trade signalling rather than a message."""
    if not isinstance(body, str):
        return False
    import sys
    module = sys.modules.get("otrv4plus_trade")
    prefix = getattr(module, "TRADE_PREFIX", None) if module else None
    return body.startswith(prefix or TRADE_PREFIX_FALLBACK)


class _Line(str):
    """A line in the outbox: the text, carrying the id it will be sent
    with (XEP-0359) and the message it replies to, so a line that waited
    for a handshake still gets its receipt matched to the right bubble. A
    str, so everything that reads the outbox as text still does."""

    message_id: str = ""
    reply_to: str = ""

    def __new__(cls, text: str, message_id: str = "", reply_to: str = ""):
        line = super().__new__(cls, text)
        line.message_id = message_id or ""
        line.reply_to = reply_to or ""
        return line


# ── Logging ───────────────────────────────────────────────────────────────────


# ── Value types returned to Kotlin ────────────────────────────────────────────

@dataclass(frozen=True)
class ContactView:
    """Everything the contacts list needs, and nothing else."""

    jid: str
    display_name: str
    #: One of otrv4plus_presence.STATES: "unknown", "online", "offline".
    #: "unknown" (never heard) is distinct from "offline".
    presence: str
    security: SecurityState
    smp: SmpState
    last_activity: Optional[float] = None
    call_available: bool = False
    #: RFC 6121 show: "", "away", "chat", "dnd", "xa". Empty unless online.
    presence_show: str = ""
    #: The XMPP roster subscription, verbatim: "none", "to", "from", "both",
    #: or "" when the roster did not say. Shown so a contact who has not yet
    #: approved us explains why their presence stays unknown.
    subscription: str = ""
    #: Whether we have asked and not yet been answered. slixmpp exposes this
    #: separately from `subscription`, because a pending request does not
    #: change the subscription until it is approved.
    pending: bool = False

    @property
    def online(self) -> bool:
        """True only when online. Derived from `presence`, never stored;
        False covers both offline and unknown -- read `presence` to tell them
        apart."""
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
    """What OtrApp needs from a transport (the XMPP client implements it).
    Four methods, so the transport and I2P details stay outside the facade."""

    def send(self, peer: str, payload: str) -> None:            # pragma: no cover
        raise NotImplementedError

    def connect(self) -> None:                                   # pragma: no cover
        raise NotImplementedError

    def disconnect(self) -> None:                                # pragma: no cover
        raise NotImplementedError

    def roster(self) -> List[Dict[str, Any]]:                    # pragma: no cover
        raise NotImplementedError


# ── The facade ────────────────────────────────────────────────────────────────


def _is_otr_frame(text: str) -> bool:
    """Whether [text] is an OTRv4 frame -- the only thing a 1:1 send may put
    on the wire (owner, 2026-10-24: never plaintext between 1:1 users)."""
    return isinstance(text, str) and text.startswith("?OTRv4")

class OtrApp(RoomChatMixin, SmpMixin, CallsMixin, FilesMixin, WipeMixin):
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
        #: When each peer last got an automatic recovery handshake.
        self._recovered_at: Dict[str, float] = {}
        #: Secure groups (MLS), created on first use; see `groups`.
        self._groups: Optional[SecureGroups] = None
        self._group_verify = None
        self._group_calls = None
        self._group_files = None
        self._connection = ConnectionState.DISCONNECTED
        #: Each peer's availability, including "never heard" (see
        #: otrv4plus_presence).
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
        # Rooms we are only briefly in to ask to join (request_group_entry):
        # nothing from them is registered, shown or reported.
        self._knocking: set = set()
        # (room, requester) -> when its last request was shown.
        self._entry_seen: Dict[Tuple[str, str], float] = {}
        #: peer -> monotonic time a handshake was first seen, for "elapsed".
        self._handshake_seen: dict = {}
        #: The outbox: peer -> lines typed before the conversation was ready
        #: (no session yet, or capability not known). `_flush_outbox` sends
        #: them encrypted, or in the clear only once the contact is confirmed
        #: not to speak OTRv4+.
        self._outbox: Dict[str, List[str]] = {}
        #: Rooms carrying MLS frames that this device holds no group for.
        self._keyless_groups: set = set()
        #: peer -> rooms to invite them to once OTRv4+ with them is up.
        self._invite_after_otr: Dict[str, List[str]] = {}
        #: Handshake durations (seconds): per peer and overall, for the ETA.
        self._hs_started: Dict[str, float] = {}
        self._hs_history: Dict[str, List[float]] = {}
        self._hs_all: List[float] = []
        #: Set by `wipe` and never cleared. See `wipe` for what it refuses.
        self._wiped = False
        self._wipe_lock = threading.Lock()
        #: peer -> (full JID, id) of the newest message that asked for a read
        #: marker (XEP-0333); answered by `mark_displayed`.
        self._markable: Dict[str, tuple] = {}
        #: The user's choices: send "typing..." and read markers.
        self._chat_states_on = True
        self._read_markers_on = True
        #: peer -> the MESSAGE_META the engine just decrypted with a frame
        #: (otrv4plus_actions), read by `receive_message` in the same call.
        self._meta_stash: Dict[str, Any] = {}
        self._register_meta_handler()
        self._enable_guided_smp()

    #: How many peers' last-seen times to keep. Bounded because the key is the
    #: sender's JID, which a remote party chooses; far above any real contact
    #: list, and eviction only loses a "last seen" caption.
    MAX_TRACKED_ACTIVITY = 2048

    def _touch(self, peer: str) -> None:
        """Record activity with *peer*: the only writer of `_last_activity`,
        so the bound always applies. Evicts the least recently active."""
        self._last_activity[peer] = self._clock()
        self._last_activity.move_to_end(peer)
        while len(self._last_activity) > self.MAX_TRACKED_ACTIVITY:
            self._last_activity.popitem(last=False)

    def _enable_guided_smp(self) -> None:
        """Tell the engine this front end can ask the user for an SMP secret.

        With the flag off (the engine's default) an incoming SMP1 that has no
        stored secret is aborted, so the responder flow -- hold the request,
        report SECRET_REQUIRED, prompt, `smp_respond` -- never runs. Set here
        because `OtrApp` is the whole front-end contract: anything holding one
        can show the prompt. An engine without the attribute cannot hold an
        SMP1 at all, so its absence is ignored.
        Covered by tests/test_smp_android_interop.py against the real engine.
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

        Calls go first: their hang-up signal travels over the OTR session
        that is destroyed below, so ending them later would leave the peer on
        a call nobody is on.
        """
        if self._group_calls is not None:
            try:
                self._group_calls.shutdown()
            except Exception:
                _log.warning("group call teardown reported a problem")
        # The call path built in advance (the green phone): its tunnels go too.
        try:
            import otrv4plus_warmpath
            otrv4plus_warmpath.WARM.close()
        except Exception:
            pass
        if self._group_files is not None:
            self._group_files.close()
            self._group_files = None
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
        # A note being recorded is dropped, never kept for later.
        self.voice_note_cancel()
        self.voice_note_play_stop()
        # The secure groups: sealed to disk and released, lock included, so
        # the next sign-in on this device can open them.
        if self._groups is not None:
            try:
                self._groups.close()
            except Exception:
                _log.warning("group teardown reported a problem")
        try:
            self._engine.clear_all_sessions("shutdown")
        except Exception:
            _log.warning("session teardown reported a problem")
        self.disconnect()

    @property
    def wiped(self) -> bool:
        return self._wiped


    @staticmethod
    def canonical_peer(peer: str) -> str:
        """One contact, one key, however their address is spelled.

        Every per-peer record here -- the OTR mode, presence, last activity, call
        state and, through the engine, the session table -- is keyed by this value.
        Two spellings of one contact would be two entries, and the OTR mode could
        then miss for one of them and let a message out in the clear. So the JID is
        bared and case-folded at this boundary, matching `ChatState.bare`,
        `AccountScope.normalise` and `DAKE1RateLimiter._canonical`. Folding only
        ever merges keys, never splits them.

        A value that is not a JID is trimmed and folded, not rejected: this is a
        key normaliser, not a validator.
        """
        return str(peer or "").strip().split("/", 1)[0].casefold()

    def note_connected(self) -> None:
        """Called by the transport once the stream is usable."""
        self._connection = ConnectionState.CONNECTED
        self._emit(ConnectionStateChanged(state=ConnectionState.CONNECTED))

    def note_presence(self, peer: str, online: bool, show: str = "") -> None:
        """A presence stanza arrived. Called from the transport's loop thread."""
        # Keep the resource: availability is tracked per resource so that an
        # old session timing out cannot mark a live contact offline.
        text = str(peer or "").strip()
        resource = text.split("/", 1)[1] if "/" in text else ""
        key = self.canonical_peer(text)
        self._presence.note(key + "/" + resource if resource else key, online, show)

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
        """Drop what a roster subscription told us about one peer: presence and
        last seen. Called when the roster entry is removed.

        The OTR session, pinned fingerprint and message history are kept: they
        did not come from the subscription, and dropping the fingerprint would
        turn the next conversation into a fresh trust-on-first-use decision.
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

        Guarded because it runs for every roster entry on every UI poll and for
        every inbound frame; one engine error must not fail the whole poll. An
        unreadable state is reported as PLAINTEXT, never as anything stronger.
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
        """Whether the core is holding this peer's SMP1, waiting for our secret.

        The predicate the terminal clients use: Rust's
        `RustSMP.get_phase() == "SECRET_REQUIRED"`. An engine without the method
        cannot hold an SMP1, so it answers False.
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

        The JID goes through `canonical_peer`, because the presence and
        last-activity maps read here are written under canonical keys; any other
        spelling would show the contact twice and with blank state.
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

    # -- OTRv4Plus capability ---------------------------------------------------

    def _capability_enforced(self) -> bool:
        """Whether the transport tracks per-resource OTRv4Plus capability.

        The real XMPP transport does, and then it is the law: no OTRv4+ frame
        leaves for a resource that has not been confirmed. Test doubles that
        model no presence do not, and keep the older behaviour.
        """
        return callable(getattr(self._transport, "otr_capability", None))

    def otr_capability(self, peer: str) -> str:
        """otrv4plus_caps state for *peer*: unknown, offline, checking,
        available or unavailable. NOT a security state."""
        fn = getattr(self._transport, "otr_capability", None)
        if fn is None:
            return "unknown"
        try:
            return str(fn(self.canonical_peer(peer)))
        except Exception:
            return "unknown"

    #: Bounds on the outbox: lines per contact, and characters per line.
    OUTBOX_MAX = 100
    #: The handshake ETA before any has been measured (I2P, two tunnels).
    HANDSHAKE_TYPICAL_SECONDS = 75

    def _hold(self, peer: str, body: str, message_id: str = "",
              reply_to: str = "") -> bool:
        box = self._outbox.setdefault(peer, [])
        if len(box) >= self.OUTBOX_MAX:
            return False
        box.append(body if isinstance(body, _Line) else _Line(body, message_id, reply_to))
        return True

    # -- MESSAGE_META: ids and actions inside the OTR payload -----------------

    def _register_meta_handler(self) -> None:
        # One handler per process, shared with the terminal client; the frame's
        # meta goes to whoever is decrypting it (otrv4plus_actions.receiving).
        _actions.install(self._engine)

    def _on_meta_tlv(self, peer: str, value: bytes) -> None:
        """Called by the engine while it decrypts a frame (same call, same
        thread as `receive_message`), with the frame's MESSAGE_META."""
        meta = _actions.decode_meta(value)
        if meta is not None:
            self._meta_stash[self.canonical_peer(peer)] = meta

    def _encrypt_user(self, peer: str, body: str, message_id: str = "",
                      reply_to: str = ""):
        """(payload, should_send) for a typed line: with its MESSAGE_META
        (id, reply) when a session is up, otherwise exactly what
        `handle_outgoing_message` does (queueing included)."""
        send_meta = getattr(self._engine, "send_text_with_tlv", None)
        if message_id and send_meta is not None and _actions.valid_id(message_id):
            try:
                meta = _actions.encode_meta(
                    message_id, reply=reply_to if _actions.valid_id(reply_to) else "")
                frame = send_meta(peer, body, _actions.META_TLV, meta)
            except Exception:
                frame = None
            if frame:
                return frame, True
        return self._engine.handle_outgoing_message(peer, body)

    def _send_user(self, peer: str, payload: str, message_id: str = "") -> None:
        """Send something a person typed, with its id when the transport
        can carry one (XmppTransport.send_typed); test doubles get `send`."""
        typed = getattr(self._transport, "send_typed", None)
        if message_id and typed is not None:
            typed(peer, payload, message_id)
        else:
            self._transport.send(peer, payload)

    def outbox_count(self, peer: str) -> int:
        return len(self._outbox.get(self.canonical_peer(peer), ()))

    def _flush_outbox(self, peer: str) -> None:
        """Send what waited for `peer`, if the conversation is ready now."""
        box = self._outbox.get(peer)
        invites = self._invite_after_otr.get(peer)
        secure = self.security_state(peer) is not SecurityState.PLAINTEXT
        if secure and invites:
            self._invite_after_otr.pop(peer, None)
            groups = self._groups
            for room in invites:
                try:
                    groups.invite(room, peer)
                except Exception:
                    self._emit(ErrorOccurred(peer=peer, code="group_invite_failed"))
        if not box:
            return
        if secure:
            sent = 0
            while box:
                body = box[0]
                try:
                    payload, ok = self._encrypt_user(
                        peer, str(body), getattr(body, "message_id", ""),
                        getattr(body, "reply_to", ""))
                    if not (ok and payload):
                        break
                    text = (payload.decode("utf-8", errors="replace")
                            if isinstance(payload, (bytes, bytearray)) else str(payload))
                    if not _is_otr_frame(text):
                        break                       # never the clear: it waits
                    self._send_user(peer, text, getattr(body, "message_id", ""))
                except Exception:
                    break
                box.pop(0)
                sent += 1
            if sent:
                self._touch(peer)
                self._emit(QueuedSent(peer=peer, count=sent, encrypted=True))
        # Not encrypted: everything waits. A 1:1 message is never sent in the
        # clear (owner, 2026-10-24), not even to a contact whose client says
        # it has no OTRv4+.
        if not box:
            self._outbox.pop(peer, None)

    def _own_bare(self) -> str:
        profile = getattr(self._transport, "_profile", None)
        return str(getattr(profile, "jid", "") or "").split("/", 1)[0].lower()

    def _auto_start(self, peer: str) -> None:
        """OTRv4+ as soon as a capable contact is online, so the
        conversation is ready before anyone types. Only ONE side starts it
        (the lower JID), unless something is waiting on our side: two DAKEs
        crossing would cost a round of restarts over I2P."""
        if self.security_state(peer) is not SecurityState.PLAINTEXT:
            return
        waiting = bool(self._outbox.get(peer) or self._invite_after_otr.get(peer))
        me = self._own_bare()
        if not waiting and not (me and me < peer):
            return
        try:
            if self._engine.has_session(peer):
                return
        except Exception:
            pass
        try:
            self.start_session(peer)
            _TRACE.record("otr", "auto_started", "info", jid=peer)
        except BridgeError:
            pass

    def invite_when_ready(self, room: str, peer: str) -> str:
        """Invite `peer` to a secure group, starting OTRv4+ with them first if
        need be (the invite needs it). "sent", or "waiting_for_otr"."""
        peer = self.canonical_peer(peer)
        if self.security_state(peer) is not SecurityState.PLAINTEXT:
            self.groups.invite(room, peer)
            return "sent"
        rooms = self._invite_after_otr.setdefault(peer, [])
        if room not in rooms:
            rooms.append(room)
        state = self.ensure_otr(peer)
        if state in ("offline", "unknown") and not self._sees_presence_of(peer):
            # Device report, 2026-10-24: "Invite people online" lists people
            # the server says are online, contacts or not. A non-contact
            # sends us no presence, so their OTRv4+ support is never learnt,
            # no session ever starts, and the invitation waited forever. Ask
            # to add them: once they accept, presence and the session follow
            # and the invitation goes (`_flush_outbox`).
            try:
                self._transport.add_contact(peer)
            except Exception:
                self._invite_after_otr.pop(peer, None)
                raise BridgeError("group_invite_failed",
                                  "the contact request could not be sent")
            _TRACE.record("groups", "invite_needs_contact", "info", jid=peer)
            return "waiting_for_contact"
        if state in ("offline", "checking", "unknown"):
            return "waiting_for_otr"
        if state == "unavailable":
            self._invite_after_otr.pop(peer, None)
            raise BridgeError("otrv4plus_unavailable",
                              "this contact's app does not support OTRv4+")
        return "waiting_for_otr"

    def _sees_presence_of(self, peer: str) -> bool:
        """Whether the roster lets us see *peer*'s presence (subscription
        to or both), so their capability can be learnt."""
        try:
            for entry in self._transport.roster():
                if self.canonical_peer(entry.get("jid", "")) == peer:
                    return entry.get("subscription") in ("to", "both")
        except Exception:
            return True     # cannot tell: do not send a request on a guess
        return False

    def _report_pq_refusal(self, peer: str) -> None:
        """A2: the engine refused a handshake because the contact's
        post-quantum key was dropped or changed under the same identity."""
        take = getattr(self._engine, "take_pq_refusal", None)
        refused = take(peer) if take is not None else None
        if refused == "pq_downgrade":
            self._emit(ErrorOccurred(peer=peer, code="pq_downgrade"))
        elif refused == "pq_key_changed":
            self._emit(ErrorOccurred(peer=peer, code="pq_key_changed"))
        elif refused == "pq_v2_required":
            self._emit(ErrorOccurred(peer=peer, code="pq_v2_required"))

    def _session_settled(self, peer: str, before, after) -> None:
        """A session came up (or went): record the handshake time and send
        whatever waited for it."""
        if after is not SecurityState.PLAINTEXT and before is SecurityState.PLAINTEXT:
            started = self._hs_started.pop(peer, None) or self._handshake_seen.get(peer)
            if started:
                took = max(1.0, time.monotonic() - started)
                hist = self._hs_history.setdefault(peer, [])
                hist.append(took)
                del hist[:-5]
                self._hs_all.append(took)
                del self._hs_all[:-20]
            self._flush_outbox(peer)

    def handshake_eta(self, peer: str, elapsed: int) -> int:
        """Seconds still expected, from how long handshakes have taken
        (this contact first, then anyone, then a default). A guide only:
        I2P routes vary; never below 5 while one is still running."""
        hist = self._hs_history.get(peer) or self._hs_all
        if hist:
            typical = sorted(hist)[len(hist) // 2]
        else:
            typical = float(self.HANDSHAKE_TYPICAL_SECONDS)
        return int(max(5.0, typical - elapsed))

    def note_capability(self, peer: str, pinned_left: bool = False) -> None:
        """The transport's capability changed for *peer*. Called on its loop.

        If the resource an OTRv4+ session lived on went away, that session is
        over: its state is in that one client process, and frames must not be
        re-aimed at another device. It is torn down locally (no TLV: there is
        nobody to send it to) and the conversation STAYS OTR-requested, so the
        next line is queued for a new handshake, never sent in the clear.
        """
        if self._wiped:
            return
        peer = self.canonical_peer(peer)
        if pinned_left:
            try:
                ender = getattr(self._engine, "end_session", None)
                if ender is not None and self._engine.has_session(peer):
                    ender(peer, "the peer's OTRv4Plus resource went offline")
                    _TRACE.record("otr", "session_ended_resource_left", "info",
                                  jid=peer)
                    self._emit(SessionStateChanged(
                        peer=peer, security=self.security_state(peer)))
            except Exception:
                _log.warning("could not end the session of a departed resource")
        state = self.otr_capability(peer)
        self._emit(OtrCapabilityChanged(peer=peer, state=state))
        if peer in self._rooms:
            return
        if state == "available":
            self._auto_start(peer)
        if state in ("available", "unavailable"):
            self._flush_outbox(peer)

    #: What `ensure_otr` found or did. Stable codes for Kotlin.
    ENSURE_ESTABLISHED = "established"
    ENSURE_STARTED = "started"
    ENSURE_IN_PROGRESS = "in_progress"

    def ensure_otr(self, peer: str) -> str:
        """Automatic OTRv4+ for a private conversation the user has open.

        Contact -> resource -> capability -> OTRv4+, in that order:
          * already encrypted: "established";
          * capability not confirmed: the capability state ("checking",
            "offline", "unavailable", "unknown") and NOTHING is sent;
          * a handshake already in flight: "in_progress";
          * otherwise a DAKE is started: "started".
        Never SMP, never trust: those stay explicit.
        """
        peer = self.canonical_peer(peer)
        if peer in self._rooms or self._wiped or self._transport is None:
            return "unavailable"
        if self.security_state(peer) is not SecurityState.PLAINTEXT:
            return self.ENSURE_ESTABLISHED
        capability = self.otr_capability(peer)
        if self._capability_enforced() and capability != "available":
            return capability
        try:
            if self._engine.has_session(peer):
                return self.ENSURE_IN_PROGRESS
        except Exception:
            pass
        try:
            self.start_session(peer)
        except BridgeError as exc:
            return getattr(exc, "code", "failed") or "failed"
        return self.ENSURE_STARTED

    #: Handshake stages for the UI. Stable codes: Kotlin maps them to words.
    HS_IDLE = "idle"
    HS_RECEIVING_REQUEST = "receiving_request"   # their DAKE1 arriving
    HS_WAITING_REPLY = "waiting_reply"           # our DAKE1 sent
    HS_RECEIVING_REPLY = "receiving_reply"       # their DAKE2 arriving
    HS_REPLYING = "replying"                     # building/sending our DAKE2
    HS_WAITING_CONFIRM = "waiting_confirm"       # our DAKE2 sent
    HS_RECEIVING_CONFIRM = "receiving_confirm"   # their DAKE3 arriving
    HS_ESTABLISHED = "established"
    HS_FAILED = "failed"

    def handshake_status(self, peer: str) -> dict:
        """Where an OTRv4+ handshake with *peer* has got to.

        From the engine's own DAKE state and the transport's count of
        fragments received -- nothing estimated, nothing timed except the
        elapsed seconds since this handshake was first seen. Over I2P the
        11 KB DAKE2 and DAKE3 arrive in parts, which is where the minutes go,
        so "1 of 2 parts" is the part worth showing.

        Keys: stage, step (1-3), steps (3), have, of (fragments; 0 when none
        are in flight), elapsed (seconds). No key material, no payload.
        """
        peer = self.canonical_peer(peer)
        out = {"stage": self.HS_IDLE, "step": 0, "steps": 3,
               "have": 0, "of": 0, "elapsed": 0, "eta": 0,
               "capability": self.otr_capability(peer),
               "queued": len(self._outbox.get(peer, ()))}
        if peer in self._rooms:
            return out
        if self.security_state(peer) is not SecurityState.PLAINTEXT:
            self._handshake_seen.pop(peer, None)
            out["stage"], out["step"] = self.HS_ESTABLISHED, 3
            return out
        # The DAKE ADAPTER's state is authoritative for both roles: the
        # responder's session object stays IDLE while its adapter moves
        # RECEIVED_DAKE1 -> SENT_DAKE2 (observed against the real engine).
        dake = "IDLE"
        try:
            engines = getattr(self._engine, "dake_engines", {}) or {}
            adapter = engines.get(peer)
            if adapter is not None:
                state = adapter.get_state() if hasattr(adapter, "get_state") \
                    else getattr(adapter, "state", None)
                dake = getattr(state, "name", "IDLE")
            if dake == "IDLE":
                session = self._engine.get_session(peer)
                if session is not None:
                    dake = getattr(getattr(session, "dake_state", None),
                                   "name", "IDLE")
        except Exception:
            dake = "IDLE"
        parts = None
        transport = self._transport
        if transport is not None and hasattr(transport, "inbound_progress"):
            try:
                parts = transport.inbound_progress(peer)
            except Exception:
                parts = None
        if parts:
            out["have"], out["of"] = int(parts[0]), int(parts[1])
        stage = {
            "SENT_DAKE1": self.HS_RECEIVING_REPLY if parts
                          else self.HS_WAITING_REPLY,
            "RECEIVED_DAKE1": self.HS_REPLYING,
            "SENT_DAKE2": self.HS_RECEIVING_CONFIRM if parts
                          else self.HS_WAITING_CONFIRM,
            "FAILED": self.HS_FAILED,
        }.get(dake, self.HS_RECEIVING_REQUEST if parts else self.HS_IDLE)
        step = {self.HS_RECEIVING_REQUEST: 1, self.HS_WAITING_REPLY: 1,
                self.HS_RECEIVING_REPLY: 2, self.HS_REPLYING: 2,
                self.HS_WAITING_CONFIRM: 2, self.HS_RECEIVING_CONFIRM: 3,
                self.HS_FAILED: 0}.get(stage, 0)
        if stage in (self.HS_IDLE, self.HS_FAILED):
            self._handshake_seen.pop(peer, None)
        else:
            started = self._handshake_seen.setdefault(peer, time.monotonic())
            out["elapsed"] = int(time.monotonic() - started)
            out["eta"] = self.handshake_eta(peer, out["elapsed"])
        out["stage"], out["step"] = stage, step
        return out

    def start_session(self, peer: str) -> None:
        """Begin the DAKE (about 20 s over I2P) and send its first message.

        This is the explicit request: from here on nothing in this conversation
        goes out in the clear, even if the handshake fails. Success is reported
        from the send itself, not from creating the session --
        `handle_outgoing_message` returns `(payload, should_send)` and the payload
        must be handed to the transport. The transport fragments it
        (`otrv4plus_fragment.MAX_FRAGMENT`): a DAKE2 is ~11.7 KB after base64,
        above I2P's ~8 KB comfortable message size.
        """
        peer = self.canonical_peer(peer)
        self._refuse_room(peer, 'room_not_encryptable')
        if self._transport is None:
            raise BridgeError("no_transport")
        # CAPABILITY FIRST. A DAKE is never how we find out whether the peer
        # speaks OTRv4Plus; a transport that tracks capability must have
        # confirmed a resource first. (The transport refuses the frame on
        # its own too -- this is the answer the UI can explain.)
        capability = self.otr_capability(peer)
        if self._capability_enforced() and capability != "available":
            raise BridgeError("otrv4plus_" + capability,
                              "OTRv4Plus is not available for this contact")

        # BEFORE the send, and deliberately. From here this conversation is
        # OTR-requested, so a failure below leaves it refusing plaintext
        # rather than quietly reverting -- a failed handshake is not consent
        # to continue without one.
        self._mode.request(peer)
        _TRACE.record("otr", "dake_requested", "info", jid=peer)
        self._hs_started.setdefault(peer, time.monotonic())

        # AN EXPLICIT REQUEST RESTARTS A HANDSHAKE THAT IS NOT FINISHING.
        # The engine declines to build a DAKE1 while one is in flight, and a
        # handshake whose DAKE2 or DAKE3 was lost -- a VPN switch, a dropped
        # I2P tunnel -- is in flight forever. The terminal's `/otr` resets in
        # that case; this facade sent a bare query the peer ignores, so the
        # user could tap Start as often as they liked and nothing recovered.
        # A fresh DAKE1 is always safe to send: the peer's engine lets it
        # supersede a stale run, and settles glare if both sides retry.
        # "In flight" is either state the engine uses for it: an initiator
        # waiting for DAKE2 is DAKE_IN_PROGRESS, and a responder waiting for
        # DAKE3 is still PLAINTEXT with a DAKE engine attached.
        live = getattr(self._engine, "sessions", {}).get(peer)
        live_state = getattr(getattr(live, "session_state", None), "name", "")
        half_done = (live_state == "DAKE_IN_PROGRESS"
                     or (live_state == "PLAINTEXT"
                         and getattr(live, "dake_engine", None) is not None))
        if half_done and hasattr(self._engine, "end_session"):
            try:
                self._engine.end_session(peer, "handshake restarted by the user")
                _TRACE.record("otr", "dake_restarted", "info", jid=peer)
            except Exception as exc:
                _TRACE.record_exception("otr", "dake_restart_failed", exc, jid=peer)

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

    def send_user_text(self, peer: str, body: str, message_id: str = "",
                       reply_to: str = "") -> str:
        """Send one typed line. Returns SEND_ENCRYPTED, SEND_QUEUED,
        SEND_PLAINTEXT or SEND_FAILED.

        [message_id] (the UI's random id for the bubble) goes on the wire as the
        message id and XEP-0359 origin-id, so receipts, read markers and copies on
        other devices match it.

        Unlike `send_message` (which raises `not_encrypted` and never downgrades),
        this reports what actually happened: a line typed before the session is
        ready is QUEUED and sent when the DAKE completes.

        Plaintext only where nobody asked for OTR: `OtrMode` decides and fails
        closed -- a session that exists or was requested is never downgraded, and
        a peer's own protocol frame marks the conversation before its handshake
        finishes. Plain sends bypass `handle_outgoing_message`, which would start a
        DAKE instead of delivering the text.
        """
        peer = self.canonical_peer(peer)
        if self._transport is None:
            raise BridgeError("no_transport")

        # A ROOM, and never the OTR path. Group chat is plaintext by design
        # (XEP-0045 has no end-to-end encryption) and is labelled so on every
        # message; sending it as type="chat" to the room's JID -- what this
        # method did before rooms were routed -- is rejected by the server
        # while the UI reported it sent.
        # A SECURE GROUP is MLS or nothing: a failure is SEND_FAILED, never a
        # plaintext retry. Checked before room membership: after a re-login
        # the group is known before its room is joined again, and what is
        # typed then is held until the group is in sync (QUEUED).
        if self._groups is not None and self._groups.is_secure(peer):
            try:
                # With its id (and what it replies to), inside MLS, so others
                # can reply to, react to, and -- only we -- correct or delete it.
                if _actions.valid_id(message_id):
                    body = _actions.encode_group_message(
                        _actions.encode_meta(message_id, reply=reply_to
                                             if _actions.valid_id(reply_to) else ""), body)
                outcome = self._groups.send(peer, body)
            except (GroupError, Exception):
                return self.SEND_FAILED
            return self.SEND_QUEUED if outcome == "held" else self.SEND_ENCRYPTED
        if self._groups is not None and self._groups.awaiting_welcome(peer):
            # A secure group we accepted whose keys (the Welcome) have not
            # arrived: never plaintext, even though the room itself may
            # already look like an ordinary one.
            self._emit(ErrorOccurred(peer=peer, code="group_joining"))
            return self.SEND_FAILED
        if peer in self._rooms:
            if peer in self._keyless_groups:
                # An encrypted group we have no keys for: never plaintext.
                self._emit(ErrorOccurred(peer=peer, code="group_keys_missing"))
                return self.SEND_FAILED
            sender = getattr(self._transport, "send_room_message", None)
            if sender is None:
                return self.SEND_FAILED
            try:
                if _actions.valid_id(message_id):
                    extra = (_actions.action_elements("reply", reply_to)
                             if _actions.valid_id(reply_to) else [])
                    try:
                        sender(peer, body, message_id=message_id, elements=extra)
                    except TypeError:          # a transport without ids
                        sender(peer, body)
                else:
                    sender(peer, body)
            except Exception:
                return self.SEND_FAILED
            return self.SEND_PLAINTEXT

        # No plaintext to anyone who might speak OTRv4+.
        # Until the conversation is encrypted, a line waits in the outbox
        # (QUEUED) when the contact's app speaks OTRv4+ -- and a handshake is
        # made sure of -- or when that is not known yet (offline, still
        # checking). Only a contact confirmed online without OTRv4+, who never
        # asked for OTR, is written to in the clear (PLAINTEXT, labelled).
        secure = self.security_state(peer) is not SecurityState.PLAINTEXT
        if secure and self._outbox.get(peer):
            # Behind what is already waiting, in order.
            if not self._hold(peer, body, message_id, reply_to):
                return self.SEND_FAILED
            self._flush_outbox(peer)
            return self.SEND_QUEUED if self._outbox.get(peer) else self.SEND_ENCRYPTED
        if not secure and self._capability_enforced():
            capability = self.otr_capability(peer)
            if capability == "available" or self._mode.is_otr(peer):
                if not self._hold(peer, body, message_id, reply_to):
                    return self.SEND_FAILED
                if capability == "available":
                    try:
                        if not self._engine.has_session(peer):
                            self.start_session(peer)
                    except (BridgeError, Exception):
                        pass
                return self.SEND_QUEUED
            if capability in ("checking", "unknown", "offline"):
                return self.SEND_QUEUED if self._hold(peer, body, message_id, reply_to) else self.SEND_FAILED
            # Confirmed online without OTRv4+. Owner, 2026-10-24: a 1:1
            # message is NEVER sent in the clear -- it used to be, labelled,
            # and a capability check that misjudged a real OTRv4+ phone sent
            # its owner's words unencrypted. It waits; the screen says why.
            self._emit(ErrorOccurred(peer=peer, code="plaintext_refused"))
            return self.SEND_QUEUED if self._hold(peer, body, message_id, reply_to) else self.SEND_FAILED
        if not secure:
            # Not encrypted and nothing above decided: it waits for the
            # session, which is started now. Never the engine's opportunistic
            # path, which would answer with a DAKE1 "to send" and keep the
            # text in a queue of its own.
            if not self._hold(peer, body, message_id, reply_to):
                return self.SEND_FAILED
            try:
                if not self._engine.has_session(peer):
                    self.start_session(peer)
            except (BridgeError, Exception):
                pass
            return self.SEND_QUEUED

        try:
            payload, should_send = self._encrypt_user(peer, body, message_id, reply_to)
        except Exception:
            return self.SEND_FAILED

        if not should_send:
            # No session yet. The OUTBOX holds it (the engine's own queue is
            # dropped when its handshake completes) and sends it then.
            return self.SEND_QUEUED if self._hold(peer, body, message_id, reply_to) else self.SEND_FAILED
        if not payload:
            return self.SEND_FAILED

        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        if not _is_otr_frame(text):
            # Whatever the engine handed back, only an OTRv4 frame leaves for
            # a 1:1 contact. The line waits for the session.
            return self.SEND_QUEUED if self._hold(peer, body, message_id, reply_to) else self.SEND_FAILED
        try:
            self._send_user(peer, text, message_id)
        except Exception:
            # It was encrypted but did not leave. Distinct from queued: there
            # is nothing holding it and nothing will retry.
            return self.SEND_FAILED
        self._touch(peer)
        return self.SEND_ENCRYPTED

    def receive_message(self, peer: str, payload: str, meta: Any = None) -> Optional[str]:
        """Feed an inbound frame to the engine; emit a MessageReceived if it was one.

        Returns the plaintext for the caller that wants it inline; the same value
        is delivered as an event.  Nothing here is logged.

        [meta] is the transport's `otrv4plus_sync.Item` for the stanza (its
        ids, whether it asks for a read marker); None from a caller that has
        none. The transport sends the delivery receipt itself, and only when
        this returns text.
        """
        peer = self.canonical_peer(peer)
        otr_in = _fragment.is_otr_protocol(payload)
        # MESSAGE_META arrives through the engine's TLV handler DURING this
        # call; anything left from an earlier frame is not this frame's.
        self._meta_stash.pop(peer, None)
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
            with _actions.receiving(self._on_meta_tlv):
                result = self._engine.handle_incoming_message(peer, payload)
        except Exception:
            self._emit(ErrorOccurred(peer=peer, code="decrypt_failed"))
            return None

        if result is None:
            self._report_pq_refusal(peer)
            # Protocol frame (DAKE/SMP), not user text: surface any state change.
            after = self.security_state(peer)
            if after != before:
                self._emit(SessionStateChanged(peer=peer, security=after))
                self._session_settled(peer, before, after)
            self._announce_smp_change(peer, before_smp)
            self._recover_if_orphaned(peer)
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
                self._session_settled(peer, before, after)
            self._announce_smp_change(peer, before_smp)
            return None

        body = result.decode("utf-8", errors="replace") if isinstance(result, (bytes, bytearray)) else str(result)

        # Decrypted bodies that are protocol, not chat, never reach the screen.
        # Each returns None like any other protocol frame.
        #
        # Call signalling: `VoiceCallManager` validates it (`parse_signal` is
        # structural, `handle_signal` rate-limits, and `_on_invite` applies the
        # SMP gate before a session exists, so an unverified peer cannot make
        # this device ring).
        if is_call_signal(body):
            self._touch(peer)
            self.calls.handle_signal(peer, body)
            self._announce_smp_change(peer, before_smp)
            return None

        # File transfer signalling: the engine validates it, and refuses an
        # offer from a peer who is not SMP-verified before any transfer exists.
        if is_file_signal(body):
            self._touch(peer)
            self.files.handle_signal(peer, body)
            self._announce_smp_change(peer, before_smp)
            return None

        # GROUP SETUP: an invitation, a KeyPackage or a Welcome for a secure
        # group, which only ever travel inside this OTRv4+ session.
        if is_group_signal(body):
            self._touch(peer)
            if not self._wiped:
                # Groups that did not open at sign-in (another copy of the app
                # held the state, since closed): try again before the signal is
                # refused, so an invitation is not lost to a lock long gone.
                if not self.groups.is_open:
                    own = self._own_bare()
                    if own:
                        self.open_groups(own)
                try:
                    self.groups.on_signal(peer, body)
                except GroupError:
                    pass
            return None

        # Trade signalling: not supported on Android, so it is dropped rather
        # than handled -- only so that it is never shown as chat text.
        if _is_trade_signal(body):
            self._touch(peer)
            return None

        # An ACTION on an earlier message. Inside an encrypted conversation
        # it came with the frame (MESSAGE_META, authenticated); in a plaintext
        # one a correction rides on its XEP-0308 element. Never both: the
        # elements outside an OTR frame are ignored.
        tlv = self._meta_stash.pop(peer, None) if otr_in else None
        action = None
        if tlv is not None and tlv.get("action"):
            action = (tlv["action"], tlv["target"], tuple(tlv.get("emojis") or ()))
        elif not otr_in and meta is not None and getattr(meta, "action", "") == "edit":
            action = ("edit", meta.target, ())
        if action is not None:
            self._touch(peer)
            self._emit(MessageChanged(
                peer=peer, action=action[0], target_id=action[1],
                body=body if action[0] == "edit" else "", emojis=action[2],
                outgoing=False, source="live"))
            return body if action[0] == "edit" and body else None

        # An empty body is a carrier, not a message: SMP travels as TLVs on an
        # empty data message, and heartbeats are empty too.
        if body == "":
            self._touch(peer)
            after = self.security_state(peer)
            if after != before:
                self._emit(SessionStateChanged(peer=peer, security=after))
            self._announce_smp_change(peer, before_smp)
            return None

        self._touch(peer)
        ref = getattr(meta, "ref", "") or None
        reply_to = ""
        if tlv is not None:
            # The id the sender's client gave it, authenticated with it.
            ref = tlv.get("id") or ref
            reply_to = tlv.get("reply", "")
        elif not otr_in and meta is not None:
            reply_to = getattr(meta, "reply", "") or ""
        self._emit(MessageReceived(peer=peer, body=body, timestamp=self._clock(),
                                   message_id=ref, reply_to=reply_to))
        if meta is not None and getattr(meta, "markable", False) and \
                getattr(meta, "message_id", ""):
            if len(self._markable) < self.MAX_TRACKED_ACTIVITY or peer in self._markable:
                self._markable[peer] = (getattr(meta, "full_jid", "") or peer,
                                        meta.message_id)
        # A decrypted message means a session exists; the level may have moved
        # on this very frame (a DATA message completing a rekey, say).
        after = self.security_state(peer)
        if after != before:
            self._emit(SessionStateChanged(peer=peer, security=after))
        self._announce_smp_change(peer, before_smp)
        return body

    # -- other devices, the archive, receipts, typing (android_bridge.sync) ----

    def on_sync(self, kind: str, **fields: Any) -> None:
        """The transport's sync handler (XmppTransport.set_sync_handler).

        Copies (carbons, the archive) arrive here already classified by
        otrv4plus_sync: plaintext only, never an OTR frame, and never handed
        to the engine -- a copy of encrypted traffic belongs to the device
        whose session it was."""
        if self._wiped:
            return
        if kind == "message":
            item = fields.get("item")
            if item is None:
                return
            import otrv4plus_sync as _sync
            peer = self.canonical_peer(item.peer)
            if peer in self._rooms:
                return
            body = _sync.strip_whitespace_tag(item.body)
            if getattr(item, "action", ""):
                # A correction, deletion or reaction from a copy, or a live
                # plaintext deletion/reaction (otrv4plus_actions).
                self._emit(MessageChanged(
                    peer=peer, action=item.action, target_id=item.target,
                    body=body if item.action == "edit" else "",
                    emojis=tuple(item.emojis), outgoing=item.direction == "out",
                    source=item.source))
                return
            if not body.strip():
                return
            if item.direction == "out":
                self._emit(MessageSentElsewhere(
                    peer=peer, body=body, timestamp=item.when,
                    message_id=item.ref, source=item.source))
            else:
                self._emit(MessageReceived(
                    peer=peer, body=body, timestamp=item.when,
                    message_id=item.ref or None, source=item.source,
                    reply_to=getattr(item, "reply", "") or ""))
        elif kind == "receipt":
            self._emit(MessageDelivered(peer=self.canonical_peer(fields.get("peer", "")),
                                        message_id=str(fields.get("message_id", ""))))
        elif kind == "marker":
            peer = self.canonical_peer(fields.get("peer", ""))
            mid = str(fields.get("message_id", ""))
            if fields.get("marker") == "displayed":
                self._emit(MessageDisplayed(peer=peer, message_id=mid))
            elif fields.get("marker") == "received":
                self._emit(MessageDelivered(peer=peer, message_id=mid))
        elif kind == "chat_state":
            state = str(fields.get("state", ""))
            self._emit(ChatStateChanged(peer=self.canonical_peer(fields.get("peer", "")),
                                        state=state))
        elif kind == "synced":
            self._emit(HistorySynced(count=int(fields.get("count", 0) or 0)))

    def send_action(self, peer: str, action: str, target_id: str,
                    body: str = "", emojis: Any = None, message_id: str = "") -> str:
        """Correct ("edit", with the new text in [body]), delete for
        everyone ("retract") or react to ("react", the whole set in
        [emojis], empty to remove) our or their message [target_id].

        Encrypted conversation: the action is inside the OTR payload
        (MESSAGE_META), nothing about it outside. Plaintext conversation: the
        standard XEP elements. A conversation that asked for OTR but has no
        session yet gets NOTHING (no plaintext action, no queue): SEND_FAILED.
        Rooms are not supported yet: SEND_FAILED."""
        peer = self.canonical_peer(peer)
        if action not in _actions.ACTIONS or not _actions.valid_id(target_id):
            return self.SEND_FAILED
        if self._transport is None:
            return self.SEND_FAILED
        if self._groups is not None and self._groups.is_secure(peer):
            return self._group_action(peer, action, target_id, body, emojis, message_id)
        if self._groups is not None and self._groups.awaiting_welcome(peer):
            return self.SEND_FAILED             # never plaintext: see send
        if peer in self._rooms:
            return self._room_action(peer, action, target_id, body, emojis, message_id)
        message_id = message_id if _actions.valid_id(message_id) else _new_message_id()
        emojis = _actions.clean_emojis(list(emojis or []))
        text = body if action == "edit" else ""
        if action == "edit" and not text.strip():
            return self.SEND_FAILED
        if self.security_state(peer) is not SecurityState.PLAINTEXT:
            send_meta = getattr(self._engine, "send_text_with_tlv", None)
            if send_meta is None:
                return self.SEND_FAILED
            try:
                meta = _actions.encode_meta(message_id, **{action: target_id},
                                            emojis=emojis)
                frame = send_meta(peer, text, _actions.META_TLV, meta)
            except Exception:
                return self.SEND_FAILED
            if not frame:
                return self.SEND_FAILED
            frame = (frame.decode("utf-8", errors="replace")
                     if isinstance(frame, (bytes, bytearray)) else str(frame))
            try:
                if action == "edit":
                    self._send_user(peer, frame, message_id)
                else:
                    self._transport.send(peer, frame)
            except Exception:
                return self.SEND_FAILED
            self._touch(peer)
            return self.SEND_ENCRYPTED
        # A correction, deletion or reaction in a 1:1 chat goes only inside
        # an encrypted session, like the message it is about: never in the
        # clear (owner, 2026-10-24).
        return self.SEND_FAILED

    def mark_displayed(self, peer: str) -> bool:
        """The user is looking at [peer]'s conversation: tell them their
        newest message was seen (XEP-0333), if read markers are on."""
        peer = self.canonical_peer(peer)
        entry = self._markable.pop(peer, None)
        if entry is None or not self._read_markers_on:
            return False
        sender = getattr(self._transport, "send_marker", None)
        if sender is None:
            return False
        try:
            sender(entry[0], entry[1], "displayed")
            return True
        except Exception:
            return False

    def set_chat_state(self, peer: str, state: str) -> bool:
        """The user started or stopped typing to [peer] (XEP-0085)."""
        peer = self.canonical_peer(peer)
        if not self._chat_states_on or peer in self._rooms or (
                self._groups is not None and self._groups.is_secure(peer)):
            return False
        sender = getattr(self._transport, "send_chat_state", None)
        if sender is None:
            return False
        try:
            return bool(sender(peer, state))
        except Exception:
            return False

    def set_privacy(self, chat_states: bool, read_markers: bool) -> None:
        """Settings: send "typing..." and read markers. Kept here so a new
        transport (every reconnect builds one) gets them too."""
        self._chat_states_on = bool(chat_states)
        self._read_markers_on = bool(read_markers)
        apply = getattr(self._transport, "set_privacy", None)
        if apply is not None:
            try:
                apply(self._chat_states_on, self._read_markers_on)
            except Exception:
                pass

    def privacy(self) -> Dict[str, bool]:
        return {"chat_states": self._chat_states_on,
                "read_markers": self._read_markers_on}

    def set_client_active(self, active: bool) -> None:
        """The app came to the front or went to the background (XEP-0352)."""
        apply = getattr(self._transport, "set_client_active", None)
        if apply is not None:
            try:
                apply(bool(active))
            except Exception:
                pass

    def sync_status(self) -> Dict[str, Any]:
        status = getattr(self._transport, "sync_status", None)
        try:
            return dict(status()) if status is not None else {}
        except Exception:
            return {}

    #: At most one automatic handshake per peer in this many seconds.
    RECOVERY_INTERVAL = 30.0

    def _recover_if_orphaned(self, peer: str) -> None:
        """Start a handshake when the peer is encrypting to a session we lack.

        After this device restarts (a new identity every launch) or when a
        DAKE3 is lost, the peer keeps sending DATA frames this side cannot
        read, and nothing ever changes: the peer has a session and no reason
        to start another, and this side had no reason either. The frames are
        now the reason. A DAKE1 is sent -- never plaintext, never a reply to
        the frame's contents -- and the peer's engine answers it from a
        pending session, so their side is not disturbed unless the handshake
        completes.

        Bounded: once per `RECOVERY_INTERVAL` per peer, never for a room, and
        only to a contact whose OTRv4Plus capability is confirmed where the
        transport tracks it, so a stream of junk frames cannot make this
        device send handshakes to anybody.
        """
        take = getattr(self._engine, "take_orphan_data", None)
        if take is None or not take(peer):
            return
        if self.is_room(peer):
            return
        if self._capability_enforced() and self.otr_capability(peer) != "available":
            return
        now = self._clock()
        last = self._recovered_at.get(peer)
        if last is not None and now - last < self.RECOVERY_INTERVAL:
            return
        self._recovered_at[peer] = now
        _TRACE.record("otr", "orphan_data_recovery", "info", jid=peer)
        try:
            self.start_session(peer)
        except BridgeError:
            pass


