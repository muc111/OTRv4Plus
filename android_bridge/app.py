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

import json
import logging
import os
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
from .files import FileBridge, FileOutcome, is_file_signal
from .voice import CallBridge, CallOutcome, is_call_signal
from .groups import GroupError, SecureGroups, is_group_signal
import otrv4plus_presence as _presence
from otrv4plus_mode import OtrMode

from .events import (
    CallState, CallStateChanged, ConnectionState, ConnectionStateChanged,
    ChatStateChanged, ErrorOccurred, Event, EventSink, FingerprintChanged,
    GroupEntryRequested,
    HistorySynced, MessageChanged, MessageDelivered, MessageDisplayed, MessageReceived,
    MessageSentElsewhere, OtrCapabilityChanged, QueuedSent, RoomMessageAcked, RoomMessageReceived,
    SecurityState, SessionStateChanged, SmpProgress, SmpResult, SmpState,
    call_state_from_engine, security_state_from_level, smp_state_from_status,
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


def _new_message_id() -> str:
    import uuid
    return uuid.uuid4().hex


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

    # -- rooms -----------------------------------------------------------------

    def note_room_joined(self, room: str) -> None:
        """We are in [room]: its text is group chat from now on. A join
        completing on the loop thread after a wipe began records nothing."""
        if self._wiped:
            return
        room = self.canonical_peer(room)
        if room in self._knocking:
            return
        self._rooms.add(room)
        # A secure group whose own commit was lost with the old stream: post
        # it again now we are back in the room. Off this thread -- it is the
        # transport's loop thread, and a room send from it would wait on
        # itself.
        groups = getattr(self, "_groups", None)
        if groups is not None and getattr(groups, "on_room_rejoined", None):
            threading.Thread(target=self._quietly, args=(groups.on_room_rejoined, room),
                             name="group-rejoin", daemon=True).start()

    def note_knocking(self, room: str, on: bool) -> None:
        """We are about to be (or have stopped being) in [room] only to ask
        its members for an invitation: see ConnectionController.
        request_group_entry."""
        room = self.canonical_peer(room)
        if on:
            self._knocking.add(room)
        else:
            self._knocking.discard(room)
            self._rooms.discard(room)

    #: A request to be invited, posted in an encrypted group's room.
    ENTRY_REQUEST_PREFIX = "?OTRv4Plus-ASK:"
    #: The same requester in the same room is shown at most once per hour.
    ENTRY_REQUEST_EVERY = 3600.0
    #: Replayed history older than this is not shown at all.
    ENTRY_REQUEST_MAX_AGE = 24 * 3600.0

    def _entry_requested(self, room: str, body: str, timestamp: float,
                         own: bool, item: Any) -> None:
        """A request to be invited (ENTRY_REQUEST_PREFIX + {"jid": ...}).
        Shown to members as an address and two buttons; nothing happens
        unless one of them taps Invite."""
        if own:
            return
        try:
            data = json.loads(body[len(self.ENTRY_REQUEST_PREFIX):][:600])
            raw = str(data.get("jid", ""))
            jid = self.canonical_peer(raw)
        except Exception:
            return
        if "/" in raw:
            # A bare address or nothing: an invitation goes to an account.
            return
        local, _, domain = jid.partition("@")
        if (not local or not domain or len(jid) > 320 or "/" in jid
                or any(c.isspace() or ord(c) < 32 for c in jid)):
            return
        if jid == self._own_bare():
            return
        now = self._clock()
        live = item is None or getattr(item, "source", "live") == "live"
        if not live and timestamp and now - timestamp > self.ENTRY_REQUEST_MAX_AGE:
            return
        key = (room, jid)
        if now - self._entry_seen.get(key, 0.0) < self.ENTRY_REQUEST_EVERY:
            return
        self._entry_seen[key] = now
        self._emit(GroupEntryRequested(peer=room, requester=jid, live=live))

    def note_room_rejected(self, room: str, condition: str = "") -> None:
        """The server bounced a message we sent to `room`. For a secure group
        that may be our commit, which is posted again (off the loop thread,
        as above)."""
        if self._wiped:
            return
        room = self.canonical_peer(room)
        groups = getattr(self, "_groups", None)
        if groups is not None and room in self._rooms:
            threading.Thread(target=self._quietly, args=(groups.on_room_rejected, room),
                             name="group-rejected", daemon=True).start()

    @staticmethod
    def _quietly(fn, *args) -> None:
        try:
            fn(*args)
        except Exception:
            pass

    def note_room_left(self, room: str) -> None:
        self._rooms.discard(self.canonical_peer(room))

    def forget_rooms(self) -> None:
        """The stream went; so did every room membership it carried."""
        self._rooms.clear()
        self._handshake_seen.clear()

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

    def _room_refs(self):
        refs = getattr(self, "_room_refs_table", None)
        if refs is None:
            import otrv4plus_roomsync as _rs
            refs = self._room_refs_table = _rs.RoomRefs()
        return refs

    def receive_room_message(self, room: str, nick: str, body: str,
                             timestamp: float = 0.0, own: bool = False,
                             item: Any = None) -> None:
        """A room message from the transport. Emitted as its own event type,
        never as `MessageReceived`: nothing downstream may confuse a room's
        plaintext with a peer's decrypted text.

        A SECURE GROUP's room goes to `SecureGroups` and nowhere else: what
        comes out is MLS-decrypted text or nothing, never the raw body. `own`
        marks the room reflecting our own message back, which MLS needs (it
        is how a commit learns it won) and a plain room does not show."""
        room = self.canonical_peer(room)
        if room not in self._rooms or room in self._knocking:
            return
        groups = self._groups
        secure = groups is not None and groups.is_secure(room)
        if secure and body.startswith(self.ENTRY_REQUEST_PREFIX):
            self._entry_requested(room, body, timestamp, own, item)
            return
        if item is not None and (item.action or not body) and secure:
            # A plaintext action on a secure group's message is not
            # authenticated: ignored, never applied.
            return
        if not secure and item is not None and self._plain_room_item(room, nick, body,
                                                                      timestamp, own, item):
            return
        if groups is not None:
            try:
                if groups.on_room_body(room, nick, body, timestamp, own=own):
                    return
            except GroupError:
                return
        if body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            # An ENCRYPTED GROUP whose keys this device does not hold (never
            # joined, or its saved state was lost). Its ciphertext is never
            # shown as a message, and the room is never treated as plain:
            # sending into it is refused (`send_user_text`).
            if room not in self._keyless_groups:
                self._keyless_groups.add(room)
                self._emit(ErrorOccurred(peer=room, code="group_keys_missing"))
            return
        if own:
            return
        self._emit(RoomMessageReceived(peer=room, sender=nick, body=body,
                                       timestamp=timestamp))

    def _group_action(self, room: str, action: str, target_id: str, body: str,
                      emojis: Any, message_id: str) -> str:
        """A correction, deletion or reaction in a SECURE GROUP: an MLS
        application message (otrv4plus_actions envelope), never plaintext.
        Every member checks that the MLS-authenticated sender of a correction
        or deletion is the author of its target."""
        if action == "edit" and not (body or "").strip():
            return self.SEND_FAILED
        message_id = message_id if _actions.valid_id(message_id) else _new_message_id()
        try:
            env = _actions.encode_group_message(
                _actions.encode_meta(message_id, **{action: target_id},
                                     emojis=_actions.clean_emojis(list(emojis or []))),
                body if action == "edit" else "")
            outcome = self._groups.send(room, env)
        except Exception:
            return self.SEND_FAILED
        return self.SEND_QUEUED if outcome == "held" else self.SEND_ENCRYPTED

    def _room_action(self, room: str, action: str, target_id: str, body: str,
                     emojis: Any, message_id: str) -> str:
        """A correction, deletion or reaction in a PLAIN room, with the
        standard elements. A correction names the message's own id
        (XEP-0308); a deletion or reaction names the room's (XEP-0424/-0444)."""
        if room in self._keyless_groups:
            return self.SEND_FAILED
        send = getattr(self._transport, "send_room_message", None)
        if send is None:
            return self.SEND_FAILED
        emojis = _actions.clean_emojis(list(emojis or []))
        if action == "edit":
            if not (body or "").strip():
                return self.SEND_FAILED
            target, text = self._room_refs().own_id_of(room, target_id), body
        elif action == "retract":
            target, text = target_id, _actions.RETRACT_FALLBACK
        else:
            target, text = target_id, None
        message_id = message_id if _actions.valid_id(message_id) else _new_message_id()
        try:
            send(room, text, message_id=message_id,
                 elements=_actions.action_elements(action, target, emojis))
        except Exception:
            return self.SEND_FAILED
        return self.SEND_PLAINTEXT

    def _plain_room_item(self, room: str, nick: str, body: str, timestamp: float,
                         own: bool, item: Any) -> bool:
        """A plain room message with its ids (otrv4plus_roomsync). True if it
        was handled here (an echo, an action, or a message with ids)."""
        refs = self._room_refs()
        refs.remember(room, item.own_id, item.ref)
        if not refs.first_time(item):
            return True
        if own and item.source == "live":
            # The room's id for a message we sent: say so, show nothing.
            # (Our own from its history or archive is shown: see
            # XmppTransport._on_groupchat.)
            if item.own_id and item.stanza_id:
                self._emit(RoomMessageAcked(peer=room, message_id=item.own_id,
                                            stanza_id=item.stanza_id))
            return True
        if item.action:
            self._emit(MessageChanged(
                peer=room, action=item.action, target_id=refs.resolve(room, item.target),
                body=body if item.action == "edit" else "",
                emojis=tuple(item.emojis), outgoing=own, source=item.source,
                sender="" if own else nick))
            return True
        if not body or body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            return False
        self._emit(RoomMessageReceived(
            peer=room, sender=nick, body=body, timestamp=timestamp,
            message_id=item.ref, reply_to=refs.resolve(room, item.reply) if item.reply else "",
            source=item.source, own=own))
        return True

    # -- secure groups (MLS) ---------------------------------------------------

    #: Where the sealed group state lives: the Python home, which on Android
    #: is app-private storage and is removed by Wipe & Exit's storage stage.
    GROUP_STATE_DIR = "~/.otrv4plus/groups"

    @property
    def groups(self) -> SecureGroups:
        if self._groups is None:
            self._groups = SecureGroups(
                send_room=self._send_room_body,
                send_room_volatile=self._send_room_body_volatile,
                send_private=self._send_group_signal,
                emit=self._emit,
                peer_security=self.security_state,
                state_dir=os.path.expanduser(self.GROUP_STATE_DIR),
                clock=self._clock)
            # A password-protected group's room: its password goes to an
            # invitee with the invitation (groups.ROOMPW).
            self._groups.room_password_source = self._room_password
        return self._groups

    def _room_password(self, room: str) -> str:
        source = getattr(self._transport, "room_password", None)
        try:
            return str(source(room) or "") if source is not None else ""
        except Exception:
            return ""

    def open_groups(self, account: str) -> bool:
        """Open this account's secure groups. False when this build has no
        group encryption, which the UI reports rather than hiding."""
        try:
            self.groups.open(self.canonical_peer(account))
        except GroupError as exc:
            _TRACE.record("groups", "open_failed", "warning", code=exc.code)
            return False
        # Group verification (the group passphrase) and group calls: built
        # now, so a verification or a ring that arrives first is not lost.
        if self._group_verify is None:
            from .group_verify import GroupVerify
            self._group_verify = GroupVerify(self._groups, emit=self._emit,
                                             clock=self._clock)
        if self._group_calls is None:
            try:
                from .group_call_bridge import GroupCallBridge
                self._group_calls = GroupCallBridge(
                    self, sam=lambda: self.sam_endpoint, emit=self._emit)
            except Exception:
                _TRACE.record("groups", "group_calls_unavailable", "warning")
        if self._group_files is None:
            from .group_files import GroupFiles
            # Sealed at rest like a 1:1 file: the same viewer opens both.
            self._group_files = GroupFiles(self._groups, emit=self._emit,
                                           seal_at_rest=True, clock=self._clock)
        return True

    #: Where the I2P SAM bridge is; set by the controller from the profile.
    sam_endpoint = ("127.0.0.1", 7656)

    @property
    def group_verify(self):
        if self._group_verify is None:
            raise GroupError("not_ready")
        return self._group_verify

    @property
    def group_calls(self):
        if self._group_calls is None:
            raise GroupError("group_calls_unavailable")
        return self._group_calls

    def _send_room_body(self, room: str, body: str) -> None:
        sender = getattr(self._transport, "send_room_message", None)
        if sender is None:
            raise GroupError("no_transport")
        sender(room, body)

    def _send_room_body_volatile(self, room: str, body: str) -> None:
        """A group file's piece: with the room's no-store hint (XEP-0334)."""
        sender = getattr(self._transport, "send_room_message", None)
        if sender is None:
            raise GroupError("no_transport")
        sender(room, body, volatile=True)

    def _send_group_signal(self, peer: str, text: str) -> None:
        """Group setup goes inside an encrypted OTRv4+ session or not at all:
        never plaintext, and never a handshake started on its behalf."""
        has = getattr(self._engine, "has_encrypted_session", None)
        if has is None or not has(peer):
            raise GroupError("otr_required")
        frame, should_send = self._engine.handle_outgoing_message(peer, text)
        if not (should_send and frame):
            raise GroupError("otr_required")
        self._send_protocol_or_raise(peer, frame, "group_send_failed")

    def delete_server_account(self, timeout: Optional[float] = None) -> str:
        """Wipe & Exit's opt-in last word to the server: delete this account
        (XEP-0077). Runs on the live, already-authenticated session, AFTER the
        keys are destroyed in Rust and BEFORE the transport closes. Returns
        the transport's outcome ("deleted", "unconfirmed", "refused",
        "offline") or "unsupported". Never raises; never blocks for long."""
        transport = self._transport
        if transport is None:
            return "offline"
        remove = getattr(transport, "delete_account", None)
        if remove is None:
            return "unsupported"
        try:
            return str(remove(timeout))
        except Exception:
            return "unconfirmed"

    def wipe(self, delete_account: bool = False) -> Dict[str, Any]:
        """Wipe & Exit, Python side. Idempotent; the app is spent afterwards.

        [delete_account]: the user also asked for the account to be deleted
        on the server. Done after the Rust keys are gone (stage B) and before
        the transport closes; reported as `server_account`, and never a
        reason for the rest of the wipe to wait or stop.

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
          4. The engine, on the transport's loop thread, where inbound frames
             are processed, so the wipe cannot interleave with one.
             `EnhancedSessionManager.wipe` zeroizes every ratchet, SMP state,
             vault, handshake and the identity handles in Rust, then refuses
             all further use.
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
        # A note being recorded: the microphone off and the PCM overwritten.
        try:
            self.voice_note_cancel()
            self.voice_note_play_stop()
        except Exception:
            report["errors"].append("voice_note")

        # STAGE B FIRST: every secret destroyed in Rust before anything that
        # can wait on the network. See `wipe_crypto`.
        crypto = self.wipe_crypto()
        report["errors"].extend(crypto.get("errors", []))
        report.update({k: v for k, v in crypto.items()
                       if k not in ("errors", "already_wiped")})

        # STAGE C: stop the subsystems. The calls' keys are already gone, so
        # no END is attempted -- it could not be encrypted -- and the peer's
        # side times out; what remains is releasing audio, SAM and the loop.
        calls, self._calls_bridge = self._calls_bridge, None
        if calls is not None:
            try:
                calls.shutdown(graceful=False)
            except TypeError:
                calls.shutdown()
            except Exception:
                report["errors"].append("calls")

        # The server, if asked: the account and what the server keeps for it.
        report["server_account"] = (self.delete_server_account() if delete_account
                                    else "not_requested")

        transport = self._transport
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
        # Room memberships (addresses: who this account talks to in groups)
        # and the diagnostics trace (aliased, but still a record of activity).
        try:
            self.forget_rooms()
        except Exception:
            report["errors"].append("rooms")
        try:
            from .trace import TRACE as _trace
            _trace.clear()
        except Exception:
            report["errors"].append("trace")
        try:
            from . import server_pins as _pins
            _pins.default_store().forget()
        except Exception:
            report["errors"].append("server_pins")

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

    def wipe_crypto(self) -> Dict[str, Any]:
        """Wipe & Exit, STAGE B: destroy every secret in Rust. Local only.

        Runs before anything that can wait on a network timeout, so that the
        cryptographic state is gone first whatever happens after:

          * each call's key schedule, key exchange and media ciphers,
            force-closed (`CallBridge.destroy_keys`) -- no END is sent;
          * each transfer's FileKey, zeroized, and partial files unlinked;
          * the engine (`EnhancedSessionManager.wipe`): every ratchet, DAKE,
            SMP state and vault, and the identity and prekey handles -- on
            the transport's loop thread, so it cannot interleave with an
            inbound frame.

        Sets `_wiped` first, so nothing can recreate state meanwhile.
        Idempotent; never raises. `wipe()` calls it before its own teardown.
        """
        with self._wipe_lock:
            already = getattr(self, "_crypto_wiped", False)
            self._crypto_wiped = True
            self._wiped = True
        report: Dict[str, Any] = {"already_wiped": already, "errors": []}
        if already:
            return report
        # Lines waiting to be sent are plaintext the user typed: gone too.
        for box in getattr(self, "_outbox", {}).values():
            box.clear()
        getattr(self, "_outbox", {}).clear()
        getattr(self, "_markable", {}).clear()
        # The archive cursor (android_bridge.sync): an opaque id, but it is
        # this account's, and Wipe & Exit leaves nothing of the account.
        try:
            import otrv4plus_sync as _sync
            from .sync import CURSOR_PATH
            _sync.ArchiveCursor(os.path.expanduser(CURSOR_PATH)).forget()
        except Exception as exc:
            report["errors"].append("sync_cursor:%s" % type(exc).__name__)
        getattr(self, "_invite_after_otr", {}).clear()

        calls = self._calls_bridge
        if calls is not None:
            destroy = getattr(calls, "destroy_keys", None)
            try:
                if destroy is not None:
                    destroy()
                else:
                    calls.shutdown()
                    self._calls_bridge = None
            except Exception:
                report["errors"].append("call_keys")
        files, self._files_bridge = self._files_bridge, None
        if files is not None:
            try:
                files.shutdown()
            except Exception:
                report["errors"].append("transfers")
        group_files, self._group_files = self._group_files, None
        if group_files is not None:
            try:
                group_files.close()
            except Exception:
                report["errors"].append("group_transfers")
        # Every MLS group secret, pending commit and the signing key, in
        # Rust, and the sealed state file. Constructed here if it was never
        # used, so a state file from a previous run is removed too.
        try:
            self.groups.wipe()
        except Exception:
            report["errors"].append("groups")

        engine_wipe = getattr(self._engine, "wipe", None)

        def _wipe_engine():
            if engine_wipe is not None:
                return engine_wipe("wipe and exit")
            self._engine.clear_all_sessions("wipe and exit")
            return {}

        runner = getattr(self._transport, "run_on_loop_thread", None)
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
        return report

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
                    self._send_user(peer, text, getattr(body, "message_id", ""))
                except Exception:
                    break
                box.pop(0)
                sent += 1
            if sent:
                self._touch(peer)
                self._emit(QueuedSent(peer=peer, count=sent, encrypted=True))
        elif (self._capability_enforced()
              and self.otr_capability(peer) == "unavailable"
              and not self._mode.is_otr(peer)):
            # Online and confirmed not to speak OTRv4+: written to in the
            # clear, labelled as such. Never a contact that ever asked for
            # OTR (`is_otr`).
            sent = 0
            while box:
                try:
                    self._send_user(peer, str(box[0]),
                                    getattr(box[0], "message_id", ""))
                except Exception:
                    break
                box.pop(0)
                sent += 1
            if sent:
                self._touch(peer)
                self._emit(QueuedSent(peer=peer, count=sent, encrypted=False))
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
        if state in ("offline", "checking", "unknown"):
            return "waiting_for_otr"
        if state == "unavailable":
            self._invite_after_otr.pop(peer, None)
            raise BridgeError("otrv4plus_unavailable",
                              "this contact's app does not support OTRv4+")
        return "waiting_for_otr"

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

        if self._mode.may_send_plaintext(
                peer, self.security_state(peer) is not SecurityState.PLAINTEXT):
            try:
                plain = getattr(self._transport, "send_plain_action", None)
                if reply_to and message_id and plain is not None and \
                        _actions.valid_id(reply_to):
                    # XEP-0461: a reply says which message it answers.
                    plain(peer, body, message_id,
                          _actions.action_elements("reply", reply_to))
                else:
                    self._send_user(peer, body, message_id)
            except Exception:
                return self.SEND_FAILED
            self._touch(peer)
            return self.SEND_PLAINTEXT

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
        if not self._mode.may_send_plaintext(peer, False):
            return self.SEND_FAILED
        # The rule plaintext messages follow: never in the clear to somebody
        # who might speak OTRv4+ (send_user_text holds those until it knows).
        if self._capability_enforced() and self.otr_capability(peer) != "unavailable":
            return self.SEND_FAILED
        plain = getattr(self._transport, "send_plain_action", None)
        if plain is None:
            return self.SEND_FAILED
        try:
            elements = _actions.action_elements(action, target_id, emojis)
            out_body = (text if action == "edit" else
                        _actions.RETRACT_FALLBACK if action == "retract" else None)
            plain(peer, out_body, message_id, elements)
        except Exception:
            return self.SEND_FAILED
        self._touch(peer)
        return self.SEND_PLAINTEXT

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

    def _announce_smp_change(self, peer: str, before: SmpState) -> None:
        """Emit an event when an inbound frame moved this peer's verification
        state.

        Needed because an SMP1 on an already-encrypted session does not change the
        security level, so no `SessionStateChanged` would announce it. Emitted only
        on a real transition: a resent SMP1 must not stack prompts. This reports the
        state only; the UI asks for the secret in its own dialog (see
        `smp_respond`).
        """
        after = self.smp_state(peer)
        if after == before:
            return
        if after in (SmpState.VERIFIED, SmpState.FAILED, SmpState.CANCELLED):
            self._emit(SmpResult(peer=peer, state=after))
            if after is SmpState.VERIFIED and self._groups is not None:
                # Verified now: the groups we share with them learn it, and
                # each side sends its group key (calls need verified members).
                try:
                    self._groups.on_peer_verified(peer)
                except Exception:
                    _log.warning("group verification update failed")
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
        except Exception as exc:
            code = self._smp_start_refusal(exc)
            self._emit(ErrorOccurred(peer=peer, code=code))
            raise BridgeError(code)
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

    @staticmethod
    def _smp_start_refusal(exc: BaseException) -> str:
        """Name why the engine would not start a run (cooldown, attempts used
        up, ...), so the UI can say "wait" instead of "failed". The engine's
        text is matched here and never shown: only the code leaves."""
        text = str(exc)
        if "cooldown" in text:
            return "smp_cooldown"
        if "max attempt limit" in text:
            return "smp_attempts_exhausted"
        if "already verified" in text:
            return "smp_already_verified"
        if "already in progress" in text:
            return "smp_in_progress"
        return "smp_start_failed"

    def smp_respond(self, peer: str, secret: str) -> None:
        """Answer a peer's verification challenge: set the secret, resume the
        SMP1 the core is holding (`resume_held_smp1`) and send the resulting SMP2.

        Safe under INV-06 (SECURITY_INVARIANTS.md: a peer may cause the client to
        ASK for the secret, never cause the next thing typed to BECOME it). Here
        that separation is structural: this is reached only from a dialog with its
        own secret field, while chat text goes to `send_user_text`.
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
        if self._wiped:
            return FileOutcome.UNAVAILABLE
        if self.is_room(peer):
            # A secure group's file goes to the whole group, over MLS
            # (android_bridge.group_files); an ordinary room has none.
            room = self.canonical_peer(peer)
            if self._group_files is None or not self.groups.is_secure(room):
                return FileOutcome.UNAVAILABLE
            return self._group_files.send(room, path, bool(strip_metadata))
        return self.files.send_file(self.canonical_peer(peer), path,
                                    bool(strip_metadata))

    def inspect_file(self, path: str) -> Dict[str, Any]:
        """Whether [path] carries metadata the app can remove.

        Asked BEFORE sending, so the user can choose. See
        `android_bridge.metadata` for exactly what counts and what is kept.
        """
        return self.files.inspect(path)

    # -- voice notes -----------------------------------------------------------
    #
    # A voice note is recorded into memory, put through the voice mask
    # (otrv4plus_voicenote, Rust/src/voice_mask.rs), written as a small
    # metadata-free audio file, and then sent with `send_file` like any other
    # file -- so the session and verification gates are the file gates.

    def _voice(self):
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            import otrv4plus_voicenote as vn
            rec = self._voice_recorder = vn.Recorder()
        return rec

    def voice_note_modes(self) -> Dict[str, Any]:
        """The choices, and whether the mask is in this build."""
        import otrv4plus_voicenote as vn
        return {"modes": list(vn.MODES), "default": vn.DEFAULT_MODE,
                "labels": {m: vn.describe_mode(m) for m in vn.MODES},
                "mask_available": vn.mask_available(),
                "max_seconds": vn.MAX_SECONDS}

    def voice_note_start(self) -> str:
        """Start recording. "ok", or why not."""
        if self._wiped:
            return "unavailable"
        import otrv4plus_voicenote as vn
        try:
            self._voice().start()
        except vn.VoiceNoteError as exc:
            # Which backend refused and why ("parec not found"): no content.
            _log.warning("voice note: %s (%s)", exc.code, exc)
            return exc.code
        except Exception:
            return "no_microphone"
        return "ok"

    def voice_note_status(self) -> Dict[str, Any]:
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            return {"recording": False, "seconds": 0.0, "level": 0.0, "error": ""}
        return {"recording": rec.recording, "seconds": round(rec.seconds, 1),
                "level": round(rec.level, 3), "error": rec.error}

    def voice_note_stop(self, mode: str, directory: str) -> Dict[str, Any]:
        """Stop, mask and write the note under [directory]. {"path", "seconds",
        "mode", "format", "bytes"} or {"error": code}. The raw recording is
        wiped either way; a masked note is never replaced by an unmasked one."""
        import otrv4plus_voicenote as vn
        rec = getattr(self, "_voice_recorder", None)
        if rec is None:
            return {"error": "too_short"}
        pcm, rate = rec.stop(vn.TAIL_SECONDS)
        try:
            if not directory:
                import otrv4plus_filetransfer as _ft
                directory = _ft.staging_dir()
            return vn.make_note(pcm, rate, mode, directory)
        except vn.VoiceNoteError as exc:
            return {"error": exc.code}
        except Exception:
            _log.warning("voice note could not be made")
            return {"error": "bad_file"}

    def send_voice_note(self, peer: str, path: str) -> Dict[str, Any]:
        """Send a note made by `voice_note_stop`, keeping a sealed copy so it
        can be played back from the chat like a received one.

        {"outcome": FileOutcome, "path": the kept copy, or ""}. The gates are
        `send_file`'s; a refused note keeps nothing."""
        from .files import keep_sent_note
        kept = keep_sent_note(path)
        outcome = self.send_file(peer, path, False)
        if outcome != FileOutcome.STARTED and kept:
            try:
                os.unlink(kept)
            except OSError:
                pass
            kept = ""
        return {"outcome": outcome, "path": kept}

    def voice_note_cancel(self) -> None:
        rec = getattr(self, "_voice_recorder", None)
        if rec is not None:
            rec.cancel()

    def voice_note_play(self, path: str) -> Dict[str, Any]:
        """Play a note (a preview, or a received one) through the call audio
        path. For hosts without a media player of their own (desktop)."""
        import otrv4plus_voicenote as vn
        try:
            data = self._note_bytes(path)
            player = getattr(self, "_voice_player", None)
            if player is None:
                player = self._voice_player = vn.Player()
            return {"seconds": round(player.play(data), 1)}
        except vn.VoiceNoteError as exc:
            _log.warning("voice note playback: %s (%s)", exc.code, exc)
            return {"error": exc.code}
        except Exception as exc:
            _log.warning("voice note playback: %s", type(exc).__name__)
            return {"error": "bad_file"}

    def _note_bytes(self, path: str) -> bytes:
        """A note's file, decrypted in memory when it is a sealed container
        (`files.open_received` checks it is one, in the received directory);
        otherwise only an unsent note of ours (voice-note-*)."""
        import otrv4plus_voicenote as vn
        if path.endswith(".otrv"):
            return self.files.open_received(path)
        if not os.path.basename(path or "").startswith("voice-note-"):
            raise ValueError("not a voice note")
        with open(path, "rb") as f:
            return f.read(vn.MAX_NOTE_BYTES + 1)

    def voice_note_waveform(self, path: str, bars: int = 0) -> Dict[str, Any]:
        """{"bars": [0..1, ...], "seconds"} for a note's bubble, or
        {"error": code}. Decoded by the same bounded decoder as playback;
        nothing is written anywhere."""
        import otrv4plus_voicenote as vn
        try:
            pcm, rate = vn.decode(self._note_bytes(path))
            return {"bars": vn.waveform(pcm, rate, int(bars or vn.WAVEFORM_BARS)),
                    "seconds": round(len(pcm) / 2 / max(rate, 1), 1)}
        except vn.VoiceNoteError as exc:
            return {"error": exc.code}
        except Exception:
            return {"error": "bad_file"}

    def voice_note_play_status(self) -> Dict[str, Any]:
        """Where playback is, for the waveform: {"playing", "position", "seconds"}."""
        player = getattr(self, "_voice_player", None)
        if player is None or not player.playing:
            return {"playing": False, "position": 0.0, "seconds": 0.0}
        return {"playing": True, "position": round(player.position, 2),
                "seconds": round(player.seconds, 2)}

    def voice_note_play_stop(self) -> None:
        player = getattr(self, "_voice_player", None)
        if player is not None:
            player.stop()

    def voice_note_discard(self, path: str) -> None:
        """Delete a note that was not sent."""
        name = os.path.basename(path or "")
        if name.startswith("voice-note-"):
            try:
                os.unlink(path)
            except OSError:
                pass

    def accept_file(self, transfer_id: str) -> str:
        """Accept an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.UNAVAILABLE
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.accept(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.accept(transfer_id)

    def decline_file(self, transfer_id: str) -> str:
        """Decline an offered transfer. Returns a `FileOutcome` code."""
        if self._wiped:
            return FileOutcome.NO_TRANSFER
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.decline(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.decline(transfer_id)

    def cancel_file(self, transfer_id: str) -> str:
        """Stop a transfer that is under way, either direction. A `FileOutcome`."""
        if self._wiped:
            return FileOutcome.NO_TRANSFER
        if self._group_files is not None and self._group_files.knows(transfer_id):
            return (FileOutcome.STARTED if self._group_files.cancel(transfer_id)
                    else FileOutcome.NO_TRANSFER)
        return self.files.cancel(transfer_id)

    def transfers(self) -> List[Dict[str, Any]]:
        """Every live transfer, structured. Never the engine's own sentences."""
        if self._wiped:
            return []
        group = self._group_files.transfers() if self._group_files is not None else []
        return self.files.transfers() + group

    def received_file_dir(self) -> str:
        """Where a FINISHED file lands, as the engine decides it.

        Not the partial-work directory, which the engine keeps separate so a
        partial file can never be mistaken for a complete one.
        """
        return self.files.received_dir()

    # A received file rests as a `.otrv` container (Rust-sealed). These open
    # it without leaving plaintext behind, or save it on an explicit request.
    # Failures are codes: a container that does not open says so, and never
    # why in engine words.

    def open_received(self, path: str) -> bytes:
        """Decrypt into memory for the in-app viewer."""
        try:
            return self.files.open_received(path)
        except Exception:
            raise BridgeError("open_failed", "the file could not be opened")

    def open_received_to(self, path: str, directory: str) -> str:
        """Decrypt to a transient file for a viewer that needs one (PDF,
        video). The caller deletes it when the viewer closes."""
        try:
            return self.files.open_received_to(path, directory)
        except Exception:
            raise BridgeError("open_failed", "the file could not be opened")

    def save_received(self, path: str, destination: str) -> str:
        """Explicit Save to `destination`, replacing a file already there."""
        try:
            self.files.save_received(path, destination)
            return "ok"
        except Exception:
            return "save_failed"

    def export_received(self, path: str, destination: str, passphrase: str) -> str:
        """A passphrase-sealed `.otrv` any OTRv4Plus build can import."""
        if len(passphrase or "") < 8:
            return "passphrase_too_short"
        try:
            self.files.export_received(path, destination, passphrase)
            return "ok"
        except Exception:
            return "export_failed"

    def poll_calls(self) -> None:
        """Emit an event for any call whose state moved.

        The manager publishes no state callback, so movement is noticed by
        reading. Driven from the host's existing drain rather than a timer of
        its own, so there is one observer and nothing to leak.
        """
        if self._calls_bridge is not None and not self._wiped:
            self._calls_bridge.poll()
