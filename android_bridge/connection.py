"""Bringing a connection up, and saying precisely where it stopped.

The connection path has five places to fail and they need five different
sentences, because the thing a user should do about each is different:

    1. no SAM bridge reachable      -> start your router
    2. SAM reachable, not SAM       -> something else is on that port
    3. SAM ok, tunnel never built   -> wait, or the network is hostile
    4. tunnel ok, XMPP refused      -> the server is down or the address is wrong
    5. XMPP ok, login refused       -> the account or the password is wrong

Rolled into one "could not connect" they are indistinguishable, and the first
two are separated by seconds while the third takes up to four minutes. A
progress spinner that cannot tell them apart is how someone spends an evening
restarting an app that was never going to work.

So `probe_sam` exists: a SAMv3 HELLO, which is a local handshake answering in
milliseconds, run *before* the tunnel attempt. It converts "hangs for 240
seconds then fails" into "your router is not running", immediately.

The loopback question
---------------------
`ANDROID_I2P_FEASIBILITY.md` §2 calls it "the single most important technical
finding in this report": that a SAM bridge belonging to another app is not
reachable at 127.0.0.1:7656 because "every app has its own UID and its own
loopback view".

That claim is doubtful. Standard Android has no per-app network namespace --
that is `isolatedProcess` and separate users/work profiles, not ordinary apps
on one device -- and the counter-example is routine: apps reach Orbot's SOCKS
proxy on 127.0.0.1:9050 by explicit configuration, which is exactly this
pattern. If the claim is wrong, bundling a router stops being a precondition
for a working app and becomes a convenience for users who do not want to run
one themselves.

It is not restated here as a fact in the other direction. `probe_sam` is how it
gets settled: run it on a handset with i2pd in Termux and the answer is a
result code rather than an argument.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger("otrv4plus.bridge.connection")

import otrv4plus_address as _address

from .settings import ConnectionProfile


def _c2s_port() -> int:
    """The far-side XMPP port, read from the transport rather than repeated."""
    try:
        from .transport import DEFAULT_C2S_PORT
        return DEFAULT_C2S_PORT
    except Exception:
        return 5222

__all__ = [
    "probe_sam", "SamProbe",
    "SAM_HELLO", "SAM_PROBE_TIMEOUT",
]

#: SAMv3's opening line. MIN/MAX bracket the versions we can speak; i2pd
#: answers with the highest it supports. Sent verbatim by the engine's own SAM
#: code, and repeated here rather than imported because importing it would drag
#: the whole engine into a screen whose job is to say whether a port answers.
SAM_HELLO = b"HELLO VERSION MIN=3.0 MAX=3.1\n"

#: Seconds. A local handshake, so this is generous rather than tight -- but it
#: is emphatically NOT the tunnel timeout. SAM_CONNECT_TIMEOUT is 240s because
#: building a tunnel is slow; answering HELLO is not, and waiting minutes to
#: discover a port is closed is the failure this whole module exists to avoid.
SAM_PROBE_TIMEOUT = 5.0


class SamProbe:
    """What a probe found. A result, not an exception.

    An exception would be wrong here: "no router" is the expected state on a
    fresh install, not an error condition, and the screen wants to render it
    as guidance rather than catch it.
    """

    __slots__ = ("reachable", "code", "detail", "version")

    def __init__(self, reachable: bool, code: str, detail: str,
                 version: str = ""):
        self.reachable = reachable
        #: Stable, for the UI to branch on. One of: ok, refused, timeout,
        #: not_sam, unreachable.
        self.code = code
        #: A sentence for a person, naming what to do where that is knowable.
        self.detail = detail
        #: The SAM version the bridge agreed to, when it got that far.
        self.version = version

    def __repr__(self) -> str:
        return ("<SamProbe %s code=%s version=%r>"
                % ("reachable" if self.reachable else "unreachable",
                   self.code, self.version))

    def as_dict(self) -> Dict[str, Any]:
        """For the Kotlin side, which cannot read attributes off a PyObject
        as cheaply as it can read a map."""
        return {"reachable": self.reachable, "code": self.code,
                "detail": self.detail, "version": self.version}


def probe_sam(host: str, port: int, timeout: float = SAM_PROBE_TIMEOUT,
              opener: Optional[Callable[..., Any]] = None) -> SamProbe:
    """Ask whether a SAM bridge is listening, and answer in milliseconds.

    Deliberately does not create a session. `SESSION CREATE` makes i2pd build a
    complete set of tunnels before it replies -- minutes, on a phone -- and the
    question here is only whether there is a router to talk to at all.

    *opener* is injected by the tests; nothing else should pass it.
    """
    connect = opener or socket.create_connection
    try:
        sock = connect((host, port), timeout)
    except ConnectionRefusedError:
        return SamProbe(
            False, "refused",
            "Nothing is listening on %s:%d. Start your I2P router and make "
            "sure its SAM bridge is enabled (i2pd: sam.enabled=true in "
            "i2pd.conf)." % (host, port))
    except socket.timeout:
        return SamProbe(
            False, "timeout",
            "%s:%d did not answer within %gs. A SAM bridge on this device "
            "should answer immediately." % (host, port, timeout))
    except OSError as exc:
        # Includes EHOSTUNREACH, ENETUNREACH, EACCES. The type, not the
        # message: an OSError's text carries paths and addresses.
        return SamProbe(
            False, "unreachable",
            "Could not reach %s:%d (%s)." % (host, port, type(exc).__name__))

    try:
        sock.settimeout(timeout)
        sock.sendall(SAM_HELLO)
        reply = _read_line(sock, timeout)
    except OSError as exc:
        return SamProbe(
            False, "not_sam",
            "%s:%d accepted a connection but the SAM handshake failed (%s). "
            "Something other than a SAM bridge may be on that port."
            % (host, port, type(exc).__name__))
    finally:
        try:
            sock.close()
        except Exception:
            pass

    text = reply.decode("ascii", "replace").strip()
    if "RESULT=OK" not in text:
        return SamProbe(
            False, "not_sam",
            "%s:%d answered, but not as a SAM bridge would (%r)."
            % (host, port, text[:120]))
    return SamProbe(
        True, "ok",
        "SAM bridge reachable at %s:%d." % (host, port),
        version=_version_from(text))


def _read_line(sock, timeout: float) -> bytes:
    """One newline-terminated line, bounded.

    Bounded because the far end is not necessarily a SAM bridge -- that is the
    thing being tested -- and reading until newline from an arbitrary service
    is how a probe becomes a hang.
    """
    buf = bytearray()
    while b"\n" not in buf and len(buf) < 512:
        chunk = sock.recv(256)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _version_from(reply: str) -> str:
    for token in reply.split():
        if token.startswith("VERSION="):
            return token.partition("=")[2]
    return ""


class ConnectionController:
    """Brings a connection up one stage at a time, and names the stage.

    The stages are the five failures in this module's docstring, in order.
    Each one reports before the next is attempted, so the UI can show
    "checking router" -> "building tunnels" -> "connecting" -> "authenticating"
    rather than a spinner that means all four.

    Holds the real `OtrApp` and the real `XmppTransport`. Nothing here
    simulates a connection or a security state: if the DAKE has not run, the
    security state is UNENCRYPTED because that is what the engine says, not
    because a placeholder was chosen.
    """

    #: In order, then the states a live connection can end up in. Reported as
    #: they are entered, so a stall is attributable.
    #:
    #: `disconnected` and `cancelled` are here because they were being entered
    #: without being declared: the transport emits "disconnected" when the
    #: server drops the stream, the lambda below passed it straight through,
    #: and the screen rendered a stage this tuple said did not exist. A stage
    #: vocabulary that the code can step outside of is not a vocabulary.
    STAGES = ("idle", "checking_router", "building_tunnels",
              "connecting", "authenticating", "connected",
              "disconnected", "cancelled", "failed")

    def __init__(self, app: Any, profile: ConnectionProfile,
                 *, transport_factory: Optional[Callable[..., Any]] = None,
                 prober: Optional[Callable[..., SamProbe]] = None,
                 on_state: Optional[Callable[[str, str], None]] = None):
        self._app = app
        self._profile = profile
        self._transport_factory = transport_factory
        self._prober = prober or probe_profile
        self._on_state = on_state
        self._transport: Any = None
        self._stage = "idle"
        self._last: Dict[str, Any] = {}
        #: Whether a password was supplied, and nothing else about it. A bool,
        #: never the value: this object is rendered into a status map that
        #: crosses into Kotlin and ends up in an exported report.
        self._password_present = False
        #: Guards against two overlapping attempts. See `connect`.
        self._connect_lock = threading.Lock()
        self._connecting = False

        # Installed here rather than at connect time: a DAKE frame can arrive
        # in the same breath as session_start, and an event emitted before the
        # sink exists is an event nobody ever sees.
        from .eventlog import EventQueue
        self._events = EventQueue()
        try:
            self._app.set_event_sink(self._events)
        except Exception:
            # A facade that cannot take a sink still connects; the UI polls
            # the typed getters instead and loses live updates, not function.
            pass

    @property
    def stage(self) -> str:
        return self._stage

    @property
    def profile(self) -> ConnectionProfile:
        return self._profile

    #: Transport state -> controller stage. Written out because the two
    #: vocabularies genuinely differ and the difference is not obvious: the
    #: transport's "connected" means the XMPP stream is up, which is the
    #: controller's "connecting" -- there is still a SASL exchange to go, and
    #: calling that connected is the one claim this whole module exists not to
    #: make. Anything not named here is passed through and validated.
    _TRANSPORT_STAGE = {
        "building_tunnels": "building_tunnels",
        "connected": "connecting",
        "disconnected": "disconnected",
        "failed": "failed",
    }

    def _on_subscription_request(self, _jid: str) -> None:
        """Someone asked to see our presence.

        Under the shipped ACCEPT policy slixmpp has already said yes, so this
        is a notification rather than a question, and the contact appears in
        the list on the next poll either way.

        Deliberately NOT pushed through the event queue. `EventQueue._describe`
        flattens dataclasses, so a plain dict arrives in Kotlin as
        `{"type": "dict"}` with no fields and the mapper drops it -- a new
        event type would need a dataclass in `android_bridge.events`, a Kotlin
        branch and an entry in the mapping test. That is worth doing when the
        UI has somewhere to show it; wiring half of it now would leave a
        notification that silently goes nowhere.

        The JID is not logged. Who is asking to watch this device's presence
        is exactly the kind of thing logcat should not have.
        """
        _log.info("a subscription request arrived and was handled by policy")

    def _on_transport_state(self, state: str, _server: str) -> None:
        """Translate a transport state into a stage, and never invent one."""
        stage = self._TRANSPORT_STAGE.get(state, state)
        if stage not in self.STAGES:
            # A transport state this controller has no stage for. Dropping it
            # is right -- rendering an undeclared stage is what put the string
            # "disconnected" on a screen whose labels did not cover it -- but
            # it is worth a line, because it means the two have drifted.
            _log.info("ignoring an unmapped transport state")
            return
        # A drop after we were up is not a stage on the way to connecting, so
        # the connected flag has to go with it or `status` keeps saying yes.
        self._enter(stage)

    def _enter(self, stage: str) -> None:
        self._stage = stage
        if self._on_state is None:
            return
        try:
            self._on_state(stage, self._profile.effective_server)
        except Exception:
            pass

    def _fail(self, code: str, detail: str) -> Dict[str, Any]:
        failed_at, self._stage = self._stage, "failed"
        self._enter("failed")
        self._last = {"ok": False, "stage": failed_at,
                      "code": code, "detail": detail}
        return dict(self._last)

    def connect(self, password: str) -> Dict[str, Any]:
        """Bring the connection up. Returns a result dict, never raises.

        A dict rather than an exception because every caller is Kotlin, and an
        exception crossing Chaquopy arrives as a PyException whose message is
        the only thing that survives -- which is exactly the failure mode that
        made the first handset report say nothing but "PyException".
        """
        # One attempt at a time. Two are easy to start by accident on Android
        # -- rotate the screen during a tunnel build and the recreated screen
        # presses Connect again -- and two would each build their own tunnel,
        # each set `app._transport`, and the loser would leave a live worker
        # thread and an I2P lease behind with nothing holding a reference.
        with self._connect_lock:
            if self._connecting:
                return {"ok": False, "stage": self._stage,
                        "code": "already_connecting",
                        "detail": "A connection attempt is already running."}
            if self._transport is not None and getattr(
                    self._transport, "is_connected", False):
                return {"ok": True, "stage": "connected", "code": "ok",
                        "detail": "Already connected."}
            self._connecting = True
        try:
            return self._connect(password)
        finally:
            with self._connect_lock:
                self._connecting = False

    def _connect(self, password: str) -> Dict[str, Any]:
        self._password_present = bool(password)
        self._enter("checking_router")
        probe = self._prober(self._profile)
        if not probe.reachable:
            return self._fail(probe.code, probe.detail)

        try:
            factory = self._transport_factory or _default_transport_factory()
            self._transport = factory(
                self._profile, password,
                on_payload=self._app.receive_message,
                on_state=self._on_transport_state,
                # Presence was never wired, so `OtrApp._presence` stayed
                # empty and every contact rendered "offline" no matter what
                # the server said. The transport has always emitted these;
                # nobody was listening.
                on_presence=self._app.note_presence,
                on_subscription_request=self._on_subscription_request,
            )
        except Exception as exc:
            return self._fail("transport_failed", type(exc).__name__)

        # The transport is what OtrApp sends through. Set before connecting so
        # a stanza arriving during session_start has somewhere to go.
        self._app._transport = self._transport
        self._enter("connecting")
        try:
            self._transport.connect()
        except Exception as exc:
            code = getattr(exc, "code", "connect_failed")
            detail = getattr(exc, "detail", "") or type(exc).__name__
            # A failed attempt keeps nothing. The transport has already given
            # back its tunnel and stopped slixmpp retrying; dropping the
            # reference here means the next Connect builds a fresh one rather
            # than finding a half-dead object and believing it usable.
            self._release_transport()
            if code == "cancelled":
                # Not a failure. Somebody pressed Back, and reporting it in red
                # next to "could not connect" teaches people to ignore the red.
                self._enter("cancelled")
                self._last = {"ok": False, "stage": "cancelled",
                              "code": "cancelled",
                              "detail": "The connection attempt was stopped."}
                return dict(self._last)
            return self._fail(code, detail)

        self._enter("connected")
        self._last = {"ok": True, "stage": "connected", "code": "ok",
                      "detail": "Connected to %s as %s"
                                % (self._profile.effective_server,
                                   self._profile.jid),
                      "sam_version": probe.version}
        return dict(self._last)

    def cancel(self) -> Dict[str, Any]:
        """Stop an attempt that is still running.

        Separate from `disconnect` because they mean different things to a
        user: one stops something that has not happened yet, the other ends
        something that has. Rolled together, a Cancel button would also have
        to be a Disconnect button, and pressing it during a tunnel build would
        be indistinguishable from pressing it while connected.

        Returns immediately. The blocked `connect` call on the other thread is
        what actually unwinds, and it reports `cancelled` when it does.
        """
        transport = self._transport
        if transport is None:
            return {"ok": True, "code": "not_connecting",
                    "detail": "Nothing to cancel."}
        try:
            transport.cancel()
        except Exception as exc:
            return {"ok": False, "code": "cancel_failed",
                    "detail": type(exc).__name__}
        return {"ok": True, "code": "ok",
                "detail": "Stopping the connection attempt."}

    def disconnect(self) -> Dict[str, Any]:
        """Tear down. Best effort, and always ends at a known state."""
        self._release_transport()
        self._enter("idle")
        self._last = {"ok": True, "stage": "idle", "code": "ok",
                      "detail": "Disconnected."}
        return dict(self._last)

    def _release_transport(self) -> None:
        """Close the transport and forget it. Never raises.

        `close` rather than `disconnect`: the worker thread and the SAM tunnel
        belong to the transport object, and a transport we are dropping the
        last reference to must not leave either behind. A disconnected-but-open
        transport is exactly the shape that leaked a loop thread per attempt.
        """
        transport, self._transport = self._transport, None
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        try:
            self._app._transport = None
        except Exception:
            pass

    def drain_events(self, limit: int = 0) -> List[Dict[str, Any]]:
        """Hand the UI everything that has happened since it last asked.

        Pull rather than push: these are emitted on the transport's loop
        thread, and a callback into Kotlin from there would put a
        thread-marshalling obligation on every screen that ever handles one.
        """
        return self._events.drain(limit)

    def add_contact(self, jid: str, name: str = "") -> Dict[str, Any]:
        """Roster operations, forwarded to the transport.

        On the controller rather than reached through it, so Kotlin keeps
        talking to one object. A result dict rather than an exception, for the
        same reason `connect` returns one: a PyException crossing Chaquopy
        arrives with its message as the only survivor.
        """
        return self._roster_call("add_contact", jid, name)

    def remove_contact(self, jid: str) -> Dict[str, Any]:
        return self._roster_call("remove_contact", jid)

    def answer_subscription(self, jid: str, approve: bool) -> Dict[str, Any]:
        return self._roster_call("answer_subscription", jid, approve)

    def _roster_call(self, name: str, *args) -> Dict[str, Any]:
        transport = self._transport
        if transport is None:
            return {"ok": False, "code": "not_connected",
                    "detail": "Connect before changing the contact list."}
        try:
            getattr(transport, name)(*args)
        except Exception as exc:
            return {"ok": False,
                    "code": getattr(exc, "code", "roster_failed"),
                    "detail": getattr(exc, "detail", "")
                              or type(exc).__name__}
        return {"ok": True, "code": "ok", "detail": ""}

    def events_dropped(self) -> int:
        """How many events the bound discarded. A gap is worth saying."""
        return self._events.dropped()

    def probe(self) -> Dict[str, Any]:
        """Just the router check, as a plain dict.

        Exposed as a method so the Kotlin side never reaches into `_profile`.
        A private attribute read across a language boundary is a coupling that
        breaks without a compiler noticing.
        """
        return self._prober(self._profile).as_dict()

    def inputs(self, password: Optional[str] = None) -> Dict[str, Any]:
        """What actually arrived from Kotlin, minus the password itself.

        A value that crosses a language boundary and then fails is two
        questions -- did the call fail, or did it get the wrong arguments --
        and without this they are indistinguishable from a handset. Every
        field here is one the connection depends on and none of them is
        secret.

        The password is reported as present or absent and nothing else. Not
        its length: a length is a real clue to an attacker who gets the
        report, and it answers no question a boolean does not.
        """
        return {
            "jid": self._profile.jid,
            "jid_localpart_present": bool(
                self._profile.jid and self._profile.jid.partition("@")[0]),
            "jid_domain": _address.jid_domain(self._profile.jid),
            "password_present": (self._password_present if password is None
                                 else password != ""),
            "server_configured": self._profile.server,
            "tunnel_target": self._profile.effective_server,
            "is_default_server": self._profile.is_default_server,
            "sam_host": self._profile.sam_host,
            "sam_port": self._profile.sam_port,
            "c2s_port": _c2s_port(),
            "use_i2p": self._profile.use_i2p,
            # STARTTLS on a normal c2s port at the far end of the tunnel;
            # direct TLS would be wrong and is explicitly turned off. Whether
            # the certificate is checked depends on whether the ADDRESS
            # already authenticates the endpoint -- see
            # transport.endpoint_authenticated_by. Reported from the transport
            # once it exists, so this states what was decided rather than what
            # was intended; the two differed, and that difference was the bug.
            "tls_mode": self._tls_mode(),
            "profile_errors": self._profile.errors(),
        }

    def inputs_text(self) -> str:
        """The propagation snapshot as one pasteable block.

        Rendered here rather than in Kotlin, for the same reason
        `diagnostics.as_text` is: a second renderer is a second place deciding
        what a report may contain, and it is the one that forgets the rule
        when a field is added.
        """
        got = self.inputs()
        lines = ["what reached the transport:"]
        for key in sorted(got):
            value = got[key]
            if isinstance(value, list):
                value = "; ".join(str(v) for v in value) or "(none)"
            lines.append("  %-22s %s" % (key, value))
        lines.append("  %-22s %s" % ("worker_alive", self._worker_alive()))
        return "\n".join(lines)

    def status(self) -> Dict[str, Any]:
        """Everything the screen renders, in one crossing of the boundary."""
        return {
            "stage": self._stage,
            "connected": bool(self._transport is not None
                              and getattr(self._transport, "is_connected",
                                          False)),
            "jid": self._profile.jid,
            "server": self._profile.effective_server,
            "is_default_server": self._profile.is_default_server,
            "sam": "%s:%d" % (self._profile.sam_host, self._profile.sam_port),
            "last": dict(self._last),
            "inputs": self.inputs(),
            "worker_alive": self._worker_alive(),
        }

    def _tls_mode(self) -> str:
        """What the transport actually settled on, or what it would settle on.

        Asks the live transport when there is one. Before that, it computes
        the same rule, so the screen can say what is about to happen without
        pretending a decision has been taken.
        """
        transport = self._transport
        policy = getattr(transport, "tls_policy", None) if transport else None
        if policy and policy != "not yet decided":
            return "starttls, %s" % policy
        try:
            from .transport import endpoint_authenticated_by
            by = endpoint_authenticated_by(self._profile)
        except Exception:
            return "starttls"
        return ("starttls, certificate required" if by is None
                else "starttls, certificate checks off (endpoint "
                     "authenticated by %s)" % by)

    def _worker_alive(self) -> bool:
        """Whether the transport's event loop thread is still running.

        The transport deliberately does its work off the calling thread, so
        "nothing happened" has two very different causes: the work failed, or
        the thread that was supposed to do it is gone. A dead loop with a
        connected-looking status is the shape of a lifecycle bug, and it is
        invisible unless something asks.
        """
        transport = self._transport
        if transport is None:
            return False
        thread = getattr(transport, "_thread", None)
        return bool(thread is not None and thread.is_alive())


def _default_transport_factory():
    from .transport import XmppTransport
    return XmppTransport


def controller_for(app: Any, jid: str = "",
                   server: str = "", sam_host: str = "",
                   sam_port: int = 0) -> ConnectionController:
    """Build a controller around the shipped default, with overrides.

    The entry point Kotlin calls. Keeping it a plain function of plain
    arguments means the language boundary carries strings and ints, not an
    object graph -- a PyObject held across the boundary is a lifetime question
    nobody wants to answer twice.

    Empty arguments mean "use the default", so the common case on the handset
    is `controller_for(app, jid)` and the server, SAM host and port come from
    `settings.DEFAULT_SERVER` and the SAM defaults.
    """
    from .settings import DEFAULT_SERVER
    profile = ConnectionProfile(
        jid=jid,
        server=server or DEFAULT_SERVER,
        **{k: v for k, v in (("sam_host", sam_host), ("sam_port", sam_port))
           if v}
    )
    return ConnectionController(app, profile)


def probe_profile(profile: ConnectionProfile, **kw) -> SamProbe:
    """`probe_sam` against a profile's configured bridge.

    Short-circuits for a clearnet profile: there is no SAM bridge in that path
    and reporting one as unreachable would be a false alarm about a component
    that is not in use.
    """
    if not profile.use_i2p:
        return SamProbe(True, "ok", "Not using I2P; no SAM bridge needed.")
    return probe_sam(profile.sam_host, profile.sam_port, **kw)
