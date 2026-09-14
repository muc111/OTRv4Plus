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

import socket
from typing import Any, Callable, Dict, Optional

from .settings import ConnectionProfile

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

    #: In order. Reported as they are entered, so a stall is attributable.
    STAGES = ("idle", "checking_router", "building_tunnels",
              "connecting", "authenticating", "connected", "failed")

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

    @property
    def stage(self) -> str:
        return self._stage

    @property
    def profile(self) -> ConnectionProfile:
        return self._profile

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
        self._enter("checking_router")
        probe = self._prober(self._profile)
        if not probe.reachable:
            return self._fail(probe.code, probe.detail)

        try:
            factory = self._transport_factory or _default_transport_factory()
            self._transport = factory(
                self._profile, password,
                on_payload=self._app.receive_message,
                on_state=lambda s, _srv: self._enter(
                    "building_tunnels" if s == "building_tunnels"
                    else "connecting" if s == "connected" else s),
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
            return self._fail(code, detail)

        self._enter("connected")
        self._last = {"ok": True, "stage": "connected", "code": "ok",
                      "detail": "Connected to %s as %s"
                                % (self._profile.effective_server,
                                   self._profile.jid),
                      "sam_version": probe.version}
        return dict(self._last)

    def disconnect(self) -> Dict[str, Any]:
        """Tear down. Best effort, and always ends at a known state."""
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
        self._enter("idle")
        self._last = {"ok": True, "stage": "idle", "code": "ok",
                      "detail": "Disconnected."}
        return dict(self._last)

    def probe(self) -> Dict[str, Any]:
        """Just the router check, as a plain dict.

        Exposed as a method so the Kotlin side never reaches into `_profile`.
        A private attribute read across a language boundary is a coupling that
        breaks without a compiler noticing.
        """
        return self._prober(self._profile).as_dict()

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
        }


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
