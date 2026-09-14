"""The XMPP transport, over an I2P SAM stream.

`OtrApp` already owns the protocol. Look at what it asks a transport for --
`send(peer, payload)`, `connect`, `disconnect`, `roster` -- and at what
`send_message` hands over: a string the engine produced, already encrypted,
which the transport is not expected to understand. That is the whole contract,
and it means this module does **not** need `otrv4plus_xmpp.OTRv4PlusXMPP`.

That matters more than it sounds. `OTRv4PlusXMPP` is a seven-thousand-line
terminal program: an ANSI panel manager, a raw-mode line editor, a module-scope
`print` shadow that routes through a session log, argparse, `getpass`,
`readline`. Every bit of it is right for a terminal and wrong inside an
application, and Phase 5 of the original plan was budgeted for tearing it out.
It turns out not to be necessary: an ordinary `slixmpp.ClientXMPP` carries
message bodies, `OtrApp` does the cryptography, and the terminal client stays
a terminal client.

What is reused is `start_i2p_sam_forwarder`, which opens the SAM stream and
exposes it as a local TCP endpoint for slixmpp to connect to. That function is
where the hard-won details live -- the 1 KB write chunking that avoids the SAM
cliff, keeping the session and writer alive on the loop so they are not
collected -- and reimplementing it here would be reimplementing a bug fix.

Threading
---------
slixmpp is asyncio; Android calls in from Kotlin threads, and Chaquopy will
happily hand us the UI thread if we let it. So the transport owns a loop on a
worker thread and every public method is a thread-safe hand-off onto it. The
methods block for a bounded time and raise on failure, because `OtrApp.connect`
is written to expect that.

Secrets
-------
The password is held because SASL needs it again on every reconnect, and
slixmpp holds it too -- but this object is the sort of thing that ends up in a
log line or a diagnostic report, so `__repr__` is written by hand and
`tests/test_android_transport.py` asserts the password is absent from it, from
`str()`, and from the event stream.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from .app import Transport
from .settings import ConnectionProfile

__all__ = ["XmppTransport", "TransportError", "DEFAULT_C2S_PORT"]

_log = logging.getLogger("otrv4plus.bridge.transport")

#: The c2s port on the far side of the SAM stream. 5222 is the XMPP default and
#: the I2P destination speaks it normally -- the tunnel is a pipe, not a proxy
#: that rewrites ports.
DEFAULT_C2S_PORT = 5222

#: How long a blocking call waits on the loop thread before giving up. Not the
#: same thing as the SAM timeouts: those are how long a tunnel may take to
#: build (SAM_CONNECT_TIMEOUT is 240s), and this has to be larger or a cold
#: tunnel would be reported as a failed connection while it was still working.
#: The number is deliberately generous; the UI shows progress, not a stopwatch.
CONNECT_TIMEOUT = 300.0
CALL_TIMEOUT = 30.0


class TransportError(RuntimeError):
    """The transport could not do what was asked.

    Carries a short stable `code` for the UI to branch on and a `detail` for a
    human. The detail never contains the password -- it is built from exception
    types and our own strings, never from the credential.
    """

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


class XmppTransport(Transport):
    """Carries OTR payloads between `OtrApp` and an XMPP server over I2P."""

    def __init__(
        self,
        profile: ConnectionProfile,
        password: str,
        *,
        on_payload: Callable[[str, str], None],
        on_presence: Optional[Callable[[str, bool], None]] = None,
        on_state: Optional[Callable[[str, str], None]] = None,
        client_factory: Optional[Callable[..., Any]] = None,
        forwarder: Optional[Callable[..., Any]] = None,
    ):
        profile.validate()
        if not profile.is_complete:
            raise TransportError(
                "profile_incomplete",
                "the connection profile has no account or no server")
        self._profile = profile
        self._password = password
        self._on_payload = on_payload
        self._on_presence = on_presence
        self._on_state = on_state
        # Injected so the tests can drive the whole state machine without
        # slixmpp, a SAM bridge, or a network. Defaulted lazily rather than
        # here, because importing the real ones costs the engine.
        self._client_factory = client_factory
        self._forwarder = forwarder

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._client: Any = None
        self._connected = threading.Event()
        self._lock = threading.RLock()

    # -- what this object says about itself -----------------------------------

    def __repr__(self) -> str:
        # Written out, never derived. A default repr on a class holding a
        # credential is one logging call away from putting it in a file.
        return ("<XmppTransport jid=%r server=%r sam=%s:%d i2p=%s connected=%s>"
                % (self._profile.jid, self._profile.effective_server,
                   self._profile.sam_host, self._profile.sam_port,
                   self._profile.use_i2p, self.is_connected))

    __str__ = __repr__

    @property
    def profile(self) -> ConnectionProfile:
        return self._profile

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    # -- the loop thread ------------------------------------------------------

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        """Start the worker loop if it is not already running.

        A dedicated loop rather than whatever loop happens to be current:
        Chaquopy calls in from Kotlin threads that have none, and the one place
        this must never run is the Android main thread, where a tunnel build
        would be an ANR.
        """
        with self._lock:
            if self._loop is not None and self._loop.is_running():
                return self._loop
            ready = threading.Event()
            loop = asyncio.new_event_loop()

            def run():
                asyncio.set_event_loop(loop)
                loop.call_soon(ready.set)
                loop.run_forever()

            thread = threading.Thread(
                target=run, name="otrv4plus-transport", daemon=True)
            thread.start()
            if not ready.wait(timeout=10):
                raise TransportError("loop_start_failed",
                                     "the transport's event loop did not start")
            self._loop, self._thread = loop, thread
            return loop

    def _run(self, coro, timeout: float):
        """Run *coro* on the loop thread and wait for it."""
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return future.result(timeout=timeout)
        except TransportError:
            raise
        except TimeoutError:
            # Builtin TimeoutError, which since 3.11 is what both
            # concurrent.futures.TimeoutError and asyncio.TimeoutError alias.
            # This is the "no underlying exception" case: nothing raised, the
            # work simply never finished, and saying so is different from
            # saying it failed.
            future.cancel()
            raise TransportError(
                "timeout",
                "the operation did not finish within %gs and nothing raised. "
                "The connection was still in progress when the wait expired."
                % timeout)
        except Exception as exc:
            # The type, not the message. An exception raised inside slixmpp's
            # SASL path can quote what it was given.
            #
            # "unexpected_error" rather than "failed": anything reaching here
            # is a bug rather than a diagnosable condition, and it must not be
            # confusable with the `failed` STAGE, which is where every other
            # error also ends up.
            raise TransportError("unexpected_error", type(exc).__name__)

    # -- Transport ------------------------------------------------------------

    def connect(self) -> None:
        self._run(self._connect(), CONNECT_TIMEOUT)

    async def _connect(self) -> None:
        host, port = await self._endpoint()
        # Separately coded for the same reason as the forwarder above: a
        # slixmpp that will not import is a packaging fault, and reporting it
        # as a generic connect failure sends someone to look at their router.
        try:
            client = self._make_client()
        except Exception as exc:
            self._emit_state("failed")
            raise TransportError(
                "client_build_failed",
                "the XMPP client could not be built (%s)."
                % type(exc).__name__)
        self._wire(client)
        self._client = client
        started = asyncio.get_event_loop().create_future()

        def on_session(_event):
            if not started.done():
                started.set_result(True)

        def on_failed(_event):
            if not started.done():
                started.set_exception(
                    TransportError("auth_failed",
                                   "the server rejected the account or password"))

        def on_connection_failed(event):
            # slixmpp reschedules a failed connection rather than giving up
            # ("If everything fails, the connection is rescheduled for
            # later" -- XMLStream._connect_loop), so without this the retry
            # loop spins silently and the only thing that ever ends the wait
            # is the 300s timeout. An interactive Connect should say what
            # happened at the first failure, not five minutes later.
            if not started.done():
                started.set_exception(TransportError(
                    "stream_failed",
                    "the XMPP stream could not be established (%s). The SAM "
                    "tunnel was open, so this is the server or the TLS "
                    "handshake rather than I2P."
                    % type(event).__name__))

        client.add_event_handler("session_start", on_session)
        client.add_event_handler("failed_auth", on_failed)
        client.add_event_handler("connection_failed", on_connection_failed)

        # host= and port= point slixmpp at the local end of the SAM tunnel
        # rather than at a DNS lookup of the JID's domain. getaddrinfo is never
        # called on a .i2p name -- TRANSPORT_POLICY.md is emphatic about that,
        # and this is the line that keeps it true. slixmpp only skips its SRV
        # lookup when BOTH are given, so they must stay together.
        #
        # This said `address=(host, port)` until the first handset test, which
        # is an older slixmpp API that no longer exists: 1.17's signature is
        # connect(host, port). It raised TypeError before a socket was opened,
        # and the unit tests passed anyway because the fake client accepted
        # `address=` -- the fake encoded the same wrong assumption as the code
        # it was standing in for. tests/test_android_transport.py now binds
        # this call against the real slixmpp signature so a fake cannot agree
        # with a mistake again.
        client.connect(host=host, port=port)
        await started
        self._connected.set()
        self._emit_state("connected")

    async def _endpoint(self):
        """Where slixmpp should point: the SAM tunnel, or the server itself."""
        if not self._profile.use_i2p:
            # A clearnet server, which the profile allows and the UI does not
            # advertise. No tunnel to build, so no forwarder.
            return self._profile.effective_server, DEFAULT_C2S_PORT

        # Inside its own try, and separately coded. This import pulls in
        # otrv4plus_xmpp and therefore the whole engine, and it sat outside the
        # try below -- so a failure here escaped as a bare exception and was
        # reported as "failed: ModuleNotFoundError", which names neither the
        # stage nor the module. "The forwarder would not import" and "the
        # router would not answer" are different problems with different
        # remedies and they must not share a code.
        try:
            forward = self._forwarder or _default_forwarder()
        except Exception as exc:
            self._emit_state("failed")
            raise TransportError(
                "forwarder_import_failed",
                "the I2P forwarder could not be loaded (%s). This is a "
                "packaging fault, not a router problem."
                % type(exc).__name__)

        self._emit_state("building_tunnels")
        try:
            return await forward(
                self._profile.effective_server, DEFAULT_C2S_PORT,
                self._profile.sam_host, self._profile.sam_port)
        except Exception as exc:
            self._emit_state("failed")
            raise TransportError(
                "sam_unavailable",
                "could not open an I2P stream (%s). Is the router running and "
                "is its SAM bridge enabled?" % type(exc).__name__)

    def send(self, peer: str, payload: str) -> None:
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._send(peer, payload), CALL_TIMEOUT)

    async def _send(self, peer: str, payload: str) -> None:
        self._client.send_message(mto=peer, mbody=payload, mtype="chat")

    def disconnect(self) -> None:
        if self._client is None:
            return
        try:
            self._run(self._disconnect(), CALL_TIMEOUT)
        except TransportError:
            # Tearing down is best effort: a disconnect that raises would
            # leave the app believing it is still connected, which is worse
            # than a socket that closes untidily.
            _log.warning("transport disconnect did not complete cleanly")
        finally:
            self._connected.clear()
            self._emit_state("disconnected")

    async def _disconnect(self) -> None:
        self._client.disconnect()

    def roster(self) -> List[Dict[str, Any]]:
        if self._client is None:
            return []
        # On the loop thread like everything else. slixmpp mutates the roster
        # from its own coroutines as presence and roster pushes arrive, and
        # iterating it from a Kotlin thread is a data race that would show up
        # as an occasional empty contact list rather than as a crash.
        try:
            return self._run(self._roster(), CALL_TIMEOUT)
        except TransportError:
            _log.warning("could not read the roster")
            return []

    async def _roster(self) -> List[Dict[str, Any]]:
        out = []
        try:
            for jid in self._client.client_roster:
                entry = self._client.client_roster[jid]
                out.append({
                    "jid": str(jid),
                    "name": entry.get("name") or "",
                    "subscription": entry.get("subscription") or "",
                })
        except Exception:
            _log.warning("could not read the roster")
            return []
        return out

    def close(self) -> None:
        """Stop the loop thread. Safe to call more than once."""
        self.disconnect()
        with self._lock:
            loop, self._loop = self._loop, None
            thread, self._thread = self._thread, None
        if loop is not None:
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=5)

    # -- slixmpp wiring -------------------------------------------------------

    def _make_client(self):
        factory = self._client_factory or _default_client_factory()
        client = factory(self._profile.jid, self._password)
        self._apply_tls_policy(client)
        return client

    def _apply_tls_policy(self, client) -> None:
        """Relax certificate checking where the address is already the key.

        Without this the app hung. slixmpp's default context is
        `check_hostname=True, verify_mode=CERT_REQUIRED` with the system trust
        store, and it validates against `default_domain` -- the JID's domain.
        Over I2P nothing in that path is CA-signed, so STARTTLS failed; and
        `XMLStream._connect_loop` reschedules a failed connection rather than
        giving up, so neither `session_start` nor `failed_auth` ever fired and
        the connect sat until its 300s timeout with nothing to report.

        The terminal client has always done this -- see
        `endpoint_authenticated_by` -- and it does it automatically, precisely
        so nobody has to type a flag with "insecure" in its name for a link
        that is not insecure. The transport reimplemented everything around
        this and quietly omitted it.

        This is NOT a weakening. The `.b32.i2p` address is the hash of the
        server's key; the SAM stream reaches that key-holder or it fails, and
        I2P encrypts it end to end. On clearnet this does nothing at all and
        the certificate is still required.
        """
        by = endpoint_authenticated_by(self._profile)
        self._tls_policy = ("certificate required"
                            if by is None
                            else "certificate checks off, endpoint "
                                 "authenticated by %s" % by)
        if by is None:
            return
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        client.ssl_context = ctx

    @property
    def tls_policy(self) -> str:
        """What was actually decided, for the report to state rather than claim."""
        return getattr(self, "_tls_policy", "not yet decided")

    def _wire(self, client) -> None:
        client.add_event_handler("message", self._on_message)
        client.add_event_handler("presence_available",
                                 lambda p: self._presence(p, True))
        client.add_event_handler("presence_unavailable",
                                 lambda p: self._presence(p, False))
        client.add_event_handler("disconnected", self._on_disconnected)

    def _on_message(self, stanza) -> None:
        """Hand the body up, whatever it is.

        No filtering for OTR framing here. The transport does not know what an
        OTR frame looks like and should not learn: `OtrApp.receive_message`
        gives it to the engine, which is the one thing entitled to decide
        whether a payload is a DAKE frame, an SMP frame, ciphertext, or a
        plaintext message from someone with no session.
        """
        try:
            if stanza.get("type") not in ("chat", "normal", None, ""):
                return
            body = stanza.get("body") or ""
            if not body:
                return
            peer = str(stanza.get("from")).split("/", 1)[0]
        except Exception:
            _log.warning("could not read an inbound stanza")
            return
        try:
            self._on_payload(peer, body)
        except Exception:
            # A callback that raises must not take the connection down: it is
            # UI code across a language boundary, and a screen bug is not a
            # reason to drop a session. Same rule as OtrApp._emit.
            _log.warning("the inbound payload handler raised")

    def _presence(self, stanza, online: bool) -> None:
        if self._on_presence is None:
            return
        try:
            peer = str(stanza["from"]).split("/", 1)[0]
        except Exception:
            return
        try:
            self._on_presence(peer, online)
        except Exception:
            _log.warning("the presence handler raised")

    def _on_disconnected(self, _event) -> None:
        self._connected.clear()
        self._emit_state("disconnected")

    def _emit_state(self, state: str) -> None:
        if self._on_state is None:
            return
        try:
            self._on_state(state, self._profile.effective_server)
        except Exception:
            _log.warning("the state handler raised")


def endpoint_authenticated_by(profile) -> Optional[str]:
    """Whether the ADDRESS already authenticates the endpoint, and by what.

    "I2P", "Tor", or None for clearnet.

    This is the rule `otrv4plus_xmpp.main()` applies around line 7170, and the
    reasoning there is worth repeating rather than re-deriving: a `.b32.i2p`
    label is the hash of the destination's key, and a v3 onion name is the key
    itself. Reaching that address means reaching that key-holder, with the
    transport's own end-to-end encryption in between. There is no certificate
    authority in the path and no MITM position for one to defend against, so
    demanding a CA-valid certificate there is asking for a weaker second name
    for a server already named by its key.

    None means clearnet, and clearnet still demands a real certificate.
    """
    if getattr(profile, "use_i2p", False):
        return "I2P"
    if str(getattr(profile, "effective_server", "")).endswith(".onion"):
        return "Tor"
    return None


def _default_client_factory():
    """slixmpp, imported late.

    Late because a settings screen, a unit test and the diagnostics report all
    touch this module without ever connecting, and slixmpp costs about a second
    to import on a handset.
    """
    from slixmpp import ClientXMPP

    def factory(jid: str, password: str):
        client = ClientXMPP(jid, password)
        # STARTTLS, never direct TLS: the far end of a SAM stream is a normal
        # c2s port. This mirrors what the terminal client sets in main().
        if hasattr(client, "enable_direct_tls"):
            client.enable_direct_tls = False
        if hasattr(client, "enable_starttls"):
            client.enable_starttls = True
        return client

    return factory


def _default_forwarder():
    """The terminal client's SAM forwarder, imported late.

    Late for the same reason and one more: importing `otrv4plus_xmpp` pulls in
    the whole OTR engine, and this module is imported by things that have no
    business loading it.
    """
    import otrv4plus_xmpp

    return otrv4plus_xmpp.start_i2p_sam_forwarder
