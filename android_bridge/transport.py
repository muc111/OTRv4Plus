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
import concurrent.futures as _futures
import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from .app import Transport
from .settings import ConnectionProfile

__all__ = ["XmppTransport", "TransportError", "DEFAULT_C2S_PORT",
           "SubscriptionPolicy"]


class SubscriptionPolicy:
    """What happens when someone asks to see your presence.

    Presence is metadata. Approving a subscription tells that account when you
    are online, from which device, and how idle you are -- for as long as they
    keep it. On an anonymity-oriented messenger that is worth a deliberate
    choice rather than an inherited default, which is what slixmpp's
    `auto_authorize = True` would otherwise be.

    ACCEPT is the shipped default because it is what was asked for and because
    on a server you control it is the difference between a contact list that
    works and one that needs a second out-of-band step per person. It is a
    setting, and ASK is one line away for anyone who wants it.

    None of this is an OTR question. A subscription grants presence, not the
    ability to read anything: a message from an approved contact is still
    plaintext until a DAKE has run, and the conversation screen says so.
    """

    #: Approve, and ask for theirs back. slixmpp: auto_authorize=True,
    #: auto_subscribe=True.
    ACCEPT = "accept"
    #: Approve, but do not ask for theirs. auto_authorize=True,
    #: auto_subscribe=False.
    ACCEPT_ONE_WAY = "accept_one_way"
    #: Neither approve nor refuse -- hand it to the UI. auto_authorize=None.
    ASK = "ask"
    #: Refuse. auto_authorize=False.
    REJECT = "reject"

    ALL = (ACCEPT, ACCEPT_ONE_WAY, ASK, REJECT)

    #: (auto_authorize, auto_subscribe) for each, mapped onto the two
    #: properties slixmpp actually has. Verified against basexmpp.py: True
    #: approves, None disables automatic handling, False refuses.
    _SLIXMPP = {
        ACCEPT: (True, True),
        ACCEPT_ONE_WAY: (True, False),
        ASK: (None, False),
        REJECT: (False, False),
    }

    @classmethod
    def apply(cls, client, policy: str) -> str:
        """Set the policy on *client*. Returns the policy actually applied."""
        if policy not in cls._SLIXMPP:
            policy = cls.ACCEPT
        authorize, subscribe = cls._SLIXMPP[policy]
        client.auto_authorize = authorize
        client.auto_subscribe = subscribe
        return policy

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

#: How long teardown waits. Short on purpose: `close` is called from Android
#: lifecycle callbacks that must return promptly, and a shutdown that blocks
#: is a worse failure than one that gives up and logs.
CLOSE_TIMEOUT = 5.0

#: The two unrelated CancelledError classes, as a tuple to catch on. They are
#: genuinely different types -- `asyncio.CancelledError is
#: concurrent.futures.CancelledError` is False on 3.12 -- and only one of them
#: derives from Exception, so naming either alone gets the wrong half.
_CANCELLED = (asyncio.CancelledError, _futures.CancelledError)


def _accepts(fn: Any, name: str) -> bool:
    """Whether *fn* takes a keyword argument called *name*.

    Asked rather than discovered by catching TypeError, because a TypeError
    raised inside the callee is indistinguishable from one raised by the call.
    """
    try:
        import inspect

        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if name in params:
        return True
    return any(p.kind is p.VAR_KEYWORD for p in params.values())


def _forwarder_log(message: str) -> None:
    """Where the forwarder's progress lines go on Android.

    Not `print`. Chaquopy routes stdout into logcat, and these lines name the
    I2P destination -- which CONTRIBUTING.md's rejection list puts alongside
    keys and plaintext as a thing that must not be logged. In a terminal the
    same string is feedback to the person who typed the address; in a system
    log that `adb logcat` reads, it is a record of who this device talks to.

    The stage is still worth knowing, so the message is reduced to whether a
    tunnel is being opened or is up, with the destination dropped.
    """
    text = str(message)
    if "established" in text:
        _log.info("i2p: SAM stream established")
    elif "local bridge ready" in text:
        _log.info("i2p: local bridge ready")
    elif "opening SAM stream" in text:
        _log.info("i2p: opening a SAM stream (a cold tunnel can take 30-90s)")


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
        on_subscription_request: Optional[Callable[[str], None]] = None,
        subscription_policy: str = SubscriptionPolicy.ACCEPT,
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
        self._on_subscription_request = on_subscription_request
        self._subscription_policy = subscription_policy
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
        #: Set by close(). After this the object is finished and no call may
        #: start a loop again -- see _ensure_loop.
        self._closed = False
        #: The in-flight connect, so another thread can cancel it. Android's
        #: Back button and a rotation both need to stop a four-minute tunnel
        #: build, and the Kotlin coroutine that called in cannot: a blocking
        #: JNI call is not interruptible by cancelling the coroutine around it.
        self._connect_future: Any = None
        #: What the SAM forwarder opened, so it can be closed again. Without
        #: this the sockets live on `loop._i2p_keep`, which is a keep-alive
        #: with no release.
        self._i2p_resources: List[Any] = []

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
            if self._closed:
                # A closed transport must never start a thread. It used to:
                # close() cleared _loop but left _client set, so the next
                # call -- and on Android there is always a next call, because
                # the chat screen polls every 500ms and shutdown races it --
                # went through _ensure_loop and got a brand new loop thread
                # that nothing would ever join. Verified before the fix: a
                # disconnect() after close() left one running.
                raise TransportError(
                    "closed", "this transport has been closed")
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
        """Bring the stream up. Blocks; must not be called on a UI thread.

        Kept out of `_run` because this is the one call another thread needs to
        be able to stop: a cold tunnel is minutes, and Android will rotate the
        screen or send Back inside that window.
        """
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._connect(), loop)
        with self._lock:
            self._connect_future = future
        try:
            future.result(timeout=CONNECT_TIMEOUT)
        except TransportError:
            raise
        except _CANCELLED:
            # BOTH CancelledErrors, because they are not the same class and
            # which one arrives depends on where the cancellation was noticed.
            # `asyncio.CancelledError` derives from BaseException (3.8+), so
            # `except Exception` would miss it; `concurrent.futures`' one does
            # derive from Exception, so `except Exception` would swallow it and
            # report `unexpected_error`. It did: the first cut of this method
            # named only the asyncio class and every cancelled connect came
            # back as an unexpected error.
            raise TransportError(
                "cancelled", "the connection attempt was cancelled")
        except TimeoutError:
            # Builtin TimeoutError, which since 3.11 is what both
            # concurrent.futures.TimeoutError and asyncio.TimeoutError alias.
            # Nothing raised; the work simply never finished. Cancelling is
            # what makes that true rather than merely reported -- without it
            # slixmpp's _connect_loop keeps rescheduling against a tunnel
            # nobody is waiting on any more.
            future.cancel()
            raise TransportError(
                "timeout",
                "the operation did not finish within %gs and nothing raised. "
                "The connection was still in progress when the wait expired."
                % CONNECT_TIMEOUT)
        except Exception as exc:
            raise TransportError("unexpected_error", type(exc).__name__)
        finally:
            with self._lock:
                self._connect_future = None

    def cancel(self) -> None:
        """Stop an in-flight connect from another thread.

        The reason this exists rather than relying on the caller: Kotlin calls
        `connect` through Chaquopy, which is a blocking JNI call. Cancelling
        the coroutine that wrapped it does not interrupt the thread inside
        Python, so without this a rotation during a four-minute tunnel build
        leaves the old attempt running while the recreated screen starts a
        second one.

        Safe at any time, including when nothing is connecting.
        """
        with self._lock:
            future = self._connect_future
        if future is not None:
            future.cancel()

    async def _connect(self) -> None:
        try:
            await self._connect_inner()
        except BaseException:
            # Every failure path, cancellation included, gives back what it
            # took: the SAM tunnel, the local listening socket, and slixmpp's
            # retry loop. Before this, a connect that timed out left all three
            # running -- verified -- so pressing Connect a second time built a
            # second tunnel on top of the first, and the app degraded with
            # every attempt instead of recovering.
            await self._abandon()
            raise

    async def _connect_inner(self) -> None:
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

    async def _abandon(self) -> None:
        """Give back everything a failed or cancelled attempt took.

        Runs on the loop thread. Three distinct things, and leaving any of them
        is its own bug:

        1. **slixmpp's retry loop.** `XMLStream._connect_loop` reschedules a
           failed connection rather than giving up, so a client that is simply
           dropped keeps dialling for the life of the process. `abort()` is the
           call that stops it; `disconnect()` is the fallback for a client that
           has not got one.
        2. **The I2P tunnel and the local listening socket.** Opened by the
           forwarder, and previously parked on `loop._i2p_keep` where nothing
           could reach them.
        3. **The reference to the client**, so a later call cannot find a
           half-dead one and believe it is usable.
        """
        self._connected.clear()
        client, self._client = self._client, None
        if client is not None:
            for method in ("abort", "disconnect"):
                fn = getattr(client, method, None)
                if fn is None:
                    continue
                try:
                    result = fn()
                    if asyncio.iscoroutine(result):
                        await result
                except Exception:
                    _log.warning("could not stop the XMPP client cleanly")
                break
        self._release_i2p()

    def _release_i2p(self) -> None:
        """Close the forwarder's sockets. Safe to call more than once.

        Deliberately imports nothing. The first version called a helper in
        `otrv4plus_xmpp`, which is a twelve-thousand-line module that pulls in
        the Rust core -- so on the one path where the import was not already
        warm, teardown sat behind it and the sockets were still open when the
        caller looked. Measured, not feared: the timeout test closed nothing
        while the cancel test closed everything, and the only difference was
        whether that import had happened yet.

        Teardown runs when something has already gone wrong. It gets to depend
        on nothing.
        """
        resources, self._i2p_resources = self._i2p_resources, []
        # Reverse order: the writer before the SAM session that owns it.
        for obj in reversed(resources):
            for method in ("close", "disconnect"):
                fn = getattr(obj, method, None)
                if fn is None:
                    continue
                try:
                    fn()
                except Exception:
                    pass
                break

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

        # Ask the signature rather than calling and catching TypeError. A
        # TypeError raised *inside* the forwarder looks identical from out
        # here, and retrying on one would open a second tunnel while the first
        # was still being built -- the precise failure this module exists to
        # avoid.
        extra = {}
        if _accepts(forward, "resources"):
            extra["resources"] = self._i2p_resources
        if _accepts(forward, "log"):
            extra["log"] = _forwarder_log
        if "resources" not in extra:
            _log.info("the I2P forwarder does not accept resource handover; "
                      "its sockets will not be released on teardown")

        self._emit_state("building_tunnels")
        try:
            return await forward(
                self._profile.effective_server, DEFAULT_C2S_PORT,
                self._profile.sam_host, self._profile.sam_port, **extra)
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
        if self._client is None or self._closed:
            # Closed is not an error to report here: disconnecting something
            # already finished with is what a lifecycle callback does, and
            # raising would turn tidy shutdown into a crash.
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
        client = self._client
        if client is not None:
            client.disconnect()
        # The tunnel goes with the session it carried. Leaving it open would
        # hold an I2P lease and a listening local socket for a connection that
        # no longer exists, and the next connect would build a second one.
        self._release_i2p()

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
        """Finish with this transport. Safe to call more than once.

        After this the object is spent: every method raises `closed` rather
        than starting a loop. That is the point. It used to leave `_client`
        set and `_loop` cleared, so the next call -- and on Android the chat
        screen polls every 500ms, so there is always a next call -- went
        through `_ensure_loop` and got a fresh worker thread nothing would
        ever join.
        """
        with self._lock:
            already = self._closed
            self._closed = True
            future = self._connect_future
            loop = self._loop
            thread = self._thread
            self._loop = None
            self._thread = None
        if already and loop is None:
            return

        # Stop an attempt that is still running, or the teardown below waits
        # behind a tunnel build.
        if future is not None:
            future.cancel()

        if loop is not None and loop.is_running():
            # On the loop thread, and bounded: teardown that hangs is a worse
            # failure than teardown that gives up, because the caller is
            # usually a lifecycle callback that must return.
            done = threading.Event()

            async def shut():
                try:
                    await self._abandon()
                finally:
                    done.set()

            try:
                asyncio.run_coroutine_threadsafe(shut(), loop)
                done.wait(timeout=CLOSE_TIMEOUT)
            except Exception:
                _log.warning("the transport did not shut down cleanly")
            loop.call_soon_threadsafe(loop.stop)
        else:
            # No loop to do it on; do what can be done from here.
            self._release_i2p()

        if thread is not None:
            thread.join(timeout=CLOSE_TIMEOUT)
            if thread.is_alive():
                _log.warning("the transport's worker thread did not stop")
        self._connected.clear()
        self._emit_state("disconnected")

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

    # -- roster ---------------------------------------------------------------

    def add_contact(self, jid: str, name: str = "") -> None:
        """Ask *jid* to let us see their presence, and put them on the roster.

        Two separate things in XMPP and worth keeping separate here: the roster
        entry is local bookkeeping, the subscription is a request the other
        side answers. `add_contact` does both because a contact you cannot see
        is not what anyone means by adding one.
        """
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._add_contact(jid, name), CALL_TIMEOUT)

    async def _add_contact(self, jid: str, name: str) -> None:
        self._client.update_roster(jid, name=name or None)
        self._client.send_presence_subscription(pto=jid, ptype="subscribe")

    def remove_contact(self, jid: str) -> None:
        """Drop the roster entry and both directions of subscription."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._remove_contact(jid), CALL_TIMEOUT)

    async def _remove_contact(self, jid: str) -> None:
        self._client.send_presence_subscription(pto=jid, ptype="unsubscribe")
        self._client.update_roster(jid, subscription="remove")

    def answer_subscription(self, jid: str, approve: bool) -> None:
        """Answer a request that `SubscriptionPolicy.ASK` handed to the UI.

        Only meaningful under ASK. Under ACCEPT slixmpp has already answered
        before the UI sees anything, which is the point of that policy.
        """
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._answer_subscription(jid, approve), CALL_TIMEOUT)

    async def _answer_subscription(self, jid: str, approve: bool) -> None:
        self._client.send_presence_subscription(
            pto=jid, ptype="subscribed" if approve else "unsubscribed")

    @property
    def subscription_policy(self) -> str:
        return self._subscription_policy

    def _wire(self, client) -> None:
        # Applied explicitly rather than inherited. slixmpp defaults both
        # auto_authorize and auto_subscribe to True, so "we accept everyone"
        # would otherwise be true by accident rather than by decision, and
        # would silently change if upstream changed its mind.
        self._subscription_policy = SubscriptionPolicy.apply(
            client, self._subscription_policy)
        client.add_event_handler("presence_subscribe", self._on_subscribe)
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

    def _on_subscribe(self, stanza) -> None:
        """Someone asked to see our presence.

        Reported even under ACCEPT, where slixmpp has already said yes. The
        user is entitled to know a stranger is now watching their presence,
        and finding out only because a name appeared in a list is not the
        same as being told.
        """
        if self._on_subscription_request is None:
            return
        try:
            jid = str(stanza["from"]).split("/", 1)[0]
        except Exception:
            _log.warning("could not read a subscription request")
            return
        try:
            self._on_subscription_request(jid)
        except Exception:
            _log.warning("the subscription handler raised")

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
