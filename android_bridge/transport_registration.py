# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Creating an account (XEP-0077) over the XMPP transport, and probing a
server before signing in to it.

A mixin of XmppTransport (transport.py). In-band registration is the one
operation that sends a password to a server that has not yet proved who it
is, so it runs only over TLS (or I2P) and says plainly why a server refused."""
from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any, Dict, Optional

import otrv4plus_registration as _registration

from . import captcha as _captcha
from . import route as _route_mod
from .trace import TRACE as _TRACE
from .transport_base import CONNECT_TIMEOUT, DEFAULT_C2S_PORT, TransportError
from .transport_stream import _StreamWatch, _stream_failure_text, _tls_in_place


#: How long the open stream waits for the user to type a CAPTCHA answer before
#: giving up. The XEP-0158 challenge is bound to this stream (its `sid` and
#: `challenge` only mean anything on the connection they arrived on), so the
#: answer cannot be deferred past the life of the connection; it must come back
#: while the socket is still up. Three minutes is long enough to read a few
#: distorted characters and short enough that an abandoned screen does not hold
#: a socket (and a SAM tunnel) open indefinitely.
CAPTCHA_ANSWER_TIMEOUT = 180.0

#: How long submit_captcha_answer() waits for the server's verdict after the
#: answer is sent. The stream is already up (it was held open across the user's
#: typing), so the server either accepts or rejects the register-set promptly;
#: it does NOT need the full cold-tunnel CONNECT_TIMEOUT (300 s). A tighter
#: bound means a server that stalls on the submit fails in about a minute --
#: and the screen stops spinning -- instead of appearing hung for five.
CAPTCHA_SUBMIT_TIMEOUT = 60.0


#: What a transport-level failure means to somebody trying to create an account.
#:
#: Two different vocabularies meeting: `_endpoint` raises TransportError with
#: codes about the transport, and the Register screen renders codes from
#: `otrv4plus_registration`. Anything not named here is "unknown", because
#: guessing at a failure is worse than admitting to one.
_REGISTRATION_CODES = {
    # The router did not answer or the tunnel would not open. From the user's
    # side that is indistinguishable from the server being unreachable, and
    # the remedy -- check the router, try again -- is the same.
    "sam_unavailable": "network",
    "i2p_name_not_found": "network",
    "i2p_name_invalid": "network",
    "i2p_destination_unreachable": "network",
    "i2p_session_failed": "network",
    # A packaging fault. Nothing the user can do, and calling it a network
    # problem would send them to look at their router for no reason.
    "forwarder_import_failed": "unknown",
    # X1 and the Tor route: their own codes, never folded into "network".
    "i2p_destination_changed": "server_identity_changed",
    "i2p_server_pins_unreadable": "server_identity_changed",
    "tor_unavailable": "tor_unavailable",
    "client_build_failed": "unknown",
    "cancelled": "cancelled",
    "timeout": "timeout",
}


def _localpart(jid: str) -> str:
    """The username out of a JID, tolerating one that is only a username."""
    return str(jid or "").strip().split("@", 1)[0]


async def _clearnet_dns_records(domain: str, loop, lookup=None, getaddrinfo=None,
                                fallback_port: int = DEFAULT_C2S_PORT):
    """(service, host, address, port) records for slixmpp, SRV first.

    Returns (records, plan) where `plan` is a safe description for the
    trace: the SRV status, the targets and ports, and how many addresses of
    each family. IPv4 before IPv6 within each target: slixmpp has no
    per-address connect timeout, so an IPv6 route that silently drops
    packets would stall the attempt for the OS's TCP timeout (minutes)
    before IPv4 was ever tried; a refused or unreachable IPv4 fails fast.
    """
    from . import dns_srv as _dns
    import socket as _socket
    lookup = lookup or _dns.lookup
    getaddrinfo = getaddrinfo or loop.getaddrinfo
    srv = await loop.run_in_executor(None, lookup, domain)
    if srv.status == "found" and srv.records:
        targets = [("xmpp-client", r.target, r.port) for r in _dns.order(srv.records)]
        fallback = False
    else:
        targets = [("", domain, fallback_port)]
        fallback = True
    records, v4, v6 = [], 0, 0
    for service, host, port in targets:
        for fam in (_socket.AF_INET, _socket.AF_INET6):
            try:
                infos = await getaddrinfo(host, port, family=fam,
                                          type=_socket.SOCK_STREAM)
            except (OSError, _socket.gaierror):
                continue
            for addr in dict.fromkeys(i[4][0] for i in infos):
                records.append((service, host, addr, port))
                if fam == _socket.AF_INET:
                    v4 += 1
                else:
                    v6 += 1
    plan = {"srv": srv.status, "srv_detail": srv.detail,
            "targets": ",".join("%s:%d" % (h, p) for _s, h, p in targets),
            "fallback_used": fallback, "ipv4": v4, "ipv6": v6}
    return records, plan


def _form_field_names(form) -> str:
    """The NAMES of the fields a registration form asks for -- never values."""
    names = []
    try:
        query = form["register"]
        for n in ("username", "password", "email", "name"):
            if query.xml.find("{jabber:iq:register}%s" % n) is not None:
                names.append(n)
        xform = query["form"]
        if xform is not None:
            names.extend(k for k in (xform.get_fields() or {}) if k not in names)
    except Exception:
        pass
    return ",".join(names[:12]) or "none"


def _safe_condition(exc) -> str:
    """An XMPP error condition name (RFC 6120 vocabulary), or the type."""
    try:
        cond = getattr(exc, "condition", None) or exc.iq["error"]["condition"]
        if cond and str(cond).replace("-", "").isalpha():
            return str(cond)
    except Exception:
        pass
    return type(exc).__name__


def _registration_blocker(form) -> Optional[str]:
    """Why this XEP-0077 form cannot be filled with a username and password
    alone, or None. Read BEFORE the password is sent: a CAPTCHA or an extra
    required field means the submission would be refused anyway."""
    try:
        query = form["register"]
    except Exception:
        return None
    try:
        xform = query["form"]
        fields = xform.get_fields() if xform is not None else {}
    except Exception:
        fields = {}
    names = set(fields or {})
    try:
        ftype = fields["FORM_TYPE"].get_value() if "FORM_TYPE" in names else ""
    except Exception:
        ftype = ""
    if "urn:xmpp:captcha" in str(ftype) or names & {"ocr", "captcha", "qa",
                                                   "audio_recog", "picture_recog",
                                                   "speech_recog", "video_recog"}:
        return "registration_captcha_required"
    extra = []
    for name, field in (fields or {}).items():
        if name in ("FORM_TYPE", "username", "password"):
            continue
        try:
            required = field["required"]
        except Exception:
            required = False
        if required and field["type"] not in ("hidden", "fixed"):
            extra.append(name)
    if extra:
        return "registration_fields_required"
    return None


def _enable_registration(client) -> None:
    """Turn a client into one that will create an account.

    XEP-0077 happens during stream negotiation, before authentication, so the
    plugin has to be registered on a client that has not connected yet -- a
    plugin added later never sees the feature go past.

    `force_registration` is set because without it slixmpp only attempts
    registration when the server has offered nothing else to do; a server that
    advertises SASL alongside `<register/>` would go straight to authenticating
    an account that does not exist, and the user would be told their password
    was wrong. With it, `xep_0077` filters the stream features so registration
    is negotiated first.

    Raises rather than warning, unlike the XEP-0199 registration in
    `_default_client_factory`. A keepalive that could not be registered
    degrades; a registration that could not be registered silently logs in
    instead, which is the failure this whole path exists to avoid.
    """
    client.register_plugin("xep_0077")
    plugin = client["xep_0077"]
    plugin.create_account = True
    plugin.force_registration = True


class RegistrationMixin:
    """Account creation and server probes. Mixed into XmppTransport."""

    # -- account creation -----------------------------------------------------

    def register_account(self) -> "tuple[str, str]":
        """Create the account named by this transport's profile. Blocks.

        Returns `(code, detail)` from `otrv4plus_registration` -- `("ok", ...)`
        when the server accepted, a classified failure otherwise. It does NOT
        raise: every outcome here is something the Register screen shows, and a
        TransportError would have to be translated at the call site anyway.

        WHY IT REGISTERS THE PROFILE'S OWN CREDENTIALS rather than taking a
        username and password of its own: the next thing the user does is sign
        in, and a transport that could register one account while being
        configured for another is a way to create an account nobody can then
        log into. Build the transport with what was typed on the form; this
        registers exactly that.

        WHY IT GOES THROUGH `_endpoint` AND `_make_client`: registration is not
        allowed to be the one operation that reaches the network some other
        way. Same SAM tunnel, same TLS decision, same local-end host and port
        -- a separate path here would be a second network policy with nothing
        holding it to the first, and the credential being sent is the one that
        matters most.

        The stream is torn down before returning EXCEPT when the server asks
        for a CAPTCHA the app can show: then this returns `("captcha_required",
        ...)` with the stream still up and the challenge live (an XEP-0158
        challenge is bound to its connection -- its `sid`/`challenge` mean
        nothing on a fresh stream), and the caller completes it with
        `submit_captcha_answer`. Every other outcome, success included, leaves
        no live session: `connect()` stays the only way to one.
        """
        problem = _registration.validate(
            _localpart(self._profile.jid), self._password)
        if problem is not None:
            _TRACE.record("registration", "refused_locally", "info",
                          code=problem[0])
            return problem

        loop = self._ensure_loop()
        # Two hand-offs across the thread boundary: `_reg_stage1` carries the
        # first outcome register_account() returns on (a terminal result, or
        # "captcha_required" with the stream held open); `_reg_final` carries
        # the terminal result of a CAPTCHA flow for submit_captcha_answer().
        # concurrent.futures.Future because the coroutine sets them on the loop
        # thread and these methods read them on the caller's thread.
        self._reg_stage1 = concurrent.futures.Future()
        self._reg_final = concurrent.futures.Future()
        self._reg_captcha = None
        self._reg_answer = None
        future = asyncio.run_coroutine_threadsafe(self._register(), loop)
        # Recorded in the same slot a connect uses so `cancel()` stops this
        # too. A cold tunnel is minutes and Android will rotate the screen
        # inside that window whatever the screen happens to be.
        with self._lock:
            self._connect_future = future
        try:
            code, detail = self._reg_stage1.result(timeout=CONNECT_TIMEOUT)
        except BaseException as exc:                 # noqa: BLE001 -- see below
            # Deliberately everything, CancelledError included: `classify` is
            # total and answers "cancelled" for that case, and an exception
            # escaping here would reach Kotlin as a Chaquopy PyException with
            # the stanza still inside its message. If the coroutine already
            # failed, classify its exception rather than this wait's timeout.
            source = exc
            if future.done():
                try:
                    inner = future.exception(timeout=0)
                    if inner is not None:
                        source = inner
                except BaseException:                # pragma: no cover
                    pass
            code, detail = _registration.classify(source)
            with self._lock:
                self._connect_future = None
            _TRACE.record("registration", "failed", "warn", code=code)
            return code, detail
        if code == "captcha_required":
            # Phase one. The challenge is live and the stream is held open; the
            # coroutine is parked in `_submit_captcha` awaiting the answer, so
            # `_connect_future` stays set (a cancel still reaches it) and the
            # transport is NOT torn down here. submit_captcha_answer() finishes.
            _TRACE.record("registration", "captcha_required", "info")
            return code, detail
        # Terminal already: the coroutine set stage1 only after its `finally`
        # tore the stream down, so there is nothing left to keep.
        with self._lock:
            self._connect_future = None
        _TRACE.record("registration",
                      "succeeded" if code == _registration.OK else "failed",
                      "info" if code == _registration.OK else "warn", code=code)
        return code, detail

    def pending_captcha(self) -> Optional[Dict[str, Any]]:
        """The live CAPTCHA challenge for the Register screen to show, or None.

        Meaningful only between register_account() returning "captcha_required"
        and submit_captcha_answer(). `image_base64` is the inline challenge
        image (never a fetched one -- see captcha.py); the UI renders it and
        asks for the characters."""
        ch = self._reg_captcha
        if ch is None:
            return None
        return {"image_base64": ch.image_base64(),
                "image_mime": ch.image_mime,
                "instructions": ch.instructions,
                "answer_var": ch.answer_var}

    def submit_captcha_answer(self, answer: str) -> "tuple[str, str]":
        """Phase two: answer the CAPTCHA register_account() reported, over the
        stream it held open, and wait for the server's verdict. Blocks.

        Returns `(code, detail)` like register_account() -- `("ok", ...)` when
        the account was created. The stream is torn down before returning
        whatever the outcome: there is still no live session to keep. Returns
        a protocol error if no CAPTCHA is actually waiting (a double submit, or
        a submit after the park already timed out)."""
        loop = self._ensure_loop()
        answer_future = self._reg_answer
        final = self._reg_final
        if answer_future is None or final is None:
            return ("registration_protocol_error",
                    "No CAPTCHA is waiting to be answered.")
        text = "" if answer is None else str(answer)

        def _resolve():
            if not answer_future.done():
                answer_future.set_result(text)

        loop.call_soon_threadsafe(_resolve)
        _TRACE.record("registration", "captcha_answered", "info")
        try:
            code, detail = final.result(timeout=CAPTCHA_SUBMIT_TIMEOUT)
        except concurrent.futures.TimeoutError:
            # The server did not answer the submit in time. Tear the held
            # stream down so nothing is left spinning, and report a timeout
            # rather than blocking the caller (and the UI) any longer.
            _TRACE.record("registration", "captcha_submit_timeout", "warn")
            try:
                self.cancel()
            except Exception:
                pass
            code, detail = "timeout", _registration.describe("timeout")
        except BaseException as exc:                 # noqa: BLE001
            code, detail = _registration.classify(exc)
            _TRACE.record("registration", "failed", "warn", code=code)
        else:
            _TRACE.record("registration",
                          "succeeded" if code == _registration.OK else "failed",
                          "info" if code == _registration.OK else "warn",
                          code=code)
        finally:
            with self._lock:
                self._connect_future = None
        return code, detail

    def _reg_set_stage1(self, code: str, detail: str) -> None:
        fut = getattr(self, "_reg_stage1", None)
        if fut is not None and not fut.done():
            fut.set_result((code, detail))

    def _reg_set_final(self, code: str, detail: str) -> None:
        fut = getattr(self, "_reg_final", None)
        if fut is not None and not fut.done():
            fut.set_result((code, detail))

    async def _register(self) -> None:
        try:
            await self._register_inner()
            result = (_registration.OK,
                      _registration.describe(_registration.OK))
        except BaseException as exc:                 # noqa: BLE001
            # Total, like register_account's own catch: the outcome is handed
            # across to a waiting thread as a (code, detail), never as a raised
            # exception carrying a stanza.
            result = _registration.classify(exc)
        finally:
            # Unconditional, unlike `_connect`'s teardown which only runs on
            # failure. There is no session to keep here even when it worked.
            await self._abandon()
        # Hand the terminal outcome to whoever is waiting. For the no-CAPTCHA
        # path register_account() is blocked on stage1; for the CAPTCHA path
        # stage1 was already set to "captcha_required" (so this is a no-op on
        # it) and submit_captcha_answer() is blocked on final.
        self._reg_set_stage1(*result)
        self._reg_set_final(*result)

    async def _register_inner(self) -> None:
        try:
            host, port = await self._endpoint()
        except TransportError as exc:
            # `_endpoint` speaks the transport's vocabulary; the Register
            # screen speaks the registration module's. Translated here, where
            # both meanings are in scope, rather than by teaching `classify`
            # about transport codes it has no business knowing.
            raise _registration.RegistrationFailed(
                _REGISTRATION_CODES.get(exc.code, "unknown"))
        try:
            client = self._make_client()
        except Exception:
            raise _registration.RegistrationFailed("unknown")
        _enable_registration(client)
        self._client = client

        loop = asyncio.get_event_loop()
        done = loop.create_future()
        offered = {"register": False}

        async def on_register(form):
            """Submit the form XEP-0077 asked us to fill in.

            slixmpp fetches the form and fires this; the submission is ours to
            build. Errors are caught and put on `done` rather than allowed to
            escape, because this coroutine is awaited by slixmpp's feature
            negotiation and an exception in it is logged and dropped -- which
            is how a rejected registration turns into a silent wait for the
            300s timeout instead of "that username is taken".
            """
            offered["register"] = True
            blocker = _registration_blocker(form)
            _TRACE.record("registration", "form_received", "info",
                          fields=_form_field_names(form),
                          blocker=blocker or "none")
            if blocker == "registration_captcha_required":
                # A CAPTCHA. If the image is inline and showable, this parks on
                # the open stream for the user's answer and submits it; if it
                # can only be fetched from a web server, or cannot be shown,
                # `_submit_captcha` fails with the right code and nothing (no
                # password) is sent.
                await self._submit_captcha(client, form, done)
                return
            if blocker is not None:
                # An extra required field (not a CAPTCHA): the server would
                # refuse a username-and-password submission, so the password
                # is not sent at all.
                if not done.done():
                    done.set_exception(_registration.RegistrationFailed(blocker))
                return
            if self._route.verify_certificate and not _tls_in_place(client):
                # Clearnet (or a clearnet name over Tor): the form carries the
                # new password, and without TLS it would travel in the clear.
                # slixmpp does not insist on STARTTLS, so this does.
                if not done.done():
                    done.set_exception(
                        _registration.RegistrationFailed("tls_required"))
                return
            try:
                iq = client.Iq()
                iq["type"] = "set"
                iq["register"]["username"] = _localpart(self._profile.jid)
                iq["register"]["password"] = self._password
                _TRACE.record("registration", "submitted", "info")
                await iq.send()
            except Exception as exc:
                _TRACE.record("registration", "rejected", "info",
                              condition=_safe_condition(exc))
                if not done.done():
                    done.set_exception(exc)
            else:
                _TRACE.record("registration", "accepted", "info")
                if not done.done():
                    done.set_result(True)

        def on_session(_event):
            # Registration succeeded and slixmpp carried straight on into
            # SASL. Also the path on a server that never offered registration,
            # which `_register_inner` distinguishes below.
            if not done.done():
                done.set_result(True)

        def on_failed_auth(_event):
            if done.done():
                return
            # The account was not created and the server let us try to log in
            # as it anyway. That is the shape of a server with no in-band
            # registration, so say that rather than "wrong password" -- there
            # is no password to be wrong yet.
            done.set_exception(
                _registration.RegistrationFailed("unsupported"))

        watch = None
        if self._route.kind == _route_mod.CLEARNET_TLS:
            # Clearnet: every address is tried before giving up, and the
            # failure names its stage (see _StreamWatch).
            def fail(code, detail):
                if not done.done():
                    done.set_exception(
                        _registration.RegistrationFailed(code, detail))
            watch = _StreamWatch(client, self._route, fail, "registration")
            self._plan_clearnet_dns(client, watch, host)
        else:
            def on_connection_failed(event):
                if not done.done():
                    done.set_exception(ConnectionError(type(event).__name__))
            client.add_event_handler("connection_failed", on_connection_failed)
        self._watch_registration_discovery(client, done)

        client.add_event_handler("register", on_register)
        client.add_event_handler("session_start", on_session)
        client.add_event_handler("failed_auth", on_failed_auth)

        _TRACE.record("registration", "requested", "info")
        client.connect(host=host, port=port)
        try:
            await done
        finally:
            if watch is not None:
                watch.finish()

        if not offered["register"]:
            # The stream came up and authentication was reached without the
            # register feature ever appearing. Nothing was created, and
            # reporting success here would send the user to a sign-in screen
            # for an account that does not exist.
            raise _registration.RegistrationFailed("unsupported")
        # The server answered the registration as this name's server: pin
        # the destination it was reached at (X1; I2P names only).
        self._confirm_destination()

    async def _submit_captcha(self, client, form, done) -> None:
        """Hold the stream open across the CAPTCHA, then submit the answer.

        Called from `on_register` (itself a task, so awaiting here does not
        stall slixmpp) when the registration form is a CAPTCHA. It:

          1. parses the form with `captcha.extract_challenge`, which renders
             the image ONLY from the inline bits-of-binary the server already
             sent and REFUSES an image hosted at an http(s)/ftp URL (fetching
             it would leak the user's address). A refusal ends the attempt
             here with the right code and no password is ever sent;
          2. checks TLS is in place first -- the submission carries the new
             password, exactly as the no-CAPTCHA path does;
          3. signals phase one ("captcha_required") so register_account()
             returns with the stream still up, and parks on `_reg_answer`;
          4. when submit_captcha_answer() supplies the answer, builds the
             XEP-0004 submit form (every hidden field echoed verbatim, the
             user's text in the answer field) and sends it with the username
             and password as the XEP-0077 register sub-elements.
        """
        try:
            query_xml = form["register"].xml
        except Exception:
            query_xml = None
        try:
            challenge = _captcha.extract_challenge(query_xml)
        except _captcha.CaptchaError as exc:
            # Refused (external image, unshowable, oversized) or unreadable:
            # the stream is up but we send nothing. The code is already one of
            # the registration vocabulary, with the "password not sent" line.
            _TRACE.record("registration", "captcha_refused", "info",
                          code=exc.code)
            if not done.done():
                done.set_exception(
                    _registration.RegistrationFailed(exc.code, exc.detail))
            return
        except Exception:
            if not done.done():
                done.set_exception(_registration.RegistrationFailed(
                    "registration_protocol_error"))
            return

        missing = _captcha.missing_required(challenge)
        if missing:
            # The form asks for a field the Register screen cannot provide (an
            # e-mail address, a real name, ...). Do not prompt for a CAPTCHA we
            # could never complete; say so and send nothing.
            _TRACE.record("registration", "captcha_extra_fields", "info",
                          fields=",".join(sorted(missing))[:64])
            if not done.done():
                done.set_exception(_registration.RegistrationFailed(
                    "registration_fields_required"))
            return

        if self._route.verify_certificate and not _tls_in_place(client):
            # The submission will carry the new password; refuse to send it in
            # the clear. (The GET that brought the form is harmless; the SET is
            # the one that matters.)
            if not done.done():
                done.set_exception(
                    _registration.RegistrationFailed("tls_required"))
            return

        loop = asyncio.get_event_loop()
        answer_future = loop.create_future()
        self._reg_captcha = challenge
        self._reg_answer = answer_future
        # Phase one done: let register_account() return with the challenge
        # live. This is the one place stage1 becomes "captcha_required".
        self._reg_set_stage1(
            "captcha_required", _registration.describe("captcha_required"))
        _TRACE.record("registration", "captcha_wait", "info")
        try:
            answer = await asyncio.wait_for(answer_future, CAPTCHA_ANSWER_TIMEOUT)
        except asyncio.TimeoutError:
            # The screen was abandoned. End the attempt so the stream (and any
            # tunnel under it) is released by `_register`'s teardown.
            _TRACE.record("registration", "captcha_timeout", "info")
            if not done.done():
                done.set_exception(_registration.RegistrationFailed("cancelled"))
            return

        if not (answer or "").strip():
            # An empty answer is the UI's cancel (nobody submits a blank
            # CAPTCHA): release the stream without putting anything on the wire.
            _TRACE.record("registration", "captcha_cancelled", "info")
            if not done.done():
                done.set_exception(_registration.RegistrationFailed("cancelled"))
            return

        localpart = _localpart(self._profile.jid)
        try:
            submit = client["xep_0004"].make_form(ftype="submit")
            # Reply to the server's OWN form: echo the hidden fields, put the
            # answer in the answer field, and fill username/password wherever
            # the form declared them (ejabberd puts them in the form; others
            # read the sub-elements set below). Each field keeps the type the
            # server gave it, so this is not tied to any one server's layout.
            built = _captcha.submission_fields(
                challenge, answer, username=localpart, password=self._password)
            for var, vals in built.items():
                ftype = challenge.fields.get(var) or (
                    "text-single" if var == challenge.answer_var else "hidden")
                value = vals[0] if len(vals) == 1 else list(vals)
                submit.add_field(var=var, ftype=ftype, value=value)
            iq = client.Iq()
            iq["type"] = "set"
            iq["register"]["username"] = localpart
            iq["register"]["password"] = self._password
            iq["register"].append(submit.xml)
            _TRACE.record("registration", "captcha_submitted", "info")
            # Bounded: a server that takes the submit but never answers must
            # not hang the coroutine (and the blocked caller) indefinitely.
            # slixmpp raises IqTimeout past this, which `classify` reads as
            # "timeout" -- the same outcome as the caller-side bound.
            await iq.send(timeout=CAPTCHA_SUBMIT_TIMEOUT)
        except Exception as exc:
            _TRACE.record("registration", "captcha_rejected", "info",
                          condition=_safe_condition(exc))
            if not done.done():
                done.set_exception(exc)
        else:
            _TRACE.record("registration", "accepted", "info")
            if not done.done():
                done.set_result(True)

    def _plan_clearnet_dns(self, client, watch, host) -> None:
        """SRV-first address plan for a clearnet name (see dns_srv).

        Only when slixmpp was left to resolve (no explicit host): an explicit
        host:port is one attempt, and asyncio tries that host's addresses
        itself."""
        if host is not None or not hasattr(client, "get_dns_records"):
            watch.expected = 1
            return
        domain = self._route.host

        async def get_dns_records(_domain, port=None):
            loop = asyncio.get_event_loop()
            try:
                records, plan = await _clearnet_dns_records(
                    domain, loop, lookup=getattr(self, "_srv_lookup", None),
                    getaddrinfo=getattr(self, "_getaddrinfo", None),
                    fallback_port=int(getattr(client, "default_port",
                                              DEFAULT_C2S_PORT) or DEFAULT_C2S_PORT))
            except Exception as exc:                 # never let DNS code raise
                _TRACE.record("transport", "dns_plan_failed", "warning",
                              error=type(exc).__name__)
                records, plan = [], {}
            _TRACE.record("transport", "dns_plan", "info", **plan)
            watch.expected = max(1, len(records))
            if records:
                watch.stage = "tcp_connecting"
            return records

        client.get_dns_records = get_dns_records

    def _watch_registration_discovery(self, client, done) -> None:
        """The registration GET (XEP-0077 discovery) is sent by slixmpp's
        feature handler, where an error is logged and dropped, which would
        leave a silent wait for the timeout. Wrapped so its failure ends the
        attempt with its own code."""
        try:
            plugin = client["xep_0077"]
            original = plugin.get_registration
        except Exception:
            return

        async def get_registration(*args, **kwargs):
            _TRACE.record("registration", "discovery_requested", "info")
            try:
                return await original(*args, **kwargs)
            except Exception as exc:
                code, _ = _registration.classify(exc)
                if code == "unknown":
                    code = "registration_protocol_error"
                _TRACE.record("registration", "discovery_failed", "info",
                              code=code, condition=_safe_condition(exc))
                if not done.done():
                    done.set_exception(_registration.RegistrationFailed(code))
                raise

        plugin.get_registration = get_registration

    # -- probe: reach the server, sign in to nothing ----------------------------

    def probe_server(self) -> Dict[str, Any]:
        """DNS, TCP, TLS (certificate verified), the XMPP stream and its
        features, and XEP-0077 registration DISCOVERY -- then stop. Never
        authenticates and never submits a registration: the client carries an
        empty password and the SASL feature is removed before slixmpp sees
        it. Answers "unreachable" / "reached, registration offered or not" /
        "reached, then closed" / "reached, form needs a CAPTCHA". Blocks."""
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._probe(), loop)
        with self._lock:
            self._connect_future = future
        try:
            return future.result(timeout=CONNECT_TIMEOUT)
        except BaseException as exc:                 # noqa: BLE001
            code = getattr(exc, "code", None) or type(exc).__name__
            return {"ok": False, "code": str(code),
                    "detail": getattr(exc, "detail", "") or "", "reached": []}
        finally:
            with self._lock:
                self._connect_future = None

    async def _probe(self) -> Dict[str, Any]:
        try:
            return await self._probe_inner()
        finally:
            await self._abandon()

    async def _probe_inner(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"ok": False, "code": "", "detail": "",
                                  "route": self._route.kind, "reached": [],
                                  "register_offered": None,
                                  "registration_fields": "", "blocker": ""}
        try:
            host, port = await self._endpoint()
        except TransportError as exc:
            result.update(code=exc.code, detail=exc.detail)
            return result
        password, self._password = self._password, ""
        try:
            client = self._make_client()
        finally:
            self._password = password
        _enable_registration(client)
        self._client = client
        done = asyncio.get_event_loop().create_future()

        def finish(code, detail="", ok=False):
            if not done.done():
                result.update(ok=ok, code=code, detail=detail)
                done.set_result(True)

        watch = None
        if self._route.kind == _route_mod.CLEARNET_TLS:
            watch = _StreamWatch(client, self._route, finish, "probe")
            self._plan_clearnet_dns(client, watch, host)
        else:
            client.add_event_handler(
                "connection_failed",
                lambda e: finish("stream_failed", _stream_failure_text(
                    self._route, type(e).__name__)))

        def features(stanza):
            if type(stanza).__name__ != "StreamFeatures":
                return stanza
            names = [str(c.tag).rsplit("}", 1)[-1] for c in stanza.xml]
            for child in list(stanza.xml):
                if str(child.tag).endswith("}mechanisms"):
                    stanza.xml.remove(child)       # never authenticate
            if _tls_in_place(client):
                result["reached"].append("xmpp_stream")
                result["register_offered"] = "register" in names
                _TRACE.record("probe", "features", "info",
                              register="register" in names,
                              sasl="mechanisms" in names)
                if "register" not in names:
                    finish("registration_not_offered",
                           "Reached; TLS verified; the server does not "
                           "offer in-app registration.", ok=True)
            elif "starttls" not in names:
                finish("tls_required",
                       "Reached, but the server offered no TLS.")
            return stanza

        async def on_register(form):
            blocker = _registration_blocker(form)
            result["registration_fields"] = _form_field_names(form)
            result["blocker"] = blocker or ""
            result["reached"].append("registration_form")
            finish(blocker or "registration_available",
                   "Reached; TLS verified; registration form received "
                   "(%s)." % result["registration_fields"], ok=True)

        client.add_filter("in", features)
        client.add_event_handler("register", on_register)
        self._watch_registration_discovery(client, done)
        _TRACE.record("probe", "requested", "info", route=self._route.kind)
        client.connect(host=host, port=port)
        try:
            await done
        except _registration.RegistrationFailed as exc:
            result.update(code=exc.code, detail=_registration.describe(exc.code))
        finally:
            if watch is not None:
                watch.finish()
                result["reached"] = watch.reached + [
                    r for r in result["reached"] if r not in watch.reached]
        _TRACE.record("probe", "result", "info", code=result["code"],
                      reached=",".join(result["reached"]))
        return result
