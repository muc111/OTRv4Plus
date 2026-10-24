# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Creating an account (XEP-0077) over the XMPP transport, and probing a
server before signing in to it.

A mixin of XmppTransport (transport.py). In-band registration is the one
operation that sends a password to a server that has not yet proved who it
is, so it runs only over TLS (or I2P) and says plainly why a server refused."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import otrv4plus_registration as _registration

from . import route as _route_mod
from .trace import TRACE as _TRACE
from .transport_base import CONNECT_TIMEOUT, DEFAULT_C2S_PORT, TransportError
from .transport_stream import _StreamWatch, _stream_failure_text, _tls_in_place


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

        The stream is always torn down before returning. Registration leaves
        slixmpp authenticated on some servers, and keeping that would mean two
        ways to arrive at a live session; `connect()` stays the only one.
        """
        problem = _registration.validate(
            _localpart(self._profile.jid), self._password)
        if problem is not None:
            _TRACE.record("registration", "refused_locally", "info",
                          code=problem[0])
            return problem

        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(self._register(), loop)
        # Recorded in the same slot a connect uses so `cancel()` stops this
        # too. A cold tunnel is minutes and Android will rotate the screen
        # inside that window whatever the screen happens to be.
        with self._lock:
            self._connect_future = future
        try:
            future.result(timeout=CONNECT_TIMEOUT)
        except BaseException as exc:                 # noqa: BLE001 -- see below
            # Deliberately everything, CancelledError included: `classify` is
            # total and answers "cancelled" for that case, and an exception
            # escaping here would reach Kotlin as a Chaquopy PyException with
            # the stanza still inside its message.
            code, detail = _registration.classify(exc)
            _TRACE.record("registration", "failed", "warn", code=code)
            return code, detail
        finally:
            with self._lock:
                self._connect_future = None
        _TRACE.record("registration", "succeeded", "info")
        return _registration.OK, _registration.describe(_registration.OK)

    async def _register(self) -> None:
        try:
            await self._register_inner()
        finally:
            # Unconditional, unlike `_connect`'s teardown which only runs on
            # failure. There is no session to keep here even when it worked.
            await self._abandon()

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
            if blocker is not None:
                # A CAPTCHA or an extra required field: the server would
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
