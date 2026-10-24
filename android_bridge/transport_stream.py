# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Watching a stream to the server come up, and saying why it did not.

Shared by the sign-in path (transport.py) and account creation
(transport_registration.py): the stage watcher, the TLS check, and the
text a failed stream is reported with.
"""
from __future__ import annotations

import asyncio
from typing import List, Optional

from . import route as _route_mod
from .trace import TRACE as _TRACE


def _tls_in_place(client) -> bool:
    """Whether the stream is TLS-protected (STARTTLS done, or TLS socket)."""
    try:
        if "starttls" in getattr(client, "features", set()):
            return True
        import ssl
        return isinstance(getattr(client, "socket", None),
                          (ssl.SSLSocket, ssl.SSLObject))
    except Exception:
        return False


def _errno_name(exc) -> str:
    import errno as _errno
    num = getattr(exc, "errno", None)
    if isinstance(num, int) and num in _errno.errorcode:
        return _errno.errorcode[num]
    return type(exc).__name__


class _StreamWatch:
    """How one slixmpp connection attempt is going, and when it has failed.

    Fed by slixmpp's own events. `fail(code, detail)` is called at most
    once, with a code from STAGE_CODES (clearnet) and a detail naming the
    stage and the OS/TLS reason -- never a password, a stanza or a key.
    """

    def __init__(self, client, route, fail, label: str):
        self.client, self.route, self._fail, self.label = client, route, fail, label
        self.stage = "resolving"
        self.expected: Optional[int] = None     # planned addresses, if known
        self.failures: List[str] = []
        self.done = False
        #: Stages reached, in order -- the probe reports these.
        self.reached: List[str] = []
        for name, fn in (("connection_failed", self._on_conn_failed),
                         ("reconnect_delay", self._on_reconnect_delay),
                         ("connected", self._on_connected),
                         ("tls_success", self._on_tls),
                         ("ssl_invalid_chain", self._on_invalid_chain),
                         ("stream_error", self._on_stream_error),
                         ("disconnected", self._on_disconnected)):
            client.add_event_handler(name, fn)
        if route.verify_certificate and hasattr(client, "add_filter"):
            client.add_filter("in", self._features_filter)

    def _features_filter(self, stanza):
        """A clearnet server whose first features offer no STARTTLS is
        refused by name, before anything else is negotiated."""
        if type(stanza).__name__ == "StreamFeatures" and not self.done:
            names = [str(c.tag).rsplit("}", 1)[-1] for c in stanza.xml]
            if not _tls_in_place(self.client):
                if "starttls" not in names:
                    self.stage = "xmpp_stream"
                    self._emit("tls_required",
                               "The server was reached but offered no TLS, "
                               "so nothing was sent.")
                    return None
                # slixmpp answers <starttls/> next: the handshake is the
                # stage from here until tls_success.
                self.stage = "tls_handshake"
            elif "xmpp_stream" not in self.reached:
                self.reached.append("xmpp_stream")
                _TRACE.record(self.label, "stream_features", "info",
                              register="register" in names,
                              sasl="mechanisms" in names)
        return stanza

    def finish(self):
        self.done = True

    def _emit(self, code, detail):
        if self.done:
            return
        self.done = True
        _TRACE.record(self.label, "failed_at", "warning", code=code,
                      stage=self.stage, reasons=";".join(self.failures[-6:]))
        self._fail(code, detail)

    def _on_conn_failed(self, event):
        if isinstance(event, BaseException):
            reason = _errno_name(event)
        else:
            reason = "dns"                      # slixmpp passes a string
        self.failures.append(reason)
        _TRACE.record(self.label, "address_failed", "info", reason=reason,
                      attempt=len(self.failures))
        if self.expected is None or len(self.failures) >= self.expected:
            self._all_failed()

    def _on_reconnect_delay(self, _event):
        # slixmpp only reschedules after every address in the round failed.
        if self.failures:
            self._all_failed()

    def _all_failed(self):
        if all(f == "dns" for f in self.failures):
            self._emit("dns_failure",
                       "DNS: the server's name did not resolve to any address.")
        else:
            self._emit("tcp_failure",
                       "TCP: no address of the server accepted a connection "
                       "(%s). The server was not reached; nothing was sent."
                       % ", ".join(dict.fromkeys(self.failures)))

    def _on_connected(self, _event):
        self.stage = "tcp_connected"
        self.reached.append("tcp_connected")
        _TRACE.record(self.label, "tcp_connected", "info",
                      after_failures=len(self.failures))

    def _on_tls(self, _event):
        self.stage = "tls_established"
        self.reached.append("tls_established")
        _TRACE.record(self.label, "tls_established", "info",
                      certificate="verified" if self.route.verify_certificate
                      else "not used")

    def _on_invalid_chain(self, exc):
        import ssl as _ssl
        self.stage = "tls_handshake"
        if isinstance(exc, _ssl.SSLCertVerificationError):
            why = getattr(exc, "verify_message", "") or "not trusted"
            self._emit("certificate_failure",
                       "TLS: the server's certificate was rejected (%s). "
                       "Nothing was sent; certificate checks are never "
                       "switched off for a clearnet server." % why)
        else:
            self._emit("tls_failure",
                       "TLS: the handshake with the server failed (%s)."
                       % type(exc).__name__)
        try:
            self.client.abort()
        except Exception:
            pass

    def _on_stream_error(self, stanza):
        try:
            cond = stanza["condition"]
        except Exception:
            cond = "unknown"
        self._emit("xmpp_stream_failure",
                   "XMPP: the server ended the stream with an error (%s) at "
                   "stage %s." % (cond, self.stage))

    def _on_disconnected(self, _event):
        if self.stage in ("resolving", "tcp_connecting"):
            return
        if self.stage == "tls_handshake":
            # A rejected certificate makes the server drop the connection,
            # and `disconnected` can arrive before slixmpp's
            # `ssl_invalid_chain`. Give the precise event a moment to land.
            try:
                asyncio.get_event_loop().call_later(
                    0.5, self._emit, "tls_failure",
                    "TLS: the connection closed during the handshake.")
            except RuntimeError:
                self._emit("tls_failure",
                           "TLS: the connection closed during the handshake.")
            return
        self._emit("server_closed_connection",
                   "The server closed the connection after %s, before the "
                   "operation finished." % self.stage.replace("_", " "))


def _stream_failure_text(route, what: str) -> str:
    """Which layer a stream failure belongs to, by route."""
    if route.kind == _route_mod.CLEARNET_TLS:
        return ("the XMPP stream could not be established (%s): DNS, the TCP "
                "connection or the TLS handshake with the server failed. If "
                "TLS failed, the server's certificate may not be valid for "
                "its domain; nothing insecure was attempted instead." % what)
    if route.kind == _route_mod.TOR:
        return ("the XMPP stream could not be established (%s). The Tor "
                "circuit was open, so this is the server or the TLS "
                "handshake rather than Tor." % what)
    return ("the XMPP stream could not be established (%s). The SAM tunnel "
            "was open, so this is the server or the TLS handshake rather "
            "than I2P." % what)
