# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Refuse a DTD, and an endless stanza, before the XML parser sees them.

slixmpp hands every byte from the socket straight to expat. Expat accepts a
`<!DOCTYPE ...>` at the start of a stream and expands the entities it
declares, so whoever is at the far end (the server, or on clearnet anyone on
the path before STARTTLS has finished) reaches expat's DTD and entity code
with no action from the user. That code is where most of expat's memory and
recursion CVEs have been. XMPP forbids DTDs outright (RFC 6120 §11.1), so no
real stream loses anything when they are refused.

`StreamGuard` reads the bytes first. In well-formed XML a `<!` outside a
comment, a CDATA section or a processing instruction can only open a
declaration (DOCTYPE, ENTITY, ELEMENT, ATTLIST, NOTATION) or a conditional
section, and none of those belongs in XMPP. So the rule is: `<!` must be
followed by `--` or `[CDATA[`; anything else ends the connection before the
byte that decides it is passed on.

Why a byte scan is exact here:

* Where this scanner and expat disagree about what is a comment, CDATA or
  PI, expat has already stopped with a syntax error (`<` in an attribute
  value, `--` inside a comment, CDATA in the prolog), and a stopped parser
  processes nothing further.
* Another encoding cannot hide the markup. UTF-16 and UTF-32 put a zero byte
  beside every ASCII character, and a zero byte is refused; every other
  encoding expat accepts must keep `<`, `!` and the letters at their ASCII
  values (expat's own rule for unknown encodings).

A peer cannot use this to disconnect someone: text inside a stanza cannot
contain a bare `<!` without being malformed, which the server's parser has
already refused.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# Bytes received since the last complete stanza. The largest real stanza is
# well under 1 MiB (the server caps what a client may send at 256 KiB); past
# this, the far end is feeding the parser memory.
MAX_OPEN_STANZA_BYTES = 16 * 1024 * 1024

# Fired on the client, with the reason, just before a refused stream is
# closed; sasl_hardening fires it too.
REFUSED_EVENT = "stream_refused"

_TEXT, _PI, _COMMENT, _CDATA = range(4)
_OPEN = re.compile(rb"<[!?]")
_CDATA_OPEN = b"[CDATA["
_COMMENT_OPEN = b"--"
_END = {_PI: b"?>", _COMMENT: b"-->", _CDATA: b"]]>"}
_STATE_NAMES = {_TEXT: "text", _PI: "instruction", _COMMENT: "comment",
                _CDATA: "cdata"}


class StreamGuard:
    """One per XML stream; `reset()` when the stream restarts."""

    def __init__(self) -> None:
        self.reason: Optional[str] = None
        self._state = _TEXT
        self._carry = b""

    def reset(self) -> None:
        self.reason = None
        self._state = _TEXT
        self._carry = b""

    def state_name(self) -> str:
        """Where the scan was: in text, or inside a comment, a CDATA section
        or a processing instruction. For the report; a name, nothing read."""
        return _STATE_NAMES.get(self._state, "text")

    def allows(self, data) -> bool:
        """True if `data` may be passed to the parser. Once False, always
        False until `reset()`."""
        if self.reason is not None:
            return False
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        if b"\x00" in data:
            self.reason = "nul_byte"
            return False
        # `_carry` is the end of what was already passed on, kept only
        # because its meaning depends on bytes not yet seen: a lone `<`, a
        # `<!` whose next bytes decide it, or the start of a terminator.
        buf = self._carry + bytes(data)
        self._carry = b""
        pos = 0
        while True:
            if self._state == _TEXT:
                match = _OPEN.search(buf, pos)
                if match is None:
                    if buf.endswith(b"<"):
                        self._carry = b"<"
                    return True
                at = match.start()
                if buf[at + 1:at + 2] == b"?":
                    self._state = _PI
                    pos = at + 2
                    continue
                rest = buf[at + 2:at + 2 + len(_CDATA_OPEN)]
                if rest.startswith(_COMMENT_OPEN):
                    self._state = _COMMENT
                    pos = at + 2 + len(_COMMENT_OPEN)
                elif rest == _CDATA_OPEN:
                    self._state = _CDATA
                    pos = at + 2 + len(_CDATA_OPEN)
                elif (at + 2 + len(rest) == len(buf)
                      and (_CDATA_OPEN.startswith(rest)
                           or _COMMENT_OPEN.startswith(rest))):
                    # Still could be either; the next bytes decide.
                    self._carry = buf[at:]
                    return True
                else:
                    self.reason = "declaration"
                    return False
            else:
                end = _END[self._state]
                found = buf.find(end, pos)
                if found < 0:
                    # Only bytes after the opener can start the terminator.
                    keep = len(end) - 1
                    self._carry = buf[max(pos, len(buf) - keep):]
                    return True
                self._state = _TEXT
                pos = found + len(end)


def stream_position(client) -> Dict[str, Any]:
    """Where a connection was when something on it was refused: which stream
    (1 is before TLS, 2 after it, 3 after signing in), whether it was
    encrypted, how much had arrived on it and how long it had been open.
    Counts and a protocol name; nothing that was sent or received."""
    facts: Dict[str, Any] = {}
    number = getattr(client, "_stream_number", None)
    if isinstance(number, int) and not isinstance(number, bool) and number > 0:
        facts["stream"] = number
    for fact, attribute in (("stream_bytes", "_stream_bytes"),
                            ("stream_stanzas", "_stream_stanzas")):
        value = getattr(client, attribute, None)
        if isinstance(value, int) and not isinstance(value, bool):
            facts[fact] = value
    now = time.monotonic()
    for fact, attribute in (("since_connect_s", "_connect_started"),
                            ("since_stream_s", "_stream_started")):
        began = getattr(client, attribute, None)
        if isinstance(began, (int, float)) and not isinstance(began, bool):
            facts[fact] = now - began
    try:
        transport = getattr(client, "transport", None)
        if transport is not None:
            tls = transport.get_extra_info("ssl_object")
            facts["tls"] = (tls.version() or "unknown") if tls else "none"
    except Exception:
        pass
    return facts


class GuardedStream:
    """Mixin, placed before slixmpp's client class.

    `init_parser` runs for every new stream (connect, after STARTTLS, after
    SASL), which is each point where a document prolog, and so a DOCTYPE,
    is possible again.
    """

    def init_parser(self):
        guard = getattr(self, "_stream_guard", None)
        if guard is None:
            self._stream_guard = StreamGuard()
        else:
            guard.reset()
        # A new stream is judged afresh. (Left set, a second refusal for the
        # same reason on a reused client was dropped without closing.)
        self._stream_refused = None
        self._open_stanza_bytes = 0
        now = time.monotonic()
        self._stream_number = getattr(self, "_stream_number", 0) + 1
        if self._stream_number == 1:
            self._connect_started = now
        self._stream_started = now
        self._stream_bytes = 0
        self._stream_stanzas = 0
        # The size cap resets on each complete stanza, which needs slixmpp's
        # `_spawn_event` hook. Without the hook (another slixmpp version) the
        # cap is off rather than counting the whole session against it.
        self._stanza_cap_on = callable(
            getattr(super(), "_spawn_event", None))
        try:
            from . import server_proof
            server_proof.passed("streams_guarded")
        except Exception:
            pass
        return super().init_parser()

    def connection_lost(self, exception):
        # The next connection on this object counts its streams from one.
        self._stream_number = 0
        return super().connection_lost(exception)

    def data_received(self, data):
        guard = getattr(self, "_stream_guard", None)
        if guard is None:
            guard = self._stream_guard = StreamGuard()
            self._open_stanza_bytes = 0
            self._stanza_cap_on = False
        if not guard.allows(data):
            self._refuse_stream(guard.reason or "declaration")
            return None
        if getattr(self, "_stanza_cap_on", False):
            self._open_stanza_bytes += len(data)
            if self._open_stanza_bytes > MAX_OPEN_STANZA_BYTES:
                guard.reason = "stanza_too_large"
                self._refuse_stream(guard.reason)
                return None
        self._stream_bytes = getattr(self, "_stream_bytes", 0) + len(data)
        return super().data_received(data)

    def _spawn_event(self, xml):
        self._open_stanza_bytes = 0
        self._stream_stanzas = getattr(self, "_stream_stanzas", 0) + 1
        return super()._spawn_event(xml)

    def _refuse_stream(self, reason: str) -> None:
        """Close at once, without replying: nothing more is parsed, and a
        stream error would be a courtesy to whoever sent this."""
        if getattr(self, "_stream_refused", None) == reason:
            return
        self._stream_refused = reason
        line = reason
        facts: Dict[str, Any] = {}
        try:
            # Where it was, for the report: the bytes themselves are never
            # kept (android_bridge/server_proof.py says what may be).
            from . import server_proof
            facts = stream_position(self)
            guard = getattr(self, "_stream_guard", None)
            if guard is not None:
                facts["parser_state"] = guard.state_name()
            if reason == "stanza_too_large":
                facts["open_stanza_bytes"] = getattr(
                    self, "_open_stanza_bytes", None)
            record = server_proof.note("xml", reason, **facts)
            line = server_proof.summary_line(record) or reason
        except Exception:
            pass
        _log.error("stream refused before parsing: %s", line)
        try:
            from . import trace as _trace
            _trace.TRACE.record("connection", "restricted_xml_refused",
                                "error", reason=reason,
                                stream=facts.get("stream"),
                                tls=facts.get("tls"),
                                received=facts.get("stream_bytes"),
                                stanzas=facts.get("stream_stanzas"))
        except Exception:
            pass
        try:
            self.event(REFUSED_EVENT, reason)
        except Exception:
            pass
        try:
            self.disconnect_reason = "restricted XML refused (%s)" % reason
            self.abort()
        except Exception:
            _log.exception("could not close a refused stream")
