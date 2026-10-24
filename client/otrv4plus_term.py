# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Terminal output for the XMPP client: `print`, the session transcript and
the coloured tags.

Moved out of otrv4plus_xmpp.py so the parts of the client that live in their
own modules print through the same function. `print` here shadows the builtin
on purpose: every line also goes to the TUI panel (when one is up), the
channel log and, under --debug, the session transcript.

The state below is set by the client while it runs, as attributes of this
module (`otrv4plus_term._ACTIVE_CLIENT = self`), never copied elsewhere.
"""
import builtins
import os
import re
import sys
import time

#: The engine's colour function; the client sets it at import (the engine is
#: not imported here). Plain text until then.
_colorize = lambda s, c: s  # noqa: E731

_ACTIVE_TUI_CLIENT = None
# Set unconditionally as soon as the client object exists, independent of
# whether the TUI starts.  The module-level print() uses this to route every
# line to channel_log even in plain (--no-tui / default) mode.
_ACTIVE_CLIENT = None

# Full session transcript (written under --debug, deleted on clean exit).
_SESSION_LOG_FH = None
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _sanitise(text, max_len: int = 1024) -> str:
    """Strip ANSI/OSC/CSI escape sequences and control characters from
    untrusted data (peer JIDs, plaintext bodies, decrypted OTR payloads)
    before writing to the terminal."""
    text = str(text)
    text = re.sub(r"\x1b[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", "", text)
    text = re.sub(r"\x1b[\x20-\x2f][\x30-\x7e]", "", text)
    text = re.sub(r"\x1b.", "", text, flags=re.DOTALL)
    text = re.sub(r"[\x00-\x08\x0a-\x1f\x7f\x80-\x9f]", "", text)
    return text[:max_len]


# --------------------------------------------------------------------------
# Session transcript: what may be written, not what must be stripped
# --------------------------------------------------------------------------
#
# This used to be one regex that redacted `[otr] <peer> body` lines and wrote
# everything else verbatim.  That fails open: a `print()` added anywhere in
# the client carrying a passphrase, a key or a token reaches the file with
# nothing objecting, and these are the files people paste into bug reports.
# A denylist has to enumerate every way a secret can look; an allowlist has
# to enumerate the ways a diagnostic can look, and there are far fewer of
# those and they change far less often.
#
# So: a line is written only if its shape is recognised.  Anything else is
# recorded as its tag and its length, which is enough to see that something
# happened and where, and not enough to leak what.

#: Message-content lines.  The prefix is kept, the body is not: knowing that
#: a message arrived from a peer at a time is the diagnostic value; the words
#: are the thing being protected.
#: `[otr] alice@host: body` and the older `[otr] <alice@host> body`.
#:
#: Both shapes are matched because the display moved from the second to the
#: first in v10.27.0 and this is the allowlist that keeps message bodies off
#: disk (INV-03).  A pattern that knew only the old shape would not have
#: LEAKED -- `_log_line_for_file` falls through to "<unlogged line: N chars>"
#: for anything it cannot classify -- but it would have thrown the sender away
#: with the body, and a transcript that cannot say who spoke is most of the
#: way to useless.  The old alternative stays because other paths may still
#: print it, and dropping it would silently downgrade those to unlogged.
_LOG_CONTENT_RE = re.compile(
    r"^(\[(?:otr|plain)\] (?:<[^>]*>|[^\s:]+:))\s(.*)$", re.DOTALL)

#: Tags whose lines are wholly diagnostic and carry no user or key material.
#: Adding one is a deliberate act: whatever that subsystem prints becomes
#: readable on disk, so the reviewer's question is "can this tag ever print a
#: secret", not "does it today".
_LOG_SAFE_TAGS = frozenset({
    "audio", "auth", "call", "dake", "identity", "i2p", "jitter", "log",
    "media", "net", "otr", "ping", "presence", "rekey", "sam", "smp",
    "trust", "tui", "voice", "xmpp",
})

#: Bare structural lines: rules, banners and blank separators.
_LOG_STRUCTURAL_RE = re.compile(r"^[\s\-=!*_.#|+>]*$")

#: `[tag] free text` -- the shape of essentially every diagnostic here.
_LOG_TAGGED_RE = re.compile(r"^\[([a-z0-9 _-]{1,16})\](.*)$", re.DOTALL)

#: Status glyphs the client prints in front of a tag -- the padlock on every
#: SMP line, the traffic lights on trust changes.  They are decoration, not
#: shape, so they are stripped before anything is matched rather than being
#: allowed for in each rule.  Stripping first is the point: were the marker
#: tolerated only by the `[tag]` rule, "MARKER [otr] <peer> body" would walk
#: straight past the message-body redaction and write the message to disk.
#: The list is exact on purpose -- "any leading emoji" would be a hole.
_LOG_MARKERS = ("\U0001f510", "\U0001f512", "\U0001f513", "\U0001f535",
                "\U0001f7e2", "\U0001f7e1", "\U0001f534", "\u2705",
                "\u274c", "\u26a0\ufe0f", "\u26a0", "\U0001f980")


def _strip_log_markers(text: str, limit: int = 4) -> str:
    """Remove leading status glyphs and the space after them."""
    for _ in range(limit):
        for marker in _LOG_MARKERS:
            if text.startswith(marker):
                text = text[len(marker):].lstrip(" ")
                break
        else:
            break
    return text


def _log_line_for_file(msg: str) -> str:
    """The text to write for `msg`, or a redacted stand-in.

    Pure and side-effect free so the tests can drive it directly with
    candidate leaks rather than through a file handle.
    """
    clean = _strip_log_markers(_ANSI_RE.sub("", msg))

    m = _LOG_CONTENT_RE.match(clean)
    if m:
        return "%s <message body redacted: %d chars>" % (m.group(1),
                                                         len(m.group(2)))

    if _LOG_STRUCTURAL_RE.match(clean):
        return clean

    m = _LOG_TAGGED_RE.match(clean)
    if m and m.group(1).strip().lower() in _LOG_SAFE_TAGS:
        return clean

    # Unrecognised shape.  Something printed it, and the transcript should
    # show that -- but not its content, because nothing here knows what it
    # is.  A password prompt, a traceback, a third-party library's warning
    # and a leaked key all arrive through this branch.
    return "<unlogged line: %d chars>" % len(clean)


def _log_to_file(msg):
    if _SESSION_LOG_FH is None:
        return
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        _SESSION_LOG_FH.write("%s %s\n" % (ts, _log_line_for_file(msg)))
        _SESSION_LOG_FH.flush()
    except Exception:
        pass


#: `[tag]` -> the colour it is drawn in.
#:
#: Nearly every line this client prints is `[tag] free text`, and until now
#: every one of those tags was the same colourless grey as the sentence after
#: it.  On a handset that is a wall: a fingerprint-change warning and a
#: keepalive tick look identical until you have read both.  Asked for from
#: the device -- "colour coding to improve the layout".
#:
#: The grouping is by what the line MEANS to a reader, not by which module
#: emitted it:
#:
#:   red      something failed or is refusing to proceed
#:   yellow   attention: the transport wobbled, or trust needs a decision
#:   cyan     things the user asked for -- transfers, trades, tips
#:   magenta  the call subsystem
#:   grey     plumbing that is working: I2P, SAM, presence, the log itself
#:
#: `[otr]` and `[smp]` are absent deliberately.  Those two already carry
#: their own padlock-and-colour prefixes, built above, and a second colour
#: applied here would fight them.
_TAG_COLOURS = {
    "fatal": "bold_red",
    "auth failed": "bold_red",
    "rate-limit": "red",

    "trust": "bold_yellow",
    # Admin is the one surface that is NOT end-to-end encrypted and the one
    # that can delete an account, so it is coloured for attention rather than
    # grouped with the cyan things the user merely asked for.
    "admin": "bold_yellow",
    "reconnect": "yellow",
    "keepalive": "yellow",
    "auth": "yellow",

    "file": "cyan",
    "trade": "cyan",
    "tip": "cyan",
    "roster": "cyan",

    "voice": "magenta",
    "audio": "magenta",

    "i2p": "grey",
    "tor": "grey",
    "log": "grey",
    "tui": "grey",
    "ping": "grey",
    "presence": "grey",
    "identity": "grey",
}

#: `[tag]` at the very start of a line, with nothing before it.
#:
#: The anchor is the whole design.  `re.search` here would colour the `[otr]`
#: inside "use [otr] to start a session", and an lstrip() before the match
#: would colour the indented continuation lines of a multi-line report --
#: repeating the heading's mark down the block.  Matched against the raw
#: line, from position zero, so only a line whose SUBJECT is the tag is
#: touched.
_TAG_AT_START_RE = re.compile(r"^\[([a-z0-9 _-]{1,16})\]")


def _colour_tag(msg: str) -> str:
    """Colour a leading `[tag]`, and nothing else on the line.

    Display only.  This runs AFTER the line has been handed to the session
    log and the channel log, so nothing coloured is ever what gets written --
    INV-03's redaction reasons about shapes, and it should not have to
    reason about escape sequences as well.

    The client's existing palette is safe from this by construction rather
    than by a guard: the chat transcript and the SMP prompts begin with a
    padlock glyph or an escape sequence, so the anchored pattern never
    matches them.  The one shape that does reach here already carrying
    colour is the voice call summary, whose mouth-to-ear reading is coloured
    by its band -- and a magenta `[voice]` in front of that is exactly what
    the rest of the call's output has.
    """
    try:
        if not msg:
            return msg
        m = _TAG_AT_START_RE.match(msg)
        if not m:
            return msg
        colour = _TAG_COLOURS.get(m.group(1).strip().lower())
        if not colour:
            return msg
        return _colorize(m.group(0), colour) + msg[m.end():]
    except Exception:
        return msg


#: Monotonic count of lines this module has printed.
#:
#: Used by the plain-mode echo below to tell "nothing has been printed since
#: the user pressed Enter" from "an inbound message arrived in between". The
#: first case can safely rewrite the line the terminal echoed; the second
#: must not, because the line above the cursor is no longer the user's input.
_PRINT_SEQ = 0


def _terminal_cols():
    """Width of the terminal, or None if stdout is not one we can measure.

    One seam rather than two checks at the call site, because everything that
    depends on this is destructive: the caller uses it to decide how many
    rows to move the cursor up, and "not a terminal" and "a terminal of
    unknown width" have to fail exactly the same way -- by not moving it.
    """
    try:
        if not sys.stdout.isatty():
            return None
        cols = os.get_terminal_size().columns
        return cols if cols and cols > 0 else None
    except Exception:
        return None


def _raw_write(text):
    """Write control text straight to the terminal, unlogged.

    Deliberately not `print`: this carries cursor movement, not content.  It
    must not reach the session transcript, must not advance `_PRINT_SEQ`
    (which exists to detect that content was printed), and must not be
    routed to a TUI panel.
    """
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except Exception:
        pass


def print(*args, **kwargs):  # noqa: A001 (intentional module-scope shadow)
    global _PRINT_SEQ
    _PRINT_SEQ += 1
    c = _ACTIVE_TUI_CLIENT
    sep = kwargs.get("sep", " ")
    msg = sep.join(str(a) for a in args)
    _log_to_file(msg)
    # Always write to the encrypted per-peer channel log, TUI or not.
    # Without this, plain-mode sessions (the default) never record history.
    lc = _ACTIVE_CLIENT
    if lc is not None and getattr(lc, "channel_log", None) is not None and msg:
        try:
            peer = lc._extract_peer(msg) if hasattr(lc, "_extract_peer") else None
            lc.channel_log.append(peer or "system", msg)
        except Exception:
            pass
    # The TUI is handed the PLAIN line, deliberately.
    #
    # _tui_route_output decides which panel a line belongs to with
    # `stripped.startswith("[keepalive]")` and the rest of _SYS_PREFIXES.  A
    # coloured tag begins with an escape sequence, so every one of those
    # tests would quietly fail and keepalive ticks would land in the peer's
    # chat panel.  The panels apply their own palette anyway; this colouring
    # is for the plain terminal, which is the default mode.
    if c is not None and getattr(c, "_tui_enabled", False):
        try:
            c._tui_route_output(msg)
            return
        except Exception:
            pass
    # Colour goes on LAST, after both logs have taken the plain text.
    shown = _colour_tag(msg)
    if shown is msg:
        builtins.print(*args, **kwargs)
    else:
        builtins.print(shown, **{k: v for k, v in kwargs.items()
                                 if k != "sep"})
