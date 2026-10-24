#!/usr/bin/env python3
"""
otrv4plus_log.py — in-memory per-channel scrollback for OTRv4+
==============================================================

What this is
------------
A bounded ring of recent lines per conversation, so `/log` can show history
in either front end.  It lives in the process and dies with it.

What this used to be, and why it changed (v10.13.1)
---------------------------------------------------
This module used to write `~/.otrv4plus/logs/channels/<id>.enc` under a
hand-rolled AEAD -- a SHAKE-256 keystream XORed over the plaintext with an
HMAC-SHA3-512 tag, described in its own docstring as "stdlib-only, no new
deps".  It had two modes:

    persistent=False   ephemeral key, files deleted on close()
    persistent=True    key saved to ~/.otrv4plus/channel_log.key, files kept

Three things were wrong with that.

1.  The project already has an audited AES-256-GCM in the Rust core,
    reachable from Python as `otrv4_core.aes256gcm_encrypt`.  A second,
    home-grown construction existing beside it is exactly the divergence the
    security invariants forbid (INV-14).

2.  The persistent mode was dead.  Both clients passed `persistent=False`
    and always had; only the docstring claimed otherwise.  So the key file,
    the retained transcripts and the cross-session history were an
    unexercised code path one constructor argument away from writing every
    message anyone had typed to disk.

3.  Even ephemerally it wrote plaintext-derived files during the session and
    deleted them at close, so a crash left them behind.  Unreadable, since
    the key was gone with the process -- but written all the same.

Deleting the persistent branch and swapping the cipher would have fixed (1)
and (2).  Removing the disk entirely fixes (3) as well and leaves no cipher
here to get wrong, which is why that is what happened.

If cross-session history is ever wanted, it needs designing against the Rust
AEAD and the sealed-storage architecture in `android_bridge/secure_store.py`,
not by restoring what was here.  `tests/test_no_parallel_crypto.py` fails if
this module grows a cipher or a file write again.
"""

import re
from collections import deque

#: Lines retained per conversation.  A 12-hour session at a brisk typing
#: rate does not approach this; the cap exists so a misbehaving peer or a
#: chatty diagnostic cannot grow the process without bound.
MAX_LINES_PER_CHANNEL = 20_000

#: Conversations tracked at once.  Beyond this the least recently used is
#: dropped, so a peer cannot allocate unbounded channels by cycling JIDs.
MAX_CHANNELS = 256


_ANSI_STRIP = re.compile(
    r"\x1b(?:"
    r"[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|[\x20-\x2f][\x30-\x7e]"
    r"|."
    r")"
)


def _strip_ansi(text: str) -> str:
    return _ANSI_STRIP.sub("", str(text))


class ChannelLogManager:
    """Recent lines per conversation, in memory, for this process only.

    There is no `persistent` parameter.  There was one, it was never set to
    True by any caller, and it is not coming back: see the module docstring.
    """

    def __init__(self):
        self._logs = {}          # channel -> deque[str]
        self._order = deque()    # channel names, least-recent first
        self._closed = False

    # -- internals --------------------------------------------------------

    def _touch(self, channel: str) -> deque:
        existing = self._logs.get(channel)
        if existing is not None:
            try:
                self._order.remove(channel)
            except ValueError:
                pass
            self._order.append(channel)
            return existing

        while len(self._order) >= MAX_CHANNELS:
            oldest = self._order.popleft()
            self._logs.pop(oldest, None)

        ring = deque(maxlen=MAX_LINES_PER_CHANNEL)
        self._logs[channel] = ring
        self._order.append(channel)
        return ring

    # -- public -----------------------------------------------------------

    def append(self, channel: str, message: str) -> None:
        if self._closed:
            return
        try:
            self._touch(channel).append(_strip_ansi(message))
        except Exception:
            pass

    def read_recent(self, channel: str, n: int = 500) -> list:
        if self._closed:
            return []
        ring = self._logs.get(channel)
        if not ring:
            return []
        if n >= len(ring):
            return list(ring)
        return list(ring)[-n:]

    def close(self) -> None:
        """Drop everything.  Idempotent."""
        self._closed = True
        self._logs.clear()
        self._order.clear()

    #: Kept as an alias because callers say `wipe()` when they mean "destroy
    #: it now" and `close()` when they mean "we are finishing".  With no
    #: files involved the two are the same operation.
    wipe = close

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
