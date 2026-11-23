# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Making untrusted text safe to print on a terminal.

Everything a peer or a server controls -- nicks, JIDs, topics, reasons, and
decrypted message bodies -- passes through `sanitise` before it is printed.
An encrypted message is no exception: encryption says who sent it, not that
what they sent is harmless to a terminal.

What a hostile sender could otherwise do, and what is removed:

* **Escape sequences** (OSC, DCS, PM, APC, CSI and two-byte Fe): retitle the
  window, move the cursor, recolour or clear the screen, or (on some
  terminals) write to the clipboard.
* **Line breaks** (CR, LF, and the Unicode line and paragraph separators):
  a CR returns to the start of the line and overwrites what was printed
  there, sender included; an LF starts a new line that looks like the
  client's own output (`[otr] SMP verified`). Both become a space, so the
  message stays on its own line and its words stay apart.
* **mIRC colour codes** (`\\x03` with its digits) and every other C0 or C1
  control character, except the tab.

This was two copies, one in otrv4+.py for the IRC client and one in
otrv4plus_term.py for the XMPP client, and they had drifted: the IRC copy
let CR and LF through, so a peer could forge a status line in the IRC
client. There is one now.
"""
import re

_STRING_SEQUENCE = re.compile(r"\x1b[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)")
_CSI_SEQUENCE = re.compile(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]")
_NF_ESCAPE = re.compile(r"\x1b[\x20-\x2f][\x30-\x7e]")
_ANY_ESCAPE = re.compile(r"\x1b.", re.DOTALL)
_MIRC_COLOUR = re.compile(r"\x03(?:\d{1,2}(?:,\d{1,2})?)?")
_LINE_BREAK = re.compile("\r\n|[\r\n\x0b\x0c\x85  ]")
_CONTROL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f\x80-\x9f]")


def sanitise(text, max_len: int = 512) -> str:
    """`text` with every escape sequence and control character removed and
    line breaks turned into spaces, cut to `max_len` characters."""
    text = str(text)
    text = _STRING_SEQUENCE.sub("", text)
    text = _CSI_SEQUENCE.sub("", text)
    text = _NF_ESCAPE.sub("", text)
    text = _ANY_ESCAPE.sub("", text)
    text = _MIRC_COLOUR.sub("", text)
    text = _LINE_BREAK.sub(" ", text)
    text = _CONTROL.sub("", text)
    return text[:max_len]
