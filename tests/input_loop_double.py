# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Run the XMPP client's plain input loop (`_input_loop`) against scripted
reads, recording which reader took each line and where it went.

Shared by tests/test_auth_retry.py and tests/test_secret_never_echoes.py,
which used to read the loop's source for "getpass" (Phase 5)."""
import asyncio


class LoopClient:
    def __init__(self, password_prompt=None, secret_request=None):
        self._password_prompt = password_prompt
        self._secret_request = secret_request
        self.peer = "bob@example.i2p"
        self.passwords, self.dispatched = [], []
        self.disconnected = False

    def supply_password(self, line):
        self.passwords.append(line)
        self._password_prompt = None

    def dispatch_line(self, peer, line):
        self.dispatched.append(line)
        return True

    def disconnect(self):
        self.disconnected = True


def run(xmpp, monkeypatch, client, reads):
    """`reads`: a list of (reader, line, hook). reader is "getpass" or
    "readline"; a read by the other reader fails the test. hook, if given,
    runs while that read is blocked (to raise a prompt mid-read)."""
    script = list(reads)
    seen = []

    def _next(kind, prompt=None):
        assert script, "the loop read again after the script ended"
        want, line, hook = script.pop(0)
        seen.append((kind, prompt))
        assert kind == want, "expected a %s read, got %s (%r)" % (want, kind, prompt)
        if hook:
            hook(client)
        return line

    monkeypatch.setattr(xmpp.getpass, "getpass", lambda prompt="": _next("getpass", prompt))
    monkeypatch.setattr(xmpp.sys.stdin, "readline", lambda: _next("readline"), raising=False)
    asyncio.run(asyncio.wait_for(xmpp._input_loop(client), 5))
    return seen
