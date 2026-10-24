# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A call that cannot go out says why, on the screen.

Owner, 2026-10-24: "pressed call button when it was green and nothing
happened". The bridge answered "started" (the request was taken), the voice
manager then refused or failed in the background, and the bridge's
`call_not_placed` event was a code the app did not show. Now the manager
records why (`last_refusal`), the bridge reports `call_<reason>`, and
CallUi.failure (CallUiTest) has a sentence for each.
"""
import asyncio
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from android_bridge import voice as bridge_voice  # noqa: E402

V = __import__("otrv4plus_voice")


class _App:
    def __init__(self):
        self.events = []

    def _emit(self, event):
        self.events.append(event)


class _Manager:
    def __init__(self, reason):
        self.last_refusal = ""
        self._reason = reason

    async def start_call(self, peer):
        self.last_refusal = self._reason
        return False


def _run(reason):
    app = _App()
    calls = bridge_voice.CallBridge(app)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    calls._loop = loop
    try:
        manager = _Manager(reason)
        calls._submit(manager.start_call("bob@x.i2p"), "bob@x.i2p",
                      "call_not_placed", refused_by=manager)
        for _ in range(200):
            if app.events:
                break
            threading.Event().wait(0.01)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(2)
    return [e.code for e in app.events]


def test_the_managers_reason_becomes_the_code():
    assert _run("tunnel") == ["call_tunnel"]
    assert _run("rate_limited") == ["call_rate_limited"]


def test_an_unknown_or_missing_reason_keeps_the_generic_code():
    assert _run("") == ["call_not_placed"]
    assert _run("something new") == ["call_not_placed"]


def test_every_refusal_the_manager_records_is_one_the_bridge_knows():
    import re
    src = open(V.__file__, encoding="utf-8").read()
    recorded = set(re.findall(r'self\.last_refusal = "([a-z_]+)"', src))
    assert recorded, "start_call no longer records why it refused"
    assert recorded <= bridge_voice.CALL_REFUSALS


def test_the_app_has_a_sentence_for_each():
    path = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                        "otrv4plus", "android", "crypto", "CallUi.kt")
    kt = open(path, encoding="utf-8").read()
    for reason in bridge_voice.CALL_REFUSALS:
        assert '"call_%s" ->' % reason in kt, reason


def test_frame_crypto_zeroize_never_raises_even_if_the_core_does():
    """A stray `setattr(self, name, None)` sat in the except branch: a Rust
    zeroize that raised turned into a NameError from a method documented as
    "never raises", in the call teardown path."""
    class _Boom:
        def zeroize(self):
            raise RuntimeError("core says no")
    fc = V.VoiceFrameCrypto.__new__(V.VoiceFrameCrypto)
    fc._rust = _Boom()
    fc.zeroize()
    assert fc._zeroized
