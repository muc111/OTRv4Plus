# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Diagnostic report fixes from a two-phone call test (2026-11-04).

  * the `inputs` line stopped at `password_present: [REDACTED]` -- the line
    redactor runs to the end of the line, and inputs was one dict on one line;
  * `rust_core_version` read `-` with the core loaded: the core exported none;
  * `capability_checked` was logged 3-5 times per burst of presences;
  * `closing_confirmed` was logged twice for one close.
"""
import asyncio
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from android_bridge import report                        # noqa: E402
from android_bridge.trace import TRACE                   # noqa: E402


def _events(component, event):
    return [e for e in TRACE.events()
            if e["component"] == component and e["event"] == event]


def test_inputs_after_the_password_are_not_swallowed():
    status = {"connected": True, "jid": "alice@example.i2p",
              "inputs": {"jid_localpart_present": True,
                         "password_present": True,
                         "server_present": True,
                         "use_default_server": False}}
    text = report.build(status=status, device={}, environment={}, trace=TRACE)
    assert "input.server_present" in text and "input.use_default_server" in text, (
        "inputs after password_present were redacted with it:\n" + text)
    pw = [l for l in text.splitlines() if "password_present" in l]
    assert pw and "[REDACTED]" in pw[0], "the password field must still be withheld"


def test_the_core_reports_its_version():
    from android_bridge import diagnostics
    import otrv4_core
    info = diagnostics._rust_core_info()
    assert info["loaded"] and info.get("version") not in (None, "", "-")
    expected = getattr(otrv4_core, "__version__", None)
    if expected:
        assert info["version"] == expected
    else:                        # a core built before the export: said so
        assert info["version"].startswith("unknown")
    src = open(os.path.join(ROOT, "Rust", "src", "lib.rs"), encoding="utf-8").read()
    assert 'm.add("__version__", env!("CARGO_PKG_VERSION"))' in src


def test_capability_is_logged_once_per_answer_not_per_presence():
    from android_bridge.transport import XmppTransport
    t = XmppTransport.__new__(XmppTransport)

    class Caps:
        answer = "available"

        def disco_result(self, jid, features):
            pass

        def disco_failed(self, jid):
            pass

        def state(self, bare):
            return self.answer

    class Disco:
        async def get_info(self, jid, timeout):
            return {"disco_info": {"features": []}}

    t._caps = Caps()
    t._client = {"xep_0030": Disco()}
    t._on_capability = None
    TRACE.clear()
    for resource in ("a", "b", "c", "d"):
        asyncio.run(t._query_caps("bob@example.i2p/" + resource))
    assert len(_events("otr", "capability_checked")) == 1
    t._caps.answer = "unavailable"                 # a change is still logged
    asyncio.run(t._query_caps("bob@example.i2p/e"))
    assert len(_events("otr", "capability_checked")) == 2
    TRACE.clear()


def test_one_close_is_confirmed_once_even_with_two_callers():
    from android_bridge.app_deniable import DeniableMixin

    gate = threading.Event()

    class Transport:
        def confirm_received(self):
            gate.wait(2)                 # both callers inside the round trip
            return True

    class App(DeniableMixin):
        def __init__(self):
            self._transport = Transport()
            self._closing_lock = threading.Lock()

        def _marks_done(self, peer):
            pass

    app = App()
    app._closings().extend([("bob", 1, True), ("bob", 2, True)])
    TRACE.clear()
    callers = [threading.Thread(target=app.confirm_closings) for _ in range(2)]
    for c in callers:
        c.start()
    gate.set()
    for c in callers:
        c.join(2)
    confirmed = _events("otr", "closing_confirmed")
    assert len(confirmed) == 1, confirmed
    assert confirmed[0]["fields"]["messages"] == "2"
    TRACE.clear()
