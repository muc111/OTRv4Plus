# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every failure code is registered, logged when it happens, and reported.

`android_bridge/codes.py` is the one list of codes. A code the bridge can
produce but the list does not name fails here, so a new failure arrives with
its meaning written down; every ErrorOccurred and BridgeError lands in the
debug log as it is created; the diagnostic report opens with a tally.
"""
import ast
import glob
import os

from android_bridge import codes, report
from android_bridge.app_base import BridgeError
from android_bridge.events import ErrorOccurred
from android_bridge.trace import TRACE

from test_failures_reach_the_screen import emitted_codes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _call_name(node):
    return getattr(node.func, "id", getattr(node.func, "attr", ""))


def _literal_codes():
    """Codes written as literals anywhere they reach ErrorOccurred or
    BridgeError, including through a helper that takes the code as an
    argument (`_refuse_room(peer, "room_not_verifiable")`)."""
    found = set()
    for path in glob.glob(os.path.join(ROOT, "android_bridge", "*.py")):
        tree = ast.parse(open(path, encoding="utf-8").read())
        helpers = set()
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and any(a.arg == "code" for a in fn.args.args):
                helpers.add(fn.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name == "BridgeError" and node.args and isinstance(node.args[0], ast.Constant):
                found.add(node.args[0].value)
            if name in helpers or name in {"_refuse_room", "_require_encrypted",
                                           "_send_protocol_or_raise"}:
                found |= {a.value for a in node.args[1:] if isinstance(a, ast.Constant)
                          and isinstance(a.value, str) and a.value.islower()
                          and "_" in a.value and " " not in a.value}
        # Functions that answer a code (`_smp_start_refusal`).
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name.endswith("_refusal"):
                found |= {r.value.value for r in ast.walk(fn) if isinstance(r, ast.Return)
                          and isinstance(r.value, ast.Constant)}
    return found


def test_the_scan_is_not_vacuous():
    found = _literal_codes() | emitted_codes()
    assert {"room_not_verifiable", "smp_cooldown", "smp_send_failed", "wiped",
            "call_tunnel", "group_send_failed"} <= found, found


def test_every_code_the_bridge_produces_is_registered():
    missing = sorted((_literal_codes() | emitted_codes()) - set(codes.CODES))
    assert not missing, (
        "add these to android_bridge/codes.py with their component and "
        "meaning: %s" % missing)


def test_capability_refusals_are_registered():
    """`BridgeError("otrv4plus_" + capability)` for every state but available."""
    import otrv4plus_caps
    for state in otrv4plus_caps.STATES:
        if state != otrv4plus_caps.AVAILABLE:
            assert "otrv4plus_" + state in codes.CODES, state


def test_every_entry_has_a_component_and_a_meaning():
    for code, (component, meaning) in codes.CODES.items():
        assert component and meaning and code == code.strip().lower(), code


def test_an_error_event_is_in_the_debug_log_with_its_meaning():
    codes.reset()
    TRACE.clear()
    ErrorOccurred(peer="bob@example.i2p", code="call_tunnel")
    rows = [e for e in TRACE.events() if e["event"] == "failed"]
    assert rows and rows[-1]["component"] == "call"
    assert rows[-1]["fields"]["code"] == "call_tunnel"
    assert "tunnel" in rows[-1]["fields"]["meaning"]
    assert "bob@example.i2p" not in TRACE.render(0), "the peer must be a label"


def test_a_raised_bridge_error_is_logged_once_with_its_event():
    codes.reset()
    TRACE.clear()
    ErrorOccurred(peer="bob@example.i2p", code="smp_send_failed")
    BridgeError("smp_send_failed")
    assert codes.tally()[0][:2] == ("smp_send_failed", 1)
    BridgeError("wiped")
    assert dict((c, n) for c, n, _, _ in codes.tally()) == {"smp_send_failed": 1, "wiped": 1}


def test_an_unregistered_code_is_still_logged():
    codes.reset()
    TRACE.clear()
    BridgeError("something_new")
    rows = [e for e in TRACE.events() if e["event"] == "failed"]
    assert rows[-1]["fields"]["code"] == "something_new"
    assert rows[-1]["fields"]["meaning"] == "unregistered code"


def test_the_report_opens_with_the_tally():
    codes.reset()
    for _ in range(3):
        BridgeError("call_tunnel")
        codes._last = ("", 0.0)      # three separate failures, not one
    text = report.build(status={})
    assert "Failures seen" in text
    assert text.index("Failures seen") < text.index("Events (oldest first)")
    assert "call_tunnel" in text and "x3" in text
    assert "call_tunnel x3" in report.summary(status={})
    codes.reset()
    assert "none since the app started" in report.build(status={})
