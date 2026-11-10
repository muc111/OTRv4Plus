# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A call's progress reaches the diagnostic report (owner, 2026-10-20: the
laptop's terminal showed the call ring, be answered and stall at
"establishing media", and the phone's report showed nothing).

`otrv4plus_voice` reports only by printing; on the phone that is logcat.
Each line now also becomes a trace event: a stage code, and for a failure
the reason, with identities replaced by labels. Never the line itself."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from android_bridge.trace import TRACE                               # noqa: E402
from android_bridge.voice import call_stage, traced_call_print       # noqa: E402

JID = "alice@otrv4plus.i2p"


def _calls():
    return [e for e in TRACE.events() if e["component"] == "call"]


def test_a_call_leaves_its_stages_in_the_report_and_no_names():
    TRACE.clear()
    printed = []
    say = traced_call_print(lambda *a, **k: printed.append(a))
    for line in ("[voice] building I2P tunnels for the call — this takes 30-120 s",
                 "[voice] calling %s — waiting for an answer" % JID,
                 "[voice] %s answered — keys confirmed, establishing media…" % JID,
                 "[voice] could not create SAM session: refused by 127.0.0.1:7659",
                 "[voice] • call ended — 6s, mouth-to-ear not measured (call too short)",
                 "[voice] %s ended the call" % JID):
        say(line)
    assert len(printed) == 6, "the terminal stopped printing"
    codes = [e["event"] for e in _calls()]
    assert codes == ["tunnels_building", "ringing_out", "keys_confirmed",
                     "sam_session_failed", "ended", "peer_ended"]
    report = TRACE.render()
    assert "alice" not in report and "otrv4plus.i2p" not in report
    assert "127.0.0.1" not in report
    failed = [e for e in _calls() if e["event"] == "sam_session_failed"][0]
    assert failed["severity"] == "error" and "refused" in failed["fields"]["reason"]
    # The hang-up summary keeps its figures (duration, delay, delivery):
    # recorded as a bare "ended", a report could not say how good a call was.
    ended = [e for e in _calls() if e["event"] == "ended"][0]
    assert "6s" in ended["fields"]["reason"]
    assert "reason" not in [e for e in _calls()
                            if e["event"] == "peer_ended"][0]["fields"], (
        "the line that names the peer must not keep its text")


def test_the_quality_summary_reaches_the_report_without_colour():
    TRACE.clear()
    say = traced_call_print(lambda *a, **k: None)
    say("[voice] \U0001f7e2 call ended \u2014 good \u2014 1m54s, mouth-to-ear "
        "~\x1b[32m640ms\x1b[0m, 1826 received, 1810 played, 16 concealed, "
        "1900 frames sent")
    say("[voice]   420ms network (one-way) + 180ms jitter buffer + 40ms playout")
    by = {e["event"]: e["fields"].get("reason", "") for e in _calls()}
    assert "16 concealed" in by["ended"] and "\x1b" not in by["ended"]
    assert "420ms network" in by["call_latency_budget"]


def test_lines_that_are_not_calls_are_not_recorded():
    TRACE.clear()
    traced_call_print(lambda *a: None)("[file] something else")
    assert _calls() == []
    assert call_stage("hello") is None


def test_wrapping_twice_is_once():
    w = traced_call_print(print)
    assert w._otrv4plus_traced
    src = open(os.path.join(ROOT, "android_bridge", "voice.py"), encoding="utf-8").read()
    assert 'getattr(current, "_otrv4plus_traced", False)' in src
