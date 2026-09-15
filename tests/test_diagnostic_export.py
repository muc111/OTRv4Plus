# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The shareable error log: what it captures, and what it must never carry.

WHY IT EXISTS
-------------
The expensive handset bugs were not crashes. A connection said DISCONNECTING
with no stated reason; contacts read "presence unknown"; Add Contact appeared
inert. Each had an exact cause a few layers down and none of it reached the
screen, so diagnosing them meant ADB, logcat and a developer.

This log is what a non-developer sends back instead. Its value is the SEQUENCE:
`controller connected -> failed` preceded by `keepalive probe_unanswered
failures=2` is a diagnosis in one read.

THE SAFETY PROPERTY
-------------------
The file leaves the device and goes wherever the user sends it. So the tests
below are not decoration -- they are the reason the feature can ship at all.
Two independent mechanisms, and both are tested:

  1. `trace` redacts field values by KEY NAME as they are recorded;
  2. `report._scrub` sweeps the FINISHED document again, line by line.

Belt and braces on purpose: either alone would be a single point of failure
for a file the user is about to attach to a bug tracker.
"""

import re

import pytest

from android_bridge import report
from android_bridge.diagnostics import SENSITIVE_KEY_HINTS
from android_bridge.trace import (BANNED_KEYS, DEFAULT_CAPACITY, REDACTED,
                                  TraceLog)

PASSWORD = "correct horse battery staple"
JID = "bob@xmpp-elite.i2p"


@pytest.fixture
def log():
    return TraceLog(capacity=50)


# ── the ring ────────────────────────────────────────────────────────────────

class TestItRecordsWhatHappened:

    def test_an_event_is_kept(self, log):
        log.record("transport", "session_started", jid=JID)
        assert len(log.events()) == 1

    def test_the_fields_survive(self, log):
        log.record("transport", "session_started", jid=JID, server="x.i2p")
        fields = log.events()[0]["fields"]
        assert fields["jid"] == JID
        assert fields["server"] == "x.i2p"

    def test_order_is_oldest_first(self, log):
        for i in range(5):
            log.record("c", "e%d" % i)
        assert [e["event"] for e in log.events()] == \
            ["e0", "e1", "e2", "e3", "e4"]

    def test_a_transition_carries_both_sides(self, log):
        log.transition("controller", "connected", "failed", reason="keepalive")
        fields = log.events()[0]["fields"]
        assert fields["state_before"] == "connected"
        assert fields["state_after"] == "failed"
        assert log.events()[0]["event"] == "state_change"

    def test_severity_is_recorded(self, log):
        log.record("keepalive", "probe_unanswered", "warning")
        assert log.events()[0]["severity"] == "warning"


class TestItIsBounded:
    """A log that grows until the process dies is not a diagnostic."""

    def test_the_default_holds_several_thousand(self):
        assert DEFAULT_CAPACITY >= 2000

    def test_the_oldest_go_first(self):
        log = TraceLog(capacity=3)
        for i in range(6):
            log.record("c", "e%d" % i)
        assert [e["event"] for e in log.events()] == ["e3", "e4", "e5"]

    def test_the_gap_is_counted(self):
        log = TraceLog(capacity=3)
        for i in range(6):
            log.record("c", "e%d" % i)
        assert log.dropped() == 3

    def test_the_gap_is_reported_in_the_render(self):
        log = TraceLog(capacity=2)
        for i in range(5):
            log.record("c", "e%d" % i)
        assert "dropped" in log.render()

    def test_a_limit_keeps_the_newest(self, log):
        for i in range(10):
            log.record("c", "e%d" % i)
        assert [e["event"] for e in log.events(3)] == ["e7", "e8", "e9"]


class TestItNeverBreaksWhatItWatches:
    """Called from the connect path, the keepalive and the inbound handler."""

    def test_an_unprintable_value_does_not_raise(self, log):
        class Hostile:
            def __str__(self):
                raise RuntimeError("no")

        log.record("c", "e", thing=Hostile())
        assert "unprintable" in log.events()[0]["fields"]["thing"]

    def test_recording_never_raises(self, log):
        log.record("c", "e", **{"weird key": object()})
        assert log.events()


# ── exceptions, described rather than printed ───────────────────────────────

class TestExceptions:

    def test_the_type_is_recorded(self, log):
        try:
            raise OSError("stream gone")
        except OSError as exc:
            log.record_exception("transport", "probe_failed", exc)
        assert log.events()[0]["fields"]["exception_type"] == "OSError"

    def test_a_stack_trace_is_recorded(self, log):
        try:
            raise ValueError("x")
        except ValueError as exc:
            log.record_exception("c", "e", exc)
        trace = log.events()[0]["fields"]["stack_trace"]
        assert " in " in trace, "no frames, so the location is lost"
        assert "test_diagnostic_export.py" in trace

    def test_the_severity_is_error(self, log):
        try:
            raise ValueError("x")
        except ValueError as exc:
            log.record_exception("c", "e", exc)
        assert log.events()[0]["severity"] == "error"

    def test_context_fields_survive_alongside_it(self, log):
        try:
            raise ValueError("x")
        except ValueError as exc:
            log.record_exception("roster", "add_contact", exc, jid=JID)
        assert log.events()[0]["fields"]["jid"] == JID

    def test_a_third_party_message_is_not_printed_verbatim(self, log):
        """`failure.describe` chooses the detail by TYPE. Our own messages are
        written in this repository; a third party's may quote a path or an
        argument."""
        try:
            raise OSError("/data/user/0/org.otrv4plus/files/secret-thing")
        except OSError as exc:
            log.record_exception("c", "e", exc)
        rendered = log.render()
        assert "/data/user/0" not in rendered


# ── the safety property ─────────────────────────────────────────────────────

class TestSecretsCannotBeRecorded:

    @pytest.mark.parametrize("key", [
        "password", "passphrase", "secret", "device_seed", "private_key",
        "session_key", "chain_key", "root_key", "mac_key", "credential",
        "token", "api_token", "cookie", "ratchet_state",
    ])
    def test_a_sensitive_key_is_redacted(self, log, key):
        log.record("c", "e", **{key: PASSWORD})
        assert log.events()[0]["fields"][key] == REDACTED
        assert PASSWORD not in log.render()

    def test_redaction_is_a_marker_not_a_deletion(self, log):
        """A field that vanished tells the reader nothing. One that says
        REDACTED tells them the code was asked and refused."""
        log.record("c", "e", password=PASSWORD)
        assert "password" in log.render()
        assert REDACTED in log.render()

    def test_case_does_not_matter(self, log):
        log.record("c", "e", PassWord=PASSWORD, DEVICE_SEED="x")
        assert PASSWORD not in log.render()
        assert "x" not in log.render().split("DEVICE_SEED=")[1][:20]

    def test_every_hint_is_honoured(self, log):
        for hint in SENSITIVE_KEY_HINTS:
            log.record("c", "e", **{"a_%s_field" % hint: PASSWORD})
        assert PASSWORD not in log.render()


class TestMessageContentCannotBeRecorded:
    """The peer who wrote the message did not agree to it being shared."""

    @pytest.mark.parametrize("key", sorted(BANNED_KEYS))
    def test_a_content_key_is_redacted(self, log, key):
        log.record("c", "e", **{key: "are you free tonight"})
        assert log.events()[0]["fields"][key] == REDACTED
        assert "tonight" not in log.render()

    def test_the_banned_set_covers_the_obvious_names(self):
        for name in ("body", "message", "text", "plaintext", "content"):
            assert name in BANNED_KEYS


# ── the export ──────────────────────────────────────────────────────────────

STATUS = {
    "stage": "failed", "connected": False, "jid": JID,
    "server": "xmpp-elite.i2p", "sam": "127.0.0.1:7656",
    "worker_alive": True,
    "last": {"code": "auth_failed", "detail": "The server rejected the "
                                             "password.", "stage": "authenticating"},
}
DEVICE = {"model": "Pixel 7", "release": "14", "sdk_int": 34,
          "app_version": "10.13.2"}


@pytest.fixture
def exported(log):
    log.transition("controller", "connecting", "connected")
    log.record("transport", "session_started", jid=JID)
    log.record("keepalive", "probe_unanswered", "warning",
               failures=2, threshold=2)
    try:
        raise OSError("boom")
    except OSError as exc:
        log.record_exception("keepalive", "stream_declared_dead", exc)
    return report.build(status=STATUS, device=DEVICE, trace=log)


class TestTheReportIsUseful:

    def test_it_has_a_header_and_a_timestamp(self, exported):
        assert report.HEADER in exported
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", exported)

    def test_the_device_is_named(self, exported):
        assert "Pixel 7" in exported and "10.13.2" in exported

    def test_the_connection_state_is_there(self, exported):
        assert "failed" in exported
        assert "auth_failed" in exported

    def test_the_failure_detail_is_there(self, exported):
        assert "The server rejected the password." in exported

    def test_the_events_are_there_in_order(self, exported):
        assert exported.index("state_change") < \
            exported.index("probe_unanswered")

    def test_state_transitions_carry_both_sides(self, exported):
        assert "state_before=connecting" in exported
        assert "state_after=connected" in exported

    def test_an_exception_and_its_trace_are_there(self, exported):
        assert "exception_type=OSError" in exported
        assert "stack_trace=" in exported
        assert "test_diagnostic_export.py" in exported

    def test_the_run_up_to_the_failure_is_visible(self, exported):
        """The point of the whole feature."""
        assert exported.index("session_started") < \
            exported.index("stream_declared_dead")

    def test_the_jid_and_server_are_included_deliberately(self, exported):
        """A roster, presence or routing fault cannot be diagnosed without
        them. The header says so, so nobody is surprised."""
        assert JID in exported
        assert "xmpp-elite.i2p" in exported

    def test_the_header_says_what_is_and_is_not_in_it(self, exported):
        head = exported[:exported.index("Device")]
        assert "NO" in head
        assert "passwords" in head
        assert "message contents" in head


class TestTheExportCannotCarrySecrets:
    """§18. These are the tests that let the feature ship."""

    def test_a_password_recorded_by_mistake_does_not_reach_the_file(self, log):
        log.record("connect", "attempt", password=PASSWORD)
        assert PASSWORD not in report.build(status={}, trace=log)

    def test_a_password_in_the_STATUS_does_not_reach_the_file(self, log):
        """The second mechanism, on its own. `_scrub` sweeps the finished
        document whatever produced the line."""
        text = report.build(
            status={"stage": "x", "inputs": "jid=%s password=%s"
                                            % (JID, PASSWORD)},
            trace=log)
        assert PASSWORD not in text
        assert REDACTED in text

    def test_an_aligned_column_is_swept_too(self, log):
        """`_kv` aligns with spaces and no separator, which the assignment
        pattern cannot see. A second pattern covers it."""
        text = report.build(status={}, device={"session_key": PASSWORD},
                            trace=log)
        assert PASSWORD not in text

    def test_a_message_body_does_not_reach_the_file(self, log):
        log.record("transport", "inbound", body="are you free tonight")
        assert "tonight" not in report.build(status={}, trace=log)

    def test_the_scrub_leaves_useful_state_alone(self, log):
        """Over-redaction is its own failure: a report that hides
        `authenticating` and `auth_failed` cannot diagnose a login problem."""
        log.record("controller", "state_change",
                   state_before="connecting", state_after="authenticating")
        text = report.build(
            status={"stage": "authenticating",
                    "last": {"code": "auth_failed", "detail": "no"}},
            trace=log)
        assert "authenticating" in text
        assert "auth_failed" in text

    def test_building_with_nothing_at_all_still_produces_a_file(self):
        text = report.build()
        assert report.HEADER in text
        assert text.endswith("\n")

    def test_a_trace_that_explodes_does_not_lose_the_report(self):
        class Broken:
            def render(self, limit=0):
                raise RuntimeError("no")

        text = report.build(status=STATUS, trace=Broken())
        assert report.HEADER in text
        assert "could not be rendered" in text


class TestTheClipboardSummary:

    def test_it_names_the_stage(self, log):
        assert "failed" in report.summary(status=STATUS, trace=log)

    def test_it_names_the_device(self, log):
        assert "Pixel 7" in report.summary(status=STATUS, device=DEVICE,
                                           trace=log)

    def test_it_carries_the_last_error(self, log):
        assert "auth_failed" in report.summary(status=STATUS, trace=log)

    def test_it_is_short(self, log):
        for i in range(500):
            log.record("c", "e%d" % i)
        assert len(report.summary(status=STATUS, trace=log).splitlines()) < 40

    def test_it_is_scrubbed_too(self, log):
        text = report.summary(
            status={"stage": "x", "inputs": "password=%s" % PASSWORD},
            trace=log)
        assert PASSWORD not in text
