# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Getting the error log off a handset without a developer.

The behaviour -- what the log records, and what it refuses to -- is
`tests/test_diagnostic_export.py`, which executes. What is here is the platform
half no Python test can reach: that the file leaves through the Android
Sharesheet behind a FileProvider grant, that Kotlin renders nothing itself, and
that the Android-side lifecycle lands in the SAME timeline as Python's events.

The required workflow, in full:

    Diagnostics -> Share error log -> Android Sharesheet -> pick an app

No ADB, no root, no Termux, no logcat, no terminal.
"""

import io
import os
import re
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "android", "app", "src", "main")
JAVA = os.path.join(MAIN, "java", "org", "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return text


@pytest.fixture(scope="module")
def exporter():
    return _read(JAVA, "ui", "DiagnosticsExport.kt")


@pytest.fixture(scope="module")
def screen():
    return _read(JAVA, "ui", "DevShellScreen.kt")


@pytest.fixture(scope="module")
def core():
    return _read(JAVA, "bridge", "ChaquopyOtrCore.kt")


@pytest.fixture(scope="module")
def service():
    return _read(JAVA, "connection", "OtrConnectionService.kt")


# ── the share itself ────────────────────────────────────────────────────────

class TestItGoesThroughTheSharesheet:

    def test_a_chooser_is_started(self, exporter):
        assert "Intent.createChooser" in exporter, (
            "no Sharesheet, so the file cannot reach an app of the user's "
            "choosing without a developer")

    def test_the_action_is_send(self, exporter):
        assert "Intent.ACTION_SEND" in exporter

    def test_it_is_plain_text_so_every_app_offers_itself(self, exporter):
        assert 'type = "text/plain"' in exporter

    def test_the_file_is_a_txt(self, exporter):
        assert '.txt"' in exporter, (
            "the person receiving it has to be able to open it without being "
            "told how")


class TestNoRawPathLeavesTheApp:

    def test_it_is_a_file_provider_uri(self, exporter):
        assert "FileProvider.getUriForFile" in exporter, (
            "a raw filesystem path was handed to another app")

    def test_the_grant_is_read_only_and_one_shot(self, exporter):
        assert "FLAG_GRANT_READ_URI_PERMISSION" in exporter
        assert "FLAG_GRANT_WRITE_URI_PERMISSION" not in exporter

    def test_it_writes_to_the_cache_and_not_to_shared_storage(self, exporter):
        assert "context.cacheDir" in exporter
        for elsewhere in ("getExternalStorage", "getExternalFilesDir",
                          "Environment.DIRECTORY"):
            assert elsewhere not in exporter, (
                "%s puts a report where other apps can read it" % elsewhere)

    def test_the_provider_is_declared_and_not_exported(self):
        manifest = _read(MAIN, "AndroidManifest.xml")
        block = manifest[manifest.index("androidx.core.content.FileProvider"):]
        block = block[:block.index("</provider>")]
        assert 'android:exported="false"' in block
        assert 'android:grantUriPermissions="true"' in block

    def test_the_provider_path_is_narrow(self):
        """A FileProvider path is a capability, so it should be the narrowest
        one that does the job."""
        root = ET.parse(os.path.join(MAIN, "res", "xml",
                                     "file_paths.xml")).getroot()
        paths = list(root)
        assert len(paths) == 1
        assert paths[0].tag == "cache-path"
        assert paths[0].get("path") == "diagnostics/"

    def test_the_authority_matches_the_manifest(self, exporter):
        manifest = _read(MAIN, "AndroidManifest.xml")
        assert '${applicationId}.diagnostics' in manifest
        assert '"${context.packageName}.$DIRECTORY"' in exporter
        assert 'DIRECTORY = "diagnostics"' in exporter

    def test_the_app_asks_for_no_storage_permission(self):
        manifest = _read(MAIN, "AndroidManifest.xml")
        for permission in ("WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
                           "MANAGE_EXTERNAL_STORAGE"):
            assert permission not in manifest


# ── Kotlin renders nothing ──────────────────────────────────────────────────

class TestTheContentIsDecidedInOnePlace:
    """A second renderer is a second place to forget the redaction rule."""

    def test_the_exporter_only_writes_what_it_is_given(self, exporter):
        code = _code_only(exporter)
        for building in ("appendLine", "buildString", "StringBuilder"):
            assert building not in code, (
                "DiagnosticsExport is composing report text, which makes it a "
                "second place that decides what a diagnostic may contain")

    def test_the_report_is_rendered_in_python(self, core):
        assert 'callAttr("diagnostic_report"' in core

    def test_the_summary_is_rendered_in_python(self, core):
        assert 'callAttr("diagnostic_summary"' in core

    def test_the_screen_shares_what_python_returned(self, screen):
        code = _code_only(screen)
        assert "core?.diagnosticReport()" in code

    def test_no_python_exception_text_reaches_the_report(self, core):
        """A PyException carries the engine's own message."""
        block = core[core.index("fun diagnosticReport()"):]
        block = block[:block.index("\n    /** A short version")]
        assert "javaClass.simpleName" in block
        assert re.search(r"it\.message\b", _code_only(block)) is None


# ── the buttons ─────────────────────────────────────────────────────────────

class TestTheButtonsExist:

    def test_there_is_a_share_error_log_button(self, screen):
        assert "Share error log" in screen

    def test_there_is_a_copy_error_details_button(self, screen):
        assert "Copy error details" in screen

    def test_the_copy_button_uses_the_short_summary(self, screen):
        code = _code_only(screen)
        assert "core?.diagnosticSummary()" in code, (
            "Copy puts the whole log on the clipboard, which is not what a "
            "short summary is for")

    def test_a_failed_share_says_so_and_offers_the_alternative(self, screen):
        assert "Share failed" in screen
        assert "use Copy instead" in screen

    def test_the_start_up_report_is_still_exportable(self, screen):
        """A working run is evidence too, and FLAG_SECURE blocks a
        screenshot -- so if it cannot be exported it cannot leave at all."""
        assert "Export start-up report" in screen

    def test_the_error_log_is_distinguished_from_the_start_up_snapshot(
            self, screen):
        """They answer different questions. The snapshot is taken at launch
        and contains nothing about a fault that happened afterwards."""
        assert "Error log" in screen
        assert "Start-up report" in screen
        assert screen.index("Error log") < screen.index("Start-up report"), (
            "the snapshot is offered first, so that is the one people send")


class TestExportingDoesNotDisturbTheConnection:

    def test_the_exporter_never_touches_the_service(self, exporter):
        code = _code_only(exporter)
        for forbidden in ("OtrConnectionService", "stopService", "disconnect",
                          "stopSelf"):
            assert forbidden not in code

    def test_the_screen_does_not_build_a_second_core(self, screen):
        code = _code_only(screen)
        assert "ChaquopyOtrCore(" not in code, (
            "a second interpreter and a second engine over the same identity "
            "and trust files, opened from the screen that exists to report on "
            "the health of the first")

    def test_old_reports_are_pruned_rather_than_accumulating(self, exporter):
        assert "prune" in exporter


# ── the Android half of the timeline ────────────────────────────────────────

class TestTheServiceRecordsItsOwnLifecycle:
    """One log and one ordering. Two would have to be merged by eye, and by
    then the moment that mattered is lost."""

    def test_the_bridge_offers_a_way_to_record(self, core):
        assert "fun note(component: String, event: String" in core

    def test_recording_never_throws(self, core):
        block = core[core.index("fun note(component: String"):]
        block = block[:block.index("\n    /**")]
        assert "runCatching" in block, (
            "a diagnostic that can crash the thing it is diagnosing is worse "
            "than no diagnostic")

    @pytest.mark.parametrize("event", [
        "phase_change", "stop_requested", "logout_requested", "destroyed",
        "stop_connection",
    ])
    def test_the_service_records_it(self, service, event):
        assert '"%s"' % event in service

    def test_every_phase_change_goes_through_one_place(self, service):
        """So none can be made without being recorded."""
        code = _code_only(service)
        body = code[code.index("private fun enter(next: LinkPhase"):]
        # Anchored on CODE, not on a comment: `_code_only` strips comments,
        # so a docstring anchor is a substring that is not there.
        body = body[:body.index("var status: ConnectionStatus")]
        assert "phase = next" in body
        # No other assignment to `phase` anywhere else in the class.
        others = re.findall(r"^\s+phase = (?!next)", code, re.M)
        assert not others, (
            "a phase is set outside enter(), so that transition is invisible "
            "in the export: %r" % others)

    def test_the_three_routes_to_disconnecting_are_distinguishable(self,
                                                                   service):
        """The whole reason an unexplained DISCONNECTING was hard: a user
        action, a logout and Android reclaiming the service look identical
        afterwards unless each says so at the time."""
        for marker in ("stop_requested", "logout_requested", "destroyed"):
            assert marker in service

    def test_the_reason_travels_with_the_transition(self, service):
        code = _code_only(service)
        assert 'enter(LinkPhase.CONNECTED, "the transport reported connected")' \
            in code
        assert "$previous -> $next ($why)" in code


class TestTheDeviceFactsAreSuppliedByKotlin:
    """Python is told them rather than guessing."""

    @pytest.mark.parametrize("key", [
        "model", "release", "sdk_int", "app_version", "build_id",
    ])
    def test_it_is_included(self, core, key):
        assert '"%s"' % key in core

    def test_the_build_is_named_because_it_is_the_first_question(self, core):
        assert "BuildConfig.VERSION_NAME" in core
        assert "BuildConfig.BUILD_ID" in core
