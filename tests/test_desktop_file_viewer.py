# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop app views received files the way the Android app does.

Owner (2026-10-24): "image view and file view aren't working on desktop ...
metadata, hidden content tabs etc must all be same as android app". The
desktop had no viewer at all: a finished transfer was simply hidden. Now a
received line has Open, and the viewer has the same three tabs, the same
facts and checks (shared from the Android tree, not copied) and the same
words. These pin that parity; the logic itself runs in the JVM tests
(ExifReaderTest, FileFactsTest, HiddenDataTest, PdfScanTest).
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
DESKTOP = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


ANDROID_TABS = _read(ANDROID, "ui", "FileViewerTabs.kt")
ANDROID_VIEWER = _read(ANDROID, "ui", "FileViewer.kt")
VIEWER = _read(DESKTOP, "ui", "FileViewer.kt")
PANE = _read(DESKTOP, "ui", "ConversationPane.kt")
MODEL = _read(DESKTOP, "AppModel.kt")
CORE = _read(DESKTOP, "engine", "DesktopCore.kt")
GRADLE = _read(ROOT, "desktop", "build.gradle.kts")


def _strings(text):
    return set(re.findall(r'"((?:\\.|[^"\\\n]){12,})"', text))


class TestTheSameChecksAreShared:
    @pytest.mark.parametrize("name", ["ExifReader", "FileExport", "FileFacts",
                                      "HiddenData", "PdfScan", "SafeView", "MetadataChoice"])
    def test_the_desktop_compiles_the_android_file(self, name):
        assert '"org/otrv4plus/android/crypto/%s.kt",' % name in GRADLE

    def test_shared_files_import_nothing_from_android(self):
        for name in ("ExifReader", "FileExport", "FileFacts", "HiddenData", "PdfScan"):
            text = _read(ANDROID, "crypto", name + ".kt")
            assert not re.search(r"^import (android|androidx)\.", text, re.M), name


class TestTheSameTabsAndWords:
    def test_the_three_tabs_are_named_as_on_android(self):
        line = 'FILE("File"), METADATA("Metadata"), HIDDEN("Hidden content")'
        assert line in ANDROID_TABS and line in VIEWER
        assert "TabRow(selectedTabIndex = tab.ordinal)" in VIEWER
        assert "tab == ViewerTab.METADATA -> MetadataTab(facts, metadataLine)" in VIEWER
        assert "tab == ViewerTab.HIDDEN -> HiddenContentTab(facts, kind, pdfFindings)" in VIEWER

    def test_every_tab_sentence_on_android_is_on_desktop(self):
        start = ANDROID_TABS.index("internal fun MetadataTab(")
        missing = _strings(ANDROID_TABS[start:]) - _strings(VIEWER)
        assert not missing, sorted(missing)

    def test_the_header_and_save_warning_match(self):
        assert '"Received and hash-verified · shown inside this app"' in ANDROID_VIEWER
        assert '"Received and hash-verified · shown inside this app"' in VIEWER
        assert "title = { Text(FileExport.TITLE) }" in VIEWER
        assert "text = { Text(FileExport.warning(name)) }" in VIEWER
        assert "saveNote = FileExport.result(bytes)" in VIEWER


class TestTheFactsAreTheSameFacts:
    def test_metadata_comes_from_the_shared_readers(self):
        read = VIEWER[VIEWER.index("internal fun readViewerFacts("):VIEWER.index("internal fun MetadataTab(")]
        for needed in ("ExifReader.read(bytes)", "FileFacts.exif { tag -> exif[tag] }",
                       "FileFacts.position(exif.latLong)", "HiddenData.scan(bytes)",
                       "FileFacts.basic(name, kind.label, file, width, height)",
                       "FileFacts.pdf(pdfFindings)"):
            assert needed in read, needed

    def test_a_big_picture_is_not_read_whole(self):
        read = VIEWER[VIEWER.index("internal fun readViewerFacts("):VIEWER.index("internal fun MetadataTab(")]
        assert "file.length() <= HiddenData.MAX_SCAN_BYTES" in read
        assert "readNBytes(1 shl 20)" in read
        assert "HiddenData.Status.NOT_CHECKED" in read

    def test_the_pdf_scan_and_stripped_metadata_line_are_shown(self):
        assert "PdfScan.scan(File(plain))" in VIEWER
        assert "MetadataChoice.receivedSummary(" in VIEWER


class TestOpeningAndClosing:
    def test_a_received_line_has_open(self):
        assert "if (model.canOpenLine(m)) {" in PANE
        # The received-file line is a SYSTEM line: its branch returns early,
        # so Open must be inside it (device report, 2026-10-25).
        system = PANE[PANE.index("if (m.security == SecurityLabel.SYSTEM) {"):]
        system = system[:system.index("        return\n")]
        assert "model.canOpenLine(m)" in system and "model.openLine(m)" in system
        assert "model.openLine(m)" in PANE
        assert "FileViewerDialog(container = file.path" in PANE

    def test_only_a_file_in_the_received_directory_opens(self):
        assert "SafeView.openable(m.filePath, dir)" in MODEL
        assert "SafeView.openable(container, dir)" in MODEL
        assert '"open_received_to", "path" to container, "directory" to directory' in CORE

    def test_the_transient_copy_is_removed(self):
        assert "onDispose { viewDir.listFiles()?.forEach { it.delete() } }" in VIEWER
        wipe = MODEL[MODEL.index("fun wipeAndExit("):]
        wipe = wipe[:wipe.index("\n    }\n")]
        assert wipe.index("viewDirectory().deleteRecursively()") < wipe.index("core.wipe(")

    def test_nothing_is_run_or_handed_to_another_program(self):
        assert "Desktop.getDesktop" not in VIEWER
        assert "ProcessBuilder" not in VIEWER and "Runtime.getRuntime" not in VIEWER

    def test_a_failed_save_leaves_no_partial_file(self):
        save = MODEL[MODEL.index("fun saveViewedTo("):]
        save = save[:save.index("\n    }\n")]
        assert 'core.saveReceived(container, destination) != "ok"' in save
        assert "File(destination).delete()" in save


def test_the_host_allows_the_viewer_op():
    import importlib
    import sys
    sys.path.insert(0, ROOT)
    host = importlib.import_module("desktop_bridge.host")
    assert host.APP_OPS["open_received_to"] == ("path", "directory")
