# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The file viewer zooms and keeps its metadata reachable; a chat that needs
the user pulses yellow and says why.

Owner, 2026-10-24: "add a scroll bar to the viewer as I can't see the
metadata below and we need to add a zoom in and out", and "when we get a
notification for a chat such as verification request it could flash yellow
tint in the chat tab". The rules are executed by ZoomTest and AttentionTest
(JVM); these hold the wiring, which only CI can compile.
"""
import os
import re

UI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "android", "app", "src", "main", "java", "org", "otrv4plus", "android", "ui")


def _read(name):
    with open(os.path.join(UI, name), encoding="utf-8") as f:
        return f.read()


def test_pictures_and_pdf_pages_are_zoomable():
    viewer = _read("FileViewer.kt")
    assert viewer.count("ZoomableImage(") >= 3, "image and PDF bodies must both zoom"
    body = viewer[viewer.index("private fun ZoomableImage("):]
    for needed in ("detectTransformGestures", "onDoubleTap", "Zoom.zoomIn(", "Zoom.zoomOut(",
                   "Zoom.clampPan("):
        assert needed in body, needed


def test_the_viewer_has_file_metadata_and_hidden_content_tabs():
    """Owner (2026-10-24): three tabs, and metadata never cut off."""
    viewer = _read("FileViewer.kt")
    tabs = _read("FileViewerTabs.kt")
    assert 'FILE("File"), METADATA("Metadata"), HIDDEN("Hidden content")' in tabs
    assert "TabRow(selectedTabIndex = tab.ordinal)" in viewer
    assert "tab == ViewerTab.METADATA -> MetadataTab(facts, metadataLine)" in viewer
    assert "tab == ViewerTab.HIDDEN -> HiddenContentTab(facts, kind, pdfFindings)" in viewer


def test_the_metadata_tab_scrolls_the_whole_list_and_says_so():
    tabs = _read("FileViewerTabs.kt")
    body = tabs[tabs.index("internal fun MetadataTab("):tabs.index("internal fun HiddenContentTab(")]
    assert "Modifier.fillMaxSize().verticalScrollbar(scroll).verticalScroll(scroll)" in body
    assert "heightIn(max" not in body, "no cap: the tab is the whole space"
    assert "for (f in facts.facts)" in body


def test_facts_are_read_off_the_main_thread_and_within_a_memory_bound():
    viewer = _read("FileViewer.kt")
    assert "withContext(Dispatchers.IO) {\n                runCatching { readViewerFacts(" in viewer
    tabs = _read("FileViewerTabs.kt")
    read = tabs[tabs.index("internal fun readViewerFacts("):tabs.index("internal fun MetadataTab(")]
    assert "inJustDecodeBounds = true" in read, "dimensions without decoding the picture"
    assert "file.length() > HiddenData.MAX_SCAN_BYTES" in read
    assert read.index("file.length() > HiddenData.MAX_SCAN_BYTES") < read.index("file.readBytes()")
    assert "android.media.ExifInterface(path)" in read


def test_the_hidden_tab_says_what_it_does_not_check():
    tabs = _read("FileViewerTabs.kt")
    assert "Not checked yet: data hidden in the" in tabs
    assert "HiddenData.describe(report)" in tabs


def test_a_chat_that_needs_the_user_pulses_and_says_so():
    screen = _read("ConversationsScreen.kt")
    assert "attention = needs[conversation.jid]" in screen
    assert "AttentionYellow.copy(alpha = pulse)" in screen
    assert re.search(r'Text\("⚑ \$\{it\.text\}"', screen), "colour must not be the only signal"


def test_the_chats_tab_pulses_while_any_chat_needs_the_user():
    bar = _read("MainNavBar.kt")
    assert "attentionAlpha(model.attentionByChat().isNotEmpty())" in bar


def test_the_viewer_keeps_its_buttons_clear_of_the_system_bars():
    """Device report (Pixel 7 / Android 17): the buttons under pictures and
    PDFs were cut off. From Android 15 a full-screen dialog is drawn edge to
    edge, so the viewer takes the bars' space itself."""
    viewer = _read("FileViewer.kt")
    dialog = viewer[viewer.index("Dialog(onDismissRequest = onClose"):]
    dialog = dialog[:dialog.index("if (confirmHandoff)")]
    assert "decorFitsSystemWindows = false" in dialog
    assert dialog.index(".windowInsetsPadding(WindowInsets.safeDrawing)") < dialog.index(
        "Open with another app"), "the padding wraps the whole column, buttons included"
