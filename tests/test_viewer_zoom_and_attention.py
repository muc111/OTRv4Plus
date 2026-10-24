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


def test_the_metadata_has_its_own_scrolling_panel():
    viewer = _read("FileViewer.kt")
    block = viewer[viewer.index("metadataLine?.let {"):][:700]
    assert "verticalScroll(details)" in block and "heightIn(max" in block
    assert "verticalScrollbar(details)" in block, "the panel must show that it scrolls"


def test_a_chat_that_needs_the_user_pulses_and_says_so():
    screen = _read("ConversationsScreen.kt")
    assert "attention = needs[conversation.jid]" in screen
    assert "AttentionYellow.copy(alpha = pulse)" in screen
    assert re.search(r'Text\("⚑ \$\{it\.text\}"', screen), "colour must not be the only signal"


def test_the_chats_tab_pulses_while_any_chat_needs_the_user():
    bar = _read("MainNavBar.kt")
    assert "attentionAlpha(model.attentionByChat().isNotEmpty())" in bar
