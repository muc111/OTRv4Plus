# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Received PDFs are parsed only in an isolated process.

A PDF is parsed by native code (fonts, images, compressed streams), and a
memory bug there is reached by whoever sent the file: CVE-2026-86950, a font
rasteriser overflow in Apple's CoreGraphics, was exploited through PDFs sent
over messengers. OTRv4+ has no Apple build, but Android's PdfRenderer is the
same kind of parser, so it runs in `PdfRenderService`, declared
`isolatedProcess` -- no permissions, no app files, no network -- and hands
back raw pixels. These checks keep it there; PdfScanTest (JVM) covers the
structure scan.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JAVA = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def test_the_renderer_is_declared_isolated_and_private():
    manifest = _read(ROOT, "android", "app", "src", "main", "AndroidManifest.xml")
    block = re.search(r'<service\s+android:name="\.ui\.PdfRenderService"[^>]*/>', manifest)
    assert block, "PdfRenderService is not declared"
    assert 'android:isolatedProcess="true"' in block.group(0)
    assert 'android:exported="false"' in block.group(0)
    assert "<intent-filter" not in block.group(0)


def test_only_the_isolated_service_touches_pdf_renderer():
    users = []
    for base, _, files in os.walk(JAVA):
        for name in files:
            src = _read(base, name) if name.endswith(".kt") else ""
            if "android.graphics.pdf" in src or re.search(r"\bPdfRenderer\(", src):
                users.append(name)
    assert users == ["PdfRenderService.kt"], (
        "PdfRenderer used outside the isolated process: %s" % users)


def test_python_never_starts_in_the_isolated_process():
    src = _read(JAVA, "OtrApplication.kt")
    on_create = src[src.index("override fun onCreate()"):]
    assert on_create.index("if (isolatedProcess()) return") < on_create.index("Python.start(")


def test_what_comes_back_is_bounded_raw_pixels():
    client = _read(JAVA, "ui", "IsolatedPdf.kt")
    assert "w !in 1..maxSide || h !in 1..maxSide" in client
    assert "readFully(pixels)" in client and "copyPixelsFromBuffer" in client
    assert "BitmapFactory" not in client, "the app must not decode an image the renderer made"


def test_the_viewer_uses_the_isolated_renderer_and_the_scan():
    viewer = _read(JAVA, "ui", "FileViewer.kt")
    assert "IsolatedPdf(" in viewer
    assert "PdfScan.handoffNote(pdfFindings)" in viewer
    assert "PdfScan.summary(pdfFindings)" in viewer
