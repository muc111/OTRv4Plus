# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Save to device (owner, 2026-10-24: files stayed inside the app, where
Wipe & Exit destroys them).

The copy goes through Android's own save dialog (Storage Access Framework):
no storage permission, write access to the one new document only. It is
asked for first, with what it means; the copy runs off the main thread; a
failed copy removes the half-written document. The copy and naming logic is
plain Kotlin with its own unit test (FileExportTest); this checks the wiring.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
VIEWER = open(os.path.join(PKG, "ui", "FileViewer.kt"), encoding="utf-8").read()
EXPORT = open(os.path.join(PKG, "crypto", "FileExport.kt"), encoding="utf-8").read()
MANIFEST = open(os.path.join(ROOT, "android", "app", "src", "main", "AndroidManifest.xml"),
                encoding="utf-8").read()


def test_it_uses_the_system_save_dialog_and_no_storage_permission():
    assert "ActivityResultContracts.CreateDocument(FileExport.MIME)" in VIEWER
    assert "WRITE_EXTERNAL_STORAGE" not in MANIFEST
    assert "MANAGE_EXTERNAL_STORAGE" not in MANIFEST


def test_it_asks_first_and_says_wipe_and_exit_will_not_reach_the_copy():
    ask = VIEWER[VIEWER.index("if (confirmSave)"):VIEWER.index("if (confirmHandoff)")]
    assert "FileExport.warning(name)" in ask
    assert "saver.launch(FileExport.safeName(name))" in ask
    assert "Wipe & Exit does not delete it" in EXPORT
    button = VIEWER[VIEWER.index("onClick = { confirmSave = true }") - 200:]
    assert "saver.launch" not in button[:400], "the button only opens the question"


def test_the_copy_runs_off_the_main_thread_and_cleans_up_a_failure():
    assert "withContext(Dispatchers.IO) { saveTo(context, uri, source) }" in VIEWER
    save = VIEWER[VIEWER.index("private fun saveTo("):]
    save = save[:save.index("\n}\n")]
    assert "DocumentsContract.deleteDocument" in save
    assert "FileExport.copy(" in save


def test_one_name_sanitiser_for_save_and_handoff():
    assert VIEWER.count("FileExport.safeName(name)") >= 2
    assert 'Regex("[^A-Za-z0-9._ -]")' not in VIEWER
