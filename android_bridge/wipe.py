# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Destroying what the Python side left on disk, for Wipe & Exit.

WHAT IS HERE, ON ANDROID
------------------------
Measured by constructing the engine exactly as `ChaquopyOtrCore` does
(`EnhancedSessionManager(OTRConfig())`) under an empty HOME: the only file it
writes is `~/.otrv4plus/keys/.device_seed`. Identity and trust are in memory
(`persist_identity` / `persist_trust` default False). Received files land in
`otrv4plus_filetransfer.state_dir()` -- `~/.otrv4plus/files` unless
`OTRV4PLUS_FILE_DIR` says otherwise -- and partial transfers in its
`.incoming` subdirectory. Everything the Python side persists is therefore
under `~/.otrv4plus` or the file directory, and that is what is destroyed.

Chaquopy's own runtime also lives under the app's files directory. It is not
touched: this module walks only the two roots above, and refuses any path that
resolves outside them (a symlink planted in the tree cannot turn the wipe into
deletion of something else).

WHAT "DESTROYED" MEANS, AND WHAT IT DOES NOT
--------------------------------------------
Each file is overwritten once with AES-256-GCM ciphertext under a fresh,
immediately discarded key, fsync'd, and unlinked -- the terminal client's
`_secure_file_destroy`, reused rather than restated. On flash storage that
overwrite is BEST EFFORT: wear levelling and the flash translation layer may
write the new bytes elsewhere and leave the old block to be erased later, and
nothing an app can do guarantees otherwise. What bounds the exposure on
Android is that these files live in app-private storage under file-based
encryption. This module does not, and must not be read to, promise physical
erasure of NAND. The Kotlin vault is different -- its records are sealed under
an AndroidKeyStore key that Wipe & Exit deletes, which IS cryptographic
erasure -- and ANDROID_WIPE_AND_EXIT.md records the distinction.
"""

import os
import shutil
import sys
from typing import Callable, List, Tuple

__all__ = ["python_state_roots", "destroy_tree", "wipe_disk"]


def _file_dir() -> str:
    """Where `otrv4plus_filetransfer.state_dir()` puts received files.

    Computed the same way rather than by calling it: `state_dir()` CREATES
    the directory, and a wipe must not.
    """
    base = os.environ.get("OTRV4PLUS_FILE_DIR")
    if base:
        return base
    return os.path.join(os.path.expanduser("~"), ".otrv4plus", "files")


def python_state_roots() -> List[str]:
    """Every directory the Python side persists into. Existence not required."""
    roots = [os.path.join(os.path.expanduser("~"), ".otrv4plus")]
    files = _file_dir()
    real_files = os.path.realpath(files)
    if not any(real_files == os.path.realpath(r)
               or real_files.startswith(os.path.realpath(r) + os.sep)
               for r in roots):
        roots.append(files)
    return roots


def _destroyer() -> Callable[[str], None]:
    """The engine's `_secure_file_destroy`, or plain unlink if it is absent."""
    for name in ("otrv4_", "otrv4plus"):
        engine = sys.modules.get(name)
        fn = getattr(engine, "_secure_file_destroy", None) if engine else None
        if fn is not None:
            return fn
    return os.remove


def destroy_tree(root: str) -> Tuple[int, int]:
    """Destroy every regular file under [root], then remove the tree.

    Returns `(destroyed, failed)`. Never raises. Files that resolve outside
    [root] -- through a symlink -- are skipped, not followed. A file the
    overwrite could not handle is still unlinked and counted as failed, so the
    count says honestly how many had only the weaker treatment.
    """
    destroyed = failed = 0
    if not root or not os.path.isdir(root):
        return 0, 0
    base = os.path.realpath(root)
    destroy = _destroyer()
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path):
                    os.unlink(path)          # the link, never its target
                    continue
                real = os.path.realpath(path)
                if real != base and not real.startswith(base + os.sep):
                    continue
                if not os.path.isfile(path):
                    continue
            except OSError:
                continue
            try:
                destroy(path)
                destroyed += 1
            except Exception:
                failed += 1
                try:
                    os.remove(path)
                except OSError:
                    pass
    shutil.rmtree(root, ignore_errors=True)
    return destroyed, failed


def wipe_disk() -> dict:
    """Destroy every Python-side state root. For a process whose engine was
    never started -- `OtrApp.wipe` does this itself when it was."""
    destroyed = failed = 0
    for root in python_state_roots():
        d, f = destroy_tree(root)
        destroyed += d
        failed += f
    return {"files_destroyed": destroyed, "files_unlinked_only": failed,
            "errors": []}
