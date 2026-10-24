# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A terminal client started from client/ can import android_bridge.

`python otrv4plus_xmpp.py` runs with only client/ on its import path. The
modules that reuse the bridge (secure groups, group calls, the sealed
identity, metadata scrubbing) failed to import there, and secure groups
quietly turned off; Rust/build.sh's own check failed the desktop installer
(found 2026-10-24). This starts a clean interpreter exactly that way.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "client")

MODULES = ("otrv4plus_groups", "otrv4plus_groupcall", "otrv4plus_identity",
           "otrv4plus_xmpp_files", "otrv4plus_stresstest")


def test_the_modules_that_use_the_bridge_import_from_client_alone():
    code = ("import sys; sys.path.insert(0, %r)\n" % CLIENT
            + "".join("import %s\n" % m for m in MODULES)
            + "import android_bridge.groups, android_bridge.identity\n"
            + "print('ok')")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run([sys.executable, "-I", "-c", code], cwd="/",
                          env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0 and "ok" in done.stdout, done.stderr[-2000:]


def test_every_client_module_that_imports_the_bridge_asks_for_the_path_first():
    import ast
    for name in sorted(os.listdir(CLIENT)):
        if not name.endswith(".py") or name == "otrv4plus_repo.py":
            continue
        path = os.path.join(CLIENT, name)
        if os.path.islink(path):
            continue
        tree = ast.parse(open(path, encoding="utf-8").read())
        uses = any(isinstance(n, (ast.Import, ast.ImportFrom))
                   and any((getattr(n, "module", "") or a.name or "").startswith("android_bridge")
                           for a in n.names)
                   for n in ast.walk(tree))
        if uses:
            assert any(isinstance(n, ast.Import) and n.names[0].name == "otrv4plus_repo"
                       for n in tree.body), name
