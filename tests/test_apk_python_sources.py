"""What the APK packages must be what the client actually imports.

`syncPythonSources` in `android/app/build.gradle.kts` copies the orchestration
layer into the Chaquopy source set, and it is a hand-maintained list. It had
drifted by seven modules -- including `otrv4plus_coreapi` and
`otrv4plus_smpflow`, which `otrv4plus_xmpp.py` imports on its first two lines.

Every omission is an ImportError the moment the app starts, and nothing could
catch it: no APK has ever been built, so the list has never been executed. This
computes the import closure and compares, which is a check that runs on every
commit rather than one that waits for a device.

The exclusions matter as much as the inclusions. `smp_engine_compat.py`
re-implements the SMP KDF in pure Python for tests and must never reach a
handset; the TUI, the IRC client and the WeeChat plugin are simply not part of
the app.
"""

import ast
import os
import re

import pytest

GRADLE = "android/app/build.gradle.kts"
ENTRY_POINTS = ("otrv4plus_xmpp.py", "otrv4+.py")

#: Modules that must never be packaged, and why.
FORBIDDEN = {
    "smp_engine_compat.py": "re-implements the SMP KDF in pure Python",
    "otrv4plus_tui.py": "the terminal UI has no place in an APK",
    "weechat_otrv4plus.py": "a WeeChat plugin",
    "otrv4_testlib.py": "test-only helpers",
}

pytestmark = pytest.mark.skipif(
    not os.path.exists(GRADLE), reason="no android/ project in this checkout")


def import_closure():
    """Every otrv4plus_* module reachable from the two entry points."""
    seen, queue = set(), list(ENTRY_POINTS)
    while queue:
        path = queue.pop()
        if path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        for node in ast.walk(ast.parse(open(path).read())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            else:
                continue
            for mod in names:
                if mod.startswith("otrv4plus_"):
                    queue.append(mod + ".py")
    return {p for p in seen if p.startswith("otrv4plus_")}


def _task_source():
    """The syncPythonSources task, with // comments removed.

    Comments are stripped FIRST. The include list carries a worked example of
    how to re-derive it, and that example contains parentheses -- an earlier
    version of this helper looked for the closing paren before stripping and
    ended the block inside the comment, finding two filenames out of twelve.
    """
    src = open(GRADLE).read()
    task = src[src.index("val syncPythonSources"):]
    return re.sub(r"//[^\n]*", "", task)


def _quoted_py(task, call):
    block = task[task.index(call):]
    block = block[:block.index(")")]
    return set(re.findall(r'"([^"]+\.py)"', block))


def synced_files():
    """The `include(...)` list inside the syncPythonSources task."""
    return _quoted_py(_task_source(), "include(")


def excluded_files():
    return _quoted_py(_task_source(), "exclude(")


class TestTheAppShipsWhatItImports:

    def test_every_imported_module_is_packaged(self):
        missing = sorted(import_closure() - synced_files())
        assert missing == [], (
            "these are imported at module scope but never copied into the "
            "APK, so the app would ImportError at launch: %s" % missing)

    def test_the_entry_points_themselves_are_packaged(self):
        synced = synced_files()
        for entry in ENTRY_POINTS:
            assert entry in synced, "%s is the app; it must ship" % entry

    def test_nothing_packaged_is_missing_from_the_repository(self):
        for name in sorted(synced_files()):
            assert os.path.exists(name), (
                "%s is in the copy list but not in the repository" % name)


class TestWhatMustNotShip:

    def test_the_test_only_smp_shim_is_excluded(self):
        # It re-implements the SMP KDF in pure Python. On a device that would
        # be a second cryptographic implementation of the thing the Rust core
        # exists to own.
        assert "smp_engine_compat.py" in excluded_files()

    def test_the_forbidden_modules_are_not_in_the_copy_list(self):
        synced = synced_files()
        for name, why in FORBIDDEN.items():
            assert name not in synced, "%s must not ship: %s" % (name, why)

    def test_the_irc_client_is_not_dragged_in(self):
        # otrv4+.py IS the engine and does ship; the IRC front end lives in the
        # same file, which is why the exclusions are by filename rather than by
        # walking imports. If that ever changes this test should be revisited.
        assert "otrv4plus_tui.py" not in synced_files()


class TestTheListIsHonest:

    def test_it_is_not_simply_everything(self):
        """A copy list of every .py in the repo would pass the first test.

        It would also package the test suite and the IRC TUI. The point is
        that the list is the closure, not the directory.
        """
        repo_modules = {f for f in os.listdir(".")
                        if f.startswith("otrv4plus_") and f.endswith(".py")}
        packaged = synced_files() - set(ENTRY_POINTS)
        assert packaged < repo_modules, (
            "the copy list has stopped being a closure and become a glob")

    def test_a_new_module_would_be_caught(self):
        """The regression this file exists for, stated directly.

        v10.30.0 added otrv4plus_admin.py, imported by otrv4plus_xmpp.py at
        module scope. It was not in the copy list, and no existing test
        noticed.
        """
        assert "otrv4plus_admin.py" in import_closure()
        assert "otrv4plus_admin.py" in synced_files()
