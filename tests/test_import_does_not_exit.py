"""Importing a module must never end the process.

`otrv4plus_xmpp.py` used to call `sys.exit(1)` at module level when the OTR
engine or slixmpp could not be imported. That is fine for the program -- it is
a program -- but the same file is imported by the test suite, the Android
bridge and the packaging tooling, and for them it was a trap:

`sys.exit` raises SystemExit, which inherits from BaseException rather than
Exception, precisely so that `except Exception` around a shutdown does not
swallow it. Nothing that handles import failures handles it. So importing the
module on a host without the Rust core did not fail -- it terminated the
interpreter doing the importing. Under pytest that was an INTERNALERROR during
collection, and the *entire* suite stopped: not the tests that needed the core,
all of them. `pytest.importorskip` could do nothing, because there was no
exception for it to catch.

Every scenario below runs in its own subprocess with a `sys.meta_path` hook
that makes a named dependency unimportable. That costs a process each, and buys
two things worth more: the tests are hermetic (no half-imported module left in
`sys.modules` for the next test to trip over), and they are *host-independent*
-- they simulate the absent dependency rather than requiring one, so they prove
the same thing on a Termux handset with the core built as on a bare CI runner
without it.
"""

import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

MODULE = "otrv4plus_xmpp"

#: Installs an import hook that makes the named top-level modules unimportable.
#: Every line sits at column zero and the scenario body is appended as-is, so
#: nothing here depends on splicing one indented block into another -- which is
#: how generated programs usually break.
BLOCKER = '''\
import sys
sys.path.insert(0, %(root)r)

class _Block:
    """Refuse to find the named modules, as if they were not installed."""
    names = set(%(blocked)r)

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in self.names:
            raise ModuleNotFoundError("blocked by test: " + name, name=name)
        return None

sys.meta_path.insert(0, _Block())
for _n in list(sys.modules):
    if _n.split(".")[0] in _Block.names:
        del sys.modules[_n]
'''

#: Report what `import otrv4plus_xmpp` raised, in a form the test can assert on
#: without the exception having to survive a process boundary.
REPORT = '''\
try:
    import otrv4plus_xmpp
except BaseException as exc:
    print("TYPE", type(exc).__name__)
    print("MRO", ",".join(k.__name__ for k in type(exc).__mro__))
    print("NAME", getattr(exc, "name", None))
    print("MSG", str(exc).replace(chr(10), " ")[:300])
else:
    print("TYPE none")
'''


def _run(body, blocked=("otrv4plus", "otrv4_core")):
    prog = BLOCKER % {"root": ROOT, "blocked": list(blocked)} + body
    return subprocess.run([sys.executable, "-c", prog],
                          capture_output=True, text=True, timeout=180)


def _report(blocked):
    r = _run(REPORT, blocked=blocked)
    assert r.returncode == 0, (
        "the reporting subprocess itself died (rc=%s): %s"
        % (r.returncode, r.stderr[-2000:]))
    out = {}
    for line in r.stdout.splitlines():
        key, _, value = line.partition(" ")
        out[key] = value
    return out


class TestImportingWithoutTheEngine:
    """The engine (otrv4plus -> otrv4+.py) and the Rust core beneath it."""

    def test_it_does_not_raise_system_exit(self):
        """The whole point. Everything else here elaborates on it."""
        got = _report(("otrv4plus", "otrv4_core"))
        assert got["TYPE"] != "none", (
            "the module imported cleanly with the engine blocked, which means "
            "the block did not work and this test proves nothing")
        assert "SystemExit" not in got["MRO"].split(","), (
            "importing %s still raises SystemExit (%s). An importer cannot "
            "catch that, and pytest collection dies on it."
            % (MODULE, got["TYPE"]))

    def test_it_raises_an_import_error(self):
        got = _report(("otrv4plus", "otrv4_core"))
        assert "ImportError" in got["MRO"].split(",")

    def test_it_is_a_module_not_found_error(self):
        """So `pytest.importorskip` skips, with no argument at the call site.

        Since pytest 9.1 importorskip skips on ModuleNotFoundError and nothing
        else -- a plain ImportError is taken to mean the module is present and
        broken, which is a defect rather than a reason to skip. A host that has
        simply not built the core is the ordinary case, so that is what this
        must be.
        """
        got = _report(("otrv4plus", "otrv4_core"))
        assert "ModuleNotFoundError" in got["MRO"].split(","), (
            "got %s; importorskip will not skip on that, so every test that "
            "needs the core becomes a collection error" % got["TYPE"])

    def test_it_names_the_module_that_was_missing(self):
        got = _report(("otrv4plus", "otrv4_core"))
        assert got["NAME"] in ("otrv4plus", "otrv4_core"), got

    def test_the_advice_survives_on_the_exception(self):
        """Not printed to stderr on import -- carried, for a caller to show."""
        got = _run('try:\n'
                   '    import otrv4plus_xmpp\n'
                   'except ImportError as exc:\n'
                   '    print("ADVICE", len(getattr(exc, "advice", ())))\n')
        assert "ADVICE" in got.stdout, got.stderr[-2000:]
        assert int(got.stdout.split("ADVICE")[1]) > 0, (
            "the guidance the program prints was dropped rather than attached")


class TestImportorskipActuallySkips:
    """The requirement, stated as pytest sees it.

    Everything above reasons about exception classes. This asks pytest, which
    is the only opinion that decides whether a run survives -- and it asks the
    installed pytest, so an upstream change to what importorskip skips on shows
    up here as a failure rather than as a mystery in CI.
    """

    def test_a_missing_core_produces_a_skip_not_an_error(self):
        r = _run(
            "import pytest\n"
            "try:\n"
            '    pytest.importorskip("otrv4plus_xmpp")\n'
            "except BaseException as exc:\n"
            '    print("RAISED", type(exc).__name__)\n'
            "else:\n"
            '    print("RAISED none")\n')
        assert r.returncode == 0, r.stderr[-2000:]
        assert "RAISED Skipped" in r.stdout, (
            "pytest.importorskip did not skip on a missing core -- it gave "
            "%r. Every test module that needs the core becomes a collection "
            "error instead of a skip." % (r.stdout.strip(),))

    def test_a_broken_core_does_not_produce_a_skip(self):
        """The other half. A defect must not be quietly skipped past."""
        prog = (
            "import sys, types, pytest\n"
            "sys.path.insert(0, %r)\n" % ROOT +
            'broken = types.ModuleType("otrv4plus")\n'
            "def _boom(name):\n"
            '    raise RuntimeError("the engine is installed and broken")\n'
            "broken.__getattr__ = _boom\n"
            'sys.modules["otrv4plus"] = broken\n'
            "try:\n"
            '    pytest.importorskip("otrv4plus_xmpp")\n'
            "except BaseException as exc:\n"
            '    print("RAISED", type(exc).__name__)\n'
            "else:\n"
            '    print("RAISED none")\n')
        r = subprocess.run([sys.executable, "-c", prog],
                           capture_output=True, text=True, timeout=180)
        assert r.returncode == 0, r.stderr[-2000:]
        assert "RAISED Skipped" not in r.stdout, (
            "a broken engine was skipped past rather than reported")
        assert "RAISED DependencyUnavailable" in r.stdout, r.stdout


def _engine_is_importable():
    """Whether `import otrv4plus` works at all on this host.

    The slixmpp guard sits below the engine guard in the module, so on a host
    where the engine cannot be imported it is simply never reached and there is
    nothing to assert about it. Rather than pretend otherwise, those tests skip
    -- and say which of the two guards they could not get to.
    """
    r = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r); import otrv4plus" % ROOT],
        capture_output=True, text=True, timeout=180)
    return r.returncode == 0


@pytest.mark.skipif(
    not _engine_is_importable(),
    reason="the engine guard fires first here, so the slixmpp guard is "
           "unreachable (needs Python 3.12+ and the Rust core)")
class TestImportingWithoutSlixmpp:
    """The second import-time exit, which had the same defect."""

    def test_it_does_not_raise_system_exit(self):
        got = _report(("slixmpp",))
        assert got["TYPE"] != "none", "slixmpp block did not take effect"
        assert "SystemExit" not in got["MRO"].split(",")

    def test_it_is_a_module_not_found_error(self):
        got = _report(("slixmpp",))
        assert "ModuleNotFoundError" in got["MRO"].split(",")

    def test_it_names_slixmpp(self):
        got = _report(("slixmpp",))
        assert got["NAME"] == "slixmpp", got


class TestABrokenDependencyIsNotTreatedAsAnAbsentOne:
    """Absence skips. Breakage must not.

    If a core that is installed and raising were reported as merely missing,
    every test that would have caught the breakage would skip, and the suite
    would go green on a machine whose core does not work. That is the one
    outcome this whole change must not produce.
    """

    def test_a_dependency_that_raises_is_not_a_module_not_found_error(self):
        # A fake `otrv4plus` that imports fine but blows up on attribute
        # access, standing in for a core that is present and broken.
        prog = (
            "import sys, types\n"
            "sys.path.insert(0, %r)\n" % ROOT +
            'broken = types.ModuleType("otrv4plus")\n'
            "def _boom(name):\n"
            '    raise RuntimeError("the engine is installed and broken")\n'
            "broken.__getattr__ = _boom\n"
            'sys.modules["otrv4plus"] = broken\n'
            + REPORT)
        r = subprocess.run([sys.executable, "-c", prog],
                           capture_output=True, text=True, timeout=180)
        assert r.returncode == 0, r.stderr[-2000:]
        mro = [l for l in r.stdout.splitlines() if l.startswith("MRO")]
        assert mro, r.stdout + r.stderr[-2000:]
        names = mro[0].split(" ", 1)[1].split(",")
        assert "ImportError" in names, names
        assert "ModuleNotFoundError" not in names, (
            "a broken engine is being reported as an absent one, so pytest "
            "will skip the tests that exist to catch exactly this: %s" % names)
        assert "SystemExit" not in names, names


#: Files allowed a module-level exit, and why. An entry here is a claim that
#: the file is never imported by anything -- add one only with that in mind.
EXIT_ALLOWED = {
    # A WeeChat plugin. `import weechat` resolves only inside WeeChat's
    # embedded interpreter, so the exit is the script saying "you are not
    # WeeChat" to a person who ran it by hand. Nothing imports this file --
    # it has no library surface to import -- so it cannot take a test run or a
    # CI job down with it, and raising instead would only make WeeChat's own
    # error reporting worse.
    "weechat_otrv4plus.py",
}


def _module_level_exits(path):
    """Calls that end the process, reachable by importing *path*.

    Bodies of `if __name__ == "__main__":` are skipped: that is the one place a
    module-level exit is correct, because an importer never runs it.
    """
    import ast

    with open(path, encoding="utf-8", errors="replace") as fh:
        tree = ast.parse(fh.read(), filename=path)

    def is_main_guard(node):
        if not isinstance(node, ast.If):
            return False
        t = node.test
        return (isinstance(t, ast.Compare)
                and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and len(t.comparators) == 1
                and isinstance(t.comparators[0], ast.Constant)
                and t.comparators[0].value == "__main__")

    found = []

    def walk(node, in_scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                continue          # bodies run when called, not when imported
            if is_main_guard(child):
                for orelse in child.orelse:   # `else:` still runs on import
                    walk(orelse, in_scope)
                continue
            if isinstance(child, ast.Call):
                name = ast.unparse(child.func)
                if name in ("sys.exit", "exit", "quit", "os._exit",
                            "os.abort"):
                    found.append((name, child.lineno))
            if isinstance(child, ast.Raise) and child.exc is not None:
                exc = child.exc
                target = exc.func if isinstance(exc, ast.Call) else exc
                if isinstance(target, ast.Name) and target.id == "SystemExit":
                    found.append(("raise SystemExit", child.lineno))
            walk(child, in_scope)

    walk(tree, True)
    return found


class TestNoOtherModuleEndsTheProcessOnImport:
    """The same defect, looked for everywhere rather than only where it bit.

    One `sys.exit` at module level is enough to take down a whole pytest run,
    so finding them by waiting for a collection error is not a plan. This is
    the plan.
    """

    @staticmethod
    def _project_files():
        import glob
        paths = []
        for pattern in ("*.py", "android_bridge/*.py", "tests/*.py"):
            for p in glob.glob(os.path.join(ROOT, pattern)):
                # otrv4_.py and otrv4plus.py are symlinks to otrv4+.py; reading
                # the same file three times would report every finding thrice.
                if os.path.islink(p):
                    continue
                paths.append(p)
        return sorted(paths)

    def test_there_are_files_to_check(self):
        """A scanner that silently matched nothing would pass forever."""
        assert len(self._project_files()) > 20

    def test_no_module_level_exit_outside_the_allow_list(self):
        offenders = {}
        unparseable = []
        for path in self._project_files():
            rel = os.path.relpath(path, ROOT)
            try:
                hits = _module_level_exits(path)
            except SyntaxError as e:
                # otrv4+.py uses PEP 701 f-strings and needs 3.12 to parse.
                # Recorded rather than ignored, and asserted on below.
                unparseable.append((rel, str(e)))
                continue
            if hits and rel not in EXIT_ALLOWED:
                offenders[rel] = hits
        assert not offenders, (
            "module-level process exits found. Importing one of these ends "
            "the interpreter that imported it, which under pytest is a "
            "collection INTERNALERROR that stops the entire suite. Raise an "
            "ImportError subclass instead -- see DependencyUnavailable and "
            "_fatal_dependency in otrv4plus_xmpp.py: %r" % (offenders,))
        if unparseable and sys.version_info >= (3, 12):
            pytest.fail(
                "a file could not be parsed on an interpreter new enough to "
                "parse it, so it went unchecked: %r" % (unparseable,))

    def test_the_allow_list_has_not_gone_stale(self):
        """An allowed file that no longer exits does not need allowing."""
        for rel in sorted(EXIT_ALLOWED):
            path = os.path.join(ROOT, rel)
            if not os.path.exists(path):
                pytest.fail("%s is allow-listed but does not exist" % rel)
            assert _module_level_exits(path), (
                "%s no longer has a module-level exit; drop it from "
                "EXIT_ALLOWED rather than leaving a permission nobody uses"
                % rel)


class TestRunningItAsAProgramIsUnchanged:
    """The behaviour a person at a terminal sees must not have moved."""

    def test_it_still_exits_one(self):
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, MODULE + ".py")],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "no-such-dir")},
            cwd=os.path.join(ROOT, "tests"))
        if r.returncode == 0:
            pytest.skip("the engine imported, so there is no failure to check")
        assert r.returncode == 1, (
            "a missing dependency must still be exit status 1, got %s: %s"
            % (r.returncode, r.stderr[-2000:]))

    def test_it_still_prints_the_advice_to_stderr(self):
        r = subprocess.run(
            [sys.executable, os.path.join(ROOT, MODULE + ".py")],
            capture_output=True, text=True, timeout=180,
            cwd=os.path.join(ROOT, "tests"))
        if r.returncode == 0:
            pytest.skip("the engine imported, so there is no failure to check")
        assert r.stderr.strip(), "the program failed silently"
        assert "otrv4" in r.stderr.lower() or "slixmpp" in r.stderr.lower(), (
            "the message no longer says what was missing: %r" % r.stderr[:500])
