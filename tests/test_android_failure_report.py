"""A startup failure must be diagnosable, and must still leak nothing.

Written the day the first APK ran on a handset and reported, in full:

    Failure    PyException

Two properties are in tension here and both are load-bearing. The report has
to be specific enough to fix the fault from a phone screen, and it has to stay
safe on a path where -- unlike this one, today -- a secret might one day be in
flight. Every test below pins one side or the other.
"""

import sys

import pytest

sys.path.insert(0, ".")
from android_bridge import failure                       # noqa: E402


def _raised(exc_type, *args):
    """A real exception with a real traceback, raised from this file."""
    try:
        raise exc_type(*args)
    except BaseException as e:                           # noqa: BLE001
        return e


class TestItSaysSomethingUseful:

    def test_our_own_message_survives_intact(self):
        """bootstrap.py's messages are safe because we wrote them."""
        class RuntimeUnsupported(RuntimeError):
            pass
        exc = _raised(RuntimeUnsupported,
                      "missing required modules: ['otrv4_core']")
        d = failure.describe(exc)
        assert d["code"] == "RuntimeUnsupported"
        assert "otrv4_core" in d["detail"]

    def test_an_import_error_names_the_module(self):
        exc = ImportError("dlopen failed: library not found")
        exc.name = "otrv4_core"
        d = failure.describe(exc)
        assert "otrv4_core" in d["detail"]

    def test_a_sys_exit_during_import_is_explained(self):
        # otrv4plus_xmpp.py and otrv4+.py exit(1) when a dependency is absent.
        # In an APK there is no terminal, so the printed reason is lost and the
        # exit code is the only survivor.
        d = failure.describe(_raised(SystemExit, 1))
        assert "sys.exit" in d["detail"]
        assert "1" in d["detail"]

    def test_the_frames_point_at_a_line(self):
        d = failure.describe(_raised(ValueError, "x"))
        assert d["frames"], "a traceback with no frames diagnoses nothing"
        assert "test_android_failure_report.py:" in d["frames"][-1]
        assert " in " in d["frames"][-1]

    def test_a_chained_cause_is_reported(self):
        """The common shape: ImportError chained onto a wrapper."""
        try:
            try:
                raise ImportError("inner")
            except ImportError as inner:
                inner.name = "otrv4_core"
                raise RuntimeError("outer") from inner
        except RuntimeError as e:
            d = failure.describe(e)
        assert d["code"] == "RuntimeError"
        assert "otrv4_core" in d["caused_by"]


class TestItLeaksNothing:

    def test_an_arbitrary_exception_message_is_not_shown(self):
        """The property the whole module exists for.

        A ValueError raised deep in the engine can quote the value it
        rejected. Nothing reaches the screen but the type name.
        """
        secret = "correct-horse-battery-staple"
        d = failure.describe(_raised(ValueError, secret))
        blob = repr(d)
        assert secret not in blob
        assert "ValueError" in d["detail"]

    def test_an_import_error_message_is_not_shown(self):
        """CPython quotes the full .so path on a failed extension load.

        On Android that path is inside the package's private data directory,
        which is device- and install-identifying. The module name is the part
        worth having.
        """
        exc = ImportError(
            "dlopen failed: /data/data/org.otrv4plus.android/files/"
            "chaquopy/AssetFinder/requirements/otrv4_core.so not found")
        exc.name = "otrv4_core"
        d = failure.describe(exc)
        assert "/data/data" not in repr(d)
        assert "otrv4_core" in d["detail"]

    def test_an_oserror_path_is_not_shown(self):
        d = failure.describe(_raised(OSError, 2, "No such file",
                                     "/data/user/0/org.otrv4plus.android/x"))
        assert "/data/user" not in repr(d)

    def test_frames_carry_no_source_and_no_values(self):
        """A file and a line number cannot carry a passphrase. Text can."""
        passphrase = "hunter2-the-passphrase"

        def inner(_unused):
            raise ValueError(passphrase)

        try:
            inner(passphrase)
        except ValueError as e:
            d = failure.describe(e)
        assert passphrase not in repr(d)
        # ...but it still tells you where to look.
        assert any("inner" in f for f in d["frames"])

    def test_the_detail_is_bounded(self):
        class RuntimeUnsupported(RuntimeError):
            pass
        d = failure.describe(_raised(RuntimeUnsupported, "x" * 5000))
        assert len(d["detail"]) <= failure.MAX_DETAIL

    def test_the_frame_list_is_bounded(self):
        def recurse(n):
            if n:
                return recurse(n - 1)
            raise ValueError("bottom")

        try:
            recurse(40)
        except ValueError as e:
            d = failure.describe(e)
        assert len(d["frames"]) <= failure.MAX_FRAMES


class TestItNeverMakesThingsWorse:

    def test_it_does_not_raise_on_a_hostile_exception(self):
        """A reporter that crashes while explaining a crash leaves nothing."""
        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("boom")

            @property
            def name(self):
                raise RuntimeError("boom")

        d = failure.describe(_raised(Hostile))
        assert d["code"] == "Hostile"

    def test_an_exception_with_no_traceback_is_fine(self):
        d = failure.describe(ValueError("never raised"))
        assert d["frames"] == []
        assert d["code"] == "ValueError"

    def test_every_field_is_json_safe(self):
        import json
        d = failure.describe(_raised(SystemExit, 1))
        json.dumps(d)   # must not raise: Kotlin renders this without reaching
                        # back into Python objects


class TestTheModuleShips:

    def test_it_is_packaged_into_the_apk(self):
        """It is useless on a desktop; it exists for the handset.

        android_bridge/*.py is copied wholesale by syncPythonSources, so this
        checks the mechanism rather than a filename list.
        """
        import os
        gradle = "android/app/build.gradle.kts"
        if not os.path.exists(gradle):
            pytest.skip("no android/ project in this checkout")
        src = open(gradle).read()
        assert 'from(repoRoot.resolve("android_bridge"))' in src
        assert 'include("*.py")' in src


class TestSyntaxErrorIsTheInterestingCase:
    """On this project a SyntaxError has exactly one meaning.

    otrv4+.py uses PEP 701 f-strings, so it does not parse below 3.12. A
    SyntaxError from it on a handset means the Chaquopy runtime is not the
    3.12 the build asked for -- and the file and line are what prove it.
    """

    def _syntax_error(self):
        try:
            compile('f"{x !r }"\n', "otrv4+.py", "exec")
        except SyntaxError as e:
            return e
        return None

    def test_it_names_the_file_and_line(self):
        exc = self._syntax_error()
        if exc is None:
            import pytest
            pytest.skip("this interpreter parses PEP 701 f-strings")
        d = failure.describe(exc)
        assert d["code"] == "SyntaxError"
        assert "otrv4+.py" in d["detail"]
        assert "older than 3.12" in d["detail"]

    def test_it_does_not_include_the_source_line(self):
        """exc.text is the offending source. Not shown, on principle."""
        exc = self._syntax_error()
        if exc is None:
            import pytest
            pytest.skip("this interpreter parses PEP 701 f-strings")
        assert exc.text, "the fixture is not exercising the property"
        assert exc.text.strip() not in repr(failure.describe(exc))

    def test_the_filename_is_a_basename(self):
        exc = SyntaxError("bad")
        exc.filename = "/data/data/org.otrv4plus.android/files/otrv4+.py"
        exc.lineno = 5195
        d = failure.describe(exc)
        assert "/data/data" not in d["detail"]
        assert "otrv4+.py:5195" in d["detail"]


class TestTheExportedReport:
    """`as_text` is what leaves the device, so the rule is applied to it.

    Everything upstream is already supposed to be safe. This is the
    belt-and-braces pass: the cost of checking the finished string is nothing,
    and the cost of being wrong is a secret in a file the user is about to
    upload to a bug tracker.
    """

    def _report(self, **extra):
        from android_bridge import diagnostics
        base = {"python": {"version": "3.12.12"},
                "rust_core": {"loaded": True, "missing_symbols": []}}
        base.update(extra)
        return diagnostics.as_text(base)

    def test_it_renders_nested_structure(self):
        text = self._report()
        assert "python:" in text
        assert "version: 3.12.12" in text

    def test_an_empty_list_says_so_rather_than_vanishing(self):
        # "missing_symbols:" followed by nothing reads as truncation.
        assert "(none)" in self._report()

    def test_a_key_matching_a_sensitive_hint_is_redacted(self):
        """Nothing should produce such a key. If something does, it is caught."""
        text = self._report(identity={"seed": "DEADBEEF-the-actual-seed"})
        assert "DEADBEEF" not in text
        assert "<redacted>" in text

    def test_every_sensitive_hint_is_actually_enforced(self):
        """Not just the one the author happened to test."""
        from android_bridge import diagnostics
        for hint in diagnostics.SENSITIVE_KEY_HINTS:
            text = diagnostics.as_text({"x": {hint: "SHOULD-NOT-APPEAR"}})
            assert "SHOULD-NOT-APPEAR" not in text, hint
            assert "<redacted>" in text, hint

    def test_the_hint_matches_a_substring_not_just_a_whole_key(self):
        # "root_key" must catch "current_root_key_hex".
        text = self._report(x={"current_root_key_hex": "NOPE"})
        assert "NOPE" not in text

    def test_a_real_collected_report_carries_no_hint(self):
        from android_bridge import diagnostics
        text = diagnostics.as_text(include_selftest=False)
        assert "<redacted>" not in text, (
            "a genuine report tripped the redaction pass, which means "
            "something upstream is producing a key it should not")
