"""The packaged extension module must be named the way the importer looks.

Split out from test_apk_python_sources.py deliberately: that file skips
entirely below Python 3.12, because it parses otrv4+.py's PEP 701 f-strings.
Nothing here parses the engine -- it reads a workflow and a script -- so it
must not inherit that skip, or it silently stops running on exactly the
machines most likely to be checking a build.
"""

import os


class TestTheExtensionIsNamedPlainly:
    """Chaquopy's importer looks for a bare `.so`.

    maturin emits `otrv4_core/otrv4_core.abi3.so`, and on a handset that gave
    `ModuleNotFoundError: cannot import otrv4_core.otrv4_core` with the
    package's own `__init__.py` executing one frame above -- the package
    found, the extension beside it not. Every extension that does load in that
    process is named plainly: `_bz2.so`, `math.so`, `zlib.so`.

    `.so` is unconditionally in CPython's POSIX suffix table, so the rename
    costs nothing anywhere and removes a way to fail on Android.
    """

    SCRIPT = ".github/scripts/plain_so_name.py"

    def test_the_script_exists(self):
        assert os.path.exists(self.SCRIPT)

    def test_the_workflow_runs_it_before_packaging(self):
        wf = open(".github/workflows/android.yml").read()
        assert "plain_so_name.py" in wf, (
            "the rename is only worth having if it runs")
        # Before the DT_NEEDED check, so that check inspects what ships.
        assert wf.index("plain_so_name.py") < wf.index(
            "The wheel must ask for the libpython the APK ships")

    def test_it_strips_the_suffixes_maturin_and_cpython_produce(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("pln", self.SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.plain("otrv4_core/otrv4_core.abi3.so") == \
            "otrv4_core/otrv4_core.so"
        assert mod.plain(
            "pkg/mod.cpython-312-aarch64-linux-android.so") == "pkg/mod.so"

    def test_it_leaves_an_already_plain_name_alone(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("pln", self.SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for untouched in ("otrv4_core/otrv4_core.so", "lib/libpython3.12.so",
                          "pkg/__init__.py"):
            assert mod.plain(untouched) == untouched
