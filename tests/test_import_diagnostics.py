"""A failed import must say what is actually missing.

From an IRC session with a tester on Alpine:

    $ python3 otrv4plus_xmpp.py --jid everchange000@xmpp-elite.i2p ...
    Could not import OTR engine from 'otrv4plus': No module named 'socks'
    Ensure otrv4+.py, the otrv4plus.py symlink, and otrv4_core.so are in
    this directory.

    > I've installed socks via pip, but that's apparently not what it's
    > complaining about

Two separate failures of communication in four lines:

  * The advice was wrong. The guard caught every exception and printed the
    same file-placement hint regardless, so a missing third-party module
    sent the tester checking three files that were all present and correct.

  * `pip install socks` looks like the obvious fix and is not. The module
    comes from the **PySocks** distribution; the PyPI project literally
    named `socks` is an empty placeholder ("automatically generated with
    'register_pypi' and should be deleted soon", version 0) that installs
    no module at all. So the install succeeded, nothing changed, and the
    error message stayed identical.

This is the same failure mode as the musl and cdylib bugs before it: the
program knew exactly what was wrong and said something else.
"""

import os

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def advice_for(exc):
    return "\n".join(xmpp._import_failure_advice(exc))


class TestAMissingDependencyIsNamedAsOne:

    def test_socks_sends_the_user_to_pysocks(self):
        text = advice_for(ImportError("No module named 'socks'", name="socks"))
        assert "pip install PySocks" in text
        assert "socks" in text

    def test_it_says_why_pip_install_socks_will_not_work(self):
        """Without this the reader tries the obvious thing, watches it
        succeed, and is back where they started."""
        text = advice_for(ImportError("No module named 'socks'", name="socks"))
        assert "will not fix this" in text

    def test_it_does_not_blame_file_placement(self):
        text = advice_for(ImportError("No module named 'socks'", name="socks"))
        assert "symlink" not in text, (
            "the old message sent a tester chasing files that were all there"
        )

    @pytest.mark.parametrize("module,package", [
        ("socks", "PySocks"),
        ("argon2", "argon2-cffi"),
        ("Crypto", "pycryptodome"),
    ])
    def test_modules_whose_pip_name_differs_are_translated(self, module, package):
        text = advice_for(ImportError("x", name=module))
        assert "pip install %s" % package in text

    def test_a_module_whose_name_matches_its_package_is_passed_through(self):
        text = advice_for(ImportError("x", name="slixmpp"))
        assert "pip install slixmpp" in text
        assert "are not the same name" not in text, (
            "explaining a distinction that does not exist here is noise"
        )

    def test_a_submodule_is_reported_against_its_top_level_package(self):
        text = advice_for(ImportError("x", name="slixmpp.plugins.xep_0384"))
        assert "pip install slixmpp" in text


class TestTheOtherTwoCasesAreStillHandled:

    def test_a_missing_rust_core_gets_build_instructions(self):
        text = advice_for(ImportError("x", name="otrv4_core"))
        assert "cargo build --release --features extension-module" in text
        assert "libotrv4_core.so" in text

    def test_anything_else_falls_back_to_the_placement_hint(self):
        """A SyntaxError in otrv4+.py, a missing symlink, a permissions
        problem: for those the original advice is the right advice."""
        for exc in (ValueError("bad f-string"),
                    SyntaxError("invalid syntax"),
                    AttributeError("EnhancedSessionManager")):
            text = advice_for(exc)
            assert "otrv4plus.py symlink" in text

    def test_a_failure_to_find_the_engine_itself_is_not_a_pip_problem(self):
        """`No module named 'otrv4plus'` means the symlink is missing, and
        telling someone to `pip install otrv4plus` would be actively wrong."""
        text = advice_for(ImportError("x", name=xmpp.OTR_MODULE))
        assert "pip install" not in text
        assert "symlink" in text


class TestTheEngineNamesPySocksItself:
    """`otrv4plus_xmpp.py` is not the only entry point. Someone running
    `otrv4+.py` directly, or importing it, hits the bare `import socks`."""

    @staticmethod
    @pytest.fixture(scope="class")
    def engine_source():
        with open(os.path.join(ROOT, "otrv4+.py"), "r", encoding="utf-8") as fh:
            return fh.read()

    def test_the_import_is_guarded(self, engine_source):
        head = engine_source[:4000]
        assert "import socks" in head
        assert "PySocks" in head, (
            "a bare `import socks` gives the reader nothing to act on"
        )

    def test_it_checks_that_what_it_imported_is_really_pysocks(self, engine_source):
        """The placeholder package installs nothing today, but a name that
        an unrelated project can claim is one upload away from importing
        successfully and then failing much later, inside the proxy setup."""
        head = engine_source[:4000]
        for attribute in ("setdefaultproxy", "socksocket", "PROXY_TYPE_SOCKS5"):
            assert attribute in head, (
                "nothing verifies the imported module has the PySocks API"
            )
