"""The Rust core must build on musl, not only on glibc.

`pqcrypto-mlkem` vendors PQClean, whose `pqclean/common/compat.h` does:

    #if defined(__GNUC__) && !defined(__clang__)
    #include <features.h>
    #  if !__GNUC_PREREQ(7, 1)

`__GNUC_PREREQ` is a **glibc** macro. musl ships a `<features.h>` that does not
define it, so the preprocessor meets an undefined identifier followed by `(` --
not a valid `#if` expression -- and the build dies before compiling any Rust:

    compat.h:20:21: error: missing binary operator before token "("

Reported from an Alpine-style `x86_64-unknown-linux-musl` box. Upstream has no
fixed release: 0.1.1 is the newest `pqcrypto-mlkem` published. So the macro is
supplied from `Rust/.cargo/config.toml`, and these tests hold that file to what
it has to be for the fix to work at all.
"""

import io
import os
import re
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "Rust", ".cargo", "config.toml")

#: cc-rs consults CFLAGS_<target> before falling back to plain CFLAGS, which
#: is what keeps a glibc build from ever seeing this.
MUSL_TRIPLES = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
)


@pytest.fixture(scope="module")
def env_table():
    if not os.path.exists(CONFIG):
        pytest.fail("Rust/.cargo/config.toml is gone; musl builds fail again")
    import tomllib
    with open(CONFIG, "rb") as fh:
        return tomllib.load(fh).get("env", {})


class TestTheConfigSuppliesTheMacro:

    def test_the_file_parses(self, env_table):
        assert env_table, "[env] is empty, so nothing is supplied to cc-rs"

    @pytest.mark.parametrize("triple", MUSL_TRIPLES)
    def test_each_musl_target_is_covered(self, triple, env_table):
        key = "CFLAGS_%s" % triple
        assert key in env_table, "%s would still fail to build" % triple
        assert "__GNUC_PREREQ" in env_table[key]

    def test_no_glibc_target_is_touched(self, env_table):
        """Keyed per-target on purpose. A plain `CFLAGS`, or a gnu-triple key,
        would push the macro at builds where glibc already defines it and earn
        a redefinition warning on a project that keeps its build silent."""
        for key in env_table:
            assert "musl" in key, (
                "%s applies outside musl, where the macro already exists" % key)

    def test_the_definition_has_no_spaces(self, env_table):
        """cc-rs splits CFLAGS on whitespace, so a space anywhere in the macro
        body silently truncates it into fragments that are not valid flags."""
        for key, value in env_table.items():
            body = value.split("=", 1)[1] if "=" in value else value
            assert " " not in body, (
                "%s contains a space; cc-rs will split it: %r" % (key, value))

    def test_it_is_a_function_like_macro_of_two_arguments(self, env_table):
        """The header calls it as `__GNUC_PREREQ(7, 1)`. An object-like
        definition would not fix the `#if` at all."""
        for key, value in env_table.items():
            assert re.search(r"-D__GNUC_PREREQ\(\w+,\w+\)=", value), (
                "%s is not a two-argument function-like macro: %r"
                % (key, value))


class TestTheDefinitionIsCorrect:
    """Not merely present -- right. A wrong one compiles and then silently
    decides whether a polyfill is emitted."""

    def _cc(self):
        import shutil
        cc = shutil.which("cc") or shutil.which("gcc")
        if cc is None:
            pytest.skip("no C compiler")
        return cc

    def test_it_agrees_with_glibcs_own_definition(self, env_table):
        """Compiled and run, against glibc's
        `((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))`,
        on values either side of the 7.1 boundary the header tests."""
        import subprocess
        cc = self._cc()
        flag = env_table["CFLAGS_%s" % MUSL_TRIPLES[0]]
        body = flag.split("=", 1)[1]
        # Cases derived from the compiler's OWN version, not hard-coded.
        # A fixed list of low versions never reaches the minor-number
        # comparison at all: `__GNUC__ > maj` short-circuits the `||` and the
        # `>=` is never evaluated. Mutating `>=` to `>` then passes, which is
        # exactly what happened the first time this test was written.
        # The discriminating case is maj == __GNUC__ and min == __GNUC_MINOR__.
        checks = """
    for (int maj = __GNUC__ - 2; maj <= __GNUC__ + 2; maj++)
        for (int min = 0; min <= __GNUC_MINOR__ + 2; min++)
            if (GLIBC(maj, min) != OURS(maj, min)) return 1;
    /* The boundary, named explicitly so a reader can see it is covered. */
    if (GLIBC(__GNUC__, __GNUC_MINOR__) != OURS(__GNUC__, __GNUC_MINOR__))
        return 1;
"""
        with tempfile.TemporaryDirectory() as work:
            src = os.path.join(work, "equiv.c")
            with open(src, "w", encoding="utf-8") as fh:
                fh.write(
                    "#define GLIBC(maj, min) "
                    "((__GNUC__ << 16) + __GNUC_MINOR__ >= "
                    "((maj) << 16) + (min))\n"
                    "#define OURS(maj,min) %s\n"
                    "int main(void) {\n%s\n    return 0;\n}\n"
                    % (body, checks))
            binary = os.path.join(work, "equiv")
            built = subprocess.run([cc, "-o", binary, src],
                                   capture_output=True)
            assert built.returncode == 0, built.stderr.decode()[:400]
            assert subprocess.run([binary]).returncode == 0, (
                "the definition disagrees with glibc's on some version")

    def test_it_actually_fixes_the_header(self, env_table):
        """The end-to-end check: compile PQClean's own compat.h with musl's
        behaviour simulated, with and without the flag."""
        import glob
        import subprocess
        matches = glob.glob(os.path.expanduser(
            "~/.cargo/registry/src/*/pqcrypto-mlkem-*/pqclean/common/compat.h"))
        if not matches:
            pytest.skip("pqcrypto-mlkem sources not in the cargo registry")
        cc = self._cc()
        with tempfile.TemporaryDirectory() as work:
            # musl HAS a <features.h>; it simply does not define
            # __GNUC_PREREQ. Shadowing it with an empty one reproduces that
            # exactly, which is why this test can run on a glibc box.
            fake = os.path.join(work, "fake")
            os.makedirs(fake)
            open(os.path.join(fake, "features.h"), "w").close()
            probe = os.path.join(work, "t.c")
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write('#include "compat.h"\nint main(void){return 0;}\n')
            common = [cc, "-I", fake, "-I", os.path.dirname(matches[0]),
                      "-c", probe, "-o", os.devnull]

            without = subprocess.run(common, capture_output=True)
            assert without.returncode != 0, (
                "the musl failure no longer reproduces -- upstream may have "
                "fixed it, in which case this workaround can go")
            assert b"missing binary operator" in without.stderr

            flag = env_table["CFLAGS_%s" % MUSL_TRIPLES[0]]
            with_flag = subprocess.run(common + [flag], capture_output=True)
            assert with_flag.returncode == 0, (
                "the configured flag does not fix the build: %s"
                % with_flag.stderr.decode()[:400])


class TestItIsDocumentedWhereSomeoneWillLook:

    def test_the_readme_explains_the_musl_failure(self):
        readme = io.open(os.path.join(ROOT, "README.md"),
                         encoding="utf-8").read()
        assert "Building on musl" in readme
        assert "__GNUC_PREREQ" in readme

    def test_the_readme_warns_that_cargo_must_run_from_rust(self):
        """cargo finds .cargo/config.toml by walking up from its working
        directory, not from the manifest. `--manifest-path Rust/Cargo.toml`
        run at the repository root silently skips the fix."""
        readme = io.open(os.path.join(ROOT, "README.md"),
                         encoding="utf-8").read()
        assert "manifest-path" in readme

    def test_the_config_says_why_rather_than_just_what(self):
        config = io.open(CONFIG, encoding="utf-8").read()
        assert "glibc" in config and "musl" in config
        assert "cc-rs splits" in config
