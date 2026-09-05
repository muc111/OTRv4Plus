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


class TestTheSharedLibraryIsActuallyProduced:
    """The `.so` is the whole point; an `.rlib` is not importable by Python.

    musl targets enable `crt-static` by default, and rustc cannot build a
    cdylib against a statically linked C runtime. It DROPS the crate type,
    prints one line about it among the compile output, and **exits
    successfully**. `target/release/` then holds `libotrv4_core.rlib` and
    `libotrv4_core.d` and no `.so`, so the next documented step --

        cp target/release/libotrv4_core.so ../otrv4_core.so

    -- fails with "No such file or directory", minutes and several steps away
    from the cause. Reported exactly that way.
    """

    @pytest.fixture(scope="class")
    def target_table(self):
        if not os.path.exists(CONFIG):
            pytest.fail("Rust/.cargo/config.toml is gone")
        import tomllib
        with open(CONFIG, "rb") as fh:
            return tomllib.load(fh).get("target", {})

    def test_the_crate_still_asks_for_a_cdylib(self):
        """If this ever stops being true, the rest of this class is moot --
        and so is the build step that copies the .so."""
        import tomllib
        with open(os.path.join(ROOT, "Rust", "Cargo.toml"), "rb") as fh:
            cargo = tomllib.load(fh)
        assert "cdylib" in cargo["lib"]["crate-type"]

    @pytest.mark.parametrize("triple", MUSL_TRIPLES)
    def test_crt_static_is_turned_off_for_musl(self, triple, target_table):
        assert triple in target_table, (
            "%s still defaults to crt-static, so it produces no .so" % triple)
        flags = target_table[triple]["rustflags"]
        assert "target-feature=-crt-static" in flags, (
            "%s: %r does not disable crt-static" % (triple, flags))

    def test_no_glibc_target_is_given_rustflags(self, target_table):
        """glibc does not default to crt-static and needs no help. An entry
        here would also silently replace RUSTFLAGS a developer set."""
        for triple in target_table:
            assert "musl" in triple, (
                "%s has rustflags it does not need" % triple)

    def test_the_config_explains_the_silent_failure(self):
        config = io.open(CONFIG, encoding="utf-8").read()
        assert "crt-static" in config
        assert "No such file or directory" in config, (
            "nothing connects the config to the error the user actually sees")


class TestTheBuildScriptWarnsIfThisIsBypassed:
    """`.cargo/config.toml` is found by walking up from the invocation
    directory, so `--manifest-path Rust/Cargo.toml` from the repo root skips
    it. That must not be silent."""

    def _run_build_script(self, target, features, extra_env=None):
        import shutil
        import subprocess
        import tempfile
        if shutil.which("rustc") is None:
            pytest.skip("no rustc")
        build_rs = os.path.join(ROOT, "Rust", "build.rs")
        with tempfile.TemporaryDirectory() as work:
            binary = os.path.join(work, "bs")
            # --edition 2021 to match what cargo uses for this package. Plain
            # rustc defaults to an older edition, where inline format captures
            # like `{fix}` render as that literal text -- so a message that was
            # entirely broken would still have satisfied a test looking only
            # for the "cargo:warning=" prefix. Found exactly that way.
            built = subprocess.run(
                ["rustc", "--edition", "2021", "-O", "-o", binary, build_rs],
                capture_output=True)
            assert built.returncode == 0, built.stderr.decode()[:400]
            assert b"warning" not in built.stderr, (
                "build.rs does not compile cleanly: %s"
                % built.stderr.decode()[:300])
            env = {"PATH": os.environ.get("PATH", ""),
                   "TARGET": target,
                   "CARGO_CFG_TARGET_FEATURE": features}
            env.update(extra_env or {})
            done = subprocess.run([binary], capture_output=True, env=env,
                                  text=True)
            return done

    def test_it_warns_when_crt_static_would_drop_the_cdylib(self):
        done = self._run_build_script("x86_64-unknown-linux-musl",
                                      "crt-static,fxsr,sse,sse2")
        assert "cargo:warning=" in done.stdout
        assert "NO libotrv4_core.so" in done.stdout

    def test_the_warning_names_the_fix(self):
        """A warning that reports a symptom and not a remedy just moves the
        confusion earlier."""
        done = self._run_build_script("x86_64-unknown-linux-musl",
                                      "crt-static,fxsr,sse,sse2")
        assert "target-feature=-crt-static" in done.stdout

    def test_the_warning_names_the_error_the_user_will_hit(self):
        done = self._run_build_script("x86_64-unknown-linux-musl",
                                      "crt-static,fxsr,sse,sse2")
        assert "No such file or directory" in done.stdout

    def test_the_message_is_not_an_unrendered_format_placeholder(self):
        """The message went out as the literal text "{fix}" once, and a test
        that only looked for the "cargo:warning=" prefix passed anyway."""
        done = self._run_build_script("x86_64-unknown-linux-musl",
                                      "crt-static,fxsr,sse,sse2")
        assert "{fix}" not in done.stdout and "{line}" not in done.stdout
        assert "{target}" not in done.stdout
        assert "x86_64-unknown-linux-musl" in done.stdout, (
            "the target name was never substituted in")

    def test_it_is_silent_on_an_ordinary_build(self):
        """It must not fire on glibc or on `cargo test`, or it becomes noise
        on a project that keeps its build silent."""
        done = self._run_build_script("x86_64-unknown-linux-gnu",
                                      "fxsr,sse,sse2")
        assert "cargo:warning=" not in done.stdout
        assert done.returncode == 0

    def test_asking_for_the_extension_module_is_a_HARD_error(self):
        """`--features extension-module` means "build the Python extension".
        Finishing without one is not a success worth reporting, and a warning
        was not enough: it scrolls past in several hundred lines of compile
        output exactly like rustc's own `dropping unsupported crate type`
        line, which is the line that already went unread twice."""
        done = self._run_build_script(
            "x86_64-unknown-linux-musl", "crt-static,fxsr,sse,sse2",
            extra_env={"CARGO_FEATURE_EXTENSION_MODULE": "1"})
        assert done.returncode != 0, (
            "the build still 'succeeds' while producing no .so")
        assert "crt-static is enabled" in done.stderr
        assert "target-feature=-crt-static" in done.stderr

    def test_the_hard_error_does_not_fire_without_the_feature(self):
        """`cargo test` wants only the rlib and must still run."""
        done = self._run_build_script("x86_64-unknown-linux-musl",
                                      "crt-static,fxsr,sse,sse2")
        assert done.returncode == 0

    def test_the_hard_error_is_gated_on_the_feature(self):
        """`cargo test` wants only the rlib; an unconditional hard error would
        take the Rust test suite with it."""
        source = io.open(os.path.join(ROOT, "Rust", "build.rs"),
                         encoding="utf-8").read()
        start = source.index("fn warn_if_cdylib_will_be_dropped")
        # To the closing brace at column 0, not to end-of-file: the OTHER
        # guards in this build script panic on purpose, and slicing past this
        # function picks them up and fails for the wrong reason.
        end = source.index("\n}\n", start) + 3
        fn = source[start:end]
        assert "cargo:warning=" in fn, "the warning path is gone"
        # It DOES panic -- but only behind the feature gate, so `cargo test`
        # is unaffected. That gate is the thing worth pinning.
        assert "CARGO_FEATURE_EXTENSION_MODULE" in fn, (
            "the hard error is no longer conditional on the feature, so it "
            "would take the Rust test suite down with it")
