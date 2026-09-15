"""Every place that states the licence must state the same one.

A project's licence lives in at least five files, and they drift silently:
nothing fails to build when `Cargo.toml` still says GPL-3.0 and `LICENSE` says
AGPL. The failure mode is a wheel or an APK shipped under terms its author did
not choose, which is the one class of mistake here that cannot be fixed by a
later commit — it is fixed by contacting everyone who received it.

The dual licence adds a second thing to keep true: the commercial half is only
grantable while the project can license every line under both. That needs the
CLA to exist, the contributor path to point at it, and no copyleft dependency
in the tree.
"""

import io
import json
import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: What the whole repository must agree on.
SPDX = "AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial"


def _read(*parts):
    with io.open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def licence():
    return _read("LICENSE")


class TestTheLicenceTextIsWholeAndIsTheRightOne:
    """A truncated licence file is worse than none: it looks authoritative."""

    def test_it_is_the_affero_licence(self, licence):
        assert "GNU AFFERO GENERAL PUBLIC LICENSE" in licence
        assert "Version 3, 19 November 2007" in licence

    def test_the_section_that_makes_it_affero_is_present(self, licence):
        """§13 is the whole reason for choosing AGPL over GPL: the GPL's
        obligation attaches to distribution, so a hosted service triggers
        nothing. Without §13 this is just the GPL with a different name."""
        assert "13. Remote Network Interaction" in licence

    def test_every_operative_section_is_present(self, licence):
        for n in range(1, 18):
            assert "\n%d. " % n in licence, "section %d is missing" % n
        assert "END OF TERMS AND CONDITIONS" in licence

    def test_the_warranty_disclaimers_survived(self, licence):
        """The two sections a truncation would most likely eat, and the two
        it would be most expensive to have lost."""
        assert "15. Disclaimer of Warranty." in licence
        assert "16. Limitation of Liability." in licence

    def test_it_says_it_is_dual_licensed(self, licence):
        assert "dual-licensed" in licence.lower()
        assert "LICENSE-COMMERCIAL.md" in licence

    def test_it_does_not_pretend_to_withdraw_the_old_licence(self, licence):
        """Releases went out under GPL-3.0 from a public repository. Those
        rights are permanent, and a LICENSE file implying otherwise would be
        making a claim its author cannot enforce."""
        assert "v10.16.2" in licence
        assert "cannot" in licence and "withdraw" in licence


class TestTheDeclarationsAgree:

    def test_the_crate_declares_the_dual_licence(self):
        cargo = _read("Rust", "Cargo.toml")
        assert 'license     = "%s"' % SPDX in cargo, (
            "Rust/Cargo.toml does not declare %r" % SPDX)

    def test_the_wheel_declares_it_too(self):
        """A built wheel carries its own metadata; without this it ships
        saying nothing about its terms."""
        pyproject = _read("Rust", "pyproject.toml")
        assert 'license = "%s"' % SPDX in pyproject

    def test_nothing_still_claims_plain_gpl(self):
        """The declarations, not the prose. History may discuss GPL-3.0
        freely -- and must, since earlier releases really were GPL-3.0."""
        for path in ("Rust/Cargo.toml", "Rust/pyproject.toml"):
            text = _read(*path.split("/"))
            for line in text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("#") or "license" not in stripped:
                    continue
                assert "GPL-3.0-only" not in stripped or "AGPL" in stripped, (
                    "%s still declares GPL-3.0: %s" % (path, stripped))
                if stripped.startswith("license"):
                    assert "AGPL-3.0-only" in stripped

    def test_the_readme_points_at_both_halves(self):
        readme = _read("README.md")
        assert "[AGPL-3.0](LICENSE)" in readme
        assert "LICENSE-COMMERCIAL.md" in readme

    def test_the_readme_does_not_say_it_is_still_gpl(self):
        readme = _read("README.md")
        assert "GPL-3.0. See the [LICENSE](LICENSE) file." not in readme


class TestTheCommercialHalfStaysGrantable:
    """It is grantable only while every line can be licensed both ways."""

    def test_the_contributor_agreement_exists(self):
        cla = _read("CLA.md")
        assert "Signed-off-by" in cla
        assert "relicense" in cla.lower()

    def test_the_cla_does_not_take_the_contributors_copyright(self):
        """A CLA that assigns copyright drives contributors away, and this
        project does not need one to keep both licences grantable."""
        cla = _read("CLA.md")
        assert "You keep it" in cla or "keep your copyright" in cla.lower()
        assert "not an assignment" in cla.lower()

    def test_contributing_sends_people_to_it(self):
        contributing = _read("CONTRIBUTING.md")
        assert "CLA.md" in contributing
        assert "git commit -s" in contributing

    def test_paid_work_is_assigned_rather_than_licensed(self):
        """A sign-off is a licence. For commissioned work that is not enough:
        the contractor would still own the copyright, and a commercial
        licence covering their code could not be sold."""
        terms = _read("CONTRACTOR-IP.md")
        assert "assigns to the Client" in terms
        assert "Moral rights" in terms
        assert "CONTRACTOR-IP.md" in _read("CONTRIBUTING.md")

    def test_the_ai_authorship_question_is_stated_not_buried(self):
        """It bears directly on whether there is an exclusive right to sell,
        and the README states the facts that raise it."""
        terms = _read("CONTRACTOR-IP.md")
        assert "human authorship" in terms
        assert "before you take money" in terms


class TestNoCopyleftDependencyCreepsIn:
    """One AGPL or GPL dependency makes the commercial half unsellable, and
    it would not be obvious from the diff that added it."""

    def _metadata(self):
        try:
            out = subprocess.run(
                ["cargo", "metadata", "--format-version", "1",
                 "--all-features", "--offline"],
                cwd=os.path.join(ROOT, "Rust"),
                capture_output=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            pytest.skip("cargo unavailable")
        if out.returncode != 0:
            pytest.skip("cargo metadata failed (no registry cache?)")
        return json.loads(out.stdout)

    def test_no_dependency_imposes_copyleft(self):
        meta = self._metadata()
        offenders = []
        for pkg in meta["packages"]:
            if pkg["name"] == "otrv4_core":
                continue
            lic = pkg.get("license") or ""
            # A disjunction ("X OR GPL-3.0") is a choice, and we choose the
            # permissive branch. Only a licence with no permissive option is
            # a problem.
            options = [o.strip() for o in re.split(r"\bOR\b|/", lic)]
            if not options or not any(
                    o and not re.search(r"GPL|MPL|EUPL|CDDL|SSPL|BUSL", o,
                                        re.I)
                    for o in options):
                offenders.append((pkg["name"], pkg["version"], lic))
        assert offenders == [], (
            "copyleft dependencies now in the tree, which makes the "
            "commercial licence unsellable: %s" % offenders)


class TestTheNoticeCoversWhatShips:
    """Attribution is a distribution obligation, and a stale NOTICE is a
    breached one. It is generated, so the test is that it still matches."""

    def _generator(self):
        import importlib.util
        path = os.path.join(ROOT, "tools", "generate_notice.py")
        spec = importlib.util.spec_from_file_location("gen_notice", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    # staticmethod: pytest 9 deprecates class-scoped fixtures written as
    # instance methods, because the `self` they get belongs to a throwaway
    # instance and anything stored on it is invisible to the tests. This one
    # only returns a value, so nothing was ever wrong -- the shape is what
    # pytest warns about, and correcting it is free.
    @staticmethod
    @pytest.fixture(scope="class")
    def notice():
        return _read("NOTICE")

    def test_it_exists_and_says_it_is_generated(self, notice):
        assert "third-party notices" in notice
        assert "tools/generate_notice.py" in notice, (
            "nothing tells the next reader how to rebuild it")

    def test_every_shipped_crate_is_attributed(self, notice):
        """The check that matters: a `cargo add` without a regenerate."""
        gen = self._generator()
        try:
            meta = gen.cargo_metadata()
        except Exception:
            pytest.skip("cargo metadata unavailable")
        ids = gen.shipped_packages(meta)
        missing = []
        for pkg in meta["packages"]:
            if pkg["id"] not in ids:
                continue
            if "\n%s %s" % (pkg["name"], pkg["version"]) not in notice:
                missing.append("%s %s" % (pkg["name"], pkg["version"]))
        assert missing == [], (
            "NOTICE is stale -- these ship but are not attributed: %s\n"
            "Regenerate: python3 tools/generate_notice.py > NOTICE" % missing)

    def test_the_licence_texts_of_what_we_take_are_reproduced(self, notice):
        """MIT, BSD and Apache each require the TEXT, not just the name."""
        for spdx in ("MIT", "BSD-3-Clause", "Apache-2.0"):
            assert "\n%s\n" % spdx in notice, "no %s text" % spdx
        assert "Permission is hereby granted, free of charge" in notice
        assert "Redistributions of source code must retain" in notice

    def test_nothing_is_flagged_as_unavailable(self, notice):
        """The generator says so rather than silently omitting a text."""
        assert "must be added before distribution" not in notice

    def test_the_crate_count_it_states_is_the_count_it_attributes(self, notice):
        """NOTICE's §1 heading carries a number, and four different numbers
        for "how many dependencies" were in circulation across this file, the
        README and LICENSING_AUDIT.md -- 104, 109, 134 and 137. They count
        different things (shipped versus fully resolved, with and without the
        crate itself), and nothing said so.

        The one that matters for attribution is the shipped count, because
        those are the crates whose notices must travel with a binary. Pinning
        the stated number to the generator's own answer means the heading
        cannot drift from the list beneath it.
        """
        gen = self._generator()
        try:
            meta = gen.cargo_metadata()
        except Exception:
            pytest.skip("cargo metadata unavailable")
        shipped = len(gen.shipped_packages(meta))
        m = re.search(r"Rust crates compiled into otrv4_core \((\d+)\)", notice)
        assert m, "NOTICE §1 no longer states a crate count"
        assert int(m.group(1)) == shipped, (
            "NOTICE §1 says %s crates ship; the graph says %d. Regenerate: "
            "python3 tools/generate_notice.py > NOTICE"
            % (m.group(1), shipped))

    def test_a_declined_copyleft_option_is_not_reproduced(self, notice):
        """`r-efi` offers MIT OR Apache-2.0 OR LGPL-2.1-or-later. Printing
        the LGPL text would imply an obligation not accepted, and would
        suggest a copyleft dependency that is not in the tree."""
        assert "\nLGPL-2.1-or-later\n" not in notice
        assert "GNU LESSER GENERAL PUBLIC LICENSE" not in notice

    def test_a_choice_is_recorded_as_taken(self, notice):
        """A disjunction is a choice, and a choice recorded nowhere has not
        really been made."""
        assert "Taken:" in notice
        assert "Offered:" in notice


class TestTheNoticeGeneratorItself:
    """Both of these were real defects in its first run."""

    def _generator(self):
        import importlib.util
        path = os.path.join(ROOT, "tools", "generate_notice.py")
        spec = importlib.util.spec_from_file_location("gen_notice2", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @pytest.mark.parametrize("expr,expected", [
        ("MIT OR Apache-2.0", ["MIT"]),
        ("Apache-2.0 OR MIT", ["MIT"]),
        ("MIT/Apache-2.0", ["MIT"]),
        ("MIT OR Apache-2.0 OR LGPL-2.1-or-later", ["MIT"]),
        ("(MIT OR Apache-2.0) AND Unicode-3.0", ["MIT", "Unicode-3.0"]),
        ("Apache-2.0 WITH LLVM-exception", ["Apache-2.0", "LLVM-exception"]),
        ("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT", ["MIT"]),
        ("BSD-3-Clause", ["BSD-3-Clause"]),
    ])
    def test_the_expression_parser(self, expr, expected):
        """AND binds the whole expression. Splitting on OR first read
        "(MIT OR Apache-2.0) AND Unicode-3.0" as a choice and produced the
        identifier "(MIT", which then had no licence text to find."""
        assert self._generator().chosen_licence(expr) == expected

    def test_a_conjunction_keeps_both_halves(self):
        """`unicode-ident` is not offering a choice between them."""
        taken = self._generator().chosen_licence(
            "(MIT OR Apache-2.0) AND Unicode-3.0")
        assert "Unicode-3.0" in taken

    def test_licence_body_prose_is_not_read_as_a_copyright(self):
        """The first run matched "(c) You must retain, in the Source form of
        any Derivative Works" out of Apache-2.0 and attributed that sentence
        to every crate shipping it. Attribution naming the wrong holder is
        worse than none."""
        gen = self._generator()
        for prose in (
                "  (c) You must retain, in the Source form of any Derivative",
                "     (a) You must give any other recipients a copy",
                "of the Copyright License granted, and any other"):
            assert not gen.COPYRIGHT_RE.match(prose), (
                "licence prose matched as a copyright line: %r" % prose)

    def test_template_placeholders_are_not_read_as_holders(self):
        gen = self._generator()
        for template in ("Copyright [yyyy] [name of copyright owner]",
                         "Copyright (C) <year>  <name of author>"):
            assert (not gen.COPYRIGHT_RE.match(template)
                    or gen.PLACEHOLDER_RE.search(template)), (
                "a boilerplate template would be attributed: %r" % template)

    def test_a_real_copyright_line_is_still_matched(self):
        gen = self._generator()
        for real in ("Copyright (c) 2019 The RustCrypto Project Developers",
                     "Copyright 2013-2026 The PurpleI2P Project",
                     "copyright (c) 2018 Artyom Pavlov"):
            assert gen.COPYRIGHT_RE.match(real), real
            assert not gen.PLACEHOLDER_RE.search(real), real

    def test_only_shipped_packages_are_walked(self):
        """Build- and dev-only packages are in the lockfile and not in the
        artifact. Attributing them pads the file a reviewer must read."""
        gen = self._generator()
        try:
            meta = gen.cargo_metadata()
        except Exception:
            pytest.skip("cargo metadata unavailable")
        shipped = gen.shipped_packages(meta)
        assert 0 < len(shipped) < len(meta["packages"]) - 1, (
            "the walk returned everything, so it is not filtering at all")


class TestTheManifestsParseUnderAStrictTomlParser:
    """`cargo build` is not a TOML conformance test.

    `Cargo.toml` carried a MULTI-LINE inline table:

        ed448-goldilocks-plus = {
            version = "0.16",
            ...
        }

    TOML 1.0 forbids newlines inside `{ }`. Cargo's own parser accepts them as
    an extension, so `cargo build` was green for as long as the entry existed
    -- while `maturin build` died before compiling anything with "TOML parse
    error: invalid inline table". Anything that reads the manifest with a
    conformant parser (packaging tools, licence scanners, SBOM generators,
    this test) rejected the file outright.
    """

    @pytest.mark.parametrize("manifest", ["Rust/Cargo.toml",
                                          "Rust/pyproject.toml"])
    def test_it_parses_under_tomllib(self, manifest):
        """tomllib is TOML 1.0 only, which is the point."""
        import tomllib
        path = os.path.join(ROOT, *manifest.split("/"))
        with open(path, "rb") as fh:
            tomllib.load(fh)

    def test_no_inline_table_spans_lines(self):
        """Checked directly, so the reason survives even if a future tomllib
        relaxes to TOML 1.1 and stops objecting."""
        offenders = []
        for manifest in ("Rust/Cargo.toml", "Rust/pyproject.toml",
                         "Rust/audit.toml"):
            path = os.path.join(ROOT, *manifest.split("/"))
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    code = line.split("#", 1)[0].rstrip()
                    if "=" in code and code.count("{") > code.count("}"):
                        offenders.append("%s:%d" % (manifest, n))
        assert offenders == [], (
            "multi-line inline table (invalid TOML 1.0; breaks maturin and "
            "every conformant reader): %s" % offenders)

    def test_the_dependency_survived_the_rewrite(self):
        """The fix moved an entry between TOML forms. The thing that must not
        change is what it resolves to."""
        import tomllib
        with open(os.path.join(ROOT, "Rust", "Cargo.toml"), "rb") as fh:
            cargo = tomllib.load(fh)
        ed448 = cargo["dependencies"]["ed448-goldilocks-plus"]
        assert ed448["version"] == "0.16"
        assert ed448["optional"] is True
        assert ed448["default-features"] is False
        assert ed448["features"] == ["alloc", "signing", "pkcs8"]

    def test_the_wheel_metadata_still_carries_the_licence(self):
        """The manifest edit sits beside the licence declaration; a rewrite
        that dropped it would be silent."""
        import tomllib
        with open(os.path.join(ROOT, "Rust", "pyproject.toml"), "rb") as fh:
            pyproject = tomllib.load(fh)
        assert pyproject["project"]["license"] == SPDX


class TestTheNoticeActuallyReachesTheArtifact:
    """Attribution is discharged by what a recipient gets, not by what is in
    the repository.

    NOTICE existed from v10.17.2 and satisfied nobody: an APK carried none of
    it. LICENSING_AUDIT.md listed "the APK must render it on a licences
    screen" as the one remaining delivery requirement for two releases. These
    are that requirement, written down so it cannot quietly regress -- someone
    deleting the asset copy or the screen has to delete a test too.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def build_script():
        return _read("android", "app", "build.gradle.kts")

    @staticmethod
    @pytest.fixture(scope="class")
    def about_screen():
        return _read("android", "app", "src", "main", "java", "org",
                     "otrv4plus", "android", "ui", "AboutScreen.kt")

    def test_notice_is_copied_into_the_apk_assets(self, build_script):
        assert "syncNoticeAsset" in build_script
        assert 'include("NOTICE")' in build_script
        assert "assets.srcDir(noticeAssetDir)" in build_script

    def test_the_copy_is_ordered_before_the_asset_merge(self, build_script):
        """The same class of bug the Python source sync hit: Gradle will not
        infer an edge between a task that writes a directory and one that
        reads it as a source. The losing order packages nothing, and the build
        stays green."""
        assert 'Regex("merge[A-Z]\\\\w*Assets")' in build_script

    def test_a_missing_notice_fails_the_build(self, build_script):
        """Rather than producing an APK whose licences screen is empty, which
        looks like a working screen with nothing to show."""
        assert "The APK must " in build_script
        assert "carry third-party attribution" in build_script

    def test_the_meta_inf_exclusion_says_what_it_removes(self, build_script):
        """`resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")` reads,
        to anyone auditing the build, like attribution being stripped. It is
        not -- those are empty duplicate marker stubs -- but an unexplained
        line that looks like a licence violation costs someone an afternoon."""
        assert "MARKER STUBS" in build_script
        assert "WHAT THIS DOES NOT DO: remove anyone's attribution" in build_script
        # And it must point at where the real attribution went, or the
        # explanation is only half of one.
        assert "syncNoticeAsset" in build_script.split("MARKER STUBS")[0] or \
            "NOTICE file" in build_script

    def test_the_screen_renders_the_packaged_notice(self, about_screen):
        """From the asset, not from a copy pasted into the source. A second
        copy in Kotlin would be one more thing to go stale, and it would go
        stale silently."""
        assert 'assets.open("NOTICE")' in about_screen

    def test_the_screen_carries_the_appropriate_legal_notices(self, about_screen):
        """AGPL §5(d): a copyright notice, the absence of warranty, which
        licence applies, and how to see it."""
        assert "Copyright (C) 2025-2026 muc111" in about_screen
        assert "NO WARRANTY" in about_screen
        assert "Affero" in about_screen
        assert "LICENSE-COMMERCIAL.md" in about_screen

    def test_the_screen_does_not_pretend_the_old_licence_was_withdrawn(
            self, about_screen):
        """The same promise LICENSE makes, made where a user of a binary can
        actually read it."""
        assert "v10.16.2" in about_screen
        assert "withdraws nothing" in about_screen

    def test_the_screen_names_where_the_source_is(self, about_screen):
        """AGPL §13 is the reason this licence was chosen over the GPL. An
        app that offers no route to its source undercuts the point."""
        assert "github.com/muc111/OTRv4Plus" in about_screen

    def test_the_screen_is_reachable(self):
        """A licences screen nothing navigates to discharges nothing. It is
        reached from the connection screen, which is the first thing the app
        shows, and from the contact list."""
        activity = _read("android", "app", "src", "main", "java", "org",
                         "otrv4plus", "android", "MainActivity.kt")
        assert "AboutScreen(" in activity
        for screen in ("ConnectScreen.kt", "ChatScreen.kt"):
            text = _read("android", "app", "src", "main", "java", "org",
                         "otrv4plus", "android", "ui", screen)
            assert "onOpenAbout" in text, "%s cannot reach it" % screen


class TestTheDocumentationDoesNotContradictItself:
    """A repository that states its own licence two ways is worse than one
    that states it badly: a reader cannot tell which is current."""

    def test_the_superseded_audit_section_says_so(self):
        """LICENSING_AUDIT.md §1 concluded, in the present tense, that the
        project is GPL-3.0. It is the working that led to the AGPL decision
        and is worth keeping -- but a reader landing mid-file saw the
        repository contradicting its own LICENSE."""
        audit = _read("LICENSING_AUDIT.md")
        heading = "## 1. The finding that governed the decision"
        assert heading in audit, "the §1 heading no longer marks itself historical"
        assert "historical" in audit.split(heading)[1][:400].lower()
        assert "Superseded by §0" in audit

    def test_the_audit_still_contains_the_working(self):
        """Marked historical, NOT deleted. The copyleft finding in §2-§5 is
        what made the commercial half possible, and a decision with its
        reasoning removed is indistinguishable from one taken at random."""
        audit = _read("LICENSING_AUDIT.md")
        assert "1. **Ship under GPL-3.0.**" in audit
        assert "3. **Dual-license.**" in audit

    def test_the_dependency_counts_are_reconciled(self):
        """Four numbers were in circulation with nothing saying they counted
        different things."""
        audit = _read("LICENSING_AUDIT.md")
        assert "### Counting the dependencies" in audit
        for figure in ("104", "133", "134", "137"):
            assert figure in audit, "%s is unexplained" % figure

    def test_the_readme_does_not_restate_a_count_of_its_own(self):
        """It said "109 crates", which matched nothing. A prose number drifts;
        NOTICE regenerates."""
        readme = _read("README.md")
        assert "109 crates" not in readme
        assert re.search(r"\d+ crates compiled into", readme) is None, (
            "the README is restating a crate count again; point at NOTICE")

    def test_the_readme_states_the_spdx_expression(self):
        readme = _read("README.md")
        assert SPDX in readme

    def test_the_readme_explains_the_gpl_transition_without_withdrawing_it(self):
        readme = _read("README.md")
        assert "v10.16.2" in readme
        assert "permanently" in readme
        assert "does not, and could not" in readme
