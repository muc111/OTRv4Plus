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
