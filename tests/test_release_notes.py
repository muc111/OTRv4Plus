# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The release notes are the email, so they are held to the same standard.

`.github/scripts/publish-experimental-apk.sh` writes the body of the rolling
`android-experimental` prerelease. GitHub mails release notes to watchers, so
that text is what somebody reads immediately before deciding whether to install
a binary that claims to protect their conversations.

WHY IT NEEDS TESTS AT ALL

Because it went stale, twice, in the direction that matters. It carried "this
APK has never been run" after the APK had been run, and then carried "plaintext
messaging in both directions -- NOT VERIFIED" after a handset had sent and
received messages. Both were wrong in the safe direction, which is why nobody
noticed: an understatement reads as caution.

The direction these tests guard is the OTHER one. A note that claims verified
where nothing was verified is the failure this project cannot have, and the
claims most likely to drift are the ones about encryption and audio, because
those are the two whose code is finished and whose device gates are not.

WHAT THESE CANNOT DO

They cannot check that a sentence is true. They check that the notes stay tied
to things that ARE checkable: the version comes from the build file, the open
gates in `ANDROID_XMPP_MILESTONE.md` §7 are still named as open, and no claim
of device verification is made for one of them.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, ".github", "scripts", "publish-experimental-apk.sh")
GRADLE = os.path.join(ROOT, "android", "app", "build.gradle.kts")
MILESTONE = os.path.join(ROOT, "ANDROID_XMPP_MILESTONE.md")


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def script():
    return _read(SCRIPT)


@pytest.fixture(scope="module")
def notes(script):
    """Just the heredoc that becomes the release body."""
    start = script.index("cat > notes.md <<EOF")
    return script[start:script.index("\nEOF\n", start)]


class TestTheVersionIsReadRatherThanRestated:
    """The same rule `CORE` already follows. A version typed into a release
    note is a version that can claim something the binary does not carry."""

    def test_the_app_version_comes_from_the_build_file(self, script):
        assert "build.gradle.kts" in script
        assert "versionName" in script
        assert "versionCode" in script

    def test_a_version_that_cannot_be_read_fails_the_publish(self, script):
        """Silently publishing with a blank version would be worse than not
        publishing: the provenance table is how a downloaded APK is traced."""
        assert 'if [ -z "$APP" ] || [ -z "$CODE" ]; then' in script
        assert "exit 1" in script[script.index('if [ -z "$APP"'):]

    def test_no_version_number_is_hardcoded_in_the_notes(self, notes):
        """`${CORE}` and `${APP}` are substitutions. A literal `0.4.0` here
        would survive the next bump and start lying."""
        literal = re.findall(r"(?<![\w.${])\d+\.\d+\.\d+(?![\w.}])", notes)
        assert literal == [], (
            "the notes hardcode %s; read it from the build file instead"
            % literal)

    def test_the_declared_version_is_still_a_prerelease(self):
        """`-experimental` in the versionName and `--prerelease` on the tag
        say the same thing, and they must not disagree."""
        gradle = _read(GRADLE)
        name = re.search(r'versionName\s*=\s*"([^"]+)"', gradle).group(1)
        assert "-experimental" in name, (
            "versionName is %s: the suffix comes off when the open gates in "
            "ANDROID_XMPP_MILESTONE.md section 7 do, and this test with it"
            % name)
        assert "--prerelease" in _read(SCRIPT)


class TestTheOpenGatesAreStillDeclaredOpen:
    """The list that must not quietly shrink.

    Each of these is a section 7 gate that has not been run on a handset. The
    note names it under "NOT verified", and a reader decides what to trust
    from that list.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def unverified(notes):
        start = notes.index("## NOT verified")
        return notes[start:notes.index("\n## ", start + 4)]

    def test_otr_smp_and_files_are_claimed_only_as_device_reports(
            self, notes, unverified):
        """Closed by the owner's rc.1 handset run with a Termux peer
        (ANDROID_CALL_AND_FILE_DEVICE_TEST.md, "What the rc.1 handset run
        established"; milestone 7.0a). They move to the device section, which
        is attributed to that report -- and nowhere else claims them."""
        start = notes.index("## Verified on a real device")
        device = notes[start:notes.index("\n## ", start + 4)]
        for claim in ("OTRv4+ end to end", "SMP", "file transfer"):
            assert claim in device, claim
        assert "OTR end to end" not in unverified, (
            "OTR is both claimed verified and listed as unverified")
        record = _read(os.path.join(ROOT, "ANDROID_CALL_AND_FILE_DEVICE_TEST.md"))
        assert "What the rc.1 handset run established" in record, (
            "the device claim has lost the record it rests on")

    def test_voice_is_never_claimed_as_device_verified(self, notes):
        """The direction that matters: a call has not been made from the APK,
        so the device section must not claim voice or calls."""
        start = notes.index("## Verified on a real device")
        device = notes[start:notes.index("\n## ", start + 4)].lower()
        for word in ("voice", "call", "audio"):
            assert word not in device, (
                "the device section mentions %r; no call has run on a "
                "handset" % word)

    def test_voice_is_named_as_unverified(self, unverified):
        """Verified under Termux, which is a different process model. The one
        test that would show the APK transmits audio rather than silence
        cannot run off-device -- see SKIP_AUDIT.md."""
        assert "Voice" in unverified

    def test_the_gate_document_is_pointed_at(self, notes):
        assert "ANDROID_XMPP_MILESTONE.md" in notes

    def test_the_milestone_still_has_those_gates_open(self):
        """If section 7 is signed off, this file is what should be revisited
        -- not the other way round."""
        milestone = _read(MILESTONE)
        gate = milestone[milestone.index("## 7. The handset gate"):]
        assert "This milestone is not signed off." in gate, (
            "the handset gate reads as closed; the release notes still "
            "declare voice unverified, and one of the two is wrong")
        # Matched on the sentence rather than the status line, which has
        # already moved once -- from "not performed" to "PARTIAL" -- and will
        # move again as items close. It is the sign-off that matters.
        assert re.search(r"physical Android acceptance\s+(?:is\s+)?"
                         r"(?:not performed|PARTIAL)", gate, re.I), (
            "the status line no longer says whether acceptance has been done")


class TestNothingClaimsMoreThanWasDone:

    def test_the_stale_never_been_run_line_is_gone_from_the_notes(self, notes):
        """It was true, then it was not, and it stayed in the file. Pinned
        because an outdated caution reads as caution and survives review.

        Scoped to the NOTES rather than the script: the script's header quotes
        the old line to say it was corrected, which is the record of the
        change and should not be deleted to satisfy a grep."""
        assert "this APK has never been run" not in notes
        assert "nobody has yet run this APK" not in notes

    def test_the_correction_is_recorded_rather_than_quietly_made(self, script):
        """A claim about a security tool that turns out to be wrong gets
        corrected in the open. Both places this line lived say so."""
        header = script[:script.index("cat > notes.md")]
        assert "no longer true" in header or "corrected" in header

    def test_the_device_list_is_attributed_to_a_report(self, notes):
        """"Verified on a real device" is a claim about somebody's handset,
        not about CI. It says so, and says which handset."""
        start = notes.index("## Verified on a real device")
        section = notes[start:notes.index("\n## ", start + 4)]
        assert "Reported from a handset" in section
        assert "arm64-v8a" in section

    def test_ci_claims_and_device_claims_are_separate_sections(self, notes):
        """They are different kinds of evidence and a reader has to be able
        to tell which one is behind any given line."""
        assert "## Verified on a real device" in notes
        assert "## Verified by CI" in notes
        assert notes.index("## Verified on a real device") < \
            notes.index("## Verified by CI")

    def test_it_still_points_at_the_reference_implementation(self, notes):
        """Somebody who needs a client that works today needs to be told
        where it is, in the same breath as being told this one is not it."""
        assert "Termux" in notes

    def test_it_does_not_claim_the_apk_is_a_release(self, notes):
        assert "EXPERIMENTAL" in notes
        assert "not a release" in notes

    def test_the_diagnostic_controls_are_named_as_the_app_labels_them(
            self, notes):
        """A note that sends somebody to a screen by the wrong name is a note
        that sends them to logcat."""
        ui = os.path.join(ROOT, "android", "app", "src", "main", "java",
                          "org", "otrv4plus", "android", "ui")
        shell = _read(os.path.join(ui, "DevShellScreen.kt"))
        for label in ("Share error log", "Export start-up report"):
            if label in notes:
                assert 'Text("%s")' % label in shell, (
                    "the notes name a control called '%s' that the Debug "
                    "screen does not have" % label)
