"""The app must install under its own name, with its own icon.

Written because the docs were corrected and the code was not. The launcher
disguise was withdrawn on 2026-09-14 on Play-policy grounds, and five
documents plus two source comments were updated to say so -- while
`strings.xml` still said `Calculator` and the manifest declared no icon at
all. The app kept installing under a name that misrepresented it for another
four commits, through two handset test rounds, and nobody noticed because
nothing looked at the string.

That is the failure this file exists to stop: a decision recorded in prose and
not enforced anywhere. Google Play's Deceptive Behavior policy is about what
the app *presents*, and what it presents is this string and this icon, not the
paragraph explaining them.

These read the packaged resources rather than the build output, so they run
without an Android SDK.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "android", "app", "src", "main", "res")
MANIFEST = os.path.join(ROOT, "android", "app", "src", "main",
                        "AndroidManifest.xml")

pytestmark = pytest.mark.skipif(
    not os.path.exists(MANIFEST),
    reason="no android/ project in this checkout")

#: Names that would misrepresent the app in a launcher or a store listing.
#: Not an exhaustive list of every possible lie -- it is the specific one that
#: was specified, built toward, withdrawn, and then left in place.
DISGUISE_WORDS = ("calculator", "calc", "notepad", "flashlight", "torch",
                  "utility", "system service", "com.android")

#: Densities Android expects a launcher icon in. Missing one is not fatal --
#: Android scales -- but it is visibly fuzzy on the devices that wanted it, and
#: a silently missing asset is the kind of thing nobody checks twice.
DENSITIES = ("mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi")


def strings():
    tree = ET.parse(os.path.join(RES, "values", "strings.xml"))
    return {e.get("name"): (e.text or "") for e in tree.getroot()}


def manifest():
    return ET.parse(MANIFEST).getroot()


ANDROID = "{http://schemas.android.com/apk/res/android}"


class TestTheAppSaysWhatItIs:

    def test_the_name_is_not_a_disguise(self):
        name = strings().get("app_name", "")
        low = name.lower()
        for word in DISGUISE_WORDS:
            assert word not in low, (
                "app_name is %r. The launcher disguise was withdrawn; an app "
                "that installs under a name misrepresenting it is what Play's "
                "Deceptive Behavior policy is about, and it is what got this "
                "shipped for four commits after the decision." % name)

    def test_the_name_is_the_project(self):
        assert "otr" in strings().get("app_name", "").lower()

    def test_the_name_is_not_empty_or_a_placeholder(self):
        name = strings().get("app_name", "").strip()
        assert name, "app_name is empty"
        for bad in ("todo", "changeme", "app name", "myapp", "untitled"):
            assert bad not in name.lower(), name


class TestTheIconIsDeclared:

    def test_the_manifest_declares_an_icon(self):
        """It declared none at all, so Android fell back to its default. An
        app with the stock robot is not branded; it is unfinished."""
        app = manifest().find("application")
        assert app is not None
        assert app.get(ANDROID + "icon"), "no android:icon on <application>"

    def test_the_manifest_declares_a_round_icon(self):
        app = manifest().find("application")
        assert app.get(ANDROID + "roundIcon"), "no android:roundIcon"

    def test_the_adaptive_icon_exists(self):
        """minSdk is 26, so this pair is what every supported device uses."""
        path = os.path.join(RES, "mipmap-anydpi-v26", "ic_launcher.xml")
        assert os.path.exists(path), "no adaptive icon"
        root = ET.parse(path).getroot()
        assert root.tag == "adaptive-icon"
        assert root.find("foreground") is not None
        assert root.find("background") is not None

    @pytest.mark.parametrize("density", DENSITIES)
    def test_every_density_has_the_three_assets(self, density):
        d = os.path.join(RES, "mipmap-" + density)
        for asset in ("ic_launcher.png", "ic_launcher_round.png",
                      "ic_launcher_foreground.png"):
            path = os.path.join(d, asset)
            assert os.path.exists(path), "missing %s/%s" % (density, asset)
            assert os.path.getsize(path) > 0, "empty %s/%s" % (density, asset)

    def test_the_background_colour_is_defined(self):
        path = os.path.join(RES, "values", "ic_launcher_background.xml")
        assert os.path.exists(path)
        colours = {e.get("name"): (e.text or "")
                   for e in ET.parse(path).getroot()}
        value = colours.get("ic_launcher_background", "")
        assert re.fullmatch(r"#[0-9A-Fa-f]{6,8}", value), value

    def test_the_foreground_sizes_follow_the_density_ladder(self):
        """108dp at each density. A foreground authored at one size and copied
        to the rest is the usual way this goes wrong, and it shows as a blurry
        icon on exactly the devices nobody tests on."""
        from struct import unpack
        expected = {"mdpi": 108, "hdpi": 162, "xhdpi": 216,
                    "xxhdpi": 324, "xxxhdpi": 432}
        for density, want in expected.items():
            path = os.path.join(RES, "mipmap-" + density,
                                "ic_launcher_foreground.png")
            with open(path, "rb") as fh:
                head = fh.read(24)
            # PNG IHDR: width is bytes 16..20, big-endian.
            width = unpack(">I", head[16:20])[0]
            assert width == want, (
                "%s foreground is %dpx, expected %dpx"
                % (density, width, want))


class TestNoDisguiseRemainsInTheAndroidSources:

    def test_no_launcher_activity_is_named_for_a_disguise(self):
        for activity in manifest().iter("activity"):
            name = (activity.get(ANDROID + "name") or "").lower()
            for word in DISGUISE_WORDS:
                if word == "com.android":
                    continue
                assert word not in name, name

    def test_no_string_resource_advertises_one(self):
        for key, value in strings().items():
            low = (value or "").lower()
            for word in DISGUISE_WORDS:
                if word == "com.android":
                    continue
                assert word not in low, (
                    "string %r says %r" % (key, value))


class TestTheAndroidResourcesParse:
    """Every XML under android/ must be well-formed.

    This is the third time `--` inside an XML comment has broken a file in
    this project: once in `file_paths.xml`, then in the manifest and the
    adaptive icon on the same afternoon. It is illegal in XML, it is invisible
    while writing prose, and the failure surfaces as an aapt error a CI round
    trip later -- four minutes to find out that an em dash was wanted.

    So the check is a test rather than a habit.
    """

    @staticmethod
    def _xml_files():
        import glob
        out = []
        for pattern in ("android/**/*.xml",):
            out += glob.glob(os.path.join(ROOT, pattern), recursive=True)
        return [p for p in out if "/build/" not in p]

    def test_there_are_files_to_check(self):
        assert len(self._xml_files()) >= 5

    def test_every_one_parses(self):
        broken = {}
        for path in self._xml_files():
            try:
                ET.parse(path)
            except ET.ParseError as exc:
                broken[os.path.relpath(path, ROOT)] = str(exc)
        assert not broken, (
            "malformed XML. A doubled hyphen inside a comment is the usual "
            "cause and is illegal in XML; use an em dash: %r" % (broken,))

    def test_no_comment_contains_a_doubled_hyphen(self):
        """Caught by name, so the failure says what to do rather than
        'invalid token at line 6, column 51'."""
        offenders = []
        for path in self._xml_files():
            text = open(path, encoding="utf-8", errors="replace").read()
            for comment in re.findall(r"<!--(.*?)-->", text, flags=re.S):
                if "--" in comment:
                    offenders.append(os.path.relpath(path, ROOT))
        assert not offenders, (
            "`--` inside an XML comment is illegal; use an em dash: %r"
            % (sorted(set(offenders)),))
