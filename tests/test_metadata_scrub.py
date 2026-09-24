#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A photograph sent privately should not say where it was taken.

Android can now send files over an encrypted, SMP-verified session. A phone
photo carries GPS coordinates, a timestamp, the camera make and model and an
embedded thumbnail in its EXIF block; sending it with that intact would be
encrypting the message and attaching the answer. `android_bridge.metadata`
removes it on the user's say-so.

THE FIXTURES ARE REAL FILES. `tests/data/photo_with_gps.jpg` was written by
Pillow with genuine EXIF (Make, Model, DateTime and a GPS IFD) and an ICC
profile; `image_with_text.png` carries tEXt chunks; `image_with_exif.webp`
carries EXIF, XMP and an ICC profile. They are committed so the structural
tests need no imaging library. The tests that DECODE the result use Pillow,
which CI installs and requires -- a scrubber that produced an undecodable
file would be a scrubber nobody could use.

Verified once against Pillow when written: GPS, Make and DateTime gone, the
image decodes, every pixel identical, the ICC profile kept.
"""

import io
import os
import struct
import sys
import tempfile
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from android_bridge import metadata as M                        # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _read(name):
    with open(os.path.join(DATA, name), "rb") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def jpeg():
    return _read("photo_with_gps.jpg")


@pytest.fixture(scope="module")
def png():
    return _read("image_with_text.png")


@pytest.fixture(scope="module")
def webp():
    return _read("image_with_exif.webp")


def _pil():
    """Pillow's Image module: an independent decoder to check the result.

    Skipped where Pillow is simply not installed -- a developer machine --
    but FAILED under CI, which installs it (.github/workflows/python.yml).
    A security test must not turn into a silent skip because an environment
    lost a dependency: "the scrubbed photo still decodes, with the same
    pixels" is the half of this suite that says the scrubber is usable.
    """
    try:
        from PIL import Image
        return Image
    except ImportError:
        if os.environ.get("CI"):
            pytest.fail("Pillow is required in CI to decode scrubbed images")
        pytest.skip("Pillow is not installed here")


def _jpeg_segments(data):
    """(marker, bytes) for every segment before the scan, plus the scan."""
    out, i = [], 2
    while i < len(data):
        marker = data[i + 1]
        if marker == 0xDA:
            out.append((0xDA, data[i:]))
            break
        length = (data[i + 2] << 8) | data[i + 3]
        out.append((marker, data[i:i + 2 + length]))
        i += 2 + length
    return out


class TestTheFixtureIsWhatItClaims:
    """If these fail the rest proves nothing."""

    def test_the_jpeg_really_carries_exif_and_gps(self, jpeg):
        markers = [m for m, _ in _jpeg_segments(jpeg)]
        assert 0xE1 in markers, "the fixture has no APP1/Exif segment"
        assert b"PhoneMaker" in jpeg and b"Model X9" in jpeg
        assert b"2026:09:23" in jpeg

    def test_the_jpeg_carries_an_icc_profile(self, jpeg):
        assert 0xE2 in [m for m, _ in _jpeg_segments(jpeg)]

    def test_the_png_really_carries_text(self, png):
        assert b"tEXt" in png and b"Location" in png


class TestJpeg:

    def test_it_is_recognised(self, jpeg):
        assert M.kind_of(jpeg) == M.JPEG

    def test_the_camera_and_the_place_are_gone(self, jpeg):
        clean = M.scrub(jpeg)
        for leaked in (b"PhoneMaker", b"Model X9", b"2026:09:23", b"Exif\x00"):
            assert leaked not in clean, "%r survived the scrub" % leaked

    def test_no_app1_segment_survives(self, jpeg):
        """APP1 is where Exif AND XMP live, including GPS and the
        embedded thumbnail -- which is a second copy of the photo."""
        assert 0xE1 not in [m for m, _ in _jpeg_segments(M.scrub(jpeg))]

    def test_the_colour_profile_is_kept(self, jpeg):
        """A stripped ICC profile makes colours wrong, and a colour profile
        says nothing about the photographer."""
        before = [s for m, s in _jpeg_segments(jpeg) if m == 0xE2]
        after = [s for m, s in _jpeg_segments(M.scrub(jpeg)) if m == 0xE2]
        assert before and after == before

    def test_every_segment_that_is_not_metadata_is_byte_identical(self, jpeg):
        """The scrub removes; it never rewrites. Quantisation tables, the
        frame header, Huffman tables and the scan must come through exactly."""
        kept_before = [s for m, s in _jpeg_segments(jpeg)
                       if m not in (0xE1, 0xED, 0xFE)]
        after = [s for _, s in _jpeg_segments(M.scrub(jpeg))]
        assert after == kept_before

    def test_it_still_starts_and_ends_as_a_jpeg(self, jpeg):
        clean = M.scrub(jpeg)
        assert clean[:2] == b"\xff\xd8" and clean[-2:] == b"\xff\xd9"

    def test_it_still_decodes_with_the_same_pixels(self, jpeg):
        pil = _pil()
        before = pil.open(io.BytesIO(jpeg))
        after = pil.open(io.BytesIO(M.scrub(jpeg)))
        after.load()
        assert after.size == before.size
        assert after.tobytes() == before.tobytes(), (
            "scrubbing changed the picture, not just its metadata")
        assert dict(after.getexif()) == {}

    def test_the_finding_reports_what_is_there(self, jpeg):
        finding = M.examine(jpeg)
        assert finding.kind == M.JPEG
        assert finding.carries_metadata is True
        assert finding.metadata_bytes == len(jpeg) - len(M.scrub(jpeg)) > 0

    def test_scrubbing_is_idempotent(self, jpeg):
        once = M.scrub(jpeg)
        assert M.scrub(once) == once
        assert M.examine(once).carries_metadata is False


class TestPng:

    def test_the_text_chunks_are_gone(self, png):
        clean = M.scrub(png)
        assert b"tEXt" not in clean and b"Location" not in clean

    def test_it_still_decodes_to_the_same_pixels(self, png):
        """Decoded here with zlib, no imaging library: walk the chunks, check
        every CRC, inflate IDAT, compare."""
        def pixels(data):
            i, idat = 8, b""
            while i < len(data):
                (length,) = struct.unpack(">I", data[i:i + 4])
                ctype = data[i + 4:i + 8]
                body = data[i + 8:i + 8 + length]
                (crc,) = struct.unpack(">I", data[i + 8 + length:i + 12 + length])
                assert zlib.crc32(ctype + body) & 0xFFFFFFFF == crc, (
                    "%r has a bad CRC" % ctype)
                if ctype == b"IDAT":
                    idat += body
                i += 12 + length
            return zlib.decompress(idat)
        assert pixels(M.scrub(png)) == pixels(png)

    def test_the_critical_chunks_are_all_kept(self, png):
        clean = M.scrub(png)
        for critical in (b"IHDR", b"IDAT", b"IEND"):
            assert critical in clean


class TestWebp:
    """`image_with_exif.webp` was written by Pillow 12.3 as a lossless,
    extended-format WebP with an ICC profile, EXIF (Make, DateTime and a GPS
    IFD) and an XMP packet naming a place."""

    def test_the_fixture_carries_what_it_claims(self, webp):
        assert webp[:4] == b"RIFF" and webp[8:12] == b"WEBP"
        for chunk in (b"VP8X", b"ICCP", b"EXIF", b"XMP "):
            assert chunk in webp
        assert b"secret place" in webp

    def test_it_is_recognised(self, webp):
        assert M.kind_of(webp) == M.WEBP
        finding = M.examine(webp)
        assert finding.can_scrub and finding.carries_metadata

    def test_exif_and_xmp_are_gone_and_their_flags_cleared(self, webp):
        clean = M.scrub(webp)
        assert b"EXIF" not in clean and b"XMP " not in clean
        assert b"secret place" not in clean and b"CameraMaker" not in clean
        flags = clean[20]
        assert not flags & 0x08 and not flags & 0x04, (
            "VP8X still announces metadata the file no longer has")

    def test_the_colour_profile_and_image_are_kept(self, webp):
        clean = M.scrub(webp)
        assert b"ICCP" in clean and clean[20] & 0x20, "the ICC profile was lost"
        image = webp[webp.index(b"VP8L"):webp.index(b"EXIF")]
        assert image in clean, "the image data was altered"

    def test_the_riff_size_accounts_for_the_file(self, webp):
        clean = M.scrub(webp)
        assert struct.unpack("<I", clean[4:8])[0] + 8 == len(clean)

    def test_it_still_decodes_with_the_same_pixels(self, webp):
        pil = _pil()
        before = pil.open(io.BytesIO(webp))
        after = pil.open(io.BytesIO(M.scrub(webp)))
        after.load()
        assert after.size == before.size
        assert after.tobytes() == before.tobytes()
        assert dict(after.getexif()) == {}
        assert after.info.get("icc_profile"), "the ICC profile did not survive"

    def test_scrubbing_is_idempotent(self, webp):
        once = M.scrub(webp)
        assert M.scrub(once) == once
        assert M.examine(once).carries_metadata is False

    def test_a_webp_that_disagrees_with_its_own_size_is_untouched(self, webp):
        broken = webp[:-10]
        assert M.scrub(broken) == broken
        assert M.examine(broken).can_scrub is False


class TestACleanImageAsksNothing:
    """No metadata means no question: the Kotlin side sends without asking
    (MetadataChoice) when `carries_metadata` is False and `can_scrub` True.
    A clean image must therefore say exactly that -- not "unknown", which
    would put a false "cannot check" notice on it."""

    @pytest.mark.parametrize("name", ["photo_with_gps.jpg",
                                      "image_with_text.png",
                                      "image_with_exif.webp"])
    def test_an_already_clean_image_is_checkable_and_clean(self, name):
        clean = M.scrub(_read(name))
        finding = M.examine(clean)
        assert finding.can_scrub is True
        assert finding.carries_metadata is False
        assert finding.metadata_bytes == 0

    def test_a_clean_file_is_not_copied(self):
        clean = M.scrub(_read("image_with_exif.webp"))
        path = os.path.join(tempfile.mkdtemp(), "clean.webp")
        with open(path, "wb") as f:
            f.write(clean)
        assert M.scrub_file(path) == path


class TestWhatItWillNotPretend:
    """A format it does not understand comes back byte-identical and is
    reported as uncheckable -- never as clean."""

    @pytest.mark.parametrize("data", [
        b"%PDF-1.7 not an image",
        b"",
        b"hello world",
        b"PK\x03\x04 a zip",
        # HEIC and MP4: ISO-BMFF `ftyp` boxes. Their metadata is an item in
        # a `meta` box addressed by `iloc` offsets; this module does not
        # rewrite that, so it must say it cannot check rather than pass
        # them as clean.
        b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic",
        b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2",
        b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ",
    ])
    def test_an_unknown_format_is_untouched_and_unpromised(self, data):
        assert M.scrub(data) == data
        finding = M.examine(data)
        assert finding.can_scrub is False
        assert finding.carries_metadata is False

    def test_a_truncated_jpeg_is_not_half_rewritten(self, jpeg):
        """Recognised by its magic but broken: returned exactly as it was,
        and reported as uncheckable rather than clean."""
        broken = jpeg[:40]
        assert M.scrub(broken) == broken
        assert M.examine(broken).can_scrub is False

    def test_a_truncated_png_is_not_half_rewritten(self, png):
        broken = png[:30]
        assert M.scrub(broken) == broken
        assert M.examine(broken).can_scrub is False

    def test_a_lying_length_field_does_not_read_past_the_end(self, jpeg):
        tampered = bytearray(jpeg)
        tampered[4:6] = b"\xff\xff"          # first segment claims 64 KiB
        assert M.scrub(bytes(tampered)) == bytes(tampered)


class TestFiles:

    def test_scrub_file_writes_a_cleaned_copy_beside_the_original(self, jpeg):
        directory = tempfile.mkdtemp()
        original = os.path.join(directory, "holiday.jpg")
        with open(original, "wb") as handle:
            handle.write(jpeg)
        cleaned = M.scrub_file(original)
        try:
            assert cleaned != original
            assert os.path.basename(cleaned) == "holiday.jpg", (
                "the peer would see a different name from the one picked")
            assert os.path.dirname(os.path.dirname(cleaned)) == directory, (
                "the cleaned copy was written outside the staging directory")
            assert b"PhoneMaker" not in open(cleaned, "rb").read()
            assert open(original, "rb").read() == jpeg, (
                "the user's own file was modified")
        finally:
            os.unlink(cleaned)

    def test_nothing_to_remove_returns_the_original_path(self, jpeg):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "clean.jpg")
        with open(path, "wb") as handle:
            handle.write(M.scrub(jpeg))
        assert M.scrub_file(path) == path

    def test_a_missing_file_is_reported_as_uncheckable(self):
        assert M.examine_file("/nonexistent/x.jpg").can_scrub is False

    def test_no_imaging_library_is_imported(self):
        """The dependency licence guard is why this is hand-written, and a
        stdlib-only module is what keeps it out of that question."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(M))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names.add(node.module.split(".")[0])
        assert names <= set(sys.stdlib_module_names) | {"__future__"}, names
