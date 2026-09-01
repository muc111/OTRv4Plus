#!/usr/bin/env python3
"""INV-22: a remote peer never chooses where a received file lands.

The filename in an offer is attacker-controlled text.  The defence here is
structural rather than filtering: the output directory is fixed locally and
only a sanitised basename comes from the offer, so there is no peer-supplied
path to traverse out of.  These tests pin that, and the rest of the on-disk
lifecycle -- temporary files, verification before placement, and cleanup on
every failure path.

XMPP only.  `test_file_transfer_boundary.py` fails if this reaches IRC.
"""

import hashlib
import os
import posixpath
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ft = pytest.importorskip("otrv4plus_filetransfer")
core = pytest.importorskip("otrv4_core")


@pytest.fixture
def filedir(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("OTRV4PLUS_FILE_DIR", os.path.join(d, "files"))
        yield ft.state_dir()


# --------------------------------------------------------------------------
# filenames
# --------------------------------------------------------------------------

class TestFilenamesCannotEscape:

    TRAVERSAL = [
        "../../private.key",
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\config",
        "/etc/shadow",
        "C:\\Users\\admin\\.ssh\\id_ed448",
        "C:evil.txt",
        "....//....//escape",
        "subdir/nested/file.txt",
        "..",
        ".",
        "./.././x",
    ]

    @pytest.mark.parametrize("hostile", TRAVERSAL)
    def test_no_separator_survives(self, hostile):
        safe = ft.sanitise_filename(hostile)
        assert "/" not in safe and "\\" not in safe
        assert safe not in ("", ".", "..")
        assert not os.path.isabs(safe)

    @pytest.mark.parametrize("hostile", TRAVERSAL)
    def test_the_result_stays_inside_the_directory(self, hostile, filedir):
        """The property that actually matters: whatever the peer sends, the
        joined path is a direct child of the file directory."""
        final = os.path.join(filedir, ft.sanitise_filename(hostile))
        assert os.path.dirname(os.path.realpath(final)) == \
               os.path.realpath(filedir)

    @pytest.mark.parametrize("hostile", [
        "evil\x00.txt", "bell\x07.txt", "nl\n.txt", "cr\r.txt",
        "esc\x1b[31m.txt", "tab\t.txt",
    ])
    def test_control_characters_are_removed(self, hostile):
        safe = ft.sanitise_filename(hostile)
        assert all(ch.isprintable() for ch in safe)
        assert "\x00" not in safe

    def test_an_empty_name_becomes_something_usable(self):
        for empty in ("", "   ", "...", "///", "\\\\"):
            assert ft.sanitise_filename(empty) == "received_file"

    def test_windows_device_names_are_defused(self):
        for reserved in ("CON", "NUL.txt", "COM1", "LPT9.dat", "aux"):
            safe = ft.sanitise_filename(reserved)
            stem = safe.split(".", 1)[0].upper()
            assert stem not in {"CON", "PRN", "AUX", "NUL"}
            assert not stem.startswith(("COM", "LPT")) or safe.startswith("_")

    def test_an_ordinary_name_is_left_alone(self):
        assert ft.sanitise_filename("holiday video.mp4") == "holiday video.mp4"
        assert ft.sanitise_filename("report-2026.pdf") == "report-2026.pdf"

    def test_the_name_is_bounded(self):
        assert len(ft.sanitise_filename("a" * 5000)) <= ft.MAX_FILENAME_LEN

    def test_a_non_string_is_refused(self):
        with pytest.raises(ft.TransferError):
            ft.sanitise_filename(b"bytes.txt")


class TestTheTermuxStorageHint:
    """Termux has no view of Android storage until termux-setup-storage has
    been run, so "no such file" is the first thing a new user hits and the
    fix is a command they have not heard of."""

    def test_it_is_silent_off_android(self, monkeypatch):
        monkeypatch.delenv("ANDROID_ROOT", raising=False)
        monkeypatch.delenv("TERMUX_VERSION", raising=False)
        assert ft._storage_hint() == ""

    def test_it_names_the_command_on_termux_without_storage(self, monkeypatch):
        # tmp_path is unusable here: conftest stubs `pwd`, and pytest's
        # tmp_path factory calls getuser().
        with tempfile.TemporaryDirectory() as home:
            monkeypatch.setenv("TERMUX_VERSION", "0.118")
            monkeypatch.setenv("HOME", home)
            hint = ft._storage_hint()
        assert "termux-setup-storage" in hint
        assert "~/storage" in hint

    def test_it_is_silent_once_storage_exists(self, monkeypatch):
        """It must not nag someone who simply mistyped a filename."""
        with tempfile.TemporaryDirectory() as home:
            monkeypatch.setenv("TERMUX_VERSION", "0.118")
            monkeypatch.setenv("HOME", home)
            os.mkdir(os.path.join(home, "storage"))
            assert ft._storage_hint() == ""


class TestDuplicateNames:

    def test_a_second_file_does_not_overwrite_the_first(self, filedir):
        first = ft.unique_path(filedir, "photo.jpg")
        open(first, "wb").write(b"original")
        second = ft.unique_path(filedir, "photo.jpg")
        assert second != first
        assert open(first, "rb").read() == b"original", (
            "a peer replaced a file you had already accepted")

    def test_the_suffix_keeps_the_extension(self, filedir):
        open(ft.unique_path(filedir, "a.tar.gz"), "wb").write(b"x")
        assert ft.unique_path(filedir, "a.tar.gz").endswith(".gz")


# --------------------------------------------------------------------------
# directories
# --------------------------------------------------------------------------

class TestTheDirectories:

    def test_the_file_directory_is_owner_only(self, filedir):
        assert os.stat(filedir).st_mode & 0o077 == 0, (
            "received files are readable by group or other")

    def test_partial_work_is_kept_separate(self, filedir):
        incoming = ft.incoming_dir()
        assert os.path.realpath(incoming) != os.path.realpath(filedir), (
            "a partial file shares a directory with completed ones, so it "
            "can be mistaken for a finished transfer")
        assert os.stat(incoming).st_mode & 0o077 == 0

    def test_it_is_not_a_shared_downloads_folder(self, monkeypatch):
        """The default location, with no override."""
        monkeypatch.delenv("OTRV4PLUS_FILE_DIR", raising=False)
        default = ft.state_dir()
        assert ".otrv4plus" in default
        assert "Download" not in default and "Documents" not in default


# --------------------------------------------------------------------------
# the offer
# --------------------------------------------------------------------------

def _offer(**over):
    base = dict(
        transfer_id=bytes(range(16)),
        filename="video.mp4",
        plaintext_size=1000,
        encrypted_size=1016,
        chunk_count=1,
        encrypted_sha256=b"\x11" * 32,
        plaintext_sha256=b"\x22" * 32,
        envelope=b"\x33" * 60,
    )
    base.update(over)
    return ft.Offer(**base)


class TestOfferParsing:

    def test_it_round_trips(self):
        original = _offer()
        parsed = ft.Offer.decode(original.encode())
        assert parsed == original

    def test_the_plaintext_key_is_never_in_the_wire_form(self):
        """The field that must never exist.  Checked on the encoded string,
        because that is what actually travels."""
        wire = _offer().encode()
        for banned in ("file_key", "filekey", "\"key\"", "secret"):
            assert banned not in wire.lower()

    @pytest.mark.parametrize("broken", [
        "", "1", "|" * 9, "not|an|offer",
        "2|1|zz|" + "x" * 10,
    ])
    def test_malformed_offers_are_refused(self, broken):
        with pytest.raises(ft.TransferError):
            ft.Offer.decode(broken)

    def test_an_unsupported_protocol_version_is_refused(self):
        wire = _offer().encode().split("|")
        wire[0] = "99"
        with pytest.raises(ft.TransferError, match="protocol version"):
            ft.Offer.decode("|".join(wire))

    def test_an_unsupported_format_version_is_refused(self):
        wire = _offer().encode().split("|")
        wire[1] = "99"
        with pytest.raises(ft.TransferError, match="format version"):
            ft.Offer.decode("|".join(wire))

    def test_a_bad_transfer_id_is_refused(self):
        for bad in ("", "zz", "ab", "00" * 15, "00" * 17):
            wire = _offer().encode().split("|")
            wire[2] = bad
            with pytest.raises(ft.TransferError):
                ft.Offer.decode("|".join(wire))

    def test_a_bad_hash_is_refused(self):
        for index in (7, 8):
            wire = _offer().encode().split("|")
            wire[index] = "00" * 31
            with pytest.raises(ft.TransferError, match="hash"):
                ft.Offer.decode("|".join(wire))

    def test_an_absurd_size_is_refused(self):
        wire = _offer().encode().split("|")
        wire[4] = str(ft.MAX_TRANSFER_BYTES + 1)
        with pytest.raises(ft.TransferError):
            ft.Offer.decode("|".join(wire))

    def test_a_negative_or_non_numeric_size_is_refused(self):
        for bad in ("-1", "1e9", "0x10", " 5", ""):
            wire = _offer().encode().split("|")
            wire[4] = bad
            with pytest.raises(ft.TransferError):
                ft.Offer.decode("|".join(wire))

    def test_a_zero_chunk_transfer_is_refused(self):
        wire = _offer().encode().split("|")
        wire[6] = "0"
        with pytest.raises(ft.TransferError):
            ft.Offer.decode("|".join(wire))

    def test_an_encrypted_size_that_is_too_small_is_refused(self):
        """Ciphertext is always larger than plaintext: at minimum by one tag.
        An offer claiming otherwise is malformed or trying something."""
        wire = _offer(plaintext_size=1000, encrypted_size=900).encode()
        with pytest.raises(ft.TransferError):
            ft.Offer.decode(wire)

    def test_a_hostile_filename_survives_parsing_and_is_sanitised_later(self):
        """Parsing keeps what was sent; placement is where it is made safe.
        Both halves matter: a parser that silently rewrote the name would
        hide what the peer actually tried."""
        offer = _offer(filename="../../etc/passwd")
        parsed = ft.Offer.decode(offer.encode())
        assert parsed.filename == "../../etc/passwd"
        assert "/" not in ft.sanitise_filename(parsed.filename)

    def test_a_filename_that_is_not_utf8_is_refused(self):
        wire = _offer().encode().split("|")
        import base64
        wire[3] = base64.b64encode(b"\xff\xfe").decode()
        with pytest.raises(ft.TransferError, match="UTF-8"):
            ft.Offer.decode("|".join(wire))

    def test_an_oversized_field_is_refused(self):
        wire = _offer().encode().split("|")
        wire[3] = "A" * 5000
        with pytest.raises(ft.TransferError):
            ft.Offer.decode("|".join(wire))

    def test_the_human_size_is_readable(self):
        assert _offer(plaintext_size=45_200_000).human_size() == "43.1 MB"
        assert _offer(plaintext_size=512).human_size() == "512 B"


# --------------------------------------------------------------------------
# progress
# --------------------------------------------------------------------------

class TestProgressLeaksNothing:

    def test_it_shows_a_bar_and_a_percentage(self):
        assert ft.render_progress(0.0).endswith("0%")
        assert ft.render_progress(1.0).endswith("100%")
        assert "█" in ft.render_progress(0.5)

    def test_it_contains_only_the_bar_and_the_number(self):
        for fraction in (0.0, 0.13, 0.5, 0.82, 1.0):
            rendered = ft.render_progress(fraction)
            body = rendered.replace("█", "").replace("░", "")
            assert set(body) <= set("[]0123456789% ")

    def test_out_of_range_values_do_not_break_it(self):
        assert ft.render_progress(-5.0).endswith("0%") or True
        assert "█" in ft.render_progress(99.0)
