#!/usr/bin/env python3
"""OTRv4+ file transfer — /sendfile.  XMPP only.

SCOPE
=====
This module is for the XMPP client.  The IRC client has no file transfer and
must not acquire one through this module: nothing here is imported by
``otrv4+.py``, and ``tests/test_file_transfer_boundary.py`` fails if that
changes.

WHERE THE LINE IS
=================
Every secret lives in Rust.  This module reads the file, frames the offer,
pumps sealed chunks through whatever transport it was given, and writes the
result to disk.  It holds a ``RustFileSender`` / ``RustFileReceiver`` handle
and never a key -- there is no accessor to hold one with.

TRANSPORT INDEPENDENCE
======================
The engine takes a `send` callable and is fed inbound control lines.  It does
not know what carries them.  Phase A passes it the XMPP client's OTR channel;
a later phase can pass it an I2P SAM stream without changing the protocol, the
file format, the integrity checks or the storage handling.  That is the whole
reason the pump is a parameter rather than a method.

WHY NOT A TLV
=============
Voice signalling rides the OTR channel as a prefixed message body, handled
entirely in ``otrv4plus_xmpp.py``.  Following that pattern means this feature
needs no change to the shared TLV code in ``otrv4+.py``, and therefore cannot
alter IRC behaviour even accidentally.

WHAT THE RECEIVER TRUSTS
========================
Nothing in the offer, until it authenticates.  The filename is remote input
and only its sanitised basename is ever used; the sizes are remote input and
are checked against what actually arrives; the hashes are remote input and are
verified against what was actually decrypted.  The key envelope is the one
field that is self-authenticating, and it fails closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

try:
    import otrv4_core as _core
except Exception:                                # pragma: no cover
    _core = None


# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

#: Control-message prefix, matching the voice module's CALL_PREFIX pattern.
FILE_PREFIX = "?OTRv4-FILE:"

PROTOCOL_VERSION = 2          # the offer/accept protocol
FORMAT_VERSION = 1            # the encrypted-file format, mirrored from Rust

#: Base64 of a 64 KiB chunk is ~87 KiB, which is comfortable for an XMPP
#: stanza but not for anything smaller.  A future SAM-stream pump can raise
#: this without touching the format: it is a transport parameter, not a
#: cryptographic one.
WIRE_CHUNK_PLAIN = 16 * 1024

MAX_FILENAME_LEN = 120
MAX_OFFER_FIELD = 512
#: A cap so a hostile offer cannot make us reserve unbounded disk.
MAX_TRANSFER_BYTES = 2 * 1024 * 1024 * 1024

#: How long an un-answered offer stays live.
OFFER_TIMEOUT_S = 300.0


class TransferError(Exception):
    """A transfer failed.  The message is safe to show; it never quotes key
    material, only sizes, counts and reasons."""


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

def state_dir() -> str:
    """The application-private directory received files land in.

    Not a shared Downloads folder: a received file is the output of an
    authenticated private session and should not be world-readable by
    default.  0700, created if missing.

    NOTE ON WHAT THIS PROTECTS.  On Termux and Linux this is filesystem
    permissions, not encryption -- the same limitation ANDROID_STORAGE_AUDIT
    records for the identity and SMP stores.  A decrypted file on disk is a
    decrypted file on disk.
    """
    base = os.environ.get("OTRV4PLUS_FILE_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".otrv4plus", "files")
    os.makedirs(base, mode=0o700, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except OSError:
        pass
    return base


def _storage_hint() -> str:
    """Explain the Termux storage wall, but only when it is the likely cause.

    Termux's home is inside the app's private data directory and has no view
    of Android storage until `termux-setup-storage` has been run once.  A user
    typing `/sendfile photo.jpg` on a fresh install gets "no such file" and no
    clue why, because the photo genuinely is not reachable -- and the fix is a
    command they have never heard of rather than a different path.

    Silent when ~/storage exists, so it never nags someone who simply typo'd.
    """
    on_android = ("ANDROID_ROOT" in os.environ
                  or "TERMUX_VERSION" in os.environ)
    if not on_android:
        return ""
    if os.path.exists(os.path.join(os.path.expanduser("~"), "storage")):
        return ""
    return ("  (Termux cannot see Android storage yet — run "
            "`termux-setup-storage` once, then use a path under ~/storage, "
            "e.g. ~/storage/dcim/Camera/photo.jpg)")


def incoming_dir() -> str:
    """Where partial work lives.  Separate from the finished directory so a
    partial file can never be mistaken for a complete one -- the only thing
    that ever appears in the finished directory is a fully verified file,
    placed there by an atomic rename."""
    d = os.path.join(state_dir(), ".incoming")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


def sanitise_filename(raw: str) -> str:
    """Reduce a peer-supplied name to a safe basename.

    The peer never selects a path.  The output directory is fixed locally and
    only the basename comes from the offer, so path traversal is not filtered
    out of a path -- there is no peer-supplied path to filter.  This function
    exists for the rest: separators, control characters, NUL, Windows drive
    prefixes, reserved device names, leading dots, and the empty string.

    Returns a name that is guaranteed non-empty and contains no separator.
    """
    if not isinstance(raw, str):
        raise TransferError("filename is not text")
    name = raw.replace("\x00", "")
    # Take the last component under BOTH separators: a Windows-style name is
    # untrusted input on a POSIX box too, and os.path.basename would keep the
    # backslashes.
    # Redundant with the character filter below, which maps both separators
    # to "_" anyway -- mutation testing confirmed removing this line changes
    # no outcome.  Kept because it makes the intent explicit at the point a
    # reader looks for it, and because the filter could later be relaxed.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    # A drive prefix survives basename ("C:evil"), so strip it explicitly.
    if len(name) > 1 and name[1] == ":":
        name = name[2:]
    name = "".join(ch for ch in name if ch.isprintable())
    name = _SAFE_NAME.sub("_", name).strip(" .")
    # "..", "." and the empty string all reduce to nothing usable.
    if not name or set(name) <= {"_"}:
        name = "received_file"
    # Windows reserved device names, in case the file is ever copied there.
    stem = name.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[1-9]", stem):
        name = "_" + name
    return name[:MAX_FILENAME_LEN]


# --------------------------------------------------------------------------
# picking a file to send (Android / Termux)
# --------------------------------------------------------------------------

#: How long to leave the Android picker open before giving up.  Long, because
#: a human is scrolling through a gallery, not a machine answering.
PICKER_TIMEOUT_S = 180.0

#: `termux-storage-get` does NOT wait for the human.  It hands the intent to
#: the Termux:API app and exits, so the shell command returns in milliseconds
#: and the chosen file lands at the destination path some seconds later, when
#: the chooser closes.  Checking for the file the instant the command returns
#: therefore always finds nothing, and reports "no file chosen" while the
#: gallery is still on screen -- which is exactly what a device test showed.
#: The picker is polled for the file instead.
_PICK_POLL_S = 0.3

#: The copy is a stream, so an existing file may still be filling.  A size
#: that has not moved across this many consecutive polls is taken as done;
#: three at 0.3s is ~0.9s of quiet, far longer than a pause inside a copy from
#: local storage, and shorter than anyone will notice.
_PICK_STABLE_SAMPLES = 3

#: Staged copies are named `pick-<ms>` until they are sealed, at which point
#: they are renamed to `image-...`/`document-...`.  So anything still called
#: `pick-*` is either in flight or was abandoned, and only those are swept --
#: never a file a transfer might be reading.
_STAGE_PREFIX = "pick-"

#: Destinations we stopped waiting for.  The Termux:API app may still write to
#: one after we have given up, leaving a PLAINTEXT copy of whatever the user
#: chose sitting on disk.  We cannot wait for it, so we remember it and delete
#: it at the next pick.
_ABANDONED_PICKS = set()

#: Enough magic numbers to name the things people actually send.  The picker
#: does not tell us what the file was called, so the type is sniffed from its
#: first bytes rather than trusted from an extension that no longer exists.
_MAGIC = (
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gz"),
    (b"ID3", "mp3"),
    (b"OggS", "ogg"),
    (b"fLaC", "flac"),
    (b"\x00\x00\x01\xba", "mpg"),
)


def sniff_extension(head: bytes) -> str:
    """Best-effort file type from the first bytes.  Never raises."""
    if not head:
        return "bin"
    for magic, ext in _MAGIC:
        if head.startswith(magic):
            return ext
    # ISO base media (mp4, m4a, mov, 3gp) puts a size before the brand.
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand.startswith(b"qt"):
            return "mov"
        if brand.startswith(b"M4A"):
            return "m4a"
        return "mp4"
    if head.startswith(b"RIFF") and len(head) >= 12:
        if head[8:12] == b"WEBP":
            return "webp"
        if head[8:12] == b"WAVE":
            return "wav"
    try:
        head.decode("utf-8")
        return "txt"
    except UnicodeDecodeError:
        return "bin"


def staging_dir() -> str:
    """Where a picked file is staged before it is sealed.

    Inside the private file directory at 0700, not the Termux home, because
    for the moments between picking and sealing this holds a PLAINTEXT copy
    of whatever the user chose.  The caller deletes it as soon as the file
    has been sealed.
    """
    d = os.path.join(state_dir(), ".picked")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _sweep_abandoned_picks(staging: str, older_than: float,
                           now: float = None) -> int:
    """Delete staged copies nobody is going to seal.  Returns how many went.

    Two kinds are swept, and only files still called `pick-*`, because a file
    a transfer is actually reading has already been renamed:

      * one we stopped waiting for, which the picker may have written after we
        gave up -- deleted on sight, however new, since we know it is orphaned;
      * anything older than `older_than` seconds, which covers a copy left
        behind by a crash or a kill.

    These are PLAINTEXT copies of whatever the user chose, so leaving them is
    not a tidiness problem.
    """
    if now is None:
        now = time.time()
    removed = 0
    for path in sorted(_ABANDONED_PICKS):
        if os.path.dirname(path) != staging:
            # A staging directory from a previous run of the process (the
            # tests move it, and OTRV4PLUS_FILE_DIR can change).  If it is
            # gone there is nothing left to delete, so stop tracking it.
            if not os.path.isdir(os.path.dirname(path)):
                _ABANDONED_PICKS.discard(path)
            continue
        try:
            os.unlink(path)
            removed += 1
        except FileNotFoundError:
            pass
        except OSError:
            continue
        _ABANDONED_PICKS.discard(path)
    try:
        names = os.listdir(staging)
    except OSError:
        return removed
    for name in names:
        if not name.startswith(_STAGE_PREFIX):
            continue
        path = os.path.join(staging, name)
        try:
            if now - os.path.getmtime(path) < older_than:
                continue
            os.unlink(path)
            removed += 1
        except OSError:
            continue
    return removed


def _await_picked_file(path: str, deadline: float, sleeper=time.sleep,
                       clock=time.monotonic) -> bool:
    """Wait for the chooser to deliver `path`, complete.  True if it arrived.

    Returns as soon as the size has held steady, so a normal pick costs about
    a second of waiting past the tap and not the whole deadline.  A cancelled
    chooser is indistinguishable from a slow one -- nothing is written either
    way -- so backing out costs the caller the full deadline.  That is why the
    caller says out loud that it is waiting.
    """
    stable = 0
    last = -1
    while True:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        if size > 0 and size == last:
            stable += 1
            if stable >= _PICK_STABLE_SAMPLES:
                return True
        else:
            stable = 0
        last = size
        if clock() >= deadline:
            # One last look: the file may have completed inside the final
            # sleep, and giving up on a file that is sitting right there
            # would be the same bug in a smaller window.
            return size > 0 and os.path.getsize(path) == size
        sleeper(_PICK_POLL_S)


def pick_file(runner=None, which=None, timeout: float = PICKER_TIMEOUT_S,
              sleeper=time.sleep, clock=time.monotonic,
              on_wait=None) -> str:
    """Open the Android file picker; return the path to the staged copy.

    `termux-storage-get` copies the chosen file to a path we name, so the
    user taps a photo in the normal Android chooser and it lands somewhere we
    control.  Three consequences worth knowing:

      * **The command returns before the human does.**  It hands the intent to
        the Termux:API app and exits immediately; the file appears at our path
        only when the chooser closes.  So the destination is polled until it
        turns up and stops growing, and the shell exit status says nothing
        about whether anything was picked.

      * **The original filename does not survive.**  The picker reports only
        the bytes, so the name is rebuilt from the file's magic number and a
        timestamp.  A peer receives `image-20260901-143022.jpg`, not
        `IMG_2891.jpg`.  That is a cosmetic loss and a small privacy gain --
        camera filenames carry sequence numbers, and a name someone typed can
        say more than they meant it to.  `/sendfile <path>` still preserves
        the name exactly when that matters.

      * **The staged copy is plaintext.**  It lives at 0700 under the private
        file directory and the caller removes it once the file is sealed.

    `on_wait` is called once, if we end up waiting, so the caller can tell the
    user the client has not hung.  `runner`, `which`, `sleeper` and `clock`
    are injected so this is testable without an Android device.
    """
    import subprocess

    if runner is None:
        def runner(argv, timeout):
            try:
                proc = subprocess.run(argv, capture_output=True,
                                      timeout=timeout)
                return proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                return 124, b"", b"timed out"
            except OSError as exc:
                return 127, b"", str(exc).encode()

    if which is None:
        import shutil
        which = shutil.which

    # The apt package installs shell shims; the Termux:API *app* is what
    # actually shows the picker.  Missing app means the shim exists and the
    # call hangs, so say which half is absent rather than timing out.
    if which("termux-storage-get") is None:
        raise TransferError(
            "the file picker needs termux-api: run `pkg install termux-api`, "
            "and install the Termux:API app from F-Droid as well -- the "
            "package alone is only shell shims")

    staging = staging_dir()
    _sweep_abandoned_picks(staging, older_than=timeout + 60.0)

    staged = os.path.join(staging, "%s%d" % (_STAGE_PREFIX,
                                             int(time.time() * 1000)))
    started = clock()
    rc, _out, err = runner(['termux-storage-get', staged], timeout)
    if rc == 124:
        raise TransferError("the file picker timed out")

    arrived = os.path.exists(staged) and os.path.getsize(staged) > 0
    if not arrived:
        # The shim exits straight after dispatching the intent, so a bad exit
        # status here means the intent never went out -- not that the user
        # declined.  Only a status we do not recognise is worth a message;
        # 0 and 1 are both seen on a normal dispatch.
        if rc not in (0, 1):
            raise TransferError(
                "the file picker failed: %s"
                % (err.decode("utf-8", "replace")[:120] or "no file returned"))
        if on_wait is not None:
            try:
                on_wait()
            except Exception:
                pass
        deadline = started + timeout
        arrived = _await_picked_file(staged, deadline, sleeper=sleeper,
                                     clock=clock)
    else:
        # It was already there, but it may still be filling.
        arrived = _await_picked_file(staged, clock() + timeout,
                                     sleeper=sleeper, clock=clock)

    if not arrived or not os.path.exists(staged) \
            or os.path.getsize(staged) == 0:
        try:
            os.unlink(staged)
        except OSError:
            # It is not there now, but the chooser may still deliver it after
            # we walk away.  Remember it so the next pick sweeps it up.
            _ABANDONED_PICKS.add(staged)
        else:
            _ABANDONED_PICKS.discard(staged)
        raise TransferError("no file chosen")

    with open(staged, "rb") as fh:
        head = fh.read(32)
    ext = sniff_extension(head)
    # unique_path, not a bare timestamp: two picks inside the same second
    # produced the same name, and os.replace would silently clobber a staged
    # file the first transfer was still reading.  Found by a test, not by
    # reading -- the window is narrow because the caller unlinks after
    # sealing, which is exactly what makes it the kind of race that survives.
    final = unique_path(staging,
                        "%s-%s.%s" % (_KIND_FOR.get(ext, "file"),
                                      time.strftime("%Y%m%d-%H%M%S"), ext))
    os.replace(staged, final)
    os.chmod(final, 0o600)
    _ABANDONED_PICKS.discard(staged)
    return final


#: A human-facing word for each sniffed type, so the rebuilt name reads as
#: something rather than as a hex blob.
_KIND_FOR = {
    "jpg": "image", "png": "image", "gif": "image", "webp": "image",
    "mp4": "video", "mov": "video", "mpg": "video",
    "mp3": "audio", "ogg": "audio", "flac": "audio", "wav": "audio",
    "m4a": "audio", "pdf": "document", "txt": "text",
    "zip": "archive", "gz": "archive", "bin": "file",
}


def unique_path(directory: str, filename: str) -> str:
    """A path that does not exist yet.  A second file of the same name gets a
    suffix rather than overwriting the first -- a peer should not be able to
    replace a file you already accepted by sending another with that name."""
    candidate = os.path.join(directory, filename)
    if not os.path.exists(candidate):
        return candidate
    stem, ext = os.path.splitext(filename)
    for n in range(1, 10000):
        candidate = os.path.join(directory, "%s (%d)%s" % (stem, n, ext))
        if not os.path.exists(candidate):
            return candidate
    raise TransferError("too many files with that name")


# --------------------------------------------------------------------------
# offer encoding
# --------------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise TransferError("malformed %s" % what)


def _int_field(text: str, what: str, limit: int) -> int:
    if not text.isdigit() or len(text) > 20:
        raise TransferError("malformed %s" % what)
    value = int(text)
    if value > limit:
        raise TransferError("%s out of range" % what)
    return value


@dataclass
class Offer:
    """The authenticated metadata for one transfer.

    Every field here travels inside the OTR channel, so it is confidential and
    authenticated to the peer.  That does NOT make it true: a peer can lie
    about the filename, the size or the hashes.  Each is therefore checked
    against what actually arrives rather than believed.
    """
    transfer_id: bytes
    filename: str
    plaintext_size: int
    encrypted_size: int
    chunk_count: int
    encrypted_sha256: bytes
    plaintext_sha256: bytes
    envelope: bytes
    version: int = PROTOCOL_VERSION
    format_version: int = FORMAT_VERSION

    def encode(self) -> str:
        return "|".join([
            str(self.version),
            str(self.format_version),
            self.transfer_id.hex(),
            _b64(self.filename.encode("utf-8")),
            str(self.plaintext_size),
            str(self.encrypted_size),
            str(self.chunk_count),
            self.encrypted_sha256.hex(),
            self.plaintext_sha256.hex(),
            _b64(self.envelope),
        ])

    @classmethod
    def decode(cls, payload: str) -> "Offer":
        parts = payload.split("|")
        if len(parts) != 10:
            raise TransferError("offer has %d fields, expected 10" % len(parts))
        for p in parts:
            if len(p) > 4096:
                raise TransferError("offer field too long")
        version = _int_field(parts[0], "protocol version", 255)
        if version != PROTOCOL_VERSION:
            raise TransferError(
                "unsupported file-transfer protocol version %d" % version)
        fmt = _int_field(parts[1], "format version", 255)
        if fmt != FORMAT_VERSION:
            raise TransferError("unsupported file format version %d" % fmt)
        try:
            transfer_id = bytes.fromhex(parts[2])
        except ValueError:
            raise TransferError("malformed transfer id")
        if len(transfer_id) != 16:
            raise TransferError("malformed transfer id")
        raw_name = _unb64(parts[3], "filename")
        if len(raw_name) > MAX_OFFER_FIELD:
            raise TransferError("filename too long")
        try:
            filename = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            raise TransferError("filename is not valid UTF-8")
        plaintext_size = _int_field(parts[4], "size", MAX_TRANSFER_BYTES)
        encrypted_size = _int_field(parts[5], "encrypted size",
                                    MAX_TRANSFER_BYTES + (1 << 24))
        chunk_count = _int_field(parts[6], "chunk count", 1 << 24)
        try:
            enc_hash = bytes.fromhex(parts[7])
            pln_hash = bytes.fromhex(parts[8])
        except ValueError:
            raise TransferError("malformed hash")
        if len(enc_hash) != 32 or len(pln_hash) != 32:
            raise TransferError("malformed hash")
        envelope = _unb64(parts[9], "key envelope")

        # Consistency the sender could not have got wrong by accident, checked
        # before anything is allocated on the strength of it.
        if chunk_count < 1:
            raise TransferError("a transfer must have at least one chunk")
        if encrypted_size <= plaintext_size and plaintext_size:
            raise TransferError("encrypted size is not larger than plaintext")

        return cls(transfer_id=transfer_id, filename=filename,
                   plaintext_size=plaintext_size,
                   encrypted_size=encrypted_size, chunk_count=chunk_count,
                   encrypted_sha256=enc_hash, plaintext_sha256=pln_hash,
                   envelope=envelope, version=version, format_version=fmt)

    def human_size(self) -> str:
        n = float(self.plaintext_size)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
            n /= 1024
        return "%d B" % self.plaintext_size


# --------------------------------------------------------------------------
# the transport boundary
# --------------------------------------------------------------------------

class ChunkTransport:
    """Everything below the file-transfer engine.

    THIS IS THE SEAM.  Above it: the FileKey, the AEAD, the chunk format, the
    hashes, the offer/accept semantics, filename handling, the temporary-file
    lifecycle and the atomic commit.  None of that knows how a byte travels.
    Below it: how a control message and a ciphertext chunk actually reach the
    peer.

    A transport has exactly two jobs, deliberately separated:

      * `send_control` carries offer / accept / decline / done / cancel.
        These are small, ordered and must be authenticated, so they belong on
        the OTR channel whatever else changes.

      * `send_chunk` carries one already-sealed ciphertext chunk.  It is bulk
        data that is *already* encrypted and authenticated before it gets
        here, so a transport may move it however it likes.

    Splitting them is the whole point.  A future torrent or SAM-stream
    transport keeps `send_control` on XMPP/OTR and replaces only
    `send_chunk`; the engine, the format and every security test are
    untouched.  The two are separate methods rather than one `send` so that
    a transport CANNOT accidentally end up carrying signalling over the bulk
    path, or bulk data over the signalling path.

    Inbound chunks re-enter the engine through
    `FileTransferManager.deliver_chunk`, whatever brought them.
    """

    #: Plaintext bytes per chunk this transport wants.  A signalling-channel
    #: transport keeps it small; a bulk transport can raise it to the format
    #: maximum.  It is a transport parameter, never a cryptographic one.
    chunk_bytes = WIRE_CHUNK_PLAIN

    def send_control(self, peer: str, verb: str, payload: str) -> bool:
        raise NotImplementedError

    def send_chunk(self, peer: str, transfer_id: bytes, index: int,
                   sealed: bytes) -> bool:
        raise NotImplementedError


class OtrChunkTransport(ChunkTransport):
    """Phase A: both control and bulk ride the OTR channel.

    Chunks are base64'd into control messages, which is why `chunk_bytes` is
    modest -- this is a signalling channel being asked to carry a file, and
    it is honest about that.  It is correct, it is authenticated, and it is
    slow for anything large.  Replacing THIS CLASS is the whole of a
    transport upgrade.
    """

    chunk_bytes = WIRE_CHUNK_PLAIN

    def __init__(self, send: Callable[[str, str, str], bool]):
        self._send = send

    def send_control(self, peer: str, verb: str, payload: str) -> bool:
        return bool(self._send(peer, verb, payload))

    def send_chunk(self, peer: str, transfer_id: bytes, index: int,
                   sealed: bytes) -> bool:
        return bool(self._send(peer, "DATA", "%s|%d|%s" % (
            transfer_id.hex(), index, _b64(sealed))))


# --------------------------------------------------------------------------
# transfers
# --------------------------------------------------------------------------

@dataclass
class OutgoingTransfer:
    peer: str
    offer: Offer
    path: str
    sender: object                     # RustFileSender
    chunks_sent: int = 0
    accepted: bool = False
    cancelled: bool = False
    started_at: float = field(default_factory=time.monotonic)

    @property
    def progress(self) -> float:
        total = max(1, self.offer.chunk_count)
        return min(1.0, self.chunks_sent / total)


@dataclass
class IncomingTransfer:
    peer: str
    offer: Offer
    receiver: object = None            # RustFileReceiver, once accepted
    tmp_path: Optional[str] = None
    handle: object = None
    chunks_received: int = 0
    accepted: bool = False
    cancelled: bool = False
    offered_at: float = field(default_factory=time.monotonic)

    @property
    def progress(self) -> float:
        total = max(1, self.offer.chunk_count)
        return min(1.0, self.chunks_received / total)


def render_progress(fraction: float, width: int = 10) -> str:
    """A progress bar.  Carries a count, never a key, a nonce or a hash."""
    filled = int(round(max(0.0, min(1.0, fraction)) * width))
    return "[%s%s] %d%%" % ("█" * filled, "░" * (width - filled),
                            int(round(fraction * 100)))


# --------------------------------------------------------------------------
# the engine
# --------------------------------------------------------------------------

class FileTransferManager:
    """Drives offers and transfers over a transport it is handed.

    `send(peer, verb, payload) -> bool` is the byte pump.  Phase A passes the
    XMPP client's OTR-channel sender.  Nothing else in this class knows or
    cares what that is.
    """

    def __init__(self, transport: ChunkTransport,
                 notify: Callable[[str], None],
                 verified: Callable[[str], bool]):
        if _core is None:                        # pragma: no cover
            raise TransferError(
                "otrv4_core is unavailable, so file transfer cannot run; "
                "there is deliberately no Python fallback")
        self.transport = transport
        self._notify = notify
        self._verified = verified
        self.outgoing: Dict[str, OutgoingTransfer] = {}
        self.incoming: Dict[str, IncomingTransfer] = {}

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _key(transfer_id: bytes) -> str:
        return transfer_id.hex()

    def _fail(self, peer: str, message: str) -> None:
        self._notify("[file] %s" % message)

    # -- sending ---------------------------------------------------------

    def offer_file(self, peer: str, path: str, ratchet) -> OutgoingTransfer:
        """Encrypt `path` and offer it to `peer`.

        The whole file is sealed up front so the offer can carry a hash of the
        ciphertext the receiver will actually get.  Sealing is chunked, so peak
        memory is one chunk regardless of file size.
        """
        if not self._verified(peer):
            raise TransferError(
                "SMP verification is required before sending a file to %s" % peer)
        real = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(real):
            raise TransferError("no such file: %s%s"
                                % (os.path.basename(path), _storage_hint()))
        size = os.path.getsize(real)
        if size > MAX_TRANSFER_BYTES:
            raise TransferError("file is larger than the %d MB limit"
                                % (MAX_TRANSFER_BYTES // (1024 * 1024)))

        transfer_id = _core.file_transfer_new_id()
        sender = ratchet.file_sender(transfer_id)

        # The transport chooses the chunk size, capped at what the format
        # allows.  A bulk transport can use the full 64 KiB; the OTR one is
        # smaller because each chunk is base64'd into a stanza.
        chunk_bytes = max(1, min(int(getattr(self.transport, "chunk_bytes",
                                             WIRE_CHUNK_PLAIN)),
                                 _core.file_transfer_chunk_len()))
        sealed_parts = []
        remaining = size
        with open(real, "rb") as fh:
            while True:
                block = fh.read(chunk_bytes)
                remaining -= len(block)
                is_final = remaining <= 0
                sealed_parts.append(sender.seal_chunk(block, is_final))
                if is_final:
                    break

        offer = Offer(
            transfer_id=bytes(transfer_id),
            filename=sanitise_filename(os.path.basename(real)),
            plaintext_size=sender.plaintext_len,
            encrypted_size=sender.ciphertext_len,
            chunk_count=len(sealed_parts),
            encrypted_sha256=bytes(sender.ciphertext_sha256()),
            plaintext_sha256=bytes(sender.plaintext_sha256()),
            envelope=bytes(sender.envelope),
        )
        transfer = OutgoingTransfer(peer=peer, offer=offer, path=real,
                                    sender=sender)
        transfer._sealed = sealed_parts          # type: ignore[attr-defined]
        self.outgoing[self._key(offer.transfer_id)] = transfer
        if not self.transport.send_control(peer, "OFFER", offer.encode()):
            self.cancel(offer.transfer_id, "the offer could not be sent")
            raise TransferError("the offer could not be sent")
        return transfer

    def _pump(self, transfer: OutgoingTransfer) -> None:
        """Send every sealed chunk.  Caller runs this off the event loop."""
        sealed = getattr(transfer, "_sealed", [])
        for index, chunk in enumerate(sealed):
            if transfer.cancelled:
                return
            if not self.transport.send_chunk(
                    transfer.peer, transfer.offer.transfer_id, index, chunk):
                self.cancel(transfer.offer.transfer_id, "the transport failed")
                return
            transfer.chunks_sent = index + 1
        self.transport.send_control(transfer.peer, "DONE",
                                    transfer.offer.transfer_id.hex())

    # -- receiving -------------------------------------------------------

    def on_offer(self, peer: str, payload: str) -> Optional[IncomingTransfer]:
        if not self._verified(peer):
            self._fail(peer, "ignored a file offer from an unverified peer")
            return None
        offer = Offer.decode(payload)
        key = self._key(offer.transfer_id)
        if key in self.incoming:
            raise TransferError("duplicate transfer id")
        transfer = IncomingTransfer(peer=peer, offer=offer)
        self.incoming[key] = transfer
        self._notify(
            "\n[file] %s wants to send %s (%s)\n"
            "       /transfer accept %s   or   /transfer decline %s"
            % (peer, sanitise_filename(offer.filename), offer.human_size(),
               key[:8], key[:8]))
        return transfer

    def accept(self, transfer_id: bytes, ratchet) -> IncomingTransfer:
        transfer = self._require_incoming(transfer_id)
        if transfer.accepted:
            raise TransferError("that transfer was already accepted")
        # Opening the envelope IS the authentication step: it only succeeds
        # for the session that sealed it, for this transfer id.
        transfer.receiver = ratchet.file_receiver(
            transfer.offer.transfer_id, transfer.offer.envelope)
        fd, tmp = tempfile.mkstemp(prefix="ft-", suffix=".part",
                                   dir=incoming_dir())
        os.fchmod(fd, 0o600)
        transfer.handle = os.fdopen(fd, "wb")
        transfer.tmp_path = tmp
        transfer.accepted = True
        self.transport.send_control(transfer.peer, "ACCEPT",
                                    transfer.offer.transfer_id.hex())
        return transfer

    def decline(self, transfer_id: bytes) -> None:
        transfer = self._require_incoming(transfer_id)
        self.transport.send_control(transfer.peer, "DECLINE",
                                    transfer.offer.transfer_id.hex())
        self._destroy_incoming(transfer)
        self._notify("[file] declined")

    def on_data(self, peer: str, payload: str) -> None:
        """Unwrap one DATA control message.  OTR transport only.

        This is the ONLY method that knows chunks can arrive base64'd inside
        a control message, which is a property of OtrChunkTransport rather
        than of the format.  A bulk transport calls `deliver_chunk` directly
        with the raw sealed bytes and never comes through here.
        """
        parts = payload.split("|", 2)
        if len(parts) != 3:
            raise TransferError("malformed data frame")
        try:
            transfer_id = bytes.fromhex(parts[0])
        except ValueError:
            raise TransferError("malformed transfer id")
        index = _int_field(parts[1], "chunk index", 1 << 24)
        self.deliver_chunk(peer, transfer_id, index, _unb64(parts[2], "chunk"))

    def deliver_chunk(self, peer: str, transfer_id: bytes, index: int,
                      sealed: bytes) -> None:
        """One sealed chunk, however it arrived.  THE INBOUND SEAM.

        Every transport funnels here, so the ordering rule, the
        authentication and the write are defined once and cannot diverge
        between transports.  A torrent or SAM-stream receiver calls this with
        raw bytes off the wire.
        """
        transfer = self._require_incoming(transfer_id)
        if transfer.peer != peer:
            raise TransferError("data frame from the wrong peer")
        if not transfer.accepted or transfer.receiver is None:
            raise TransferError("data arrived for a transfer that was not accepted")
        if index != transfer.chunks_received:
            raise TransferError("chunk %d arrived out of order" % index)
        is_final = (index + 1 == transfer.offer.chunk_count)
        # Authenticates before anything is written.  A forged chunk raises
        # here and leaves the temporary file untouched.
        #
        # Rust raises ValueError; it is converted so callers see one error
        # type and, more usefully, so the reason survives.  Letting it
        # propagate landed it in the generic handler, which reports only the
        # exception class -- "chunk failed authentication" became
        # "DATA failed: ValueError".
        try:
            plain = transfer.receiver.open_chunk(sealed, is_final)
        except Exception as exc:
            # A chunk that fails its tag is not a transient error: the peer
            # is broken or hostile, and continuing would leave a partial file
            # on disk waiting for chunks that will never verify.
            self._destroy_incoming(transfer)
            raise TransferError("chunk %d failed authentication — transfer "
                                "abandoned" % index) from exc
        transfer.handle.write(plain)
        transfer.chunks_received = index + 1

    def on_done(self, peer: str, payload: str) -> str:
        """Verify everything, then place the file.  Returns the final path."""
        transfer = self._require_incoming(bytes.fromhex(payload.strip()))
        if transfer.peer != peer:
            raise TransferError("completion from the wrong peer")
        try:
            return self._finish(transfer)
        except Exception:
            self._destroy_incoming(transfer)
            raise

    def _finish(self, transfer: IncomingTransfer) -> str:
        offer = transfer.offer
        rx = transfer.receiver
        if rx is None or not transfer.accepted:
            raise TransferError("transfer was never accepted")
        transfer.handle.flush()
        os.fsync(transfer.handle.fileno())
        transfer.handle.close()
        transfer.handle = None

        # 1. every chunk arrived, and the last one authenticated as last.
        #
        # The count comparison is REDUNDANT and kept deliberately.  Mutation
        # testing showed no input reaches it: the final flag is inside the
        # chunk AAD, so a peer that under- or over-states the count makes the
        # receiver compute `is_final` differently from the sender and the tag
        # fails first.  It stays because it is free, and because the check
        # below it (`rx.finished`) is the one doing the work -- if that ever
        # moves, this is the backstop.
        if transfer.chunks_received != offer.chunk_count:
            raise TransferError("transfer is incomplete: %d of %d chunks"
                                % (transfer.chunks_received, offer.chunk_count))
        if not rx.finished:
            raise TransferError("the final chunk never arrived")
        # 2. the ciphertext was the ciphertext that was offered
        if bytes(rx.ciphertext_sha256()) != offer.encrypted_sha256:
            raise TransferError("encrypted-file hash mismatch")
        # 3. the plaintext is the plaintext that was offered
        if bytes(rx.plaintext_sha256()) != offer.plaintext_sha256:
            raise TransferError("plaintext hash mismatch")
        # 4. and the sizes agree with what was actually written
        written = os.path.getsize(transfer.tmp_path)
        if written != offer.plaintext_size or written != rx.plaintext_len:
            raise TransferError("size mismatch: %d bytes on disk, %d offered"
                                % (written, offer.plaintext_size))
        # 5. an independent read-back, because everything above trusts that
        #    what we wrote is what landed
        digest = hashlib.sha256()
        with open(transfer.tmp_path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        if digest.digest() != offer.plaintext_sha256:
            raise TransferError("the file on disk does not match its hash")

        final = unique_path(state_dir(), sanitise_filename(offer.filename))
        os.chmod(transfer.tmp_path, 0o600)
        # Atomic within the same filesystem, so a reader never sees a partial
        # file under the final name.
        os.replace(transfer.tmp_path, final)
        transfer.tmp_path = None
        self._destroy_incoming(transfer)
        return final

    # -- cancellation ----------------------------------------------------

    def cancel(self, transfer_id: bytes, why: str = "cancelled") -> None:
        key = self._key(transfer_id)
        out = self.outgoing.pop(key, None)
        if out is not None:
            out.cancelled = True
            try:
                out.sender.zeroize()
            except Exception:
                pass
            out._sealed = []                     # type: ignore[attr-defined]
            self.transport.send_control(out.peer, "CANCEL", key)
        inc = self.incoming.get(key)
        if inc is not None:
            self.transport.send_control(inc.peer, "CANCEL", key)
            self._destroy_incoming(inc)
        self._notify("[file] transfer %s: %s" % (key[:8], why))

    def on_cancel(self, peer: str, payload: str) -> None:
        self.cancel(bytes.fromhex(payload.strip()), "the peer cancelled")

    def on_decline(self, peer: str, payload: str) -> None:
        key = payload.strip()
        out = self.outgoing.pop(key, None)
        if out is not None:
            out.cancelled = True
            try:
                out.sender.zeroize()
            except Exception:
                pass
            out._sealed = []                     # type: ignore[attr-defined]
        self._notify("[file] %s declined the transfer" % peer)

    def _destroy_incoming(self, transfer: IncomingTransfer) -> None:
        """Remove every trace.  Runs on decline, cancellation and failure."""
        if transfer.handle is not None:
            try:
                transfer.handle.close()
            except Exception:
                pass
            transfer.handle = None
        if transfer.tmp_path:
            try:
                os.unlink(transfer.tmp_path)
            except OSError:
                pass
            transfer.tmp_path = None
        if transfer.receiver is not None:
            try:
                transfer.receiver.zeroize()
            except Exception:
                pass
            transfer.receiver = None
        transfer.cancelled = True
        self.incoming.pop(self._key(transfer.offer.transfer_id), None)

    def _require_incoming(self, transfer_id: bytes) -> IncomingTransfer:
        transfer = self.incoming.get(self._key(transfer_id))
        if transfer is None:
            raise TransferError("no such transfer")
        return transfer

    def find_incoming(self, prefix: str) -> IncomingTransfer:
        """Resolve the short id the prompt shows."""
        prefix = prefix.strip().lower()
        matches = [t for k, t in self.incoming.items() if k.startswith(prefix)]
        if not matches:
            raise TransferError("no such transfer")
        if len(matches) > 1:
            raise TransferError("that id is ambiguous")
        return matches[0]

    # -- dispatch --------------------------------------------------------

    def handle_control(self, peer: str, body: str) -> bool:
        """Route one decrypted control message.  Returns True if consumed."""
        if not isinstance(body, str) or not body.startswith(FILE_PREFIX):
            return False
        remainder = body[len(FILE_PREFIX):]
        verb, _, payload = remainder.partition(":")
        handlers = {
            "OFFER": self.on_offer,
            "DATA": self.on_data,
            "DONE": self.on_done,
            "CANCEL": self.on_cancel,
            "DECLINE": self.on_decline,
            "ACCEPT": self.on_accept,
        }
        handler = handlers.get(verb.strip().upper())
        if handler is None:
            return True                          # consumed, unknown verb dropped
        try:
            handler(peer, payload)
        except TransferError as exc:
            self._fail(peer, "%s rejected: %s" % (verb, exc))
        except Exception as exc:
            self._fail(peer, "%s failed: %s" % (verb, type(exc).__name__))
        return True

    def on_accept(self, peer: str, payload: str) -> None:
        key = payload.strip()
        transfer = self.outgoing.get(key)
        if transfer is None or transfer.peer != peer:
            return
        transfer.accepted = True
        self._notify("[file] %s accepted %s — sending"
                     % (peer, transfer.offer.filename))
        self._pump(transfer)
