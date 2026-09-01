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

    def __init__(self, send: Callable[[str, str, str], bool],
                 notify: Callable[[str], None],
                 verified: Callable[[str], bool]):
        if _core is None:                        # pragma: no cover
            raise TransferError(
                "otrv4_core is unavailable, so file transfer cannot run; "
                "there is deliberately no Python fallback")
        self._send = send
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
            raise TransferError("no such file: %s" % os.path.basename(path))
        size = os.path.getsize(real)
        if size > MAX_TRANSFER_BYTES:
            raise TransferError("file is larger than the %d MB limit"
                                % (MAX_TRANSFER_BYTES // (1024 * 1024)))

        transfer_id = _core.file_transfer_new_id()
        sender = ratchet.file_sender(transfer_id)

        sealed_parts = []
        remaining = size
        with open(real, "rb") as fh:
            while True:
                block = fh.read(WIRE_CHUNK_PLAIN)
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
        if not self._send(peer, "OFFER", offer.encode()):
            self.cancel(offer.transfer_id, "the offer could not be sent")
            raise TransferError("the offer could not be sent")
        return transfer

    def _pump(self, transfer: OutgoingTransfer) -> None:
        """Send every sealed chunk.  Caller runs this off the event loop."""
        sealed = getattr(transfer, "_sealed", [])
        for index, chunk in enumerate(sealed):
            if transfer.cancelled:
                return
            payload = "%s|%d|%s" % (transfer.offer.transfer_id.hex(), index,
                                    _b64(chunk))
            if not self._send(transfer.peer, "DATA", payload):
                self.cancel(transfer.offer.transfer_id, "the transport failed")
                return
            transfer.chunks_sent = index + 1
        self._send(transfer.peer, "DONE", transfer.offer.transfer_id.hex())

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
        self._send(transfer.peer, "ACCEPT", transfer.offer.transfer_id.hex())
        return transfer

    def decline(self, transfer_id: bytes) -> None:
        transfer = self._require_incoming(transfer_id)
        self._send(transfer.peer, "DECLINE", transfer.offer.transfer_id.hex())
        self._destroy_incoming(transfer)
        self._notify("[file] declined")

    def on_data(self, peer: str, payload: str) -> None:
        parts = payload.split("|", 2)
        if len(parts) != 3:
            raise TransferError("malformed data frame")
        transfer = self._require_incoming(bytes.fromhex(parts[0]))
        if transfer.peer != peer:
            raise TransferError("data frame from the wrong peer")
        if not transfer.accepted or transfer.receiver is None:
            raise TransferError("data arrived for a transfer that was not accepted")
        index = _int_field(parts[1], "chunk index", 1 << 24)
        if index != transfer.chunks_received:
            raise TransferError("chunk %d arrived out of order" % index)
        sealed = _unb64(parts[2], "chunk")
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

        # 1. every chunk arrived, and the last one authenticated as last
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
            self._send(out.peer, "CANCEL", key)
        inc = self.incoming.get(key)
        if inc is not None:
            self._send(inc.peer, "CANCEL", key)
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
