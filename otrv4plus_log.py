#!/usr/bin/env python3
"""
otrv4plus_log.py — Per-channel encrypted session log for OTRv4+
================================================================

Two modes controlled by the `persistent` flag:

  persistent=False  (IRC default)
    Key: fresh os.urandom(32) each session, zeroed in close()
    Files: deleted in close()
    Effect: scrollback within one session only; nothing survives /quit
    Wipe: _secure_wipe_data() in otrv4+.py removes any remnants

  persistent=True  (XMPP default)
    Key: loaded from ~/.otrv4plus/channel_log.key (0600) on every start;
         generated and saved on first run
    Files: kept across sessions; accumulate indefinitely
    Effect: full cross-session history, no password needed
    Read: read_recent(n=500) loads last 500 lines into the panel at startup
    Wipe: call wipe(), or delete ~/.otrv4plus manually

Cipher: SHAKE-256 stream + HMAC-SHA3-512 (stdlib-only, no new deps)

File format:
  ~/.otrv4plus/logs/channels/<sha256(channel)[:24]>.enc
  Entry: [uint32_le: payload_len] [nonce: 12] [ciphertext] [tag: 16]
  Plaintext: "HH:MM:SS|<message>"
  AAD: channel name bytes

Integration hooks (otrv4plus_xmpp.py):
  __init__:   self.channel_log = ChannelLogManager(persistent=True)
  _start_tui: load history → panel.add_message() for each entry
  _tui_quit:  self.channel_log.close()
  main finally: client.channel_log.close()

Integration hooks (otrv4+.py via PanelManager):
  add_panel:    cl.read_recent(name, n=500) → load history
  add_message:  cl.append(target, message)
  shutdown:     cl.close() (then _secure_wipe_data handles file deletion)
"""

import hashlib
import hmac
import os
import re
import struct
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI strip — store clean plain text in logs
# ---------------------------------------------------------------------------
_ANSI_STRIP = re.compile(
    r"\x1b(?:"
    r"[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|[\x20-\x2f][\x30-\x7e]"
    r"|."
    r")"
)

def _strip_ansi(text: str) -> str:
    return _ANSI_STRIP.sub("", str(text))


# ---------------------------------------------------------------------------
# AEAD: SHAKE-256 stream cipher + HMAC-SHA3-512 tag (stdlib-only)
# ---------------------------------------------------------------------------
_DOM_ENC = b"\x01enc"
_DOM_MAC = b"\x02mac"


def _aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    ks = hashlib.shake_256(_DOM_ENC + key + nonce).digest(len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    mac_key = hashlib.shake_256(_DOM_MAC + key + nonce).digest(64)
    h = hmac.new(mac_key, digestmod=hashlib.sha3_512)
    h.update(struct.pack("<I", len(aad)))
    h.update(aad)
    h.update(ct)
    return ct + h.digest()[:16]


def _aead_decrypt(key: bytes, nonce: bytes, ct_tag: bytes, aad: bytes) -> bytes:
    if len(ct_tag) < 16:
        raise ValueError("payload too short")
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    mac_key = hashlib.shake_256(_DOM_MAC + key + nonce).digest(64)
    h = hmac.new(mac_key, digestmod=hashlib.sha3_512)
    h.update(struct.pack("<I", len(aad)))
    h.update(aad)
    h.update(ct)
    if not hmac.compare_digest(h.digest()[:16], tag):
        raise ValueError("authentication tag mismatch")
    ks = hashlib.shake_256(_DOM_ENC + key + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


# ---------------------------------------------------------------------------
# Per-channel encrypted log file
# ---------------------------------------------------------------------------

class EncryptedChannelLog:
    def __init__(self, path: Path, key: bytes, channel: str):
        self._path = path
        self._key = key
        self._aad = channel.encode("utf-8")
        self._fh = open(path, "a+b")

    def append(self, message: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        plaintext = f"{ts}|{_strip_ansi(message)}".encode("utf-8")
        nonce = os.urandom(12)
        ct_tag = _aead_encrypt(self._key, nonce, plaintext, self._aad)
        payload = nonce + ct_tag
        try:
            self._fh.write(struct.pack("<I", len(payload)))
            self._fh.write(payload)
            self._fh.flush()
        except OSError:
            pass

    def read_recent(self, n: int = 500) -> list:
        lines = []
        try:
            self._fh.seek(0)
            raw = self._fh.read()
        except OSError:
            return []
        pos = 0
        total = len(raw)
        while pos + 4 <= total:
            try:
                (plen,) = struct.unpack_from("<I", raw, pos)
                pos += 4
                if plen < 28 or plen > 256 * 1024:
                    pos += 1
                    continue
                if pos + plen > total:
                    break
                payload = raw[pos : pos + plen]
                pos += plen
                nonce, ct_tag = payload[:12], payload[12:]
                plain = _aead_decrypt(self._key, nonce, ct_tag, self._aad)
                lines.append(plain.decode("utf-8", errors="replace"))
            except Exception:
                pos += 1
        return lines[-n:] if len(lines) > n else lines

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def delete(self) -> None:
        self.close()
        try:
            self._path.unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Session-scoped manager
# ---------------------------------------------------------------------------

class ChannelLogManager:
    """
    persistent=False  IRC mode: ephemeral key, files deleted on close()
    persistent=True   XMPP mode: key saved to disk, files kept across sessions
    """

    _OTR_DIR  = Path.home() / ".otrv4plus"
    _LOG_DIR  = Path.home() / ".otrv4plus" / "logs" / "channels"
    _KEY_FILE = Path.home() / ".otrv4plus" / "channel_log.key"

    def __init__(self, persistent: bool = False):
        self._persistent = persistent
        self._logs: dict = {}
        self._closed: bool = False
        try:
            self._LOG_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(self._OTR_DIR, 0o700)
        except OSError:
            pass

        if persistent:
            self._key = bytearray(self._load_or_create_key())
        else:
            self._key = bytearray(os.urandom(32))

    def _load_or_create_key(self) -> bytes:
        """Load the persistent key from disk, generating it on first run."""
        if self._KEY_FILE.exists():
            try:
                data = self._KEY_FILE.read_bytes()
                if len(data) == 32:
                    return data
            except Exception:
                pass
        # First run: generate and save
        key = os.urandom(32)
        try:
            self._KEY_FILE.write_bytes(key)
            os.chmod(self._KEY_FILE, 0o600)
        except Exception:
            pass
        return key

    def _channel_id(self, channel: str) -> str:
        return hashlib.sha256(channel.encode("utf-8")).hexdigest()[:24]

    def _get(self, channel: str) -> EncryptedChannelLog:
        if channel not in self._logs:
            path = self._LOG_DIR / f"{self._channel_id(channel)}.enc"
            self._logs[channel] = EncryptedChannelLog(
                path, bytes(self._key), channel
            )
        return self._logs[channel]

    def append(self, channel: str, message: str) -> None:
        if self._closed:
            return
        try:
            self._get(channel).append(message)
        except Exception:
            pass

    def read_recent(self, channel: str, n: int = 500) -> list:
        if self._closed:
            return []
        try:
            return self._get(channel).read_recent(n)
        except Exception:
            return []

    def close(self) -> None:
        """Flush and close file handles.
        Ephemeral: also deletes .enc files and zeroes key.
        Persistent: keeps files and key on disk for next session."""
        if self._closed:
            return
        self._closed = True
        for log in self._logs.values():
            if self._persistent:
                log.close()       # keep the file
            else:
                log.delete()      # wipe the file
        self._logs.clear()
        if not self._persistent:
            # Zero the ephemeral key
            for i in range(len(self._key)):
                self._key[i] = 0

    def wipe(self) -> None:
        """Full destruction: zero key, delete key file, delete all .enc files.
        Called by otrv4+.py _secure_wipe_data equivalent or explicit reset."""
        if not self._closed:
            for log in self._logs.values():
                log.delete()
            self._logs.clear()
        self._closed = True
        for i in range(len(self._key)):
            self._key[i] = 0
        try:
            self._KEY_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            for f in self._LOG_DIR.glob("*.enc"):
                f.unlink(missing_ok=True)
        except Exception:
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
