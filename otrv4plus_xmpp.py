#!/usr/bin/env python3
"""
OTRv4+ XMPP - full OTR + SMP over XMPP, transported over I2P SAM
================================================================
Version: 10.12.0


Post-quantum OTRv4+ end-to-end encryption over XMPP, reusing the IRC client's
Rust-backed OTR engine (EnhancedSessionManager) unchanged. Every OTR frame
("?OTRv4 <base64>") rides in a single <message><body>, so there is NO
fragmentation and the post-quantum handshake/SMP are far faster than on IRC.

  slixmpp (Python)  ->  "?OTRv4 ..." frames only, never keys
       v
  EnhancedSessionManager (Python)  ->  drives DAKE/SMP/ratchet
       v
  otrv4_core.so (Rust)  ->  ALL secrets, ZeroizeOnDrop, never exposed

TRANSPORT: I2P SAM (matching the IRC client). A SAM stream is opened to the
server's c2s .b32.i2p destination and exposed as a local TCP endpoint; slixmpp
connects to that endpoint and does STARTTLS normally, unaware of I2P. A
keepalive task pings the stream so idle I2P tunnels don't get torn down.

XEP SUPPORT (slixmpp plugins):
  XEP-0030  Service discovery (capability advertisement)
  XEP-0085  Chat state notifications
  XEP-0115  Entity capabilities
  XEP-0184  Message delivery receipts (auto mode)
  XEP-0198  Stream management (stanza acks; graceful degradation if unsupported)
  XEP-0199  XMPP Ping (peer reachability check via /ping)

POST-DAKE FLOW (NOT identical to the IRC client -- see below):
  1. DAKE completes -> session ENCRYPTED.
  2. Both fingerprints are shown, then TOFU acts. Nothing is asked:
     - first contact  -> pinned automatically for this JID, and it says so.
     - same as pinned -> it says it matches.
     - CHANGED        -> a warning. The pin is NOT replaced, SMP setup does
                         not continue, and voice is refused for that peer
                         until you deliberately run /trust-reset.
     There is no y/n at any point. Approving a fingerprint you have never seen
     has nothing to check it against, so the only available answer is yes --
     and a question always answered yes trains the reflex that makes the
     CHANGED case useless. /identity shows what is pinned.
  3. You are prompted for the Socialist Millionaire Protocol passphrase, which
     is stored for AUTO-RESPOND. Press Enter / "skip" to skip.
  4. Once BOTH sides have stored the passphrase, EITHER side runs /smp start.

  This differs from the IRC client on purpose. A JID is a durable name, so XMPP
  keeps a persistent identity and pins peer fingerprints; an IRC nick is not,
  so IRC keeps a fresh identity every run and pins nothing. Being asked to pin
  on EVERY connection means one of: you are on a build older than v10.12.0
  (the old wording was "Trust this fingerprint?"), you answered something other
  than y, or the peer is on an older build and their identity is still
  regenerating -- BOTH ends need v10.12.0 for a stable fingerprint.

ROSTER / SUBSCRIPTION FLOW:
  Subscription requests are NEVER auto-approved. They queue in /pending; use
  /accept <jid> or /deny <jid> to respond. /add <jid> sends your own request,
  /remove <jid> deletes a contact, /roster lists all contacts.

USAGE:
    pip install slixmpp aiodns
    python otrv4plus_xmpp.py \
      --jid alice@<vhost>.b32.i2p \
      --server <c2s-tunnel>.b32.i2p \
      --peer bob@<vhost>.b32.i2p \
      --insecure-tls --debug

COMMANDS:
    /otr [jid]            start an OTR session (DAKE)
    y / n                 answer the trust-fingerprint prompt
    <passphrase>          answer the SMP passphrase prompt
    /smp start            begin SMP verification
    /smp <secret>         store a secret AND immediately start SMP
    /smp-secret <secret>  store a secret for auto-respond (no start)
    /trust                re-show fingerprints and the trust prompt
    /msg <jid> <text>     send plaintext (no OTR)
    /status               show session + trust + SMP state for --peer
    /roster               list all roster contacts
    /add <jid>            add a contact and send subscription request
    /remove <jid>         remove a contact from roster
    /pending              show pending subscription requests
    /accept <jid>         accept a pending subscription request
    /deny <jid>           deny a pending subscription request
    /block <jid>          block inbound messages from a JID (session-local)
    /unblock <jid>        remove a session-local block
    /blocked              list session-local blocks
    /ping <jid>           XMPP ping a peer (XEP-0199)
    /help                 show this command list
    /tui                  toggle plain / tabbed-panel mode at runtime
    /quit                 disconnect and exit
    <text>                send to --peer (auto-encrypts once OTR is up)
"""

# =============================================================================
#  SECURITY MODEL (enforced throughout this file):
#    * All cryptography lives in the Rust core (otrv4_core) via the shared
#      EnhancedSessionManager. This transport never holds key material and never
#      implements a primitive; it moves "?OTRv4 <base64>" frames and renders UI.
#    * Every piece of untrusted data shown on the terminal passes through
#      _sanitise(), which strips ANSI/OSC/CSI escape sequences, C0/C1 controls,
#      and newlines. This blocks terminal-title hijack and forged log lines.
#    * Inbound message fragments are bounded (index range, fragment count, and a
#      per-peer reassembly cap) before stitching, preventing memory-exhaustion
#      DoS and out-of-range indexing.
#    * TLS verification is on by default; only disabled behind --insecure-tls
#      which is acceptable over I2P (.b32 destination is cryptographically
#      authenticated) but warned against on clearnet.
#    * Fingerprints are pinned on first use (TOFU); the trust prompt gates the
#      transition to a VERIFIED session.
#    * Subscription requests are NEVER auto-approved. auto_authorize and
#      auto_subscribe are both set to False. All subscription requests queue in
#      _pending_subscriptions and require explicit /accept or /deny.
#    * Inbound messages are rate-limited per peer (20 msgs / 5 s) to prevent
#      event-loop flooding from a hostile or misbehaving peer.
#    * SMP secrets are validated for minimum length (8 chars) and maximum
#      length (512 chars) before being passed to the Rust engine.
#    * A session-local block list (/block, /unblock) drops all inbound messages
#      from listed JIDs without processing or displaying them.
#    * XEP-0198 stream management registered for stanza acks; degrades
#      gracefully if the server does not support it.
#    * XEP-0184 delivery receipts enabled (auto mode).
#    * Automatic reconnection with exponential backoff re-establishes the I2P
#      SAM tunnel before reconnecting slixmpp. Disabled on auth failure.
#
#  Audited for: shell/command injection, escape-sequence injection, ReDoS,
#  unsafe deserialisation, weak hashing, and insecure randomness. None present:
#  no eval/exec, no pickle/marshal, no shell=True, no user-compiled regexes,
#  no md5/sha1, and no use of the `random` module for any security decision.
# =============================================================================

import argparse
import asyncio
import builtins
import collections
import getpass
import hashlib
import hmac
import logging
import os
import re
import secrets
import struct
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Voice-call optional dependencies.
#
# These are resolved LAZILY, never at import time. _bootstrap_termux() may
# install opuslib / pulseaudio during startup, which happens AFTER this module
# has been imported. A module-level `import opuslib` would therefore be
# permanently cached as "missing" for the whole session on a fresh device.
# _load_opus() re-attempts the import (invalidating importlib's caches) and
# voice_available() re-probes the filesystem on every call.
# ---------------------------------------------------------------------------

_opus = None
_OPUS_AVAILABLE = False

TERMUX_PREFIX = "/data/data/com.termux/files/usr"
IS_TERMUX = os.path.isdir("/data/data/com.termux")


def _which(binary: str) -> "str | None":
    """Locate an executable, honouring the Termux prefix explicitly.

    shutil.which() alone is unreliable inside Termux when PATH has been
    trimmed by a wrapper script, so the canonical prefix is checked too.
    """
    import shutil as _shutil
    found = _shutil.which(binary)
    if found:
        return found
    candidate = os.path.join(TERMUX_PREFIX, "bin", binary)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def _load_opus() -> bool:
    """(Re)attempt the opuslib import. Safe to call repeatedly."""
    global _opus, _OPUS_AVAILABLE
    if _OPUS_AVAILABLE:
        return True
    try:
        import importlib
        importlib.invalidate_caches()
        import opuslib as _o  # noqa: PLC0415 (deliberate late import)
        _opus = _o
        _OPUS_AVAILABLE = True
    except Exception:
        _opus = None
        _OPUS_AVAILABLE = False
    return _OPUS_AVAILABLE


def voice_available() -> "tuple[bool, str]":
    """Return (usable, human_readable_reason).

    Re-probed on every call so a mid-session dependency install is picked up
    without a restart.
    """
    if not _load_opus():
        return False, "opuslib not installed  (pip install opuslib --break-system-packages)"
    # Voice no longer requires PulseAudio: otrv4plus_audio prefers AAudio,
    # which talks to Android's audio framework directly. parec/pacat remain
    # a selectable fallback and back the /audiotest self-test, so their
    # absence is reported as a note rather than treated as fatal.
    libopus = os.path.join(TERMUX_PREFIX, "lib", "libopus.so")
    if IS_TERMUX and not os.path.exists(libopus):
        return False, "libopus.so missing  (pkg install libopus)"

    # At least ONE audio backend must exist. AAudio is preferred and needs no
    # package at all; parec/pacat are only the fallback. Requiring PulseAudio
    # here would refuse calls on a device where AAudio works perfectly.
    try:
        import otrv4plus_audio as _aud
        if _aud.aaudio_available():
            return True, "ok"
    except Exception as exc:
        return False, "audio backend module unavailable: %s" % exc
    if _which("parec") is not None and _which("pacat") is not None:
        return True, "ok"
    return (False,
            "no audio backend: libaaudio.so unavailable and parec/pacat "
            "missing  (run /audioprobe for details)")

XMPP_VERSION = "10.12.0"

# ---------------------------------------------------------------------------
# XMPP-private state directory
# ---------------------------------------------------------------------------
#
# XMPP and IRC used to share ~/.otrv4plus/trust.json, and that was not merely
# untidy. IRC regenerates its Ed448 identity every run by design, so every IRC
# fingerprint written there is stale the moment the process exits; on the next
# run `add_trust` raised FingerprintMismatchError and the user was told "This
# may indicate a MITM attack" for what was actually normal IRC behaviour.
#
# The two protocols have opposite identity contracts, so they get separate
# stores. XMPP owns everything under ~/.otrv4plus/xmpp/ and IRC keeps the
# legacy paths for its SMP secrets while persisting no trust at all.
XMPP_STATE_DIR = os.path.expanduser(
    os.environ.get("OTRV4PLUS_XMPP_STATE_DIR", "~/.otrv4plus/xmpp"))


def _xmpp_state_path(name: str) -> str:
    return os.path.join(XMPP_STATE_DIR, name)


def _migrate_legacy_smp_secrets() -> None:
    """Move a pre-split SMP secret store into the XMPP directory, once.

    The secrets are sealed under a key derived from `.smp_seed` in the *same*
    directory, so the seed has to travel with them or the copy is unopenable.
    Copies rather than moves: the IRC client still reads the legacy pair, and
    silently removing its stored secrets is not this function's business.
    """
    legacy_dir = os.path.expanduser("~/.otrv4plus")
    legacy_secrets = os.path.join(legacy_dir, "smp_secrets.json")
    legacy_seed = os.path.join(legacy_dir, ".smp_seed")
    target_secrets = _xmpp_state_path("smp_secrets.json")
    target_seed = _xmpp_state_path(".smp_seed")

    if os.path.exists(target_secrets) or not os.path.exists(legacy_secrets):
        return
    if not os.path.exists(legacy_seed):
        # Ciphertext with no key: copying it would just move an unopenable
        # file. Leave it and let the user re-enter secrets.
        return
    try:
        os.makedirs(XMPP_STATE_DIR, mode=0o700, exist_ok=True)
        for src, dst in ((legacy_seed, target_seed),
                         (legacy_secrets, target_secrets)):
            with open(src, "rb") as fh:
                blob = fh.read()
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, blob)
            finally:
                os.close(fd)
        print("[smp] migrated stored passphrases into %s" % XMPP_STATE_DIR)
    except FileExistsError:
        pass
    except OSError as exc:
        print("[smp] could not migrate stored passphrases (%s); "
              "re-enter them with /smp-secret" % exc.__class__.__name__)


def _xmpp_otr_config():
    """OTRConfig for XMPP: persistent identity, persistent trust, own paths.

    This is the only place the two protocols diverge in configuration, and the
    divergence is deliberate. See XMPP_STATE_DIR above.
    """
    _migrate_legacy_smp_secrets()
    return OTRConfig(
        test_mode=True,
        persist_identity=True,
        persist_trust=True,
        trust_db_path=_xmpp_state_path("trust.json"),
        smp_secrets_path=_xmpp_state_path("smp_secrets.json"),
        identity_path=_xmpp_state_path("identity.sealed"),
        identity_dek_path=_xmpp_state_path(".identity_dek"),
    )


OTR_MODULE = "otrv4plus"  # symlink -> otrv4+.py
try:
    _otr = __import__(OTR_MODULE)
    EnhancedSessionManager = _otr.EnhancedSessionManager
    OTRConfig = _otr.OTRConfig
    OTRTracer = getattr(_otr, "OTRTracer", None)
    I2PSAMConnection = getattr(_otr, "I2PSAMConnection", None)
except Exception as e:
    print(f"Could not import OTR engine from '{OTR_MODULE}': {e}", file=sys.stderr)
    print(
        "Ensure otrv4+.py, the otrv4plus.py symlink, and otrv4_core.so are "
        "in this directory.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Terminal UI - REUSES the engine's own ANSI TUI (PanelManager / Screen / raw
# line editor), the same one the IRC client uses.
# ---------------------------------------------------------------------------
_PanelManager = getattr(_otr, "PanelManager", None)
_Screen = getattr(_otr, "Screen", None)
_UIConstants = getattr(_otr, "UIConstants", None)
_setup_raw_mode = getattr(_otr, "_setup_raw_mode", None)
_restore_terminal = getattr(_otr, "_restore_terminal", None)
_read_one_char = getattr(_otr, "_read_one_char", None)
_handle_input_char = getattr(_otr, "_handle_input_char", None)
_set_prompt = getattr(_otr, "_set_prompt", None)
_colorize = getattr(_otr, "colorize", lambda s, c: s)
_EOF_SENTINEL = getattr(_otr, "_EOF_SENTINEL", object())
_TUI_AVAILABLE = all(
    x is not None
    for x in (
        _PanelManager,
        _Screen,
        _UIConstants,
        _setup_raw_mode,
        _restore_terminal,
        _read_one_char,
        _handle_input_char,
        _set_prompt,
    )
)

_ACTIVE_TUI_CLIENT = None
# Set unconditionally as soon as the client object exists, independent of
# whether the TUI starts.  The module-level print() uses this to route every
# line to channel_log even in plain (--no-tui / default) mode.
_ACTIVE_CLIENT = None

# Full session transcript (written under --debug, deleted on clean exit).
_SESSION_LOG_FH = None
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _sanitise(text, max_len: int = 1024) -> str:
    """Strip ANSI/OSC/CSI escape sequences and control characters from
    untrusted data (peer JIDs, plaintext bodies, decrypted OTR payloads)
    before writing to the terminal."""
    text = str(text)
    text = re.sub(r"\x1b[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", "", text)
    text = re.sub(r"\x1b[\x20-\x2f][\x30-\x7e]", "", text)
    text = re.sub(r"\x1b.", "", text, flags=re.DOTALL)
    text = re.sub(r"[\x00-\x08\x0a-\x1f\x7f\x80-\x9f]", "", text)
    return text[:max_len]


# Lines carrying actual message content are redacted from the on-disk
# transcript so cleartext bodies never touch disk.
_LOG_CONTENT_RE = re.compile(r"^(\[(?:otr|plain)\] <[^>]*>)\s(.*)$", re.DOTALL)


def _log_to_file(msg):
    if _SESSION_LOG_FH is None:
        return
    try:
        clean = _ANSI_RE.sub("", msg)
        m = _LOG_CONTENT_RE.match(clean)
        if m:
            clean = f"{m.group(1)} <message body redacted: {len(m.group(2))} chars>"
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        _SESSION_LOG_FH.write(f"{ts} {clean}\n")
        _SESSION_LOG_FH.flush()
    except Exception:
        pass


def print(*args, **kwargs):  # noqa: A001 (intentional module-scope shadow)
    c = _ACTIVE_TUI_CLIENT
    sep = kwargs.get("sep", " ")
    msg = sep.join(str(a) for a in args)
    _log_to_file(msg)
    # Always write to the encrypted per-peer channel log, TUI or not.
    # Without this, plain-mode sessions (the default) never record history.
    lc = _ACTIVE_CLIENT
    if lc is not None and getattr(lc, "channel_log", None) is not None and msg:
        try:
            peer = lc._extract_peer(msg) if hasattr(lc, "_extract_peer") else None
            lc.channel_log.append(peer or "system", msg)
        except Exception:
            pass
    if c is not None and getattr(c, "_tui_enabled", False):
        try:
            c._tui_route_output(msg)
            return
        except Exception:
            pass
    builtins.print(*args, **kwargs)


try:
    from slixmpp import ClientXMPP
    from slixmpp.exceptions import IqError, IqTimeout
except ImportError:
    builtins.print("slixmpp not installed.  Run:  pip install slixmpp aiodns", file=sys.stderr)
    sys.exit(1)

try:
    from otrv4plus_log import ChannelLogManager as _ChannelLogManager
    _LOG_AVAILABLE = True
except ImportError:
    _ChannelLogManager = None
    _LOG_AVAILABLE = False


OTR_PREFIX = "?OTRv4 "
OTR_PREFIX_B = b"?OTRv4 "

# SMP passphrase length bounds enforced before passing to the Rust engine.
SMP_MIN_LEN = 8
SMP_MAX_LEN = 512

# Rate limiting: max inbound messages per peer per window.
_RATE_MAX = 20
_RATE_WINDOW = 5.0  # seconds

# Reconnect backoff constants.
_RECONNECT_BASE = 5    # seconds (initial delay)
_RECONNECT_MAX  = 300  # seconds (5 min ceiling)

# Matches a bare JID for output panel routing.
_JID_PATTERN = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+")


def _fmt_fp(fp: str) -> str:
    """Format a fingerprint as space-separated groups of 8 hex chars."""
    if not fp or fp == "unavailable":
        return fp or "unavailable"
    clean = fp.upper().replace(" ", "")
    return " ".join(clean[i : i + 8] for i in range(0, len(clean), 8))


# =============================================================================
# I2P SAM forwarder
# =============================================================================

# ---------------------------------------------------------------------------
# Tor SOCKS5 forwarder
# ---------------------------------------------------------------------------

#: Tor's default SOCKS port. 9150 is the Tor Browser bundle; 9050 is a system
#: tor daemon, which is what Termux installs.
TOR_SOCKS_PORT = 9050

SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CONNECT = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_IPV6 = 0x04

#: SOCKS5 reply codes worth naming; the rest are reported numerically.
_SOCKS5_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable (is the onion service up?)",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


async def socks5_connect(dest_host: str, dest_port: int,
                         socks_host: str = "127.0.0.1",
                         socks_port: int = TOR_SOCKS_PORT,
                         timeout: float = 60.0):
    """Open a SOCKS5 tunnel to dest_host:dest_port and return (reader, writer).

    The destination is sent as a DOMAIN NAME (ATYP 0x03), never as an
    address. That is the whole point: Tor resolves the name itself, inside
    the network, so a .onion never reaches the system resolver and there is
    no DNS to leak. Resolving locally first and sending an IP would defeat
    Tor for .onion entirely -- there is no IP to resolve to.

    PySocks is deliberately not used. It works by replacing socket.socket
    globally, which in this process would also capture the SAM bridge
    connection and every voice media socket. A local tunnel touches nothing
    else.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port), timeout=timeout)

    async def _fail(message):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise ConnectionError(message)

    try:
        # Greeting: one method offered, no authentication. Tor's SOCKS port
        # is loopback-only and unauthenticated by design.
        writer.write(bytes([SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if reply[0] != SOCKS5_VERSION:
            await _fail("not a SOCKS5 proxy at %s:%d (version byte 0x%02x)"
                        % (socks_host, socks_port, reply[0]))
        if reply[1] != SOCKS5_NO_AUTH:
            await _fail("SOCKS5 proxy demands authentication method 0x%02x"
                        % reply[1])

        host_bytes = dest_host.encode("idna" if not dest_host.endswith(".onion")
                                      else "ascii")
        if len(host_bytes) > 255:
            await _fail("destination hostname is too long for SOCKS5")

        writer.write(bytes([SOCKS5_VERSION, SOCKS5_CONNECT, 0x00,
                            SOCKS5_ATYP_DOMAIN, len(host_bytes)])
                     + host_bytes
                     + int(dest_port).to_bytes(2, "big"))
        await writer.drain()

        head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if head[0] != SOCKS5_VERSION:
            await _fail("malformed SOCKS5 reply")
        if head[1] != 0x00:
            await _fail("SOCKS5 CONNECT refused: %s"
                        % _SOCKS5_ERRORS.get(head[1],
                                             "code 0x%02x" % head[1]))

        # Drain the bound address so the stream starts at the payload.
        atyp = head[3]
        if atyp == SOCKS5_ATYP_IPV4:
            await reader.readexactly(4)
        elif atyp == SOCKS5_ATYP_IPV6:
            await reader.readexactly(16)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length)
        else:
            await _fail("SOCKS5 reply used unknown address type 0x%02x" % atyp)
        await reader.readexactly(2)          # bound port
        return reader, writer
    except asyncio.IncompleteReadError:
        await _fail("SOCKS5 proxy closed the connection during the handshake")
    except (ConnectionError, asyncio.TimeoutError):
        raise
    except Exception as exc:
        await _fail("SOCKS5 handshake failed: %s" % exc)


async def start_tor_socks_forwarder(onion_host: str, dest_port: int,
                                    socks_host: str = "127.0.0.1",
                                    socks_port: int = TOR_SOCKS_PORT):
    """Tunnel to a .onion through Tor and expose it as a local TCP endpoint.

    Returns (local_host, local_port). Deliberately the same shape as
    start_i2p_sam_forwarder, and for the same reason: slixmpp is handed a
    loopback address, so its SRV lookup is skipped ("If an address was
    provided, disable using DNS SRV lookup") and the .onion name never
    reaches a resolver. The name travels only inside the SOCKS5 CONNECT,
    where Tor is the thing that resolves it.

    Fails closed. If Tor is not reachable this raises, and the caller must
    not fall back to a direct connection: doing so would send the user's
    address to a server they asked to reach anonymously.
    """
    print("[tor] opening SOCKS5 tunnel to %s:%d via %s:%d ..."
          % (_sanitise(onion_host, 80), dest_port, socks_host, socks_port))
    tor_reader, tor_writer = await socks5_connect(
        onion_host, dest_port, socks_host=socks_host, socks_port=socks_port)
    print("[tor] tunnel established.")

    async def _handle_local(local_reader, local_writer):
        async def pump(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(pump(local_reader, tor_writer),
                             pump(tor_reader, local_writer),
                             return_exceptions=True)

    server = await asyncio.start_server(_handle_local, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    # Held on the loop so neither the server nor the tunnel is collected.
    _TOR_FORWARDERS.append((server, tor_reader, tor_writer))
    print("[tor] local bridge ready at %s:%d -> %s"
          % (host, port, _sanitise(onion_host, 80)))
    return host, port


#: Keeps forwarder objects alive for the process lifetime.
_TOR_FORWARDERS = []


async def start_i2p_sam_forwarder(
    dest_b32: str, dest_port: int, sam_host: str = "127.0.0.1", sam_port: int = 7656
):
    """
    Open an I2P SAM stream to `dest_b32` and expose it as a local TCP endpoint.

    Returns (local_host, local_port). slixmpp connects to the local endpoint and
    does STARTTLS normally; bytes are piped over the SAM stream to the I2P
    destination. The SAM connection, local server, and writer are kept alive on
    the loop so they are not garbage-collected.
    """
    if I2PSAMConnection is None:
        raise RuntimeError(
            "I2PSAMConnection not available from the OTR module; "
            "cannot use I2P SAM transport."
        )

    loop = asyncio.get_event_loop()
    sam = I2PSAMConnection(sam_host=sam_host, sam_port=sam_port)

    def _do_sam():
        s = sam.connect(dest_b32)
        s.setblocking(False)
        return s

    print(f"[i2p] opening SAM stream to {dest_b32} (a cold tunnel can take 30-90s)...")
    sam_sock = await loop.run_in_executor(None, _do_sam)
    print("[i2p] SAM stream established.")

    sam_reader, sam_writer = await asyncio.open_connection(sock=sam_sock)

    # I2P tunnels can drop a stream when a large message is written as one
    # burst. We pace writes in small chunks to avoid the SAM cliff (~8KB).
    SAM_CHUNK = 1024        # bytes per write toward I2P
    SAM_CHUNK_DELAY = 0.02  # seconds between chunks on large messages

    async def _handle_local(local_reader, local_writer):
        async def pump_to_i2p(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    if len(data) <= SAM_CHUNK:
                        dst.write(data)
                        await dst.drain()
                    else:
                        for i in range(0, len(data), SAM_CHUNK):
                            dst.write(data[i : i + SAM_CHUNK])
                            await dst.drain()
                            await asyncio.sleep(SAM_CHUNK_DELAY)
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        async def pump_from_i2p(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            pump_to_i2p(local_reader, sam_writer),
            pump_from_i2p(sam_reader, local_writer),
        )

    server = await asyncio.start_server(_handle_local, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    if not hasattr(loop, "_i2p_keep"):
        loop._i2p_keep = []
    loop._i2p_keep.extend([sam, server, sam_writer])
    print(f"[i2p] local bridge ready at {host}:{port} -> {dest_b32}")
    return host, port



# SAM timeouts (seconds).
#
# These must be separated by what the command actually DOES, not lumped
# together as "control plane". HELLO is a local handshake and answers in
# milliseconds. SESSION CREATE with DESTINATION=TRANSIENT, by contrast, makes
# i2pd construct a complete set of inbound and outbound tunnels BEFORE it
# replies — the same 30-120 s the XMPP tunnel took at startup, and longer on a
# busy phone. Applying a control-plane timeout to it caused calls to fail with
# "SAM timed out after 60s" while i2pd was still working normally.
SAM_HELLO_TIMEOUT = 30           # local handshake; near-instant
SAM_SESSION_TIMEOUT = 300        # builds tunnels before replying
SAM_ACCEPT_TIMEOUT = 300         # waits for the peer to connect
SAM_CONNECT_TIMEOUT = 240        # builds a path to the peer's destination
SAM_CTRL_TIMEOUT = SAM_HELLO_TIMEOUT   # retained for older call sites


def _ossl_cleanse(buf: bytearray) -> None:
    """Overwrite a mutable buffer in place.

    Prefers OPENSSL_cleanse from the OTR engine's C extension, which the
    compiler cannot elide. Falls back to a Python loop only if unavailable.
    """
    try:
        mod = getattr(_otr, "_ossl", None)
        if mod is not None and hasattr(mod, "cleanse"):
            mod.cleanse(buf)
            return
    except Exception:
        pass
    for i in range(len(buf)):
        buf[i] = 0


def _pipe_read_exact(stream, count, keep_going):
    """Read exactly `count` bytes from an unbuffered pipe.

    The audio children are spawned with bufsize=0, so their pipes are raw
    FileIO objects. Unlike a BufferedReader, raw read(n) is permitted to
    return fewer than n bytes at any time without being at EOF — that is the
    normal case on a pipe. Treating a short read as EOF would silently kill
    capture after the first partial frame and produce a one-way call.

    Returns the bytes read, or None on genuine end-of-stream.
    """
    chunks = bytearray()
    while len(chunks) < count:
        if not keep_going():
            return None
        try:
            block = stream.read(count - len(chunks))
        except (InterruptedError, BlockingIOError):
            continue
        except Exception:
            return None
        if block is None:            # non-blocking pipe with nothing ready
            time.sleep(0.002)
            continue
        if block == b"":             # genuine EOF: the child exited
            return None
        chunks += block
    return bytes(chunks)


def _pipe_write_all(stream, data):
    """Write every byte to an unbuffered pipe.

    Raw FileIO.write() may accept only part of the buffer; the remainder must
    be resubmitted or the audio stream desynchronises.
    """
    view = memoryview(data)
    while view:
        try:
            written = stream.write(view)
        except (InterruptedError, BlockingIOError):
            continue
        except Exception:
            return False
        if not written:
            return False
        view = view[written:]
    try:
        stream.flush()
    except Exception:
        pass
    return True


def _sam_release(sock) -> None:
    """Force a socket to release any thread blocked reading it.

    close() alone is NOT sufficient: on Linux a thread already parked in
    recv() is not woken when another thread closes the descriptor, and it
    stays blocked until its own timeout expires — up to SAM_ACCEPT_TIMEOUT.
    shutdown() delivers the wakeup; close() then frees the descriptor.
    Measured: close() 8s+ (never), shutdown()+close() under 1 ms.
    """
    if sock is None:
        return
    import socket as _socket
    try:
        sock.shutdown(_socket.SHUT_RDWR)
    except Exception:
        pass          # already dead or never connected — close still needed
    try:
        sock.close()
    except Exception:
        pass


class SAMProtocolError(Exception):
    """A SAM bridge command returned a non-OK result or malformed reply."""


def _sam_read_line(sock, timeout: float) -> str:
    """Read a single newline-terminated SAM control line.

    Reads exactly one byte at a time and stops at the newline so that not one
    byte of the payload that follows is consumed. SAM control lines are short
    and appear at most twice per call, so this is not a hot path.
    """
    import socket as _socket

    sock.settimeout(timeout)
    chunks = bytearray()
    while True:
        try:
            b = sock.recv(1)
        except _socket.timeout:
            raise SAMProtocolError(f"SAM timed out after {timeout}s")
        if not b:
            raise SAMProtocolError("SAM closed the connection")
        if b == b"\n":
            break
        chunks += b
        if len(chunks) > 8192:
            raise SAMProtocolError("SAM control line exceeded 8192 bytes")
    return chunks.decode("utf-8", errors="replace").strip()


def _sam_parse(line: str, expected_prefix: str) -> dict:
    """Parse a SAM reply line into a key -> value mapping.

    Raises SAMProtocolError unless the prefix matches and RESULT=OK.
    """
    if not line.startswith(expected_prefix):
        raise SAMProtocolError(f"expected '{expected_prefix}', got: {line[:200]}")
    fields = {}
    for token in line[len(expected_prefix):].split():
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key] = value
    if fields.get("RESULT") != "OK":
        raise SAMProtocolError(f"SAM error: {line[:200]}")
    return fields


def _sam_handshake(sock) -> None:
    """Perform the mandatory SAM v3.1 HELLO exchange on a fresh socket."""
    sock.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
    _sam_parse(_sam_read_line(sock, SAM_CTRL_TIMEOUT), "HELLO REPLY ")


def _sam_open(host: str, port: int, timeout: float):
    """Open a TCP socket to the SAM bridge and complete the handshake."""
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        _sam_handshake(sock)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise
    return sock



# =============================================================================
# Voice call: encrypted Opus over a single bidirectional I2P SAM stream
# =============================================================================
#
# The voice subsystem lives in otrv4plus_voice.py (protocol v3: hybrid
# X448 + ML-KEM-1024 media keys, call-ID-bound signalling, two-phase rekey,
# authenticated media headers).  It is a separate module so that the key
# agreement, the rekey state machine and the replay window can be tested
# without importing slixmpp, opuslib or PulseAudio — see
# test_voice_security.py.  Read the module docstring there for the wire
# format and the exact security claims.
#
# Everything below re-exports the voice names under their historical
# module-level spellings so the rest of this file is unchanged.

import otrv4plus_voice as _voice

_voice.bind_host(
    print=print,
    sanitise=_sanitise,
    ossl_cleanse=_ossl_cleanse,
    which=_which,
    load_opus=_load_opus,
    voice_available=voice_available,
    sam_open=_sam_open,
    sam_read_line=_sam_read_line,
    sam_parse=_sam_parse,
    sam_release=_sam_release,
    pipe_read_exact=_pipe_read_exact,
    pipe_write_all=_pipe_write_all,
    opus=_opus,
    termux_prefix=TERMUX_PREFIX,
    is_termux=IS_TERMUX,
)

VoiceKeyExchange = _voice.VoiceKeyExchange
VoiceFrameCrypto = _voice.VoiceFrameCrypto
VoiceKeySchedule = _voice.VoiceKeySchedule
VoiceCallSession = _voice.VoiceCallSession
VoiceCallManager = _voice.VoiceCallManager
CallState = _voice.CallState
KemUnavailable = _voice.KemUnavailable

VOICE_SAMPLE_RATE = _voice.VOICE_SAMPLE_RATE
VOICE_FRAME_MS = _voice.VOICE_FRAME_MS
VOICE_FRAME_SAMPLES = _voice.VOICE_FRAME_SAMPLES
VOICE_CHANNELS = _voice.VOICE_CHANNELS
VOICE_FRAME_BYTES = _voice.VOICE_FRAME_BYTES
VOICE_BITRATE = _voice.VOICE_BITRATE
VOICE_OPUS_SLOT = _voice.VOICE_OPUS_SLOT
VOICE_PACKET_LEN = _voice.VOICE_PACKET_LEN
VOICE_COMPLEXITY = _voice.VOICE_COMPLEXITY
VOICE_LOSS_PCT = _voice.VOICE_LOSS_PCT
VOICE_PLAIN_LEN = _voice.VOICE_PLAIN_LEN
VOICE_SEALED_LEN = _voice.VOICE_SEALED_LEN
VOICE_HDR_LEN = _voice.VOICE_HDR_LEN
VOICE_SYNC = _voice.VOICE_SYNC
VOICE_MIN_FRAME = _voice.VOICE_MIN_FRAME
VOICE_MAX_FRAME = _voice.VOICE_MAX_FRAME
VOICE_JITTER_PREFILL = _voice.VOICE_JITTER_PREFILL
VOICE_JITTER_MAX = _voice.VOICE_JITTER_MAX
VOICE_REKEY_SECONDS = _voice.VOICE_REKEY_SECONDS
VOICE_REKEY_TIMEOUT = _voice.VOICE_REKEY_TIMEOUT
_pad_opus = _voice.pad_opus
_unpad_opus = _voice.unpad_opus

# The _opus module is imported lazily by _load_opus(), so rebind after any
# successful load rather than capturing the None that exists at import time.
_voice_load_opus = _load_opus


def _load_opus_and_bind():
    ok = _voice_load_opus()
    if ok:
        _voice.bind_host(opus=_opus)
    return ok


_voice.bind_host(load_opus=_load_opus_and_bind)


def _smp_query(manager, peer):
    """Ask the OTR engine whether SMP has cryptographically verified a peer.

    Returns (verified, state_name).  The boolean comes only from the engine's
    published predicates; state_name is for display and no decision is taken
    on it.  See otrv4plus_voice._smp_query_default.
    """
    return _voice._smp_query_default(manager, peer)


# =============================================================================
# XMPP client
# =============================================================================

class OTRv4PlusXMPP(ClientXMPP):
    """XMPP transport driving the OTRv4+ engine, with IRC-identical SMP flow."""

    def __init__(self, jid, password, peer=None, debug=False):
        super().__init__(jid, password)
        self.peer = peer

        # Per-peer UI state.
        self._pending = {}         # peer -> 'trust' | 'smp_secret' | None
        # peer -> previously pinned fingerprint, while a mismatch is
        # unresolved. Presence in this map refuses voice for that peer.
        self._fingerprint_changed = {}
        self._encrypted = set()    # peers whose DAKE has completed
        self._smp_reported = set() # (peer, state) already announced
        # Display only.  Populated by _tui_route_output matching
        # substrings such as "SMP VERIFIED" in printed lines, which
        # peer-influenced text can reach.  NOTHING may take a
        # security decision on this set: the voice gate asks the
        # engine's cryptographic predicate and nothing else.
        self._smp_display_hints = set()
        self._frag_seq = 0         # monotonic id for outbound fragment sets

        # Security: subscription approval queue; no auto-approval.
        self._pending_subscriptions = {}  # peer -> presence stanza

        # Security: session-local block list.
        self._blocked = set()

        # Security: per-peer rate limiting.
        self._rate_limit = {}  # peer -> deque of timestamps

        # Reconnect state (populated by main() before connect()).
        self._sam_params = None   # dict of SAM args for reconnect
        self._is_tor = False
        self._tor_params = None   # dict of SOCKS args for reconnect
        self._is_i2p = False
        self._shutting_down = False
        self._reconnect_delay = _RECONNECT_BASE
        self._reconnect_task = None

        # DAKE glare / last DAKE1 for re-send on tie-break.
        self._last_dake1 = {}

        # Terminal-UI state (attached lazily in _start_tui).
        self.panel_manager = None
        self._screen = None
        self._tui_enabled = False
        self._tui_last_panel = None
        self._tui_autofocused = False
        self._tui_jid_by_label = {}
        self._tui_label_by_jid = {}
        self._own_bare = jid.split("/", 1)[0] if jid else ""
        self._prompt_refresh_cb = None
        self.nick = jid.split("@", 1)[0] if jid else "me"
        self._keepalive_task = None
        self._keepalive_ticks = 0        # liveness, shown by /status
        self._keepalive_last_ok = None   # monotonic time of last round trip
        self._keepalive_degraded = False
        self._keepalive_pings = 0        # round trips attempted
        self._keepalive_ping_fails = 0   # consecutive round-trip timeouts
        #: When the stream last delivered ANYTHING. Any inbound stanza proves
        #: the whole path works, which outranks a slow ping reply.
        self._last_inbound = time.monotonic()
        self._keepalive_timeouts = 0     # lifetime, survives reconnects
        self._reconnects_started = 0
        self._reconnects_completed = 0

        # Password re-entry. A rejected password used to be terminal, which
        # over I2P cost another 30-90 s tunnel build just to correct a typo.
        self._auth_failures = 0
        self._password_prompt = None     # prompt text while input is awaited

        # Peers seen to go offline, and when. A peer that never comes back
        # leaves a ratchet that its replacement session cannot use.
        self._peer_gone_at = {}
        self._peer_gone_task = None

        # Voice call manager (initialized lazily after event loop is available)
        self._voice_manager = None
        self._voice_sam_host = "127.0.0.1"
        self._voice_sam_port = 7656
        self._voice_debug = False

        # Diagnostic verbosity is fixed HERE, before the engine exists. The
        # tracer prints protocol state transitions itself, so constructing it
        # with enabled=True made those lines unsuppressible no matter what the
        # emit callback did — which is why --debug appeared to have no effect
        # on them.
        self._probe = bool(debug)

        # OTR engine.
        # The tracer stays ENABLED and is filtered at the callback instead of
        # being switched off. Disabling it wholesale also removed the SMP
        # progress bar, which is the only feedback a user gets during a
        # multi-minute verification — leaving both phones apparently frozen
        # while the protocol ran perfectly underneath.
        tracer = OTRTracer(enabled=True) if OTRTracer else None
        if tracer is not None and hasattr(tracer, "set_emit_callback"):
            def _trace_emit(line, *_a, **_k):
                try:
                    text = str(line)
                except Exception:
                    return
                # The latch runs FIRST and unconditionally: it is the only
                # record that SMP succeeded, because the engine destroys its
                # Rust SMP object afterwards and can no longer be asked.
                try:
                    self._latch_smp_from_trace(text)
                except Exception:
                    pass
                try:
                    if self._probe:
                        print(f"[otr-trace] {text}")
                    elif self._is_progress_line(text):
                        print(text)
                except Exception:
                    pass
            tracer.set_emit_callback(_trace_emit)
        cfg = _xmpp_otr_config()
        try:
            self.otr = EnhancedSessionManager(config=cfg, tracer=tracer)
        except Exception as exc:
            # Fail closed. Persistent identity is what makes TOFU mean
            # anything; starting anyway with a fresh identity would change our
            # fingerprint silently and every peer holding a pin would see it
            # as the identity change TOFU exists to report.
            print("[identity] XMPP could not start: %s" % exc)
            raise
        self.identity_persistent = bool(
            getattr(self.otr, "identity_is_persistent", False))

        # Dedicated SINGLE-thread executor for OTR/SMP crypto. SMP runs
        # multi-minute 3072-bit DH computations; a separate pool keeps the
        # event loop free so keepalive/network stay alive throughout.
        #
        # max_workers is 1 and must stay 1. It was 2, which contradicted the
        # comment above it and crashed a live handshake:
        #
        #   DakeOutput is unsendable, but sent to another thread
        #   left: ThreadId(3)  right: ThreadId(2)
        #
        # otrv4_core::dake::DakeOutput is #[pyclass(unsendable)] -- PyO3
        # records the creating thread and panics on access from any other.
        # The handle is created while one inbound message is processed
        # (generate_dake2 / process_dake2), stored on the session, and
        # consumed while a LATER one is (building the ratchet). A second
        # worker only spawns when a task is submitted while the first is
        # busy, so over I2P, where DAKE messages usually arrive far apart,
        # one thread handled everything and nothing went wrong. The crash
        # came when a fragmented DAKE and DAKE3 arrived back to back.
        #
        # Serialising is also correct independently of PyO3: OTR is a
        # stateful ratchet, and processing two messages for one peer
        # concurrently races the ratchet, skipped-key handling and the SMP
        # state machine. Nothing submitted here re-submits here, so one
        # worker cannot deadlock.
        self._otr_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="otr-crypto"
        )

        # Security: never auto-approve subscription requests.
        self.auto_authorize = False
        self.auto_subscribe = False

        # --- Event handlers ---
        # Every inbound stanza, before any handler. This is the evidence the
        # keepalive judges on; a filter is the only place that sees all of it.
        self.add_filter("in", self._note_inbound)

        self.add_event_handler("session_start",      self._on_start)
        self.add_event_handler("message",            self._on_message)
        self.add_event_handler("failed_auth",        self._on_failed_auth)
        self.add_event_handler("message_error",      self._on_message_error)
        self.add_event_handler("disconnected",       self._on_disconnected)
        self.add_event_handler("connection_failed",  self._on_connection_failed)
        self.add_event_handler("stream_error",       self._on_stream_error)
        self.add_event_handler("presence_subscribe",   self._on_subscribe)
        self.add_event_handler("presence_subscribed",  self._on_subscribed)
        self.add_event_handler("presence_available",   self._on_presence_available)
        self.add_event_handler("presence_unavailable", self._on_presence_unavailable)
        self.add_event_handler("receipt_received",   self._on_delivery_receipt)

        # --- XEP plugins ---
        # XEP-0030: Service discovery (required base for many XEPs).
        self.register_plugin("xep_0030")
        # XEP-0085: Chat state notifications.
        self.register_plugin("xep_0085")
        # XEP-0115: Entity capabilities (efficient feature advertisement).
        self.register_plugin("xep_0115")
        # XEP-0184: Message delivery receipts (auto=True: request+send).
        self.register_plugin("xep_0184", {"auto": True})
        # XEP-0198: Stream management (stanza acks + resumption).
        #   Degrades gracefully if the server does not advertise SM support.
        try:
            self.register_plugin("xep_0198", {"max_misses": 3})
        except Exception:
            pass
        # XEP-0199: XMPP Ping (available for /ping command).
        self.register_plugin("xep_0199")

        # Ephemeral encrypted per-session log: key zeroed and files deleted on exit,
        # matching the IRC client wipe behaviour. Within-session scrollback is backed
        # by the encrypted file so panels load their full history on tab open.
        self.channel_log = _ChannelLogManager(persistent=False) if _LOG_AVAILABLE else None
        self._cleaned_up = False
        # Register globally so print() can route to channel_log even when
        # the TUI is never started (plain mode is now the default).
        global _ACTIVE_CLIENT
        _ACTIVE_CLIENT = self

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _on_start(self, event):
        self.send_presence()
        # Initialize voice call manager now that we have an event loop
        if self._voice_manager is None:
            self._voice_manager = VoiceCallManager(
                self, asyncio.get_event_loop(),
                self._voice_sam_host, self._voice_sam_port)
            self._voice_manager.debug = self._voice_debug
            if self._voice_debug:
                print("[voice] diagnostics enabled (--voice-debug)")
        try:
            await self.get_roster()
        except (IqError, IqTimeout):
            pass
        print(f"\n[connected] {self.boundjid.full}")
        print(f"[version]   OTRv4+ XMPP {XMPP_VERSION}")
        if self.peer:
            self.send_presence_subscription(pto=self.peer)
            print(f"[subscribe] requested presence from {self.peer}")
        print(
            "[ready] /otr to start encryption. After DAKE you'll be asked to "
            "trust the fingerprint, then to set the SMP passphrase.\n"
            "[ready] Type /help for the full command list.\n"
        )
        # Reset reconnect backoff on successful connection.
        self._reconnect_delay = _RECONNECT_BASE
        # Whitespace keepalive to maintain I2P SAM streams during long SMP
        # computations when no application data flows.
        #
        # Cancel any predecessor first. _on_start fires on every session
        # start, and simply reassigning the attribute would orphan a loop
        # that is still running -- two loops then probe the same stream and
        # increment the same counter, reaching the disconnect threshold in
        # half the time for no reason.
        existing = self._keepalive_task
        if existing is not None and not existing.done():
            existing.cancel()
        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())

    # Tracer output that a user needs even when not debugging: long-running
    # operations must show progress, or a working protocol is indistinguishable
    # from a hung one.
    _PROGRESS_TOKENS = ("SMP [", "SMP VERIFIED", "SMP FAILED", "🔐")

    @classmethod
    def _is_progress_line(cls, text: str) -> bool:
        return any(token in text for token in cls._PROGRESS_TOKENS)

    # Phrases the engine emits on a completed SMP. Matching is deliberately
    # narrow: only a terminal success announcement sets the flag, never a
    # progress line that merely mentions verification.
    _SMP_TRACE_SUCCESS = (
        "SMP VERIFIED",
        "SMP: VERIFIED",        # state-transition form: "SMP: VERIFIED → ..."
        "IDENTITY CONFIRMED",
        "SMP COMPLETE",
        "SECRETS MATCH",
    )
    _SMP_TRACE_FAILURE = ("SMP FAILED", "SECRETS DID NOT MATCH", "SMP ABORT")

    def _latch_smp_from_trace(self, line: str) -> None:
        """Record SMP success at the instant the engine announces it.

        The engine destroys its Rust SMP object once the protocol finishes, in
        order to zeroize the secrets. get_smp_status() then early-returns
        {"state": "NONE", "verified": False} forever after, so a verified peer
        becomes indistinguishable from an unverified one by query alone. This
        callback is therefore the authoritative record, and it runs whether or
        not diagnostics are switched on.
        """
        upper = line.upper()
        if any(token in upper for token in self._SMP_TRACE_FAILURE):
            return
        if not any(token in upper for token in self._SMP_TRACE_SUCCESS):
            return

        # Attribute the announcement to a peer. The engine prefixes lines with
        # [OTR:<peer>]; failing that, a single active session is unambiguous.
        target = None
        match = re.search(r"\[OTR:([^\]]+)\]", line)
        if match:
            candidate = match.group(1).strip()
            if "@" in candidate:
                target = candidate.split("/", 1)[0]
        if target is None:
            try:
                active = [p for p in self.otr.sessions
                          if isinstance(p, str) and "@" in p]
                if len(active) == 1:
                    target = active[0].split("/", 1)[0]
            except Exception:
                target = None
        if target is None and self.peer:
            target = self.peer.split("/", 1)[0]
        if target is None:
            return

        key = (target, "SUCCEEDED")
        if key in self._smp_reported:
            return
        self._smp_reported.add(key)
        print("\n[smp] *** IDENTITY VERIFIED with %s - shared secret "
              "matched (SMP complete). ***\n" % target)

    def _dbg(self, message: str) -> None:
        """Protocol-level diagnostic: shown only with --debug.

        Wire-level detail (handshake stages, fragmentation, crypto timing) is
        invaluable when something breaks and pure noise when it does not. On a
        phone screen it buries the conversation, so the default is silence and
        everything here is opt-in.
        """
        if self._probe:
            print(message)

    #: Whitespace cadence. Cheap, and its only job is keeping the I2P tunnel
    #: from being torn down for idleness.
    KEEPALIVE_WHITESPACE_S = 8

    #: Round-trip cadence, used only once the stream has gone quiet.
    KEEPALIVE_PING_S = 60

    #: How long the stream must have received NOTHING before a probe is worth
    #: sending.
    #:
    #: The first version of this keepalive probed unconditionally every 60 s
    #: and scored a slow reply as a failure. Measured on a 33-minute call that
    #: produced ten self-inflicted disconnects: in one case a rekey completed
    #: a full REKEY -> REKEYACK -> REKEYCOMMIT round trip through the server
    #: 3.2 s before the keepalive declared that same stream dead on "3 round
    #: trips in a row went unanswered" -- a verdict that takes ~3 minutes to
    #: accumulate. The stream was carrying bidirectional traffic throughout
    #: the window in which it was being scored as dead.
    #:
    #: The cause was already documented in this project before the keepalive
    #: existed, in VoiceCallManager: "IQ round-trips were deliberately
    #: avoided: over a 3-hop I2P path an IQ frequently exceeds slixmpp's reply
    #: timeout, whereas a <message> is fire-and-forget and traverses
    #: reliably." XEP-0199 is an IQ round trip.
    #:
    #: So a probe is now a last resort rather than a metronome. Any inbound
    #: stanza -- presence, a message, an OTR frame, rekey signalling -- is
    #: proof the whole path works, and proof outranks a slow ping. 180 s sits
    #: above VOICE_REKEY_SECONDS (120 s), so a live call refreshes this from
    #: its own signalling and never probes at all.
    KEEPALIVE_QUIET_S = 180

    #: How long to wait for a ping reply. Sized for a 3-hop I2P round trip
    #: under load rather than for a LAN: the old 30 s was shorter than the
    #: path's own latency and turned slowness into a verdict.
    KEEPALIVE_PING_TIMEOUT_S = 60

    #: Consecutive probe failures before the stream is declared dead. Each one
    #: already means KEEPALIVE_QUIET_S of total silence plus an unanswered
    #: ping, so two is strong evidence and the worst case is ~8 minutes.
    #:
    #: The bias is deliberate. Declaring a healthy stream dead costs a
    #: reconnect storm and an I2P tunnel rebuild; being slow to notice a
    #: genuinely dead one costs a delayed rekey, and a rekey that cannot be
    #: delivered already fails safe on the committed epoch. Media does not use
    #: XMPP at all.
    KEEPALIVE_PING_FAILS = 2

    def _note_inbound(self, stanza):
        """Record that the stream delivered something.  Returns it unchanged.

        Registered as a slixmpp inbound filter, so it sees presence, messages,
        IQs and everything else before any handler runs. It must never drop or
        alter a stanza -- returning it unchanged is the contract.
        """
        self._last_inbound = time.monotonic()
        return stanza

    def _stream_quiet_for(self) -> float:
        """Seconds since the stream last delivered anything."""
        return max(0.0, time.monotonic() - self._last_inbound)

    async def _probe_stream(self) -> bool:
        """Round-trip liveness check against our own server (XEP-0199).

        Returns True if the server answered AT ALL. An IqError counts as
        alive: a server replying `service-unavailable` to a ping has proven
        the stream works, which is the only thing being asked here. Treating
        it as death would reconnect against a perfectly good session.
        """
        try:
            await self["xep_0199"].async_ping(
                self.boundjid.host, timeout=self.KEEPALIVE_PING_TIMEOUT_S)
            return True
        except IqError:
            return True
        except (IqTimeout, asyncio.TimeoutError):
            return False
        except Exception:
            return False

    def _declare_stream_dead(self, why: str) -> None:
        """Give up on the stream and let the reconnect logic take over.

        Breaking out of the keepalive loop is not enough on its own -- it
        only stops pinging. Something has to actually take the stream down so
        `_on_disconnected` fires and `_reconnect` runs.

        Any call in progress is deliberately left alone. Voice media rides
        its own I2P datagram session and does not touch XMPP once the call is
        up; only rekey signalling does, and a rekey that cannot be delivered
        already fails safe by keeping the committed epoch. Tearing down a
        working call because the control plane blinked would be the worse
        outcome by far.
        """
        print("[keepalive] %s — reconnecting. Any call in progress keeps "
              "running: media does not use XMPP." % why)
        try:
            result = self.disconnect()
            # slixmpp returns a coroutine here in some versions.
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
        except Exception as exc:
            print("[keepalive] disconnect failed: %s" % _sanitise(str(exc), 80))

    async def _keepalive_loop(self):
        """Keep the stream alive, and notice when it is not.

        Two mechanisms, because they answer different questions.

        **Whitespace, every 8 s.** Keeps an idle I2P tunnel from being torn
        down, which would drop the session during the long silences of an SMP
        exchange or a call where nothing is being typed.

        **A round trip, every 60 s.** This is the one that matters, and it
        was missing. `send_raw` only writes into the local socket buffer: it
        succeeds whether or not anything is still listening at the far end.
        Over I2P that is not a corner case -- the SAM stream can be gone
        while the local socket keeps accepting writes indefinitely -- so a
        whitespace-only keepalive reports a healthy stream forever, the
        failure counter never moves, `_on_disconnected` never fires, and
        reconnect never runs. The session dies silently and the first symptom
        is the peer appearing to go offline.

        A XEP-0199 ping requires the server to answer, so it proves the whole
        path rather than the first hop of it. On repeated timeout the stream
        is taken down explicitly, because breaking out of this loop on its
        own only stops pinging.

        Calls are never torn down here. Media rides its own I2P datagram
        session; only rekey signalling uses XMPP, and a rekey that cannot be
        delivered already fails safe by keeping the committed epoch.

        The loop is SILENT while it is working, including under --debug. A
        heartbeat that prints every 8 s forever reports nothing new — after
        the second line it is pure noise, and on a phone screen it buries the
        conversation it exists to protect. What is worth saying is a *change*:
        a probe that failed, and one that started working again.

        Set OTRV4PLUS_KEEPALIVE_TRACE=1 to watch every tick; /status reports
        the counters and the age of the last successful round trip.
        """
        trace = bool(os.environ.get("OTRV4PLUS_KEEPALIVE_TRACE"))
        whitespace_failures = 0
        next_probe = time.monotonic() + self.KEEPALIVE_PING_S

        # A new loop means a new stream, so the failure count starts again.
        #
        # It did not, and the effect was measured on a live call: the counter
        # is cleared only by a SUCCESSFUL probe, so after the first genuine
        # detection it stayed at the threshold. Every reconnect then began
        # one failure away from the limit, and a single missed ping
        # disconnected immediately -- the tolerance of three collapsed to
        # one. The live trace showed the counter climbing 3, 4, 5 with a
        # reconnect every ~96 s, which is exactly the ping interval plus the
        # timeout plus the sleep granularity: the period was this loop's own
        # signature, not the network's.
        self._keepalive_ping_fails = 0
        self._keepalive_degraded = False
        try:
            while not self._shutting_down:
                await asyncio.sleep(self.KEEPALIVE_WHITESPACE_S)
                if not self.is_connected():
                    # _on_disconnected owns the reconnect; this task is
                    # cancelled there and restarted by _on_start.
                    break
                self._keepalive_ticks += 1

                try:
                    self.send_raw(" ")
                    whitespace_failures = 0
                except Exception as exc:
                    whitespace_failures += 1
                    if whitespace_failures == 1:
                        print("[keepalive] whitespace write failed (%s)"
                              % _sanitise(str(exc), 80))
                    if whitespace_failures >= 3:
                        self._declare_stream_dead(
                            "the local socket stopped accepting writes")
                        break

                # Traffic is the best possible liveness evidence: it proves
                # the whole path, end to end, without asking the server for
                # anything. While it is arriving there is nothing to probe.
                quiet = self._stream_quiet_for()
                if quiet < self.KEEPALIVE_QUIET_S:
                    if self._keepalive_ping_fails or self._keepalive_degraded:
                        print("[keepalive] stream is delivering again "
                              "(traffic %.0fs ago)" % quiet)
                        self._keepalive_ping_fails = 0
                        self._keepalive_degraded = False
                    self._keepalive_last_ok = time.monotonic()
                    if trace:
                        print("[keepalive] tick %d (traffic %.0fs ago)"
                              % (self._keepalive_ticks, quiet))
                    continue

                if time.monotonic() < next_probe:
                    if trace:
                        print("[keepalive] tick %d (quiet %.0fs, probe due "
                              "in %.0fs)"
                              % (self._keepalive_ticks, quiet,
                                 next_probe - time.monotonic()))
                    continue

                next_probe = time.monotonic() + self.KEEPALIVE_PING_S
                self._keepalive_pings += 1
                alive = await self._probe_stream()

                if alive:
                    self._keepalive_last_ok = time.monotonic()
                    if self._keepalive_degraded:
                        print("[keepalive] server responding again after %d "
                              "missed round trip(s)"
                              % self._keepalive_ping_fails)
                        self._keepalive_degraded = False
                    self._keepalive_ping_fails = 0
                    if trace:
                        print("[keepalive] round trip %d ok"
                              % self._keepalive_pings)
                elif self._stream_quiet_for() < self.KEEPALIVE_QUIET_S:
                    # The reply never came, but something else did while we
                    # waited. The path works and the ping was merely slow --
                    # which over three I2P hops is ordinary, not a fault.
                    self._keepalive_last_ok = time.monotonic()
                    self._keepalive_ping_fails = 0
                    self._keepalive_degraded = False
                    if trace:
                        print("[keepalive] probe %d unanswered but traffic "
                              "arrived — not counted" % self._keepalive_pings)
                else:
                    self._keepalive_ping_fails += 1
                    # Lifetime tally, deliberately NOT reset per session: it
                    # is what distinguishes "one bad patch" from "this path
                    # degrades every couple of minutes" across a long call.
                    self._keepalive_timeouts += 1
                    if not self._keepalive_degraded:
                        # Said once, not once per probe.
                        self._keepalive_degraded = True
                        print("[keepalive] no reply from the server — the "
                              "I2P tunnel or the stream may be gone")
                    if self._keepalive_ping_fails >= self.KEEPALIVE_PING_FAILS:
                        self._declare_stream_dead(
                            "%d round trips in a row went unanswered"
                            % self._keepalive_ping_fails)
                        break
        except asyncio.CancelledError:
            pass

    MAX_AUTH_ATTEMPTS = 3

    def _on_failed_auth(self, event):
        """Offer a re-entry instead of ending the session on a typo.

        Retrying automatically with the SAME password would loop forever, so
        the reconnect loop stays blocked until a new one is supplied: while
        _password_prompt is set, _schedule_reconnect refuses to run. Only a
        password the user actually typed unblocks it.
        """
        self._auth_failures += 1
        left = self.MAX_AUTH_ATTEMPTS - self._auth_failures
        if left <= 0 or not self._can_prompt_for_password():
            print("\n[auth failed] the server rejected that password.",
                  file=sys.stderr)
            if left <= 0:
                print("[auth failed] %d attempts used — giving up. Check the "
                      "JID and restart." % self._auth_failures,
                      file=sys.stderr)
            self._shutting_down = True
            return
        print("\n[auth failed] the server rejected that password.")
        print("[auth] %d attempt%s left."
              % (left, "" if left == 1 else "s"))
        print("[auth] press Enter, then type the password again "
              "(it will not be shown).")
        self._password_prompt = "Password for %s: " % (self._own_bare or "?")

    def _can_prompt_for_password(self) -> bool:
        """True when a hidden prompt can actually be delivered.

        The plain reader owns stdin and can swap in getpass. The TUI draws
        and echoes its own input line, so a password typed there would be on
        screen and in any terminal capture; rather than leak it, that mode
        reports the failure and stays down.
        """
        if getattr(self, "_tui_enabled", False):
            return False
        try:
            return bool(sys.stdin.isatty())
        except Exception:
            return False

    def supply_password(self, text) -> None:
        """Accept a re-entered password and resume connecting."""
        if self._password_prompt is None:
            return
        self._password_prompt = None
        secret = (text or "").strip("\r\n")
        if not secret:
            print("[auth] nothing entered — session stays down.")
            self._shutting_down = True
            try:
                self.disconnect()
            except Exception:
                pass
            return
        # slixmpp's password setter writes credentials['password'], which is
        # what the next SASL attempt reads.
        self.password = secret
        self._reconnect_delay = _RECONNECT_BASE
        print("[auth] retrying with the new password…")
        self._schedule_reconnect("password re-entered")

    def _has_transport_params(self) -> bool:
        """True when reconnect knows which transport to re-establish.

        Reconnect is only scheduled when this holds. Without it the loop
        would run with no transport configured and take the direct-connect
        branch, which for an I2P or Tor session means silently exposing the
        user's address -- so "we do not know how to reconnect" has to mean
        "stay down", not "reconnect somehow".
        """
        return (self._sam_params is not None
                or getattr(self, "_tor_params", None) is not None)

    def _schedule_reconnect(self, why: str) -> None:
        """Start the reconnect loop unless one is already running.

        Every path that wants a reconnect goes through here. _on_disconnected
        and _on_connection_failed both fire during a failed reconnect attempt,
        and they used to schedule independently -- one of them without even
        recording the task, so it was invisible to the other's guard. The
        result was two loops with independent backoff delays both calling
        connect(), and on I2P two SAM forwarders being built for one session.
        """
        if self._shutting_down or not self._has_transport_params():
            return
        if self._password_prompt is not None:
            # Reconnecting now would present the password the server has
            # already rejected, and do it every few seconds forever.
            return
        existing = self._reconnect_task
        if existing is not None and not existing.done():
            return
        try:
            loop = asyncio.get_event_loop()
            self._reconnect_task = loop.create_task(self._reconnect())
        except Exception as exc:
            print("[reconnect] could not schedule after %s: %s"
                  % (why, _sanitise(str(exc), 80)))

    def _on_disconnected(self, event):
        print("\n[disconnected]")
        if self._keepalive_task:
            self._keepalive_task.cancel()
        # Our stream is what went away. Every peer will look unavailable for
        # the duration, and none of them has actually gone anywhere.
        self._clear_peer_gone("our transport dropped")
        self._schedule_reconnect("disconnect")

    def _on_connection_failed(self, event):
        reason = str(event) if event else "unknown"
        print(f"[connection failed] {_sanitise(reason, 256)}")
        self._schedule_reconnect("connection failure")

    # Stream errors that will NEVER succeed on retry. Reconnecting after one
    # of these rebuilds an I2P tunnel every few seconds forever, burning
    # bandwidth and hiding the real cause behind a wall of reconnect noise.
    _FATAL_STREAM_ERRORS = {
        "host-unknown": (
            "the server does not serve the domain in your --jid.\n"
            "  Your JID domain must match the server's VirtualHost.\n"
            "  If you connect by .b32.i2p address, pass it with --server and\n"
            "  keep the configured host name in --jid, e.g.\n"
            "    --jid you@yourhost.i2p --server <b32>.b32.i2p"),
        "not-authorized": "the server rejected this account or password.",
        "unsupported-version": "the server requires a different XMPP version.",
        "invalid-namespace": "protocol mismatch — is this an XMPP server?",
        "see-other-host": "the server redirected to another host.",
    }

    def _on_stream_error(self, error):
        raw = str(error)
        condition = getattr(error, "condition", None) or raw
        print(f"[stream error] {_sanitise(str(condition), 256)}")

        # slixmpp does not always populate .condition, so fall back to
        # matching the element name inside the raw stanza.
        matched = None
        for name in self._FATAL_STREAM_ERRORS:
            if name == str(condition) or ("<%s " % name) in raw or (
                    "<%s>" % name) in raw:
                matched = name
                break
        if matched is None:
            return

        self._shutting_down = True          # stop the reconnect loop
        print("\n[fatal] %s" % self._FATAL_STREAM_ERRORS[matched])
        print("[fatal] Not retrying — this cannot succeed without a change "
              "to your arguments or the server configuration.\n")
        try:
            self.disconnect()
        except Exception:
            pass

    async def _reconnect(self):
        """Exponential-backoff reconnect. Re-establishes the I2P SAM tunnel
        before reconnecting slixmpp when running over I2P."""
        while not self._shutting_down:
            delay = self._reconnect_delay
            print(f"[reconnect] waiting {delay}s before reconnecting...")
            await asyncio.sleep(delay)
            if self._shutting_down:
                return
            # The resource is what changes across a reconnect, and the next
            # live test needs to show whether it changes cleanly. The bare
            # JID is already on screen from [connected]; only the resource is
            # added here, and it is server-assigned rather than secret.
            before = ""
            try:
                before = self.boundjid.resource or ""
            except Exception:
                pass
            self._reconnects_started = getattr(self, "_reconnects_started",
                                               0) + 1
            print("[reconnect] attempt %d, resource before=%s"
                  % (self._reconnects_started,
                     _sanitise(before, 40) or "(none)"))
            try:
                if self._is_i2p and self._sam_params:
                    p = self._sam_params
                    try:
                        host, port = await start_i2p_sam_forwarder(
                            p["server_b32"],
                            p["dest_port"],
                            sam_host=p["sam_host"],
                            sam_port=p["sam_port"],
                        )
                    except Exception as e:
                        print(f"[reconnect] SAM bridge failed: {e}")
                        self._reconnect_delay = min(
                            self._reconnect_delay * 2, _RECONNECT_MAX
                        )
                        continue
                    self.connect(host, port)
                elif getattr(self, "_is_tor", False) and self._tor_params:
                    p = self._tor_params
                    try:
                        host, port = await start_tor_socks_forwarder(
                            p["onion_host"],
                            p["dest_port"],
                            socks_host=p["socks_host"],
                            socks_port=p["socks_port"],
                        )
                    except Exception as e:
                        print(f"[reconnect] Tor tunnel failed: {e}")
                        self._reconnect_delay = min(
                            self._reconnect_delay * 2, _RECONNECT_MAX
                        )
                        continue
                    self.connect(host, port)
                elif getattr(self, "_is_tor", False):
                    # Same reasoning as the I2P guard below: the fall-through
                    # would open a direct connection from a session the user
                    # asked to route through Tor.
                    print("[reconnect] REFUSING to reconnect: this session is "
                          "Tor but the SOCKS parameters are missing. Falling "
                          "back to a direct connection would expose your "
                          "address, so the session stays down.")
                    return
                elif self._is_i2p:
                    # Unreachable today: _sam_params and _is_i2p are set
                    # together, and _on_disconnected only schedules this loop
                    # when _sam_params is not None. It is guarded anyway
                    # because of what the fall-through WOULD do -- open a
                    # direct clearnet connection to the XMPP server from a
                    # session the user asked to run over I2P, silently
                    # exposing their address. A transport downgrade must
                    # never be reachable by one condition drifting.
                    print("[reconnect] REFUSING to reconnect: this session is "
                          "I2P but the SAM parameters are missing. Falling "
                          "back to a direct connection would expose your "
                          "address, so the session stays down.")
                    return
                else:
                    self.connect()
                self._reconnects_completed = getattr(
                    self, "_reconnects_completed", 0) + 1
                print("[reconnect] transport re-established (%d/%d). "
                      "[connected] will report the new resource."
                      % (self._reconnects_completed,
                         self._reconnects_started))
                return  # _on_start resets _reconnect_delay on success
            except Exception as e:
                print(f"[reconnect] failed: {e}")
                self._reconnect_delay = min(
                    self._reconnect_delay * 2, _RECONNECT_MAX
                )

    def _on_message_error(self, msg):
        peer = msg["from"].bare
        text = msg["error"]["text"] or msg["error"]["condition"]
        print(f"\n[delivery rejected] to {_sanitise(peer, 128)}: {_sanitise(text)}")
        if msg["error"]["condition"] == "forbidden":
            print(
                "  -> not mutually subscribed; both accounts must accept each "
                "other as contacts.\n"
            )

    def _on_delivery_receipt(self, receipt):
        """XEP-0184: fired when a peer acknowledges delivery of our message."""
        try:
            peer = receipt["from"].bare
            msg_id = receipt.get("id", "?")
            print(f"[receipt] delivered to {_sanitise(peer, 128)} (id {msg_id})")
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Presence handling
    # -------------------------------------------------------------------------

    def _on_subscribe(self, presence):
        """Gate subscription requests; never auto-approve."""
        peer = presence["from"].bare
        self._pending_subscriptions[peer] = presence
        print(f"[sub] {_sanitise(peer, 128)} requests subscription.")
        print(f"[sub] Type  /accept {peer}  to approve or  /deny {peer}  to reject.")

    def _on_subscribed(self, presence):
        peer = presence["from"].bare
        print(f"[sub] {_sanitise(peer, 128)} approved our subscription")
        self.send_presence(pto=peer)

    def _on_presence_available(self, presence):
        peer = presence["from"].bare
        if peer == self._own_bare:
            return
        show = presence["show"] or "available"
        status = presence["status"] or ""
        status_s = f" ({_sanitise(status, 64)})" if status else ""
        print(f"[presence] {_sanitise(peer, 128)} is {show}{status_s}")
        self._peer_is_alive(peer)

    def _on_presence_unavailable(self, presence):
        peer = presence["from"].bare
        if peer == self._own_bare:
            return
        print(f"[presence] {_sanitise(peer, 128)} went offline")
        self._arm_peer_gone(peer)

    # -------------------------------------------------------------------------
    # Abandoned OTR sessions
    # -------------------------------------------------------------------------
    #
    # A ratchet is shared state. When the peer's client exits, its half is
    # gone; ours is not, so the next /otr found a live session on our side
    # only, and the DAKE it tried to start went nowhere. start_otr already
    # force-resets a stuck session, but only after a failed attempt the user
    # has to notice and interpret.
    #
    # The trigger is a peer that goes offline and stays offline. It is
    # deliberately NOT "the peer went offline", because that fires constantly
    # for reasons that have nothing to do with the peer: our own stream
    # dropping produces the same presence, and this client reconnects often
    # enough over I2P that tearing down a verified session on a blip would be
    # far worse than the problem being fixed. So the timer is cancelled by
    # anything that proves the peer is still there, and by our own reconnects.

    PEER_GONE_SECONDS = 180

    def _peer_is_alive(self, peer: str) -> None:
        """Any sign of life cancels a pending teardown."""
        self._peer_gone_at.pop(peer, None)

    def _arm_peer_gone(self, peer: str) -> None:
        if peer not in self._encrypted:
            return                       # nothing to clear
        self._peer_gone_at[peer] = time.monotonic()
        self._start_peer_gone_sweeper()

    def _clear_peer_gone(self, why: str = "") -> None:
        """Forget every pending teardown.

        Called when OUR transport drops. The peers looked absent because we
        were, and their sessions are fine.
        """
        if self._peer_gone_at:
            self._peer_gone_at.clear()

    def _start_peer_gone_sweeper(self) -> None:
        task = self._peer_gone_task
        if task is not None and not task.done():
            return
        try:
            loop = asyncio.get_event_loop()
            self._peer_gone_task = loop.create_task(self._peer_gone_sweeper())
        except Exception:
            self._peer_gone_task = None

    async def _peer_gone_sweeper(self) -> None:
        try:
            while not self._shutting_down and self._peer_gone_at:
                await asyncio.sleep(15)
                now = time.monotonic()
                for peer, since in list(self._peer_gone_at.items()):
                    if now - since < self.PEER_GONE_SECONDS:
                        continue
                    if self._peer_in_call(peer):
                        # Media does not use XMPP, so a call can be healthy
                        # while presence says otherwise. Ending OTR here would
                        # take the rekey and END signalling with it.
                        self._peer_gone_at[peer] = now
                        continue
                    self._peer_gone_at.pop(peer, None)
                    self._forget_otr(peer, "offline for %ds"
                                     % self.PEER_GONE_SECONDS)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            print("[otr] session sweeper stopped: %s" % _sanitise(str(exc), 80))

    def _peer_in_call(self, peer: str) -> bool:
        manager = self._voice_manager
        if manager is None:
            return False
        try:
            return bool(manager.has_active_call(peer))
        except Exception:
            return False

    def _forget_otr(self, peer: str, why: str) -> None:
        """Drop every trace of an OTR session so /otr can start a fresh one.

        The same reset start_otr performs on a stuck session, done up front
        instead of after a failure. Nothing here weakens anything: it destroys
        ratchet state, and the peer's next session has to complete a full DAKE
        and be SMP-verified again exactly as the first one did. The pinned
        fingerprint is NOT touched -- that is long-term identity, and forgetting
        it would turn a reconnect into a fresh trust-on-first-use decision.
        """
        if peer not in self._encrypted and peer not in self._pending:
            return
        try:
            self.otr.end_session(peer)
        except Exception as exc:
            print("[otr] could not end session with %s: %s"
                  % (_sanitise(peer, 128), _sanitise(str(exc), 80)))
        self._encrypted.discard(peer)
        self._last_dake1.pop(peer, None)
        self._pending.pop(peer, None)
        self._smp_reported = {k for k in self._smp_reported if k[0] != peer}
        print("[otr] cleared the session with %s (%s) — /otr to start a new "
              "one when they return" % (_sanitise(peer, 128),
                                        _sanitise(why, 64)))

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------

    def _check_rate_limit(self, peer: str) -> bool:
        """Return True if the message should be processed; False if throttled."""
        now = time.monotonic()
        if peer not in self._rate_limit:
            self._rate_limit[peer] = collections.deque()
        dq = self._rate_limit[peer]
        while dq and dq[0] < now - _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= _RATE_MAX:
            return False
        dq.append(now)
        return True

    # -------------------------------------------------------------------------
    # Inbound message routing
    # -------------------------------------------------------------------------

    def _on_message(self, msg):
        if msg["type"] not in ("chat", "normal"):
            return
        peer = msg["from"].bare
        body = msg["body"]
        if not body:
            return

        # Session-local block list check.
        if peer in self._blocked:
            return

        # Anything at all from this peer proves they are still there, which
        # outranks a presence stanza that said otherwise.
        self._peer_is_alive(peer)

        # Rate limiting check.
        if not self._check_rate_limit(peer):
            print(f"[rate-limit] dropping message from {_sanitise(peer, 128)}")
            return

        # Inbound fragment reassembly.
        if body.startswith("?OTRv4F|"):
            full = self._reassemble_fragment(peer, body)
            if full is None:
                return
            body = full

        if body.startswith(OTR_PREFIX):
            # OTR processing (especially SMP) can run multi-minute 3072-bit DH
            # computations that BLOCK. Offload to a thread to keep the asyncio
            # event loop free so keepalive and network stay responsive.
            asyncio.ensure_future(self._handle_otr_in_async(peer, body))
        elif body.startswith(VoiceCallManager.CALL_PREFIX):
            # Call control is only legitimate inside the OTR channel. Arriving
            # as plaintext it is either an outdated client or an attempt to
            # steer a call by injecting signalling at the server, so it is
            # refused rather than acted upon.
            print("[voice] ignoring UNENCRYPTED call signal from %s — call "
                  "control is only accepted inside an OTR session"
                  % _sanitise(peer, 128))
        else:
            print(f"[plain] <{_sanitise(peer, 128)}> {_sanitise(body)}")

    async def _handle_otr_in_async(self, peer, body):
        stage_in = self._otr_stage(body)
        if stage_in:
            self._dbg(f"[otr-recv] <- {stage_in} from {peer}")
            # Minimal user-facing progress: the handshake stages are slow over
            # I2P and silence during them looks like a hang.
            if not self._probe and stage_in.startswith("DAKE"):
                print("[otr] handshake: received %s from %s"
                      % (stage_in, _sanitise(peer, 48)))

        if self._probe:
            try:
                keys = sorted(self.otr.sessions.keys())
                present = peer in self.otr.sessions
                self._dbg(
                    f"[otr-probe] inbound {stage_in}: lookup={peer!r} "
                    f"present={present} stored_keys={keys}"
                )
                if not present and keys:
                    for k in keys:
                        self._dbg(
                            f"[otr-probe]   key mismatch? stored={k!r} "
                            f"== lookup={peer!r} -> {k == peer} "
                            f"(len {len(k)} vs {len(peer)})"
                        )
            except Exception as e:
                self._dbg(f"[otr-probe] inbound probe error: {e}")

        # --- DAKE glare resolution ---
        # Over slow I2P both sides may send DAKE1 before either receives the
        # other's. Tie-break by bare JID: lower JID keeps initiator role;
        # higher JID yields and answers as responder. Both sides run identical
        # code so exactly one yields.
        if stage_in == "DAKE1":
            sess = self.otr.get_session(peer)
            st = getattr(getattr(sess, "session_state", None), "name", "")
            is_init = bool(getattr(sess, "is_initiator", False))
            if sess is not None and st == "DAKE_IN_PROGRESS" and is_init:
                if self._own_bare < peer:
                    print(
                        f"[otr] simultaneous start with {peer}: keeping "
                        f"initiator role; re-sending our DAKE1"
                    )
                    d1 = self._last_dake1.get(peer)
                    if d1:
                        self.send_otr_fragmented(peer, d1)
                    return
                print(
                    f"[otr] simultaneous start with {peer}: yielding initiator "
                    f"role, answering as responder"
                )
                try:
                    self.otr.end_session(peer)
                    self._last_dake1.pop(peer, None)
                    self._encrypted.discard(peer)
                except Exception as e:
                    print(f"[otr] glare teardown error: {e}")

        heavy = (stage_in or "").startswith("DATA")
        if heavy:
            import time as _t
            t0 = _t.time()
            self._dbg(
                f"[otr-crypto] processing DATA from {peer} "
                f"(SMP DH may take minutes; loop stays alive)..."
            )

        loop = asyncio.get_event_loop()
        try:
            out = await loop.run_in_executor(
                self._otr_executor, self.otr.handle_incoming_message, peer, body
            )
        except Exception as e:
            print(f"[otr error] from {peer}: {e}")
            return

        if heavy:
            import time as _t
            self._dbg(f"[otr-crypto] done processing DATA from {peer} ({_t.time() - t0:.1f}s).")

        self._check_dake_complete(peer)

        if out:
            out_b = out.encode("utf-8") if isinstance(out, str) else out
            if out_b.startswith(OTR_PREFIX_B):
                stage_out = self._otr_stage(out_b.decode("utf-8", errors="replace"))
                if stage_out:
                    self._dbg(f"[otr-send] -> {stage_out} to {peer}")
                self.send_otr_fragmented(peer, out_b.decode("utf-8", errors="replace"))
            else:
                text = out_b.decode("utf-8", errors="replace")

                # Call control travels INSIDE the OTR channel, so it surfaces
                # here as decrypted text and must be routed to the voice
                # manager before anything else touches it. Without this the
                # INVITE is rendered as a chat message and the callee never
                # learns a call is ringing — /answer then reports "no
                # incoming call" while the caller waits.
                if text.startswith(VoiceCallManager.CALL_PREFIX):
                    if self._voice_manager is not None:
                        asyncio.ensure_future(
                            self._voice_manager.handle_signal(peer, text))
                    else:
                        print("[voice] call signal received before the voice "
                              "subsystem was ready — ignoring")
                    return

                smp_ok = (peer, "SUCCEEDED") in self._smp_reported
                peer_s = _sanitise(peer, 128)
                text_s = _sanitise(text)
                if smp_ok:
                    print(
                        _colorize("[otr] ", "green")
                        + _colorize(f"<{peer_s}>", "yellow")
                        + " "
                        + _colorize(text_s, "dark_blue")
                    )
                else:
                    print(f"[otr] <{peer_s}> {text_s}")

        self._report_smp(peer)
        self._check_dake_complete(peer)

    @staticmethod
    def _otr_stage(frame):
        """Identify the OTRv4 message stage from a '?OTRv4 <base64>' frame.
        Best-effort; used for progress display only."""
        import base64 as _b64
        try:
            if not frame.startswith(OTR_PREFIX):
                return None
            payload = frame[len(OTR_PREFIX):].strip()
            if payload.endswith("."):
                payload = payload[:-1]
            try:
                decoded = _b64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            except Exception:
                std = payload.replace("-", "+").replace("_", "/")
                decoded = _b64.b64decode(std + "=" * (-len(std) % 4))
            if len(decoded) < 1:
                return None
            if (
                len(decoded) >= 3
                and decoded[0] == 0x00
                and decoded[1] == 0x04
                and decoded[2] == 0x03
            ):
                return "DATA (may carry SMP)"
            mtype = decoded[0]
            names = {0x35: "DAKE1", 0x36: "DAKE2", 0x37: "DAKE3", 0x03: "DATA"}
            return names.get(mtype, f"type 0x{mtype:02x}")
        except Exception:
            return None

    # -------------------------------------------------------------------------
    # DAKE completion -> trust prompt
    # -------------------------------------------------------------------------

    def _check_dake_complete(self, peer):
        """When a peer's session first becomes encrypted, show fingerprints
        and prompt for trust - identical to the IRC client."""
        try:
            if not self.otr.has_encrypted_session(peer):
                return
        except Exception:
            return
        if peer in self._encrypted:
            return
        self._encrypted.add(peer)

        local_fp = self._local_fp(peer)   # pass peer so session path is tried first
        remote_fp = self._remote_fp(peer)

        print("\n" + "-" * 60)
        print(
            f"[secure] OTR session with {peer} is ENCRYPTED "
            "(X448 + ML-KEM-1024 + ML-DSA-87)."
        )
        print(f"  Your fingerprint  : {_colorize(_fmt_fp(local_fp), 'green')}")
        print(f"  Their fingerprint : {_colorize(_fmt_fp(remote_fp), 'yellow')}")
        print("-" * 60)

        self._apply_tofu(peer, remote_fp)

    # -------------------------------------------------------------------------
    # TOFU (XMPP only)
    # -------------------------------------------------------------------------

    def _apply_tofu(self, peer, remote_fp):
        """Trust-on-first-use against the pinned fingerprint.

        Three outcomes, and they are genuinely different situations rather than
        three shades of the same prompt:

        first contact   nothing pinned -> show it, ask once, pin on `y`
        same key        pinned and matching -> say so, ask nothing
        changed key     pinned and DIFFERENT -> refuse, keep the old pin

        The third case never auto-repins and never offers `y` as a way through.
        A prompt that can be answered `y` is a prompt that will be answered `y`,
        and the whole point of pinning is that this particular `y` should cost
        the user some deliberate effort somewhere else.

        This is identity *continuity*, not authentication. SMP remains what
        authenticates a peer, and `_smp_verified` remains the only gate on
        voice -- a matching pin authorises nothing by itself.
        """
        if not remote_fp:
            print("[trust] no peer fingerprint available - encrypted only.")
            self._prompt_smp_secret(peer)
            return

        try:
            pinned_and_trusted = self.otr.trust_db.check_or_pin(peer, remote_fp)
        except Exception as exc:
            if type(exc).__name__ != "FingerprintMismatchError":
                print("[trust] trust store unusable (%s) - encrypted only."
                      % type(exc).__name__)
                self._prompt_smp_secret(peer)
                return
            self._fingerprint_changed[peer] = getattr(exc, "stored", "")
            print("")
            print("!" * 60)
            print("[trust] THE FINGERPRINT FOR THIS JID HAS CHANGED.")
            print("[trust]   pinned : %s" % _fmt_fp(getattr(exc, "stored", "")))
            print("[trust]   now    : %s" % _fmt_fp(remote_fp))
            print("[trust] The pinned fingerprint has NOT been replaced.")
            print("[trust] This is what a machine-in-the-middle looks like. It")
            print("[trust] also looks exactly like your peer reinstalling, so")
            print("[trust] it is a question, not a verdict - but confirm the")
            print("[trust] new fingerprint with them over a channel that is")
            print("[trust] not this one before you accept it.")
            print("[trust] To accept deliberately:  /trust-reset %s" % peer)
            print("[trust] Voice is refused for this peer until you do.")
            print("!" * 60)
            print("")
            return

        self._fingerprint_changed.pop(peer, None)
        if pinned_and_trusted:
            print("[trust] Fingerprint matches the pinned identity for this JID.")
            self._prompt_smp_secret(peer)
            return

        # First contact: pin it and say so. No question.
        #
        # The prompt is gone because it never carried the security. Asked to
        # approve a fingerprint you have never seen, there is nothing to check
        # it against -- the only available answer is yes, and a question whose
        # answer is always yes trains the reflex that makes the question that
        # DOES matter useless. Signal, WhatsApp and every other TOFU deployment
        # pin silently for the same reason.
        #
        # What protects you is the second half, and it is untouched: a pinned
        # fingerprint that CHANGES still stops the session, still refuses
        # voice, still cannot be waved through with a keystroke, and still
        # needs a deliberate /trust-reset. That is the branch above, and it is
        # where a machine-in-the-middle actually shows up.
        ok = False
        try:
            ok = self.otr.trust_fingerprint(peer, remote_fp)
        except Exception as exc:
            print("[trust] could not pin the fingerprint: %s" % type(exc).__name__)
        if ok:
            print("[trust] First contact — fingerprint PINNED for this JID.")
            print("[trust] A change will be reported and will block voice.")
        else:
            print("[trust] First contact — the fingerprint could NOT be pinned,")
            print("[trust] so a change cannot be detected. /identity for why.")
        self._prompt_smp_secret(peer)

    def show_identity(self):
        """Everything TOFU depends on, in one screen.

        Written because "it still asks me to trust the fingerprint" has three
        very different causes -- an older build at one end, a pin that did not
        stick, or a peer whose identity really is changing -- and telling them
        apart previously meant finding and reading a JSON file on both phones.
        """
        print("-" * 60)
        persistent = bool(getattr(self, "identity_persistent", False))
        print("[identity] local identity : %s"
              % ("PERSISTENT — the same every run" if persistent
                 else "EPHEMERAL — regenerates every run"))
        if not persistent:
            print("[identity]   Peers cannot pin a fingerprint that changes every")
            print("[identity]   launch. XMPP should be persistent; if this says")
            print("[identity]   ephemeral you are on a build older than v10.12.0.")
        print("[identity] your fingerprint: %s" % _fmt_fp(self._local_fp()))
        try:
            cfg = self.otr.config
            print("[identity] identity record: %s" % getattr(cfg, "identity_path", "?"))
            print("[identity] trust store    : %s%s"
                  % (self.otr.trust_db.db_path,
                     "" if self.otr.trust_db.persistent else "  (IN MEMORY ONLY)"))
        except Exception:
            pass

        try:
            entries = self.otr.trust_db.list_trusted()
        except Exception as exc:
            print("[identity] trust store unreadable: %s" % type(exc).__name__)
            entries = {}

        print("-" * 60)
        if not entries:
            print("[identity] No fingerprints pinned yet.")
            print("[identity]   First contact pins silently. If nothing is listed")
            print("[identity]   after a session, the pin did not stick.")
        else:
            print("[identity] Pinned fingerprints (%d):" % len(entries))
            for jid, fp in sorted(entries.items()):
                live = self._remote_fp(jid) if jid in self._encrypted else None
                if live and live != "unavailable":
                    state = "matches now" if live == fp else "!! DIFFERS FROM LIVE !!"
                else:
                    state = "not in session"
                print("[identity]   %-32s %s  [%s]" % (jid, _fmt_fp(fp), state))
        if self._fingerprint_changed:
            print("[identity] UNRESOLVED identity change for: %s"
                  % ", ".join(sorted(self._fingerprint_changed)))
            print("[identity]   Voice is refused for these until /trust-reset <jid>.")
        print("-" * 60)

    def _voice_blocked_by_tofu(self, peer) -> bool:
        """Refuse a call to a peer whose pinned fingerprint changed.

        This is an ADDITIONAL refusal, layered on top of the SMP gate rather
        than replacing any part of it. `_smp_verified` remains the only thing
        that authorises voice; a matching pin has never authorised anything and
        still does not. What this adds is that a *mismatched* pin refuses
        early, so an unresolved identity change cannot be walked past by
        completing SMP against whoever is on the other end.
        """
        if peer not in self._fingerprint_changed:
            return False
        print("[voice] refused: the pinned fingerprint for %s has changed and "
              "the change is unresolved." % peer)
        print("[voice] Confirm the new fingerprint with them out of band, then "
              "/trust-reset %s" % peer)
        return True

    def trust_reset(self, peer):
        """Deliberately drop a pin so the next contact re-pins (`/trust-reset`).

        Separate from the `y` prompt on purpose. Accepting a changed identity
        should cost a distinct, typed, peer-named action rather than the same
        keystroke the user already presses reflexively.
        """
        if not peer:
            print("usage: /trust-reset <jid>")
            return
        try:
            removed = self.otr.trust_db.remove_trust(peer)
        except Exception as exc:
            print("[trust] could not clear the pin: %s" % type(exc).__name__)
            return
        self._fingerprint_changed.pop(peer, None)
        if removed:
            print("[trust] Pin cleared for %s. The next session will treat it as "
                  "first contact." % peer)
            print("[trust] Run /otr again to re-establish and pin.")
        else:
            print("[trust] No pin was stored for %s." % peer)

    # -------------------------------------------------------------------------
    # SMP passphrase prompt
    # -------------------------------------------------------------------------

    def _prompt_smp_secret(self, peer):
        print("-" * 60)
        print(
            "[smp] SOCIALIST MILLIONAIRE PROTOCOL setup "
            "(hybrid PQC: ML-KEM-1024 + ML-DSA-87 + ZKP)."
        )
        print(
            f"[smp] Passphrase: {SMP_MIN_LEN}-{SMP_MAX_LEN} chars. "
            "Both sides must use the SAME secret."
        )
        print("[smp] After both have stored it, run  /smp start  (either side).")
        print("[smp] Press Enter or type  skip  to skip for now.")
        self._pending[peer] = "smp_secret"

    def _handle_smp_secret_answer(self, peer, secret):
        self._pending[peer] = None
        if not secret or secret.strip().lower() == "skip":
            print("[smp] skipped - you can set it later with  /smp-secret <secret>.")
            return
        secret = secret.strip()
        err = self._validate_smp_secret(secret)
        if err:
            print(f"[smp] {err}")
            return
        try:
            ok = self.otr.set_smp_secret(peer, secret)
        except Exception as e:
            print(f"[smp] error storing passphrase: {e}")
            return
        if ok:
            print("[smp] passphrase stored for auto-respond.")
            print("[smp] When BOTH sides have stored it, run  /smp start  to verify.")
        else:
            print("[smp] could not store passphrase.")

    @staticmethod
    def _validate_smp_secret(secret: str):
        """Return an error string if the SMP secret fails validation, else None."""
        if len(secret) < SMP_MIN_LEN:
            return f"secret too short (minimum {SMP_MIN_LEN} characters)"
        if len(secret) > SMP_MAX_LEN:
            return f"secret too long (maximum {SMP_MAX_LEN} characters)"
        return None

    # -------------------------------------------------------------------------
    # SMP result reporting
    # -------------------------------------------------------------------------

    def _report_smp(self, peer):
        # Terminal success state names across Rust engine versions
        _SMP_SUCCESS = {"SUCCEEDED", "VERIFIED", "COMPLETE", "COMPLETED",
                        "SMP_VERIFIED", "STATE_UPDATED"}
        _SMP_FAIL    = {"FAILED", "ERROR", "ABORTED", "SMP_FAILED"}
        try:
            session = self.otr.get_session(peer)
            if not session:
                return
            verified_now, name = _smp_query(self.otr, peer)
            if verified_now:
                # Return whenever the engine confirms, not only the first
                # time. _report_smp fires on several events per session, so
                # returning only on the first call let later ones fall through
                # to the heuristic branch below and print "this is NOT a
                # verification result" immediately after a genuine
                # IDENTITY VERIFIED — contradicting a true statement.
                if (peer, "SUCCEEDED") not in self._smp_reported:
                    self._smp_reported.add((peer, "SUCCEEDED"))
                    print(
                        f"\n[smp] *** IDENTITY VERIFIED with {peer} - "
                        "shared secret matched (SMP complete). ***\n"
                    )
                return
            if not name:
                return

            # Normalise to a single "SUCCEEDED" key regardless of engine naming
            key_ok   = (peer, "SUCCEEDED")
            key_fail = (peer, "FAILED")

            # Also check boolean attrs the Rust session may expose directly
            # Substring matching, because the engine's terminal name has
            # varied (SUCCEEDED / VERIFIED / STATE_UPDATED). Failure tokens
            # are checked first so an in-progress or failed phase can never
            # be misread as success.
            is_ok = (name in _SMP_SUCCESS) or (
                not any(t in name for t in
                        ("FAIL", "ABORT", "ERROR", "EXPECT", "PROGRESS"))
                and any(t in name for t in
                        ("SUCCEED", "VERIFI", "COMPLETE", "STATE_UPDATED")))
            if not is_ok:
                for attr in ("smp_verified", "is_verified", "identity_verified",
                             "smp_complete", "is_complete"):
                    if getattr(session, attr, False):
                        is_ok = True
                        break

            is_fail = (name in _SMP_FAIL) or any(
                t in name for t in ("FAIL", "ABORT", "ERROR"))

            # Deliberately NOT announced as verification.  is_ok is a
            # name/attribute heuristic; only _smp_query's boolean, handled
            # above, is the engine saying the shared secret matched.
            if is_ok and key_ok not in self._smp_display_hints:
                self._smp_display_hints.add(key_ok)
                print(
                    f"\n[smp] SMP reached a terminal state with {peer} "
                    f"(engine reports: {name}). This is NOT a verification "
                    "result — run /smpstate to see what the engine actually "
                    "says.\n"
                )
            elif is_fail and key_fail not in self._smp_reported:
                self._smp_reported.add(key_fail)
                print(
                    f"\n[smp] *** SMP FAILED with {peer} - secrets did NOT "
                    "match (or protocol error). Possible MITM. ***\n"
                )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Fingerprint helpers
    # -------------------------------------------------------------------------

    def _local_fp(self, peer=None):
        """Return local identity fingerprint.
        After DAKE, tries the session first (returns full hybrid FP length).
        Falls back to client_profile.get_fingerprint() which may return only
        the classical Ed448 portion."""
        if peer:
            try:
                sess = self.otr.get_session(peer)
                if sess:
                    for attr in (
                        "local_fingerprint", "our_fingerprint", "local_fp",
                        "identity_fingerprint", "our_identity_fp",
                    ):
                        val = getattr(sess, attr, None)
                        if val and str(val) not in ("unavailable", "None", ""):
                            return str(val)
                    for mname in (
                        "get_local_fingerprint", "get_our_fingerprint",
                        "get_identity_fingerprint",
                    ):
                        fn = getattr(sess, mname, None)
                        if callable(fn):
                            try:
                                val = fn()
                                if val and str(val) not in ("unavailable", "None", ""):
                                    return str(val)
                            except Exception:
                                pass
            except Exception:
                pass
        try:
            cp = getattr(self.otr, "client_profile", None)
            if cp and hasattr(cp, "get_fingerprint"):
                return cp.get_fingerprint() or "unavailable"
        except Exception:
            pass
        return "unavailable"

    def _remote_fp(self, peer):
        try:
            if hasattr(self.otr, "get_peer_fingerprint"):
                fp = self.otr.get_peer_fingerprint(peer)
                if fp:
                    return fp
            sess = self.otr.get_session(peer)
            if sess and hasattr(sess, "get_fingerprint"):
                fp = sess.get_fingerprint()
                if fp:
                    return fp
        except Exception:
            pass
        return "unavailable"

    # -------------------------------------------------------------------------
    # Outbound fragmentation
    # -------------------------------------------------------------------------

    def send_otr_fragmented(self, peer, payload):
        """Send an OTR message, fragmenting if over the I2P cliff (~8KB).

        Fragment wire format (one <body> per fragment):
            ?OTRv4F|<msg_id>|<n>|<total>|<chunk>

        Small messages are sent whole as a normal ?OTRv4 frame. The monotonic
        msg_id avoids collision when two large in-flight DATA frames have
        near-identical headers (version + instance tags + ratchet header).
        """
        MAX_FRAGMENT = 6000  # bytes per fragment (safely under I2P cliff)

        if len(payload) <= MAX_FRAGMENT:
            self.send_message(mto=peer, mbody=payload, mtype="chat")
            self._dbg(f"[otr-send] 1 frame ({len(payload)} bytes) -> {peer}")
            return

        chunks = [
            payload[i : i + MAX_FRAGMENT]
            for i in range(0, len(payload), MAX_FRAGMENT)
        ]
        total = len(chunks)
        self._frag_seq = (self._frag_seq + 1) & 0xFFFFFFFF
        msg_id = "%08x" % self._frag_seq

        self._dbg(
            f"[otr-send] fragmenting {len(payload)} bytes into {total} "
            f"fragments (id {msg_id}) -> {peer}"
        )
        for i, chunk in enumerate(chunks, 1):
            frag = f"?OTRv4F|{msg_id}|{i}|{total}|{chunk}"
            self.send_message(mto=peer, mbody=frag, mtype="chat")
            self._dbg(f"[otr-send]   sent fragment {i}/{total} (id {msg_id})")
        self._dbg(f"[otr-send] all {total} fragments sent (id {msg_id}) -> {peer}")

    def send_otr(self, peer, payload):
        """Legacy alias for send_otr_fragmented."""
        self.send_otr_fragmented(peer, payload)

    # -------------------------------------------------------------------------
    # Inbound fragment reassembly
    # -------------------------------------------------------------------------

    def _reassemble_fragment(self, peer, body):
        """Feed one inbound fragment to the buffer. Returns the fully
        reassembled '?OTRv4 ...' string when the last fragment arrives,
        otherwise None."""
        try:
            _, msg_id, n_s, total_s, chunk = body.split("|", 4)
            n = int(n_s)
            total = int(total_s)
        except Exception:
            self._dbg(f"[otr-recv] malformed fragment from {peer}; dropping")
            return None

        # Reject nonsensical indices before they can corrupt a buffer.
        MAX_FRAGMENTS = 4096
        if total < 1 or total > MAX_FRAGMENTS or n < 1 or n > total:
            self._dbg(f"[otr-recv] fragment index out of range from {peer}; dropping")
            return None

        if not hasattr(self, "_frag_buffers"):
            self._frag_buffers = {}

        MAX_INFLIGHT      = 64
        MAX_BUFFER_BYTES  = 8 * 1024 * 1024   # one reassembly set
        MAX_TOTAL_BYTES   = 32 * 1024 * 1024  # all in-flight sets combined

        # Evict oldest entries when inflight set count is exceeded.
        while len(self._frag_buffers) > MAX_INFLIGHT:
            del self._frag_buffers[next(iter(self._frag_buffers))]

        key = (peer, msg_id, total)
        buf = self._frag_buffers.setdefault(
            key, {"parts": {}, "total": total, "bytes": 0}
        )
        # Adjust byte tally for a resent fragment so a peer cannot inflate it.
        prev = buf["parts"].get(n)
        if prev is not None:
            buf["bytes"] -= len(prev)
        buf["parts"][n] = chunk
        buf["bytes"] += len(chunk)

        if buf["bytes"] > MAX_BUFFER_BYTES:
            self._frag_buffers.pop(key, None)
            self._dbg(
                f"[otr-recv] reassembly from {peer} exceeded "
                f"{MAX_BUFFER_BYTES} bytes; dropping"
            )
            return None
        agg = sum(b["bytes"] for b in self._frag_buffers.values())
        while agg > MAX_TOTAL_BYTES and self._frag_buffers:
            k = next(iter(self._frag_buffers))
            agg -= self._frag_buffers[k]["bytes"]
            del self._frag_buffers[k]

        have = len(buf["parts"])
        self._dbg(
            f"[otr-recv]   fragment {n}/{total} from {peer} "
            f"(id {msg_id}; have {have}/{total})"
        )

        if have < total:
            if not self._probe and total > 1:
                print("[otr] receiving %d/%d fragments from %s"
                      % (have, total, _sanitise(peer, 48)))
            return None
        # Verify every index present before stitching.
        if any(i not in buf["parts"] for i in range(1, total + 1)):
            return None
        ordered = "".join(buf["parts"][i] for i in range(1, total + 1))
        self._frag_buffers.pop(key, None)
        self._dbg(
            f"[otr-recv] reassembled {total} fragments "
            f"({len(ordered)} bytes, id {msg_id}) from {peer}"
        )
        return ordered

    # -------------------------------------------------------------------------
    # OTR session control
    # -------------------------------------------------------------------------

    def send_plain(self, peer, text):
        self.send_message(mto=peer, mbody=text, mtype="chat")

    def start_otr(self, peer):
        try:
            msg, should_send = self.otr.handle_outgoing_message(peer, "")
        except Exception as e:
            print(f"[otr error] start with {peer}: {e}")
            return

        if not (should_send and msg):
            # Engine refused — DAKE already in progress or session in bad state.
            # Force-reset and retry so /otr can always unstick a hung handshake.
            print(f"[otr] resetting stuck session with {peer}, retrying DAKE...")
            try:
                self.otr.end_session(peer)
                self._encrypted.discard(peer)
                self._last_dake1.pop(peer, None)
                self._pending.pop(peer, None)
                self._smp_reported = {k for k in self._smp_reported if k[0] != peer}
            except Exception as e:
                print(f"[otr] reset error: {e}")
            try:
                msg, should_send = self.otr.handle_outgoing_message(peer, "")
            except Exception as e:
                print(f"[otr error] retry with {peer}: {e}")
                return

        if should_send and msg:
            msg_s = msg if isinstance(msg, str) else msg.decode()
            self._last_dake1[peer] = msg_s
            self._dbg(f"[otr-send] -> DAKE1 to {peer} (starting handshake)")
            self.send_otr_fragmented(peer, msg_s)
            if self._probe:
                try:
                    keys = sorted(self.otr.sessions.keys())
                    self._dbg(
                        f"[otr-probe] after /otr: stored={peer!r} "
                        f"present={peer in self.otr.sessions} "
                        f"all_keys={keys}"
                    )
                except Exception as e:
                    self._dbg(f"[otr-probe] after-/otr probe error: {e}")
            print(f"[otr] DAKE started with {peer}. Waiting for DAKE2...")
        else:
            print(f"[otr] could not start DAKE with {peer} — try /otr again")

    def send_user_text(self, peer, text):
        try:
            msg, should_send = self.otr.handle_outgoing_message(peer, text)
        except Exception as e:
            print(f"[otr error] send to {peer}: {e}")
            return
        if should_send and msg:
            self.send_otr_fragmented(
                peer, msg if isinstance(msg, str) else msg.decode()
            )
        elif not should_send:
            print(f"[queued] will send once OTR with {peer} is ready")

    def store_smp_secret(self, peer, secret):
        """/smp-secret: store passphrase for auto-respond without starting SMP."""
        if not self.otr.has_encrypted_session(peer):
            print(f"[smp] no encrypted session with {peer}. Run /otr first.")
            return
        secret = secret.strip()
        err = self._validate_smp_secret(secret)
        if err:
            print(f"[smp] {err}")
            return
        try:
            ok = self.otr.set_smp_secret(peer, secret)
        except Exception as e:
            print(f"[smp] error: {e}")
            return
        print(
            "[smp] passphrase stored for auto-respond."
            if ok
            else "[smp] could not store passphrase."
        )

    def smp_start(self, peer, secret=None):
        """/smp start or /smp <secret>: initiate SMP verification.
        Runs the 3072-bit DH in a background thread to keep the loop free."""
        if not self.otr.has_encrypted_session(peer):
            print(f"[smp] no encrypted session with {peer}. Run /otr first.")
            return
        if secret:
            secret = secret.strip()
            err = self._validate_smp_secret(secret)
            if err:
                print(f"[smp] {err}")
                return
            try:
                self.otr.set_smp_secret(peer, secret)
            except Exception:
                pass
        use_secret = secret
        if use_secret is None:
            try:
                use_secret = self.otr.smp_storage.get_secret(peer)
            except Exception:
                use_secret = None
        if not use_secret:
            print(
                "[smp] no passphrase stored. Use  /smp-secret <secret>  first, "
                "or  /smp <secret>  to set and start in one step."
            )
            return
        try:
            def _do_start():
                return self.otr.start_smp(peer, use_secret)

            async def _run():
                loop = asyncio.get_event_loop()
                try:
                    smp1 = await loop.run_in_executor(self._otr_executor, _do_start)
                except Exception as e:
                    print(f"[smp] start error: {e}")
                    return
                if smp1:
                    self.send_otr_fragmented(
                        peer, smp1 if isinstance(smp1, str) else smp1.decode()
                    )
                    print(
                        f"[smp] started with {peer}; waiting for response "
                        "(SMP runs several 3072-bit DH rounds; keep both clients running)..."
                    )
                else:
                    print(f"[smp] could not start with {peer}")

            self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_run()))
        except Exception as e:
            print(f"[smp] start error: {e}")

    # -------------------------------------------------------------------------
    # Roster management
    # -------------------------------------------------------------------------

    def roster_list(self):
        """Display all roster contacts with subscription state."""
        try:
            roster = self.client_roster
            entries = [jid for jid in roster if jid != self.boundjid.bare]
            if not entries:
                print("[roster] no contacts")
                return
            print(f"[roster] {len(entries)} contact(s):")
            for jid in sorted(entries):
                item = roster[jid]
                sub = item["subscription"]
                name = item["name"] or jid
                groups = ", ".join(item["groups"]) or "none"
                print(f"[roster]   {name} ({jid})  sub={sub}  groups={groups}")
        except Exception as e:
            print(f"[roster] error: {e}")

    def roster_add(self, jid):
        """Add a JID to the roster and send a subscription request."""
        jid = jid.strip()
        if not jid or "@" not in jid:
            print(f"[roster] invalid JID: {_sanitise(jid, 128)}")
            return
        try:
            self.update_roster(jid)
            self.send_presence_subscription(pto=jid)
            print(f"[roster] added {jid} and sent subscription request")
        except Exception as e:
            print(f"[roster] add error: {e}")

    def roster_remove(self, jid):
        """Remove a JID from the roster."""
        jid = jid.strip()
        if not jid or "@" not in jid:
            print(f"[roster] invalid JID: {_sanitise(jid, 128)}")
            return
        async def _do():
            try:
                await self.del_roster_item(jid)
                print(f"[roster] removed {jid}")
            except Exception as e:
                print(f"[roster] remove error: {e}")
        asyncio.ensure_future(_do())

    def accept_subscription(self, jid):
        """Approve a pending subscription request."""
        jid = jid.strip()
        if jid not in self._pending_subscriptions:
            print(f"[sub] no pending request from {_sanitise(jid, 128)}")
            return
        self.send_presence(pto=jid, ptype="subscribed")
        self.send_presence(pto=jid, ptype="subscribe")
        self.send_presence(pto=jid)
        self._pending_subscriptions.pop(jid, None)
        print(f"[sub] accepted subscription from {jid}")

    def deny_subscription(self, jid):
        """Deny a pending subscription request."""
        jid = jid.strip()
        if jid not in self._pending_subscriptions:
            print(f"[sub] no pending request from {_sanitise(jid, 128)}")
            return
        self.send_presence(pto=jid, ptype="unsubscribed")
        self._pending_subscriptions.pop(jid, None)
        print(f"[sub] denied subscription from {jid}")

    # -------------------------------------------------------------------------
    # Block list
    # -------------------------------------------------------------------------

    def block_peer(self, jid):
        jid = jid.strip()
        self._blocked.add(jid)
        print(f"[block] {_sanitise(jid, 128)} blocked (session-local)")

    def unblock_peer(self, jid):
        jid = jid.strip()
        if jid in self._blocked:
            self._blocked.discard(jid)
            print(f"[block] {_sanitise(jid, 128)} unblocked")
        else:
            print(f"[block] {_sanitise(jid, 128)} was not blocked")

    # -------------------------------------------------------------------------
    # XMPP Ping (XEP-0199)
    # -------------------------------------------------------------------------

    def ping_peer(self, jid):
        """Send an XMPP ping to a peer and print the round-trip time."""
        async def _do():
            try:
                rtt = await self["xep_0199"].async_ping(jid, timeout=30)
                print(f"[ping] {_sanitise(jid, 128)}: {rtt * 1000:.0f}ms")
            except IqError as e:
                print(f"[ping] {_sanitise(jid, 128)}: error ({e.condition})")
            except IqTimeout:
                print(f"[ping] {_sanitise(jid, 128)}: timeout (30s)")
            except Exception as e:
                print(f"[ping] {_sanitise(jid, 128)}: failed ({e})")
        asyncio.ensure_future(_do())

    # -------------------------------------------------------------------------
    # Status and help
    # -------------------------------------------------------------------------

    def show_status(self, peer):
        try:
            enc = self.otr.has_encrypted_session(peer)
        except Exception:
            enc = False
        trusted = False
        try:
            trusted = self.otr.is_peer_trusted(peer)
        except Exception:
            pass
        has_secret = False
        try:
            has_secret = bool(self.otr.smp_storage.get_secret(peer))
        except Exception:
            pass
        blocked = peer in self._blocked
        pending_sub = peer in self._pending_subscriptions
        print(
            f"[status] {peer}:\n"
            f"  encrypted      : {enc}\n"
            f"  trusted        : {trusted}\n"
            f"  smp_secret     : {has_secret}\n"
            f"  blocked        : {blocked}\n"
            f"  pending_sub    : {pending_sub}"
        )

    def reshow_trust(self, peer):
        self._encrypted.discard(peer)
        self._check_dake_complete(peer)

    @staticmethod
    def show_help():
        print(
            "[help] OTRv4+ XMPP commands:\n"
            "  /otr [jid]           start OTR session (DAKE)\n"
            "  /smp start           begin SMP verification\n"
            "  /smp <secret>        set secret and start SMP\n"
            "  /smp-secret <s>      store secret for auto-respond\n"
            "  /trust-reset <jid>   clear a pinned fingerprint (deliberate)\n"
            "  /identity            your identity and every pinned fingerprint\n"
            "  /trust               re-show fingerprint trust prompt\n"
            "  /msg <jid> <text>    send plaintext message\n"
            "  /status              show session state\n"
            "  /roster              list roster contacts\n"
            "  /add <jid>           add contact + send subscription\n"
            "  /remove <jid>        remove contact from roster\n"
            "  /pending             show pending subscription requests\n"
            "  /accept <jid>        accept a subscription request\n"
            "  /deny <jid>          deny a subscription request\n"
            "  /block <jid>         block inbound from JID (session)\n"
            "  /unblock <jid>       unblock JID\n"
            "  /blocked             list blocked JIDs\n"
            "  /ping <jid>          XMPP ping (XEP-0199)\n"
            "  /call [jid]          start encrypted voice call (requires OTR)\n"
            "  /answer              accept incoming call\n"
            "  /reject              decline incoming call\n"
            "  /hangup              end active call\n"
            "  /mute                toggle microphone mute\n"
            "  /calls               show voice call state and frame counters\n"
            "  /audiotest           verify the microphone captures audio\n"
            "  /audioprobe          test each audio backend on this device\n"
            "  /smpstate            show raw SMP verification state\n"
            "  /voicedebug          toggle voice setup + telemetry logging\n"
            "  Ctrl+B               scroll up one page\n"
            "  Ctrl+F               scroll down one page\n"
            "  /up  /b              scroll up one page (text fallback)\n"
            "  /dn  /f              scroll down one page\n"
            "  /top                 jump to top of panel history\n"
            "  /bottom              jump to latest messages\n"
            "  /log  /history       show full encrypted session history for\n"
            "                       the active peer (works in plain and TUI mode)\n"
            "  /next  /prev         switch tabs (TUI)\n"
            "  /win <n|name>        jump to tab by number or name\n"
            "  /tabs                list open tabs\n"
            "  /clear               clear active tab\n"
            "  /close               close active tab\n"
            "  /help                this list\n"
            "  /tui                 toggle between plain scrollback and tabbed panels\n"
            "  /quit                disconnect and exit"
        )

    # -------------------------------------------------------------------------
    # Pending-input dispatch
    # -------------------------------------------------------------------------

    def feed_pending(self, peer, line):
        """If `peer` has a pending prompt (trust / smp_secret), consume line."""
        state = self._pending.get(peer)
        if state == "smp_secret":
            self._handle_smp_secret_answer(peer, line)
            return True
        return False

    def has_pending(self, peer):
        return self._pending.get(peer) == "smp_secret"

    # -------------------------------------------------------------------------
    # Shared command dispatch
    # -------------------------------------------------------------------------

    def dispatch_line(self, peer, line):
        """Handle one input line for `peer` (the active conversation).

        Returns True to keep running, False to quit. Single source of truth
        for command behaviour; both the plain stdin loop and the TUI call this
        so both front-ends behave identically."""
        # Pending trust/SMP prompts consume the line first.
        if peer and self.has_pending(peer):
            if line.strip() == "/quit":
                return False
            self.feed_pending(peer, line)
            return True

        if not line:
            return True

        lstrip = line.strip()

        # --- TUI toggle ---
        if lstrip == "/tui":
            if getattr(self, "_tui_enabled", False):
                print("[tui] switching to plain scrollback mode")
                self._tui_quit_to_plain()
            else:
                try:
                    loop = asyncio.get_event_loop()
                    ok = self._start_tui(loop, debug=self._probe)
                    if ok:
                        print("[tui] switched to tabbed panel mode (/tui again to go back)")
                    else:
                        print("[tui] could not start TUI (not a tty?)")
                except Exception as e:
                    print(f"[tui] error: {e}")
            return True

        # --- Quit ---
        if lstrip == "/quit":
            return False

        # --- OTR ---
        elif lstrip == "/otr":
            if peer:
                self.start_otr(peer)
            else:
                print("no --peer set; use /otr <jid>")
        elif lstrip.startswith("/otr "):
            self.start_otr(lstrip[5:].strip())

        # --- SMP ---
        elif lstrip == "/smp start":
            if peer:
                self.smp_start(peer)
            else:
                print("no --peer set")
        elif lstrip.startswith("/trust-reset"):
            rest = lstrip[len("/trust-reset"):].strip()
            self.trust_reset(rest or peer)

        elif lstrip.startswith("/smp-secret "):
            rest = lstrip[len("/smp-secret "):].strip()
            first = rest.split(" ", 1)[0]
            if "@" in first and " " in rest:
                t, s = rest.split(" ", 1)
                self.store_smp_secret(t, s)
            elif peer:
                self.store_smp_secret(peer, rest)
            else:
                print("usage: /smp-secret <jid> <secret>")
        elif lstrip.startswith("/smp "):
            rest = lstrip[5:].strip()
            if rest == "start":
                if peer:
                    self.smp_start(peer)
            else:
                first = rest.split(" ", 1)[0]
                if "@" in first and " " in rest:
                    t, s = rest.split(" ", 1)
                    self.smp_start(t, s)
                elif peer:
                    self.smp_start(peer, rest)
                else:
                    print("usage: /smp <jid> <secret>")

        # --- Trust ---
        elif lstrip == "/trust":
            if peer:
                self.reshow_trust(peer)

        # --- Plain message ---
        elif lstrip.startswith("/msg "):
            rest = lstrip[5:].strip()
            if " " in rest:
                t, txt = rest.split(" ", 1)
                self.send_plain(t, txt)
                print(f"[sent plain] -> {t}")
            else:
                print("usage: /msg <jid> <text>")

        # --- Status ---
        elif lstrip == "/status":
            if peer:
                self.show_status(peer)
            # Ticks are whitespace writes and prove only that the local
            # socket accepts bytes. The round trip is what proves the server
            # is still there, so both are reported and never conflated.
            if self._keepalive_last_ok is not None:
                print("[keepalive] %d ticks, %d round trips, %d timeouts "
                      "(lifetime), %d consecutive, last reply %.0fs ago%s"
                      % (self._keepalive_ticks, self._keepalive_pings,
                         self._keepalive_timeouts,
                         self._keepalive_ping_fails,
                         time.monotonic() - self._keepalive_last_ok,
                         "  DEGRADED" if self._keepalive_degraded else ""))
                print("[reconnect] %d started, %d completed"
                      % (self._reconnects_started,
                         self._reconnects_completed))
            elif self._keepalive_pings:
                print("[keepalive] %d ticks, %d round trips, NO reply yet"
                      % (self._keepalive_ticks, self._keepalive_pings))
            elif self._keepalive_ticks:
                print("[keepalive] %d ticks, first round trip not due yet"
                      % self._keepalive_ticks)

        # --- Roster ---
        elif lstrip in ("/roster", "/roster list"):
            self.roster_list()
        elif lstrip.startswith("/add "):
            self.roster_add(lstrip[5:].strip())
        elif lstrip.startswith("/remove "):
            self.roster_remove(lstrip[8:].strip())

        # --- Subscriptions ---
        elif lstrip == "/pending":
            if self._pending_subscriptions:
                for jid in self._pending_subscriptions:
                    print(f"[sub] pending: {_sanitise(jid, 128)}")
            else:
                print("[sub] no pending subscription requests")
        elif lstrip.startswith("/accept "):
            self.accept_subscription(lstrip[8:].strip())
        elif lstrip.startswith("/deny "):
            self.deny_subscription(lstrip[6:].strip())

        # --- Block list ---
        elif lstrip.startswith("/block "):
            jid = lstrip[7:].strip()
            if jid:
                self.block_peer(jid)
            else:
                print("usage: /block <jid>")
        elif lstrip.startswith("/unblock "):
            self.unblock_peer(lstrip[9:].strip())
        elif lstrip == "/blocked":
            if self._blocked:
                for jid in sorted(self._blocked):
                    print(f"[block] {_sanitise(jid, 128)}")
            else:
                print("[block] no blocked JIDs")

        # --- Ping ---
        elif lstrip.startswith("/ping "):
            jid = lstrip[6:].strip()
            if jid:
                self.ping_peer(jid)
            else:
                print("usage: /ping <jid>")

        # --- Voice calls ---
        elif lstrip == "/call":
            if peer and self._voice_manager:
                if self._voice_blocked_by_tofu(peer):
                    return True
                asyncio.ensure_future(self._voice_manager.start_call(peer))
            elif not self._voice_manager:
                print("[voice] not initialized — connect first")
            else:
                print("usage: /call (set --peer first) or /call <jid>")
        elif lstrip.startswith("/call "):
            jid = lstrip[6:].strip()
            if jid and self._voice_manager:
                if self._voice_blocked_by_tofu(jid):
                    return True
                asyncio.ensure_future(self._voice_manager.start_call(jid))
            else:
                print("usage: /call <jid>")
        elif lstrip == "/answer":
            if peer and self._voice_manager:
                if self._voice_blocked_by_tofu(peer):
                    return True
                asyncio.ensure_future(self._voice_manager.answer_call(peer))
            else:
                print("[voice] no incoming call")
        elif lstrip == "/reject":
            if peer and self._voice_manager:
                asyncio.ensure_future(self._voice_manager.reject_call(peer))
        elif lstrip == "/hangup":
            if self._voice_manager:
                target = peer if self._voice_manager.has_active_call(peer) \
                    else self._voice_manager.any_active_peer()
                if target:
                    asyncio.ensure_future(self._voice_manager.end_call(target))
                else:
                    print("[voice] no active call")
            else:
                print("[voice] not initialised")
        elif lstrip == "/mute":
            if self._voice_manager:
                target = peer if self._voice_manager.has_active_call(peer) \
                    else self._voice_manager.any_active_peer()
                if target:
                    self._voice_manager.toggle_mute(target)
                else:
                    print("[voice] no active call")
        elif lstrip in ("/calls", "/callstatus"):
            if self._voice_manager:
                print(self._voice_manager.status_line())
            else:
                print("[voice] not initialised")
        elif lstrip in ("/voicedebug", "/vdebug"):
            if self._voice_manager:
                self._voice_manager.debug = not self._voice_manager.debug
                print("[voice] diagnostics %s"
                      % ("ON — call setup and 5s telemetry will be logged"
                         if self._voice_manager.debug else "off"))
                if self._voice_manager.debug:
                    for p_ in list(self._voice_manager._calls):
                        self._voice_manager._start_stats(p_)
            else:
                print("[voice] not initialised")
        elif lstrip in ("/identity", "/whoami"):
            self.show_identity()

        elif lstrip in ("/smpstate", "/smpstatus"):
            if not peer:
                print("[smp] no active peer")
            else:
                vm = self._voice_manager
                name = vm._smp_state_name(peer) if vm else "?"
                reported = ((peer, "SUCCEEDED") in self._smp_reported
                            or (peer, "SUCCEEDED") in self._smp_display_hints)
                ok = vm._smp_verified(peer) if vm else False
                print("[smp] peer            : %s" % _sanitise(peer, 64))
                print("[smp] engine state    : %s" % _sanitise(name or "-", 60))
                print("[smp] client recorded : %s" % reported)
                print("[smp] call permitted  : %s" % ok)
        elif lstrip in ("/audioprobe", "/audiobackend"):
            # Determines empirically which backend works on THIS device.
            def _probe():
                try:
                    import otrv4plus_audio as _aud
                    builtins.print("[audio] %s" % _aud.backend_summary())
                    _aud.probe(duration=2.0, verbose=True)
                except Exception as exc:
                    builtins.print("[audio] probe failed: %s"
                                   % _sanitise(str(exc), 200))
            threading.Thread(target=_probe, name="audio-probe",
                             daemon=True).start()
        elif lstrip == "/audiotest":
            asyncio.ensure_future(_audio_selftest_async())

        # --- Scroll (Termux software keyboard fallback) ---
        elif lstrip in ("/up", "/pgup", "/b"):
            scr = getattr(self, "_screen", None)
            if scr:
                scr.scroll_up(max(1, scr.rows - 3))
            else:
                print("[scroll] TUI not active")
        elif lstrip in ("/dn", "/pgdn", "/f"):
            scr = getattr(self, "_screen", None)
            if scr:
                scr.scroll_down(max(1, scr.rows - 3))
            else:
                print("[scroll] TUI not active")
        elif lstrip == "/top":
            scr = getattr(self, "_screen", None)
            if scr:
                scr.scroll_up(999999)
            else:
                print("[scroll] TUI not active")
        elif lstrip == "/bottom":
            scr = getattr(self, "_screen", None)
            if scr:
                scr.scroll_down(999999)

        # --- Log / History: read from encrypted channel_log (works in any mode) ---
        elif lstrip in ("/log", "/history"):
            target_peer = None
            if self.panel_manager is not None:
                active = self.panel_manager.active_panel
                target_peer = self._tui_jid_by_label.get(active) if active else None
            if not target_peer:
                target_peer = peer or self.peer
            if not target_peer:
                print("[log] no active conversation — set --peer or open a tab first")
            elif self.channel_log is None:
                print("[log] channel log not available (otrv4plus_log.py not found)")
            else:
                history = self.channel_log.read_recent(target_peer, n=50000)
                builtins.print(
                    f"\n[log] ═══ {len(history)} entries for "
                    f"{_sanitise(target_peer, 128)} ═══"
                )
                for entry in history:
                    if "|" in entry:
                        ts, body = entry.split("|", 1)
                        builtins.print(f"  {ts}  {body}")
                    else:
                        builtins.print(f"  {entry}")
                builtins.print(f"[log] ═══ end ({len(history)} entries) ═══\n")

        # --- Help ---
        elif lstrip in ("/help", "/?"):
            self.show_help()

        # --- Outbound chat ---
        else:
            if peer:
                self.send_user_text(peer, line)
            else:
                print("no --peer set; use /msg <jid> <text> or set --peer")

        return True

    # =========================================================================
    # Inline terminal UI (drives the engine's TUI)
    # =========================================================================

    _SYS_PREFIXES = (
        "[i2p]",
        "[tls]",
        "[connected]",
        "[version]",
        "[ready]",
        "[sub]",
        "[status]",
        "[keepalive]",
        "[disconnected]",
        "[connection",
        "[stream",
        "[reconnect]",
        "[auth",
        "[delivery",
        "[sent plain]",
        "[queued]",
        "[roster]",
        "[block]",
        "[help]",
        "[rate-limit]",
        "[receipt]",
        "[ping]",
        "[presence]",
    )

    def _tui_label_for(self, jid):
        """Return a short, unique tab label for a peer JID."""
        jid = jid.split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
        existing = self._tui_label_by_jid.get(jid)
        if existing is not None:
            return existing
        local = jid.split("@", 1)[0] or jid
        label = local
        if label in self._tui_jid_by_label and self._tui_jid_by_label[label] != jid:
            dom = jid.split("@", 1)[1] if "@" in jid else ""
            label = "%s@%s" % (local, dom[:6])
            if label in self._tui_jid_by_label and self._tui_jid_by_label[label] != jid:
                label = jid
        self._tui_jid_by_label[label] = jid
        self._tui_label_by_jid[jid] = label
        return label

    def _extract_peer(self, line: str) -> "str | None":
        """Return the first non-self bare JID found in a line, or None.
        Shared by the module-level print() channel-log hook and by
        _tui_route_output so both use identical peer-identification logic."""
        own_bare = self.boundjid.bare if self.boundjid else None
        for mm in _JID_PATTERN.finditer(line):
            cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
            if cand == self._own_bare or (own_bare and cand == own_bare):
                continue
            return cand
        return None

    def _tui_route_output(self, line):
        """Route one harness output line into the panel system.

        Routing priority:
          1. Protocol/trace lines ([otr-trace], [otr-recv], [otr-send],
             [otr-probe], [otr-crypto], [keepalive]) → debug panel.
             They contain the peer JID and would flood the peer panel.
          2. System lines ([connected], [i2p], ...) → system panel.
          3. Lines with a peer JID → that peer's panel.
          4. Continuation lines (no JID, no sys prefix) → last peer panel.
        """
        if line == "":
            return

        # --- Protocol / trace lines → debug panel (keep peer panel clean) ---
        _PROTO_PREFIXES = (
            "[otr-trace]", "[otr-recv]", "[otr-send]",
            "[otr-probe]", "[otr-crypto]", "[keepalive]",
        )
        stripped = line.lstrip()
        if any(stripped.startswith(p) for p in _PROTO_PREFIXES):
            # Still scan for SMP/badge signals before routing to debug
            jid = None
            for mm in _JID_PATTERN.finditer(line):
                cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
                if cand != self._own_bare:
                    jid = cand
                    break
            # Belt-and-braces SMP detection: update peer panel badge even
            # when the trace line itself goes to debug
            _smp_ok_signals = ("SMP VERIFIED", "SMP complete",
                               "IDENTITY VERIFIED", "VERIFIED → STATE_UPDATED",
                               "SMP_VERIFIED")
            if any(s in line for s in _smp_ok_signals):
                check_peer = jid or self._tui_jid_by_label.get(
                    self._tui_last_panel)
                if check_peer and (check_peer, "SUCCEEDED") not in self._smp_display_hints:
                    self._smp_display_hints.add((check_peer, "SUCCEEDED"))
                    try:
                        SL = _UIConstants.SecurityLevel
                        lbl = self._tui_label_for(check_peer)
                        self.panel_manager.update_panel_security(
                            lbl, SL.SMP_VERIFIED)
                    except Exception:
                        pass
            try:
                self.panel_manager.add_message("debug", line)
            except Exception:
                pass
            if self._tui_enabled and self._screen is not None:
                try:
                    if self.panel_manager.active_panel == "debug":
                        self._screen.redraw_body()
                    self._screen.redraw_tabbar()
                except Exception:
                    pass
            return

        # --- Normal routing for everything else ---
        own_bare = self.boundjid.bare if self.boundjid else None
        jid = None
        for mm in _JID_PATTERN.finditer(line):
            cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
            if cand == self._own_bare or (own_bare and cand == own_bare):
                continue
            jid = cand
            break
        if jid:
            target = self._tui_label_for(jid)
            self._tui_last_panel = target
        else:
            if any(stripped.startswith(p) for p in self._SYS_PREFIXES):
                target = "system"
            else:
                target = self._tui_last_panel or "system"

        self._tui_update_badge(target, line)

        # Belt-and-braces SMP signal detection on non-trace lines
        _smp_ok_signals = ("SMP VERIFIED", "SMP complete",
                           "IDENTITY VERIFIED", "SMP_VERIFIED")
        if any(s in line for s in _smp_ok_signals):
            check_peer = jid or self._tui_jid_by_label.get(target)
            if check_peer and (check_peer, "SUCCEEDED") not in self._smp_display_hints:
                self._smp_display_hints.add((check_peer, "SUCCEEDED"))
                try:
                    SL = _UIConstants.SecurityLevel
                    lbl = self._tui_label_for(check_peer)
                    self.panel_manager.update_panel_security(lbl, SL.SMP_VERIFIED)
                except Exception:
                    pass

        try:
            self.panel_manager.add_message(target, line)
        except Exception:
            return
        if (
            not self._tui_autofocused
            and target != "system"
            and self.panel_manager.active_panel == "system"
        ):
            self._tui_autofocused = True
            try:
                self.panel_manager.switch_to_panel(target)
                self._refresh_prompt()
                if self._screen is not None:
                    self._screen.redraw_full()
                return
            except Exception:
                pass
        if self._tui_enabled and self._screen is not None:
            try:
                if target == self.panel_manager.active_panel:
                    self._screen.redraw_body()
                self._screen.redraw_tabbar()
            except Exception:
                pass

    def _tui_update_badge(self, target, line):
        if target == "system" or _UIConstants is None:
            return
        SL = _UIConstants.SecurityLevel
        try:
            if "SMP VERIFIED" in line or "SMP complete" in line:
                # 🔵 Blue: only after SMP identity verification completes
                self.panel_manager.update_panel_security(target, SL.SMP_VERIFIED)
            elif "Fingerprint TRUSTED" in line or "identity pinned" in line:
                # 🟢 Green: fingerprint accepted / TOFU trust pinned, not yet SMP
                fp_level = getattr(SL, "FINGERPRINT", SL.ENCRYPTED)
                self.panel_manager.update_panel_security(target, fp_level)
            elif "is ENCRYPTED" in line:
                # Intermediate: DAKE complete but fingerprint not yet confirmed
                self.panel_manager.update_panel_security(target, SL.ENCRYPTED)
        except Exception:
            pass

    def _refresh_prompt(self):
        pm = getattr(self, "panel_manager", None)
        active = pm.get_active_panel() if pm else None
        if active is None:
            _set_prompt(_colorize("> ", "green"))
            return
        icon = ""
        if _UIConstants is not None:
            icon = _UIConstants.SECURITY_ICONS.get(active.security_level, "")
        name = "system" if active.name == "system" else active.name
        _set_prompt(
            _colorize(self.nick, "cyan")
            + _colorize(" | ", "dim")
            + _colorize(f"[{icon}{name}]", "green")
            + " "
        )

    def _tui_peer_hint(self, label):
        hint = (
            "Type /otr to start an encrypted session with %s.  You'll then "
            "confirm the fingerprint and set a shared SMP secret to verify "
            "identity.  /help for all commands.  /quit to exit." % label
        )
        try:
            self.panel_manager.add_message(label, _colorize(hint, "yellow"))
        except Exception:
            pass

    def _make_debug_log_handler(self):
        import logging as _logging
        client = self

        class _DebugTabHandler(_logging.Handler):
            def __init__(self):
                super().__init__(_logging.DEBUG)
                self.setFormatter(
                    _logging.Formatter("%(levelname)s %(name)s: %(message)s")
                )

            def emit(self, record):
                try:
                    msg = self.format(record)
                except Exception:
                    return
                try:
                    client._tui_log_to_debug(msg)
                except Exception:
                    pass

        return _DebugTabHandler()

    def _tui_log_to_debug(self, msg):
        if not (self._tui_enabled and self.panel_manager is not None):
            return
        try:
            self.panel_manager.add_message("debug", _colorize(msg, "magenta"))
        except Exception:
            return
        if self._screen is not None:
            try:
                if self.panel_manager.active_panel == "debug":
                    self._screen.redraw_body()
                self._screen.redraw_tabbar()
            except Exception:
                pass

    def _start_tui(self, loop, debug=False):
        """Attach and start the engine's TUI. Returns True if it took over."""
        global _ACTIVE_TUI_CLIENT
        if not (_TUI_AVAILABLE and sys.stdin.isatty() and sys.stdout.isatty()):
            return False
        self._loop = loop
        self.panel_manager = _PanelManager(self)
        self._screen = _Screen(self)
        self._tui_enabled = True
        self._prompt_refresh_cb = self._refresh_prompt
        _ACTIVE_TUI_CLIENT = self

        import logging as _logging
        root = _logging.getLogger()
        self._saved_log_handlers = root.handlers[:]
        for h in self._saved_log_handlers:
            root.removeHandler(h)
        if debug:
            self.panel_manager.get_or_create_panel("debug", "debug")
            root.addHandler(self._make_debug_log_handler())
            root.setLevel(_logging.DEBUG)
        else:
            root.addHandler(_logging.NullHandler())

        self._raw = _setup_raw_mode()
        try:
            loop.add_reader(sys.stdin.fileno(), self._tui_on_readable)
        except Exception:
            pass
        # Wire Page Up/Down into the TUI screen scroll
        try:
            scr = self._screen
            _otr._TUI_SCROLL_CALLBACK = lambda d, p, s=scr: (
                s.scroll_up(p) if d == "pgup" else s.scroll_down(p)
            )
        except Exception:
            pass
        if self.peer:
            label = self._tui_label_for(self.peer)
            self.panel_manager.get_or_create_panel(label, "private")
            # Load persistent encrypted history into the panel
            try:
                if self.channel_log is not None:
                    panel = self.panel_manager.panels.get(label)
                    if panel is not None:
                        history = self.channel_log.read_recent(label, n=50000)
                        if history:
                            panel.add_message("── history ─────────────────────────────")
                            for entry in history:
                                if "|" in entry:
                                    ts_str, body = entry.split("|", 1)
                                    try:
                                        orig_ts = time.mktime(
                                            time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                        )
                                    except Exception:
                                        orig_ts = time.time()
                                    panel.history.append({
                                        "id": len(panel.history),
                                        "message": body,
                                        "timestamp": orig_ts,
                                        "metadata": {},
                                    })
                                else:
                                    panel.add_message(entry)
                            panel.add_message("── live ─────────────────────────────────")
            except Exception:
                pass
            self.panel_manager.switch_to_panel(label)
            self._tui_last_panel = label
            self._tui_autofocused = True
            self._tui_peer_hint(label)
        self._refresh_prompt()
        self._screen.redraw_full()
        return True

    def _stop_tui(self):
        global _ACTIVE_TUI_CLIENT
        if not getattr(self, "_tui_enabled", False):
            return
        self._tui_enabled = False
        _ACTIVE_TUI_CLIENT = None
        try:
            _otr._TUI_SCROLL_CALLBACK = None
        except Exception:
            pass
        try:
            self._loop.remove_reader(sys.stdin.fileno())
        except Exception:
            pass
        try:
            _restore_terminal()
        except Exception:
            pass
        try:
            import logging as _logging
            root = _logging.getLogger()
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in getattr(self, "_saved_log_handlers", []):
                root.addHandler(h)
        except Exception:
            pass
        builtins.print("\r")

    def cleanup(self) -> None:
        """Full shutdown wipe: identical behaviour to IRC client.
        Safe to call multiple times (idempotent via _cleaned_up flag)."""
        if self._cleaned_up:
            return
        self._cleaned_up = True

        self._peer_gone_at.clear()
        task = self._peer_gone_task
        self._peer_gone_task = None
        if task is not None and not task.done():
            try:
                task.cancel()
            except Exception:
                pass

        # 1. Tear down voice calls FIRST — this releases the microphone.
        #
        #    cleanup() may run from main()'s finally block, where the event
        #    loop is often already closed; run_until_complete() would then
        #    raise and the microphone would stay live past exit. The
        #    synchronous path is therefore authoritative and is always run,
        #    with the graceful async path attempted first only when a usable
        #    running-but-not-closed loop exists.
        if self._voice_manager is not None:
            try:
                loop = getattr(self, "loop", None)
                if (loop is not None and not loop.is_closed()
                        and not loop.is_running()):
                    loop.run_until_complete(self._voice_manager.cleanup())
            except Exception:
                pass
            try:
                torn = self._voice_manager.cleanup_sync()
                if torn:
                    print("[voice] %d call(s) force-closed, "
                          "microphone released, media keys zeroized" % torn)
            except Exception:
                pass

        # 2. Shut down the OTR crypto executor FIRST.
        #    DakeOutput and other Rust types are !Send (PyO3 constraint). They must
        #    be dropped on the same thread that created them. Worker threads must
        #    finish and release all references before we call clear_all_sessions()
        #    from the main thread — otherwise PyO3 raises RuntimeError on the drop.
        try:
            self._otr_executor.shutdown(wait=True, cancel_futures=True)
        except TypeError:
            # Python < 3.9 has no cancel_futures
            self._otr_executor.shutdown(wait=True)
        except Exception:
            pass

        # 2. Clear OTR sessions — Rust ZeroizeOnDrop fires on every ratchet drop.
        #    Safe now: executor threads are done and hold no !Send references.
        try:
            if hasattr(self.otr, "clear_all_sessions"):
                self.otr.clear_all_sessions("xmpp client shutdown")
        except Exception:
            pass

        # 3. Wipe ephemeral channel log (key zeroed + .enc files deleted)
        try:
            if self.channel_log is not None:
                self.channel_log.close()
                self.channel_log = None
        except Exception:
            pass

        # 4. Cryptographically destroy ~/.otrv4plus (fingerprints, trust DB, SMP)
        #    Uses the same _secure_file_destroy function the IRC client uses.
        try:
            secure_destroy = getattr(_otr, "_secure_file_destroy", None)
            if secure_destroy:
                import glob as _glob
                otr_dir = os.path.expanduser("~/.otrv4plus")
                if os.path.isdir(otr_dir):
                    for fpath in _glob.glob(
                        os.path.join(otr_dir, "**", "*"), recursive=True
                    ):
                        if os.path.isfile(fpath):
                            try:
                                secure_destroy(fpath)
                            except Exception:
                                pass
        except Exception:
            pass

    def _clear_and_exit_msg(self) -> None:
        """Clear the Termux screen and print termination message — mirrors IRC."""
        try:
            sys.stdout.write("\033[2J")
            sys.stdout.write("\033[H")
            sys.stdout.write("\033[3J")
            sys.stdout.flush()
            builtins.print("\n" * 100, end="")
            try:
                import subprocess as _subp
                _subp.run(["clear"], check=False)
            except Exception:
                pass
            _rust = getattr(_otr, "RUST_RATCHET_AVAILABLE", False)
            _wipe = "🦀 Rust memory zeroized" if _rust else "Memory cleared"
            builtins.print(f"\nOTRv4+ XMPP terminated - {_wipe} - screen cleared")
            builtins.print("Type 'python otrv4plus_xmpp.py' to start again")
        except Exception:
            pass

    def _tui_quit_to_plain(self) -> None:
        """Stop the tabbed TUI and revert to plain scrollback, keeping the
        XMPP connection alive. Called by the /tui runtime toggle command."""
        if not getattr(self, "_tui_enabled", False):
            return
        self._stop_tui()
        builtins.print(
            "\n[tui] reverted to plain scrollback. "
            "Type /tui to switch back. Commands still work."
        )

    def _tui_quit(self):
        self._shutting_down = True
        self.cleanup()
        self._stop_tui()
        self._clear_and_exit_msg()
        try:
            self.disconnect()
        except Exception:
            pass

    def _tui_on_readable(self):
        try:
            ch = _read_one_char()
        except Exception:
            return
        if ch is None:
            self._tui_quit()
            return
        try:
            res = _handle_input_char(ch)
        except Exception:
            return
        if res is None:
            return
        if res is _EOF_SENTINEL:
            self._tui_quit()
            return
        self._tui_handle_line(res)

    def _tui_handle_line(self, line):
        if not line:
            self._refresh_prompt()
            return
        if self._tui_nav(line):
            self._refresh_prompt()
            if self._screen is not None:
                self._screen.redraw_full()
            return
        active = self.panel_manager.active_panel
        peer = self._tui_jid_by_label.get(active)
        if peer is None:
            peer = self.peer or None
        if peer and not line.startswith("/") and not self.has_pending(peer):
            smp_ok = peer and (peer, "SUCCEEDED") in getattr(self, "_smp_reported", set())
            you_s = _colorize("you", "cyan")
            msg_s = _colorize(line, "dark_blue") if smp_ok else line
            self.panel_manager.add_message(active, you_s + ": " + msg_s)
        try:
            keep = self.dispatch_line(peer, line)
        except Exception as exc:
            self.panel_manager.add_message(active, _colorize(f"[error] {exc}", "red"))
            keep = True
        if keep is False:
            self._tui_quit()
            return
        self._refresh_prompt()
        if self._tui_enabled and self._screen is not None:
            self._screen.redraw_full()

    def _tui_nav(self, line):
        """Handle TUI-only tab navigation commands. Returns True if consumed."""
        pm = self.panel_manager
        parts = line.split()
        cmd = parts[0]
        order = pm.panel_order
        if cmd in ("/next", "/n"):
            i = order.index(pm.active_panel)
            pm.switch_to_panel(order[(i + 1) % len(order)])
            return True
        if cmd in ("/prev", "/p"):
            i = order.index(pm.active_panel)
            pm.switch_to_panel(order[(i - 1) % len(order)])
            return True
        if cmd in ("/win", "/window", "/w", "/switch", "/sw", "/go", "/buffer", "/b", "/j"):
            if len(parts) > 1:
                a = parts[1]
                if a.isdigit():
                    idx = int(a) - 1
                    if 0 <= idx < len(order):
                        pm.switch_to_panel(order[idx])
                elif a in pm.panels:
                    pm.switch_to_panel(a)
                else:
                    hit = [n for n in order if n.startswith(a)]
                    if len(hit) == 1:
                        pm.switch_to_panel(hit[0])
                    else:
                        pm.add_message(
                            pm.active_panel,
                            "no tab '%s'. tabs: %s" % (a, ", ".join(order))
                        )
            else:
                names = ", ".join(
                    "%d:%s" % (i + 1, n) for i, n in enumerate(order)
                )
                pm.add_message(pm.active_panel, "tabs: " + names)
            return True
        if cmd[1:].isdigit():
            idx = int(cmd[1:]) - 1
            if 0 <= idx < len(order):
                pm.switch_to_panel(order[idx])
            return True
        if cmd in ("/tabs", "/windows"):
            names = ", ".join(
                "%d:%s" % (i + 1, n) for i, n in enumerate(order)
            )
            pm.add_message(pm.active_panel, "tabs: " + names)
            return True
        if cmd in ("/close", "/wc"):
            name = pm.active_panel
            if name != "system" and name in pm.panels:
                i = order.index(name)
                pm.panels.pop(name, None)
                order.remove(name)
                pm.switch_to_panel(order[max(0, i - 1)])
            return True
        if cmd == "/clear":
            p = pm.panels.get(pm.active_panel)
            if p is not None:
                p.clear_history()
            return True
        return False


# =============================================================================
# Plain-line input loop (non-tty / piped fallback)
# =============================================================================

async def _input_loop(client):
    """Plain line reader (non-tty / piped fallback). The interactive TUI
    replaces this when stdin/stdout are a terminal; both share dispatch_line."""
    loop = asyncio.get_event_loop()
    while True:
        # This is the only stdin reader in plain mode, so the hidden password
        # prompt has to happen here rather than in a second thread racing it
        # for the same file descriptor.
        prompt = getattr(client, "_password_prompt", None)
        try:
            if prompt:
                line = await loop.run_in_executor(
                    None, getpass.getpass, prompt)
            else:
                line = await loop.run_in_executor(None, sys.stdin.readline)
        except (EOFError, KeyboardInterrupt):
            break
        if prompt:
            client.supply_password(line)
            continue
        if not line:
            break
        if getattr(client, "_password_prompt", None):
            # The prompt was raised while this read was already blocked, so
            # the line belongs to the prompt that is no longer there. Drop it
            # -- the next pass through is the hidden one. This is why the
            # auth message says "press Enter, then type the password again".
            continue
        if not client.dispatch_line(client.peer, line.rstrip("\n")):
            break
    client._shutting_down = True
    client.disconnect()


# =============================================================================
# Entry point
# =============================================================================

# -----------------------------------------------------------------------------
# Automated Termux / Android provisioning
# -----------------------------------------------------------------------------
# Goal: a user receives this single file, runs it, and ends up with a working
# encrypted voice-capable client without being walked through anything.
#
# Everything below runs with shell=False and explicit argv lists. Nothing is
# interpolated into a shell, so a hostile environment variable or filename
# cannot become command injection. Every subprocess has a timeout, so a wedged
# helper cannot hang startup forever.
#
# The provisioning is idempotent. Expensive steps (package installation) are
# gated behind a version-stamped marker file; runtime steps (starting the sound
# server, loading the microphone source) are re-checked on every launch because
# they do not survive a reboot.
# -----------------------------------------------------------------------------

BOOTSTRAP_VERSION = 5
BOOTSTRAP_MARKER = os.path.expanduser(
    "~/.otrv4plus/.bootstrap-v%d" % BOOTSTRAP_VERSION)

# Package name -> the executable or library proving it is installed.
_APT_REQUIREMENTS = (
    ("pulseaudio", "bin/parec"),
    ("libopus", "lib/libopus.so"),
    ("termux-api", "bin/termux-microphone-record"),
    # Termux splits OpenSSL: the `openssl` package ships libcrypto/libssl,
    # while the `openssl` COMMAND comes from `openssl-tool`. Checking for
    # bin/openssl while installing `openssl` can never succeed, so each entry
    # must name the package that actually provides the file being tested.
    ("openssl", "lib/libcrypto.so"),
    ("openssl-tool", "bin/openssl"),
    ("git", "bin/git"),
)

# Import name -> pip distribution name. These differ often enough that keying
# on the import name is the only reliable check.
_PIP_REQUIREMENTS = (
    ("slixmpp", "slixmpp"),
    ("aiodns", "aiodns"),
    ("cryptography", "cryptography"),
    ("opuslib", "opuslib"),
    ("argon2", "argon2-cffi"),
    ("socks", "pysocks"),
)

_PULSE_SOURCE_MODULE = "module-sles-source"


def _run(argv, timeout=120, env=None, detach=False):
    """Run a command with no shell. Returns (rc, stdout, stderr).

    Never raises: a missing binary, a timeout and a crash all return a
    non-zero rc so callers can branch uniformly.

    detach=True is REQUIRED for any command that forks a daemon and exits
    (pulseaudio --start, i2pd --daemon). Capturing output from such a command
    deadlocks: the foreground process exits immediately, but the daemon it
    forked inherits the stdout and stderr pipes and holds them open for its
    entire lifetime, so communicate() never observes EOF and blocks until the
    timeout — which then kills the very daemon we were trying to start.
    Measured: 8 s timeout with capture, 0.01 s without.
    """
    import subprocess
    try:
        if detach:
            completed = subprocess.run(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                env=env or os.environ,
                check=False,
            )
            return completed.returncode, "", ""
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as exc:
        return 1, "", str(exc)


def _termux_env():
    """Environment for child processes, with the Termux library path set.

    PortAudio and PulseAudio clients resolve libpulse.so at load time; without
    this on the child's environment they fail with a bare dlopen error that is
    very hard to diagnose.
    """
    env = dict(os.environ)
    libdir = os.path.join(TERMUX_PREFIX, "lib")
    current = env.get("LD_LIBRARY_PATH", "")
    if libdir not in current.split(os.pathsep):
        env["LD_LIBRARY_PATH"] = (
            libdir + (os.pathsep + current if current else ""))
    return env


def _apt_missing():
    """Return the apt packages whose proof-of-install file is absent."""
    missing = []
    for package, relative in _APT_REQUIREMENTS:
        if not os.path.exists(os.path.join(TERMUX_PREFIX, relative)):
            missing.append(package)
    return missing


def _pip_missing():
    """Return the pip distributions whose import name does not resolve."""
    import importlib
    importlib.invalidate_caches()
    missing = []
    for module, distribution in _PIP_REQUIREMENTS:
        try:
            importlib.import_module(module)
        except Exception:
            missing.append(distribution)
    return missing


def _apt_install(packages):
    """Install apt packages, tolerating unrelated post-install failures.

    Termux's xdg-utils post-install script fails on many devices and poisons
    apt's exit status for every package in the same transaction. The return
    code is therefore ignored entirely; success is judged solely by re-testing
    for each package's proof file afterwards.

    --no-install-recommends keeps the broken xdg-utils/qt6 dependency chain
    out of the transaction in the first place.
    """
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    _run(["apt-get", "update", "-y"], timeout=180, env=env)
    _run(
        ["apt-get", "install", "-y", "--no-install-recommends",
         "-o", "Dpkg::Options::=--force-confold",
         "-o", "Dpkg::Options::=--force-confdef"] + list(packages),
        timeout=900, env=env,
    )


def _pip_install(distributions):
    """Install pip distributions into the Termux Python."""
    _run(
        [sys.executable, "-m", "pip", "install", "--break-system-packages",
         "--disable-pip-version-check", "-q"] + list(distributions),
        timeout=900,
    )


def _pulse_running():
    return _run(["pulseaudio", "--check"], timeout=15,
                env=_termux_env())[0] == 0


def _pulse_start():
    """Start PulseAudio as a persistent daemon. Returns (started, diagnosis).

    `pulseaudio --start` forks the daemon and RETURNS — it does not block —
    so it must be run with its output captured rather than detached. An
    earlier version detached it, which discarded the daemon's own error
    message and left this function reporting the unrelated output of a later
    `--check` call.

    Timing matters more than retrying. A cold daemon on Android can take well
    over ten seconds to load its modules and accept connections. The first
    attempt is therefore given a long, patient window; `-k` is only used
    afterwards, because killing during startup destroys a daemon that was
    simply slow — which is precisely what happened before.
    """
    if _which("pulseaudio") is None:
        return False, "pulseaudio binary not found — pkg install pulseaudio"

    env = _termux_env()
    common = ["--exit-idle-time=-1"]

    def _await_daemon(seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if _pulse_running():
                return True
            time.sleep(0.4)
        return False

    # Attempt 1: patient. Captured, so a real failure is explained.
    rc, out, err = _run(["pulseaudio", "--start"] + common, timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    first_error = (err or out or "").strip()

    # Attempt 2: clear a stale runtime directory, then start again. Only now
    # is -k safe, because attempt 1 has been given every chance to finish.
    _run(["pulseaudio", "-k"], timeout=20, env=env)
    time.sleep(1.0)
    rc, out, err = _run(["pulseaudio", "--start"] + common, timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    second_error = (err or out or "").strip()

    # Attempt 3: explicit daemonize, for builds where --start misbehaves.
    rc, out, err = _run(["pulseaudio", "--daemonize=yes"] + common,
                        timeout=45, env=env)
    if _await_daemon(20):
        return True, ""
    third_error = (err or out or "").strip()

    for candidate in (first_error, second_error, third_error):
        lines = [l for l in candidate.splitlines()
                 if l.strip() and not l.startswith("I: ")]
        if lines:
            return False, lines[-1][:180]
    return False, "no diagnostic produced by the daemon"


def _pulse_sources():
    """Return the list of PulseAudio source names, or [] on failure."""
    rc, out, _ = _run(["pactl", "list", "short", "sources"],
                      timeout=20, env=_termux_env())
    if rc != 0:
        return []
    names = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            names.append(parts[1])
    return names


def _pulse_input_source(sources):
    """Pick the real microphone from a source list.

    A monitor source is the loopback of the speaker output, not a microphone;
    selecting one produces a call in which each side hears only themselves.
    """
    for name in sources:
        if "monitor" not in name.lower() and "input" in name.lower():
            return name
    for name in sources:
        if "monitor" not in name.lower():
            return name
    return None


def _ensure_microphone_source():
    """Guarantee a non-monitor capture source exists and is the default.

    Returns (source_name_or_None, note).
    """
    sources = _pulse_sources()
    source = _pulse_input_source(sources)

    if source is None:
        # Load the Android OpenSL ES capture module. Loading it twice creates
        # duplicate sources, so this only runs when none was found.
        _run(["pactl", "load-module", _PULSE_SOURCE_MODULE],
             timeout=30, env=_termux_env())
        time.sleep(1.0)
        sources = _pulse_sources()
        source = _pulse_input_source(sources)

    if source is None:
        return None, "no capture source available"

    _run(["pactl", "set-default-source", source], timeout=20,
         env=_termux_env())
    return source, "ok"


def _termux_api_present():
    """Check the Termux:API companion app, not merely the CLI package.

    The termux-api apt package only installs shell shims; the actual Android
    bridge is a separate APK. Without the APK the shims block forever waiting
    on a socket, so this probe is timeout-bounded.
    """
    if _which("termux-microphone-record") is None:
        return False, "termux-api package not installed"
    rc, out, err = _run(["termux-microphone-record", "-i"], timeout=12)
    if rc == 124:
        return False, "Termux:API app not installed (command hung)"
    blob = (out + err).lower()
    if "permission" in blob:
        return True, "permission-needed"
    return True, "ok"


def _request_microphone_permission():
    """Trigger Android's RECORD_AUDIO prompt for Termux.

    PulseAudio's OpenSL ES source records through the Termux process itself
    and cannot raise a runtime permission dialog; only the Termux:API bridge
    can. A one-second recording is therefore started purely to make the system
    dialog appear, then stopped, and the resulting file is destroyed with the
    OTR engine's cryptographic shredder. It contains a second of ambient audio
    at most and never survives this function.
    """
    target = os.path.join(
        os.path.expanduser("~"), ".otrv4plus_permcheck_%s.m4a"
        % secrets.token_hex(4))
    try:
        # termux-microphone-record backgrounds the recorder, so its output
        # must not be captured for the same reason pulseaudio --start cannot.
        _run(["termux-microphone-record", "-f", target, "-l", "1"],
             timeout=20, detach=True)
        time.sleep(2.0)
        _run(["termux-microphone-record", "-q"], timeout=20, detach=True)
        time.sleep(0.5)
    finally:
        try:
            if os.path.exists(target):
                shred = getattr(_otr, "_secure_file_destroy", None)
                if shred is not None:
                    shred(target)
                else:
                    with open(target, "r+b") as handle:
                        length = os.path.getsize(target)
                        handle.write(os.urandom(max(length, 1)))
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.remove(target)
        except Exception:
            try:
                os.remove(target)
            except Exception:
                pass


def _capture_selftest(seconds=3.0):
    """Verify the microphone actually delivers samples.

    Goes through otrv4plus_audio, so it tests whichever backend voice will
    actually use — AAudio on Android. The previous version drove parec, which
    meant a device with a perfectly working AAudio microphone was reported as
    broken and the user was told to repair PulseAudio, which was both wrong
    and unfixable on hardware where module-sles-source does not load.

    Returns (ok, bytes_captured, peak_amplitude, backend_name).

    Peak is reported rather than asserted: a silent room is not a failure, but
    a peak of zero alongside a healthy byte count is the signature of a
    revoked RECORD_AUDIO permission, or of a null source, and is worth telling
    the user about. Nothing is written to disk and no samples are printed.
    """
    try:
        import otrv4plus_audio as _aud
    except Exception:
        return False, 0, 0, "none"

    stream = None
    total, peak = 0, 0
    backend = "none"
    try:
        stream, _notes = _aud.open_capture(which=_which,
                                           read_exact=_pipe_read_exact,
                                           env=_termux_env())
        backend = stream.name
        deadline = time.monotonic() + float(seconds)
        while time.monotonic() < deadline:
            frame = stream.read_frame(timeout_ms=200)
            if not frame:
                continue
            total += len(frame)
            n = len(frame) // 2
            peak = max(peak, max(abs(v) for v in struct.unpack("<%dh" % n,
                                                               frame)))
    except Exception:
        return False, total, peak, backend
    finally:
        if stream is not None:
            try:
                stream.stop()
            except Exception:
                pass
    return True, total, peak, backend

def _persist_shell_profile():
    """Append the audio environment to ~/.bashrc, exactly once.

    Written so that a plain `bash` session (not just this script) has a working
    sound stack, which matters when the user runs the client a second time.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    marker = "# --- OTRv4+ audio environment (managed) ---"
    try:
        existing = ""
        if os.path.exists(bashrc):
            with open(bashrc, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        if marker in existing:
            return False
        with open(bashrc, "a", encoding="utf-8") as fh:
            fh.write("\n%s\n" % marker)
            fh.write("export LD_LIBRARY_PATH=%s/lib:$LD_LIBRARY_PATH\n"
                     % TERMUX_PREFIX)
            fh.write("pulseaudio --check 2>/dev/null || "
                     "pulseaudio --start --exit-idle-time=-1 2>/dev/null\n")
            fh.write("pactl list short sources 2>/dev/null | "
                     "grep -qv monitor || "
                     "pactl load-module %s 2>/dev/null\n" % _PULSE_SOURCE_MODULE)
            fh.write("# --- end OTRv4+ audio environment ---\n")
        return True
    except Exception:
        return False


def _probe_sam(host="127.0.0.1", port=7656, timeout=3.0):
    """Return True if a SAM v3.1 bridge answers on host:port."""
    import socket as _socket
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
        reply = sock.recv(256)
        sock.close()
        return b"RESULT=OK" in reply
    except Exception:
        return False


def _bootstrap_termux(skip=False, force=False, sam_host="127.0.0.1",
                      sam_port=7656):
    """Provision an Android/Termux device end to end.

    No-op on non-Termux systems. Returns a list of unresolved issues; an empty
    list means the device is ready for encrypted voice calls.
    """
    if not IS_TERMUX or skip:
        _load_opus()
        return []

    issues = []
    first_run = force or not os.path.exists(BOOTSTRAP_MARKER)

    builtins.print("=" * 62)
    builtins.print(" OTRv4+ XMPP — device provisioning")
    builtins.print("=" * 62)

    # -- 1. Native packages ---------------------------------------------------
    missing_apt = _apt_missing()
    if missing_apt:
        # openssl-tool provides only the command-line utility. Nothing in the
        # client calls it — libcrypto is reached through the C extensions —
        # so its absence is cosmetic and must not be presented as a failure.
        pass
    if missing_apt:
        builtins.print("  installing packages: %s" % " ".join(missing_apt))
        builtins.print("  (this can take a few minutes on first run)")
        _apt_install(missing_apt)
        still_missing = _apt_missing()
        cosmetic = {"openssl-tool"}
        blocking = [p for p in still_missing if p not in cosmetic]
        if blocking:
            issues.append(
                "could not install: %s  —  run manually: pkg install %s"
                % (" ".join(blocking), " ".join(blocking)))
            builtins.print("  ! failed: %s" % " ".join(blocking))
        if [p for p in still_missing if p in cosmetic]:
            builtins.print("    note: openssl-tool (the CLI) unavailable — "
                           "harmless, the client uses libcrypto directly")
        if not blocking:
            builtins.print("  packages installed")
    else:
        builtins.print("  packages           OK")

    # -- 2. Python distributions ---------------------------------------------
    missing_pip = _pip_missing()
    if missing_pip:
        builtins.print("  installing Python modules: %s" % " ".join(missing_pip))
        _pip_install(missing_pip)
        still_missing = _pip_missing()
        if still_missing:
            issues.append(
                "pip install failed for: %s" % " ".join(still_missing))
            builtins.print("  ! failed: %s" % " ".join(still_missing))
        else:
            builtins.print("  Python modules installed")
    else:
        builtins.print("  Python modules     OK")

    # Re-import opuslib now that it may exist. Without this the process would
    # run the whole session believing voice is unavailable.
    _load_opus()

    # -- 3. Library path for child processes ----------------------------------
    libdir = os.path.join(TERMUX_PREFIX, "lib")
    if libdir not in os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep):
        os.environ["LD_LIBRARY_PATH"] = (
            libdir + os.pathsep + os.environ.get("LD_LIBRARY_PATH", ""))

    # -- 4. Termux:API bridge and microphone permission -----------------------
    api_ok, api_note = _termux_api_present()
    if not api_ok:
        issues.append(
            "Termux:API app missing — install it from F-Droid "
            "(same source as Termux), then re-run. Without it Android will "
            "never prompt for microphone access.")
        builtins.print("  Termux:API         MISSING")
    elif api_note == "permission-needed" or first_run:
        builtins.print("  requesting microphone permission…")
        builtins.print("  >> TAP 'ALLOW' ON THE ANDROID DIALOG <<")
        _request_microphone_permission()
        builtins.print("  microphone permission requested")
    else:
        builtins.print("  Termux:API         OK")

    # -- 5/6. Audio backend and proof that capture works ---------------------
    #
    # AAudio is the backend voice actually uses on Android: it talks to the
    # platform audio framework directly and needs no daemon, no PulseAudio and
    # no module-sles-source. So the question is not "is PulseAudio healthy" —
    # it is "does the backend voice will use deliver real samples". PulseAudio
    # is only prepared, and only diagnosed, when it is the only backend left.
    pulse_note = ""
    aaudio_ok = False
    try:
        import otrv4plus_audio as _aud
        aaudio_ok = _aud.aaudio_available()
    except Exception as exc:
        builtins.print("  audio backend      MODULE ERROR: %s"
                       % _sanitise(str(exc), 80))

    if aaudio_ok:
        builtins.print("  audio backend      AAudio (native Android)")
    else:
        builtins.print("  audio backend      AAudio unavailable — trying "
                       "PulseAudio")
        if _pulse_running():
            builtins.print("  PulseAudio         running")
        else:
            started, pulse_note = _pulse_start()
            if started:
                builtins.print("  PulseAudio         started")
            else:
                builtins.print("  PulseAudio         did not start via --start")
                if pulse_note:
                    builtins.print("                     reason: %s"
                                   % _sanitise(pulse_note, 200))
        source, _note = _ensure_microphone_source()
        if source is None:
            builtins.print("  microphone source  none listed "
                           "(may still autospawn)")
        else:
            builtins.print("  microphone source  %s" % source)

    # Run unconditionally. If this passes, everything above was noise; if it
    # fails, it is the only failure that actually matters.
    builtins.print("  testing microphone…")
    ok_capture, total, peak, backend = _capture_selftest()
    if ok_capture and total > 0 and peak > 0:
        builtins.print("  microphone test    OK via %s (peak %d)"
                       % (backend, peak))
    elif ok_capture and total > 0:
        issues.append(
            "microphone delivered only silence via %s — grant Microphone in "
            "Settings > Apps > Termux > Permissions, then re-run. Termux:API "
            "holding the permission is not enough; the Termux app itself "
            "needs it." % backend)
        builtins.print("  microphone test    SILENT (%d bytes via %s)"
                       % (total, backend))
    elif aaudio_ok:
        issues.append(
            "AAudio loaded but produced no audio. Check Settings > Apps > "
            "Termux > Permissions > Microphone, then run /audioprobe in a "
            "session for the exact backend error. Do NOT chase PulseAudio: "
            "voice does not use it.")
        builtins.print("  microphone test    NO AUDIO (AAudio)")
    else:
        detail = (" — %s" % pulse_note) if pulse_note else ""
        issues.append(
            "no working audio backend%s. AAudio (libaaudio.so) was not "
            "available and PulseAudio produced nothing. Run /audioprobe for "
            "per-backend detail." % detail)
        builtins.print("  microphone test    NO AUDIO")

    # -- 7. I2P router --------------------------------------------------------
    if _probe_sam(sam_host, sam_port):
        builtins.print("  I2P SAM bridge     OK (%s:%d)" % (sam_host, sam_port))
    else:
        issues.append(
            "no I2P SAM bridge on %s:%d — start the i2pd Android app with SAM "
            "enabled, or run: pkg install i2pd && i2pd --daemon "
            "(SAM must be enabled in i2pd.conf)" % (sam_host, sam_port))
        builtins.print("  I2P SAM bridge     NOT FOUND")

    # -- 8. OTR engine and Rust core -----------------------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    if not (os.path.exists(os.path.join(here, "otrv4+.py"))
            or os.path.exists(os.path.join(here, "otrv4plus.py"))):
        issues.append("otrv4+.py not found beside this script")
    try:
        __import__("otrv4_core")
        builtins.print("  Rust ratchet       OK")
    except Exception:
        issues.append(
            "otrv4_core (Rust ratchet) not installed — build it: "
            "cd Rust && cargo test --release && "
            "ANDROID_API_LEVEL=24 maturin build --release && "
            "pip install target/wheels/otrv4_core-*.whl --break-system-packages")
        builtins.print("  Rust ratchet       MISSING")

    # -- 9. Persist for future shells ----------------------------------------
    if _persist_shell_profile():
        builtins.print("  ~/.bashrc          updated")

    # -- 10. Stamp ------------------------------------------------------------
    try:
        os.makedirs(os.path.dirname(BOOTSTRAP_MARKER), exist_ok=True)
        with open(BOOTSTRAP_MARKER, "w", encoding="utf-8") as fh:
            fh.write("provisioned %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        os.chmod(BOOTSTRAP_MARKER, 0o600)
    except Exception:
        pass

    # -- Summary --------------------------------------------------------------
    builtins.print("-" * 62)
    voice_ok, voice_reason = voice_available()
    if issues:
        builtins.print(" Attention needed:")
        for issue in issues:
            builtins.print("   * %s" % issue)
        builtins.print("")
        builtins.print(" Text chat works regardless; only the items above are "
                       "required for voice.")
    else:
        builtins.print(" Device ready — encrypted text and voice both available.")
    if not voice_ok:
        builtins.print(" Voice disabled: %s" % voice_reason)
    builtins.print("=" * 62)
    builtins.print("")
    return issues


async def _audio_selftest_async():
    """/audiotest — re-run the capture probe from inside a live session."""
    loop = asyncio.get_event_loop()
    if not IS_TERMUX:
        print("[audio] self-test is Termux-only")
        return
    print("[audio] capturing ~3 s from the microphone…")
    ok, total, peak, backend = await loop.run_in_executor(
        None, _capture_selftest)
    if not ok or total == 0:
        print("[audio] FAILED — no samples via %s. Run /audioprobe for the "
              "per-backend error." % backend)
        return
    if peak == 0:
        print("[audio] captured %d bytes via %s but pure silence — check "
              "Settings > Apps > Termux > Permissions > Microphone (the "
              "Termux app itself, not Termux:API)" % (total, backend))
        return
    print("[audio] OK — %d bytes via %s, peak amplitude %d"
          % (total, backend, peak))
    voice_ok, reason = voice_available()
    print("[audio] voice subsystem: %s" % ("ready" if voice_ok else reason))

def main():
    # Device provisioning deliberately runs AFTER argument parsing, so that
    # --skip-setup, --force-setup and --sam-host/--sam-port are honoured.
    # Running it before argparse would make those flags unreachable.

    # Suppress the slixmpp "Task was destroyed but it is pending" warning that
    # fires when the event loop closes before XMLStream filter tasks finish.
    # This is a cosmetic asyncio cleanup race in slixmpp, not an application bug.
    import warnings
    warnings.filterwarnings(
        "ignore",
        message="Task was destroyed but it is pending",
        category=RuntimeWarning,
    )

    ap = argparse.ArgumentParser(
        description=f"OTRv4+ XMPP {XMPP_VERSION} - full OTR + SMP over I2P SAM"
    )
    ap.add_argument("--jid", required=True, help="your full JID")
    ap.add_argument("--peer", help="default peer JID for /otr, /smp, chat")
    ap.add_argument(
        "--server",
        help="server c2s .b32.i2p address to SAM-connect to "
             "(default: the domain part of --jid)",
    )
    ap.add_argument("--port", type=int, default=5222, help="server c2s port")
    ap.add_argument("--sam-host", default="127.0.0.1", help="i2pd SAM host")
    ap.add_argument("--sam-port", type=int, default=7656, help="i2pd SAM port")
    ap.add_argument(
        "--no-i2p",
        action="store_true",
        help="connect directly (clearnet), do not use I2P SAM",
    )
    ap.add_argument(
        "--tor",
        action="store_true",
        help="route the XMPP control connection through Tor (SOCKS5). "
             "Implied by a .onion server. Voice media stays on I2P.",
    )
    ap.add_argument(
        "--no-tor",
        action="store_true",
        help="never use Tor, even for a .onion server (the connection will "
             "then fail rather than leak)",
    )
    ap.add_argument("--socks-host", default="127.0.0.1",
                    help="Tor SOCKS5 host")
    ap.add_argument("--socks-port", type=int, default=TOR_SOCKS_PORT,
                    help="Tor SOCKS5 port (9050 daemon, 9150 Tor Browser)")
    ap.add_argument(
        "--insecure-tls",
        action="store_true",
        help="accept expired/self-signed server certs",
    )
    ap.add_argument(
        "--no-reconnect",
        action="store_true",
        help="disable automatic reconnection on disconnect",
    )
    ap.add_argument(
        "--tui",
        action="store_true",
        help="enable the tabbed panel UI. Default is plain scrollback, "
             "which works with Termux's native finger-scroll. Use --tui "
             "for the tabbed curses-style view.",
    )
    ap.add_argument(
        "--no-tui",
        action="store_true",
        help="plain linear scrollback (default; kept for backward compatibility)",
    )
    ap.add_argument(
        "--log-file",
        default=None,
        help="override the session transcript path (default: "
             "~/.otrv4plus/logs/session-<timestamp>.log). "
             "Only written when --debug is set.",
    )
    ap.add_argument(
        "--no-log",
        action="store_true",
        help="disable the session transcript even with --debug",
    )
    ap.add_argument(
        "--keep-log",
        action="store_true",
        help="keep the transcript file after a clean exit "
             "(default: deleted on clean /quit or Ctrl+C; kept "
             "automatically if the session crashes)",
    )
    ap.add_argument(
        "--skip-setup",
        action="store_true",
        help="skip Android/Termux provisioning (packages, microphone, "
             "PulseAudio) and start immediately",
    )
    ap.add_argument(
        "--force-setup",
        action="store_true",
        help="re-run full provisioning even if this device was already "
             "provisioned",
    )
    ap.add_argument(
        "--setup-only",
        action="store_true",
        help="provision the device, print the report, and exit without "
             "connecting",
    )
    ap.add_argument(
        "--voice-debug",
        action="store_true",
        help="log voice call setup stages and 5-second in-call telemetry "
             "(also toggleable at runtime with /voicedebug)",
    )
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    # ---- Device provisioning (Termux only; a no-op elsewhere) ----
    _setup_issues = _bootstrap_termux(
        skip=args.skip_setup,
        force=args.force_setup,
        sam_host=args.sam_host,
        sam_port=args.sam_port,
    )
    if args.setup_only:
        sys.exit(1 if _setup_issues else 0)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)-8s %(message)s",
    )

    global _SESSION_LOG_FH
    if args.debug and not args.no_log:
        log_path = args.log_file or os.path.expanduser(
            "~/.otrv4plus/logs/session-%s.log" % time.strftime("%Y%m%d-%H%M%S")
        )
        try:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            _SESSION_LOG_FH = open(log_path, "a", encoding="utf-8")
            builtins.print(f"[log] full session transcript -> {log_path}")
            builtins.print(f"[log] read it live with: tail -f {log_path}")
            if not args.keep_log:
                builtins.print(
                    "[log] deleted automatically on a clean exit; "
                    "kept if the session crashes"
                )
        except Exception as e:
            builtins.print(f"[log] could not open log file: {e}", file=sys.stderr)
    elif args.log_file and not args.debug:
        builtins.print("[log] --log-file has no effect without --debug")

    # Validate the addresses BEFORE prompting for a password. A malformed JID
    # otherwise surfaces as a slixmpp stringprep traceback after the user has
    # already typed their password — unreadable, and it discards the input.
    def _check_jid(value, label):
        if not value:
            return
        if "@" not in value or value.count("@") != 1:
            sys.exit("Invalid %s: %r\n"
                     "  Expected  user@server.b32.i2p" % (label, value))
        local, _, domain = value.partition("@")
        if not local or not domain:
            sys.exit("Invalid %s: %r\n"
                     "  Both a username and a server are required." 
                     % (label, value))
        if "..." in value or ".." in domain:
            sys.exit("Invalid %s: %r\n"
                     "  This looks like an abbreviated address. Use the full "
                     "server name, not one shortened with '...'." 
                     % (label, value))
        for part in domain.split("."):
            if not part:
                sys.exit("Invalid %s: %r\n"
                         "  The server name has an empty part — check for a "
                         "stray or doubled dot." % (label, value))

    _check_jid(args.jid, "--jid")
    _check_jid(args.peer, "--peer")

    password = getpass.getpass(f"Password for {args.jid}: ")
    try:
        client = OTRv4PlusXMPP(args.jid, password, peer=args.peer,
                               debug=args.debug)
    except Exception as exc:
        sys.exit("Could not use that address: %s\n"
                 "  Check --jid and --peer are full user@server.b32.i2p "
                 "addresses." % exc)

    # Voice media uses its own SAM sessions, independent of the XMPP tunnel,
    # so it needs the bridge coordinates explicitly.
    client._voice_sam_host = args.sam_host
    client._voice_sam_port = args.sam_port
    client._voice_debug = bool(args.voice_debug)

    if hasattr(client, "enable_direct_tls"):
        client.enable_direct_tls = False
    if hasattr(client, "enable_starttls"):
        client.enable_starttls = True

    if args.insecure_tls:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        client.ssl_context = ctx
        print("[tls] certificate verification DISABLED (--insecure-tls).")

    domain = args.jid.split("@", 1)[-1]
    server_b32 = args.server or domain
    use_i2p = (not args.no_i2p) and server_b32.endswith(".i2p")
    # Tor is chosen by the address, or asked for explicitly. Never inferred
    # as a fallback from something else failing.
    use_tor = (not args.no_tor) and (args.tor
                                     or server_b32.endswith(".onion"))

    if use_i2p and use_tor:
        sys.exit("[transport] --tor was requested for an .i2p server. Pick "
                 "one: I2P uses the SAM bridge, Tor uses SOCKS5. Layering "
                 "them is not a supported configuration and guessing which "
                 "you meant could send traffic the wrong way.")
    if args.no_tor and server_b32.endswith(".onion"):
        sys.exit("[transport] %s is an onion address but --no-tor was given. "
                 "Refusing: without Tor there is no route to it, and trying "
                 "anyway would send the lookup to your resolver."
                 % server_b32)
    if use_tor and not server_b32.endswith(".onion"):
        print("[tor] WARNING: %s is not an onion address. Tor will carry the "
              "connection, but the exit sees a normal TLS session to a "
              "clearnet host, so the server still learns it is being reached "
              "over Tor rather than by you directly." % server_b32)

    if args.insecure_tls and use_tor and server_b32.endswith(".onion"):
        print(
            "[tls] --insecure-tls with an onion address: the v3 onion name is "
            "itself the server's public key, so the endpoint is "
            "cryptographically authenticated by Tor regardless of the "
            "certificate. That is the same reasoning that makes the flag "
            "acceptable over I2P."
        )
    elif args.insecure_tls and not use_i2p:
        print(
            "[tls] WARNING: --insecure-tls on a CLEARNET connection disables "
            "certificate verification, so an active network attacker can MITM "
            "the link and capture your XMPP password. Over I2P the .b32 "
            "destination is cryptographically authenticated, so the flag is "
            "acceptable there; over clearnet it is NOT. Use a CA-valid server "
            "certificate instead of this flag."
        )

    # Store reconnect parameters on the client before first connect.
    client._is_i2p = use_i2p
    client._is_tor = use_tor
    client._tor_params = None
    if use_tor and not args.no_reconnect:
        client._tor_params = {
            "onion_host": server_b32,
            "dest_port": args.port,
            "socks_host": args.socks_host,
            "socks_port": args.socks_port,
        }
    if args.no_reconnect:
        # _sam_params=None means reconnect logic is disabled.
        client._sam_params = None
    elif use_i2p:
        client._sam_params = {
            "server_b32": server_b32,
            "dest_port": args.port,
            "sam_host": args.sam_host,
            "sam_port": args.sam_port,
        }
    # For clearnet, _sam_params stays None (reconnect uses self.connect() directly
    # only when _sam_params is set for I2P; for clearnet reconnect is not implemented
    # because the standard case is TLS-verified servers that handle their own reconnect).

    loop = client.loop

    if use_i2p:
        try:
            host, port = loop.run_until_complete(
                start_i2p_sam_forwarder(
                    server_b32,
                    args.port,
                    sam_host=args.sam_host,
                    sam_port=args.sam_port,
                )
            )
        except Exception as e:
            print(f"[i2p] SAM bridge failed: {e}", file=sys.stderr)
            print(
                "[i2p] Is i2pd running with SAM enabled on "
                f"{args.sam_host}:{args.sam_port}? Is the server b32 correct?",
                file=sys.stderr,
            )
            sys.exit(1)
        client.connect(host, port)
    elif use_tor:
        try:
            host, port = loop.run_until_complete(
                start_tor_socks_forwarder(
                    server_b32,
                    args.port,
                    socks_host=args.socks_host,
                    socks_port=args.socks_port,
                )
            )
        except Exception as e:
            print(f"[tor] SOCKS5 tunnel failed: {e}", file=sys.stderr)
            print(
                "[tor] Is tor running with a SOCKS port on "
                f"{args.socks_host}:{args.socks_port}? "
                "(Termux: pkg install tor, then run tor)",
                file=sys.stderr,
            )
            # Fail closed. Connecting directly here would send this user's
            # address to a server they asked to reach over Tor.
            sys.exit(1)
        client.connect(host, port)
    else:
        client.connect()

    _clean_exit = True
    use_tui = getattr(args, "tui", False) and not getattr(args, "no_tui", False)
    try:
        started_tui = use_tui and client._start_tui(loop, debug=args.debug)
        if not use_tui:
            if args.debug:
                print("[mode] plain scrollback. Swipe up for history; /log "
                      "shows the full session. --tui for tabbed panels.")
        if started_tui:
            try:
                loop.run_until_complete(client.disconnected)
            except KeyboardInterrupt:
                client._tui_quit()
            finally:
                client._stop_tui()
        else:
            try:
                loop.run_until_complete(
                    asyncio.gather(client.disconnected, _input_loop(client))
                )
            except KeyboardInterrupt:
                client._shutting_down = True
                client.disconnect()
    except Exception:
        _clean_exit = False
        raise
    finally:
        client.cleanup()
        if not getattr(client, "_tui_enabled", False):
            # Non-TUI path or TUI already stopped — do screen clear here
            client._clear_and_exit_msg()
        if _SESSION_LOG_FH is not None:
            log_path = getattr(_SESSION_LOG_FH, "name", None)
            try:
                _SESSION_LOG_FH.close()
            except Exception:
                pass
            if log_path:
                if _clean_exit and not args.keep_log:
                    try:
                        os.remove(log_path)
                        builtins.print("[log] clean exit -- transcript removed")
                    except Exception:
                        pass
                else:
                    builtins.print(f"[log] transcript kept -> {log_path}")


if __name__ == "__main__":
    main()
