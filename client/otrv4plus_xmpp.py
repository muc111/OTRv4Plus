#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""
OTRv4+ XMPP - full OTR + SMP over XMPP, transported over I2P SAM
================================================================
Version: 10.23.0


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
      --debug

COMMANDS:
    /otr [jid]            start an OTR session (DAKE)
    /deniable [jid]       publish the session's MAC keys, end it, start afresh
    y / n                 answer the trust-fingerprint prompt
    <passphrase>          answer the SMP passphrase prompt
    /smp                  verify this session (prompts for the passphrase,
                          hidden, if none is stored) — the only one you need
    /smp start            same as /smp
    /smp <secret>         set the passphrase inline and start (ECHOED)
    /smp-secret           store a passphrase without verifying (prompts)
    /smp-secret <secret>  store it inline (ECHOED — advanced/compat)
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
#    * TLS verification follows the transport.  Over I2P and over Tor to
#      an .onion the address IS the server's key, so certificate checks
#      are skipped and say so; over clearnet verification is on and only
#      --insecure-tls disables it, with a warning
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

# Started as `python <client>`: run again with the project interpreter
# (~/OTRv4Plus/.venv, where Rust/build.sh installs otrv4_core). Loaded by
# name: the APK never runs a client as a script and does not ship it.
if __name__ == "__main__":
    import importlib as _importlib
    _importlib.import_module("otrv4plus_venv").ensure(__file__)

import argparse
import asyncio
import builtins
import collections
import getpass
import logging
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import otrv4plus_repo  # noqa: F401  (android_bridge importable from client/)
import otrv4plus_address as _address
import otrv4plus_host as _host
import otrv4plus_tunnels as _tunnels
import otrv4plus_termux as _termux
from otrv4plus_tunnels import (  # noqa: F401  (re-exported: android_bridge, voice, tests)
    HELD_SAM, HeldSamSession, SAMProtocolError, TOR_SOCKS_PORT, socks5_connect,
    start_i2p_sam_forwarder, start_tor_socks_forwarder, _ossl_cleanse,
    _pipe_read_exact, _pipe_write_all, _sam_open, _sam_parse, _sam_read_line,
    _sam_release)
from otrv4plus_host import TERMUX_PREFIX, _which, _xmpp_state_path, _run
from otrv4plus_termsync import TermSyncMixin as _TermSyncMixin
from otrv4plus_xmpp_admin import AdminMixin as _AdminMixin
import otrv4plus_xmpp_tui as _tui
from otrv4plus_xmpp_tui import TuiMixin as _TuiMixin
import otrv4plus_xmpp_trust as _trust
from otrv4plus_xmpp_trust import TrustMixin as _TrustMixin, _fmt_fp
from otrv4plus_xmpp_files import FilesMixin as _FilesMixin
from otrv4plus_xmpp_trade import TradeMixin as _TradeMixin
from otrv4plus_xmpp_connection import ConnectionMixin as _ConnectionMixin, _RECONNECT_BASE
from otrv4plus_xmpp_presence import PresenceMixin as _PresenceMixin


def _live_item(client, msg):
    """otrv4plus_sync's view of a live plaintext message (its ids, reply,
    correction), or None."""
    try:
        import otrv4plus_sync as _sync_mod
        return _sync_mod.parse_message(msg.xml, client._ts_own(), "live")
    except Exception:
        return None
import otrv4plus_caps as _caps
import otrv4plus_coreapi as _coreapi
import otrv4plus_fragment as _frag
from otrv4plus_mode import OtrMode as _OtrMode
import otrv4plus_smpflow as _smpflow

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
        return False, ("opuslib or libopus missing  (Linux: sudo apt install libopus0, "
                       "Termux: pkg install libopus; then .venv/bin/pip install "
                       "opuslib==3.0.1, or run Rust/build.sh again)")
    # Voice no longer requires PulseAudio: otrv4plus_audio prefers AAudio,
    # which talks to Android's audio framework directly. parec/pacat remain
    # a selectable fallback and back the /audiotest self-test, so their
    # absence is reported as a note rather than treated as fatal.
    libopus = os.path.join(TERMUX_PREFIX, "lib", "libopus.so")
    if _host.IS_TERMUX and not os.path.exists(libopus):
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

XMPP_VERSION = "10.31.0"



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
        os.makedirs(_host.XMPP_STATE_DIR, mode=0o700, exist_ok=True)
        for src, dst in ((legacy_seed, target_seed),
                         (legacy_secrets, target_secrets)):
            with open(src, "rb") as fh:
                blob = fh.read()
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, blob)
            finally:
                os.close(fd)
        print(_SMP + " migrated stored passphrases into %s" % _host.XMPP_STATE_DIR)
    except FileExistsError:
        pass
    except OSError as exc:
        print(_SMP + " could not migrate stored passphrases (%s); "
              "re-enter them with /smp-secret" % exc.__class__.__name__)


def _identity_path_for(account):
    """F2: the sealed identity record of ONE account (SPEC §3.1).

    One identity per account, so two accounts used on this machine never
    present the same long-term key -- which every DAKE1 carries, readable by
    the server -- and cannot be linked by it. The file is named by a
    domain-separated hash, never by the JID itself.

    The record from before per-account identities (identity.sealed) is kept
    by the first account to sign in afterwards, so its contacts see no key
    change; any other account starts with a new identity.
    """
    from otrv4plus_identity import account_tag
    bare = str(account or "").split("/", 1)[0].strip().lower()
    path = _xmpp_state_path("identity.%s.sealed" % account_tag(bare))
    legacy = _xmpp_state_path("identity.sealed")
    if not os.path.exists(path) and os.path.exists(legacy):
        for suffix in ("", ".mldsa"):
            if os.path.exists(legacy + suffix):
                os.replace(legacy + suffix, path + suffix)
        print("[identity] the identity kept from before is now %s's" % bare)
    return path


def _xmpp_otr_config(account=""):
    """OTRConfig for XMPP: persistent identity, persistent trust, own paths.

    The trust pins are sealed under their own key file in `trust/` (P1); the
    plaintext `trust.json` of earlier versions is moved in on the first start.

    This is the only place the two protocols diverge in configuration, and the
    divergence is deliberate. See _host.XMPP_STATE_DIR above. The identity is
    [account]'s own (F2, `_identity_path_for`).
    """
    _migrate_legacy_smp_secrets()
    return OTRConfig(
        test_mode=True,
        persist_identity=True,
        persist_trust=True,
        trust_db_path=_xmpp_state_path("trust.json"),
        trust_dek_path=_xmpp_state_path(os.path.join("trust", "trust.dek")),
        smp_secrets_path=_xmpp_state_path("smp_secrets.json"),
        identity_path=_identity_path_for(account),
        identity_dek_path=_xmpp_state_path(".identity_dek"),
    )


OTR_MODULE = "otrv4plus"  # symlink -> otrv4+.py


class DependencyUnavailable(ImportError):
    """A dependency this module cannot work without could not be loaded.

    An ImportError subclass on purpose. This file is two things at once: a
    program you run, and a module that the test suite, the Android bridge and
    the tooling import. Those two want opposite things from a missing
    dependency.

    The program wants what it has always had -- the advice on stderr and exit
    status 1 -- and `_fatal_dependency` below still gives it exactly that.

    An importer wants an exception. It used to get `sys.exit(1)`, which raises
    SystemExit, and SystemExit is not an Exception: it inherits from
    BaseException so that `except Exception` around a shutdown does not swallow
    it. Nothing that catches import failures catches it, so importing this
    module without the Rust core did not fail -- it terminated the interpreter
    that imported it. Under pytest that meant an INTERNALERROR during
    collection rather than a skip, and the rest of the suite did not run at
    all; `pytest.importorskip` could do nothing about it.

    The requirement itself is untouched. Without the engine this module still
    does not work, and it still says so at import. It now says so by raising,
    which is how Python says it.

    This class is the *broken* case: the dependency is installed and failed to
    load anyway. See DependencyMissing for the merely-absent one.
    """

    def __init__(self, message, advice=(), name=None):
        super().__init__(message)
        #: The lines `_fatal_dependency` would have printed, kept so a caller
        #: that wants to show them (a GUI, the Android diagnostics) can,
        #: without this module deciding that stderr is where they go.
        self.advice = tuple(advice)
        # ImportError.name, so anything that reads it -- android_bridge's
        # failure classifier does -- gets the module that was actually missing
        # rather than a bare "unnamed module".
        self.name = name


class DependencyMissing(DependencyUnavailable, ModuleNotFoundError):
    """The dependency is simply not installed.

    Separate from DependencyUnavailable because the two deserve opposite
    treatment, and because collapsing them is how a real defect gets skipped.

    A host without the Rust core built is an ordinary, expected state -- a
    fresh clone, a CI runner that only lints, a laptop. Tests that need the
    core should skip there, and `pytest.importorskip` skips on
    ModuleNotFoundError on every version, so this is the class that produces
    that skip with no argument passed at the call site and no suite-wide
    configuration.

    A core that is installed but raises -- an ABI mismatch, a half-built .so,
    an interpreter older than 3.12 meeting otrv4+.py's PEP 701 f-strings -- is
    not that. It is a defect, and it should not be mistaken for absence. Those
    keep the plain-ImportError base.

    How far that carries depends on the pytest in front of it, and the
    difference is worth knowing rather than assuming. Since 9.1 importorskip
    skips on ModuleNotFoundError alone, so a broken core reaches the test run
    as an error. Older versions skip on any ImportError, and there the
    distinction does not survive the call: a broken core makes every module
    that needs it skip, and the suite reports a large skip count and no
    failures. No exception class chosen here changes that, which is why
    tests/test_import_does_not_exit.py carries a check that imports the engine
    directly and fails on a broken one, rather than relying on this split to
    do it.
    """


def _fatal_dependency(message, advice=(), name=None, cause=None):
    """Report a missing dependency the way the caller needs it reported.

    Run as a program: print and exit 1, byte for byte what it did before.
    Imported as a module: raise, so the importer can decide.

    `__name__` is the boundary, and in a single-file program it is the only
    honest one -- everything below here, `main()` included, is unreachable once
    the engine import has failed, so the choice has to be made at the failure.
    """
    # Absent, or present and broken? See DependencyMissing. An ImportError from
    # the dependency means the import system could not produce it; anything
    # else means it was found and went wrong on its own terms.
    cls = DependencyMissing if isinstance(cause, ImportError) \
        else DependencyUnavailable
    exc = cls(message, advice=advice, name=name)
    if __name__ == "__main__":
        # builtins.print, never the module-scope `print` defined further down.
        # That one routes through the TUI and the session log, neither of which
        # exists yet -- and one of the two callers below sits after its
        # definition, so a bare `print` here would mean two different functions
        # depending on which dependency went missing.
        builtins.print(message, file=sys.stderr)
        for line in advice:
            builtins.print(line, file=sys.stderr)
        raise SystemExit(1)
    raise exc from cause


# Module name -> the pip distribution that supplies it.  These differ often
# enough to send people the wrong way: `socks` comes from PySocks, and the
# PyPI project literally named `socks` is an empty placeholder that installs
# nothing, so "pip install socks" succeeds and changes nothing.
_PIP_NAME_FOR_MODULE = {
    "socks": "PySocks",
    "argon2": "argon2-cffi",
    "opuslib": "opuslib",
    "Crypto": "pycryptodome",
    "cryptography": "cryptography",
}


def _import_failure_advice(exc):
    """What to tell the user about a failed engine import.

    The old text always blamed file placement -- "ensure otrv4+.py, the
    symlink and otrv4_core.so are in this directory" -- no matter what
    actually went wrong.  For a missing third-party module that is simply
    false, and it sent at least one tester chasing files that were all
    present and correct.  Split the two cases.
    """
    missing = getattr(exc, "name", None) if isinstance(exc, ImportError) else None

    # A missing dependency of the engine, not the engine itself.
    if missing and missing not in (OTR_MODULE, "otrv4_core"):
        top = missing.split(".")[0]
        pkg = _PIP_NAME_FOR_MODULE.get(top, top)
        lines = [
            f"'{OTR_MODULE}' is present but one of its dependencies is not: "
            f"the module '{missing}' is missing.",
            f"    pip install {pkg}",
        ]
        if pkg.lower() != top.lower():
            lines.append(
                f"(The module is '{top}'; the distribution that provides it "
                f"is '{pkg}'. They are not the same name, and installing a "
                f"package called '{top}' will not fix this.)"
            )
        return lines

    if missing == "otrv4_core":
        return [
            "The Rust core is missing from this Python. Build and install it "
            "(this also removes any older copies):",
            "    cd Rust && bash build.sh",
            "then start the client with the project's Python, from the "
            "repository root:",
            "    .venv/bin/python otrv4plus_xmpp.py ...",
        ]

    return [
        "Ensure otrv4+.py and the otrv4plus.py symlink are in this directory, "
        "and that the core was installed with Rust/build.sh.",
    ]


try:
    _otr = __import__(OTR_MODULE)
    EnhancedSessionManager = _otr.EnhancedSessionManager
    OTRConfig = _otr.OTRConfig
    OTRTracer = getattr(_otr, "OTRTracer", None)
except Exception as e:
    _fatal_dependency(
        f"Could not import OTR engine from '{OTR_MODULE}': {e}",
        advice=_import_failure_advice(e),
        # The module that is actually absent, when the engine told us. Falls
        # back to the engine itself: if `otrv4plus` raised an AttributeError
        # rather than an ImportError, the engine is what is broken.
        name=(getattr(e, "name", None) if isinstance(e, ImportError)
              else None) or OTR_MODULE,
        cause=e)


_colorize = getattr(_otr, "colorize", lambda s, c: s)

#: The tag every SMP line carries.  Verification is the one thing in this
#: client a user is asked to *do* rather than watch, and its lines used to look
#: like every other bracketed tag scrolling past -- asked for on the device,
#: where an SMP prompt was easy to lose in the flow.
#:
#: 🔐 is the same glyph the progress bar already uses for SMP, so the whole
#: exchange reads as one thing, and the tag itself is blue because 🔵 is
#: already spoken for: it means *verified*, the end state, and putting it on
#: every SMP line would say "verified" while verification is still running.
#: The emoji keeps its own colour whatever the terminal does -- ANSI cannot
#: recolour a glyph the font draws -- so the blue is on the text of the tag.
_SMP = "\U0001f510 " + _colorize("[smp]", "blue")

#: The prefix on an incoming chat line, and it is a security claim, so the two
#: states have to look different at a glance.
#:
#: \U0001f510 CLOSED LOCK WITH KEY, blue  -- encrypted AND SMP-verified
#: \U0001f512 CLOSED LOCK, yellow         -- encrypted, identity NOT verified
#:
#: Both are accurate: an unverified session really is encrypted, so a padlock
#: is not a lie there -- what it must not do is look like the verified one.
#: The glyph differs (key or no key) and the colour differs, because either
#: signal alone is weak: emoji are small on a handset and colour is invisible
#: to some readers.
#:
#: The colours are the project's own, from UIConstants.SECURITY_ICONS and the
#: level->colour tables in otrv4+.py: \U0001f7e1 yellow is ENCRYPTED and
#: \U0001f535 blue is SMP_VERIFIED.  This prefix used to be GREEN for
#: SMP-verified, which contradicted that table -- green there is
#: FINGERPRINT, i.e. pinned but NOT SMP-verified.  A user reading the tab
#: bar and the message prefix was being told two different things by the
#: same colour.
#:
#: Both glyphs are already in `_LOG_MARKERS`, so `_strip_log_markers` removes
#: them before `_LOG_CONTENT_RE` runs and a prefixed line is still redacted to
#: `<message body redacted: N chars>` (INV-03).  Adding a prefix that was NOT
#: in that tuple would have quietly disabled message-body redaction.
_OTR_VERIFIED = "\U0001f510 " + _colorize("[otr]", "blue")
_OTR_ENCRYPTED = "\U0001f512 " + _colorize("[otr]", "bold_yellow")


def _otr_prefix(smp_verified: bool) -> str:
    """The chat-line prefix for a peer whose SMP state is `smp_verified`."""
    return _OTR_VERIFIED if smp_verified else _OTR_ENCRYPTED

import otrv4plus_term as _term  # noqa: E402
from otrv4plus_term import (  # noqa: E402,F401  (re-exported for the tests)
    print, _raw_write, _sanitise, _colour_tag, _log_to_file, _log_line_for_file,
    _strip_log_markers, _terminal_cols, _ANSI_RE, _LOG_CONTENT_RE,
    _LOG_SAFE_TAGS, _LOG_MARKERS, _TAG_COLOURS)

_term._colorize = _colorize
_tunnels.bind_engine(_otr)
_termux.bind_engine(_otr)
# The inline TUI reuses the engine's own (PanelManager, Screen, the raw line
# editor), the same one the IRC client uses.
_tui.bind_engine(_otr, _colorize)




try:
    from slixmpp import ClientXMPP
    from slixmpp.exceptions import IqError, IqTimeout
except ImportError as _e:
    # Same reasoning as the engine import above: fatal to the program, an
    # ImportError to anything that imports this file.
    _fatal_dependency(
        "slixmpp not installed.  Run:  pip install slixmpp aiodns",
        name=getattr(_e, "name", None) or "slixmpp",
        cause=_e)

try:
    import otrv4plus_admin as _admin
    from otrv4plus_log import ChannelLogManager as _ChannelLogManager
    _LOG_AVAILABLE = True
except ImportError:
    _ChannelLogManager = None
    _LOG_AVAILABLE = False


# One definition, shared with android_bridge. Re-exported under the names this
# module and its tests have always used, so nothing here changes shape -- but
# the two clients can no longer drift apart on what counts as protocol
# traffic, which is precisely how the Android side ended up with no notion of
# it at all.
OTR_PREFIX = _frag.OTR_PREFIX
OTR_PREFIX_B = OTR_PREFIX.encode("utf-8")
#: Secure-group setup signals (android_bridge.groups.SIGNAL_PREFIX). Restated
#: so this module still imports without the android_bridge package;
#: tests/test_termux_groups.py holds the two equal.
GROUP_SIGNAL_PREFIX = "?OTRv4-MLS:"

# SMP passphrase length bounds enforced before passing to the Rust engine.
# Defined in the engine (otrv4+.py) since v10.23.0 so both clients agree;
# re-exported here because this module's own code and its tests refer to
# them by these names. getattr with the old literals as the fallback keeps
# this working against an engine that predates the move.
SMP_MIN_LEN = getattr(_otr, "SMP_MIN_LEN", 8)
SMP_MAX_LEN = getattr(_otr, "SMP_MAX_LEN", 512)
_trust.bind_engine(_otr, _SMP, SMP_MIN_LEN, SMP_MAX_LEN)

# Rate limiting: max inbound messages per peer per window.
_RATE_MAX = 20
_RATE_WINDOW = 5.0  # seconds

#: The budget while an ACCEPTED transfer with that peer is in flight.
#:
#: The chat limit is 4 messages a second.  One 16 KB file chunk becomes five
#: 6 KB fragments, so a 340 KB file is about a hundred stanzas -- at the chat
#: rate the receiver drops four fifths of them, and because the chunk AEAD is
#: a sequence, the first gap ends the transfer.  That is precisely what a
#: device test produced: a screen of `[rate-limit] dropping message` followed
#: by `chunk 10 arrived out of order`.
#:
#: A rate limiter exists to stop an UNSOLICITED flood.  A transfer the user
#: accepted, from a peer the engine says is SMP-verified, is the opposite, so
#: it gets a budget that fits it.  Bounded, not lifted: an accepted transfer
#: is not a licence to send anything at any rate, and the moment it ends the
#: peer is back to the chat limit.
_RATE_MAX_BULK = 120







# =============================================================================
# Voice call: encrypted Opus over a single bidirectional I2P SAM stream
# =============================================================================
#
# The voice subsystem lives in otrv4plus_voice.py (protocol v3: hybrid
# X448 + ML-KEM-1024 media keys, call-ID-bound signalling, two-phase rekey,
# authenticated media headers).  It is a separate module so that the key
# agreement, the rekey state machine and the replay window can be tested
# without importing slixmpp, opuslib or PulseAudio — see
# tests/test_voice_security.py.  Read the module docstring there for the wire
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
    is_termux=_host.IS_TERMUX,
)

# v10.14.0: /sendfile.  XMPP only -- the IRC client has no file transfer and
# does not import this module.
import otrv4plus_filetransfer as _filetransfer
import otrv4plus_trade as _trade
import otrv4plus_tip as _tip

TipManager = _tip.TipManager

TRADE_PREFIX = _trade.TRADE_PREFIX
TradeManager = _trade.TradeManager

FILE_PREFIX = _filetransfer.FILE_PREFIX
FileTransferManager = _filetransfer.FileTransferManager

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


# =============================================================================
# XMPP client
# =============================================================================

def _make_groups(host):
    """The secure-groups adapter, or None if it cannot be loaded here."""
    try:
        import otrv4plus_groups as _og
    except Exception:
        return None
    return _og.TermuxGroups(host, _xmpp_state_path("groups"), printer=print)


class OTRv4PlusXMPP(_TermSyncMixin, _ConnectionMixin, _PresenceMixin,
                    _TrustMixin, _FilesMixin, _TradeMixin, _AdminMixin,
                    _TuiMixin, ClientXMPP):
    """XMPP transport driving the OTRv4+ engine, with IRC-identical SMP flow."""

    def __init__(self, jid, password, peer=None, debug=False):
        """The client's state, the OTR engine, then the XMPP side: in that
        order, since handlers and plugins may refer to both."""
        super().__init__(jid, password)
        self.peer = peer
        self._init_state(jid)
        self._init_engine(debug)
        self._init_xmpp()

        # Ephemeral encrypted per-session log: key zeroed and files deleted on exit,
        # matching the IRC client wipe behaviour. Within-session scrollback is backed
        # by the encrypted file so panels load their full history on tab open.
        self.channel_log = _ChannelLogManager() if _LOG_AVAILABLE else None
        self._cleaned_up = False
        # Register globally so print() can route to channel_log even when
        # the TUI is never started (plain mode is now the default).
        _term._ACTIVE_CLIENT = self

    def _init_state(self, jid):
        """Every per-session field, before anything can call back into us."""
        # Per-peer UI state.
        # Locally-armed one-shot secret prompt: the JID a /smp-secret
        # command is collecting for, or None.  Only _request_smp_secret
        # sets it and only take_secret_request clears it.
        self._secret_request = None
        # What the secret prompt is FOR: "store" (just save it) or "start"
        # (save it, then begin SMP) or "resume" (save it, then answer the
        # SMP1 the peer already sent).  Set beside _secret_request, cleared
        # with it.
        self._secret_purpose = None
        #: The .b32.i2p the SAM bridge was pointed at, when it was given in
        #: full. Recorded as an alias once a connection succeeds.
        self._i2p_server_dest = None
        # The guided verification flow, one per peer.  This is what makes a
        # remote SMP1 unable to arm secret capture: it can move a peer to
        # AWAITING_LOCAL_CONSENT and no further.  See otrv4plus_smpflow.py.
        self._smp_flows = _smpflow.SmpFlowRegistry()
        # peer -> previously pinned fingerprint, while a mismatch is
        # unresolved. Presence in this map refuses voice for that peer.
        self._fingerprint_changed = {}
        self._encrypted = set()    # peers whose DAKE has completed
        # THE OUTBOX: lines typed before a conversation was ready, sent when
        # it is (encrypted), or in the clear only to a contact seen online
        # without OTRv4+. The engine's own queue dropped its lines when the
        # handshake completed, so "[queued] will send" never sent.
        self._outbox = {}
        # Contacts whose presence advertises OTRv4Plus (XEP-0115 node).
        self._otr_capable = set()
        # Handshake timing, for the ETA: start times and past durations.
        self._hs_started = {}
        self._hs_hist = []
        # Which conversations have had OTR asked for -- by us with /otr,
        # or by the peer sending a protocol frame. NOT a security state:
        # it says whether OTR is wanted here, not whether it is working.
        self._otr_mode = _OtrMode()
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
        # peer -> (window start, dropped since we last said so)
        self._rate_drop_report = {}
        # Stanzas sent by the last send_otr_fragmented call; the file
        # pump zeroes it before each chunk and paces on the result.
        self._file_fragments_sent = 0

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
        # bare JID -> set of resources currently available. A peer is gone
        # only when the LAST one leaves (see _on_presence_unavailable).
        self._peer_resources = {}
        self._peer_gone_task = None

        # Voice call manager (initialized lazily after event loop is available)
        self._voice_manager = None
        self._file_manager = None
        self._trade_manager = None
        self._trade_disclaimed = False
        self._tip_manager = None
        self._tip_disclaimed = False
        self._voice_sam_host = "127.0.0.1"
        self._voice_sam_port = 7656
        self._voice_debug = False
        #: XEP-0133 admin form state. All four are cleared together by
        #: _admin_reset; a half-open form would leave _admin_awaiting set and
        #: swallow the next line typed, which INV-06 forbids.
        self._admin_form = None        # otrv4plus_admin.AdminForm, or None
        self._admin_node = None        # the command node being executed
        self._admin_session = None     # the server's session id
        self._admin_awaiting = False   # one-shot: next line is a field value
        self._admin_warned = False     # the not-end-to-end notice, once
        #: (print-count, text) of the line the terminal echoed in plain mode,
        #: so our own attributed echo can replace it rather than repeat it.
        self._plain_echo = None

    def _init_engine(self, debug):
        """The OTR session manager and the one thread its crypto runs on."""
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
        cfg = _xmpp_otr_config(str(self.boundjid.bare))
        try:
            self.otr = EnhancedSessionManager(config=cfg, tracer=tracer)
        except Exception as exc:
            # Fail closed. Persistent identity is what makes TOFU mean
            # anything; starting anyway with a fresh identity would change our
            # fingerprint silently and every peer holding a pin would see it
            # as the identity change TOFU exists to report.
            print("[identity] XMPP could not start: %s" % exc)
            raise
        # Turn the guided responder flow ON for this front end.
        #
        # This switch is why the responder path did nothing on a real pair of
        # phones: the engine only parks an incoming SMP1 when the front end
        # has said it can ask the user for a passphrase, and nothing ever set
        # it.  Alice therefore aborted with NOSECRET exactly as she did before
        # the feature existed.  The unit tests missed it because they drove
        # _check_smp_secret_required directly instead of letting a real SMP1
        # reach a real session; tests/test_smp_guided_flow.py now does the
        # latter.
        #
        # IRC leaves it False deliberately: a front end that cannot prompt
        # must not leave the peer waiting for an answer that never comes.
        self.otr.smp_guided_prompt = True
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

    def _init_xmpp(self):
        """Subscription policy, event handlers, XEP plugins, secure groups."""
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
        # XEP-0004 data forms and XEP-0050 ad-hoc commands: the two
        # the XEP-0133 admin surface is built from. Registered
        # unconditionally because they are pure protocol handlers --
        # they cost nothing until /admin is typed, and a lazy
        # registration would have to happen on the event loop.
        self.register_plugin("xep_0004")
        self.register_plugin("xep_0050")
        # NOT xep_0133. Its plugin is thirty-two thin wrappers that each start
        # an ad-hoc session, and this client drives xep_0050 directly so it
        # can render the form itself. Registering it would be config that
        # nothing reads.
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
        # XEP-0045 rooms, for OTRv4Plus secure groups (MLS) only. The room is
        # transport: every body a secure group puts in it is MLS ciphertext.
        self.register_plugin("xep_0045")
        self.add_event_handler("groupchat_message", self._on_groupchat)
        # Secure groups: the Android app's SecureGroups over the Rust core's
        # OpenMLS, driven from this terminal (otrv4plus_groups). None when
        # the android_bridge package is not beside this file.
        self._groups = _make_groups(self)
        #: A pending "remove hidden information?" question (confirm_metadata).
        self._metadata_question = None
        #: /wipe sets this: the exit then destroys group state too.
        self._wipe_on_exit = False

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _on_start(self, event):
        # U1: authenticated. The device's fingerprint may be shown from now
        # on (/identity); before this it is withheld.
        self._signed_in = True
        # Signed in: the I2P destination that answered becomes the pin (X1).
        confirm = getattr(self, "_confirm_server", None)
        if confirm is not None:
            try:
                confirm()
            except Exception:
                print("[i2p] could not record the server's address")
        # Advertise OTRv4Plus (XEP-0030 feature, XEP-0115 caps) BEFORE the
        # first presence, so an OTRv4Plus peer -- the Android app -- can
        # confirm this resource speaks the protocol before it sends a DAKE.
        # See otrv4plus_caps; the identifier must match on both clients.
        try:
            import otrv4plus_caps as _caps
            self.plugin["xep_0030"].add_feature(_caps.FEATURE)
            self.plugin["xep_0115"].caps_node = _caps.CAPS_NODE
            await self.plugin["xep_0115"].update_caps(broadcast=False)
        except Exception:
            print("[xmpp] could not advertise OTRv4Plus capability; peers "
                  "will not start OTRv4+ automatically")
        self.send_presence()
        # Initialize voice call manager now that we have an event loop
        if self._voice_manager is None:
            self._voice_manager = VoiceCallManager(
                self, asyncio.get_event_loop(),
                self._voice_sam_host, self._voice_sam_port)
            self._voice_manager.debug = self._voice_debug
            if self._voice_debug:
                print("[voice] diagnostics enabled (--voice-debug)")
        if self._file_manager is None:
            # The pump is the OTR channel.  It is passed in rather than
            # reached for, so the same engine can later be handed a SAM
            # stream without the engine changing.
            # Phase A: control AND bulk both ride the OTR channel.  A future
            # transport keeps send_control here and replaces send_chunk only.
            self._file_manager = FileTransferManager(
                transport=_filetransfer.OtrChunkTransport(
                    self._send_file_signal),
                notify=print,
                verified=self._file_peer_verified,
                spawn=self._start_file_pump,
                on_state=self._on_file_state,
                quick_answer=True,
            )
        if self._trade_manager is None:
            # Same three dependencies the transfer engine takes, plus the
            # fingerprint accessor. The courier holds no keys and speaks to
            # no wallet, so there is nothing else to give it.
            self._trade_manager = TradeManager(
                send=self._send_trade_signal,
                notify=print,
                verified=self._file_peer_verified,
                fingerprint=self._peer_fingerprint,
            )
        if self._tip_manager is None:
            self._tip_manager = TipManager(
                send=self._send_tip_tlv,
                notify=print,
                verified=self._file_peer_verified,
                store_path=_xmpp_state_path("xmr.json"),
            )
            # The engine routes DISCONNECTED, SMP and EXTRA_SYMMETRIC_KEY
            # itself; TIP is a feature, so it registers here and the session
            # state machine stays out of it.
            _otr.register_tlv_handler(_tip.TIP_TLV_TYPE,
                                      self._tip_manager.handle_tlv)
        try:
            await self.get_roster()
        except (IqError, IqTimeout):
            pass
        print(f"\n[connected] {self.boundjid.full}")
        print(f"[version]   Off The Record v4 Plus (OTRv4+) XMPP {XMPP_VERSION}")
        self._remember_server_alias()
        # Carbons, the archive, blocking, replies and reactions
        # (otrv4plus_termsync): installed once, then synced in the background.
        try:
            self._ts_install()
            asyncio.ensure_future(self._ts_after_session())
        except Exception:
            pass
        if self.peer:
            self.send_presence_subscription(pto=self.peer)
            print(f"[subscribe] requested presence from {self.peer}")
        print(
            "[ready] /otr to start encryption. After DAKE the peer's "
            "fingerprint is pinned automatically\n"
            "[ready] (first contact) or checked against the pin, then you set "
            "the SMP passphrase.\n"
            "[ready] /identity shows what is pinned. Type /help for the full "
            "command list.\n"
        )
        # Secure groups: open (or reopen after a restart) and rejoin the room
        # of every group we hold, so its traffic reaches us again.
        groups = getattr(self, "_groups", None)
        if groups is not None and not getattr(groups, "_opened", False):
            groups.open(self.boundjid.bare)
        if groups is not None and getattr(groups, "_opened", False):
            try:
                await groups.rejoin_all()
            except Exception as exc:
                print("[group] rejoin failed (%s)" % type(exc).__name__)
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
        print("\n" + _SMP + " *** IDENTITY VERIFIED with %s - shared secret "
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

    def _forget_otr(self, peer: str, why: str) -> None:
        """Drop every trace of an OTR session so /otr can start a fresh one.

        The same reset start_otr performs on a stuck session, done up front
        instead of after a failure. Nothing here weakens anything: it destroys
        ratchet state, and the peer's next session has to complete a full DAKE
        and be SMP-verified again exactly as the first one did. The pinned
        fingerprint is NOT touched -- that is long-term identity, and forgetting
        it would turn a reconnect into a fresh trust-on-first-use decision.
        """
        if peer not in self._encrypted:
            return
        try:
            self.otr.end_session(peer)
        except Exception as exc:
            print("[otr] could not end session with %s: %s"
                  % (_sanitise(peer, 128), _sanitise(str(exc), 80)))
        self._encrypted.discard(peer)
        self._last_dake1.pop(peer, None)
        if self._secret_request == peer:
            self._secret_request = None
            self._secret_purpose = None
            self._mask_next_input(False)
            print(_SMP + " the passphrase prompt for that peer is closed; "
                  "nothing was stored.")
        # A verification request cannot outlive the session it belongs to: the
        # held SMP1 is gone with the ratchet, so a consent prompt still on the
        # screen would ask about something that no longer exists.
        if getattr(self, "_smp_consent_shown", None) == peer:
            self._smp_consent_shown = None
            print(_SMP + " the verification request from that peer is closed; "
                  "nothing was stored.")
        self._smp_flows.drop(peer)
        self._smp_reported = {k for k in self._smp_reported if k[0] != peer}
        print("[otr] cleared the session with %s (%s) — /otr to start a new "
              "one when they return" % (_sanitise(peer, 128),
                                        _sanitise(why, 64)))

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------

    def _rate_budget(self, peer: str) -> int:
        """How many messages this peer may send in the window, right now.

        The chat budget, unless an accepted transfer with them is running --
        see `_RATE_MAX_BULK`.  Kept for chat that runs ALONGSIDE a transfer;
        the transfer's own chunks do not come through here at all, they are
        absorbed by the allowance in `_check_rate_limit`.
        """
        mgr = self._file_manager
        if mgr is None:
            return _RATE_MAX
        try:
            if mgr.transfer_in_flight(peer):
                return _RATE_MAX_BULK
        except Exception:
            pass
        return _RATE_MAX

    def _check_rate_limit(self, peer: str) -> bool:
        """Return True if the message should be processed; False if throttled.

        An accepted transfer's traffic is taken out of the limiter's hands
        entirely rather than given a bigger allocation. Raising the budget was
        the first attempt and it only moved the cliff: a device test walked
        off the new one at chunk 33 of 119, lost the file, and then lost the
        connection when the sender kept pushing into a throttled peer. What
        bounds an accepted transfer is a quantity the user agreed to, not a
        rate -- see `absorb_transfer_message`.
        """
        mgr = self._file_manager
        if mgr is not None:
            try:
                if mgr.absorb_transfer_message(peer):
                    return True
            except Exception:
                pass
        now = time.monotonic()
        if peer not in self._rate_limit:
            self._rate_limit[peer] = collections.deque()
        dq = self._rate_limit[peer]
        while dq and dq[0] < now - _RATE_WINDOW:
            dq.popleft()
        if len(dq) >= self._rate_budget(peer):
            return False
        dq.append(now)
        return True

    def _note_rate_drop(self, peer: str) -> None:
        """Report throttling at most once per window, with a count.

        Printing per dropped message turned a throttled peer into hundreds of
        identical lines that buried the one line saying what had actually gone
        wrong. The count is the useful part; the repetition never was.
        """
        now = time.monotonic()
        first, dropped = self._rate_drop_report.get(peer, (0.0, 0))
        dropped += 1
        if now - first >= _RATE_WINDOW:
            if dropped > 1:
                print("[rate-limit] dropped %d messages from %s in the last "
                      "%.0fs" % (dropped, _sanitise(peer, 128), _RATE_WINDOW))
            else:
                print("[rate-limit] dropping message from %s"
                      % _sanitise(peer, 128))
            self._rate_drop_report[peer] = (now, 0)
        else:
            self._rate_drop_report[peer] = (first or now, dropped)

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
            self._note_rate_drop(peer)
            return

        # Inbound fragment reassembly.
        if body.startswith("?OTRv4F|"):
            full = self._reassemble_fragment(peer, body)
            if full is None:
                return
            body = full

        if body.startswith(OTR_PREFIX):
            # The peer has asked for OTR, so nothing more goes to them in the
            # clear -- including while this handshake is still in flight.
            # Marked here rather than on completion: the gap between their
            # DAKE1 and an established session is exactly where a downgrade
            # would fit.
            _m = getattr(self, "_otr_mode", None)
            if _m is not None:
                _m.request(peer)
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
        elif body.startswith(FILE_PREFIX):
            # Same rule as call control: a file offer is only meaningful
            # inside the OTR channel.  In the clear it is either an outdated
            # client or someone injecting an offer at the server, and acting
            # on it would let an off-session party start a transfer.
            print("[file] ignoring UNENCRYPTED file signal from %s — file "
                  "transfer is only accepted inside an OTR session"
                  % _sanitise(peer, 128))
        elif body.startswith(GROUP_SIGNAL_PREFIX):
            # Group setup is only accepted inside the OTR channel: in the clear
            # it could let an off-session party steer a group join.
            print("[group] ignoring UNENCRYPTED group setup message from %s — "
                  "it is only accepted inside an OTR session"
                  % _sanitise(peer, 128))
        else:
            item = _live_item(self, msg) if hasattr(self, "_ts_reply_prefix") else None
            reply = self._ts_reply_prefix(peer, item.reply) if item is not None else ""
            if item is not None and item.action == "edit":
                self._ts_show_action(peer, "edit", item.target, body, [])
                return
            if item is not None:
                self._ts_remember(peer, item.ref, body, False)
            body = reply + body
            print(f"[plain] {_sanitise(peer, 128)}: {_sanitise(body)}")

    def _on_groupchat(self, msg):
        """A room message. Only secure groups use rooms here; see
        otrv4plus_groups.TermuxGroups.on_groupchat."""
        groups = getattr(self, "_groups", None)
        if groups is None:
            return
        try:
            groups.on_groupchat(msg)
        except Exception as exc:
            self._dbg("[group] room message handling failed: %s"
                      % type(exc).__name__)

    def _check_smp_secret_required(self, peer):
        """Show the consent prompt if the engine is holding a peer's SMP1.

        Idempotent: a peer resending SMP1 while the prompt is open cannot make
        a second prompt appear, because the flow is already in
        AWAITING_LOCAL_CONSENT and both this and the flow refuse to re-arm.
        """
        try:
            if not self.otr.smp_secret_required(peer):
                return
        except Exception as e:
            self._dbg(_SMP + f" secret-required check failed: {e}")
            return
        self._announce_secret_required(peer)

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
        # Decided by the ENGINE (`EnhancedSessionManager._handle_dake1`), by
        # comparing the two DAKE1s, so both clients apply one rule and exactly
        # one side yields. This used to be a bare-JID rule applied here; the
        # Android bridge cannot use it (it does not know its own JID), and a
        # terminal keeping by JID while an Android peer kept by DAKE1 would
        # have both resending forever. The engine's answer -- our DAKE1 to
        # resend, or a DAKE2 -- goes out through the ordinary path below.

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
            # Decrypted together with its MESSAGE_META (otrv4plus_termsync).
            decrypt = getattr(self, "_ts_decrypt", None)
            if decrypt is not None:
                out, meta = await loop.run_in_executor(
                    self._otr_executor, decrypt, peer, body)
            else:
                out = await loop.run_in_executor(
                    self._otr_executor, self.otr.handle_incoming_message, peer, body)
                meta = None
        except Exception as e:
            print(f"[otr error] from {peer}: {e}")
            self._send_final_revelations()
            return
        # L1: a session this frame ended (the peer's DISCONNECTED, an error)
        # publishes the MAC keys it retired.
        self._send_final_revelations()

        if heavy:
            import time as _t
            self._dbg(f"[otr-crypto] done processing DATA from {peer} ({_t.time() - t0:.1f}s).")

        self._report_pq_refusal(peer)
        self._check_dake_complete(peer)
        self._recover_if_orphaned(peer)

        # Did the engine park an SMP1 because we have no passphrase for this
        # peer?  Asked here, on the event loop, after the executor has
        # finished: the OTR worker never waits for a human.
        self._check_smp_secret_required(peer)
        self._expire_stale_smp_consent()
        self._show_smp_progress(peer)

        # A correction, deletion or reaction, authenticated inside the frame.
        if meta is not None and meta.get("action"):
            text = (out.decode("utf-8", errors="replace")
                    if isinstance(out, (bytes, bytearray)) else (out or ""))
            self._ts_show_action(peer, meta["action"], meta["target"], text,
                                 meta.get("emojis") or [])
            self._report_smp(peer)
            self._check_dake_complete(peer)
            return

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

                # File transfer travels inside the OTR channel too, and is
                # routed before anything renders it as chat -- otherwise an
                # offer appears as a wall of base64 in the peer's window.
                if text.startswith(FILE_PREFIX):
                    if self._file_manager is not None:
                        self._file_manager.handle_control(peer, text)
                    else:
                        print("[file] file signal received before the "
                              "transfer subsystem was ready — ignoring")
                    return

                # Secure-group setup (invitation, KeyPackage, Welcome) travels
                # only inside an OTRv4+ session and is never shown as chat.
                if text.startswith(GROUP_SIGNAL_PREFIX):
                    groups = getattr(self, "_groups", None)
                    if groups is not None:
                        groups.on_signal(peer, text)
                    else:
                        print("[group] group setup message received, but "
                              "secure groups are unavailable here — ignoring")
                    return

                # Trade coordination, routed for the same reason: a multisig
                # blob rendered as chat is a screenful of base64 nobody can
                # use, and it would land in the panel history as chat rather
                # than as something the trade layer can account for.
                if text.startswith(TRADE_PREFIX):
                    if self._trade_manager is not None:
                        self._trade_manager.handle_control(peer, text)
                    else:
                        print("[trade] trade signal received before the "
                              "trade subsystem was ready — ignoring")
                    return

                smp_ok = (peer, "SUCCEEDED") in self._smp_reported
                peer_s = _sanitise(peer, 128)
                if meta is not None and hasattr(self, "_ts_reply_prefix"):
                    reply = self._ts_reply_prefix(peer, meta.get("reply", ""))
                    self._ts_remember(peer, meta.get("id", ""), text, False)
                else:
                    reply = ""
                text_s = reply + _sanitise(text)
                # The prefix carries the security state; see `_otr_prefix`.
                # The message body is _sanitise'd either way -- a peer's text
                # is never printed raw, verified or not.
                print(
                    _otr_prefix(smp_ok)
                    + " "
                    + _colorize(peer_s + ":", "yellow")
                    + " "
                    + (_colorize(text_s, "dark_blue") if smp_ok else text_s)
                )
                self._alerts().message()

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

    def _no_session_hint(self, peer: str) -> str:
        """Extra words for "no encrypted session with X", when we have one
        with someone else.

        "Run /otr first" is sound advice unless the reason there is no
        session with X is that X is not the address the peer is actually on --
        in which case /otr will fail forever and the advice sends the user
        round the same loop. A device run hit exactly that: `--peer
        bob@otrv4plus` (missing `.i2p`) while a fully established, SMP-ready
        session sat under `bob@otrv4plus.i2p`.
        """
        try:
            live = sorted(p for p in self._encrypted if p != peer)
        except Exception:
            return ""
        if not live:
            return ""
        hint = ("\n[peer] But there IS an encrypted session with: %s"
                % ", ".join(_sanitise(p, 128) for p in live))
        wanted = peer.partition("@")[2].lower()
        for other in live:
            got = other.partition("@")[2].lower()
            if wanted and got and got.startswith(wanted):
                hint += ("\n[peer] --peer %s looks truncated; the session is "
                         "with %s." % (_sanitise(peer, 128),
                                       _sanitise(other, 128)))
                break
        hint += ("\n[peer] Commands act on --peer, so restart with the "
                 "address that has the session.")
        return hint

    #: At most one recovery handshake per contact in this many seconds.
    ORPHAN_RECOVERY_INTERVAL = 60.0

    def _recover_if_orphaned(self, peer):
        """The peer encrypted to a session we no longer have (one side
        restarted, or a DAKE3 was lost): nothing they send can be read and
        neither side had a reason to start again. Start a new handshake --
        a DAKE1, never plaintext -- as the Android app does. Bounded."""
        take = getattr(getattr(self, "otr", None), "take_orphan_data", None)
        if take is None or not take(peer):
            return
        now = time.monotonic()
        seen = self.__dict__.setdefault("_orphan_at", {})
        if now - seen.get(peer, -1e18) < self.ORPHAN_RECOVERY_INTERVAL:
            return
        seen[peer] = now
        print(f"[otr] {peer} sent an encrypted message for a session this "
              f"client no longer has (one of you restarted); it cannot be "
              f"read. Starting a new encrypted session -- ask them to resend.")
        self._encrypted.discard(peer)
        self.start_otr(peer)

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

        started = getattr(self, "_hs_started", {}).pop(peer, None)
        if started is not None:
            took = max(1.0, time.monotonic() - started)
            self._hs_hist.append(took)
            del self._hs_hist[:-20]
            print(f"[secure] handshake took {int(took)} s")
        self._flush_outbox(peer)
        groups = getattr(self, "_groups", None)
        if groups is not None:
            try:
                groups.on_otr_ready(peer)
            except Exception:
                pass

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

        Returns the number of stanzas sent, and adds it to
        `_file_fragments_sent`. The file pump paces on that: what costs the
        receiver's rate-limit budget is stanzas, not chunks.
        """
        # The format itself lives in otrv4plus_fragment, because the Android
        # transport has to produce exactly these bytes and a second
        # implementation of a wire format is a second implementation to keep
        # in step. What stays here is everything that is this client's own
        # voice: its debug lines and its stanza counter.
        parts, self._frag_seq = _frag.fragment(
            payload, getattr(self, "_frag_seq", 0))
        total = len(parts)

        if total == 1:
            self.send_message(mto=peer, mbody=payload, mtype="chat")
            self._dbg(f"[otr-send] 1 frame ({len(payload)} bytes) -> {peer}")
            # getattr rather than a plain +=, and inline rather than a
            # helper: the fragmentation tests drive this method against a
            # bare stub to check the wire format without building a whole
            # client, so it must not depend on our __init__ or our methods.
            self._file_fragments_sent = \
                getattr(self, "_file_fragments_sent", 0) + 1
            return 1

        # Recovered from the first fragment rather than tracked separately, so
        # there is exactly one place that decides what a msg_id is.
        msg_id = parts[0].split("|", 2)[1]
        self._dbg(
            f"[otr-send] fragmenting {len(payload)} bytes into {total} "
            f"fragments (id {msg_id}) -> {peer}"
        )
        for i, frag in enumerate(parts, 1):
            self.send_message(mto=peer, mbody=frag, mtype="chat")
            self._dbg(f"[otr-send]   sent fragment {i}/{total} (id {msg_id})")
        self._dbg(f"[otr-send] all {total} fragments sent (id {msg_id}) -> {peer}")
        # What the file pump paces on. Counting stanzas rather than assuming
        # a fixed fragments-per-chunk keeps the pacing right for the first
        # and last chunks, which are usually shorter than the rest.
        self._file_fragments_sent = \
            getattr(self, "_file_fragments_sent", 0) + total
        return total

    def send_otr(self, peer, payload):
        """Legacy alias for send_otr_fragmented."""
        self.send_otr_fragmented(peer, payload)

    # -------------------------------------------------------------------------
    # Inbound fragment reassembly
    # -------------------------------------------------------------------------

    def _reassemble_fragment(self, peer, body):
        """Feed one inbound fragment to the buffer. Returns the fully
        reassembled '?OTRv4 ...' string when the last fragment arrives,
        otherwise None.

        The buffering, the bounds and the stitching moved to
        otrv4plus_fragment so the Android transport reassembles with the same
        code rather than a second copy of it. What stays here is this client's
        own output: `_dbg`, and the progress line that is suppressed in probe
        mode and passes the peer through `_sanitise`.

        `_frag_buffers` is still created lazily and still lives on the
        instance, because the fragmentation tests drive this method against a
        bare stub that never ran `__init__`.
        """
        reassembler = getattr(self, "_frag_reassembler", None)
        if reassembler is None:
            def on_progress(peer_, have, total):
                """The "receiving n/total" line, with this client's rules.

                Suppressed in probe mode and for a single-fragment set,
                exactly as before. This is why reassembly takes a callback
                instead of printing for itself: `print` is shadowed at module
                scope here to route through the session log, and `_sanitise`
                is this client's policy on what a peer address may look like
                in output. Neither belongs in a module Android imports.

                A closure over `self` rather than a method, and that is not a
                style choice: the fragmentation tests drive
                `_reassemble_fragment` as an unbound method against a stub
                that never ran `__init__`, so this may only touch what the
                original touched -- `_dbg` and `_probe`. Naming a new method
                here broke seven of them.
                """
                if not self._probe and total > 1:
                    print("[otr] receiving %d/%d fragments from %s"
                          % (have, total, _sanitise(peer_, 48)))

            reassembler = _frag.Reassembler(
                on_debug=self._dbg, on_progress=on_progress)
            self._frag_reassembler = reassembler
            # Kept as an alias rather than a copy: anything that inspected
            # `_frag_buffers` -- a diagnostic, a test -- still sees the live
            # dict, because it IS the live dict.
            self._frag_buffers = reassembler.buffers
        return reassembler.feed(peer, body)

    # -------------------------------------------------------------------------
    # OTR session control
    # -------------------------------------------------------------------------

    def send_plain(self, peer, text):
        self.send_message(mto=peer, mbody=text, mtype="chat")

    # -- the conversation what is typed goes to ----------------------------------

    def expand_jid(self, name):
        """`bob` -> `bob@<our server>`; a full address is kept as it is."""
        name = (name or "").strip()
        if not name or "@" in name or "/" in name or " " in name:
            return name
        try:
            domain = str(self.boundjid.domain or "")
        except Exception:
            domain = ""
        return "%s@%s" % (name.lower(), domain) if domain else name

    def set_conversation(self, target):
        """What is typed (no /command) now goes to `target`: a contact, or a
        secure group's room (MLS, never plaintext)."""
        self.peer = target
        groups = getattr(self, "_groups", None)
        is_group = groups is not None and groups.owns_room(target)
        pm = getattr(self, "panel_manager", None)
        if pm is not None and getattr(self, "_tui_enabled", False):
            try:
                label = self._tui_label_for(target)
                pm.get_or_create_panel(label, "private")
                pm.switch_to_panel(label)
            except Exception:
                pass
        if is_group:
            print("[to] now talking in the secure group %s: just type, it goes "
                  "MLS+ encrypted to the group. /to <name> to switch."
                  % _sanitise(target, 96))
        else:
            print("[to] now talking to %s: just type. /to <name> to switch."
                  % _sanitise(target, 96))

    def _cmd_to(self, arg):
        """`/to mls3`, `/to bob`, `/to bob@server`: switch the conversation.
        `/to mls3 hello`: switch, and send "hello" there."""
        arg = arg.strip()
        if not arg:
            print("[to] talking to: %s" % (_sanitise(self.peer, 96) if self.peer
                                          else "nobody (use /to <name>)"))
            return
        # The name is one word; the rest is a message. "/to secure yes" made
        # a contact called "secure yes" the conversation (device test).
        arg, _, text = arg.partition(" ")
        text = text.strip()
        if self._switch_to(arg) and text:
            self.send_user_text(self.peer, text)

    def _switch_to(self, arg):
        """Make `arg` the conversation. False if it is no contact or group."""
        groups = getattr(self, "_groups", None)
        if groups is not None and "@" not in arg:
            try:
                room = groups.room(arg)
            except Exception as exc:
                print("[to] %s matches more than one group (%s): give more of "
                      "the name" % (_sanitise(arg, 64),
                                    _sanitise(getattr(exc, "detail", ""), 200)))
                return False
            if groups.owns_room(room):
                self.set_conversation(room)
                return True
            if room in groups.known_rooms():
                print("[to] %s is an invitation: /group accept %s first"
                      % (_sanitise(room, 96), _sanitise(arg, 64)))
                return False
        target = self.expand_jid(arg)
        local, _, domain = target.partition("@")
        if not local or not domain or "." not in domain:
            print("[to] %s is not a contact or one of your secure groups "
                  "(/group list, /roster)" % _sanitise(arg, 64))
            return False
        if groups is not None and not groups.owns_room(target) and (
                domain.startswith("conference.") or any(
                    r.endswith("@" + domain) for r in groups.known_rooms())):
            # A room we hold no group for: typing there would not be MLS.
            print("[to] %s is a room, not one of your secure groups "
                  "(/group list)" % _sanitise(target, 96))
            return False
        self.set_conversation(target)
        return True

    # -- the outbox, and OTRv4+ as soon as a contact is there -------------------

    #: Lines held per contact; the ETA before any handshake was measured.
    OUTBOX_MAX = 100
    HANDSHAKE_TYPICAL_SECONDS = 75

    def _hold(self, peer, text):
        box = self._outbox.setdefault(peer, [])
        if len(box) >= self.OUTBOX_MAX:
            print(f"[queued] too many waiting for {peer}; not queued")
            return False
        box.append(text)
        return True

    def _handshake_eta(self):
        hist = self._hs_hist
        return int(sorted(hist)[len(hist) // 2]) if hist else self.HANDSHAKE_TYPICAL_SECONDS

    def _presence_ready(self, peer):
        """A contact came online. OTRv4+ with a capable one starts now (one
        side only: the lower JID, unless we have something waiting), and a
        line held for a contact without OTRv4+ goes in the clear."""
        if peer in self._encrypted:
            return
        waiting = bool(self._outbox.get(peer))
        if peer in self._otr_capable:
            try:
                mine = str(self.boundjid.bare)
            except Exception:
                mine = ""
            in_flight = peer in self._hs_started
            if (waiting or (mine and mine < peer)) and not in_flight:
                print(f"[otr] {peer} is online with OTRv4+: starting the "
                      f"encrypted session (about {self._handshake_eta()} s over I2P)")
                self.start_otr(peer)
            return
        _mode = getattr(self, "_otr_mode", None)
        if waiting and _mode is not None and not _mode.is_otr(peer):
            box = self._outbox.pop(peer, [])
            for text in box:
                try:
                    self.send_otr_fragmented(peer, text)
                    self._echo_plain_sent(peer, text)
                except Exception as e:
                    print(f"[send error] to {peer}: {e}")
            print(f"[plain] {len(box)} waiting message(s) sent UNENCRYPTED: "
                  f"{peer}'s app does not support OTRv4+")

    def _flush_outbox(self, peer):
        box = self._outbox.get(peer)
        if not box:
            return
        sent = 0
        while box:
            try:
                msg, ok = self.otr.handle_outgoing_message(peer, box[0])
            except Exception:
                break
            if not (ok and msg):
                break
            self.send_otr_fragmented(peer, msg if isinstance(msg, str) else msg.decode())
            self._echo_sent(peer, box.pop(0))
            sent += 1
        if not box:
            self._outbox.pop(peer, None)
        if sent:
            print(f"[queued] {sent} waiting message(s) sent, encrypted")

    def _send_final_revelations(self) -> int:
        """L1: send the closing messages the engine built as sessions ended
        (each publishes retired MAC keys). Dropped when not connected: the
        keys are retired and wiped in Rust regardless. Never raises."""
        return self._send_closings(self._take_final_revelations())

    def _take_final_revelations(self):
        take = getattr(self.otr, "take_final_revelations", None)
        if take is None:
            return []
        try:
            return list(take())
        except Exception:
            return []

    def _send_closings(self, waiting) -> int:
        sent = 0
        for peer, wire in waiting:
            try:
                if self.is_connected():
                    self.send_otr_fragmented(peer, wire)
                    sent += 1
            except Exception:
                pass
        return sent

    def make_deniable(self, peer):
        """/deniable: publish every MAC key of the session with [peer], tell
        them it has ended, forget it, and start a fresh session that shares
        no key with the one whose MAC keys are now public."""
        try:
            done = self.otr.make_deniable(peer)
        except Exception as exc:
            print("[otr] could not make the chat deniable: %s" % _sanitise(str(exc), 80))
            return
        if not done:
            print("[otr] no encrypted session with %s to end" % _sanitise(peer, 128))
            return
        waiting = self._take_final_revelations()
        sent = self._send_closings(waiting)
        self._encrypted.discard(peer)
        self._last_dake1.pop(peer, None)
        print("[otr] %s: publishing this session's MAC keys (%d message%s); waiting "
              "for your server to confirm" % (_sanitise(peer, 128), sent, "" if sent == 1 else "s"))
        asyncio.run_coroutine_threadsafe(self._confirm_then_restart(peer, waiting), self.loop)

    #: Make Chat Deniable (L1): how long the server has to confirm the
    #: closing messages, and how often they are sent again if it does not.
    CLOSING_CONFIRM_S = 15.0
    CLOSING_RETRY_S = 30.0
    CLOSING_TRIES = 5

    async def _server_confirms(self, budget):
        """Whether our server has received everything sent so far: the send
        queue drained, then a XEP-0199 ping answered (a server answers an IQ
        only after every stanza before it). Not knowing is never yes."""
        import otrv4plus_ping
        try:
            await asyncio.wait_for(self.waiting_queue.join(), budget)
            return bool(await otrv4plus_ping.round_trip(
                self.plugin["xep_0199"], self.boundjid.host, budget))
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _confirm_then_restart(self, peer, waiting):
        """The new session starts once the server has confirmed the closing
        messages; if it does not, it starts anyway (the old one is closed)
        and they are sent again until it does, CLOSING_TRIES times."""
        name = _sanitise(peer, 128)
        confirmed = await self._server_confirms(self.CLOSING_CONFIRM_S)
        if confirmed:
            print("[otr] %s: your server confirmed the published keys; starting a "
                  "new session" % name)
        else:
            print("[otr] %s: the session is closed and its keys retired, but your "
                  "server has not confirmed the message that publishes them yet; "
                  "sending it again in the background" % name)
        self.start_otr(peer)
        for _ in range(self.CLOSING_TRIES if not confirmed else 0):
            await asyncio.sleep(self.CLOSING_RETRY_S)
            self._send_closings(waiting)
            if await self._server_confirms(self.CLOSING_CONFIRM_S):
                print("[otr] %s: your server confirmed the published keys" % name)
                return
        if not confirmed:
            print("[otr] %s: still not confirmed; the keys stay retired" % name)

    def start_otr(self, peer):
        # Recorded BEFORE anything can fail. From here on this conversation
        # does not send in the clear, and a handshake that goes wrong must not
        # quietly restore that possibility.
        _m = getattr(self, "_otr_mode", None)
        if _m is not None:
            _m.request(peer)
        getattr(self, "_hs_started", {}).setdefault(peer, time.monotonic())
        try:
            msg, should_send = self.otr.handle_outgoing_message(peer, "")
        except Exception as e:
            print(f"[otr error] start with {peer}: {e}")
            return

        if not (should_send and msg):
            # Engine refused — DAKE already in progress or session in bad state.
            # Force-reset and retry so /otr can always unstick a hung handshake.
            print(f"[otr] resetting stuck session with {peer}, retrying DAKE...")
            # Two separate steps, deliberately. They were one try block, and
            # when the engine teardown raised, every line below it was skipped
            # -- so a failure in the ENGINE also left the CLIENT holding stale
            # state, and the retry had no chance. That is what a device saw:
            # one AttributeError and the reset did nothing at all.
            try:
                self.otr.end_session(peer)
            except Exception as e:
                print(f"[otr] engine teardown failed: {e}")
            self._encrypted.discard(peer)
            self._last_dake1.pop(peer, None)
            if self._secret_request == peer:
                self._secret_request = None
                self._mask_next_input(False)
            self._smp_reported = {k for k in self._smp_reported if k[0] != peer}
            self._smp_flows.drop(peer)
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
        """Encrypt and send one typed line, and show it in the transcript.

        Until v10.27.0 nothing was echoed here: a sent message produced no
        output at all, so the session read as a monologue by the peer with
        the user's own half missing entirely.  On a handset, where the typed
        line scrolls away behind the next arriving message, there was no way
        to read back who had said what.  The IRC client has always echoed
        both sides; this brings XMPP level.

        The echo goes out AFTER the send, and only when the engine actually
        produced ciphertext.  The line carries the same padlock the inbound
        path uses, and a padlock on a message that never left would be a
        false claim about the one thing this client exists to be right about.
        """
        # A SECURE GROUP'S ROOM, typed into as the active conversation: MLS or
        # nothing. Never the 1:1 path, never plaintext to the room.
        groups = getattr(self, "_groups", None)
        if groups is not None and groups.owns_room(peer):
            groups.say(peer, text)
            return
        # PLAINTEXT BEFORE OTR.
        #
        # `handle_outgoing_message` is opportunistic: for a peer with no
        # session it creates one, starts a DAKE, queues the text and returns
        # DAKE1. So reaching it at all would turn "hello" into an 11 KB
        # handshake frame and deliver nothing -- which is what happened, and
        # is why an ordinary XMPP conversation was impossible in either
        # direction.
        #
        # `OtrMode` fails closed: an established session, or one either side
        # has asked for, never comes down this branch.
        # `getattr`, and the default is None on purpose. Test stubs drive this
        # method unbound against objects that never ran `__init__`, and so
        # would a partially constructed client. The safe answer for "I do not
        # know whether OTR was asked for here" is to NOT take the plaintext
        # branch: fall through to the engine, which is the old behaviour and
        # cannot leak. An `_OtrMode()` default would have done the opposite.
        _mode = getattr(self, "_otr_mode", None)
        # NO PLAINTEXT TO AN OTRv4+ CONTACT (owner, 2026-10-04): until the
        # session is up a line waits in the outbox, and the handshake is
        # started. A contact not online, whose app we cannot know, waits too.
        if (_mode is not None and peer not in getattr(self, "_encrypted", ())
                and hasattr(self, "_outbox")):
            capable = peer in self._otr_capable
            online = bool(getattr(self, "_peer_resources", {}).get(peer))
            if capable or _mode.is_otr(peer) or not online:
                if not self._hold(peer, text):
                    return
                if capable and peer not in self._hs_started:
                    self.start_otr(peer)
                if not online:
                    print(f"[queued] no presence from {peer} yet: will send when "
                          f"they are online (encrypted if their app supports "
                          f"OTRv4+). /otr starts encryption now; /msg sends "
                          f"plaintext on purpose.")
                else:
                    print(f"[queued] will send once OTRv4+ with {peer} is ready "
                          f"(about {self._handshake_eta()} s)")
                return
        if _mode is not None and _mode.may_send_plaintext(
                peer, peer in getattr(self, "_encrypted", ())):
            try:
                self.send_otr_fragmented(peer, text)
            except Exception as e:
                print(f"[send error] to {peer}: {e}")
                return
            self._echo_plain_sent(peer, text)
            return

        try:
            # With its MESSAGE_META (an id for /edit, /retract, reactions).
            encrypt = getattr(self, "_ts_encrypt", None)
            if encrypt is not None:
                msg, should_send, mid = encrypt(peer, text)
            else:
                (msg, should_send), mid = self.otr.handle_outgoing_message(peer, text), ""
        except Exception as e:
            print(f"[otr error] send to {peer}: {e}")
            return
        if should_send and msg:
            self.send_otr_fragmented(
                peer, msg if isinstance(msg, str) else msg.decode()
            )
            if mid and hasattr(self, "_ts_remember"):
                self._ts_remember(peer, mid, text, True)
            self._echo_sent(peer, text)
        elif not should_send:
            hold = getattr(self, "_hold", None)
            if hold is None or hold(peer, text):
                print(f"[queued] will send once OTR with {peer} is ready")

    def _echo_plain_sent(self, peer, text):
        """Echo a message that went in the CLEAR.

        Deliberately not `_echo_sent`, and deliberately without a padlock:
        this one was readable by the server and by anything between it and the
        peer, and it appears under the same `[plain]` tag the inbound side
        uses so both halves of an unencrypted conversation look alike.

        The body is `_sanitise`d exactly as an inbound body is. Being our own
        words is not a reason to print them differently, and the redaction
        allowlist has to treat both directions the same or a session log keeps
        half a conversation.
        """
        try:
            mine = self.boundjid.bare
        except Exception:
            mine = ""
        self._erase_plain_echo(text)
        print("[plain] %s: %s"
              % (_colorize(_sanitise(mine or "me", 128), "cyan"),
                 _sanitise(text)))

    def _echo_sent(self, peer, text):
        """Print our own message in the same shape as an incoming one.

        Same `[otr]` tag and the same padlock, so the redaction allowlist
        treats both identically -- an outgoing body must be as absent from
        the session log as an incoming one, and it is the same person's
        conversation either way.

        Our own JID rather than "me" or a nickname: the peer's side already
        shows a full JID, and two names in two formats is how a transcript
        stops being readable at exactly the moment somebody needs to quote
        it.  A different colour separates the two sides at a glance.
        """
        try:
            mine = self.boundjid.bare
        except Exception:
            mine = ""
        mine_s = _sanitise(mine or "me", 128)
        smp_ok = (peer, "SUCCEEDED") in self._smp_reported
        self._erase_plain_echo(text)
        print(
            _otr_prefix(smp_ok)
            + " "
            + _colorize(mine_s + ":", "cyan")
            + " "
            + _sanitise(text)
        )

    #: Longest input we will try to erase, in terminal rows.
    #:
    #: A pasted wall of text is not worth unwinding, and getting the row
    #: count wrong on a very long line scrolls real output off the screen.
    PLAIN_ECHO_MAX_ROWS = 12

    def _erase_plain_echo(self, text):
        """Remove the copy of `text` the terminal echoed, if it is still there.

        In plain mode the input loop sits in `sys.stdin.readline()` with the
        tty in canonical mode, so the terminal has ALREADY drawn what the
        user typed by the time we are called. v10.27.0 added our own
        attributed echo without accounting for that, and every sent message
        appeared twice: once bare, once as `[otr] alice@host: ...`.

        The TUI is unaffected -- it owns the screen in raw mode and echoes
        the input itself -- so this does nothing there.

        Three conditions, and all of them must hold, because the cost of
        being wrong is scrolling real output away:

          * the line we are echoing is the one the terminal just echoed;
          * NOTHING has been printed since (an inbound message arriving
            between Enter and here means the rows above the cursor are no
            longer the user's input);
          * stdout is a terminal whose width we can actually read.

        If any fails, nothing is erased. The message then appears twice,
        which is the v10.27.0 behaviour: ugly, and strictly better than
        eating a line of somebody's conversation.
        """
        try:
            if getattr(self, "_tui_enabled", False):
                return
            pending = getattr(self, "_plain_echo", None)
            self._plain_echo = None
            if not pending:
                return
            seq, echoed = pending
            if echoed != text or seq != _term._PRINT_SEQ:
                return
            cols = _terminal_cols()
            if cols is None:
                return
            # How many rows the terminal used to draw it. A line exactly
            # `cols` wide occupies one row, not two -- the wrap happens on
            # the character after.
            rows = max(1, -(-len(text) // cols))
            if rows > self.PLAIN_ECHO_MAX_ROWS:
                return
            # Up `rows`, to column one, then clear everything below. Clearing
            # the whole region rather than each line keeps it correct when
            # the last row is shorter than the ones above it.
            _raw_write("\x1b[%dA\r\x1b[J" % rows)
        except Exception:
            # Terminal geometry is unavailable often enough (a pipe, a pty
            # that does not answer TIOCGWINSZ, a closed stdout during
            # shutdown) that this must never be the thing that breaks
            # sending a message.
            pass

    def _remember_server_alias(self):
        """Write down the b32 the first time it actually works.

        Called once a connection has succeeded, which is the only point at
        which the client knows the name/destination pair is good.  The next
        run needs neither --server nor the 52 characters:

            --jid bob@otrv4plus.i2p --peer alice@otrv4plus.i2p

        This writes only to the client's own file.  It deliberately does NOT
        touch i2pd's address book: that format varies between versions, the
        daemon owns and rewrites those files, and a bad write would break name
        resolution for every I2P application on the device rather than just
        this one.
        """
        try:
            if not getattr(self, "_i2p_server_dest", None):
                return                       # not an I2P connection
            domain = self.boundjid.domain
            if not domain or not domain.endswith(".i2p"):
                return
            if domain.endswith(".b32.i2p"):
                return                       # already the exact form
            note = _otr.remember_i2p_alias(domain, self._i2p_server_dest)
            if note:
                print(f"[i2p] {note}")
                if note.startswith("recorded"):
                    print("[i2p] next time:  --jid %s --peer <peer> "
                          "(no --server needed)" % self.boundjid.bare)
        except Exception as exc:
            self._dbg(f"[i2p] could not record the server alias: {exc}")

    def _warn_inline_secret(self):
        """Say that an inline passphrase was just echoed.

        The engine clears the input line on Enter, so it vanishes from the
        screen -- but a `script` capture records the keystrokes as they were
        echoed, before the erase, so the passphrase is in the file regardless.
        Better to say so than to let it look like it was never shown.
        """
        print(_SMP + " NOTE: that passphrase was typed in the clear, so it is in "
              "this terminal's")
        print(_SMP + " scrollback and in any session capture. Use  /smp-secret  "
              "with no argument")
        print(_SMP + " to be prompted for it hidden instead.")

    def store_smp_secret(self, peer, secret):
        """/smp-secret: store passphrase for auto-respond without starting SMP."""
        if not self.otr.has_encrypted_session(peer):
            print(_SMP + f" no encrypted session with {peer}. Run /otr first."
                  + self._no_session_hint(peer))
            return
        secret = secret.strip()
        err = self._validate_smp_secret(secret)
        if err:
            print(_SMP + f" {err}")
            return
        try:
            ok = self.otr.set_smp_secret(peer, secret)
        except Exception as e:
            print(_SMP + f" error: {e}")
            return
        print(
            _SMP + " passphrase stored for auto-respond."
            if ok
            else _SMP + " could not store passphrase."
        )

    def smp_start(self, peer, secret=None):
        """/smp start or /smp <secret>: initiate SMP verification.
        Runs the 3072-bit DH in a background thread to keep the loop free."""
        if not self.otr.has_encrypted_session(peer):
            print(_SMP + f" no encrypted session with {peer}. Run /otr first."
                  + self._no_session_hint(peer))
            return
        if secret:
            secret = secret.strip()
            err = self._validate_smp_secret(secret)
            if err:
                print(_SMP + f" {err}")
                return
            try:
                self.otr.set_smp_secret(peer, secret)
            except Exception:
                pass
        # With no secret given, the stored one is used -- bound store -> vault
        # inside Rust and started with an empty argument. It is never read
        # back into this process.
        use_stored = not secret
        if use_stored and not self.otr.has_stored_smp_secret(peer):
            # Reached only via the explicit forms; `/smp` asks instead.
            print(_SMP + " Verification requires a shared passphrase.")
            print(_SMP + " Run  /smp  and you will be prompted for it.")
            return
        try:
            def _do_start():
                if use_stored:
                    return self.otr.start_smp_with_stored_secret(peer)
                return self.otr.start_smp(peer, secret)

            async def _run():
                loop = asyncio.get_event_loop()
                try:
                    smp1 = await loop.run_in_executor(self._otr_executor, _do_start)
                except Exception as e:
                    print(_SMP + f" start error: {e}")
                    return
                if smp1:
                    self.send_otr_fragmented(
                        peer, smp1 if isinstance(smp1, str) else smp1.decode()
                    )
                    print(
                        _SMP + f" started with {peer}; waiting for response "
                        "(SMP runs several 3072-bit DH rounds; keep both clients running)..."
                    )
                    self._show_smp_progress(peer, force=True)
                else:
                    print(_SMP + f" could not start with {peer}")

            self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_run()))
        except Exception as e:
            print(_SMP + f" start error: {e}")

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
                rtt = await self.plugin["xep_0199"].async_ping(jid, timeout=30)
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
            has_secret = self.otr.has_stored_smp_secret(peer)
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

    def show_help(self):
        print(
            "[help] OTRv4+ XMPP commands:\n"
            "  /to <name>           talk to a contact or secure group, then\n"
            "                       just type (/to alice, /to mls3)\n"
            "  /otr [jid]           start OTR session (DAKE); a user name\n"
            "                       alone is enough (/otr bob)\n"
            "  /deniable [jid]      publish the keys used to authenticate this\n"
            "                       chat's messages, ask your server to confirm,\n"
            "                       end the session and start a new one. It does\n"
            "                       not hide that you talked. Not independently\n"
            "                       reviewed. A copy made before the keys are\n"
            "                       published, or a close that does not finish,\n"
            "                       can still be proof\n"
            "  /smp start           begin SMP verification\n"
            "  /smp <secret>        set secret and start SMP\n"
            "  /smp                 verify this session — prompts (hidden) for\n"
            "                       the passphrase if none is stored, then\n"
            "                       verifies. The only SMP command you need.\n"
            "  /smp-secret          store a passphrase WITHOUT verifying\n"
            "                       (prompts, hidden; advanced/compat)\n"
            "  /smp-secret <s>      store it inline (ECHOED — prefer the above)\n"
            "  /trust-reset <jid>   clear a pinned fingerprint (deliberate)\n"
            "  /group help          secure groups (MLS+): create, invite,\n"
            "                       accept, say, members, remove, leave\n"
            "  /wipe                destroy ALL local state (secure groups\n"
            "                       too) and exit; /quit keeps your groups\n"
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
            "  /block <jid> [spam]  block (and on the server, every device, when\n"
            "                       it can; spam also reports them)\n"
            "  /unblock <jid>       unblock JID\n"
            "  /blocked             list blocked JIDs\n"
            "  /ping <jid>          XMPP ping (XEP-0199)\n"
            "  /call [jid]          start encrypted voice call (requires OTR)\n"
            "  /answer              accept incoming call\n"
            "  /reject              decline incoming call\n"
            "  /hangup              end active call\n"
            "  /mute                toggle microphone mute\n"
            "  /calls               show voice call state and frame counters\n"
            "  /audiotest           test the speaker (a tone) and the microphone\n"
            "  /audioprobe          test each audio backend on this device\n"
            "  /sendfile [path]     send a file (encrypted, verified peer; in a\n"
            "                       group, to the group). Asks y/n to remove\n"
            "                       hidden information (location, camera) first\n"
            "  /voice [mode]        record a voice note in a synthetic voice\n"
            "                       (synthetic = default; natural = your\n"
            "                       own voice);\n"
            "                       /voice again to stop, then play|send|cancel\n"
            "  /transfer            show file transfer state (group files too)\n"
            + self.TS_HELP +
            "  /sound on|off        message and group-call sounds (y/n answers\n"
            "                       a ringing call or an offered file)\n"
            "  /trade               list open trades\n"
            "  /trade init <terms>  propose a trade to the verified peer\n"
            "  /trade accept        agree to a proposal\n"
            "  /trade decline [why] refuse a proposal\n"
            "  /trade blob <b64>    relay one blob from your Monero wallet\n"
            "  /trade confirm       tell them your side is done\n"
            "  /trade cancel [why]  end a trade\n"
            "  /setxmr <address>    store your Monero address (persisted)\n"
            "  /setxmr clear        forget it and stop auto-answering\n"
            "  /tip                 show tip state\n"
            "  /tip <amt> [note]    ask a verified peer for their address\n"
            "  /tipreply            answer a request that arrived first\n"
            "  /smpstate            show raw SMP verification state\n"
            "  /voicedebug          toggle voice setup + telemetry logging\n"
            "  /admin               list your server's admin commands\n"
            "  /admin <command>     run one (prompts for what it needs)\n"
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

    def take_secret_request(self):
        """Consume the locally-armed secret request, if any.

        Always clears.  A request survives exactly one dispatched line, so a
        cancelled or mistyped prompt cannot leave the client quietly waiting
        to swallow something later.
        """
        peer, self._secret_request = self._secret_request, None
        self._secret_purpose_taken, self._secret_purpose = (
            self._secret_purpose, None)
        return peer

    def _pending_consent_peer(self):
        """The peer whose verification request is waiting for a y/n, if any.

        Reads the flow rather than a loose flag so an expired request stops
        answering by itself.
        """
        flow = self._smp_flows.asking() if self._smp_flows else None
        if flow is not None and flow.awaiting_consent():
            return flow.peer
        return None

    def has_pending(self, peer=None):
        """True while a LOCALLY armed /smp-secret prompt is outstanding.

        Kept as a predicate for the front ends, which need to know not to
        echo the line into the transcript panel.  It is deliberately not
        keyed by peer any more: a per-peer map was what let one peer's
        protocol traffic arm capture for a conversation the user was not
        looking at.
        """
        return self._secret_request is not None

    # -------------------------------------------------------------------------
    # Shared command dispatch
    # -------------------------------------------------------------------------

    def dispatch_line(self, peer, line):
        """Handle one input line for `peer` (the active conversation).

        Returns True to keep running, False to quit. Single source of truth
        for command behaviour; both the plain stdin loop and the TUI call this
        so both front-ends behave identically. Each `_dispatch_*` method
        handles one family of commands and answers whether the line was one
        of its own; no two families match the same line."""
        # A prompt or question on screen answers before any command parsing:
        # a passphrase or a form field may legitimately begin with "/".
        if self._dispatch_pending(line):
            return True
        if not line:
            return True

        # Invisible characters a copy from a chat window brings along (zero-
        # width spaces, a byte-order mark, a non-breaking space) made
        # "/otr alice@..." fail to match and go out as a chat message instead
        # (device test, 2026-10-02).
        line = (line.replace("\u200b", "").replace("\u200c", "")
                .replace("\u200d", "").replace("\u2060", "")
                .replace("\ufeff", "").replace("\u00a0", " "))
        lstrip = line.strip()

        # --- TUI toggle ---
        ts_command = getattr(self, "_ts_command", None)
        if ts_command is not None and ts_command(lstrip, peer):
            return True
        if lstrip in ("/sound", "/sound on", "/sound off"):
            if lstrip != "/sound":
                self._alerts().enabled = lstrip == "/sound on"
            print("[sound] message and group-call sounds are %s (/sound on|off; "
                  "a 1:1 call always rings)"
                  % ("on" if self._alerts().enabled else "off"))
            return True
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
            self._clear_trades("/quit")
            return False

        # --- Wipe: /quit that destroys EVERYTHING, secure groups included ---
        if lstrip == "/wipe":
            self._clear_trades("/wipe")
            self._wipe_on_exit = True
            print("[wipe] destroying all local state, secure groups included, "
                  "and exiting")
            return False

        for family in (self._dispatch_session, self._dispatch_smp,
                       self._dispatch_contacts,
                       self._dispatch_media, self._dispatch_calls,
                       self._dispatch_display):
            if family(peer, lstrip):
                return True

        # --- Outbound chat ---
        if lstrip.startswith("/"):
            # A command this client does not have. Never sent as a chat
            # message: a mistyped "/otr" went to the peer as text, and with
            # no --peer it was answered with a message about --peer.
            print("unknown command: %s  (type /help for the list)"
                  % _sanitise(lstrip.split()[0], 40))
        else:
            if peer:
                self.send_user_text(peer, line)
            else:
                print("not talking to anyone yet: /to <name> picks a contact "
                      "or a secure group (e.g. /to alice, /to mls3)")

        return True

    def _dispatch_pending(self, line):
        """True if *line* answered a prompt or question on screen."""
        # A secret prompt that THIS USER armed with /smp-secret consumes the
        # next line.  Taken unconditionally so it can never persist past one
        # line. Nothing a remote peer sends can set this; see
        # _request_smp_secret.
        secret_for = self.take_secret_request()
        if secret_for is not None:
            self._mask_next_input(False)
            groups = getattr(self, "_groups", None)
            tag = getattr(groups, "PASSPHRASE_TAG", None)
            if tag and isinstance(secret_for, str) and secret_for.startswith(tag):
                # A group passphrase the user asked to type (/group verify,
                # their own y, or /group create). At /group create's optional
                # prompt a command means "skip it" and runs as typed.
                creating = secret_for[len(tag):].startswith("new:")
                if not (creating and line.lstrip().startswith("/")):
                    groups.passphrase_entered(secret_for, line)
                    return True
                print("[group] no passphrase set (/group verify sets one later)")
            else:
                self._handle_smp_secret_answer(secret_for, line)
                return True

        # An admin form THIS USER opened with /admin consumes the next line.
        # Checked here, before command parsing, for the same reason as the
        # passphrase above: a field value may legitimately begin with "/".
        # `/cancel` is the way out and is handled inside the answer path.
        if self.take_admin_field():
            self._mask_next_input(False)
            self._handle_admin_answer(line)
            return True

        # A consent request a PEER caused.  Unlike the secret prompt above it
        # does not consume the line: only an exact y/n answers it, and
        # anything else falls through to be treated as what the user typed --
        # a command, or a message that gets sent.  That asymmetry is the
        # point.  A remote peer can put a question on the screen; it cannot
        # make the answer to some other question become a passphrase.
        # Remove a file's hidden information? Asked only by the user's own
        # /sendfile, so it is answered first.
        answer_metadata = getattr(self, "_answer_metadata", None)
        if answer_metadata is not None and answer_metadata(line):
            return True
        consent_for = self._pending_consent_peer()
        if consent_for is not None and line.strip().lower() in (
                "y", "yes", "n", "no"):
            self._handle_smp_consent(consent_for, line.strip().lower())
            return True
        # A call ringing or a file offered asks the same way (QuickAnswer).
        # Before the group questions: a call is the most urgent thing on
        # screen and the newest question there.
        quick = getattr(self, "_quick_answer", None)
        if quick is not None and quick().answer(line):
            return True
        # A group invitation asks the same way: only an exact y/n answers it.
        groups = getattr(self, "_groups", None)
        if groups is not None and getattr(groups, "answer_prompt", None) is not None:
            if groups.answer_prompt(line):
                return True
        if line.strip() and getattr(self, "_alerts", None) is not None:
            self._alerts().seen()
        return False

    def _dispatch_session(self, peer, lstrip):
        """Secure groups, OTR, the conversation, trust, /msg, /status, /identity."""
        # --- Secure groups (MLS) ---
        if lstrip == "/group" or lstrip.startswith("/group "):
            groups = getattr(self, "_groups", None)
            if groups is None:
                print("[group] secure groups are unavailable in this install")
            else:
                asyncio.ensure_future(groups.command(lstrip[len("/group"):].strip()))
            return True

        # --- L1: publish this session's MAC keys and start afresh ---
        elif lstrip == "/deniable" or lstrip.startswith("/deniable "):
            target = _expand(self, lstrip[len("/deniable"):].strip()) if " " in lstrip else peer
            if target:
                self.make_deniable(target)
            else:
                print("no --peer set; use /deniable <jid>")

        # --- OTR ---
        elif lstrip == "/otr":
            if peer:
                self.start_otr(peer)
            else:
                print("no --peer set; use /otr <jid>")
        elif lstrip.startswith("/otr "):
            self.start_otr(_expand(self, lstrip[5:].strip()))

        # --- The conversation what is typed goes to ---
        elif lstrip in ("/to", "/talk") or lstrip.startswith(("/to ", "/talk ")):
            self._cmd_to(lstrip.split(None, 1)[1] if " " in lstrip else "")
        # --- Trust ---
        elif lstrip == "/trust":
            if peer:
                self.reshow_trust(peer)

        # --- Plain message ---
        elif lstrip.startswith("/msg "):
            rest = lstrip[5:].strip()
            if " " in rest:
                t, txt = rest.split(" ", 1)
                groups = getattr(self, "_groups", None)
                if groups is not None and groups.owns_room(t):
                    # A room this client is in for a secure group. /msg is
                    # PLAINTEXT to one address: it went to the room's JID
                    # unencrypted (device test, 2026-10-02; the server
                    # refused it). Group text is MLS or nothing.
                    print("[group] %s is a secure group room; /msg would "
                          "send plaintext. Use  /group say %s <text>"
                          % (_sanitise(t, 80), _sanitise(t, 80)))
                    return True
                if t in getattr(self, "_otr_capable", ()) or t in self._encrypted:
                    print("[otr] %s uses OTRv4+: /msg would send plaintext. "
                          "Type to them normally; it goes encrypted."
                          % _sanitise(t, 80))
                    return True
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
        elif lstrip in ("/identity", "/whoami"):
            self.show_identity()
        else:
            return False
        return True

    def _dispatch_smp(self, peer, lstrip):
        """SMP verification and its passphrase, /trust-reset, /smpstate."""
        # --- SMP ---
        # `/smp` is the normal verb: verify this session, asking for whatever
        # is missing.  `/smp start` still works and is documented as the
        # explicit form for anyone who already has a passphrase stored.
        if lstrip == "/smp":
            groups = getattr(self, "_groups", None)
            if peer and groups is not None and groups.owns_room(peer):
                # In a secure group: verify the whole group with its passphrase.
                groups.start_verify(peer)
            elif peer:
                self.smp_verify(peer)
            else:
                print("no --peer set")
        elif lstrip == "/smp start":
            if peer:
                self.smp_verify(peer)
            else:
                print("no --peer set")
        elif lstrip.startswith("/trust-reset"):
            rest = lstrip[len("/trust-reset"):].strip()
            self.trust_reset(rest or peer)

        elif lstrip in ("/smp-secret", "/smpsecret"):
            # No argument: prompt for it hidden. The argument form below is
            # typed in the clear, so this is the one to reach for.
            if peer:
                self._request_smp_secret(peer)
            else:
                print("usage: /smp-secret            (prompts, hidden)")
                print("       /smp-secret <jid>      (prompts, hidden)")

        elif lstrip.startswith("/smp-secret "):
            rest = lstrip[len("/smp-secret "):].strip()
            first = rest.split(" ", 1)[0]
            if "@" in first and " " in rest:
                t, sec = rest.split(" ", 1)
                self.store_smp_secret(t, sec)
                self._warn_inline_secret()
            elif "@" in first and " " not in rest:
                # A JID and nothing else: they want to be asked, hidden.
                self._request_smp_secret(first)
            elif peer:
                self.store_smp_secret(peer, rest)
                self._warn_inline_secret()
            else:
                print("usage: /smp-secret            (prompts, hidden)")
                print("       /smp-secret <jid>      (prompts, hidden)")
        elif lstrip.startswith("/smp "):
            rest = lstrip[5:].strip()
            if rest in ("start", "verify"):
                if peer:
                    self.smp_verify(peer)
            else:
                first = rest.split(" ", 1)[0]
                if "@" in first and " " in rest:
                    t, s = rest.split(" ", 1)
                    self.smp_start(t, s)
                elif peer:
                    self.smp_start(peer, rest)
                else:
                    print("usage: /smp <jid> <secret>")
        elif lstrip in ("/smpstate", "/smpstatus"):
            if not peer:
                print(_SMP + " no active peer")
            else:
                vm = self._voice_manager
                name = vm._smp_state_name(peer) if vm else "?"
                reported = ((peer, "SUCCEEDED") in self._smp_reported
                            or (peer, "SUCCEEDED") in self._smp_display_hints)
                ok = vm._smp_verified(peer) if vm else False
                print(_SMP + " peer            : %s" % _sanitise(peer, 64))
                print(_SMP + " engine state    : %s" % _sanitise(name or "-", 60))
                print(_SMP + " client recorded : %s" % reported)
                print(_SMP + " call permitted  : %s" % ok)
        else:
            return False
        return True

    def _dispatch_contacts(self, peer, lstrip):
        """Roster, subscriptions, the block list, /ping and /admin."""
        # --- Roster ---
        if lstrip in ("/roster", "/roster list"):
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
        elif lstrip == "/admin" or lstrip.startswith("/admin "):
            parts = lstrip.split(None, 1)
            arg = parts[1].strip() if len(parts) > 1 else ""
            asyncio.ensure_future(self._cmd_admin(arg))
        else:
            return False
        return True

    def _dispatch_media(self, peer, lstrip):
        """Files, voice notes, trades and tips."""
        # --- File transfer (XMPP only) ---
        if lstrip.startswith("/sendfile"):
            self._cmd_sendfile(peer, lstrip[9:].strip())
        elif lstrip == "/voice" or lstrip.startswith("/voice "):
            self._cmd_voice(peer, lstrip[6:].strip())
        elif lstrip == "/transfer" or lstrip.startswith("/transfer "):
            self._cmd_transfer(lstrip[9:].strip())

        # --- Trade courier (XMPP only, same as file transfer) ---
        elif lstrip == "/trade" or lstrip.startswith("/trade "):
            self._cmd_trade(peer, lstrip[6:].strip())

        # --- Tip: relay a Monero address, nothing more ---
        elif lstrip == "/setxmr" or lstrip.startswith("/setxmr "):
            self._cmd_setxmr(lstrip[7:].strip())
        elif lstrip == "/tipreply":
            self._cmd_tipreply(peer)
        elif lstrip == "/tip" or lstrip.startswith("/tip "):
            self._cmd_tip(peer, lstrip[4:].strip())
        else:
            return False
        return True

    def _dispatch_calls(self, peer, lstrip):
        """One-to-one and group calls, and the audio diagnostics."""
        # --- Voice calls ---
        if lstrip == "/call":
            if peer and self._voice_manager:
                if self._voice_blocked_by_tofu(peer):
                    return True
                asyncio.ensure_future(self._voice_manager.start_call(peer))
            elif not self._voice_manager:
                print("[voice] not initialized — connect first")
            else:
                print("usage: /call (set --peer first) or /call <jid>")
        elif lstrip.startswith("/call "):
            jid = _expand(self, lstrip[6:].strip())
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
        elif lstrip == "/hangup" and getattr(getattr(self, "_groups", None),
                                             "in_call", lambda: False)():
            self._groups._hangup()
        elif lstrip == "/pause":
            groups = getattr(self, "_groups", None)
            if groups is not None and groups.in_call():
                groups.pause_call()
            elif self._voice_manager and self._voice_manager.any_active_peer():
                self._voice_manager.toggle_mute(self._voice_manager.any_active_peer())
            else:
                print("[call] no call to pause")
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
            asyncio.ensure_future(_termux._audio_selftest_async(voice_available))
        else:
            return False
        return True

    def _dispatch_display(self, peer, lstrip):
        """Scrolling, the log and help."""
        # --- Scroll (Termux software keyboard fallback) ---
        if lstrip in ("/up", "/pgup", "/b"):
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

        # --- Log / History: in-memory scrollback (works in any mode) ---
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
        else:
            return False
        return True

    def cleanup(self) -> None:
        """Full shutdown wipe: identical behaviour to IRC client.
        Safe to call multiple times (idempotent via _cleaned_up flag)."""
        if self._cleaned_up:
            return
        self._cleaned_up = True
        self._signed_in = False                    # U1: the fingerprint goes dark first

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
        # L1: every session ended deniably above; its closing messages go
        # now, while the stream is still up (dropped if it is not).
        self._send_final_revelations()

        # 3. Wipe ephemeral channel log (key zeroed + .enc files deleted)
        try:
            if self.channel_log is not None:
                self.channel_log.close()
                self.channel_log = None
        except Exception:
            pass

        # 3b. Secure groups. /quit keeps them: the state is sealed to disk by
        #     Rust and every group secret is zeroized in memory. /wipe destroys
        #     them: Rust wipes the secrets and the state files are removed.
        groups = getattr(self, "_groups", None)
        wiping = bool(getattr(self, "_wipe_on_exit", False))
        keep_dir = None
        if groups is not None:
            try:
                if wiping:
                    groups.wipe()
                else:
                    groups.close()
                    keep_dir = os.path.realpath(_xmpp_state_path("groups"))
            except Exception:
                pass

        # 4. Overwrite and remove ~/.otrv4plus (fingerprints, trust DB, SMP).
        #    File-level only: on flash the old blocks are beyond our reach.
        #    Uses the same _secure_file_destroy function the IRC client uses.
        #    The ONE exception on /quit is the sealed secure-group state (3b).
        try:
            secure_destroy = getattr(_otr, "_secure_file_destroy", None)
            if secure_destroy:
                import glob as _glob
                otr_dir = os.path.expanduser("~/.otrv4plus")
                if os.path.isdir(otr_dir):
                    if wiping:
                        # /wipe means everything, dot-files included (the
                        # identity DEK, the SMP seed), which the glob below
                        # does not match. /quit keeps its old behaviour.
                        paths = [os.path.join(d, f) for d, _s, fs
                                 in os.walk(otr_dir) for f in fs]
                    else:
                        paths = _glob.glob(
                            os.path.join(otr_dir, "**", "*"), recursive=True)
                    for fpath in paths:
                        if keep_dir is not None and os.path.realpath(
                                fpath).startswith(keep_dir + os.sep):
                            continue
                        if os.path.isfile(fpath):
                            try:
                                secure_destroy(fpath)
                            except Exception:
                                pass
        except Exception:
            pass

def _expand(client, name):
    """`client.expand_jid`, for partial clients (tests) without it too."""
    fn = getattr(client, "expand_jid", None)
    return fn(name) if fn is not None else name




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
        # A /smp-secret prompt the USER armed is hidden the same way.  It is
        # a shared secret, not a command, and echoing it put it in scrollback
        # and in `script` captures of the session.
        #
        # Driven by the explicit request rather than by the mask flag: the
        # flag is a display concern that several things can set, and a hidden
        # read is not something a stray display state should be able to start.
        secret_prompt = (None if prompt
                         else (_SMP + " passphrase: "
                               if getattr(client, "_secret_request", None)
                               else None))
        try:
            if prompt:
                line = await loop.run_in_executor(
                    None, getpass.getpass, prompt)
            elif secret_prompt:
                line = await loop.run_in_executor(
                    None, getpass.getpass, secret_prompt)
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
        # Remember that the terminal has just echoed this line itself, and
        # that nothing has been printed since. `_echo_sent` uses both facts
        # to rewrite that echo in place instead of printing the message a
        # second time underneath it.
        client._plain_echo = (_term._PRINT_SEQ, line.rstrip("\n"))
        if not client.dispatch_line(client.peer, line.rstrip("\n")):
            break
    client._shutting_down = True
    client.disconnect()


# =============================================================================
# Entry point
# =============================================================================

class _RegistrationOnly:
    """What `ConnectionController.register` needs of an app: nothing arrives
    over a registration stream, so there is nothing to deliver."""

    def set_event_sink(self, _sink):
        pass

    def note_presence_lost(self):
        pass


def _register_account(args, password):
    """--register: create the account exactly as the apps' Create account
    does (`android_bridge.connection.ConnectionController.register`): the
    route decided the same way, the egress rule, the X1 destination check
    and SCRAM-only, the same codes and sentences. Exits on failure; the
    sign-in that follows uses the password just set."""
    if getattr(args, "insecure_tls", False):
        sys.exit("[register] Not with --insecure-tls: a new account's password is "
                 "never sent to a server whose certificate is not checked.")
    from android_bridge.connection import ConnectionController
    from android_bridge.settings import ConnectionProfile
    server = (args.server or "").strip()
    if args.port and int(args.port) != 5222:
        server = "%s:%d" % (server or _address.jid_domain(args.jid), int(args.port))
    transport = ("tor" if getattr(args, "tor", False)
                 else "clearnet_tls" if getattr(args, "no_i2p", False) else "auto")
    try:
        profile = ConnectionProfile(
            jid=args.jid, server=server, sam_host=args.sam_host,
            sam_port=int(args.sam_port), transport=transport,
            socks_host=args.socks_host, socks_port=int(args.socks_port))
    except Exception as exc:
        sys.exit("[register] %s" % exc)
    print("[register] creating %s ..." % args.jid)
    result = ConnectionController(_RegistrationOnly(), profile).register(password)
    if not result.get("ok"):
        sys.exit("[register] The account was not created: %s (%s)"
                 % (result.get("detail") or "no reason given", result.get("code") or "unknown"))
    if result.get("notice"):
        print("[register] %s" % result["notice"])
    print("[register] account created; signing in")


def _parser():
    """The command line. Kept apart so `main` reads as the steps it takes."""
    ap = argparse.ArgumentParser(
        description=f"OTRv4+ XMPP {XMPP_VERSION} - full OTR + SMP over I2P SAM"
    )
    ap.add_argument("--jid", required=True, help="your full JID")
    ap.add_argument(
        "--register",
        action="store_true",
        help="create the account on the server first (XEP-0077), then sign "
             "in: the same rules as the Android and desktop apps' Create "
             "account (SCRAM-only where certificates are not checked, the "
             "server's I2P destination pinned)",
    )
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
        help="accept expired/self-signed server certs on a CLEARNET server. "
             "Not needed for .i2p or .onion: there the address is the "
             "server's key and the transport authenticates the endpoint, so "
             "certificate checks are skipped automatically.",
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
    return ap


def _open_session_log(args):
    """Open the --debug session transcript, unless --no-log."""
    if args.debug and not args.no_log:
        log_path = args.log_file or os.path.expanduser(
            "~/.otrv4plus/logs/session-%s.log" % time.strftime("%Y%m%d-%H%M%S")
        )
        try:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            _term._SESSION_LOG_FH = open(log_path, "a", encoding="utf-8")
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


def _warn_if_domains_differ(jid, peer):
    """A --peer on a different server than --jid is almost always a typo.

    `_check_jid` accepts `bob@otrv4plus` -- one `@`, a non-empty local
    part, a non-empty domain, no doubled dots. Nothing about it is
    malformed. It is simply the wrong server, and a device run lost
    `.i2p` off the end of `--peer` and spent the whole session looking
    like a protocol bug: the outgoing DAKE was bounced by the server
    ("Communication with remote domains is not enabled"), the peer's own
    DAKE arrived and established a session under their REAL jid, and
    every command that acts on --peer then reported "no encrypted
    session ... Run /otr first" about a peer that was never reachable.

    Not fatal: federated XMPP across domains is perfectly ordinary, and
    this client should not refuse it. But both ends of an OTRv4+ pair are
    normally on the same server, and the servers this is used with reject
    remote domains outright, so a mismatch is worth stopping to read.
    """
    if not jid or not peer:
        return
    jid_domain = jid.partition("@")[2].lower()
    peer_domain = peer.partition("@")[2].lower()
    if jid_domain == peer_domain:
        return
    print("\n[peer] --jid and --peer are on DIFFERENT servers:")
    print("[peer]   --jid  %s   (server: %s)" % (jid, jid_domain))
    print("[peer]   --peer %s   (server: %s)" % (peer, peer_domain))
    if peer_domain and jid_domain.startswith(peer_domain):
        missing = jid_domain[len(peer_domain):]
        print("[peer] The peer's server looks like it is missing %r."
              % missing)
        print("[peer] Did you mean  --peer %s%s ?" % (peer, missing))
    print("[peer] Continuing, because federated XMPP is legitimate -- but "
          "if this")
    print("[peer] server does not allow remote domains, nothing you send "
          "will arrive.\n")


def _check_jid(value, label):
    # The rules live in otrv4plus_address so the Android settings screen
    # can apply the same ones without exiting a process it does not own.
    # The wording is unchanged; only who chooses to call sys.exit is.
    err = _address.jid_error(value, label)
    if err is not None:
        sys.exit(err)


def _choose_transport(args):
    """(server, use_i2p, use_tor) from the address and flags; exits on a contradiction."""
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
    if args.no_i2p and server_b32.endswith(".i2p"):
        sys.exit("[transport] %s is an I2P address but --no-i2p was given. "
                 "Refusing: without I2P there is no route to it, and trying "
                 "anyway would send the name to your resolver (N1)."
                 % server_b32)
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
    return server_b32, use_i2p, use_tor


def _configure_tls(client, args, server_b32, use_i2p, use_tor):
    """Certificate checks: decided by the transport, not by a flag."""
    # ── TLS: decided by the transport, not by a flag ─────────────────────
    #
    # Over I2P and over Tor-to-.onion the ADDRESS is a public key: a .b32.i2p
    # label is the hash of the destination's key, and a v3 onion name is the
    # key itself.  Reaching that address means reaching that key-holder, with
    # the transport's own end-to-end encryption in between.  There is no
    # certificate authority in the path and no MITM position for one to
    # defend against, so requiring a CA-valid certificate there is asking for
    # a weaker second name for a server already named by its key.
    #
    # Users had to pass --insecure-tls to get past that, on every single
    # connection.  A flag with "insecure" in it, typed daily, for a link that
    # is not insecure -- and the same habit carried to a clearnet server is
    # genuinely dangerous.  So the transport decides, the flag is not needed,
    # and clearnet still demands a real certificate.
    endpoint_authenticated_by = None
    if use_i2p:
        endpoint_authenticated_by = "I2P"
    elif use_tor and server_b32.endswith(".onion"):
        endpoint_authenticated_by = "Tor"

    relax_tls = bool(endpoint_authenticated_by) or args.insecure_tls
    if relax_tls:
        _restrict_to_scram(client)
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        client.ssl_context = ctx

    if endpoint_authenticated_by == "I2P":
        print("[tls] The endpoint is authenticated by I2P: the .b32.i2p "
              "address is the hash of")
        print("[tls] the server's key, so the connection reaches that key or "
              "it fails. Certificate")
        print("[tls] checks are not used here and are not needed; no "
              "--insecure-tls required.")
    elif endpoint_authenticated_by == "Tor":
        print("[tls] The endpoint is authenticated by Tor: a v3 onion name is "
              "the server's public")
        print("[tls] key. Certificate checks are not used here and are not "
              "needed.")
    elif args.insecure_tls:
        print(
            "[tls] WARNING: --insecure-tls on a CLEARNET connection disables "
            "certificate verification, so an active network attacker can MITM "
            "the link and capture your XMPP password. Over I2P and over Tor "
            "to an onion address the endpoint is authenticated by the address "
            "itself and the flag is unnecessary; over clearnet nothing "
            "replaces a CA-valid certificate."
        )
    else:
        print("[tls] certificate verification ON (clearnet).")

    if args.insecure_tls and endpoint_authenticated_by:
        print("[tls] --insecure-tls was passed and is not needed here; "
              "%s already authenticates the endpoint." % endpoint_authenticated_by)


def _store_reconnect(client, args, server_b32, use_i2p, use_tor):
    """What the client needs to reconnect the same way it first connected."""
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


def _restrict_to_scram(client):
    """Never send the password itself where the certificate is not checked
    (docs/SECURITY_ISSUES.md X1): SCRAM only, PLAIN off, as the app does
    (android_bridge.transport._restrict_to_scram, the same list)."""
    mech = client.plugin["feature_mechanisms"]
    mech.use_mechs = set(SCRAM_ONLY)
    mech.encrypted_plain = False      # PLAIN without TLS is off by default


#: Must equal android_bridge.transport.SCRAM_ONLY (tests/test_x1_terminal_client.py).
SCRAM_ONLY = frozenset({
    "SCRAM-SHA-512-PLUS", "SCRAM-SHA-512",
    "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256",
    "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1",
})


def _server_identity(name):
    """X1 for this client: (verify, confirm, pins) for the I2P server `name`.

    `verify(dest_b64)` runs between NAMING LOOKUP and STREAM CONNECT and
    raises DestinationChanged before any byte reaches a destination the
    rule refuses (android_bridge.server_pins.check_destination). `confirm()`
    pins a first-use or approved destination once sign-in succeeded.

    Raises PinsUnreadable at once, before anything is sent to the router,
    when the pins file will not open and this name would consult it
    (`ensure_pins_usable`, the app's rule; X1 residual 5, closed).
    """
    from android_bridge import server_pins as pins_mod
    pins = pins_mod.default_store()
    name = name.strip().lower()
    shipped = _address.shipped_server_address(name)
    typed_b32 = name.endswith(".b32.i2p")
    def preflight():
        pins_mod.ensure_pins_usable(name, pins, shipped=shipped,
                                    self_authenticating=typed_b32)

    def verify(dest_b64):
        seen = pins_mod.b32_of_destination(dest_b64)
        pins_mod.check_destination(name, seen, pins, shipped=shipped,
                                   self_authenticating=typed_b32)

    # The reconnect loop runs this before it asks the router for anything.
    verify.preflight = preflight
    preflight()

    def confirm():
        if not shipped and not typed_b32:
            pins.confirm(name)

    return verify, confirm, pins


def _ask_to_trust(changed, pins):
    """A pinned server name now resolves elsewhere: say so, and approve the
    new destination only if the user types it in full. True if approved."""
    print("\n[i2p] SECURITY: %s now resolves to a DIFFERENT I2P destination."
          % changed.name, file=sys.stderr)
    print("[i2p]   pinned : %s" % (changed.pinned or "-"), file=sys.stderr)
    print("[i2p]   now    : %s" % changed.seen, file=sys.stderr)
    print("[i2p] Nothing was sent to it. If the server's operator told you its "
          "address changed,", file=sys.stderr)
    if changed.name.endswith(".b32.i2p") or _address.shipped_server_address(changed.name):
        print("[i2p] this address cannot be approved here: it is fixed by the "
              "address you typed or by this version.", file=sys.stderr)
        return False
    try:
        typed = input("[i2p] type the new address in full to trust it "
                      "(anything else stops): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if typed != changed.seen:
        return False
    pins.approve(changed.name, changed.seen)
    return True


def _pins_unreadable(exc):
    """The server pins file will not open: say which, and stop before any
    byte reaches the router. Nothing is rewritten or replaced."""
    print("\n[i2p] SECURITY: the server pins file would not open (%s):"
          % exc.reason, file=sys.stderr)
    print("[i2p]   %s" % exc.path, file=sys.stderr)
    print("[i2p] Nothing was sent. Without it a changed server address could "
          "not be told from a first visit.", file=sys.stderr)
    print("[i2p] The file has not been changed. Move it aside, or restore it, "
          "and start again.", file=sys.stderr)
    sys.exit(1)


def _sam_failed(e, args):
    """The SAM bridge did not give us a stream: say why, and stop."""
    print(f"[i2p] SAM bridge failed: {e}", file=sys.stderr)
    # Only suggest checking the router when the router is what did
    # not answer.  A failure that came back FROM the router has
    # already been explained by _explain_stream_failure, and
    # repeating "is the b32 correct?" after it contradicts it.
    if "SAM stream connect failed" not in str(e):
        print(
            "[i2p] Is i2pd running with SAM enabled on "
            f"{args.sam_host}:{args.sam_port}?",
            file=sys.stderr,
        )
    sys.exit(1)


def _open_connection(client, args, server_b32, use_i2p, use_tor):
    """Open the tunnel the transport needs and connect through it. Fails closed."""
    loop = client.loop
    # N1: the route's rules for the whole process, before any socket. On
    # I2P and Tor only loopback and the configured bridge are reachable and
    # nothing is resolved; no .i2p or .onion name ever reaches DNS.
    import otrv4plus_egress as _egress
    kind = "i2p_sam" if use_i2p else "tor" if use_tor else "clearnet_tls"
    bridge = ((args.sam_host, args.sam_port) if use_i2p
              else (args.socks_host, args.socks_port) if use_tor else None)
    try:
        _egress.enter(kind, bridge=bridge)
    except _egress.EgressRefused as exc:
        sys.exit("[transport] %s" % exc)

    if use_i2p:
        # Remembered after a successful connection, so the 52-character b32 is
        # typed once.  Only a b32 is worth recording: a short name is what we
        # would be mapping FROM, and a name that resolved through the router
        # needs no local note.
        if server_b32.endswith(".b32.i2p"):
            client._i2p_server_dest = server_b32
        from android_bridge.server_pins import DestinationChanged, PinsUnreadable
        try:
            verify, client._confirm_server, pins = _server_identity(server_b32)
        except PinsUnreadable as unreadable:
            _pins_unreadable(unreadable)
        client._server_check = verify
        for attempt in (1, 2):
            try:
                host, port = loop.run_until_complete(
                    _tunnels.start_i2p_sam_forwarder(
                        server_b32,
                        args.port,
                        sam_host=args.sam_host,
                        sam_port=args.sam_port,
                        verify=verify,
                    )
                )
                break
            except DestinationChanged as changed:
                if attempt == 2 or not _ask_to_trust(changed, pins):
                    sys.exit(1)
            except Exception as e:
                _sam_failed(e, args)
        client.connect(host, port)
    elif use_tor:
        try:
            host, port = loop.run_until_complete(
                _tunnels.start_tor_socks_forwarder(
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


def _run_until_disconnected(client, args):
    """Run until disconnected, then clean up and deal with the transcript."""
    loop = client.loop
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
        if _term._SESSION_LOG_FH is not None:
            log_path = getattr(_term._SESSION_LOG_FH, "name", None)
            try:
                _term._SESSION_LOG_FH.close()
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


def main():
    # Not in --help on purpose: a server load test, for that server's admins
    # (the server enforces it -- see otrv4plus_stresstest).
    # Loaded by name so the APK, which ships this file, need not carry it.
    if "--stresstest" in sys.argv[1:]:
        import importlib
        stress = importlib.import_module("otrv4plus_stresstest")
        sys.exit(stress.main([a for a in sys.argv[1:] if a != "--stresstest"]))
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

    # The compiled core is versioned separately from this file, and `git pull`
    # updates only one of them.  A mismatch used to surface as an AttributeError
    # inside an executor thread at the first /smp, worded as though SMP had
    # failed.  Say it here instead, once, in terms of what to rebuild.
    _coreapi.verify_core_api()

    args = _parser().parse_args()

    # ---- Device provisioning (Termux only; a no-op elsewhere) ----
    _setup_issues = _termux._bootstrap_termux(
        skip=args.skip_setup,
        force=args.force_setup,
        sam_host=args.sam_host,
        sam_port=args.sam_port,
        load_opus=_load_opus,
        voice_available=voice_available,
    )
    if args.setup_only:
        sys.exit(1 if _setup_issues else 0)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)-8s %(message)s",
    )

    _open_session_log(args)

    # Validate the addresses BEFORE prompting for a password. A malformed JID
    # otherwise surfaces as a slixmpp stringprep traceback after the user has
    # already typed their password — unreadable, and it discards the input.
    _check_jid(args.jid, "--jid")
    _check_jid(args.peer, "--peer")
    _warn_if_domains_differ(args.jid, args.peer)

    # An account on the project server's b32 is an account on its NAME: the
    # server hosts otrv4plus.i2p and answers host-unknown to a stream
    # addressed to the b32. Same rule as the Android app
    # (android_bridge.settings.ConnectionProfile).
    _canonical = _address.canonical_jid(args.jid)
    if _canonical != args.jid:
        args.jid = _canonical
        print(f"[i2p] signing in as {args.jid} (the server's accounts live "
              "on its name, not on its .b32.i2p address)")

    password = getpass.getpass(f"Password for {args.jid}: ")
    if args.register:
        if getpass.getpass("Same password again: ") != password:
            sys.exit("[register] The two passwords differ; nothing was sent.")
        _register_account(args, password)
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

    server_b32, use_i2p, use_tor = _choose_transport(args)
    _configure_tls(client, args, server_b32, use_i2p, use_tor)
    _store_reconnect(client, args, server_b32, use_i2p, use_tor)
    _open_connection(client, args, server_b32, use_i2p, use_tor)
    _run_until_disconnected(client, args)


if __name__ == "__main__":
    main()
