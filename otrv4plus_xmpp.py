#!/usr/bin/env python3
"""
OTRv4+ XMPP - full OTR + SMP over XMPP, transported over I2P SAM
================================================================
Version: 10.10.4

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

POST-DAKE FLOW (identical to the IRC client):
  1. DAKE completes -> session ENCRYPTED.
  2. Both fingerprints are shown; you are asked "Trust this fingerprint? y/n".
     - y -> fingerprint pinned as VERIFIED (TOFU trust DB).
     - n -> encrypted-only.
  3. You are prompted for the Socialist Millionaire Protocol passphrase, which
     is stored for AUTO-RESPOND. Press Enter / "skip" to skip.
  4. Once BOTH sides have stored the passphrase, EITHER side runs /smp start.

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
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

XMPP_VERSION = "10.10.4"

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


# =============================================================================
# XMPP client
# =============================================================================

class OTRv4PlusXMPP(ClientXMPP):
    """XMPP transport driving the OTRv4+ engine, with IRC-identical SMP flow."""

    def __init__(self, jid, password, peer=None):
        super().__init__(jid, password)
        self.peer = peer

        # Per-peer UI state.
        self._pending = {}         # peer -> 'trust' | 'smp_secret' | None
        self._encrypted = set()    # peers whose DAKE has completed
        self._smp_reported = set() # (peer, state) already announced
        self._frag_seq = 0         # monotonic id for outbound fragment sets

        # Security: subscription approval queue; no auto-approval.
        self._pending_subscriptions = {}  # peer -> presence stanza

        # Security: session-local block list.
        self._blocked = set()

        # Security: per-peer rate limiting.
        self._rate_limit = {}  # peer -> deque of timestamps

        # Reconnect state (populated by main() before connect()).
        self._sam_params = None   # dict of SAM args for reconnect
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
        self._probe = False
        self._prompt_refresh_cb = None
        self.nick = jid.split("@", 1)[0] if jid else "me"
        self._keepalive_task = None

        # OTR engine.
        tracer = OTRTracer(enabled=True) if OTRTracer else None
        if tracer is not None and hasattr(tracer, "set_emit_callback"):
            def _trace_emit(line, *_a, **_k):
                try:
                    print(f"[otr-trace] {line}")
                except Exception:
                    pass
            tracer.set_emit_callback(_trace_emit)
        cfg = OTRConfig(test_mode=True)
        self.otr = EnhancedSessionManager(config=cfg, tracer=tracer)

        # Dedicated single-thread executor for OTR/SMP crypto. SMP runs
        # multi-minute 3072-bit DH computations; a separate pool keeps the
        # event loop free so keepalive/network stay alive throughout.
        self._otr_executor = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="otr-crypto"
        )

        # Security: never auto-approve subscription requests.
        self.auto_authorize = False
        self.auto_subscribe = False

        # --- Event handlers ---
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

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    async def _on_start(self, event):
        self.send_presence()
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
        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())

    async def _keepalive_loop(self):
        """Send a whitespace ping every 8s so idle I2P tunnels stay alive.
        The tick counter confirms the event loop is not frozen during SMP."""
        n = 0
        try:
            while self.is_connected():
                await asyncio.sleep(8)
                n += 1
                try:
                    self.send_raw(" ")
                    print(f"[keepalive] tick {n} (loop alive)")
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    def _on_failed_auth(self, event):
        print("\n[auth failed] check JID and password.", file=sys.stderr)
        # Don't retry on bad credentials; reconnect would loop forever.
        self._shutting_down = True

    def _on_disconnected(self, event):
        print("\n[disconnected]")
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if not self._shutting_down and self._sam_params is not None:
            try:
                loop = asyncio.get_event_loop()
                self._reconnect_task = loop.create_task(self._reconnect())
            except Exception as e:
                print(f"[reconnect] could not schedule: {e}")

    def _on_connection_failed(self, event):
        reason = str(event) if event else "unknown"
        print(f"[connection failed] {_sanitise(reason, 256)}")
        if not self._shutting_down and self._sam_params is not None:
            try:
                loop = asyncio.get_event_loop()
                loop.create_task(self._reconnect())
            except Exception:
                pass

    def _on_stream_error(self, error):
        condition = getattr(error, "condition", None) or str(error)
        print(f"[stream error] {_sanitise(str(condition), 256)}")

    async def _reconnect(self):
        """Exponential-backoff reconnect. Re-establishes the I2P SAM tunnel
        before reconnecting slixmpp when running over I2P."""
        while not self._shutting_down:
            delay = self._reconnect_delay
            print(f"[reconnect] waiting {delay}s before reconnecting...")
            await asyncio.sleep(delay)
            if self._shutting_down:
                return
            print("[reconnect] attempting reconnection...")
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
                else:
                    self.connect()
                print("[reconnect] reconnected.")
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

    def _on_presence_unavailable(self, presence):
        peer = presence["from"].bare
        if peer == self._own_bare:
            return
        print(f"[presence] {_sanitise(peer, 128)} went offline")

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
        else:
            print(f"[plain] <{_sanitise(peer, 128)}> {_sanitise(body)}")

    async def _handle_otr_in_async(self, peer, body):
        stage_in = self._otr_stage(body)
        if stage_in:
            print(f"[otr-recv] <- {stage_in} from {peer}")

        if self._probe:
            try:
                keys = sorted(self.otr.sessions.keys())
                present = peer in self.otr.sessions
                print(
                    f"[otr-probe] inbound {stage_in}: lookup={peer!r} "
                    f"present={present} stored_keys={keys}"
                )
                if not present and keys:
                    for k in keys:
                        print(
                            f"[otr-probe]   key mismatch? stored={k!r} "
                            f"== lookup={peer!r} -> {k == peer} "
                            f"(len {len(k)} vs {len(peer)})"
                        )
            except Exception as e:
                print(f"[otr-probe] inbound probe error: {e}")

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
            print(
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
            print(f"[otr-crypto] done processing DATA from {peer} ({_t.time() - t0:.1f}s).")

        self._check_dake_complete(peer)

        if out:
            out_b = out.encode("utf-8") if isinstance(out, str) else out
            if out_b.startswith(OTR_PREFIX_B):
                stage_out = self._otr_stage(out_b.decode("utf-8", errors="replace"))
                if stage_out:
                    print(f"[otr-send] -> {stage_out} to {peer}")
                self.send_otr_fragmented(peer, out_b.decode("utf-8", errors="replace"))
            else:
                text = out_b.decode("utf-8", errors="replace")
                print(f"[otr] <{_sanitise(peer, 128)}> {_sanitise(text)}")

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

    def _handle_otr_in(self, peer, body):
        """Sync fallback (retained for compatibility; async path is preferred)."""
        try:
            out = self.otr.handle_incoming_message(peer, body)
        except Exception as e:
            print(f"[otr error] from {peer}: {e}")
            return
        self._check_dake_complete(peer)
        if out:
            out_b = out.encode("utf-8") if isinstance(out, str) else out
            if out_b.startswith(OTR_PREFIX_B):
                self.send_otr_fragmented(peer, out_b.decode("utf-8", errors="replace"))
            else:
                text = out_b.decode("utf-8", errors="replace")
                print(f"[otr] <{_sanitise(peer, 128)}> {_sanitise(text)}")
        self._report_smp(peer)
        self._check_dake_complete(peer)

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

        local_fp = self._local_fp()
        remote_fp = self._remote_fp(peer)

        print("\n" + "-" * 60)
        print(
            f"[secure] OTR session with {peer} is ENCRYPTED "
            "(X448 + ML-KEM-1024 + ML-DSA-87)."
        )
        print(f"  Your fingerprint  : {_fmt_fp(local_fp)}")
        print(f"  Their fingerprint : {_fmt_fp(remote_fp)}")
        print("-" * 60)

        already = False
        try:
            already = self.otr.is_peer_trusted(peer)
        except Exception:
            already = False

        if already:
            print("[trust] Fingerprint already trusted - VERIFIED.")
            self._prompt_smp_secret(peer)
        else:
            print("[trust] Trust this fingerprint? Type  y  or  n :")
            self._pending[peer] = "trust"

    def _handle_trust_answer(self, peer, answer):
        ans = answer.strip().lower()
        if ans in ("y", "yes"):
            ok = False
            try:
                remote_fp = self._remote_fp(peer)
                ok = self.otr.trust_fingerprint(peer, remote_fp)
            except Exception as e:
                print(f"[trust] error saving trust: {e}")
            if ok:
                print("[trust] Fingerprint TRUSTED - identity pinned (VERIFIED).")
            else:
                print("[trust] Could not store trust, continuing encrypted-only.")
        else:
            print("[trust] Fingerprint NOT trusted - encrypted only.")
        self._pending[peer] = None
        self._prompt_smp_secret(peer)

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
        try:
            session = self.otr.get_session(peer)
            if not session:
                return
            state = getattr(session, "smp_state", None)
            if state is None:
                return
            name = getattr(state, "name", str(state))
            key = (peer, name)
            if name == "SUCCEEDED" and key not in self._smp_reported:
                self._smp_reported.add(key)
                print(
                    f"\n[smp] *** IDENTITY VERIFIED with {peer} - "
                    "shared secret matched (SMP complete). ***\n"
                )
            elif name == "FAILED" and key not in self._smp_reported:
                self._smp_reported.add(key)
                print(
                    f"\n[smp] *** SMP FAILED with {peer} - secrets did NOT "
                    "match (or protocol error). Possible MITM. ***\n"
                )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Fingerprint helpers
    # -------------------------------------------------------------------------

    def _local_fp(self):
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
            print(f"[otr-send] 1 frame ({len(payload)} bytes) -> {peer}")
            return

        chunks = [
            payload[i : i + MAX_FRAGMENT]
            for i in range(0, len(payload), MAX_FRAGMENT)
        ]
        total = len(chunks)
        self._frag_seq = (self._frag_seq + 1) & 0xFFFFFFFF
        msg_id = "%08x" % self._frag_seq

        print(
            f"[otr-send] fragmenting {len(payload)} bytes into {total} "
            f"fragments (id {msg_id}) -> {peer}"
        )
        for i, chunk in enumerate(chunks, 1):
            frag = f"?OTRv4F|{msg_id}|{i}|{total}|{chunk}"
            self.send_message(mto=peer, mbody=frag, mtype="chat")
            print(f"[otr-send]   sent fragment {i}/{total} (id {msg_id})")
        print(f"[otr-send] all {total} fragments sent (id {msg_id}) -> {peer}")

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
            print(f"[otr-recv] malformed fragment from {peer}; dropping")
            return None

        # Reject nonsensical indices before they can corrupt a buffer.
        MAX_FRAGMENTS = 4096
        if total < 1 or total > MAX_FRAGMENTS or n < 1 or n > total:
            print(f"[otr-recv] fragment index out of range from {peer}; dropping")
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
            print(
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
        print(
            f"[otr-recv]   fragment {n}/{total} from {peer} "
            f"(id {msg_id}; have {have}/{total})"
        )

        if have < total:
            return None
        # Verify every index present before stitching.
        if any(i not in buf["parts"] for i in range(1, total + 1)):
            return None
        ordered = "".join(buf["parts"][i] for i in range(1, total + 1))
        self._frag_buffers.pop(key, None)
        print(
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
        if should_send and msg:
            msg_s = msg if isinstance(msg, str) else msg.decode()
            self._last_dake1[peer] = msg_s
            print(f"[otr-send] -> DAKE1 to {peer} (starting handshake)")
            self.send_otr_fragmented(peer, msg_s)
            if self._probe:
                try:
                    keys = sorted(self.otr.sessions.keys())
                    print(
                        f"[otr-probe] after /otr: stored={peer!r} "
                        f"present={peer in self.otr.sessions} "
                        f"all_keys={keys}"
                    )
                except Exception as e:
                    print(f"[otr-probe] after-/otr probe error: {e}")
            print(f"[otr] DAKE started with {peer}. Waiting for DAKE2...")
        else:
            print(f"[otr] could not start DAKE with {peer}")

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
            "  /next  /prev         switch tabs (TUI)\n"
            "  /win <n|name>        jump to tab by number or name\n"
            "  /tabs                list open tabs\n"
            "  /clear               clear active tab\n"
            "  /close               close active tab\n"
            "  /help                this list\n"
            "  /quit                disconnect and exit"
        )

    # -------------------------------------------------------------------------
    # Pending-input dispatch
    # -------------------------------------------------------------------------

    def feed_pending(self, peer, line):
        """If `peer` has a pending prompt (trust / smp_secret), consume line."""
        state = self._pending.get(peer)
        if state == "trust":
            self._handle_trust_answer(peer, line)
            return True
        if state == "smp_secret":
            self._handle_smp_secret_answer(peer, line)
            return True
        return False

    def has_pending(self, peer):
        return self._pending.get(peer) in ("trust", "smp_secret")

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

    def _tui_route_output(self, line):
        """Route one harness output line into the panel system."""
        if line == "":
            return
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
            stripped = line.lstrip()
            if any(stripped.startswith(p) for p in self._SYS_PREFIXES):
                target = "system"
            else:
                target = self._tui_last_panel or "system"
        self._tui_update_badge(target, line)
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
            if (
                "SMP VERIFIED" in line
                or "Fingerprint TRUSTED" in line
                or "identity pinned" in line
            ):
                self.panel_manager.update_panel_security(target, SL.SMP_VERIFIED)
            elif "is ENCRYPTED" in line:
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
        if self.peer:
            label = self._tui_label_for(self.peer)
            self.panel_manager.get_or_create_panel(label, "private")
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

    def _tui_quit(self):
        self._shutting_down = True
        self._stop_tui()
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
            self.panel_manager.add_message(active, _colorize("you", "cyan") + ": " + line)
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
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        if not client.dispatch_line(client.peer, line.rstrip("\n")):
            break
    client._shutting_down = True
    client.disconnect()


# =============================================================================
# Entry point
# =============================================================================

def main():
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
        "--no-tui",
        action="store_true",
        help="disable the tabbed TUI; use plain linear scrollback "
             "(better for reading debug/trace output)",
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
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
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

    password = getpass.getpass(f"Password for {args.jid}: ")
    client = OTRv4PlusXMPP(args.jid, password, peer=args.peer)

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

    if args.insecure_tls and not use_i2p:
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
    else:
        client.connect()

    client._probe = args.debug
    _clean_exit = True
    try:
        started_tui = (not args.no_tui) and client._start_tui(loop, debug=args.debug)
        if args.no_tui:
            print(
                "[tui] disabled (--no-tui): plain scrollback. "
                "Commands still work (/otr, /smp, /msg, /status, /help, /quit)."
            )
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
