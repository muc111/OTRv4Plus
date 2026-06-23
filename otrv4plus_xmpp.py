#!/usr/bin/env python3
"""
OTRv4+ XMPP - full OTR + SMP over XMPP, transported over I2P SAM
================================================================

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

POST-DAKE FLOW (identical to the IRC client):
  1. DAKE completes -> session ENCRYPTED.
  2. Both fingerprints are shown; you are asked "Trust this fingerprint? y/n".
     - y -> fingerprint pinned as VERIFIED (TOFU trust DB).
     - n -> encrypted-only.
  3. You are prompted for the Socialist Millionaire Protocol passphrase, which
     is stored for AUTO-RESPOND (so the peer can start SMP and this side
     answers automatically). Press Enter / "skip" to skip.
  4. Once BOTH sides have stored the passphrase, EITHER side runs  /smp start
     to begin verification. On success both print  SMP VERIFIED.

USAGE:
    pip install slixmpp aiodns
    python otrv4plus_xmpp.py \
      --jid alice@<vhost>.b32.i2p \
      --server <c2s-tunnel>.b32.i2p \
      --peer bob@<vhost>.b32.i2p \
      --insecure-tls --debug

COMMANDS:
    /otr [jid]           start an OTR session (DAKE)
    y / n                answer the trust-fingerprint prompt
    <passphrase>         answer the SMP passphrase prompt (stores for auto-respond)
    /smp start           begin SMP verification (after both sides stored a secret)
    /smp <secret>        store a secret AND immediately start SMP
    /smp-secret <secret> store a secret for auto-respond (no start)
    /trust               re-show fingerprints and the trust prompt
    /msg <jid> <text>    send plaintext (no OTR)
    /status              show session + trust + SMP state for --peer
    /quit                disconnect and exit
    <text>               send to --peer (auto-encrypts once OTR is up)
"""

# =============================================================================
#  SECURITY MODEL (enforced throughout this file):
#    * All cryptography lives in the Rust core (otrv4_core) via the shared
#      EnhancedSessionManager. This transport never holds key material and never
#      implements a primitive; it moves "?OTRv4 <base64>" frames and renders UI.
#    * Every piece of untrusted data shown on the terminal (peer JIDs, plaintext
#      bodies, and DECRYPTED OTR payloads) passes through _sanitise(), which
#      strips ANSI/OSC/CSI escape sequences, C0/C1 controls, and newlines. This
#      blocks terminal-title hijack, cursor manipulation, and forged log lines
#      from a hostile peer or server, even over the encrypted channel.
#    * Inbound message fragments are bounded (index range, fragment count, and a
#      per-peer reassembly cap) before stitching, preventing memory-exhaustion
#      DoS and out-of-range indexing. See _reassemble_fragment.
#    * TLS verification is on by default; it is only disabled behind the explicit
#      --insecure-tls opt-in, intended for a self-signed server reached over an
#      already authenticated I2P tunnel (the .b32 destination is the key hash).
#    * Fingerprints are pinned on first use (TOFU); the trust prompt gates the
#      transition to a VERIFIED session.
#
#  Audited for: shell/command injection, escape-sequence injection, ReDoS,
#  unsafe deserialisation, weak hashing, and insecure randomness. None present:
#  no eval/exec, no pickle/marshal, no shell=True, no user-compiled regexes,
#  no md5/sha1, and no use of the `random` module for any security decision.
# =============================================================================

import argparse
import asyncio
import builtins
import getpass
import logging
import os
import re
import sys
import time

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
        "Ensure otrv4+.py, the otrv4plus.py symlink, and otrv4_core.so are " "in this directory.",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Terminal UI - REUSES the engine's own ANSI TUI (PanelManager / Screen / raw
# line editor), the same one the IRC client uses. We do NOT reimplement any of
# it; we just drive it. These are all module-level in the engine.
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

# When the TUI is active, the harness's plain print() output is routed into the
# panel system instead of scribbling over the engine's screen. We shadow the
# builtin `print` at MODULE scope, so every print(...) in THIS file (and only
# this file) goes through here; the engine renders via its own sys.stdout.
_ACTIVE_TUI_CLIENT = None

# Full session transcript, written to disk as plain text, independent of the
# TUI's repainting. The TUI clears+repaints the terminal on every update
# (\033[2J\033[H), which on mobile terminals (Termux) destroys the native
# scrollback for anything painted via cursor-addressing rather than normal
# newline scroll -- so once a panel scrolls off-screen it's gone from view,
# even though it's still sitting in memory (ChatPanel.history is never
# trimmed). This file is the reliable way to read back everything: it can be
# tailed live from a second Termux session (`tail -f <path>`) or opened after
# the fact, fully scrollable.
#
# Only written under --debug (see main()), stored under ~/.otrv4plus/logs/
# alongside the rest of the local OTR state (keys, trust.json), and deleted
# automatically on a clean exit -- it's a debug aid, not a permanent
# plaintext transcript of conversations. If the session crashes instead, the
# file is kept on purpose so the failure is diagnosable; --keep-log keeps it
# even after a clean exit.
_SESSION_LOG_FH = None
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _sanitise(text, max_len: int = 1024) -> str:
    """Strip ANSI/OSC/CSI escape sequences and control characters from
    untrusted data (peer JIDs, plaintext bodies, and DECRYPTED OTR payloads)
    before it is written to the terminal.

    A decrypted message is fully peer-controlled; without this a hostile peer
    could hijack the terminal title (OSC), move the cursor, or inject control
    codes through an "encrypted" message. Because this client prints one line
    per message, newlines and carriage returns are also stripped so a body
    cannot forge additional log lines (e.g. a fake "[system]" notice). Mirrors
    the IRC client's _sanitise(). Printable Unicode (incl. emoji) is preserved.
    """
    text = str(text)
    # OSC / DCS / PM / APC strings, terminated by BEL or ST (e.g. title hijack).
    text = re.sub(r"\x1b[P\]X^_][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    # CSI sequences (cursor movement, colours, erase line/display, ...).
    text = re.sub(r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", "", text)
    # Two-character Fe escapes.
    text = re.sub(r"\x1b[\x20-\x2f][\x30-\x7e]", "", text)
    text = re.sub(r"\x1b.", "", text, flags=re.DOTALL)
    # Remaining C0/C1 controls and DEL, including newlines/CR (keep only tab).
    text = re.sub(r"[\x00-\x08\x0a-\x1f\x7f\x80-\x9f]", "", text)
    return text[:max_len]


def _log_to_file(msg):
    if _SESSION_LOG_FH is None:
        return
    try:
        clean = _ANSI_RE.sub("", msg)
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
SMP_MIN_LEN = 1  # the engine enforces its own minimum; we just avoid empty

# Matches a bare JID (localpart@domain) for routing output lines to panels.
_JID_PATTERN = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+")


def _fmt_fp(fp: str) -> str:
    """Format a fingerprint as space-separated groups of 8 (like the IRC client)."""
    if not fp or fp == "unavailable":
        return fp or "unavailable"
    clean = fp.upper().replace(" ", "")
    # OTRv4 fingerprints are long (SHA3-512 hex); group in 8s for readability.
    return " ".join(clean[i : i + 8] for i in range(0, len(clean), 8))


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
            "I2PSAMConnection not available from the OTR module; " "cannot use I2P SAM transport."
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

    # I2P tunnels can drop a stream when a large message (e.g. a ~16KB SMP
    # stanza) is written as one burst - the DAKE (~4KB) survives but SMP does
    # not. The IRC client never hits this because IRC fragments big messages
    # into many tiny lines, which paces the data. We get the same gentle pacing
    # WITHOUT changing the XMPP wire format by writing to the SAM stream in
    # small chunks with a brief yield between them. The peer still receives one
    # XMPP stanza; only our local->I2P feed is paced.
    SAM_CHUNK = 1024  # bytes per write toward I2P
    SAM_CHUNK_DELAY = 0.02  # seconds between chunks on large messages

    async def _handle_local(local_reader, local_writer):
        async def pump_to_i2p(src, dst):
            """local (slixmpp) -> I2P, paced in small chunks for big messages."""
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
            """I2P -> local (slixmpp), as fast as it arrives."""
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


class OTRv4PlusXMPP(ClientXMPP):
    """XMPP transport driving the OTRv4+ engine, with IRC-identical SMP flow."""

    def __init__(self, jid, password, peer=None):
        super().__init__(jid, password)
        self.peer = peer

        # Per-peer UI state:
        #   self._pending[peer] = 'trust' | 'smp_secret' | None
        self._pending = {}
        self._encrypted = set()  # peers whose DAKE has completed
        self._smp_reported = set()  # (peer, state) already announced
        self._frag_seq = 0  # monotonic id for outbound fragment sets

        # Terminal-UI state (engine TUI is attached lazily in _start_tui).
        self.panel_manager = None
        self._screen = None
        self._tui_enabled = False
        self._tui_last_panel = None
        self._tui_autofocused = False  # focus the first peer tab exactly once
        self._tui_jid_by_label = {}  # short tab label -> full peer JID
        self._tui_label_by_jid = {}  # full peer JID -> short tab label
        self._own_bare = jid.split("/", 1)[0] if jid else ""  # never tab-route to self
        self._probe = False  # --debug: trace session presence around DAKE
        self._last_dake1 = {}  # peer -> our last DAKE1 (for glare re-send)
        self._prompt_refresh_cb = None
        self.nick = jid.split("@", 1)[0] if jid else "me"

        tracer = OTRTracer(enabled=True) if OTRTracer else None
        if tracer is not None and hasattr(tracer, "set_emit_callback"):
            # Route OTR-internal traces to the terminal so we can see SMP
            # state transitions and the exact reason any SMP message is
            # rejected (NO_SECRET, out-of-sequence, ZKP/ML-DSA verify fail…).
            def _trace_emit(line, *_a, **_k):
                try:
                    print(f"[otr-trace] {line}")
                except Exception:
                    pass

            tracer.set_emit_callback(_trace_emit)
        cfg = OTRConfig(test_mode=True)
        self.otr = EnhancedSessionManager(config=cfg, tracer=tracer)

        # Dedicated single-thread executor for OTR/SMP crypto. SMP runs
        # multi-minute 3072-bit DH computations; we must NOT run them on the
        # default executor because stdin.readline also lives there and blocks
        # forever, which would starve the crypto. A separate pool keeps the
        # event loop free (so keepalive/network stay alive) AND guarantees the
        # SMP work always has a worker.
        from concurrent.futures import ThreadPoolExecutor

        self._otr_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="otr-crypto")

        self.auto_authorize = True
        self.auto_subscribe = True

        self.add_event_handler("session_start", self._on_start)
        self.add_event_handler("message", self._on_message)
        self.add_event_handler("failed_auth", self._on_failed_auth)
        self.add_event_handler("message_error", self._on_message_error)
        self.add_event_handler("disconnected", self._on_disconnected)
        self.add_event_handler("presence_subscribe", self._on_subscribe)
        self.add_event_handler("presence_subscribed", self._on_subscribed)

        self.register_plugin("xep_0030")
        self.register_plugin("xep_0199")  # ping (used for keepalive)
        self.register_plugin("xep_0085")

        self._keepalive_task = None

    # ---------- lifecycle ----------

    async def _on_start(self, event):
        self.send_presence()
        try:
            await self.get_roster()
        except (IqError, IqTimeout):
            pass
        print(f"\n[connected] {self.boundjid.full}")
        if self.peer:
            self.send_presence_subscription(pto=self.peer)
            print(f"[subscribe] requested presence from {self.peer}")
        print(
            "[ready] /otr to start encryption. After DAKE you'll be asked to "
            "trust the fingerprint, then to set the SMP passphrase. /quit to exit.\n"
        )
        # Start XMPP-level keepalive so idle I2P tunnels stay up.
        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())

    async def _keepalive_loop(self):
        """Send a periodic XMPP whitespace ping so the I2P SAM stream is never
        idle - especially important during the minutes-long SMP DH computations,
        when no application data flows but the tunnel must stay alive. The
        counter lets us SEE in the log that the event loop is still running
        while the SMP crypto executes in the background thread."""
        n = 0
        try:
            while self.is_connected():
                await asyncio.sleep(8)
                n += 1
                try:
                    self.send_raw(" ")
                    # Quiet single-line heartbeat; if these stop appearing
                    # during SMP, the loop has frozen.
                    print(f"[keepalive] tick {n} (loop alive)")
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    def _on_failed_auth(self, event):
        print("\n[auth failed] check JID and password.", file=sys.stderr)

    def _on_disconnected(self, event):
        print("\n[disconnected]")
        if self._keepalive_task:
            self._keepalive_task.cancel()

    def _on_message_error(self, msg):
        peer = msg["from"].bare
        text = msg["error"]["text"] or msg["error"]["condition"]
        print(f"\n[delivery rejected] to {_sanitise(peer, 128)}: {_sanitise(text)}")
        if msg["error"]["condition"] == "forbidden":
            print(
                "  -> not mutually subscribed; both accounts must accept each "
                "other as contacts.\n"
            )

    # ---------- subscription handshake ----------

    def _on_subscribe(self, presence):
        peer = presence["from"].bare
        print(f"[sub] {peer} requested subscription - approving")
        self.send_presence(pto=peer, ptype="subscribed")
        self.send_presence(pto=peer, ptype="subscribe")
        self.send_presence(pto=peer)

    def _on_subscribed(self, presence):
        peer = presence["from"].bare
        print(f"[sub] {peer} approved our subscription")
        self.send_presence(pto=peer)

    # ---------- inbound message routing ----------

    def _on_message(self, msg):
        if msg["type"] not in ("chat", "normal"):
            return
        peer = msg["from"].bare
        body = msg["body"]
        if not body:
            return

        # Inbound fragment? Buffer it; only proceed once fully reassembled.
        if body.startswith("?OTRv4F|"):
            full = self._reassemble_fragment(peer, body)
            if full is None:
                return  # waiting for more fragments
            body = full  # reassembled into a complete ?OTRv4 ... frame

        if body.startswith(OTR_PREFIX):
            # OTR processing (especially SMP) can run multi-minute 3072-bit DH
            # computations that BLOCK. If we ran them inline we'd freeze the
            # asyncio event loop, the keepalive couldn't fire, and the I2P
            # tunnel would time out ("unexpected eof") right in the middle of
            # SMP. So we offload to a thread and schedule result-handling back
            # on the loop - exactly how the IRC client keeps its network loop
            # responsive during the long SMP computations.
            asyncio.ensure_future(self._handle_otr_in_async(peer, body))
        else:
            print(f"[plain] <{_sanitise(peer, 128)}> {_sanitise(body)}")

    async def _handle_otr_in_async(self, peer, body):
        # Announce what kind of OTR message we received.
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

        # --- Glare resolution -------------------------------------------------
        # A DAKE1 arriving while we already have our OWN outgoing DAKE in
        # progress means both sides ran /otr. Over slow I2P this is common: our
        # DAKE1 hasn't reached them yet, so they start one too. The engine has
        # no tie-break - it rejects the incoming DAKE1 ("DAKE1 REJECTED,
        # DAKE_IN_PROGRESS") and both sides deadlock. Resolve it deterministically
        # by bare JID: the LOWER JID keeps the initiator role; the HIGHER yields,
        # tears down its half-built session, and answers as the responder. Both
        # sides run identical code, so exactly one yields.
        if stage_in == "DAKE1":
            sess = self.otr.get_session(peer)
            st = getattr(getattr(sess, "session_state", None), "name", "")
            is_init = bool(getattr(sess, "is_initiator", False))
            if sess is not None and st == "DAKE_IN_PROGRESS" and is_init:
                if self._own_bare < peer:
                    # We win the tie. Ignore their DAKE1, but RE-SEND ours so a
                    # dropped/late first DAKE1 still reaches them - otherwise they
                    # may never learn to yield. They will answer with DAKE2.
                    print(
                        f"[otr] simultaneous start with {peer}: keeping "
                        f"initiator role; re-sending our DAKE1"
                    )
                    d1 = self._last_dake1.get(peer)
                    if d1:
                        self.send_otr_fragmented(peer, d1)
                    return
                # We lose the tie: drop our attempt and respond as the responder.
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
                # fall through: handle_incoming_message now builds a fresh
                # responder session and returns DAKE2.
        # ----------------------------------------------------------------------
        # If this is a DATA message it may carry an SMP TLV whose response
        # requires a multi-minute 3072-bit DH computation. Log entry/exit so we
        # can see on each side exactly when the heavy crypto runs - and confirm
        # the event loop stayed alive (keepalives keep printing) throughout.
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

            print(f"[otr-crypto] done processing DATA from {peer} " f"({_t.time() - t0:.1f}s).")

        # Detect a freshly-encrypted session and run the trust prompt (once).
        self._check_dake_complete(peer)

        if out:
            out_b = out.encode("utf-8") if isinstance(out, str) else out
            if out_b.startswith(OTR_PREFIX_B):
                # OTR reply to send: DAKE2/DAKE3, or an SMP auto-response
                # (SMP2/SMP3/SMP4). Sending it back is what advances the
                # handshake / SMP chain to completion.
                stage_out = self._otr_stage(out_b.decode("utf-8", errors="replace"))
                if stage_out:
                    print(f"[otr-send] -> {stage_out} to {peer}")
                self.send_otr_fragmented(peer, out_b.decode("utf-8", errors="replace"))
            else:
                text = out_b.decode("utf-8", errors="replace")
                print(f"[otr] <{_sanitise(peer, 128)}> {_sanitise(text)}")

        # Surface SMP state changes (VERIFIED / FAILED) and re-check DAKE.
        self._report_smp(peer)
        self._check_dake_complete(peer)

    @staticmethod
    def _otr_stage(frame):
        """Identify the OTRv4 message stage (DAKE1/2/3, DATA) from a
        '?OTRv4 <base64>' frame, for progress display. Best-effort.

        Wire layout (matches the engine's _handle_otr_message):
          * DAKE messages: byte[0] IS the type (0x35/0x36/0x37).
          * DATA messages: 3-byte header 0x00 0x04 0x03, so byte[2] is the
            DATA type and byte[0:2] is the version 0x0004.
        """
        import base64 as _b64

        try:
            if not frame.startswith(OTR_PREFIX):
                return None
            payload = frame[len(OTR_PREFIX) :].strip()
            if payload.endswith("."):
                payload = payload[:-1]
            try:
                decoded = _b64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            except Exception:
                # Fallback: normalise the url-safe alphabet to standard first so
                # '-'/'_' aren't silently dropped (this is display-only, but keep
                # it correct). Standard b64decode discards unknown chars.
                std = payload.replace("-", "+").replace("_", "/")
                decoded = _b64.b64decode(std + "=" * (-len(std) % 4))
            if len(decoded) < 1:
                return None

            # DATA message: version-prefixed 0x00 0x04 0x03
            if (
                len(decoded) >= 3
                and decoded[0] == 0x00
                and decoded[1] == 0x04
                and decoded[2] == 0x03
            ):
                return "DATA (may carry SMP)"

            # Otherwise byte[0] is the DAKE message type.
            mtype = decoded[0]
            names = {0x35: "DAKE1", 0x36: "DAKE2", 0x37: "DAKE3", 0x03: "DATA"}
            return names.get(mtype, f"type 0x{mtype:02x}")
        except Exception:
            return None

    def _handle_otr_in(self, peer, body):
        # Retained for compatibility; the async path above is what runs now.
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

    # ---------- DAKE completion -> trust prompt ----------

    def _check_dake_complete(self, peer):
        """When a peer's session first becomes encrypted, show fingerprints and
        prompt for trust - exactly like the IRC client."""
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
        print(f"[secure] OTR session with {peer} is ENCRYPTED " "(X448 + ML-KEM-1024 + ML-DSA-87).")
        print(f"  Your fingerprint  : {_fmt_fp(local_fp)}")
        print(f"  Their fingerprint : {_fmt_fp(remote_fp)}")
        print("-" * 60)

        # If already trusted (TOFU pin from a previous session), skip the prompt.
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

    # ---------- SMP passphrase prompt (auto-respond storage) ----------

    def _prompt_smp_secret(self, peer):
        print("-" * 60)
        print(
            "[smp] SOCIALIST MILLIONAIRE PROTOCOL setup "
            "(hybrid PQC: ML-KEM-1024 + ML-DSA-87 + ZKP)."
        )
        print("[smp] Enter the SMP passphrase for auto-respond.")
        print("[smp]   - Both sides must enter the SAME passphrase.")
        print("[smp]   - Once both have stored it, either side runs  /smp start.")
        print("[smp]   - Press Enter or type  skip  to skip for now.")
        self._pending[peer] = "smp_secret"

    def _handle_smp_secret_answer(self, peer, secret):
        self._pending[peer] = None
        if not secret or secret.strip().lower() == "skip":
            print("[smp] skipped - you can set it later with  /smp-secret <secret>.")
            return
        secret = secret.strip()
        try:
            ok = self.otr.set_smp_secret(peer, secret)
        except Exception as e:
            print(f"[smp] error storing passphrase: {e}")
            return
        if ok:
            print("[smp] passphrase stored for auto-respond.")
            print(
                "[smp] When BOTH sides have stored it, run  /smp start  " "(either side) to verify."
            )
        else:
            print("[smp] could not store passphrase.")

    # ---------- SMP result reporting ----------

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

    # ---------- fingerprint helpers (engine-backed) ----------

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

    # ---------- outbound with fragmentation ----------

    def send_otr_fragmented(self, peer, payload):
        """Send an OTR message, fragmenting if large.

        Fragment wire format (one per <body>):
            ?OTRv4F|<msg_id>|<n>|<total>|<chunk>
        The receiver reassembles by msg_id. Small messages are sent whole as
        a normal ?OTRv4 frame.

        IMPORTANT - why the threshold is small: the I2P streaming layer behind
        the SAM bridge does NOT reliably deliver a single large (>~8KB) write as
        one piece end-to-end; a ~16KB SMP2 frame arrives truncated and the
        stream tears down ("unexpected eof"). DAKE (~6KB) and SMP1 (~8KB) are
        under the cliff and survive; SMP2/SMP3 (~16KB) are over it and don't.
        The IRC client never hit this because it fragments every OTR message
        into small lines. We do the same here: split anything over ~6KB into
        small per-stanza fragments, each comfortably under the cliff, then
        reassemble on the far side."""
        MAX_FRAGMENT = 6000  # bytes of payload per fragment (I2P-safe)

        if len(payload) <= MAX_FRAGMENT:
            self.send_message(mto=peer, mbody=payload, mtype="chat")
            print(f"[otr-send] 1 frame ({len(payload)} bytes) -> {peer}")
            return

        chunks = [payload[i : i + MAX_FRAGMENT] for i in range(0, len(payload), MAX_FRAGMENT)]
        total = len(chunks)
        # A monotonic per-sender counter, NOT hash(peer, payload[:64], total).
        # The old hash keyed on the first 64 chars of the frame, which are
        # near-constant across DATA frames (version + instance tags + ratchet
        # header), so two large in-flight frames to the same peer could collide
        # and cross-stitch on reassembly. The receiver namespaces buffers by
        # (peer, msg_id, total), so a plain incrementing id is unique per sender
        # and wire-compatible. Hex-formatted, wrapped at 32 bits for tidiness.
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
        """Legacy send_otr - now uses fragmentation."""
        self.send_otr_fragmented(peer, payload)

    # ---------- inbound fragment reassembly ----------

    def _reassemble_fragment(self, peer, body):
        """Feed one inbound fragment to the buffer.

        Returns the fully reassembled `?OTRv4 ...` string when the last
        fragment arrives, otherwise None. Prints a received-fragment counter
        matching the IRC client's progress style.
        """
        try:
            # ?OTRv4F|<msg_id>|<n>|<total>|<chunk>
            _, msg_id, n_s, total_s, chunk = body.split("|", 4)
            n = int(n_s)
            total = int(total_s)
        except Exception:
            print(f"[otr-recv] malformed fragment from {peer}; dropping")
            return None

        # Reject nonsensical indices before they can corrupt a buffer or make
        # the final stitch raise KeyError (n out of [1, total]).
        if total < 1 or total > 100000 or n < 1 or n > total:
            print(f"[otr-recv] fragment index out of range from {peer}; dropping")
            return None

        if not hasattr(self, "_frag_buffers"):
            self._frag_buffers = {}

        # Bound memory against a peer that opens many reassemblies it never
        # completes: evict the oldest in-flight set once past a sane cap.
        MAX_INFLIGHT = 64
        while len(self._frag_buffers) > MAX_INFLIGHT:
            del self._frag_buffers[next(iter(self._frag_buffers))]

        key = (peer, msg_id, total)
        buf = self._frag_buffers.setdefault(key, {"parts": {}, "total": total})
        buf["parts"][n] = chunk
        have = len(buf["parts"])
        print(
            f"[otr-recv]   fragment {n}/{total} from {peer} " f"(id {msg_id}; have {have}/{total})"
        )

        if have < total:
            return None

        # Complete - but verify every index is present before stitching, so a
        # duplicate/garbled set can never KeyError here.
        if any(i not in buf["parts"] for i in range(1, total + 1)):
            return None
        ordered = "".join(buf["parts"][i] for i in range(1, total + 1))
        del self._frag_buffers[key]
        print(
            f"[otr-recv] reassembled {total} fragments "
            f"({len(ordered)} bytes, id {msg_id}) from {peer}"
        )
        return ordered

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
            self.send_otr_fragmented(peer, msg if isinstance(msg, str) else msg.decode())
        elif not should_send:
            print(f"[queued] will send once OTR with {peer} is ready")

    def store_smp_secret(self, peer, secret):
        """/smp-secret : store for auto-respond, no initiation."""
        if not self.otr.has_encrypted_session(peer):
            print(f"[smp] no encrypted session with {peer}. Run /otr first.")
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
        """
        /smp start  : begin SMP using the already-stored passphrase.
        /smp <secret> : store then start.
        """
        if not self.otr.has_encrypted_session(peer):
            print(f"[smp] no encrypted session with {peer}. Run /otr first.")
            return
        if secret:
            try:
                self.otr.set_smp_secret(peer, secret)
            except Exception:
                pass
        # If no secret passed, start_smp needs the stored one. The engine's
        # start_smp takes the secret explicitly, so retrieve the stored value.
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
            # start_smp runs heavy DH; offload so it never blocks the input
            # thread or the loop. Schedule on the loop, run in the OTR executor.
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
                    self.send_otr_fragmented(peer, smp1 if isinstance(smp1, str) else smp1.decode())
                    print(
                        f"[smp] started with {peer}; waiting for response "
                        "(SMP runs several 3072-bit DH rounds; keep both "
                        "clients running)..."
                    )
                else:
                    print(f"[smp] could not start with {peer}")

            self.loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_run()))
        except Exception as e:
            print(f"[smp] start error: {e}")
            return

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
        print(
            f"[status] {peer}: encrypted={enc} trusted={trusted} " f"smp_secret_stored={has_secret}"
        )

    def reshow_trust(self, peer):
        self._encrypted.discard(peer)
        self._check_dake_complete(peer)

    # ---------- pending-input dispatch ----------

    def feed_pending(self, peer, line):
        """If `peer` has a pending prompt (trust / smp_secret), consume `line`."""
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

    # ---------- shared command dispatch ----------

    def dispatch_line(self, peer, line):
        """Handle one input line for `peer` (the active conversation).

        Returns True to keep running, False to quit. This is the single source
        of command behaviour, used by BOTH the plain stdin loop and the TUI, so
        the two front-ends are guaranteed to behave identically. `peer` is the
        active target (the TUI passes the active tab; the stdin loop passes the
        --peer default); commands that name an explicit JID override it."""
        # 1) A pending trust/SMP prompt for this peer consumes the line.
        if peer and self.has_pending(peer):
            if line.strip() == "/quit":
                return False
            self.feed_pending(peer, line)
            return True

        if not line:
            return True

        if line == "/quit":
            return False
        elif line == "/otr":
            if peer:
                self.start_otr(peer)
            else:
                print("no --peer set; use /otr <jid>")
        elif line.startswith("/otr "):
            self.start_otr(line[5:].strip())
        elif line == "/smp start":
            if peer:
                self.smp_start(peer)
            else:
                print("no --peer set")
        elif line.startswith("/smp-secret "):
            rest = line[len("/smp-secret ") :].strip()
            first = rest.split(" ", 1)[0]
            if "@" in first and " " in rest:
                t, s = rest.split(" ", 1)
                self.store_smp_secret(t, s)
            elif peer:
                self.store_smp_secret(peer, rest)
            else:
                print("usage: /smp-secret <jid> <secret>")
        elif line.startswith("/smp "):
            rest = line[5:].strip()
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
        elif line == "/trust":
            if peer:
                self.reshow_trust(peer)
        elif line.startswith("/msg "):
            rest = line[5:].strip()
            if " " in rest:
                t, txt = rest.split(" ", 1)
                self.send_plain(t, txt)
                print(f"[sent plain] -> {t}")
            else:
                print("usage: /msg <jid> <text>")
        elif line == "/status":
            if peer:
                self.show_status(peer)
        else:
            if peer:
                self.send_user_text(peer, line)
            else:
                print("no --peer set; use /msg <jid> <text> or set --peer")
        return True

    # ================= inline terminal UI (drives the engine's TUI) =========
    # No new module: we attach the engine's PanelManager + Screen + raw-mode
    # line editor (the IRC client's UI) to this XMPP client and feed them.

    # System-prefixed lines have no peer; everything else routes by JID, with
    # JID-less continuation lines (fingerprints, the SMP banner) inheriting the
    # last peer routed to.
    _SYS_PREFIXES = (
        "[i2p]",
        "[tls]",
        "[connected]",
        "[ready]",
        "[sub]",
        "[status]",
        "[keepalive]",
        "[disconnected]",
        "[auth",
        "[delivery",
        "[sent plain]",
        "[queued]",
    )

    def _tui_label_for(self, jid):
        """Return a short, unique tab label for a peer JID (its localpart,
        disambiguated only if two distinct JIDs share one localpart). The JID
        is normalised to its bare form first (strip /resource and trailing
        punctuation) so the same peer always resolves to one tab."""
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
                label = jid  # last resort: keep them distinct
        self._tui_jid_by_label[label] = jid
        self._tui_label_by_jid[jid] = label
        return label

    def _tui_route_output(self, line):
        """Route one harness output line into the panel system. Called from the
        module-level print() shadow while the TUI is active (possibly from the
        OTR crypto thread - PanelManager/Screen are internally lock-guarded).

        Routing is peer-first: any line naming a peer (other than us) goes to
        that peer's tab - presence, delivery receipts, OTR/SMP traces included.
        Only genuinely peerless lines fall to system; bare continuation lines
        (fingerprints, the SMP banner) inherit the last peer."""
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
                target = "system"  # global, peerless
            else:
                target = self._tui_last_panel or "system"  # continuation
        self._tui_update_badge(target, line)
        try:
            self.panel_manager.add_message(target, line)
        except Exception:
            return
        # First time a real peer conversation appears while we're parked in
        # system (e.g. no --peer was given and the peer initiated), jump to it
        # once. Subsequent messages never steal focus.
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
            if "SMP VERIFIED" in line or "Fingerprint TRUSTED" in line or "identity pinned" in line:
                self.panel_manager.update_panel_security(target, SL.SMP_VERIFIED)
            elif "is ENCRYPTED" in line:
                self.panel_manager.update_panel_security(target, SL.ENCRYPTED)
        except Exception:
            pass

    def _refresh_prompt(self):
        """Build the input prompt: nick | [<icon><panel>]."""
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
        """Drop a one-time 'how to start OTR' hint into a peer tab, so the user
        sees what to do in the tab they're actually looking at."""
        hint = (
            "Type /otr to start an encrypted session with %s.  You'll then "
            "confirm the fingerprint and set a shared SMP secret to verify "
            "identity.  /quit to exit." % label
        )
        try:
            self.panel_manager.add_message(label, _colorize(hint, "yellow"))
        except Exception:
            pass

    def _make_debug_log_handler(self):
        """A logging.Handler that funnels every record into the 'debug' tab,
        coloured purple. Records may arrive from the OTR crypto thread; the
        engine's panel/screen primitives are lock-guarded, matching the
        print()-shadow path."""
        import logging

        client = self

        class _DebugTabHandler(logging.Handler):
            def __init__(self):
                super().__init__(logging.DEBUG)
                self.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

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
        """Attach and start the engine's TUI. Returns True if it took over the
        terminal, False to fall back to the plain line reader. With debug=True,
        a 'debug' tab is opened and all log records are routed into it."""
        global _ACTIVE_TUI_CLIENT
        if not (_TUI_AVAILABLE and sys.stdin.isatty() and sys.stdout.isatty()):
            return False
        self._loop = loop
        self.panel_manager = _PanelManager(self)
        self._screen = _Screen(self)
        self._tui_enabled = True
        self._prompt_refresh_cb = self._refresh_prompt  # PanelManager calls this
        _ACTIVE_TUI_CLIENT = self  # arm the print() shadow

        # Take over logging. The root logger's stream handlers would scribble
        # the curses-style screen, so detach them. With --debug, route every
        # record into a dedicated 'debug' tab (rendered purple); otherwise drop
        # them so nothing reaches the terminal directly.
        import logging

        root = logging.getLogger()
        self._saved_log_handlers = root.handlers[:]
        for h in self._saved_log_handlers:
            root.removeHandler(h)
        if debug:
            self.panel_manager.get_or_create_panel("debug", "debug")
            root.addHandler(self._make_debug_log_handler())
            root.setLevel(logging.DEBUG)
        else:
            root.addHandler(logging.NullHandler())

        self._raw = _setup_raw_mode()
        try:
            loop.add_reader(sys.stdin.fileno(), self._tui_on_readable)
        except Exception:
            pass
        # If a default peer was given, open AND focus its tab so the user lands
        # in the private chat ready to type /otr (instead of stuck in system).
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
            root = logging.getLogger()
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in getattr(self, "_saved_log_handlers", []):
                root.addHandler(h)
        except Exception:
            pass
        builtins.print("\r")  # leave the cursor on a clean line

    def _tui_quit(self):
        self._stop_tui()
        try:
            self.disconnect()
        except Exception:
            pass

    def _tui_on_readable(self):
        """loop add_reader callback: pull one keystroke through the engine's
        raw-mode line editor; act on a completed line."""
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
        # Tab navigation handled locally against the engine's PanelManager.
        if self._tui_nav(line):
            self._refresh_prompt()
            if self._screen is not None:
                self._screen.redraw_full()
            return
        active = self.panel_manager.active_panel
        # The active tab is keyed by a short label; map it back to the full JID.
        # In system (or any non-peer tab), fall back to the --peer default so a
        # bare /otr (and chat) still work without switching.
        peer = self._tui_jid_by_label.get(active)
        if peer is None:
            peer = self.peer or None
        # Echo our own outgoing plaintext (dispatch_line/send don't echo it) into
        # the tab the user is looking at.
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
        """Handle UI-only tab commands. Returns True if consumed."""
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
                    # match by prefix (e.g. "/switch de" -> debug)
                    hit = [n for n in order if n.startswith(a)]
                    if len(hit) == 1:
                        pm.switch_to_panel(hit[0])
                    else:
                        pm.add_message(
                            pm.active_panel, "no tab '%s'. tabs: %s" % (a, ", ".join(order))
                        )
            else:
                names = ", ".join("%d:%s" % (i + 1, n) for i, n in enumerate(order))
                pm.add_message(pm.active_panel, "tabs: " + names)
            return True
        # bare /1 /2 /3 ... jumps to that tab by index
        if cmd[1:].isdigit():
            idx = int(cmd[1:]) - 1
            if 0 <= idx < len(order):
                pm.switch_to_panel(order[idx])
            return True
        if cmd in ("/tabs", "/windows"):
            names = ", ".join("%d:%s" % (i + 1, n) for i, n in enumerate(order))
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
    client.disconnect()


def main():
    ap = argparse.ArgumentParser(description="OTRv4+ XMPP - full OTR + SMP over I2P SAM")
    ap.add_argument("--jid", required=True, help="your full JID")
    ap.add_argument("--peer", help="default peer JID for /otr, /smp, chat")
    ap.add_argument(
        "--server",
        help="server c2s .b32.i2p address to SAM-connect to " "(default: the domain part of --jid)",
    )
    ap.add_argument("--port", type=int, default=5222, help="server c2s port")
    ap.add_argument("--sam-host", default="127.0.0.1", help="i2pd SAM host")
    ap.add_argument("--sam-port", type=int, default=7656, help="i2pd SAM port")
    ap.add_argument(
        "--no-i2p", action="store_true", help="connect directly (clearnet), do not use I2P SAM"
    )
    ap.add_argument(
        "--insecure-tls", action="store_true", help="accept expired/self-signed server certs"
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
        "~/.otrv4plus/logs/session-<timestamp>.log). Only "
        "written when --debug is set.",
    )
    ap.add_argument(
        "--no-log", action="store_true", help="disable the session transcript even with --debug"
    )
    ap.add_argument(
        "--keep-log",
        action="store_true",
        help="keep the transcript file after a clean exit "
        "(default: deleted on clean /quit or Ctrl+C; kept "
        "automatically if the session crashes, so a failure "
        "is always diagnosable)",
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
                    "[log] deleted automatically on a clean exit; " "kept if the session crashes"
                )
        except Exception as e:
            builtins.print(f"[log] could not open log file: {e}", file=sys.stderr)
    elif args.log_file and not args.debug:
        builtins.print("[log] --log-file has no effect without --debug")

    password = getpass.getpass(f"Password for {args.jid}: ")
    client = OTRv4PlusXMPP(args.jid, password, peer=args.peer)

    # Prosody c2s expects STARTTLS (not direct TLS).
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

    loop = client.loop

    if use_i2p:
        try:
            host, port = loop.run_until_complete(
                start_i2p_sam_forwarder(
                    server_b32, args.port, sam_host=args.sam_host, sam_port=args.sam_port
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

    # Interactive terminal -> engine ANSI TUI (tabs, pinned input); otherwise
    # the plain line reader (piped/headless, or forced with --no-tui, which
    # gives linear scrollback that's far easier to read for debug/trace output).
    client._probe = args.debug
    _clean_exit = True
    try:
        started_tui = (not args.no_tui) and client._start_tui(loop, debug=args.debug)
        if args.no_tui:
            print(
                "[tui] disabled (--no-tui): plain scrollback. Commands still work "
                "(/otr, /smp, /msg, /status, /quit)."
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
                loop.run_until_complete(asyncio.gather(client.disconnected, _input_loop(client)))
            except KeyboardInterrupt:
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
