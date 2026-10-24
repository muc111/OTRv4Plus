# -*- coding: utf-8 -*-
#
# weechat_otrv4plus.py — OTRv4+ plugin for WeeChat
#
# Wraps the existing otrv4_.py protocol implementation.
# Place otrv4_.py and the three .so extensions in the same directory
# as this script (typically ~/.local/share/weechat/python/) then:
#
#   /python load weechat_otrv4plus.py
#
# Commands:
#   /otr start [nick]    — begin encrypted session
#   /otr end [nick]      — end encrypted session
#   /otr fingerprint     — show fingerprints
#   /otr trust [nick]    — trust peer fingerprint
#   /otr status          — show all OTR sessions
#   /smp <secret>        — set SMP secret for current buffer
#   /smp start           — begin SMP verification
#   /smp abort           — abort SMP
#
# Bar item:
#   /set weechat.bar.status.items "...,otr_status"
#

import os
import sys
import hashlib
import concurrent.futures
from collections import deque

# ── WeeChat bootstrap ────────────────────────────────────────────────
try:
    import weechat
except ImportError:
    print("This script must be run inside WeeChat.")
    sys.exit(1)

SCRIPT_NAME    = "otrv4plus"
SCRIPT_AUTHOR  = "muc111"
SCRIPT_VERSION = "1.1"
SCRIPT_LICENSE  = "GPL3"
SCRIPT_DESC    = "OTRv4+ post-quantum encrypted messaging"

# ── Import OTRv4+ library ───────────────────────────────────────────
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

_otr_dir = os.path.expanduser("~/.local/share/weechat/python")
if _otr_dir not in sys.path:
    sys.path.insert(0, _otr_dir)

from otrv4_ import (
    EnhancedSessionManager, OTRConfig, NullLogger,
    OTRFragmentBuffer, OTRMessageFragmenter,
    UIConstants, SessionState,
)

# ── Globals ──────────────────────────────────────────────────────────
_manager    = None   # EnhancedSessionManager
_frag_bufs  = {}     # peer → OTRFragmentBuffer
_fragmenter = None   # OTRMessageFragmenter
_result_q   = deque()  # background threads → main thread
_send_queue = deque()  # outgoing fragment queue
_executor   = None   # ThreadPoolExecutor for heavy crypto
_alive      = False  # set True after init, False on shutdown


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def otr_print(buf, msg):
    """Print to a WeeChat buffer with OTR prefix."""
    weechat.prnt(buf, f"otr4+\t{msg}")


def otr_print_main(msg):
    """Print to the core WeeChat buffer."""
    otr_print("", msg)


def buffer_nick(buf):
    """Extract the remote nick from a WeeChat query buffer.

    Returns empty string for channels and non-query buffers.
    """
    btype = weechat.buffer_get_string(buf, "localvar_type")
    # Only return a nick for private/query buffers
    if btype != "private":
        return ""
    name = weechat.buffer_get_string(buf, "localvar_channel")
    if name:
        return name
    name = weechat.buffer_get_string(buf, "short_name")
    if name and not name.startswith("#"):
        return name
    return ""


def buffer_server(buf):
    """Extract the IRC server name from a WeeChat buffer."""
    srv = weechat.buffer_get_string(buf, "localvar_server")
    return srv or ""


def ensure_query_buffer(server, nick):
    """Find or create a query buffer for nick on server."""
    nick = sanitize_nick(nick)
    if not nick or not server:
        return ""
    buf = weechat.info_get("irc_buffer", f"{server},{nick}")
    if buf:
        return buf
    weechat.command("", f"/query -server {server} {nick}")
    buf = weechat.info_get("irc_buffer", f"{server},{nick}")
    return buf or ""


def is_ctcp(message):
    """Return True if message is CTCP (\\x01 delimited).

    OTR messages are never CTCP.
    """
    if message.startswith("?OTRv4") or message.startswith("?OTR|"):
        return False
    return len(message) >= 2 and message[0] == "\x01" and message[-1] == "\x01"


def is_otr_fragment(message):
    """Return True if message contains OTR protocol data."""
    return "?OTRv4" in message or "?OTR|" in message


def sanitize_nick(nick):
    """Sanitize an IRC nick for safe use in WeeChat commands.

    Strips control characters, newlines, spaces, and slashes that
    could inject IRC commands via /quote or /query.  Returns empty
    string if the nick is invalid after sanitization.
    """
    if not nick:
        return ""
    # Only allow printable ASCII minus dangerous chars
    clean = ""
    for ch in nick:
        if ch in "\r\n\x00 \t/\\":
            continue
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            continue
        clean += ch
    # IRC nicks: max ~30 chars, must not start with # & : digit
    if not clean or clean[0] in "#&:0123456789":
        return ""
    return clean[:30]


def parse_irc_line(raw):
    """Parse a raw IRC line, stripping IRCv3 tags.

    Returns (sender_nick, target, message) or None on failure.
    IRCv3 message tags (@key=value;...) are stripped transparently.
    """
    line = raw
    # Strip IRCv3 message tags
    if line.startswith("@"):
        space = line.find(" ")
        if space == -1:
            return None
        line = line[space + 1:]

    parts = line.split(" ", 3)
    if len(parts) < 4:
        return None

    prefix = parts[0]           # :nick!user@host
    # parts[1] = PRIVMSG
    target = parts[2]
    message = parts[3]
    if message.startswith(":"):
        message = message[1:]

    nick = prefix.split("!")[0].lstrip(":")
    return nick, target, message


# ═══════════════════════════════════════════════════════════════════════
# Fragment handling
# ═══════════════════════════════════════════════════════════════════════

def get_frag_buf(peer):
    """Get or create a fragment buffer for a peer."""
    if peer not in _frag_bufs:
        buf = OTRFragmentBuffer(timeout=120.0)
        buf.first_fragment_cb = lambda s, n, chunk="": None
        _frag_bufs[peer] = buf
    return _frag_bufs[peer]


def cleanup_frag_bufs_cb(data, remaining_calls):
    """Periodic timer: evict stale fragment buffers."""
    expired = []
    for peer, buf in list(_frag_bufs.items()):
        try:
            buf.cleanup_expired()
            if buf.get_pending_count() == 0:
                expired.append(peer)
        except Exception:
            expired.append(peer)
    for peer in expired:
        _frag_bufs.pop(peer, None)
    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# Non-blocking fragment sending
# ═══════════════════════════════════════════════════════════════════════

def send_otr_to_peer(server, nick, otr_message):
    """Queue an OTR message for fragmented, non-blocking send."""
    if not _alive or not _manager or not _fragmenter:
        return

    nick = sanitize_nick(nick)
    if not nick or not server:
        return

    if isinstance(otr_message, bytes):
        otr_message = otr_message.decode("utf-8", errors="replace")

    sender_tag = 0
    receiver_tag = 0
    try:
        sess = _manager.get_session(nick)
        if sess is not None:
            sender_tag   = getattr(sess, '_sender_tag',   0) or 0
            receiver_tag = getattr(sess, '_receiver_tag', 0) or 0
    except Exception:
        pass

    fragments = _fragmenter.fragment(
        otr_message,
        sender_tag=sender_tag,
        receiver_tag=receiver_tag,
    )

    for frag in fragments:
        _send_queue.append((server, nick, frag))

    # Single fragment: send immediately instead of waiting for timer
    if len(fragments) == 1:
        _drain_one_fragment("", 0)


def _drain_one_fragment(data, remaining_calls):
    """Timer callback: send one queued fragment per tick."""
    if not _send_queue:
        return weechat.WEECHAT_RC_OK
    server, nick, frag = _send_queue.popleft()
    nick = sanitize_nick(nick)
    if not nick or not server:
        return weechat.WEECHAT_RC_OK
    # Ensure frag contains no newlines (defence in depth — fragments
    # are base64 OTR data but validate anyway)
    frag = frag.replace("\r", "").replace("\n", "")
    weechat.command("", f"/quote -server {server} PRIVMSG {nick} :{frag}")
    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# Background thread → main thread result queue
# ═══════════════════════════════════════════════════════════════════════

def _poll_results_cb(data, remaining_calls):
    """Main-thread timer: process results from background threads.

    Limits to 20 results per tick to avoid blocking the UI
    if many messages arrive simultaneously.
    """
    processed = 0
    while _result_q and processed < 20:
        try:
            action = _result_q.popleft()
            action()
        except Exception as e:
            try:
                otr_print_main(f"OTR result error: {e}")
            except Exception:
                pass
        processed += 1
    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# Incoming message handler (modifier — suppresses OTR ciphertext)
# ═══════════════════════════════════════════════════════════════════════

def modifier_privmsg_in_cb(data, modifier, server, string):
    """Intercept incoming PRIVMSG for OTR processing.

    Uses hook_modifier (not hook_signal) so we can return "" to
    suppress OTR ciphertext from being displayed in the buffer.
    Returning the original string passes non-OTR messages through.

    modifier = "irc_in_PRIVMSG"
    server   = IRC server name
    string   = raw IRC line (may include IRCv3 tags)
    """
    if not _alive or not _manager:
        return string

    _is_otr = False   # track whether message is OTR for safe error path

    try:
        parsed = parse_irc_line(string)
        if not parsed:
            return string

        sender, target, message = parsed

        # Pass through: channels, CTCP, non-OTR
        if target.startswith("#"):
            return string
        if is_ctcp(message):
            return string
        if not is_otr_fragment(message):
            return string

        _is_otr = True   # from here on, NEVER return the original string

        # Sanitize sender nick
        sender = sanitize_nick(sender)
        if not sender:
            return ""

        # ── Fragment reassembly ──────────────────────────────
        frag_buf = get_frag_buf(sender)
        try:
            complete = frag_buf.add_fragment(sender, message)
        except ValueError:
            return ""   # malformed fragment — suppress

        if not complete:
            return ""   # buffering fragments — suppress

        # ── Offload complete OTR message to background thread ─
        if _executor and _alive:
            try:
                _executor.submit(
                    _process_incoming_otr, server, sender, complete
                )
            except RuntimeError:
                pass  # executor shut down

        return ""   # always suppress OTR protocol data

    except Exception as e:
        try:
            otr_print_main(f"OTR recv error: {e}")
        except Exception:
            pass
        # CRITICAL: if we identified the message as OTR, suppress it
        # even on error — never display raw ciphertext to the user
        return "" if _is_otr else string


def _process_incoming_otr(server, sender, complete_msg):
    """Background thread: decrypt/process a complete OTR message.

    Never calls weechat.* directly — all UI actions are deferred
    to the main thread via _result_q.
    """
    if not _alive or not _manager:
        return

    try:
        was_encrypted = (_manager.has_session(sender) and
                         _manager.get_security_level(sender) !=
                         UIConstants.SecurityLevel.PLAINTEXT)

        result = _manager.handle_incoming_message(sender, complete_msg)

        is_encrypted = (_manager.has_session(sender) and
                        _manager.get_security_level(sender) !=
                        UIConstants.SecurityLevel.PLAINTEXT)

        newly_encrypted = (not was_encrypted and is_encrypted)

        # ── DAKE response to send back ───────────────────────
        if result and isinstance(result, bytes) and result.startswith(b"?OTRv4"):
            # Bind variables for closure safety
            _r, _s, _n, _ne = result, server, sender, newly_encrypted
            def _send_dake():
                send_otr_to_peer(_s, _n, _r)
                if _ne:
                    buf = ensure_query_buffer(_s, _n)
                    otr_print(buf, f"🔒 Encrypted session established with {_n}")
                    _flush_queued(_s, _n)
            _result_q.append(_send_dake)
            return

        # ── Session just established (DAKE3 responder, no response) ──
        if newly_encrypted:
            _s, _n = server, sender
            def _notify():
                buf = ensure_query_buffer(_s, _n)
                otr_print(buf, f"🔒 Encrypted session established with {_n}")
                _flush_queued(_s, _n)
            _result_q.append(_notify)
            return

        # ── Decrypted plaintext ──────────────────────────────
        if result and isinstance(result, bytes):
            text = result.decode("utf-8", errors="replace")
            _s, _n, _t = server, sender, text
            def _display():
                buf = ensure_query_buffer(_s, _n)
                weechat.prnt(buf, f"{_n}\t🔒 {_t}")
            _result_q.append(_display)
            return

    except Exception as e:
        _err = str(e)
        _n = sender
        def _show_error():
            otr_print_main(f"OTR error ({_n}): {_err}")
        _result_q.append(_show_error)


def _flush_queued(server, nick):
    """Send messages queued during DAKE handshake."""
    if not _manager:
        return
    try:
        sess = _manager.get_session(nick)
        if sess and hasattr(sess, '_outgoing_queue'):
            while sess._outgoing_queue:
                queued = sess._outgoing_queue.pop(0)
                enc = _manager.encrypt_message(nick, queued)
                if enc:
                    send_otr_to_peer(server, nick, enc)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
# Outgoing message handler
# ═══════════════════════════════════════════════════════════════════════

def modifier_privmsg_out_cb(data, modifier, server, string):
    """Intercept outgoing PRIVMSG for OTR encryption.

    modifier = "irc_out_PRIVMSG"
    server   = IRC server name
    string   = "PRIVMSG target :message text"
    """
    if not _alive or not _manager:
        return string

    _has_session = False   # track whether encryption was expected

    try:
        parts = string.split(" ", 2)
        if len(parts) < 3 or parts[0] != "PRIVMSG":
            return string

        target = parts[1]
        message = parts[2]
        if message.startswith(":"):
            message = message[1:]

        # Pass through: channels, OTR protocol data, CTCP
        if target.startswith("#"):
            return string
        if is_otr_fragment(message):
            return string
        if is_ctcp(message):
            return string

        # No encrypted session — send plaintext
        if not _manager.has_session(target):
            return string
        sec = _manager.get_security_level(target)
        if sec == UIConstants.SecurityLevel.PLAINTEXT:
            return string

        _has_session = True   # encryption expected — never leak plaintext

        # ── Encrypt ──────────────────────────────────────────
        encrypted = _manager.encrypt_message(target, message)
        if not encrypted:
            otr_print_main(
                f"OTR: encryption failed for {target} — message NOT sent")
            return ""   # suppress plaintext

        # Send encrypted fragments
        send_otr_to_peer(server, target, encrypted)

        # Display locally as sent
        buf = weechat.info_get("irc_buffer", f"{server},{target}")
        if buf:
            my_nick = weechat.info_get("irc_nick", server)
            weechat.prnt(buf, f"{my_nick}\t🔒 {message}")

        return ""   # suppress original plaintext

    except Exception as e:
        otr_print_main(f"OTR send error: {e}")
        # CRITICAL: if an encrypted session exists, NEVER send plaintext
        # on error — suppress the message entirely
        if _has_session:
            otr_print_main(
                "Message suppressed — would have leaked plaintext")
            return ""
        return string


# ═══════════════════════════════════════════════════════════════════════
# /otr command
# ═══════════════════════════════════════════════════════════════════════

def cmd_otr_cb(data, buf, args):
    """Handle /otr command."""
    if not _manager:
        otr_print(buf, "OTR not initialised")
        return weechat.WEECHAT_RC_OK

    argv = args.strip().split()
    if not argv:
        otr_print(buf,
            "Usage: /otr start|end|fingerprint|trust|status [nick]")
        return weechat.WEECHAT_RC_OK

    subcmd = argv[0].lower()
    server = buffer_server(buf)
    nick   = argv[1] if len(argv) > 1 else buffer_nick(buf)
    nick   = sanitize_nick(nick)

    # ── /otr start ───────────────────────────────────────────
    if subcmd == "start":
        if not nick or nick.startswith("#"):
            otr_print(buf,
                "Usage: /otr start <nick>  (not a channel)")
            return weechat.WEECHAT_RC_OK
        if not server:
            otr_print(buf, "Cannot determine IRC server for this buffer")
            return weechat.WEECHAT_RC_OK

        otr_print(buf, f"Starting OTR with {nick}…")
        dake_msg, should_send = _manager.handle_outgoing_message(nick, "")
        if should_send and dake_msg:
            send_otr_to_peer(server, nick, dake_msg)
            otr_print(buf, f"🔑 DAKE1 → {nick}")
        else:
            otr_print(buf, f"Failed to start OTR with {nick}")

    # ── /otr end ─────────────────────────────────────────────
    elif subcmd == "end":
        if not nick:
            otr_print(buf, "Usage: /otr end <nick>")
            return weechat.WEECHAT_RC_OK
        if _manager.has_session(nick):
            try:
                _manager.end_session(nick)
            except Exception:
                pass
            _manager.sessions.pop(nick, None)
            _manager.dake_engines.pop(nick, None)
            _frag_bufs.pop(nick, None)
            otr_print(buf, f"🔓 OTR session with {nick} ended")
        else:
            otr_print(buf, f"No OTR session with {nick}")

    # ── /otr fingerprint ─────────────────────────────────────
    elif subcmd == "fingerprint":
        try:
            pub = _manager.client_profile.identity_pub_bytes
            if pub:
                fp = hashlib.sha256(pub).hexdigest()[:40].upper()
                fp_fmt = " ".join(fp[i:i+8] for i in range(0, 40, 8))
                otr_print(buf, f"Your fingerprint: {fp_fmt}")

            for peer, sess in _manager.sessions.items():
                remote = getattr(sess, '_remote_long_term_pub_bytes', None)
                if remote:
                    fp = hashlib.sha256(remote).hexdigest()[:40].upper()
                    fp_fmt = " ".join(fp[i:i+8] for i in range(0, 40, 8))
                    sec = _manager.get_security_level(peer)
                    icon = UIConstants.SECURITY_ICONS.get(sec, "")
                    otr_print(buf, f"  {icon} {peer}: {fp_fmt}")
        except Exception as e:
            otr_print(buf, f"Fingerprint error: {e}")

    # ── /otr trust ───────────────────────────────────────────
    elif subcmd == "trust":
        if not nick:
            otr_print(buf, "Usage: /otr trust <nick>")
            return weechat.WEECHAT_RC_OK
        if not _manager.has_session(nick):
            otr_print(buf, f"No OTR session with {nick}")
            return weechat.WEECHAT_RC_OK
        try:
            sess = _manager.get_session(nick)
            remote = getattr(sess, '_remote_long_term_pub_bytes', None)
            if remote:
                fp = hashlib.sha256(remote).hexdigest()[:40]
                _manager.trust_db.add_trust(nick, fp)
                otr_print(buf, f"🟢 {nick} fingerprint trusted")
            else:
                otr_print(buf, f"No fingerprint available for {nick}")
        except Exception as e:
            otr_print(buf, f"Trust error: {e}")

    # ── /otr status ──────────────────────────────────────────
    elif subcmd == "status":
        sessions = _manager.sessions
        if not sessions:
            otr_print(buf, "No active OTR sessions")
        else:
            otr_print(buf, "Active OTR sessions:")
            for peer in sessions:
                sec = _manager.get_security_level(peer)
                icon = UIConstants.SECURITY_ICONS.get(sec, "")
                name = UIConstants.SECURITY_NAMES.get(
                    sec, sec.name if hasattr(sec, 'name') else str(sec))
                otr_print(buf, f"  {icon} {peer}: {name}")

    else:
        otr_print(buf,
            "Usage: /otr start|end|fingerprint|trust|status [nick]")

    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# /smp command
# ═══════════════════════════════════════════════════════════════════════

def cmd_smp_cb(data, buf, args):
    """Handle /smp command."""
    if not _manager:
        otr_print(buf, "OTR not initialised")
        return weechat.WEECHAT_RC_OK

    argv = args.strip().split(None, 1)
    if not argv:
        otr_print(buf, "Usage: /smp <secret> | /smp start | /smp abort")
        return weechat.WEECHAT_RC_OK

    nick   = buffer_nick(buf)
    server = buffer_server(buf)

    if not nick:
        otr_print(buf, "Switch to a query buffer first")
        return weechat.WEECHAT_RC_OK
    if not _manager.has_session(nick):
        otr_print(buf,
            f"No OTR session with {nick} — /otr start {nick} first")
        return weechat.WEECHAT_RC_OK

    subcmd = argv[0].lower()

    # ── /smp start — offload to background thread ────────────
    if subcmd == "start":
        # Bind closure variables explicitly
        _nick, _server, _buf = nick, server, buf
        def _do_smp_start():
            if not _alive or not _manager:
                return
            try:
                sess = _manager.get_session(_nick)
                if sess and hasattr(sess, 'start_smp'):
                    result = sess.start_smp()
                    if result:
                        _r = result
                        def _send():
                            send_otr_to_peer(_server, _nick, _r)
                            otr_print(_buf, "SMP verification started")
                        _result_q.append(_send)
                    else:
                        _result_q.append(
                            lambda: otr_print(_buf,
                                "Set a secret first: /smp <secret>"))
                else:
                    _result_q.append(
                        lambda: otr_print(_buf,
                            "SMP not available for this session"))
            except Exception as exc:
                _msg = str(exc)
                _result_q.append(
                    lambda: otr_print(_buf, f"SMP start error: {_msg}"))

        if _executor and _alive:
            try:
                _executor.submit(_do_smp_start)
            except RuntimeError:
                otr_print(buf, "OTR executor is shutting down")

    # ── /smp abort ───────────────────────────────────────────
    elif subcmd == "abort":
        try:
            sess = _manager.get_session(nick)
            if sess and hasattr(sess, 'abort_smp'):
                result = sess.abort_smp()
                if result:
                    send_otr_to_peer(server, nick, result)
            otr_print(buf, "SMP aborted")
        except Exception as e:
            otr_print(buf, f"SMP abort error: {e}")

    # ── /smp <secret> ───────────────────────────────────────
    else:
        secret = args.strip()
        try:
            sess = _manager.get_session(nick)
            if sess and hasattr(sess, 'set_smp_secret'):
                sess.set_smp_secret(secret)
                otr_print(buf,
                    "SMP secret set — /smp start to begin verification")
            else:
                otr_print(buf, "SMP not available")
        except Exception as e:
            otr_print(buf, f"SMP error: {e}")

    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# Bar item
# ═══════════════════════════════════════════════════════════════════════

def bar_item_otr_cb(data, item, window):
    """Render OTR status indicator for the current buffer."""
    if not _manager:
        return ""
    buf = weechat.window_get_pointer(window, "buffer")
    if not buf:
        return ""
    nick = buffer_nick(buf)
    if not nick or not _manager.has_session(nick):
        return ""

    sec = _manager.get_security_level(nick)
    icons = {
        UIConstants.SecurityLevel.ENCRYPTED:    " OTR:enc ",
        UIConstants.SecurityLevel.FINGERPRINT:  " OTR:fp  ",
        UIConstants.SecurityLevel.SMP_VERIFIED: " OTR:smp ",
    }
    return icons.get(sec, "")


# ═══════════════════════════════════════════════════════════════════════
# Plugin lifecycle
# ═══════════════════════════════════════════════════════════════════════

def otrv4plus_shutdown(data):
    """Clean shutdown — wipe secrets from memory.

    WeeChat unload callback signature: (data) → WEECHAT_RC_OK
    """
    global _manager, _executor, _alive
    _alive = False

    if _manager:
        try:
            for peer, sess in list(_manager.sessions.items()):
                try:
                    if hasattr(sess, 'zeroize'):
                        sess.zeroize()
                except Exception:
                    pass
            _manager.sessions.clear()
            _manager.dake_engines.clear()
        except Exception:
            pass
        _manager = None

    if _executor:
        try:
            _executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            _executor.shutdown(wait=False)
        _executor = None

    _frag_bufs.clear()
    _send_queue.clear()
    _result_q.clear()

    return weechat.WEECHAT_RC_OK


# ═══════════════════════════════════════════════════════════════════════
# Registration
# ═══════════════════════════════════════════════════════════════════════

weechat.register(
    SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
    SCRIPT_LICENSE, SCRIPT_DESC, "otrv4plus_shutdown", ""
)

# Initialise OTR subsystem
_otr_dir_path = os.path.expanduser("~/.otrv4plus")
os.makedirs(_otr_dir_path, exist_ok=True)

_config = OTRConfig(
    trust_db_path    = os.path.join(_otr_dir_path, "trust.json"),
    smp_secrets_path = os.path.join(_otr_dir_path, "smp_secrets.json"),
    key_storage_path = os.path.join(_otr_dir_path, "keys"),
    log_file_path    = os.path.join(_otr_dir_path, "logs", "otrv4plus.log"),
    test_mode        = False,
    server           = "weechat",
    channel          = "",
)

_manager    = EnhancedSessionManager(config=_config, logger=NullLogger())
_fragmenter = OTRMessageFragmenter()
_executor   = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="otr4-crypto"
)
_alive = True

# ── Incoming PRIVMSG: modifier (can suppress OTR ciphertext) ────────
weechat.hook_modifier("irc_in_PRIVMSG", "modifier_privmsg_in_cb", "")

# ── Outgoing PRIVMSG: modifier (encrypts before send) ──────────────
weechat.hook_modifier("irc_out_PRIVMSG", "modifier_privmsg_out_cb", "")

# ── /otr command ─────────────────────────────────────────────────────
weechat.hook_command(
    "otr",
    "OTRv4+ post-quantum encrypted messaging",
    "start|end|fingerprint|trust|status [nick]",
    "  start [nick]    begin encrypted session\n"
    "  end [nick]      end encrypted session\n"
    "  fingerprint     show all fingerprints\n"
    "  trust [nick]    trust peer fingerprint\n"
    "  status          list active sessions\n\n"
    "If nick is omitted, uses the current query buffer.",
    "start|end|fingerprint|trust|status",
    "cmd_otr_cb",
    ""
)

# ── /smp command ─────────────────────────────────────────────────────
weechat.hook_command(
    "smp",
    "SMP identity verification (OTRv4+)",
    "<secret> | start | abort",
    "  <secret>   set the shared secret\n"
    "  start      begin verification (runs in background)\n"
    "  abort      abort current verification\n\n"
    "Must be in a query buffer with an active OTR session.",
    "start|abort",
    "cmd_smp_cb",
    ""
)

# ── Bar item ─────────────────────────────────────────────────────────
weechat.bar_item_new("otr_status", "bar_item_otr_cb", "")

# ── Timers ───────────────────────────────────────────────────────────
# Drain outgoing fragment queue: one fragment every 30ms
weechat.hook_timer(30, 0, 0, "_drain_one_fragment", "")

# Poll background crypto results: every 50ms
weechat.hook_timer(50, 0, 0, "_poll_results_cb", "")

# Clean stale fragment buffers: every 60 seconds
weechat.hook_timer(60000, 0, 0, "cleanup_frag_bufs_cb", "")

otr_print_main(f"OTRv4+ {SCRIPT_VERSION} loaded — /otr start <nick> to begin")
