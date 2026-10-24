# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client's tunnels: XMPP over Tor (SOCKS5) and over I2P (SAM).

Each forwarder listens on a local port and carries what slixmpp writes to it
through Tor or an I2P stream to the server. Moved out of otrv4plus_xmpp.py,
which re-exports these names; the Android bridge reaches the forwarders
through it.

The engine's SAM connection class is handed over by the client once it has
loaded the engine (`bind_engine`): this module does not import the engine.
"""
import asyncio
import threading
import time

from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)

#: The engine (otrv4+.py) and its SAM client; set by bind_engine().
_otr = None
I2PSAMConnection = None


def bind_engine(otr) -> None:
    """Take the engine from the client (see the module doc)."""
    global _otr, I2PSAMConnection
    _otr = otr
    I2PSAMConnection = getattr(otr, "I2PSAMConnection", None)


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
                                    socks_port: int = TOR_SOCKS_PORT,
                                    *, resources=None, log=None):
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
    # `log` and `resources` exist for the Android bridge, exactly as on the
    # SAM forwarder: logcat must not name the destination, and the caller's
    # list is what lets a failed or finished connection release the tunnel.
    say = log if log is not None else print
    say("[tor] opening SOCKS5 tunnel to %s:%d via %s:%d ..."
        % (_sanitise(onion_host, 80), dest_port, socks_host, socks_port))
    tor_reader, tor_writer = await socks5_connect(
        onion_host, dest_port, socks_host=socks_host, socks_port=socks_port)
    say("[tor] tunnel established.")

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
    # Held so neither the server nor the tunnel is collected; the caller's
    # list, when given, so it can also let go.
    if resources is not None:
        resources.extend([server, tor_writer])
    else:
        _TOR_FORWARDERS.append((server, tor_reader, tor_writer))
    say("[tor] local bridge ready at %s:%d -> %s"
        % (host, port, _sanitise(onion_host, 80)))
    return host, port


#: Keeps forwarder objects alive for the process lifetime.
_TOR_FORWARDERS = []


def _first_byte_kind(byte: int) -> str:
    """What the server's first byte says it is speaking, as one word.

    "xml" is an XMPP server's stream header; "tls" a TLS record (handshake
    0x16 or alert 0x15) -- a server expecting direct TLS, i.e. port 5223 --
    and "other" anything else, such as an HTTP reply from a tunnel of the
    wrong type."""
    if byte == 0x3C:            # '<'
        return "xml"
    if byte in (0x15, 0x16):
        return "tls"
    return "other"


class HeldSamSession:
    """One SAM session kept between FAILED sign-in attempts (Android).

    Owner's report (2026-10-17): "I2P router 0:02, sign-in 2:39, 10
    attempts". Each attempt made a brand-new transient destination, and a
    failed STREAM CONNECT closed it: the next attempt, ten seconds later,
    built tunnels and looked the server up again from nothing -- and failed
    the same way. A session whose STREAM CONNECT failed is now held here, and
    the next attempt to the same server tries again on it: the tunnels are
    built and the router is already looking for the server.

      * One at a time, for the same SAM bridge and server only.
      * Only after a failed stream: a sign-in that worked keeps its session
        for the connection, and the next sign-in starts a fresh destination
        as before (sessions stay unlinkable).
      * Closed after HOLD_SECONDS unused, or by `drop` (Wipe, Sign out).
    """

    HOLD_SECONDS = 300.0

    def __init__(self):
        self._lock = threading.Lock()
        self._sam = None
        self._key = None
        self._timer = None

    def _swap(self, sam=None, key=None):
        with self._lock:
            old, self._sam, self._key = self._sam, sam, key
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if sam is not None:
                self._timer = threading.Timer(self.HOLD_SECONDS, self.drop)
                self._timer.daemon = True
                self._timer.start()
        return old

    def take(self, key):
        """The held session for `key` if it is still open; else None."""
        with self._lock:
            held_key = self._key
        sam = self._swap()
        if sam is None:
            return None
        if held_key == key and sam.session_alive():
            return sam
        sam.close()
        return None

    def keep(self, key, sam):
        old = self._swap(sam, key)
        if old is not None and old is not sam:
            old.close()

    def drop(self):
        old = self._swap()
        if old is not None:
            old.close()

    @property
    def holding(self) -> bool:
        return self._sam is not None


#: The one held session (see HeldSamSession).
HELD_SAM = HeldSamSession()


async def start_i2p_sam_forwarder(
    dest_b32: str, dest_port: int, sam_host: str = "127.0.0.1", sam_port: int = 7656,
    *, resources=None, log=None, aliases: bool = True, verify=None,
    hold: bool = False,
):
    """
    Open an I2P SAM stream to `dest_b32` and expose it as a local TCP endpoint.

    Returns (local_host, local_port). slixmpp connects to the local endpoint and
    does STARTTLS normally; bytes are piped over the SAM stream to the I2P
    destination. The SAM connection, local server, and writer are kept alive on
    the loop so they are not garbage-collected.

    `resources` and `log` exist for the Android bridge and change nothing when
    they are omitted, which is how the terminal client calls this.

    **resources** -- a list to append the SAM session, the local server and the
    writer to, INSTEAD of stashing them on `loop._i2p_keep`. The stash is a
    keep-alive with no way to let go: it grows by three on every connection and
    nothing ever closes what is in it. In a terminal process that runs one
    session and exits, that is invisible. In an app where the user presses
    Connect, fails, and presses it again, every attempt leaves a live I2P
    tunnel and a listening local socket behind. Handing the caller the list
    makes releasing them possible; passing nothing keeps the old behaviour
    exactly.

    **log** -- where the progress lines go, defaulting to `print`. The default
    is the terminal's. Android needs a different one because Chaquopy routes
    stdout into logcat, and these lines name the destination -- which is the
    one thing CONTRIBUTING.md's rejection list says must not be logged. A
    destination in a terminal a user is looking at is feedback; the same string
    in a system log that any `adb logcat` reads is a disclosure.

    **hold** -- keep the SAM session after a failed STREAM CONNECT and reuse
    it on the next call to the same server (HeldSamSession). Android only.
    """
    if I2PSAMConnection is None:
        raise RuntimeError(
            "I2PSAMConnection not available from the OTR module; "
            "cannot use I2P SAM transport."
        )

    say = log if log is not None else print

    loop = asyncio.get_event_loop()
    key = (sam_host, sam_port, dest_b32)
    sam = HELD_SAM.take(key) if hold else None
    reused = sam is not None
    if sam is None:
        sam = I2PSAMConnection(sam_host=sam_host, sam_port=sam_port)
    extra = {"keep_session": True} if hold else {}

    def _do_sam():
        # `dest_b32` may be a .b32.i2p address or a short .i2p name: the
        # router resolves either with NAMING LOOKUP (I2PSAMConnection.resolve).
        # `aliases=False` (Android) means the local alias file is never read.
        # `verify` (Android, X1): checked against the resolved destination
        # before any stream to it exists. Omitted, the call is unchanged.
        if verify is not None:
            s = sam.connect(dest_b32, allow_aliases=aliases,
                            verify_destination=verify, **extra)
        else:
            s = sam.connect(dest_b32, allow_aliases=aliases, **extra)
        s.setblocking(False)
        return s

    if reused:
        say(f"[i2p] opening SAM stream to {dest_b32} again, on the tunnels "
            "a failed attempt already built...")
    else:
        say(f"[i2p] opening SAM stream to {dest_b32} "
            "(the router resolves the name; a cold tunnel can take 30-90s)...")
    try:
        sam_sock = await loop.run_in_executor(None, _do_sam)
    except BaseException as exc:
        if (hold and getattr(exc, "stage", "") == "stream"
                and sam.session_alive()):
            # The server did not answer this time; the tunnels are fine.
            # Held for the next attempt (HeldSamSession).
            HELD_SAM.keep(key, sam)
            raise
        # Cancelled (the Android connect timed out) or failed: the executor
        # thread is not stopped by either, and a session it created would stay
        # open in the router -- one more per retry. See I2PSAMConnection.abandon.
        abandon = getattr(sam, "abandon", None)
        if abandon is not None:
            abandon()
        raise
    if getattr(sam, "used_shipped_address", False):
        # The name, never the destination: on Android `say` reaches logcat.
        say(f"[i2p] {dest_b32} was dialled at the address this version "
            "ships for it.")
    say("[i2p] SAM stream established.")

    sam_reader, sam_writer = await asyncio.open_connection(sock=sam_sock)

    # I2P tunnels can drop a stream when a large message is written as one
    # burst. We pace writes in small chunks to avoid the SAM cliff (~8KB).
    SAM_CHUNK = 1024        # bytes per write toward I2P
    SAM_CHUNK_DELAY = 0.02  # seconds between chunks on large messages

    async def _handle_local(local_reader, local_writer):
        # Byte COUNTS, which side ended the stream, and what kind of byte the
        # server sent first -- never content. A device report showed a tunnel
        # that opened and then closed with nothing else known; these tell
        # "the server never said a word" (its I2P tunnel points at nothing,
        # or at the wrong port) from "it answered in TLS" (a direct-TLS port,
        # 5223, where XMPP wants 5222) from an XMPP server that answered.
        seen = {"sent": 0, "got": 0, "first": "", "ended_by": ""}

        async def pump_to_i2p(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        seen["ended_by"] = seen["ended_by"] or "client"
                        break
                    seen["sent"] += len(data)
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
                        seen["ended_by"] = seen["ended_by"] or "server"
                        break
                    if not seen["got"]:
                        seen["first"] = _first_byte_kind(data[0])
                    seen["got"] += len(data)
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
        say(f"[i2p] I2P stream ended by the {seen['ended_by'] or 'client'}: "
            f"sent={seen['sent']} received={seen['got']} "
            f"first={seen['first'] or 'none'}")

    server = await asyncio.start_server(_handle_local, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    # Somewhere to keep these alive. Either place works as a keep-alive; only
    # the caller's list can also be used to let go. See the docstring.
    if resources is None:
        if not hasattr(loop, "_i2p_keep"):
            loop._i2p_keep = []
        resources = loop._i2p_keep
    resources.extend([sam, server, sam_writer])
    say(f"[i2p] local bridge ready at {host}:{port} -> {dest_b32}")
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
