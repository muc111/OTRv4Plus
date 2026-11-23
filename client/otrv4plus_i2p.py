# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""I2P for the terminal client: the SAM bridge, and the names it dials.

Two things live here, both about reaching an I2P destination:

* **Short names** (`otrv4plus.i2p`). I2P names are not DNS; this is the
  local alias file that maps a short name to the `.b32.i2p` it means on
  this device, with the shipped defaults and the rules for what an alias
  may and may not do.
* **The SAM v3.1 client** (`I2PSAMConnection`): session creation, name and
  key lookups (including the retries a just-started router needs), and the
  stream sockets the XMPP and IRC transports run over.

Moved out of otrv4+.py unchanged; otrv4+.py re-exports every name, so
`otrv4+.I2PSAMConnection` and friends still work. Code that patches the
alias file's location patches it here, where it is read.
"""
import os
import re
import secrets
import socket
import time
from typing import Optional

import otrv4plus_address as _address

#: Where the router's SAM bridge listens, by default.
SAM_HOST = "127.0.0.1"
SAM_PORT = 7656
#: Socket timeout, in seconds, for a connection over I2P (SAM streams here;
#: the IRC transport uses it too, as NetworkConstants.TIMEOUT_I2P).
I2P_TIMEOUT_S = 120


# ─────────────────────────────────────────────────────────────────────────────
# I2P short names
# ─────────────────────────────────────────────────────────────────────────────
#
# `.i2p` names are NOT DNS.  There is no global resolver: a router only knows
# the names in its own address book, which it builds from subscriptions.  A
# private server is in nobody's subscription, so `otrv4plus.i2p` resolves on
# the machine that created it and nowhere else, while the 52-character
# `.b32.i2p` form works everywhere because it IS the destination hash.
#
# That is why the b32 has to be pasted, and it is a genuine usability problem:
# nobody is going to type 52 base32 characters correctly on a phone keyboard.
#
# This file is the local answer.  One line per name:
#
#     otrv4plus.i2p = <52 characters>.b32.i2p
#
# WHAT AN ALIAS IS AND IS NOT.  It is a note to yourself about what a name
# means on this device.  It is not authenticated, it is not published, and it
# proves nothing about who answers.  The security of a conversation does not
# rest on it: the DAKE authenticates the peer and TOFU pins their identity
# key, so pointing an alias at the wrong server yields a failed connection or
# a server that cannot read anything, not a silent impersonation.
#
# A name given in full as .b32.i2p is never looked up here -- see
# _apply_i2p_alias -- so a local file cannot redirect an address typed in
# full.

I2P_HOSTS_FILENAME = "i2p_hosts"

#: What a router answers NAMING LOOKUP with for a well-formed short name its
#: address book does not have. Java I2P says KEY_NOT_FOUND; i2pd says
#: INVALID_KEY (it keeps KEY_NOT_FOUND for a b32 whose LeaseSet it cannot
#: find). The name is validated before it is sent, so for a short name both
#: mean "unknown here" -- the case the alias file and the fallback below are
#: for. Device report 2026-10-01: i2pd answered INVALID_KEY for otrv4plus.i2p
#: and the fallback, which accepted only KEY_NOT_FOUND, never ran.
I2P_NAME_UNKNOWN_RESULTS = ("KEY_NOT_FOUND", "INVALID_KEY")

#: The project's own server name and the b32 it is dialled at, without asking
#: the router (otrv4plus_address.SHIPPED_SERVERS says why). Re-exported here
#: for the terminal client's callers.
SHIPPED_SERVERS = _address.SHIPPED_SERVERS

#: What a router answers NAMING LOOKUP with for a .b32.i2p whose LeaseSet it
#: could not find (i2pd: INVALID_KEY, SAM.cpp HandleNamingLookupLeaseSet-
#: RequestComplete; Java I2P: KEY_NOT_FOUND).
I2P_KEY_NOT_FOUND_RESULTS = ("KEY_NOT_FOUND", "INVALID_KEY")
#: A key lookup refused faster than this was not a search of the network:
#: a router that has just started has no peers to ask and answers at once. A
#: real search that finds nothing takes seconds.
KEY_LOOKUP_INSTANT_S = 2.0
#: How long one attempt keeps asking while the answers are instant, and the
#: pauses between asks. Device reports 2026-11-09 and 2026-11-10: on the
#: built-in router's first minute or two, every sign-in and sign-up failed in
#: milliseconds (five sign-up taps in 2 minutes) until one found the server.
KEY_LOOKUP_SETTLE_S = 150.0
KEY_LOOKUP_PAUSES_S = (3.0, 5.0, 8.0, 12.0, 15.0)
#: Real (slow) searches still retried once a router has stopped answering
#: instantly, within the same attempt: its first searches can miss.
KEY_LOOKUP_SLOW_RETRIES = 2


def remember_i2p_alias(name: str, destination: str, path: str = None,
                       learned: bool = True) -> str:
    """Record `name = destination` in the local alias file.

    So the 52-character b32 is typed once and never again: the client calls
    this after a connection has actually succeeded, which is the only moment
    it knows the pair is good.

    Three refusals, and the third is the one that matters:

      * a name that is not a short `.i2p` name, or a destination that is not a
        b32 or a full destination -- the file must stay loadable;
      * a name already recorded with THE SAME destination -- nothing to do;
      * a name already recorded with a DIFFERENT destination -- left alone and
        reported.  A server whose destination changed is something the user
        needs to see, not something a client should quietly rewrite under
        them.  Editing the file by hand is the way to accept such a change.

    Returns a short status string for display: "" when nothing was written.
    """
    name = (name or "").strip().lower()
    destination = (destination or "").strip()
    if not name.endswith(".i2p") or name.endswith(".b32.i2p"):
        return ""
    if not _valid_i2p_destination(destination):
        return ""

    path = path or i2p_hosts_path()
    if i2p_aliases(i2p_hosts_defaults_path()).get(name) == destination:
        return ""            # the shipped defaults already say this
    existing = i2p_aliases(path).get(name)
    if existing == destination:
        return ""
    if existing:
        return (f"{name } is already recorded as {existing }, which is not "
                f"the destination just used. Not changing it -- edit "
                f"{path } yourself if the server really moved.")

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        new_file = not os.path.exists(path)
        with open(path, "a", encoding="utf-8") as fh:
            if new_file:
                fh.write("# OTRv4+ I2P name aliases.  One per line:\n")
                fh.write("#     name.i2p = <52 chars>.b32.i2p\n")
                fh.write("# A local note about what a name means on this "
                         "device; it is not\n"
                         "# authenticated and proves nothing about who "
                         "answers.  Delete a line\n"
                         "# to forget it.\n")
            marker = f"  {LEARNED_MARKER }" if learned else ""
            fh.write(f"{name } = {destination }{marker }\n")
        if new_file:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError as exc:
        return f"could not write {path }: {exc }"
    return f"recorded {name } = {destination } in {path }"


def i2p_hosts_path() -> str:
    """Where the local alias file lives."""
    return os.path.join(os.path.expanduser("~/.otrv4plus"), I2P_HOSTS_FILENAME)


def _valid_i2p_destination(value: str) -> bool:
    """A b32 address or a full base64 destination, and nothing else.

    Deliberately strict: an alias that expands to something the router cannot
    use produces a confusing failure much later, and an alias that expands to
    another short name would let one line chain into another.
    """
    if value.endswith(".b32.i2p"):
        label = value[:-len(".b32.i2p")]
        return (len(label) == 52
                and all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in label))
    # A full destination is base64 (I2P's alphabet) and long.
    return (len(value) >= 516
            and all(c.isalnum() or c in "-~=" for c in value))


#: Written after an entry the client learned from a successful connection.
#: The marker is what separates "this device worked it out" from "the user
#: decided this", and the two are treated differently when a shipped default
#: disagrees -- see resolve_i2p_aliases().
LEARNED_MARKER = "# learned"

#: Shipped defaults, updated by `git pull` like any other code.
I2P_HOSTS_DEFAULTS = "i2p_hosts.defaults"


def i2p_hosts_defaults_path() -> str:
    """The defaults that travel with the source, beside this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        I2P_HOSTS_DEFAULTS)


def i2p_aliases(path: str = None, with_provenance: bool = False):
    """Read an alias file.  Returns {} when it does not exist.

    Never raises: a malformed line is skipped with a warning rather than
    stopping the client from starting, because the alternative is that one
    typo makes the whole thing unusable.

    With `with_provenance`, values are `(destination, learned)` pairs.
    """
    path = path or i2p_hosts_path()
    out = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError):
        return out

    for number, raw in enumerate(lines, 1):
        learned = LEARNED_MARKER in raw
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            name, _, dest = line.partition("=")
        else:
            parts = line.split()
            if len(parts) != 2:
                print(f"[i2p] {path }:{number }: cannot read this line, skipping")
                continue
            name, dest = parts
        name, dest = name.strip().lower(), dest.strip()
        if not name.endswith(".i2p") or name.endswith(".b32.i2p"):
            print(f"[i2p] {path }:{number }: {name !r} is not a short .i2p "
                  "name, skipping")
            continue
        if not _valid_i2p_destination(dest):
            print(f"[i2p] {path }:{number }: {name } does not point at a "
                  ".b32.i2p address or a full destination, skipping")
            continue
        out[name] = (dest, learned) if with_provenance else dest
    return out


def resolve_i2p_aliases(user_path: str = None,
                        defaults_path: str = None,
                        on_message=print) -> dict:
    """Merge the shipped defaults with the user's own file.

    The precedence rule, and the reason for it:

      * a hand-written user entry ALWAYS wins.  Someone who typed a line into
        that file meant it, and an update has no business overruling them;
      * a LEARNED entry -- one this client recorded itself after a successful
        connection -- yields to a shipped default that disagrees, with a
        notice.  Otherwise the first successful connection would pin an
        address forever, and moving the server would strand every user who had
        ever connected, which is exactly the case this layer exists for;
      * otherwise the shipped default applies.

    Nothing here writes.  `~/.otrv4plus/i2p_hosts` is the user's file and an
    update never edits it; the defaults change because `git pull` changed
    them, which is visible in the diff.
    """
    defaults = i2p_aliases(defaults_path or i2p_hosts_defaults_path())
    merged = dict(defaults)
    for name, (dest, learned) in i2p_aliases(
            user_path, with_provenance=True).items():
        shipped = defaults.get(name)
        if learned and shipped and shipped != dest:
            on_message(
                f"[i2p] the address shipped for {name } has changed; using "
                f"the new one.\n"
                f"[i2p]   was (remembered here): {dest }\n"
                f"[i2p]   now (from this build): {shipped }\n"
                f"[i2p] to keep the old one, edit {user_path or i2p_hosts_path ()} "
                f"and remove the '{LEARNED_MARKER }' marker from that line.")
            continue
        merged[name] = dest
    return merged


class SamError(ConnectionError):
    """A SAM failure, classified by the layer that failed.

    `stage` is one of:
      * "bridge"  -- the LOCAL SAM bridge: unreachable, closed, refused HELLO,
                     or sent a malformed / oversized / mismatched reply;
      * "naming"  -- the router could not resolve the name (RESULT= says why);
      * "session" -- SESSION CREATE failed;
      * "stream"  -- STREAM CONNECT failed: the destination is not reachable;
      * "cancelled" -- the caller gave up (I2PSAMConnection.abandon).
    `result` is the SAM RESULT= value when there was one. These are different
    problems with different remedies, and callers report which one it was.
    """

    def __init__(self, stage: str, message: str, result: str = ""):
        super().__init__(message)
        self.stage = stage
        self.result = result


#: A short I2P name: dot-separated labels of letters, digits and hyphens,
#: ending in `.i2p`. Checked BEFORE anything is sent, so a malformed name can
#: never inject text (a space, a newline) into a SAM command.
_I2P_NAME_RE = re.compile(r"^(?=.{5,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+i2p$")
_B32_RE = re.compile(r"^[a-z2-7]{52}\.b32\.i2p$")
#: A full destination in I2P's base64 alphabet (at least 387 characters).
_I2P_DEST_RE = re.compile(r"^[A-Za-z0-9~-]{387,}={0,2}$")
#: A SAM reply line is a few hundred bytes (a destination is under 1 KB).
#: Anything far larger is not a SAM reply and is refused unread.
SAM_MAX_REPLY = 16384


def i2p_target_error(target: str) -> Optional[str]:
    """Why `target` is not an I2P address this client will look up, or None."""
    t = (target or "").strip().lower()
    if not t.endswith(".i2p"):
        return "not an .i2p address"
    if t.endswith(".b32.i2p"):
        return None if _B32_RE.match(t) else (
            "a .b32.i2p address is 52 characters of a-z and 2-7 before "
            "'.b32.i2p'")
    return None if _I2P_NAME_RE.match(t) else (
        "an .i2p name is letters, digits, hyphens and dots, ending in .i2p")

class I2PSAMConnection:
    """Connect to I2P via the SAM bridge instead of SOCKS5.

    SAM creates a unique transient destination per session. With SOCKS5,
    all connections share one local destination - an observer at the IRC
    server can trivially correlate your sessions across reconnects.

    SAM v3.1 is supported by both i2pd and Java I2P.
    Default port: 7656.

    Usage:
        sam = I2PSAMConnection()
        if sam.is_available():
            sock = sam.connect("irc.postman.i2p")
            # sock is a raw TCP stream to the IRC server
    """

    #: Longest wait for one SAM reply line. NAMING LOOKUP and SESSION CREATE
    #: on a cold router legitimately take 60-90 s.
    reply_timeout = 90

    #: How long `lookup_key` keeps asking a router too new to search
    #: (KEY_LOOKUP_SETTLE_S); a test of the "not found" outcome sets it to 0.
    key_lookup_settle_s = KEY_LOOKUP_SETTLE_S

    #: Random bytes in the SAM session name. SAM has no login and any
    #: program on the machine can reach its port, so the name is the only
    #: thing between such a program and this session (STREAM CONNECT or
    #: ACCEPT by ID). Four bytes could be guessed in days; sixteen cannot.
    SAM_SESSION_ID_BYTES = 16

    def __init__(self, sam_host: str = None, sam_port: int = None):
        self.sam_host = sam_host or SAM_HOST
        self.sam_port = sam_port or SAM_PORT
        self._session_id = f"otrv4plus_{secrets .token_hex (self .SAM_SESSION_ID_BYTES )}"
        self._control_sock = None
        self._our_destination = None
        #: Set by `resolve`: the name is the project's server and was dialled
        #: at the address shipped for it (SHIPPED_SERVERS).
        self.used_shipped_address = False
        #: Set by `abandon`; see there.
        self._abandoned = False
        self._pending_stream = None

    def _send_cmd(self, sock, cmd: str) -> str:
        """Send a SAM command and read ONE reply line.

        Deadline is 90s - I2P NAMING LOOKUP and SESSION CREATE on a cold tunnel
        can legitimately take 60-90 seconds.  The reply is bounded
        (SAM_MAX_REPLY): a peer that streams without a newline is not a SAM
        bridge and must not be able to grow this buffer without limit.  Every
        failure is a SamError("bridge"), never a bare socket error."""
        if "\n" in cmd or "\r" in cmd:
            raise SamError("bridge", "refusing to send a multi-line SAM command")
        try:
            sock.sendall((cmd + "\n").encode("utf-8"))
            buf = b""
            deadline = time.time() + self.reply_timeout
            while b"\n" not in buf:
                if time.time() > deadline:
                    raise SamError("bridge", "SAM bridge timeout", "TIMEOUT")
                if len(buf) > SAM_MAX_REPLY:
                    raise SamError("bridge", "SAM reply too long")
                chunk = sock.recv(4096)
                if not chunk:
                    raise SamError("bridge", "SAM bridge closed connection")
                buf += chunk
        except SamError:
            raise
        except socket.timeout:
            raise SamError("bridge", "SAM bridge timeout", "TIMEOUT") from None
        except OSError as exc:
            raise SamError("bridge", "SAM bridge I/O error (%s)"
                           % type(exc).__name__) from None
        line = buf.split(b"\n", 1)[0]
        try:
            return line.decode("ascii").strip()
        except UnicodeDecodeError:
            raise SamError("bridge", "SAM reply is not ASCII") from None

    def _parse_reply(self, reply: str, prefix: str) -> dict:
        """Parse SAM key=value reply."""
        if not reply.startswith(prefix):
            raise SamError("bridge", f"SAM unexpected reply: {reply[:120] }")
        parts = reply[len(prefix) :].strip().split(" ")
        result = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                result[k] = v
        return result

    def _handshake(self, sock):
        """SAM v3.1 handshake on a socket."""
        reply = self._send_cmd(sock, "HELLO VERSION MIN=3.1 MAX=3.1")
        parsed = self._parse_reply(reply, "HELLO REPLY ")
        if parsed.get("RESULT") != "OK":
            raise SamError("bridge", f"SAM handshake failed: {reply[:120] }",
                           parsed.get("RESULT", ""))

    @staticmethod
    def _explain_stream_failure(target_host, parsed, reply) -> str:
        """Say which step failed, because they need different fixes.

        The old message ended with "Is the server b32 correct?" for every
        result, which is actively misleading for the common one: by the time
        STREAM CONNECT runs the address has already been resolved, so a
        CANT_REACH_PEER means the address was fine and the destination is not
        reachable.  Sending someone to re-check an address that is correct is
        worse than saying nothing.
        """
        result = parsed.get("RESULT", "")
        detail = f"SAM stream connect failed: {reply }"

        if result == "CANT_REACH_PEER":
            return (
                f"{detail }\n"
                f"The address resolved; the destination is not reachable "
                f"right now.\n"
                f"'LeaseSet not found' means the server has not published "
                f"tunnels the router can find -- usually the server is down "
                f"or its I2P tunnel is not running. It can also be a cold "
                f"local router that has not integrated into the netDB yet, "
                f"in which case waiting a few minutes and retrying is enough."
                f"\nThe address is not the problem: {target_host }")
        if result in ("I2P_ERROR", "TIMEOUT"):
            return (f"{detail }\n"
                    f"The router accepted the address but the connection did "
                    f"not complete. Cold tunnels can take 30-120 s; retrying "
                    f"is reasonable.")
        if result == "INVALID_KEY":
            return (f"{detail }\n"
                    f"The router would not accept that destination. Check the "
                    f"address, and any alias pointing at it.")
        return detail

    @staticmethod
    def _retired_destinations(path: str = None) -> dict:
        """{old b32: name it moved to}, from the shipped defaults.

        Read so a user whose command still names the old address in full is
        told where it went.  They are NOT redirected: an address given in full
        is used as given, which is the rule that stops any file from
        re-pointing something the user spelled out.
        """
        out = {}
        try:
            with open(path or i2p_hosts_defaults_path(), encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.split("#", 1)[0].strip()
                    parts = line.split()
                    if len(parts) == 3 and parts[0] == "retired":
                        out[parts[1].lower()] = parts[2].lower()
        except OSError:
            pass
        return out

    @staticmethod
    def _apply_i2p_alias(target_host):
        """Substitute a short name from the local alias file.

        Returns (host_to_resolve, alias_source_or_None).
        """
        if not target_host or target_host.endswith(".b32.i2p"):
            # A b32 address is self-describing: the router resolves it from the
            # hash itself, with no address book involved.  Never let an alias
            # shadow one -- that would let a local file redirect an address the
            # user typed in full.
            #
            # If we know it moved, say so.  Saying is not redirecting.
            moved_to = I2PSAMConnection._retired_destinations().get(
                target_host.lower())
            if moved_to:
                print(f"[i2p] {target_host } is a retired address for "
                      f"{moved_to }.")
                print(f"[i2p] Still trying it as given. The current form is:  "
                      f"--server {moved_to }")
            return target_host, None
        aliases = resolve_i2p_aliases()
        dest = aliases.get(target_host.lower())
        if not dest:
            return target_host, None
        print(f"[i2p] {target_host } -> {dest } (from {i2p_hosts_path ()})")
        return dest, i2p_hosts_path()

    @staticmethod
    def _explain_resolve_failure(target_host, reply, alias_source):
        """Say why a name did not resolve, and what to do about it.

        The bare SAM reply ("Cannot resolve x: NAMING REPLY RESULT=KEY_NOT_FOUND")
        is accurate and useless: it does not say that short .i2p names have to
        come from somewhere, or that this client keeps a file for exactly that.
        """
        if alias_source:
            return (f"Cannot resolve {target_host }, which came from "
                    f"{alias_source }: {reply }\n"
                    "The alias points at a destination the router does not "
                    "recognise. Check the line in that file.")
        if target_host.endswith(".b32.i2p"):
            return (f"Cannot resolve {target_host }: {reply }\n"
                    "That is a b32 address, so this is a router or tunnel "
                    "problem rather than a naming one: the router could not "
                    "find that key on the network. A router that has just "
                    "started needs a few minutes; retrying is right.")
        return (
            f"Cannot resolve {target_host }: {reply }\n"
            f"Short .i2p names are not global the way DNS is -- the router "
            f"only knows names in its address book, and a private server is "
            f"not in anyone's.\n"
            f"Either use the full <52 chars>.b32.i2p address, or add a line to "
            f"{i2p_hosts_path ()}:\n"
            f"    {target_host } = <52 chars>.b32.i2p")

    def _bridge_socket(self, timeout: float) -> "socket.socket":
        """A connected, HELLO'd socket to the LOCAL SAM bridge.

        `sam_host` is the bridge's own address (normally 127.0.0.1). The I2P
        destination never reaches this call or any resolver: it only ever
        travels inside a SAM command on this socket.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, self.reply_timeout))
        try:
            sock.connect((self.sam_host, self.sam_port))
        except OSError as exc:
            sock.close()
            raise SamError("bridge", "no SAM bridge at %s:%s (%s)"
                           % (self.sam_host, self.sam_port,
                              type(exc).__name__)) from None
        try:
            self._handshake(sock)
        except Exception:
            sock.close()
            raise
        return sock

    def naming_lookup(self, name: str) -> str:
        """`NAMING LOOKUP NAME=<name>` on the router.

        Returns the full base64 destination, or raises SamError("naming",
        ..., RESULT). The reply must name what was asked and carry a
        well-formed destination; anything else is a bridge fault, never a
        destination to connect to."""
        sock = self._bridge_socket(90)
        try:
            reply = self._send_cmd(sock, f"NAMING LOOKUP NAME={name }")
        finally:
            sock.close()
        parsed = self._parse_reply(reply, "NAMING REPLY ")
        result = parsed.get("RESULT", "")
        if result != "OK":
            raise SamError("naming", reply[:200], result or "MISSING")
        if parsed.get("NAME", "").lower() != name.lower():
            raise SamError("bridge", "SAM answered for a different NAME")
        value = parsed.get("VALUE", "")
        if not _I2P_DEST_RE.match(value):
            raise SamError("bridge", "SAM NAMING REPLY carried no valid destination")
        return value

    def lookup_key(self, name: str, pause=None) -> str:
        """`naming_lookup` for a .b32.i2p, waiting out a router that is too
        new to search.

        A "not found" that came back instantly (KEY_LOOKUP_INSTANT_S) is a
        router with no peers yet, not an answer about the server: the lookup
        is asked again, after KEY_LOOKUP_PAUSES_S, for up to
        `key_lookup_settle_s`. A router that was too new when this began then
        gets up to KEY_LOOKUP_SLOW_RETRIES real searches as well: its first
        searches, with few peers, can miss (device report 2026-11-11: seven
        instant answers, one 30 s search that missed, and the next attempt
        found the server in under a second). A slow "not found" on a router
        that answered properly from the start, and any other failure, are
        raised at once, as before. `abandon()` ends the wait. Each retry is
        reported through `on_progress`, if set."""
        pause = pause or self._pause
        # The pauses, plus the time each failed search took (a search that
        # came back at once counts as nothing).
        waited = 0.0
        tries = 0
        slow = 0
        while True:
            asked = time.monotonic()
            try:
                return self.naming_lookup(name)
            except SamError as exc:
                took = time.monotonic() - asked
                instant = took < KEY_LOOKUP_INSTANT_S
                if not instant:
                    waited += took
                wait = KEY_LOOKUP_PAUSES_S[min(tries, len(KEY_LOOKUP_PAUSES_S) - 1)]
                settling = instant or (tries > 0 and slow < KEY_LOOKUP_SLOW_RETRIES)
                if (exc.stage != "naming"
                        or exc.result not in I2P_KEY_NOT_FOUND_RESULTS
                        or not settling or self._abandoned
                        or waited + wait > self.key_lookup_settle_s):
                    raise
                if not instant:
                    slow += 1
            tries += 1
            waited += wait
            progress = getattr(self, "on_progress", None)
            if progress is not None:
                try:
                    progress("the router is too new to find the server yet; "
                             "asking again (%d) limit=%d"
                             % (tries, round(self.key_lookup_settle_s)))
                except Exception:
                    pass
            pause(wait)
            if self._abandoned:
                raise SamError("cancelled", "the SAM connection was abandoned")

    def _pause(self, seconds: float) -> None:
        """Sleep, in steps, so `abandon()` cuts it short."""
        end = time.monotonic() + seconds
        while not self._abandoned and time.monotonic() < end:
            time.sleep(min(0.25, max(0.0, end - time.monotonic())))

    def _naming_failure(self, target, exc, alias_source=None):
        if exc.stage != "naming":
            return exc
        return SamError("naming", self._explain_resolve_failure(
            target, str(exc), alias_source), exc.result)

    def resolve(self, target_host: str, allow_aliases: bool = True) -> str:
        """The full destination for an .i2p address, from the ROUTER.

        THE NAMING MODEL, and why it is this way round
        ----------------------------------------------
        * `x.b32.i2p` is the hash of the destination and the router resolves
          it from the hash. No address book and no local file is consulted,
          so nothing can redirect an address typed in full.
        * A short `x.i2p` is asked of the router first -- NAMING LOOKUP,
          always. The router's address book is the authority for what a name
          means NOW. The local alias file (Termux) is consulted only when the
          router does not know the name (I2P_NAME_UNKNOWN_RESULTS:
          KEY_NOT_FOUND from Java I2P, INVALID_KEY from i2pd), and its use is
          announced.
          It used to be consulted FIRST, together with a shipped defaults file
          that mapped the project's server name to its old b32. A server
          recreated under that name was therefore never looked up: the name
          was quietly rewritten to the retired destination (Android, device
          report 2026-09-28).
        * The project's own server name (SHIPPED_SERVERS) is the exception:
          it is dialled at its shipped b32 and the router is not asked what
          the name means. An address book that mapped it elsewhere sent the
          app's server list entry to another destination; the b32 can only
          reach the server's own key. The alias file is not consulted for it.
        * A malformed name (refused before anything is sent), a bridge
          fault, or any other result is a clean naming failure. There is no
          fallback to DNS or to anything else: no path in this class hands
          an .i2p name to a system resolver.
        """
        target = (target_host or "").strip().lower()
        problem = i2p_target_error(target)
        if problem:
            raise SamError("naming", f"{target_host !r}: {problem }", "INVALID_NAME")
        if target.endswith(".b32.i2p"):
            moved_to = I2PSAMConnection._retired_destinations().get(target)
            if moved_to:
                print(f"[i2p] {target } is a retired address for {moved_to }; "
                      "trying it as given.")
            try:
                return self.lookup_key(target)
            except SamError as exc:
                raise self._naming_failure(target, exc) from None
        self.used_shipped_address = False
        shipped = _address.shipped_server_address(target)
        if shipped:
            # Reported by the caller (`used_shipped_address`), which knows
            # whether its log may name the address.
            try:
                dest = self.lookup_key(shipped)
            except SamError as exc:
                raise self._naming_failure(shipped, exc) from None
            self.used_shipped_address = True
            return dest
        try:
            return self.naming_lookup(target)
        except SamError as exc:
            if not (exc.stage == "naming"
                    and exc.result in I2P_NAME_UNKNOWN_RESULTS):
                raise self._naming_failure(target, exc) from None
            router_reply = exc
        if allow_aliases:
            alias, alias_source = self._apply_i2p_alias(target)
            if alias_source:
                if _I2P_DEST_RE.match(alias):
                    return alias
                try:
                    return self.naming_lookup(alias)
                except SamError as exc:
                    raise self._naming_failure(alias, exc, alias_source) from None
        raise self._naming_failure(target, router_reply) from None

    def session_alive(self) -> bool:
        """Whether this object still holds an open SAM session: the router
        ends one by closing its control connection, which reads as EOF."""
        sock = self._control_sock
        if sock is None or self._abandoned:
            return False
        try:
            sock.setblocking(False)
            try:
                return sock.recv(1, socket.MSG_PEEK) != b""
            except (BlockingIOError, InterruptedError):
                return True
            finally:
                sock.setblocking(True)
        except OSError:
            return False

    def connect(self, target_host: str, target_port: int = 0,
                allow_aliases: bool = True,
                verify_destination=None,
                keep_session: bool = False) -> "socket.socket":
        """Connect to an I2P destination via SAM. Returns a raw socket.

        Creates a transient destination (fresh identity, not saved).
        The port arg is ignored - I2P destinations don't use ports.
        `target_host` is a 52-character .b32.i2p address or a short .i2p
        name; `resolve` says how each becomes a destination. Every failure
        is a SamError naming the stage that failed.

        `verify_destination(dest_b64)`, when given, is called with the
        resolved destination BEFORE any session or stream exists; whatever it
        raises propagates and nothing is sent to that destination. This is
        where the Android bridge enforces its destination pin (X1).

        `keep_session` (Android sign-in retries): when STREAM CONNECT fails,
        the session -- its destination, its built tunnels and what its router
        has learnt about the server -- is kept open, and calling `connect`
        again on this object reuses it instead of starting from nothing.
        Without it, every retry was a brand-new destination that had to build
        tunnels and look the server up again, so retries a few seconds apart
        kept failing the same way. The caller must `close()` it when done.
        """
        dest_b64 = self.resolve(target_host, allow_aliases=allow_aliases)
        if verify_destination is not None:
            verify_destination(dest_b64)

        if not self.session_alive():
            self.close()
            self._session_id = f"otrv4plus_{secrets .token_hex (self .SAM_SESSION_ID_BYTES )}"
            self._control_sock = self._bridge_socket(90)
            if self._abandoned:
                self.close()
                raise SamError("cancelled", "the SAM connection was abandoned")
            try:
                reply = self._send_cmd(
                    self._control_sock,
                    f"SESSION CREATE STYLE=STREAM ID={self ._session_id } "
                    f"DESTINATION=TRANSIENT SIGNATURE_TYPE=7",
                )
            except SamError as exc:
                if exc.result != "TIMEOUT":
                    raise
                # The bridge answered HELLO on this socket; what never came is
                # the router finishing this session's tunnels. That is the
                # SESSION stage, not an unreachable bridge -- reported as one,
                # a cold router was blamed on a SAM bridge that was working.
                self.close()
                raise SamError(
                    "session", "SESSION CREATE did not finish within %ds: the "
                    "router has not built this session's tunnels yet"
                    % self.reply_timeout, "TIMEOUT") from None
            parsed = self._parse_reply(reply, "SESSION STATUS ")
            if parsed.get("RESULT") != "OK":
                self.close()
                raise SamError("session", f"SAM session failed: {reply[:200] }",
                               parsed.get("RESULT", ""))
            self._our_destination = parsed.get("DESTINATION", "")

        stream_sock = self._bridge_socket(I2P_TIMEOUT_S)
        self._pending_stream = stream_sock
        try:
            reply = self._send_cmd(
                stream_sock,
                f"STREAM CONNECT ID={self ._session_id } " f"DESTINATION={dest_b64 } SILENT=false",
            )
        except SamError as exc:
            if exc.result != "TIMEOUT" or self._abandoned:
                raise
            # The session is up (SESSION STATUS OK) and the bridge answered
            # HELLO on this socket: what timed out is reaching the SERVER. The
            # STREAM stage -- so a sign-in retry keeps this session and its
            # built tunnels (keep_session / HeldSamSession) instead of starting
            # cold with a new destination every time, which turned one server
            # blip into an 18-minute reconnect (device report, 2026-11-04).
            stream_sock.close()
            if not keep_session:
                self.close()
            raise SamError(
                "stream", "%s did not answer within %ds over I2P"
                % (target_host, self.reply_timeout), "TIMEOUT") from None
        finally:
            self._pending_stream = None
        if self._abandoned:
            stream_sock.close()
            self.close()
            raise SamError("cancelled", "the SAM connection was abandoned")
        parsed = self._parse_reply(reply, "STREAM STATUS ")
        if parsed.get("RESULT") != "OK":
            stream_sock.close()
            if not keep_session:
                self.close()
            raise SamError("stream",
                           self._explain_stream_failure(target_host, parsed, reply),
                           parsed.get("RESULT", ""))

        stream_sock.settimeout(1.0)
        return stream_sock

    def abandon(self):
        """Give up on a `connect` that another thread is still inside.

        A connect that times out on Android is cancelled, but the thread
        doing the SAM work is not: it went on to finish SESSION CREATE and
        sat in STREAM CONNECT, and the session -- a transient destination
        with its own tunnels -- stayed open in the router for the life of the
        app. Every retry added another. Closing the sockets here ends the
        session in the router and wakes the blocked thread; the flag stops a
        step that was already past its socket from opening a new one.
        """
        self._abandoned = True
        # shutdown before close: on Linux, close() from another thread does
        # not wake a recv() blocked on the same socket; shutdown() does.
        for sock in (self._pending_stream, self._control_sock):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
        self.close()

    def close(self):
        """Close the SAM control session."""
        try:
            if self._control_sock:
                self._control_sock.close()
                self._control_sock = None
        except Exception:
            pass
        self._our_destination = None

    @staticmethod
    def is_available(host: str = None, port: int = None) -> bool:
        """Check if SAM bridge is reachable and speaking SAM v3.1."""
        host = host or SAM_HOST
        port = port or SAM_PORT
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(b"HELLO VERSION MIN=3.1 MAX=3.1\n")
            reply = sock.recv(256)
            sock.close()
            return b"RESULT=OK" in reply
        except Exception:
            return False
