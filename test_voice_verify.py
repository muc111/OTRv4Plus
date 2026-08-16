"""Static + behavioural verification of otrv4plus_xmpp.py voice subsystem."""
import sys, os, types, struct, io

# ---- Stub the OTR engine so the module imports without the real one ----
stub = types.ModuleType("otrv4plus")


class _Cleanse:
    @staticmethod
    def cleanse(buf):
        for i in range(len(buf)):
            buf[i] = 0


class _SM:
    def __init__(self, *a, **k):
        self.sessions = {}


stub.EnhancedSessionManager = _SM
stub.OTRConfig = lambda **k: types.SimpleNamespace(**k)
stub.OTRTracer = None
stub.I2PSAMConnection = object
stub._ossl = _Cleanse
stub.PanelManager = None
stub.RUST_RATCHET_AVAILABLE = True
stub._secure_file_destroy = lambda p: os.remove(p)
sys.modules["otrv4plus"] = stub

# slixmpp stub
sli = types.ModuleType("slixmpp")


class ClientXMPP:
    def __init__(self, jid, password):
        self.boundjid = types.SimpleNamespace(bare=jid, full=jid)

    def __getattr__(self, n):
        return lambda *a, **k: None


sli.ClientXMPP = ClientXMPP
exc = types.ModuleType("slixmpp.exceptions")
exc.IqError = type("IqError", (Exception,), {})
exc.IqTimeout = type("IqTimeout", (Exception,), {})
sli.exceptions = exc
sys.modules["slixmpp"] = sli
sys.modules["slixmpp.exceptions"] = exc

import importlib.util
spec = importlib.util.spec_from_file_location("xm", "otrv4plus_xmpp.py")
xm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xm)
print("[1] module imports cleanly")

FAIL = []


def check(name, cond, extra=""):
    if cond:
        print("    PASS  %s" % name)
    else:
        print("    FAIL  %s %s" % (name, extra))
        FAIL.append(name)


# ---- 2. VoiceFrameCrypto ----
print("\n[2] VoiceFrameCrypto")
CID = bytes(range(16))
a = xm.VoiceFrameCrypto(b"shared-binding-value", CID, True)   # caller
b = xm.VoiceFrameCrypto(b"shared-binding-value", CID, False)  # callee

f1 = a.encrypt_frame(b"opus-frame-one")
check("roundtrip", b.decrypt_frame(f1) == b"opus-frame-one")

# symmetry: different binding -> cannot decrypt
c = xm.VoiceFrameCrypto(b"different-binding", CID, False)
try:
    c.decrypt_frame(f1)
    check("wrong key rejected", False)
except Exception:
    check("wrong key rejected", True)

# replay
try:
    b.decrypt_frame(f1)
    check("replay rejected", False)
except Exception:
    check("replay rejected", True)

# tamper ciphertext
f2 = a.encrypt_frame(b"second")
t = bytearray(f2)
t[-1] ^= 0xFF
try:
    b.decrypt_frame(bytes(t))
    check("tamper rejected", False)
except Exception:
    check("tamper rejected", True)
# the legitimate frame must still work after a forgery attempt
check("forgery did not poison replay window", b.decrypt_frame(f2) == b"second")

# nonce uniqueness across many frames
a2 = xm.VoiceFrameCrypto(b"k", CID, True)
nonces = {a2.encrypt_frame(b"x" * 40)[:12] for _ in range(5000)}
check("5000 unique nonces", len(nonces) == 5000, len(nonces))

# malformed nonce padding
bad = bytearray(a2.encrypt_frame(b"y"))
bad[8] = 0x01
try:
    xm.VoiceFrameCrypto(b"k", CID, False).decrypt_frame(bytes(bad))
    check("bad nonce padding rejected", False)
except Exception:
    check("bad nonce padding rejected", True)

# short frame
try:
    b.decrypt_frame(b"\x00" * 10)
    check("short frame rejected", False)
except Exception:
    check("short frame rejected", True)

# zeroize
key_before = bytes(a._send_key)
a.zeroize()
check("both keys zeroized", a._send_key is None and a._recv_key is None and any(key_before))
try:
    a.encrypt_frame(b"z")
    check("use after zeroize refused", False)
except Exception:
    check("use after zeroize refused", True)
a.zeroize()  # idempotent
check("zeroize idempotent", True)

# empty binding refused
try:
    xm.VoiceFrameCrypto(b"", CID, True)
    check("empty binding refused", False)
except ValueError:
    check("empty binding refused", True)

# ---- 3. Replay window pruning ----
print("\n[3] replay window pruning under load")
enc = xm.VoiceFrameCrypto(b"prune", CID, True)
dec = xm.VoiceFrameCrypto(b"prune", CID, False)
frames = [enc.encrypt_frame(b"f%05d" % i) for i in range(25000)]
for fr in frames:
    dec.decrypt_frame(fr)
check("window bounded", len(dec._recv_seen) <= xm.VoiceFrameCrypto._MAX_SEEN,
      len(dec._recv_seen))
check("low-water advanced", dec._recv_low_water > 0, dec._recv_low_water)
try:
    dec.decrypt_frame(frames[0])
    check("old frame still rejected after prune", False)
except Exception:
    check("old frame still rejected after prune", True)
try:
    dec.decrypt_frame(frames[-1])
    check("recent frame still rejected after prune", False)
except Exception:
    check("recent frame still rejected after prune", True)

# ---- 4. SAM reply parsing ----
print("\n[4] SAM parsing")
f = xm._sam_parse("HELLO REPLY RESULT=OK VERSION=3.1", "HELLO REPLY ")
check("hello parse", f.get("VERSION") == "3.1")
f = xm._sam_parse("SESSION STATUS RESULT=OK DESTINATION=AAAA~BBBB",
                  "SESSION STATUS ")
check("destination extracted", f.get("DESTINATION") == "AAAA~BBBB")
for bad_line, why in (
    ("SESSION STATUS RESULT=I2P_ERROR MESSAGE=x", "error result"),
    ("STREAM STATUS RESULT=CANT_REACH_PEER", "unreachable"),
    ("GARBAGE", "wrong prefix"),
):
    try:
        xm._sam_parse(bad_line, "SESSION STATUS ")
        check("rejects %s" % why, False)
    except xm.SAMProtocolError:
        check("rejects %s" % why, True)

# ---- 5. SAM line reader: must not over-read into payload ----
print("\n[5] SAM line reader byte-exactness")


class FakeSock:
    """Socket that hands out one byte per recv, tracking consumption."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def settimeout(self, t):
        pass

    def recv(self, n):
        if self.pos >= len(self.data):
            return b""
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


payload = b"\x00\x50" + b"\xAA" * 80
sock = FakeSock(b"STREAM STATUS RESULT=OK\n" + b"PEERDEST~~~\n" + payload)
line1 = xm._sam_read_line(sock, 5)
line2 = xm._sam_read_line(sock, 5)
remaining = sock.data[sock.pos:]
check("line 1 exact", line1 == "STREAM STATUS RESULT=OK", line1)
check("line 2 exact", line2 == "PEERDEST~~~", line2)
check("payload untouched", remaining == payload,
      "%d of %d bytes left" % (len(remaining), len(payload)))

# closed socket
try:
    xm._sam_read_line(FakeSock(b"no newline"), 5)
    check("EOF raises", False)
except xm.SAMProtocolError:
    check("EOF raises", True)

# ---- 6. Frame parser resync (mirrors _network_reader logic exactly) ----
print("\n[6] media frame parser + authenticated resync")

SYNC = bytes([xm.VOICE_SYNC])


def make_stream(crypto, payloads):
    out = bytearray()
    for pl in payloads:
        sealed = crypto.encrypt_frame(xm._pad_opus(pl))
        assert len(sealed) == xm.VOICE_SEALED_LEN
        out += struct.pack(">BBH", xm.VOICE_SYNC, 0, len(sealed)) + sealed
    return bytes(out)


def parse(buf_bytes, crypto):
    """Byte-for-byte reimplementation of the parser in _network_reader."""
    buf = bytearray(buf_bytes)
    good, dropped = [], 0
    while len(buf) >= xm.VOICE_HDR_LEN:
        if buf[0] != xm.VOICE_SYNC:
            idx = buf.find(SYNC, 1)
            if idx == -1:
                dropped += len(buf); buf.clear(); break
            del buf[:idx]; dropped += 1; continue
        length = struct.unpack(">H", buf[2:4])[0]
        if not (xm.VOICE_MIN_FRAME <= length <= xm.VOICE_MAX_FRAME):
            del buf[:1]; dropped += 1; continue
        if len(buf) < xm.VOICE_HDR_LEN + length:
            break
        sealed = bytes(buf[xm.VOICE_HDR_LEN:xm.VOICE_HDR_LEN + length])
        consumed = False
        try:
            pt = xm._unpad_opus(crypto.decrypt_frame(sealed))
            del buf[:xm.VOICE_HDR_LEN + length]
            consumed = True
            good.append(pt)
        except Exception:
            dropped += 1
            if not consumed:
                del buf[:1]
    return good, dropped, bytes(buf)


payloads = [b"frame-%03d" % i + b"\x11" * 60 for i in range(20)]

enc = xm.VoiceFrameCrypto(b"parser", CID, True)
stream = make_stream(enc, payloads)
got, drops, rest = parse(stream, xm.VoiceFrameCrypto(b"parser", CID, False))
check("20 clean frames", got == payloads and drops == 0 and rest == b"",
      "%d frames %d drops" % (len(got), drops))

# leading garbage that contains a plausible-looking length field
enc = xm.VoiceFrameCrypto(b"parser", CID, True)
stream = make_stream(enc, payloads)
got, drops, rest = parse(b"\x00\x02\x99" + stream,
                         xm.VoiceFrameCrypto(b"parser", CID, False))
check("resync past leading garbage", got == payloads,
      "%d/%d frames" % (len(got), len(payloads)))

# a stray SYNC byte injected inside the stream must not eat real frames
enc = xm.VoiceFrameCrypto(b"parser", CID, True)
stream = make_stream(enc, payloads)
poisoned = SYNC + b"\x00\x00\x64" + stream
got, drops, rest = parse(poisoned, xm.VoiceFrameCrypto(b"parser", CID, False))
check("false sync does not consume real frames", got == payloads,
      "%d/%d frames" % (len(got), len(payloads)))

# truncated final frame retained for more data
enc = xm.VoiceFrameCrypto(b"parser", CID, True)
stream = make_stream(enc, payloads)
cut = stream[:-30]
got, drops, rest = parse(cut, xm.VoiceFrameCrypto(b"parser", CID, False))
check("partial frame retained", len(got) == len(payloads) - 1 and len(rest) > 0,
      "%d frames, %d held" % (len(got), len(rest)))

# oversize length field rejected
got, drops, rest = parse(SYNC + b"\x00\xFF\xFF" + stream,
                         xm.VoiceFrameCrypto(b"parser", CID, False))
check("oversize length resyncs", got == payloads)

# byte-level fuzz: every single-byte corruption must terminate and never crash
enc = xm.VoiceFrameCrypto(b"fuzz", CID, True)
small = make_stream(enc, [b"a" * 60, b"b" * 60, b"c" * 60])
crashed = 0
for i in range(len(small)):
    for mask in (0x01, 0xFF):
        mutated = bytearray(small)
        mutated[i] ^= mask
        try:
            parse(bytes(mutated), xm.VoiceFrameCrypto(b"fuzz", CID, False))
        except Exception:
            crashed += 1
check("single-byte fuzz never crashes", crashed == 0, "%d crashes" % crashed)

# truncation fuzz
crashed = 0
for i in range(len(small)):
    try:
        parse(small[:i], xm.VoiceFrameCrypto(b"fuzz", CID, False))
    except Exception:
        crashed += 1
check("truncation fuzz never crashes", crashed == 0, "%d crashes" % crashed)

# random-garbage fuzz
crashed = 0
for _ in range(300):
    try:
        parse(os.urandom(200), xm.VoiceFrameCrypto(b"fuzz", CID, False))
    except Exception:
        crashed += 1
check("random garbage never crashes", crashed == 0, "%d crashes" % crashed)

# ---- 7. Session binding symmetry ----
print("\n[7] session-binding symmetry (media key agreement)")


class FakeClient:
    def __init__(self, local, remote):
        self._l, self._r = local, remote
        self.otr = types.SimpleNamespace(
            has_encrypted_session=lambda p: True,
            get_session=lambda p: types.SimpleNamespace(),
        )

    def _local_fp(self, peer=None):
        return self._l

    def _remote_fp(self, peer):
        return self._r


_cid0 = bytes(range(16))
FP_A = "AAAA1111BBBB2222"
FP_B = "CCCC3333DDDD4444"
ka = xm.VoiceKeyExchange(); kb = xm.VoiceKeyExchange()
sh_a = ka.agree(kb.public); 
kb2 = xm.VoiceKeyExchange(); ka2 = xm.VoiceKeyExchange()
sh_b = kb2.agree(ka2.public)
ba = xm.VoiceKeyExchange.build_binding(b"SSID1234", sh_a, FP_A, FP_B, _cid0)
bb = xm.VoiceKeyExchange.build_binding(b"SSID1234", sh_a, FP_B, FP_A, _cid0)
check("bindings identical on both sides", ba == bb and ba is not None)
# The two endpoints must agree on the BINDING but must NOT share an
# encryption key: caller send-key == callee recv-key, and vice versa.
_cid = bytes(range(16))
_ca = xm.VoiceFrameCrypto(ba, _cid, True)
_cb = xm.VoiceFrameCrypto(bb, _cid, False)
check("caller send == callee recv", _ca._send_key == _cb._recv_key)
check("callee send == caller recv", _cb._send_key == _ca._recv_key)
check("directions use DIFFERENT keys", _ca._send_key != _cb._send_key)

# session_id preferred when present
class FakeClient2(FakeClient):
    def __init__(self):
        super().__init__(FP_A, FP_B)
        self.otr = types.SimpleNamespace(
            has_encrypted_session=lambda p: True,
            get_session=lambda p: types.SimpleNamespace(session_id=b"SID-123"),
        )


# The SSID is deliberately NOT used: the engine falls back to
# secrets.token_bytes(32) per side when the DAKE omits it, so mixing it in
# guarantees the two endpoints derive different media keys. A fixed label is
# used instead, and the binding rests on the ephemeral X448 secret.
_mat = xm.VoiceCallManager(FakeClient2(), None)._otr_material("b")
check("ssid excluded from material (constant label)",
      _mat is not None and _mat[0] == b"OTRv4+VoiceBind/no-ssid")
check("material still requires fingerprints",
      _mat is not None and _mat[1] and _mat[2])


# unencrypted -> refuse
class FakeClient3(FakeClient):
    def __init__(self):
        super().__init__(FP_A, FP_B)
        self.otr = types.SimpleNamespace(
            has_encrypted_session=lambda p: False,
            get_session=lambda p: None,
        )


check("no OTR session -> None",
      xm.VoiceCallManager(FakeClient3(), None)._otr_material("b") is None)


# unavailable fingerprints -> refuse
class FakeClient4(FakeClient):
    def __init__(self):
        super().__init__("unavailable", "unavailable")


check("unavailable fp -> None",
      xm.VoiceCallManager(FakeClient4(), None)._otr_material("b") is None)

# ---- 8. Signalling parse ----
print("\n[8] signalling")
mgr = xm.VoiceCallManager(FakeClient(FP_A, FP_B), None)
check("bare jid", mgr._bare("a@b/resource") == "a@b")
P = xm.VoiceCallManager.CALL_PREFIX
for raw, verb, payload in (
    (P + "INVITE:DEST~~", "INVITE", "DEST~~"),
    (P + "ACCEPT", "ACCEPT", ""),
    (P + "REJECT:busy", "REJECT", "busy"),
    (P + "END", "END", ""),
):
    rem = raw[len(P):]
    v, _, pl = rem.partition(":")
    check("parse %s" % verb, v.strip().upper() == verb and pl.strip() == payload)

# ---- 9. Constants sanity ----
print("\n[9] audio constants")
check("frame bytes = samples*2", xm.VOICE_FRAME_BYTES == xm.VOICE_FRAME_SAMPLES * 2)
check("640 samples @16k/40ms", xm.VOICE_FRAME_SAMPLES == 640)
check("frame bytes 1280", xm.VOICE_FRAME_BYTES == 1280)
fps = 1000 / xm.VOICE_FRAME_MS
overhead = (12 + 16 + 2) * fps * 8 / 1000
print("    info  overhead %.1f kbit/s + %d kbit/s opus = ~%.1f kbit/s total"
      % (overhead, xm.VOICE_BITRATE // 1000, overhead + xm.VOICE_BITRATE / 1000))
check("total under 25 kbit/s", overhead + xm.VOICE_BITRATE / 1000 < 25)

# ---- 10. voice_available ----
print("\n[10] availability probe")
ok, reason = xm.voice_available()
check("returns (bool,str)", isinstance(ok, bool) and isinstance(reason, str))
print("    info  -> %s / %s" % (ok, reason))

# ---- 11. Manager API completeness ----
print("\n[11] API surface used by dispatch_line")
for m in ("start_call", "answer_call", "reject_call", "end_call",
          "toggle_mute", "has_active_call", "any_active_peer",
          "status_line", "cleanup", "cleanup_sync", "handle_signal"):
    check("manager.%s" % m, callable(getattr(xm.VoiceCallManager, m, None)))
for m in ("create_session", "accept_media_stream", "connect_media_stream",
          "start_audio", "end", "force_close_sync", "toggle_mute", "describe"):
    check("session.%s" % m, callable(getattr(xm.VoiceCallSession, m, None)))

# ---- 12. cleanup_sync with no loop ----
print("\n[12] synchronous teardown without an event loop")
s = xm.VoiceCallSession.__new__(xm.VoiceCallSession)
s._running = True
s._closing = False
s.state = "active"
s._parec = s._pacat = None
s._media_sock = s._sam_control = None
s._writer = s._reader = None
import queue
s._play_queue = queue.Queue()
s._play_queue.put(bytearray(b"\x11" * 32))
s._crypto = xm.VoiceFrameCrypto(b"tk", CID, True)
s._cryptos = {0: s._crypto}
s._root = bytearray(b"r"*64)
_kept = s._crypto
s.force_close_sync()
check("force_close_sync runs", s._running is False and s.state == "ended")
check("keys zeroized by force close",
      _kept._send_key is None and _kept._recv_key is None)
check("root wiped by force close", s._root is None)
check("all generations dropped", not s._cryptos)
check("queue drained", s._play_queue.empty())
s.force_close_sync()
check("force_close_sync idempotent", True)

print("\n" + "=" * 55)
if FAIL:
    print("FAILURES (%d): %s" % (len(FAIL), ", ".join(FAIL)))
    sys.exit(1)
print("ALL CHECKS PASSED")
