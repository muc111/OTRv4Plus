import sys
import os
import socket
import socks
import threading
try:
    from otrv4_core import RustDoubleRatchet as _RustRatchet
    RUST_RATCHET_AVAILABLE = True
except ImportError:
    RUST_RATCHET_AVAILABLE = False
try:
    from otrv4_core import RustDAKE as _RustDAKE
    import otrv4_core as _RustDAKE_module
    RUST_DAKE_AVAILABLE = True
except ImportError:
    _RustDAKE = None
    _RustDAKE_module = None
    RUST_DAKE_AVAILABLE = False
try:
    from otrv4_core import py_ring_sign as _rust_ring_sign
    from otrv4_core import py_ring_verify as _rust_ring_verify
    RUST_RING_SIG_AVAILABLE = True
except ImportError:
    _rust_ring_sign = None
    _rust_ring_verify = None
    RUST_RING_SIG_AVAILABLE = False

def _check_rust_requirements():
    if not RUST_DAKE_AVAILABLE or _RustDAKE is None:
        raise ImportError('OTRv4+ v10.6.11+ requires otrv4_core.RustDAKE.  The .so was not built with the dake module.  Rebuild Rust/ with: cargo build --release --features pq-rust')
    if not RUST_RING_SIG_AVAILABLE or _rust_ring_sign is None or _rust_ring_verify is None:
        raise ImportError('OTRv4+ v10.6.11+ requires otrv4_core.py_ring_sign and otrv4_core.py_ring_verify.  The .so was not built with the ring_sig module.  Rebuild Rust/ with the latest src/ring_sig.rs and src/lib.rs that registers it.')
    _required_methods = ['new_from_bytearrays', 'sign_profile_body_and_construct', 'sign_profile_body_and_construct_with_handles', 'ed448_sign_test', 'generate_dake2_output', 'process_dake2_output']
    _missing = [m for m in _required_methods if not hasattr(_RustDAKE, m)]
    if _missing:
        raise ImportError(f'OTRv4+ v10.6.11+ requires the following methods on otrv4_core.RustDAKE: {_required_methods}.  Missing: {_missing}.  Rebuild the .so from the current Rust/src/dake.rs.')
    _required_module_symbols = ['Ed448KeyHandle', 'X448KeyHandle', 'generate_ed448_keypair', 'generate_x448_keypair', 'verify_ed448_sig', 'mldsa87_keygen', 'mldsa87_sign', 'mldsa87_verify', 'aes256gcm_encrypt', 'aes256gcm_decrypt', 'mlkem1024_keygen', 'mlkem1024_encaps', 'mlkem1024_decaps']
    _missing_mod = [s for s in _required_module_symbols if not hasattr(_RustDAKE_module, s)]
    if _missing_mod:
        raise ImportError(f'OTRv4+ v10.6.20+ requires the following on the otrv4_core module: {_required_module_symbols}.  Missing: {_missing_mod}.  Rebuild the .so from the current Rust/src/key_handles.rs, Rust/src/mldsa.rs, Rust/src/aead.rs, Rust/src/mlkem.rs, and Rust/src/lib.rs.')
_check_rust_requirements()
import time
import secrets
import hashlib
import json
import signal
import re
import hmac
import struct
import base64
import math
import select
import ctypes
import ctypes.util
import tempfile
import getpass
import textwrap
import atexit
import gc
import resource
import shutil
import termios
import tty
import logging
import logging.handlers
from typing import Optional, Dict, Any, Tuple, List, Set, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
from enum import IntEnum
import concurrent.futures
CRYPTO_AVAILABLE = True
try:
    import resource as _resource
    _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
except Exception:
    pass
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
MLDSA87_AVAILABLE = True
try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    print('WARNING: argon2-cffi not installed. Using weaker key derivation.')
    print('For secure storage: pip install argon2-cffi')
    ARGON2_AVAILABLE = False

def secure_compare(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))

def secure_compare_bytes(a: bytes, b: bytes) -> bool:
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        return False
    return hmac.compare_digest(a, b)

def acquire_lock_with_timeout(lock: threading.RLock, timeout: float=5.0) -> bool:
    if lock is None:
        return True
    try:
        return lock.acquire(timeout=timeout)
    except Exception:
        return False

class OTRConstants:
    PROTOCOL_VERSION = 4
    SESSION_ID_BYTES = 32
    ED448_PUBLIC_KEY_SIZE = 57
    ED448_SIGNATURE_SIZE = 114
    X448_PUBLIC_KEY_SIZE = 56
    MESSAGE_TYPE_DAKE1 = 53
    MESSAGE_TYPE_DAKE2 = 54
    MESSAGE_TYPE_DAKE3 = 55
    MESSAGE_TYPE_DATA = 3
    TLV_TYPE_PADDING = 0
    TLV_TYPE_DISCONNECTED = 1
    TLV_TYPE_SMP_MESSAGE_1 = 2
    TLV_TYPE_SMP_MESSAGE_2 = 3
    TLV_TYPE_SMP_MESSAGE_3 = 4
    TLV_TYPE_SMP_MESSAGE_4 = 5
    TLV_TYPE_SMP_ABORT = 6
    TLV_TYPE_SMP_MESSAGE_1Q = 7
    TLV_TYPE_CLIENT_PROFILE = 8
    TLV_TYPE_EXTRA_SYMMETRIC_KEY = 9
    RATCHET_SENDING = 0
    RATCHET_RECEIVING = 1
    MAX_SKIP = 1000
    MAX_MESSAGE_KEYS = 2000
    RATCHET_INFO = b'OTR4-DH-Ratchet'
    REKEY_INTERVAL = 100
    REKEY_TIMEOUT = 86400

    class DAKEState:
        IDLE = 0
        SENT_DAKE1 = 1
        GOT_DAKE1 = 2
        SENT_DAKE2 = 3
        GOT_DAKE2 = 4
        SENT_DAKE3 = 5
        ESTABLISHED = 6
        FAILED = 7

class KDFUsage:
    SSID = 1
    BRACE_KEY = 2
    SHARED_SECRET = 3
    AUTH_R_MAC = 4
    AUTH_I_MSG = 5
    ROOT_KEY = 17
    CHAIN_KEY = 18
    MESSAGE_KEY = 19
    MAC_KEY = 20
    DAKE_MAC_KEY = 21
    EXTRA_SYM_KEY = 31
    BRACE_KEY_ROTATE = 22
_KDF_DOMAIN = b'OTRv4'

def kdf_1(usage_id: int, value: bytes, length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(_KDF_DOMAIN)
    shake.update(bytes([usage_id]))
    shake.update(value)
    return shake.digest(length)

def _secure_wipe(buf: bytearray) -> None:
    if buf is None:
        return
    try:
        n = len(buf)
        if n == 0:
            return
        addr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(addr, 0, n)
    except (TypeError, BufferError):
        try:
            for _i in range(len(buf)):
                buf[_i] = 0
        except (TypeError, IndexError):
            pass

def _secure_wipe_bytes(b: bytes) -> None:
    pass

def _secure_file_destroy(filepath: str) -> None:
    size = os.path.getsize(filepath)
    if size == 0:
        os.remove(filepath)
        return
    key = bytearray(os.urandom(32))
    nonce = os.urandom(12)
    try:
        plaintext_len = max(size - 16, 1)
        ct = _RustDAKE_module.aes256gcm_encrypt(bytes(key), nonce, b'\x00' * plaintext_len, b'wipe')
        with open(filepath, 'r+b') as f:
            written = 0
            while written < size:
                chunk = ct[written:written + 65536] if written < len(ct) else os.urandom(min(65536, size - written))
                f.write(chunk)
                written += len(chunk)
            f.flush()
            os.fsync(f.fileno())
        os.remove(filepath)
    finally:
        _secure_wipe(key)
        del key

class MLKEM1024BraceKEM:
    EK_BYTES = 1568
    CT_BYTES = 1568
    SS_BYTES = 32

    def __init__(self):
        ek, self._dk_handle = _RustDAKE_module.mlkem1024_keygen()
        self.encap_key_bytes: bytes = ek

    @classmethod
    def encapsulate(cls, ek_bytes: bytes) -> Tuple[bytes, bytes]:
        if len(ek_bytes) != cls.EK_BYTES:
            raise ValueError(f'ML-KEM-1024 encap key must be {cls.EK_BYTES} bytes, got {len(ek_bytes)}')
        ct, ss = _RustDAKE_module.mlkem1024_encaps(ek_bytes)
        return (ct, ss)

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        if len(ct_bytes) != self.CT_BYTES:
            raise ValueError(f'ML-KEM-1024 ciphertext must be {self.CT_BYTES} bytes, got {len(ct_bytes)}')
        return _RustDAKE_module.mlkem1024_decaps(ct_bytes, bytes(self._dk_handle))

    def zeroize(self):
        if self._dk_handle is not None:
            if isinstance(self._dk_handle, bytearray):
                _secure_wipe(self._dk_handle)
            self._dk_handle = None
        self.encap_key_bytes = b'\x00' * self.EK_BYTES

class MLDSA87Auth:
    PUB_BYTES = 2592
    PRIV_BYTES = 4896
    SIG_BYTES = 4627

    def __init__(self):
        pub, priv = _RustDAKE_module.mldsa87_keygen()
        self.pub_bytes: bytes = pub
        self._priv: bytearray = priv

    def sign(self, msg: bytes) -> bytes:
        if self._priv is None:
            raise RuntimeError('ML-DSA-87 private key has been zeroized')
        return _RustDAKE_module.mldsa87_sign(bytes(self._priv), msg)

    @classmethod
    def verify(cls, pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        if len(pub_bytes) != cls.PUB_BYTES:
            return False
        if len(sig) != cls.SIG_BYTES:
            return False
        try:
            return bool(_RustDAKE_module.mldsa87_verify(pub_bytes, msg, sig))
        except Exception:
            return False

    def zeroize(self):
        if self._priv is not None:
            _secure_wipe(self._priv)
            self._priv = None
        self.pub_bytes = b'\x00' * self.PUB_BYTES

class RingSignature:
    SCALAR_BYTES = 57
    TOTAL_BYTES = 4 * 57
    _USAGE_SIGMA = 28

    @classmethod
    def sign(cls, handle, A1_bytes: bytes, A2_bytes: bytes, msg: bytes) -> bytes:
        return bytes(handle.ring_sign(A1_bytes, A2_bytes, msg))

    @classmethod
    def verify(cls, A1_bytes: bytes, A2_bytes: bytes, msg: bytes, sig: bytes) -> bool:
        if len(sig) != cls.TOTAL_BYTES:
            return False
        try:
            return bool(_rust_ring_verify(A1_bytes, A2_bytes, msg, sig))
        except Exception:
            return False

class SessionState(IntEnum):
    PLAINTEXT = 0
    DAKE_IN_PROGRESS = 1
    ENCRYPTED = 2
    FINISHED = 3
    FAILED = 4

class DAKEState(IntEnum):
    IDLE = 0
    SENT_DAKE1 = 1
    RECEIVED_DAKE1 = 2
    SENT_DAKE2 = 3
    ESTABLISHED = 4
    FAILED = 5

class IRCConstants:
    PORT = 6667
    TLS_PORT = 6697
    DEFAULT_SERVER = 'irc.postman.i2p'
    DEFAULT_CHANNEL = '#otr'
    IRCV3_CAPS = ['sasl', 'multi-prefix', 'server-time', 'message-tags', 'account-notify', 'away-notify', 'cap-notify']
    RPL_LISTSTART = 321
    RPL_LIST = 322
    RPL_LISTEND = 323
    RPL_NAMREPLY = 353
    RPL_ENDOFNAMES = 366
    RPL_WHOISUSER = 311
    RPL_WHOISSERVER = 312
    RPL_WHOISOPERATOR = 313
    RPL_WHOISIDLE = 317
    RPL_ENDOFWHOIS = 318
    RPL_WHOISCHANNELS = 319
    RPL_TOPIC = 332
    RPL_TOPICWHOTIME = 333
    RPL_CHANNELMODEIS = 324

class UIConstants:
    MAX_HISTORY_LINES = 10000
    PAGER_LINES = 20
    NOTIFICATION_THRESHOLD = 3
    PANEL_SWITCH_DELAY = 0.5
    MAX_MESSAGE_LENGTH = 4096
    MAX_PRIVMSG_LENGTH = 350
    MESSAGE_FRAGMENT_SIZE = 450
    OTR_FRAGMENT_SIZE = 450
    FRAGMENT_TIMEOUT = 120.0
    FRAGMENT_LIMIT = 50
    SMP_FRAGMENT_LIMIT = 100
    HEARTBEAT_INTERVAL = 300
    DAKE_TIMEOUT = 120.0
    REKEY_INTERVAL = 100

    class SecurityLevel(IntEnum):
        PLAINTEXT = 0
        ENCRYPTED = 1
        FINGERPRINT = 2
        SMP_VERIFIED = 3

    class SMPState(IntEnum):
        NONE = 0
        EXPECT1 = 1
        SENT1 = 2
        EXPECT2 = 3
        SENT2 = 4
        EXPECT3 = 5
        SENT3 = 6
        EXPECT4 = 7
        SUCCEEDED = 8
        FAILED = 9
    COLORS = {'reset': '\x1b[0m', 'bold': '\x1b[1m', 'dim': '\x1b[2m', 'italic': '\x1b[3m', 'underline': '\x1b[4m', 'black': '\x1b[30m', 'red': '\x1b[91m', 'green': '\x1b[92m', 'yellow': '\x1b[93m', 'blue': '\x1b[94m', 'magenta': '\x1b[95m', 'cyan': '\x1b[96m', 'white': '\x1b[97m', 'dark_red': '\x1b[31m', 'dark_green': '\x1b[32m', 'dark_yellow': '\x1b[33m', 'dark_blue': '\x1b[34m', 'dark_magenta': '\x1b[35m', 'dark_cyan': '\x1b[36m', 'grey': '\x1b[90m', 'orange': '\x1b[38;5;214m', 'pink': '\x1b[38;5;213m', 'teal': '\x1b[38;5;43m', 'lime': '\x1b[38;5;118m', 'gold': '\x1b[38;5;220m', 'lavender': '\x1b[38;5;183m', 'bg_green': '\x1b[42m', 'bg_yellow': '\x1b[43m', 'bg_blue': '\x1b[44m', 'bg_magenta': '\x1b[45m', 'bg_cyan': '\x1b[46m', 'bg_red': '\x1b[41m', 'dim_italic': '\x1b[2;3m', 'bold_cyan': '\x1b[1;96m', 'bold_green': '\x1b[1;92m', 'bold_red': '\x1b[1;91m', 'bold_yellow': '\x1b[1;93m'}
    SECURITY_ICONS = {SecurityLevel.PLAINTEXT: '🔴', SecurityLevel.ENCRYPTED: '🟡', SecurityLevel.FINGERPRINT: '🟢', SecurityLevel.SMP_VERIFIED: '🔵'}
    SECURITY_NAMES = {SecurityLevel.PLAINTEXT: 'PLAINTEXT', SecurityLevel.ENCRYPTED: 'ENCRYPTED', SecurityLevel.FINGERPRINT: 'VERIFIED', SecurityLevel.SMP_VERIFIED: 'SMP VERIFIED'}
    USERNAME_COLORS = ['bold_cyan', 'magenta', 'bold_green', 'yellow', 'orange', 'pink', 'teal', 'gold', 'lavender', 'bold_yellow', 'cyan', 'dark_magenta']

def _probe_socks5(host: str, port: int, timeout: float=2.0) -> bool:
    import socket as _sock_mod
    try:
        with _sock_mod.socket(_sock_mod.AF_INET, _sock_mod.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
        return True
    except OSError:
        return False

class NetworkConstants:
    I2P_PROXY_HOST = '127.0.0.1'
    I2P_PROXY_PORT = 4447
    TOR_PROXY_HOST = '127.0.0.1'
    TOR_PROXY_PORT = 9050
    I2P_SUFFIXES = ('.i2p',)
    TOR_SUFFIXES = ('.onion',)
    TIMEOUT_CLEARNET = 30
    TIMEOUT_TOR = 90
    TIMEOUT_I2P = 120
    NET_CLEARNET = 'clearnet'
    NET_TOR = 'tor'
    NET_I2P = 'i2p'

    @staticmethod
    def detect(server: str) -> str:
        host = server.split(':')[0].lower().strip()
        for sfx in NetworkConstants.I2P_SUFFIXES:
            if host.endswith(sfx):
                return NetworkConstants.NET_I2P
        for sfx in NetworkConstants.TOR_SUFFIXES:
            if host.endswith(sfx):
                return NetworkConstants.NET_TOR
        return NetworkConstants.NET_CLEARNET
    MLOCK_PAGE_SIZE = 4096
    I2P_SAM_HOST = '127.0.0.1'
    I2P_SAM_PORT = 7656

class I2PSAMConnection:

    def __init__(self, sam_host: str=None, sam_port: int=None):
        self.sam_host = sam_host or NetworkConstants.I2P_SAM_HOST
        self.sam_port = sam_port or NetworkConstants.I2P_SAM_PORT
        self._session_id = f'otrv4plus_{secrets.token_hex(4)}'
        self._control_sock = None
        self._our_destination = None

    def _send_cmd(self, sock, cmd: str) -> str:
        sock.sendall((cmd + '\n').encode('utf-8'))
        buf = b''
        deadline = time.time() + 90
        while not buf.endswith(b'\n'):
            if time.time() > deadline:
                raise ConnectionError('SAM bridge timeout')
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError('SAM bridge closed connection')
            buf += chunk
        return buf.decode('utf-8').strip()

    def _parse_reply(self, reply: str, prefix: str) -> dict:
        if not reply.startswith(prefix):
            raise ConnectionError(f'SAM unexpected: {reply}')
        parts = reply[len(prefix):].strip().split(' ')
        result = {}
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                result[k] = v
        return result

    def _handshake(self, sock):
        reply = self._send_cmd(sock, 'HELLO VERSION MIN=3.1 MAX=3.1')
        parsed = self._parse_reply(reply, 'HELLO REPLY ')
        if parsed.get('RESULT') != 'OK':
            raise ConnectionError(f'SAM handshake failed: {reply}')

    def connect(self, target_host: str, target_port: int=0) -> 'socket.socket':
        resolve_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        resolve_sock.settimeout(90)
        try:
            resolve_sock.connect((self.sam_host, self.sam_port))
            self._handshake(resolve_sock)
            reply = self._send_cmd(resolve_sock, f'NAMING LOOKUP NAME={target_host}')
            parsed = self._parse_reply(reply, 'NAMING REPLY ')
            if parsed.get('RESULT') != 'OK':
                raise ConnectionError(f'Cannot resolve {target_host}: {reply}')
            dest_b64 = parsed['VALUE']
        finally:
            resolve_sock.close()
        self._control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._control_sock.settimeout(90)
        self._control_sock.connect((self.sam_host, self.sam_port))
        self._handshake(self._control_sock)
        reply = self._send_cmd(self._control_sock, f'SESSION CREATE STYLE=STREAM ID={self._session_id} DESTINATION=TRANSIENT SIGNATURE_TYPE=7')
        parsed = self._parse_reply(reply, 'SESSION STATUS ')
        if parsed.get('RESULT') != 'OK':
            self._control_sock.close()
            raise ConnectionError(f'SAM session failed: {reply}')
        self._our_destination = parsed.get('DESTINATION', '')
        stream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stream_sock.settimeout(NetworkConstants.TIMEOUT_I2P)
        stream_sock.connect((self.sam_host, self.sam_port))
        self._handshake(stream_sock)
        reply = self._send_cmd(stream_sock, f'STREAM CONNECT ID={self._session_id} DESTINATION={dest_b64} SILENT=false')
        parsed = self._parse_reply(reply, 'STREAM STATUS ')
        if parsed.get('RESULT') != 'OK':
            stream_sock.close()
            self._control_sock.close()
            raise ConnectionError(f'SAM stream connect failed: {reply}')
        stream_sock.settimeout(1.0)
        return stream_sock

    def close(self):
        try:
            if self._control_sock:
                self._control_sock.close()
                self._control_sock = None
        except Exception:
            pass
        self._our_destination = None

    @staticmethod
    def is_available(host: str=None, port: int=None) -> bool:
        host = host or NetworkConstants.I2P_SAM_HOST
        port = port or NetworkConstants.I2P_SAM_PORT
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.sendall(b'HELLO VERSION MIN=3.1 MAX=3.1\n')
            reply = sock.recv(256)
            sock.close()
            return b'RESULT=OK' in reply
        except Exception:
            return False

class BinaryReader:

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError(f'Expected bytes, got {type(data)}')
        self.data = data
        self.offset = 0
        self.length = len(data)

    def remaining(self) -> int:
        return self.length - self.offset

    def ensure(self, needed: int) -> None:
        remaining = self.remaining()
        if remaining < needed:
            raise ValueError(f'Truncated: need {needed} bytes, have {remaining}')

    def read_uint8(self) -> int:
        try:
            self.ensure(1)
            val = self.data[self.offset]
            self.offset += 1
            return val
        except IndexError as e:
            raise ValueError(f'Failed to read uint8: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading uint8: {e}')

    def read_uint16(self) -> int:
        try:
            self.ensure(2)
            val = struct.unpack('>H', self.data[self.offset:self.offset + 2])[0]
            self.offset += 2
            return val
        except struct.error as e:
            raise ValueError(f'Failed to unpack uint16: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading uint16: {e}')

    def read_uint32(self) -> int:
        try:
            self.ensure(4)
            val = struct.unpack('>I', self.data[self.offset:self.offset + 4])[0]
            self.offset += 4
            return val
        except struct.error as e:
            raise ValueError(f'Failed to unpack uint32: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading uint32: {e}')

    def read_uint64(self) -> int:
        try:
            self.ensure(8)
            val = struct.unpack('>Q', self.data[self.offset:self.offset + 8])[0]
            self.offset += 8
            return val
        except struct.error as e:
            raise ValueError(f'Failed to unpack uint64: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading uint64: {e}')

    def read_bytes(self, length: int) -> bytes:
        try:
            if length < 0:
                raise ValueError(f'Negative length: {length}')
            self.ensure(length)
            val = self.data[self.offset:self.offset + length]
            self.offset += length
            return val
        except IndexError as e:
            raise ValueError(f'Failed to read {length} bytes: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading bytes: {e}')

    def read_mpi(self) -> bytes:
        try:
            length = self.read_uint32()
            if length == 0:
                return b''
            if length > 1024 * 1024:
                raise ValueError(f'MPI too large: {length}')
            return self.read_bytes(length)
        except ValueError as e:
            raise ValueError(f'Invalid MPI: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error reading MPI: {e}')

    def read_varbytes(self) -> bytes:
        return self.read_mpi()

    def expect_end(self) -> None:
        if self.offset != self.length:
            raise ValueError(f'Trailing bytes: {self.length - self.offset} remaining')

def _generate_instance_tag() -> int:
    while True:
        a = int.from_bytes(secrets.token_bytes(4), 'big')
        b = int.from_bytes(os.urandom(4), 'big')
        tag = a ^ b
        if 256 <= tag <= 4294967295:
            return tag

class OTRv4TLV:
    __slots__ = ('type', 'value')
    PADDING = 0
    DISCONNECTED = 1
    SMP_MSG_1 = 2
    SMP_MSG_2 = 3
    SMP_MSG_3 = 4
    SMP_MSG_4 = 5
    SMP_ABORT = 6
    SMP_MSG_1Q = 7
    EXTRA_SYMMETRIC_KEY = 9
    SMP_TYPES = frozenset({SMP_MSG_1, SMP_MSG_2, SMP_MSG_3, SMP_MSG_4, SMP_ABORT, SMP_MSG_1Q})

    def __init__(self, tlv_type: int, value: bytes=b''):
        if not 0 <= tlv_type <= 65535:
            raise ValueError(f'TLV type out of range: {tlv_type:#06x}')
        if len(value) > 65535:
            raise ValueError(f'TLV value too large: {len(value)} bytes (max 65535)')
        self.type = tlv_type
        self.value = bytes(value)

    def encode(self) -> bytes:
        return struct.pack('!HH', self.type, len(self.value)) + self.value

    @classmethod
    def decode_one(cls, data: bytes, offset: int=0) -> Tuple['OTRv4TLV', int]:
        if offset + 4 > len(data):
            raise ValueError(f'TLV header truncated at offset {offset} (need 4, have {len(data) - offset})')
        tlv_type, length = struct.unpack_from('!HH', data, offset)
        end = offset + 4 + length
        if end > len(data):
            raise ValueError(f'TLV value truncated: type=0x{tlv_type:04x} declares {length} bytes but only {len(data) - offset - 4} available')
        return (cls(tlv_type, data[offset + 4:end]), end)

    @classmethod
    def decode_all(cls, data: bytes) -> List['OTRv4TLV']:
        tlvs: List['OTRv4TLV'] = []
        offset = 0
        while offset < len(data):
            tlv, offset = cls.decode_one(data, offset)
            tlvs.append(tlv)
        return tlvs

    @classmethod
    def encode_all(cls, tlvs: List['OTRv4TLV']) -> bytes:
        return b''.join((t.encode() for t in tlvs))

    @classmethod
    def random_padding(cls, min_bytes: int=8, max_bytes: int=72) -> 'OTRv4TLV':
        pad_len = secrets.randbelow(max_bytes - min_bytes + 1) + min_bytes
        return cls(cls.PADDING, os.urandom(pad_len))

    def __repr__(self) -> str:
        _NAMES = {0: 'PADDING', 1: 'DISCONNECTED', 2: 'SMP_MSG_1', 3: 'SMP_MSG_2', 4: 'SMP_MSG_3', 5: 'SMP_MSG_4', 6: 'SMP_ABORT', 7: 'SMP_MSG_1Q', 8: 'EXTRA_SYMMETRIC_KEY'}
        name = _NAMES.get(self.type, f'UNKNOWN(0x{self.type:04x})')
        return f'OTRv4TLV({name}, {len(self.value)} bytes)'

class OTRv4Payload:
    __slots__ = ('text', 'tlvs')

    def __init__(self, text: str='', tlvs: Optional[List['OTRv4TLV']]=None):
        self.text = text or ''
        self.tlvs: List[OTRv4TLV] = list(tlvs) if tlvs else []

    def encode(self, add_padding: bool=True) -> bytes:
        text_bytes = self.text.encode('utf-8') if self.text else b''
        tlvs = list(self.tlvs)
        if add_padding:
            tlvs.append(OTRv4TLV.random_padding())
        if tlvs:
            return text_bytes + b'\x00' + OTRv4TLV.encode_all(tlvs)
        return text_bytes

    @classmethod
    def decode(cls, data: bytes) -> 'OTRv4Payload':
        null_pos = data.find(b'\x00')
        if null_pos == -1:
            return cls(data.decode('utf-8', errors='replace'), [])
        text = data[:null_pos].decode('utf-8', errors='replace')
        tlv_bytes = data[null_pos + 1:]
        if not tlv_bytes:
            return cls(text, [])
        all_tlvs = OTRv4TLV.decode_all(tlv_bytes)
        non_padding = [t for t in all_tlvs if t.type != OTRv4TLV.PADDING]
        return cls(text, non_padding)

class OTRv4DataMessage:
    PROTOCOL_VERSION = 4
    TYPE = 3
    ECDH_LEN = 56
    NONCE_LEN = 12
    MAC_LEN = 64
    FLAG_IGNORE_UNREADABLE = 1

    def __init__(self):
        self.sender_tag: int = 0
        self.receiver_tag: int = 0
        self.flags: int = 0
        self.prev_chain_len: int = 0
        self.ratchet_id: int = 0
        self.message_id: int = 0
        self.ecdh_pub: bytes = b''
        self.dh_pub: Optional[bytes] = None
        self.kem_ek: Optional[bytes] = None
        self.kem_ct: Optional[bytes] = None
        self.nonce: bytes = b''
        self.ciphertext: bytes = b''
        self.mac: bytes = b''
        self.revealed_mac_keys: List[bytes] = []

    def _auth_header(self) -> bytes:
        try:
            if len(self.ecdh_pub) != self.ECDH_LEN:
                raise ValueError(f'ECDH key must be {self.ECDH_LEN} bytes')
            if len(self.nonce) != self.NONCE_LEN:
                raise ValueError(f'Nonce must be {self.NONCE_LEN} bytes')
            buf = bytearray()
            buf += struct.pack('!HB', self.PROTOCOL_VERSION, self.TYPE)
            buf += struct.pack('!II', self.sender_tag, self.receiver_tag)
            buf += struct.pack('!B', self.flags)
            buf += struct.pack('!III', self.prev_chain_len, self.ratchet_id, self.message_id)
            buf += self.ecdh_pub
            if self.dh_pub is not None:
                if len(self.dh_pub) != self.ECDH_LEN:
                    raise ValueError(f'DH key must be {self.ECDH_LEN} bytes')
                buf += b'\x01' + self.dh_pub
            else:
                buf += b'\x00'
            if self.kem_ek is not None:
                if len(self.kem_ek) != MLKEM1024BraceKEM.EK_BYTES:
                    raise ValueError(f'KEM ek must be {MLKEM1024BraceKEM.EK_BYTES} bytes')
                buf += b'\x01' + self.kem_ek
            else:
                buf += b'\x00'
            if self.kem_ct is not None:
                if len(self.kem_ct) != MLKEM1024BraceKEM.CT_BYTES:
                    raise ValueError(f'KEM ct must be {MLKEM1024BraceKEM.CT_BYTES} bytes')
                buf += b'\x01' + self.kem_ct
            else:
                buf += b'\x00'
            buf += self.nonce
            return bytes(buf)
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f'Failed to build auth header: {e}')

    def compute_mac(self, mac_key: bytes) -> bytes:
        try:
            ah = self._auth_header()
            ct = struct.pack('!I', len(self.ciphertext)) + self.ciphertext
            return hashlib.sha3_512(mac_key + ah + ct).digest()
        except (TypeError, ValueError, struct.error) as e:
            raise ValueError(f'Failed to compute MAC: {e}')

    def verify_mac(self, mac_key: bytes) -> bool:
        try:
            if len(self.mac) != self.MAC_LEN:
                return False
            computed = self.compute_mac(mac_key)
            return hmac.compare_digest(self.mac, computed)
        except (TypeError, ValueError) as e:
            if DEBUG_MODE:
                safe_print(f'[OTRv4DataMessage] MAC verification error: {e}')
            return False
        except Exception:
            return False

    def encode(self) -> bytes:
        try:
            ah = self._auth_header()
            ct_blk = struct.pack('!I', len(self.ciphertext)) + self.ciphertext
            mac = self.mac if len(self.mac) == self.MAC_LEN else b'\x00' * self.MAC_LEN
            keys = struct.pack('!I', len(self.revealed_mac_keys))
            for k in self.revealed_mac_keys:
                if len(k) != 32:
                    raise ValueError(f'Revealed MAC key must be 32 bytes, got {len(k)}')
                keys += k
            return ah + ct_blk + mac + keys
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f'Failed to encode message: {e}')

    @classmethod
    def decode(cls, data: bytes) -> 'OTRv4DataMessage':
        try:
            r = BinaryReader(data)
            msg = cls()
            ver = r.read_uint16()
            if ver != cls.PROTOCOL_VERSION:
                raise ValueError(f'Wrong OTRv4 version: 0x{ver:04x}')
            mtype = r.read_uint8()
            if mtype != cls.TYPE:
                raise ValueError(f'Wrong message type: 0x{mtype:02x} (expected 0x{cls.TYPE:02x})')
            msg.sender_tag = r.read_uint32()
            msg.receiver_tag = r.read_uint32()
            msg.flags = r.read_uint8()
            msg.prev_chain_len = r.read_uint32()
            msg.ratchet_id = r.read_uint32()
            msg.message_id = r.read_uint32()
            msg.ecdh_pub = r.read_bytes(cls.ECDH_LEN)
            dh_flag = r.read_uint8()
            if dh_flag == 1:
                msg.dh_pub = r.read_bytes(cls.ECDH_LEN)
            elif dh_flag != 0:
                raise ValueError(f'Invalid DH flag byte: 0x{dh_flag:02x}')
            kem_ek_flag = r.read_uint8()
            if kem_ek_flag == 1:
                msg.kem_ek = r.read_bytes(MLKEM1024BraceKEM.EK_BYTES)
            elif kem_ek_flag != 0:
                raise ValueError(f'Invalid KEM ek flag: 0x{kem_ek_flag:02x}')
            kem_ct_flag = r.read_uint8()
            if kem_ct_flag == 1:
                msg.kem_ct = r.read_bytes(MLKEM1024BraceKEM.CT_BYTES)
            elif kem_ct_flag != 0:
                raise ValueError(f'Invalid KEM ct flag: 0x{kem_ct_flag:02x}')
            msg.nonce = r.read_bytes(cls.NONCE_LEN)
            ct_len = r.read_uint32()
            msg.ciphertext = r.read_bytes(ct_len)
            msg.mac = r.read_bytes(cls.MAC_LEN)
            num_keys = r.read_uint32()
            if num_keys > 2000:
                raise ValueError(f'Implausible revealed key count: {num_keys}')
            for _ in range(num_keys):
                msg.revealed_mac_keys.append(r.read_bytes(32))
            return msg
        except (ValueError, struct.error, TypeError) as e:
            raise ValueError(f'Failed to decode message: {e}')
VERSION = 'OTRv4+ 10.8.1'
if not hasattr(hashlib, 'sha3_512'):
    raise RuntimeError('FATAL: SHA3-512 is required by OTRv4 §3.2 but is unavailable in this Python build.  Please upgrade to Python ≥ 3.6 with SHA3 support.')
DEBUG_MODE = '--debug' in sys.argv or '-d' in sys.argv
SMP_DEBUG = DEBUG_MODE or '--smp-debug' in sys.argv
TEST_MODE = '--test' in sys.argv
global IS_TERMUX
IS_TERMUX = 'ANDROID_ROOT' in os.environ or 'TERMUX_VERSION' in os.environ
try:
    terminal_size = shutil.get_terminal_size(fallback=(80, 24))
    TERMINAL_WIDTH = terminal_size.columns
    TERMINAL_HEIGHT = terminal_size.lines
    if IS_TERMUX and TERMINAL_WIDTH < 40:
        TERMINAL_WIDTH = 80
except Exception:
    TERMINAL_WIDTH = 80
    TERMINAL_HEIGHT = 24

def _sanitise(text: str, max_len: int=512) -> str:
    text = re.sub('\\x1b[P\\]X\\^_][^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)', '', text)
    text = re.sub('\\x1b\\[[\\x30-\\x3f]*[\\x20-\\x2f]*[\\x40-\\x7e]', '', text)
    text = re.sub('\\x1b[\\x20-\\x2f][\\x30-\\x7e]', '', text)
    text = re.sub('\\x1b.', '', text, flags=re.DOTALL)
    text = re.sub('\\x03(?:\\d{1,2}(?:,\\d{1,2})?)?', '', text)
    text = re.sub('[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\\x7f\\x80-\\x9f]', '', text)
    return text[:max_len]

def colorize(text: str, color: str) -> str:
    return f'{UIConstants.COLORS.get(color, '')}{text}{UIConstants.COLORS['reset']}'

def colorize_username(username: str) -> str:
    if not username:
        return ''
    username = _sanitise(username, 64)
    if not username:
        return ''
    R = UIConstants.COLORS['reset']
    DI = UIConstants.COLORS['dim_italic']
    if '.' in username and (not username.startswith('#')):
        return f'{DI}{UIConstants.COLORS['dark_cyan']}{username}{R}'
    _services = ('chanserv', 'nickserv', 'memoserv', 'operserv', 'botserv', 'hostserv', 'groupserv', 'global', 'alis')
    if username.lower() in _services:
        return f'{DI}{UIConstants.COLORS['dark_magenta']}{username}{R}'
    h = 2166136261
    for c in username:
        h = (h ^ ord(c)) * 16777619 & 4294967295
    color = UIConstants.USERNAME_COLORS[h % len(UIConstants.USERNAME_COLORS)]
    return colorize(username, color)
_print_lock = threading.Lock()
_current_prompt: str = ''
_input_buffer: List[str] = []
_raw_mode_active = False
_stdin_fd: int = -1
_orig_termios = None

def _setup_raw_mode() -> bool:
    global _raw_mode_active, _stdin_fd, _orig_termios
    if not sys.stdin.isatty():
        return False
    try:
        import termios as _tm
        _stdin_fd = sys.stdin.fileno()
        _orig_termios = _tm.tcgetattr(_stdin_fd)
        new = _tm.tcgetattr(_stdin_fd)
        new[3] &= ~(_tm.ECHO | _tm.ICANON | _tm.ECHOE | _tm.ECHOK | _tm.ECHONL)
        new[6][_tm.VMIN] = 1
        new[6][_tm.VTIME] = 0
        _tm.tcsetattr(_stdin_fd, _tm.TCSADRAIN, new)
        _raw_mode_active = True
        return True
    except Exception:
        return False

def _restore_terminal() -> None:
    global _raw_mode_active
    if _raw_mode_active and _stdin_fd >= 0 and (_orig_termios is not None):
        try:
            import termios as _tm
            _tm.tcsetattr(_stdin_fd, _tm.TCSADRAIN, _orig_termios)
        except Exception:
            pass
        _raw_mode_active = False

def _read_one_char() -> Optional[str]:
    b = os.read(_stdin_fd, 1)
    if not b:
        return None
    byte = b[0]
    if byte < 128:
        return chr(byte)
    if byte < 192:
        return None
    remaining = 1 if byte < 224 else 2 if byte < 240 else 3
    data = b
    for _ in range(remaining):
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            break
        data += b2
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return None

def _consume_escape_seq() -> None:
    try:
        r, _, _ = select.select([_stdin_fd], [], [], 0.05)
        if not r:
            return
        b2 = os.read(_stdin_fd, 1)
        if not b2:
            return
        if b2 in (b'[', b'O'):
            while True:
                r2, _, _ = select.select([_stdin_fd], [], [], 0.05)
                if not r2:
                    break
                b3 = os.read(_stdin_fd, 1)
                if not b3 or 64 <= b3[0] <= 126:
                    break
    except Exception:
        pass
_EOF_SENTINEL = object()

def _handle_input_char(ch: str):
    if ch == '\r' or ch == '\n':
        with _print_lock:
            line = ''.join(_input_buffer)
            _input_buffer.clear()
            _ansi_strip = re.compile('\\x1b\\[[0-9;]*m')
            _vis_prompt = _ansi_strip.sub('', _current_prompt)
            _total = len(_vis_prompt) + len(line)
            _tw = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
            _lines = max(1, (_total + _tw - 1) // _tw)
            if _lines > 1:
                sys.stdout.write(f'\x1b[{_lines - 1}A')
            sys.stdout.write('\r')
            for _ in range(_lines):
                sys.stdout.write('\x1b[2K\n')
            sys.stdout.write(f'\x1b[{_lines}A\r')
            sys.stdout.flush()
        return line
    if ch == '\x04':
        with _print_lock:
            if not _input_buffer:
                return _EOF_SENTINEL
        return None
    if ch == '\x15':
        with _print_lock:
            _input_buffer.clear()
            sys.stdout.write('\r\x1b[2K' + _current_prompt)
            sys.stdout.flush()
        return None
    if ch == '\x17':
        with _print_lock:
            while _input_buffer and _input_buffer[-1] == ' ':
                _input_buffer.pop()
            while _input_buffer and _input_buffer[-1] != ' ':
                _input_buffer.pop()
            sys.stdout.write('\r\x1b[2K' + _current_prompt + ''.join(_input_buffer))
            sys.stdout.flush()
        return None
    if ch in ('\x7f', '\x08'):
        with _print_lock:
            if _input_buffer:
                _input_buffer.pop()
                sys.stdout.write('\x08 \x08')
                sys.stdout.flush()
        return None
    if ch == '\x1b':
        _consume_escape_seq()
        return None
    if ch == '\t':
        return None
    if ch >= ' ':
        with _print_lock:
            _input_buffer.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
        return None
    return None

def _set_prompt(prompt: str) -> None:
    global _current_prompt
    with _print_lock:
        buf = ''.join(_input_buffer)
        if _current_prompt or buf:
            sys.stdout.write('\x1b[1G\x1b[2K')
        _current_prompt = prompt
        sys.stdout.write(prompt + buf)
        sys.stdout.flush()
_ANSI_RE = re.compile('\\x1b\\[[0-9;]*[A-Za-z]')

def _visible_len(text: str) -> int:
    return len(_ANSI_RE.sub('', text))

def _word_wrap(text: str, width: int) -> str:
    if width < 20 or _visible_len(text) <= width:
        return text
    vis = _ANSI_RE.sub('', text)
    _bracket_end = vis.find('] ')
    if _bracket_end != -1 and _bracket_end < width // 2:
        indent = _bracket_end + 2
    else:
        indent = 4
    indent_str = ' ' * indent
    parts = _ANSI_RE.split(text)
    codes = _ANSI_RE.findall(text)
    tokens = []
    for i, part in enumerate(parts):
        if part:
            tokens.append((part, False))
        if i < len(codes):
            tokens.append((codes[i], True))
    lines = []
    current_line = ''
    current_vis = 0
    first_line = True
    for token_str, is_ansi in tokens:
        if is_ansi:
            current_line += token_str
            continue
        words = token_str.split(' ')
        for wi, word in enumerate(words):
            if wi > 0:
                space_fits = current_vis + 1 + len(word) <= width
                if current_vis > 0 and (not space_fits) and (len(word) > 0):
                    lines.append(current_line)
                    current_line = indent_str + word if not first_line else indent_str + word
                    first_line = False
                    current_vis = indent + len(word)
                else:
                    current_line += ' ' + word
                    current_vis += 1 + len(word)
            elif current_vis + len(word) > width and current_vis > 0:
                lines.append(current_line)
                current_line = indent_str + word
                first_line = False
                current_vis = indent + len(word)
            else:
                current_line += word
                current_vis += len(word)
    if current_line:
        lines.append(current_line)
    return '\n'.join(lines)
_scroll_locked = False
_scroll_buffer: deque = deque(maxlen=500)

def _emit_line(text: str) -> None:
    global _scroll_locked
    wrapped = _word_wrap(text, TERMINAL_WIDTH)
    try:
        if _scroll_locked:
            _scroll_buffer.append(wrapped)
            with _print_lock:
                buf = ''.join(_input_buffer)
                sys.stdout.write('\r\x1b[2K')
                sys.stdout.write(f'\x1b[33m[PAUSED — {len(_scroll_buffer)} buffered]\x1b[0m ' + _current_prompt + buf)
                sys.stdout.flush()
            return
        with _print_lock:
            buf = ''.join(_input_buffer)
            # Use live terminal width — keyboard popup on mobile shrinks
            # the terminal but TERMINAL_WIDTH is set only at startup.
            try:
                _cols = max(1, shutil.get_terminal_size(fallback=(80, 24)).columns)
            except Exception:
                _cols = max(1, TERMINAL_WIDTH)
            _pvis = len(_ANSI_RE.sub('', _current_prompt + buf))
            _extra_rows = max(0, (_pvis - 1) // _cols)
            if _extra_rows > 0:
                sys.stdout.write(f'\x1b[{_extra_rows}A')
            # \x1b[1G = move to column 1; \x1b[2K = erase entire line.
            # More reliable than \r\x1b[2K across mobile terminal emulators.
            sys.stdout.write('\x1b[1G\x1b[2K')
            sys.stdout.write(wrapped + '\n')
            if _current_prompt or buf:
                sys.stdout.write(_current_prompt + buf)
            sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass

def _scroll_unlock() -> None:
    global _scroll_locked
    _scroll_locked = False
    with _print_lock:
        sys.stdout.write('\r\x1b[2K')
        while _scroll_buffer:
            sys.stdout.write(_scroll_buffer.popleft() + '\n')
        buf = ''.join(_input_buffer)
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()
_display_queue: deque = deque()

def _flush_display_queue() -> None:
    if not _display_queue:
        return
    with _print_lock:
        buf = ''.join(_input_buffer)
        sys.stdout.write('\r\x1b[2K')
        while _display_queue:
            sys.stdout.write(_display_queue.popleft() + '\n')
        if _current_prompt or buf:
            sys.stdout.write(_current_prompt + buf)
        sys.stdout.flush()

def safe_print(*args, **kwargs):
    kwargs['flush'] = True
    try:
        with _print_lock:
            buf = ''.join(_input_buffer)
            if (_current_prompt or buf) and _raw_mode_active:
                sys.stdout.write('\r\x1b[2K')
            print(*args, **kwargs)
            if (_current_prompt or buf) and _raw_mode_active:
                sys.stdout.write(_current_prompt + buf)
                sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass

@dataclass
class OTRConfig:
    trust_db_path: Optional[str] = None
    smp_secrets_path: Optional[str] = None
    key_storage_path: Optional[str] = None
    log_file_path: Optional[str] = None
    test_mode: bool = False
    i2p_proxy: Tuple[str, int] = ('127.0.0.1', 4447)
    i2p_sam: Tuple[str, int] = ('127.0.0.1', 7656)
    tor_proxy: Tuple[str, int] = ('127.0.0.1', 9050)
    server: str = 'irc.postman.i2p'
    port: int = 0
    use_tls: bool = False
    sasl_user: Optional[str] = None
    sasl_pass: Optional[str] = None
    channel: str = '#otr'
    log_level: str = 'INFO'
    dake_timeout: float = 120.0
    fragment_timeout: float = 120.0
    heartbeat_interval: int = 300
    rekey_interval: int = 100
    nickserv_login: bool = False
    nickserv_register: bool = False
    nickserv_nick: Optional[str] = None
    nickserv_pass: Optional[str] = None

@dataclass
class IRCMessage:
    raw: str
    prefix: Optional[str]
    command: str
    params: List[str]
    trailing: Optional[str]
    timestamp: float
    sender: Optional[str]

@dataclass
class RecoveryState:
    session_id: bytes
    last_message_counter: int
    recovery_attempts: int = 0
    security_level: UIConstants.SecurityLevel = UIConstants.SecurityLevel.PLAINTEXT
    timestamp: float = time.time()

class StateMachineError(Exception):
    pass

class EncryptionError(Exception):

    def __init__(self, message: str, session: Optional['OTRSession']=None):
        super().__init__(message)
        self.session = session

class TypeValidationError(Exception):
    pass

class NullLogger:

    def __init__(self):
        pass

    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        pass

    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        pass

    def ui_interaction(self, action: str, panel: str, user_input: str):
        pass

    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        pass

    def info(self, msg: str):
        pass

    def warning(self, msg: str):
        pass

    def error(self, msg: str):
        pass

    def debug(self, msg: str):
        pass

class OTRLogger:

    def __init__(self, config: Optional[OTRConfig]=None):
        self.config = config or OTRConfig()
        self._setup_loggers()

    def _setup_loggers(self):
        log_dir = os.path.dirname(self.config.log_file_path or '~/.otrv4/logs/otrv4.log')
        log_dir = os.path.expanduser(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        try:
            os.chmod(log_dir, 448)
        except Exception:
            pass
        log_file = self.config.log_file_path or os.path.join(log_dir, 'otrv4plus.log')
        if not os.path.exists(log_file):
            try:
                with open(log_file, 'a'):
                    pass
                os.chmod(log_file, 384)
            except Exception:
                pass
        handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s')
        handler.setFormatter(formatter)
        self.security_logger = logging.getLogger('otrv4.security')
        self.network_logger = logging.getLogger('otrv4.network')
        self.ui_logger = logging.getLogger('otrv4.ui')
        self.session_logger = logging.getLogger('otrv4.session')
        for logger in [self.security_logger, self.network_logger, self.ui_logger, self.session_logger]:
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
            logger.propagate = False

    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        self.security_logger.info(f'EVENT={event} | SESSION={session_id} | PEER={peer} | {json.dumps(details)}')

    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        self.network_logger.debug(f'DIRECTION={direction} | PEER={peer} | TYPE={msg_type} | LENGTH={length}')

    def ui_interaction(self, action: str, panel: str, user_input: str):
        self.ui_logger.info(f'ACTION={action} | PANEL={panel} | INPUT_LENGTH={len(user_input)}')

    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        self.session_logger.info(f'TRANSITION={old_state}→{new_state} | PEER={peer} | SESSION={session_id}')

    def info(self, msg: str):
        self.security_logger.info(msg)

    def warning(self, msg: str):
        self.security_logger.warning(msg)

    def error(self, msg: str):
        self.security_logger.error(msg)

    def debug(self, msg: str):
        self.security_logger.debug(msg)

class OTRTracer:

    def __init__(self, enabled: bool=True, logger: Optional[OTRLogger]=None):
        self.enabled = enabled or DEBUG_MODE
        self.logger = logger
        self.peer_states: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self._emit_cb = None

    def set_emit_callback(self, cb) -> None:
        self._emit_cb = cb

    def trace(self, peer: str, category: str, old_state: Any, new_state: Any, reason: Optional[str]=None, details: Optional[Dict]=None):
        if not self.enabled:
            return
        with self.lock:
            if peer not in self.peer_states:
                self.peer_states[peer] = {}
            self.peer_states[peer][category] = new_state
            old_str = str(old_state).replace('State.', '').replace('SMPState.', '').replace('DAKEState.', '')
            new_str = str(new_state).replace('State.', '').replace('SMPState.', '').replace('DAKEState.', '')
            msg = f'[OTR:{peer}] {category}: {old_str} → {new_str}'
            if reason:
                msg += f' | {reason}'
            if self.logger:
                self.logger.session_transition(old_str, new_str, peer, category)
            color = 'green' if 'ESTABLISHED' in new_str or 'ENCRYPTED' in new_str else 'red' if 'FAILED' in new_str else 'yellow' if 'SENT' in new_str or 'RECEIVED' in new_str else 'cyan'
            colored_msg = colorize(msg, color)
            if self._emit_cb:
                self._emit_cb(colored_msg)
                if details and DEBUG_MODE:
                    for k, v in details.items():
                        if k not in ('secret', 'key', 'nonce', 'private', 'password'):
                            self._emit_cb(f'  {k}: {v}')

    def get_peer_state(self, peer: str, category: Optional[str]=None) -> Any:
        with self.lock:
            if peer not in self.peer_states:
                return None
            if category:
                return self.peer_states[peer].get(category)
            return self.peer_states[peer].copy()

    def reset_peer(self, peer: str):
        with self.lock:
            if peer in self.peer_states:
                del self.peer_states[peer]
                self.trace(peer, 'TRACER', 'ACTIVE', 'RESET', 'peer reset')

    def is_session_encrypted(self, peer: str) -> bool:
        with self.lock:
            state = self.get_peer_state(peer, 'SESSION')
            return state == 'ENCRYPTED'

    def is_dake_complete(self, peer: str) -> bool:
        with self.lock:
            state = self.get_peer_state(peer, 'DAKE')
            return state == 'ESTABLISHED'

    def format_state_report(self, peer: str) -> str:
        with self.lock:
            if peer not in self.peer_states:
                return f'No state tracked for {peer}'
            report = []
            report.append(f'OTR State Report for {colorize_username(peer)}:')
            for category, state in sorted(self.peer_states[peer].items()):
                state_str = str(state).replace('State.', '').replace('SMPState.', '').replace('DAKEState.', '')
                report.append(f'  {category:12} : {state_str}')
            return '\n'.join(report)

class SecureMemory:

    def __init__(self, size: int):
        self._size = size
        self._locked = False
        self._buffer: Optional[bytearray] = None
        self._lock = threading.RLock()
        self._libc = None
        aligned_size = (size + NetworkConstants.MLOCK_PAGE_SIZE - 1) // NetworkConstants.MLOCK_PAGE_SIZE * NetworkConstants.MLOCK_PAGE_SIZE
        with self._lock:
            self._buffer = bytearray(aligned_size)
            self._attempt_mlock()

    def _attempt_mlock(self):
        try:
            libc_names = ['libc.so.6', 'libc.so', 'libc.dylib', 'libc']
            for name in libc_names:
                try:
                    self._libc = ctypes.CDLL(ctypes.util.find_library(name) or name)
                    break
                except (OSError, TypeError) as e:
                    continue
            if self._libc is None:
                self._log_mlock_failure('No libc found')
                return
            buf_addr = ctypes.c_void_p.from_buffer(self._buffer)
            buf_size = len(self._buffer)
            if hasattr(self._libc, 'mlock'):
                result = self._libc.mlock(buf_addr, buf_size)
                if result == 0:
                    self._locked = True
                else:
                    errno = ctypes.get_errno()
                    self._log_mlock_failure(f'mlock failed with errno: {errno}')
            else:
                self._log_mlock_failure('mlock function not found')
        except (OSError, AttributeError, ValueError, Exception) as e:
            self._log_mlock_failure(f'Exception: {e}')

    def _log_mlock_failure(self, reason: str):
        if DEBUG_MODE:
            print(f'[SecureMemory] Warning: {reason} - memory not locked')

    def zeroize(self):
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError('Failed to acquire lock for zeroize')
        try:
            if self._buffer is None:
                return
            try:
                n = len(self._buffer)
                if n > 0:
                    addr = (ctypes.c_char * n).from_buffer(self._buffer)
                    ctypes.memset(addr, 0, n)
            except Exception:
                pass
            if self._locked and self._libc is not None:
                try:
                    buf_addr = ctypes.c_void_p.from_buffer(self._buffer)
                    buf_size = len(self._buffer)
                    if hasattr(self._libc, 'munlock'):
                        self._libc.munlock(buf_addr, buf_size)
                except (OSError, AttributeError, Exception) as e:
                    if DEBUG_MODE:
                        print(f'[SecureMemory] munlock failed: {e}')
                self._locked = False
            self._buffer = None
        except Exception as e:
            if DEBUG_MODE:
                print(f'[SecureMemory] Zeroize error: {e}')
            raise
        finally:
            try:
                self._lock.release()
            except Exception:
                pass

    def write(self, data: bytes):
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError('Failed to acquire lock for write')
        try:
            if self._buffer is None:
                raise RuntimeError('SecureMemory buffer destroyed')
            if len(data) > self._size:
                raise ValueError(f'Data too large for SecureMemory')
            try:
                n = len(self._buffer)
                if n > 0:
                    addr = (ctypes.c_char * n).from_buffer(self._buffer)
                    ctypes.memset(addr, 0, n)
            except Exception:
                self._buffer[:] = bytearray(len(self._buffer))
            self._buffer[:len(data)] = data
        except Exception as e:
            raise RuntimeError(f'Write failed: {e}')
        finally:
            try:
                self._lock.release()
            except Exception:
                pass

    def read(self) -> bytes:
        if not acquire_lock_with_timeout(self._lock, timeout=5.0):
            raise RuntimeError('Failed to acquire lock for read')
        try:
            if self._buffer is None:
                raise RuntimeError('SecureMemory buffer destroyed')
            return bytes(self._buffer[:self._size])
        except Exception as e:
            raise RuntimeError(f'Read failed: {e}')
        finally:
            try:
                self._lock.release()
            except Exception:
                pass

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def size(self) -> int:
        return self._size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zeroize()

    def __del__(self):
        try:
            if hasattr(self, '_buffer') and self._buffer is not None:
                for i in range(len(self._buffer)):
                    self._buffer[i] = 0
        except Exception:
            pass

class SHA3_512:

    @staticmethod
    def _require() -> Any:
        if not hasattr(hashlib, 'sha3_512'):
            raise RuntimeError('SHA3-512 is required by OTRv4 spec §3.2 but is not available in this Python build.  Upgrade to Python ≥ 3.6 with hashlib SHA3 support.')
        return hashlib.sha3_512

    @staticmethod
    def hash(data: bytes) -> bytes:
        return SHA3_512._require()(data).digest()

    @staticmethod
    def hmac(key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, SHA3_512._require()).digest()

class ClientProfile:
    VALIDITY_SECONDS = 14 * 24 * 3600

    def __init__(self, identity_key=None, prekey=None):
        if identity_key is None:
            self.identity_key = _RustDAKE_module.generate_ed448_keypair()
        else:
            self.identity_key = identity_key
        if prekey is None:
            self.prekey = _RustDAKE_module.generate_x448_keypair()
        else:
            self.prekey = prekey
        self.versions = [OTRConstants.PROTOCOL_VERSION]
        self.created = int(time.time())
        self.expires = self.created + self.VALIDITY_SECONDS
        self.signature = None
        self.identity_pub_bytes = bytes(self.identity_key.public_bytes())
        self.prekey_pub_bytes = bytes(self.prekey.public_bytes())
        if DEBUG_MODE:
            import sys as _sys
            _sys.stderr.write(f'[ClientProfile] Fresh Rust-owned identity keys — expires {time.ctime(self.expires)}\n')

    def encode_unsigned(self) -> bytes:
        identity_pub = self.identity_pub_bytes
        prekey_pub = self.prekey_pub_bytes
        if len(identity_pub) != OTRConstants.ED448_PUBLIC_KEY_SIZE:
            raise ValueError(f'Identity key wrong length: {len(identity_pub)}')
        if len(prekey_pub) != OTRConstants.X448_PUBLIC_KEY_SIZE:
            raise ValueError(f'Prekey wrong length: {len(prekey_pub)}')
        profile_data = bytearray()
        profile_data.append(OTRConstants.PROTOCOL_VERSION)
        profile_data.append(len(self.versions))
        for v in self.versions:
            profile_data.append(v)
        profile_data.extend(identity_pub)
        profile_data.extend(prekey_pub)
        profile_data.extend(struct.pack('>Q', self.expires))
        return bytes(profile_data)

    def encode(self) -> bytes:
        try:
            identity_pub = self.identity_pub_bytes
            prekey_pub = self.prekey_pub_bytes
            if len(identity_pub) != OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError(f'Identity key wrong length: {len(identity_pub)}')
            if len(prekey_pub) != OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError(f'Prekey wrong length: {len(prekey_pub)}')
            profile_data = bytearray()
            profile_data.append(OTRConstants.PROTOCOL_VERSION)
            profile_data.append(len(self.versions))
            for v in self.versions:
                profile_data.append(v)
            profile_data.extend(identity_pub)
            profile_data.extend(prekey_pub)
            profile_data.extend(struct.pack('>Q', self.expires))
            self.signature = bytes(self.identity_key.sign(bytes(profile_data)))
            if len(self.signature) != OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError(f'Signature wrong length: {len(self.signature)}')
            profile_data.extend(self.signature)
            result = bytes(profile_data)
            expected = 1 + 1 + len(self.versions) + OTRConstants.ED448_PUBLIC_KEY_SIZE + OTRConstants.X448_PUBLIC_KEY_SIZE + 8 + OTRConstants.ED448_SIGNATURE_SIZE
            if len(result) != expected:
                raise ValueError(f'ClientProfile.encode() produced {len(result)} bytes, expected {expected}. OTRConstants key-size mismatch.')
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp: _cp._emit('debug', f'[ClientProfile] encode() → {len(result)} bytes ✅')
                else: safe_print(f'[ClientProfile] encode() → {len(result)} bytes ✅')
            return result
        except (ValueError, TypeError, AttributeError) as e:
            raise ValueError(f'Client profile encoding failed: {e}')
        except Exception as e:
            raise RuntimeError(f'Unexpected error encoding profile: {e}')

    @classmethod
    def decode(cls, data: bytes) -> 'ClientProfile':
        try:
            min_size = 1 + 1 + 1 + OTRConstants.ED448_PUBLIC_KEY_SIZE + OTRConstants.X448_PUBLIC_KEY_SIZE + 8 + OTRConstants.ED448_SIGNATURE_SIZE
            if len(data) < min_size:
                raise ValueError(f'ClientProfile too short: {len(data)} < {min_size} bytes. Truncated profiles are rejected (OTRv4 §4.1.2).')
            offset = 0
            version = data[offset]
            offset += 1
            if version != OTRConstants.PROTOCOL_VERSION:
                raise ValueError(f'Unsupported protocol version {version} — expected {OTRConstants.PROTOCOL_VERSION}. Refusing potential downgrade.')
            num_versions = data[offset]
            offset += 1
            if num_versions == 0 or num_versions > 8:
                raise ValueError(f'Implausible version count: {num_versions}')
            versions = []
            for _ in range(num_versions):
                if offset >= len(data):
                    raise ValueError('Truncated during version list')
                versions.append(data[offset])
                offset += 1
            if 4 not in versions:
                raise ValueError(f'OTRv4 not in supported versions: {versions}')
            if len(data) < offset + OTRConstants.ED448_PUBLIC_KEY_SIZE:
                raise ValueError('Truncated identity public key')
            identity_pub_bytes = data[offset:offset + OTRConstants.ED448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.ED448_PUBLIC_KEY_SIZE
            if len(data) < offset + OTRConstants.X448_PUBLIC_KEY_SIZE:
                raise ValueError('Truncated prekey public key')
            prekey_pub_bytes = data[offset:offset + OTRConstants.X448_PUBLIC_KEY_SIZE]
            offset += OTRConstants.X448_PUBLIC_KEY_SIZE
            if len(data) < offset + 8:
                raise ValueError('Truncated expiry timestamp')
            expires = struct.unpack('>Q', data[offset:offset + 8])[0]
            offset += 8
            now = int(time.time())
            if expires <= now:
                raise ValueError(f'ClientProfile has expired (expires={time.ctime(expires)}). Rejecting stale profile.')
            if len(data) < offset + OTRConstants.ED448_SIGNATURE_SIZE:
                raise ValueError('ClientProfile has no signature — rejecting unsigned profile. OTRv4 §4.1.2 requires signature verification.')
            signature = data[offset:offset + OTRConstants.ED448_SIGNATURE_SIZE]
            signed_data = data[:offset]
            try:
                _sig_ok = _RustDAKE_module.verify_ed448_sig(identity_pub_bytes, signed_data, signature)
            except ValueError as sig_err:
                raise ValueError(f'ClientProfile signature verification FAILED: {sig_err}. Rejecting profile — malformed identity key or signature (OTRv4 §4.1.2).') from sig_err
            if not _sig_ok:
                raise ValueError('ClientProfile signature verification FAILED. Rejecting profile — potential MITM/forged identity (OTRv4 §4.1.2).')
            profile = cls.__new__(cls)
            profile.identity_key = None
            profile.prekey = None
            profile.versions = versions
            profile.expires = expires
            profile.signature = signature
            profile.created = now
            profile.identity_pub_bytes = identity_pub_bytes
            profile.prekey_pub_bytes = prekey_pub_bytes
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp:
                    _cp._emit('debug', f'[ClientProfile] ✅ decode OK expires {time.ctime(expires)} versions:{versions}')
                else:
                    safe_print(f'[ClientProfile] ✅ Strict decode OK — sig verified, expires {time.ctime(expires)}')
                    safe_print(f'  versions: {versions}')
            return profile
        except ValueError:
            raise
        except (IndexError, struct.error, TypeError) as e:
            raise ValueError(f'ClientProfile decode failed due to malformed data: {e}') from e
        except Exception as e:
            raise RuntimeError(f'ClientProfile decode failed unexpectedly: {e}') from e

    def get_fingerprint(self) -> str:
        try:
            if self.identity_pub_bytes:
                identity_pub = self.identity_pub_bytes
            elif self.identity_key:
                identity_pub = bytes(self.identity_key.public_bytes())
            else:
                return ''
            if identity_pub is None:
                return ''
            fp_bytes = hashlib.sha3_512(identity_pub).digest()
            hex_str = fp_bytes.hex().upper()
            groups = [hex_str[i:i + 8] for i in range(0, 80, 8)]
            return ' '.join(groups)
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp: _cp._emit('debug', f'[ClientProfile] fingerprint error: {e}')
                else: safe_print(f'[ClientProfile] Error getting fingerprint: {e}')
            return ''
        except Exception:
            return ''

    def verify_fingerprint(self, fingerprint: str) -> bool:
        try:
            actual = self.get_fingerprint()
            if not actual or not fingerprint:
                return False
            return hmac.compare_digest(actual.encode('utf-8'), fingerprint.encode('utf-8'))
        except (TypeError, AttributeError, ValueError) as e:
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp: _cp._emit('debug', f'[ClientProfile] verify error: {e}')
                else: safe_print(f'[ClientProfile] Fingerprint verification error: {e}')
            return False
        except Exception:
            return False

    def get_prekey_fingerprint(self) -> str:
        try:
            if self.prekey_pub_bytes:
                prekey_pub = self.prekey_pub_bytes
            elif self.prekey:
                prekey_pub = bytes(self.prekey.public_bytes())
            else:
                return ''
            if prekey_pub is None:
                return ''
            fp_bytes = hashlib.sha3_512(prekey_pub).digest()
            return fp_bytes.hex().upper()
        except (AttributeError, TypeError, ValueError) as e:
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp: _cp._emit('debug', f'[ClientProfile] prekey fingerprint error: {e}')
                else: safe_print(f'[ClientProfile] Error getting prekey fingerprint: {e}')
            return ''
        except Exception:
            return ''

    def is_expired(self) -> bool:
        try:
            return self.expires < int(time.time())
        except (TypeError, AttributeError):
            return True

    def renew(self):
        try:
            self.created = int(time.time())
            self.expires = self.created + self.VALIDITY_SECONDS
            self.signature = None
        except Exception as e:
            if DEBUG_MODE:
                _cp = getattr(__import__('builtins'), '_active_client', None)
                if _cp: _cp._emit('debug', f'[ClientProfile] Renew failed: {e}')
                else: safe_print(f'[ClientProfile] Renew failed: {e}')

class TLVHandler:

    @staticmethod
    def encode_tlv(tlv_type: int, data: bytes) -> bytes:
        length = len(data)
        return struct.pack('!HH', tlv_type, length) + data

    @staticmethod
    def decode_tlv(data: bytes) -> Tuple[int, bytes, bytes]:
        if len(data) < 4:
            raise ValueError(f'TLV too short: need 4-byte header, have {len(data)}')
        try:
            tlv_type, length = struct.unpack('!HH', data[:4])
        except struct.error as e:
            raise ValueError(f'TLV header unpack failed: {e}')
        end = 4 + length
        if len(data) < end:
            raise ValueError(f'TLV value truncated: type=0x{tlv_type:04x} declares {length} bytes but only {len(data) - 4} available')
        return (tlv_type, data[4:end], data[end:])

    @staticmethod
    def debug_tlv(data: bytes, description: str='') -> None:
        if len(data) < 4:
            safe_print(f'TLV {description}: Too short ({len(data)} bytes)')
            return
        try:
            tlv_type, length = struct.unpack('!HH', data[:4])
            safe_print(f'TLV {description}: type=0x{tlv_type:04x}, length={length}, data_len={len(data)}')
            safe_print(f'  Hex: {data[:min(32, len(data))].hex()}...')
        except struct.error as e:
            safe_print(f'TLV {description}: Unpack error: {e}')
            safe_print(f'  Hex: {data[:min(32, len(data))].hex()}...')

class RatchetHeader:

    def __init__(self, dh_pub: bytes, prev_chain_len: int, msg_num: int):
        self.dh_pub = dh_pub
        self.prev_chain_len = prev_chain_len
        self.msg_num = msg_num

    def encode(self) -> bytes:
        return self.dh_pub + struct.pack('!II', self.prev_chain_len, self.msg_num)

    @classmethod
    def decode(cls, data: bytes) -> 'RatchetHeader':
        if len(data) != 56 + 8:
            raise ValueError(f'Invalid header length: {len(data)}')
        dh_pub = data[:56]
        prev_chain_len, msg_num = struct.unpack('!II', data[56:])
        return cls(dh_pub, prev_chain_len, msg_num)

class SkippedMessageKey:

    def __init__(self, dh_pub: bytes, msg_num: int, message_key: bytes):
        self.dh_pub = dh_pub
        self.msg_num = msg_num
        self.message_key = bytearray(message_key)

    def zeroize(self):
        if hasattr(self, 'message_key') and self.message_key:
            _secure_wipe(self.message_key)
            self.message_key = bytearray()

    def __del__(self):
        self.zeroize()

class _RatchetKeyStore:
    __slots__ = ('_buf', '_lock')

    def __init__(self, initial: bytes=b'\x00' * 32):
        import threading
        self._lock = threading.Lock()
        self._buf = bytearray(initial[:32].ljust(32, b'\x00'))

    def read(self) -> bytes:
        with self._lock:
            return bytes(self._buf)

    def write(self, data: bytes) -> None:
        with self._lock:
            self._buf[:] = bytearray(data[:32].ljust(32, b'\x00'))

    def zeroize(self) -> None:
        with self._lock:
            for i in range(len(self._buf)):
                self._buf[i] = 0

    def __repr__(self):
        return f'<_RatchetKeyStore {self.read()[:4].hex()}…>'

class RustBackedDoubleRatchet:

    def __init__(self, root_key, is_initiator: bool, ad: bytes=b'OTRv4-DATA', logger=None, chain_key_send=None, chain_key_recv=None, brace_key=None, rekey_interval: int=OTRConstants.REKEY_INTERVAL, rekey_timeout: int=OTRConstants.REKEY_TIMEOUT):
        self.lock = threading.RLock()
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()
        self.dh_ratchet_local = _RustDAKE_module.generate_x448_keypair()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_bytes()
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = None
        self.last_remote_pub = None
        self._brace_kem_local = None
        self._brace_kem_ek_out = None
        self._brace_kem_ct_out = None
        self._brace_key = brace_key if brace_key else bytes(32)
        rk_bytes = root_key.read() if hasattr(root_key, 'read') else bytes(root_key)
        bk_bytes = self._brace_key
        if chain_key_send is None or chain_key_recv is None:
            seed = kdf_1(KDFUsage.ROOT_KEY, rk_bytes + bk_bytes, 64)
            if is_initiator:
                ck_s, ck_r = (seed[:32], seed[32:64])
            else:
                ck_s, ck_r = (seed[32:64], seed[:32])
        else:
            ck_s = chain_key_send[:32]
            ck_r = chain_key_recv[:32]
        if all((b == 0 for b in ck_s)) or all((b == 0 for b in ck_r)):
            raise ValueError('Chain keys zero — possible KDF failure')
        _rust_init = True
        self._rust = _RustRatchet(rk_bytes[:32], ck_s, ck_r, bk_bytes[:32], self.dh_ratchet_local_pub, _rust_init)
        self.ratchet_id = 0
        self.message_counter_send = 0
        self._rks_send = _RatchetKeyStore(ck_s)
        self._rks_recv = _RatchetKeyStore(ck_r)
        self._rks_root = _RatchetKeyStore(rk_bytes[:32])
        self._rks_recv_init = _RatchetKeyStore(ck_r)
        self._rks_send_init = _RatchetKeyStore(ck_s)
        self._dh_epoch: int = 0
        self.message_num_recv: int = 0
        self.skipped_keys: dict = {}
        self._next_expected_recv_num: int = 0
        self._current_recv_dh_pub: Optional[bytes] = None
        self.logger.debug(f'RustBackedDoubleRatchet initialized (initiator={is_initiator})')

    @classmethod
    def from_dake_output(cls, dake_output, is_initiator: bool, ad: bytes=b'OTRv4-DATA', logger=None, rekey_interval: int=None, rekey_timeout: int=None) -> 'RustBackedDoubleRatchet':
        if rekey_interval is None:
            rekey_interval = OTRConstants.REKEY_INTERVAL
        if rekey_timeout is None:
            rekey_timeout = OTRConstants.REKEY_TIMEOUT
        if dake_output is None:
            raise ValueError('from_dake_output: dake_output is None')
        if getattr(dake_output, 'consumed', False):
            raise ValueError('from_dake_output: DakeOutput already consumed')
        self = cls.__new__(cls)
        self.lock = threading.RLock()
        self.is_initiator = is_initiator
        self.ad = ad
        self.logger = logger or NullLogger()
        self.rekey_interval = rekey_interval
        self.rekey_timeout = rekey_timeout
        self.last_rekey_time = time.time()
        self.dh_ratchet_local = _RustDAKE_module.generate_x448_keypair()
        self.dh_ratchet_local_pub = self.dh_ratchet_local.public_bytes()
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = None
        self.last_remote_pub = None
        self._brace_kem_local = None
        self._brace_kem_ek_out = None
        self._brace_kem_ct_out = None
        self._brace_key = bytes(32)
        if not RUST_RATCHET_AVAILABLE:
            raise RuntimeError('otrv4_core Rust module not installed — Phase-4 ratchet requires the Rust core.')
        self._rust = dake_output.consume_into_ratchet(ad, self.dh_ratchet_local_pub, is_initiator)
        self.ratchet_id = 0
        self.message_counter_send = 0
        _placeholder = b'\x00' * 32
        self._rks_send = _RatchetKeyStore(_placeholder)
        self._rks_recv = _RatchetKeyStore(_placeholder)
        self._rks_root = _RatchetKeyStore(_placeholder)
        self._rks_recv_init = _RatchetKeyStore(_placeholder)
        self._rks_send_init = _RatchetKeyStore(_placeholder)
        self._dh_epoch = 0
        self.message_num_recv = 0
        self.skipped_keys = {}
        self._next_expected_recv_num = 0
        self._current_recv_dh_pub = None
        self._dake_output_consumed = True
        self.logger.debug(f'RustBackedDoubleRatchet.from_dake_output (initiator={is_initiator}) — Phase 4 path: session keys live ONLY in Rust')
        return self

    @property
    def chain_key_send(self) -> '_RatchetKeyStore':
        return self._rks_send

    @chain_key_send.setter
    def chain_key_send(self, value):
        data = value.read() if hasattr(value, 'read') else bytes(value or b'\x00' * 32)
        self._rks_send.write(data[:32])

    @property
    def chain_key_recv(self) -> '_RatchetKeyStore':
        return self._rks_recv

    @chain_key_recv.setter
    def chain_key_recv(self, value):
        data = value.read() if hasattr(value, 'read') else bytes(value or b'\x00' * 32)
        self._rks_recv.write(data[:32])

    @property
    def root_key(self) -> '_RatchetKeyStore':
        return self._rks_root

    @root_key.setter
    def root_key(self, value):
        data = value.read() if hasattr(value, 'read') else bytes(value or b'\x00' * 32)
        self._rks_root.write(data[:32])

    @property
    def message_num_send(self) -> int:
        return self.message_counter_send

    @message_num_send.setter
    def message_num_send(self, value: int):
        self.message_counter_send = int(value)

    @property
    def message_counter_recv(self) -> int:
        return self.message_num_recv

    @message_counter_recv.setter
    def message_counter_recv(self, value: int):
        self.message_num_recv = int(value)

    @property
    def chain_key_recv_init(self) -> '_RatchetKeyStore':
        return self._rks_recv_init

    @property
    def chain_key_send_init(self) -> '_RatchetKeyStore':
        return self._rks_send_init

    def _kdf_ck(self, ck: bytes, label: bytes=b'MESSAGE_KEY'):
        new_ck = kdf_1(KDFUsage.CHAIN_KEY, ck, 32)
        mk = kdf_1(KDFUsage.MESSAGE_KEY, ck, 32)
        return (new_ck, mk, bytes(32))

    def encrypt_message(self, plaintext):
        with self.lock:
            now = time.time()
            if self.message_counter_send >= self.rekey_interval or now - self.last_rekey_time > self.rekey_timeout:
                _rekey_target = self.dh_ratchet_remote_pub or self.last_remote_pub
                if _rekey_target:
                    self._ratchet(_rekey_target)
                self.last_rekey_time = now
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            enc = self._rust.encrypt(plaintext)
            self.message_counter_send += 1
            new_ck_s, _, _ = self._kdf_ck(self._rks_send.read())
            self._rks_send.write(new_ck_s)
            return (enc['ciphertext'], enc['header'], enc['nonce'], enc['tag'], self._dh_epoch, list(enc['reveal_mac_keys']))

    def decrypt_message(self, header_bytes, ciphertext, nonce, tag):
        with self.lock:
            hdr_dh_pub = None
            hdr_msg_num = None
            try:
                _rh = RatchetHeader.decode(header_bytes)
                hdr_dh_pub = _rh.dh_pub
                hdr_msg_num = _rh.msg_num
            except Exception:
                pass
            try:
                is_new_dh = self._rust.is_new_dh(header_bytes)
                if is_new_dh and self.dh_ratchet_remote_pub is not None:
                    pt = self._decrypt_new_dh(header_bytes, ciphertext, nonce, tag)
                else:
                    if self.dh_ratchet_remote_pub is None:
                        dh_pub_h = self._rust.header_dh_pub(header_bytes)
                        if dh_pub_h is not None:
                            self.dh_ratchet_remote = None
                            self.dh_ratchet_remote_pub = dh_pub_h
                    pt = self._rust.decrypt_same_dh(header_bytes, ciphertext, nonce, tag)
                _did_dh_ratchet_recv = is_new_dh and self.dh_ratchet_remote_pub is not None and (pt is not None)
                if hdr_dh_pub is not None and hdr_msg_num is not None:
                    new_epoch = self._current_recv_dh_pub is None or hdr_dh_pub != self._current_recv_dh_pub
                    if new_epoch:
                        for k in list(self.skipped_keys):
                            if k[0] != hdr_dh_pub:
                                self.skipped_keys.pop(k, None)
                        self._current_recv_dh_pub = hdr_dh_pub
                        self._next_expected_recv_num = 0
                    if hdr_msg_num > self._next_expected_recv_num:
                        for skipped in range(self._next_expected_recv_num, hdr_msg_num):
                            self.skipped_keys[hdr_dh_pub, skipped] = True
                        self._next_expected_recv_num = hdr_msg_num + 1
                    elif hdr_msg_num == self._next_expected_recv_num:
                        self._next_expected_recv_num = hdr_msg_num + 1
                    else:
                        self.skipped_keys.pop((hdr_dh_pub, hdr_msg_num), None)
                self.message_num_recv += 1
                new_ck_r, _, _ = self._kdf_ck(self._rks_recv.read())
                self._rks_recv.write(new_ck_r)
                return pt
            except Exception as e:
                raise EncryptionError(f'Decryption failed: {e}')

    def _decrypt_new_dh(self, header_bytes, ciphertext, nonce, tag):
        dh_pub = self._rust.header_dh_pub(header_bytes)
        dh_secret_recv = self.dh_ratchet_local.dh(dh_pub)
        new_local = _RustDAKE_module.generate_x448_keypair()
        new_local_pub = new_local.public_bytes()
        dh_secret_send = new_local.dh(dh_pub)
        pt = self._rust.decrypt_new_dh(header_bytes, ciphertext, nonce, tag, dh_secret_recv, dh_secret_send, new_local_pub)
        if self.dh_ratchet_remote_pub is not None:
            self.last_remote_pub = self.dh_ratchet_remote_pub
        self.dh_ratchet_remote = None
        self.dh_ratchet_remote_pub = dh_pub
        self.dh_ratchet_local = new_local
        self.dh_ratchet_local_pub = new_local_pub
        self._dh_epoch += 1
        self.ratchet_id = self._dh_epoch
        self.message_counter_send = 0
        _cur_root = self._rks_root.read()
        _seed_r = kdf_1(KDFUsage.ROOT_KEY, _cur_root + bytes(dh_secret_recv), 64)
        _new_root_r = _seed_r[:32]
        _new_ck_recv = _seed_r[32:64]
        _seed_s = kdf_1(KDFUsage.ROOT_KEY, _new_root_r + bytes(dh_secret_send), 64)
        _new_root_s = _seed_s[:32]
        _new_ck_send = _seed_s[32:64]
        self._rks_root.write(_new_root_s)
        self._rks_send.write(_new_ck_send)
        self._rks_recv.write(_new_ck_recv)
        self.prepare_brace_rotation()
        return pt

    def _ratchet(self, dh_pub):
        with self.lock:
            self.dh_ratchet_local = _RustDAKE_module.generate_x448_keypair()
            self.dh_ratchet_local_pub = self.dh_ratchet_local.public_bytes()
            dh_secret = self.dh_ratchet_local.dh(dh_pub)
            self._rust.send_ratchet(dh_secret, self.dh_ratchet_local_pub)
            self._dh_epoch += 1
            self.ratchet_id = self._dh_epoch
            self.message_counter_send = 0
            _combined = bytes(dh_secret) + self._brace_key
            _seed = kdf_1(KDFUsage.ROOT_KEY, self._rks_root.read() + _combined, 64)
            self._rks_root.write(_seed[:32])
            self._rks_send.write(_seed[32:64])
            self.prepare_brace_rotation()

    def prepare_brace_rotation(self):
        if self._brace_kem_local is not None:
            return
        if self._brace_kem_ct_out is not None:
            return
        self._brace_kem_local = MLKEM1024BraceKEM()
        self._brace_kem_ek_out = self._brace_kem_local.encap_key_bytes

    def consume_outgoing_kem_ek(self):
        ek = self._brace_kem_ek_out
        self._brace_kem_ek_out = None
        return ek

    def consume_outgoing_kem_ct(self):
        ct = self._brace_kem_ct_out
        self._brace_kem_ct_out = None
        return ct

    def process_incoming_kem_ek(self, ek):
        ct, ss = MLKEM1024BraceKEM.encapsulate(ek)
        self._brace_kem_ct_out = ct
        self._rust.rotate_brace_key(ss)
        self._brace_key = kdf_1(KDFUsage.BRACE_KEY_ROTATE, self._brace_key + ss, 32)

    def process_incoming_kem_ct(self, ct):
        if self._brace_kem_local is None:
            raise ValueError('Received KEM ct but no local keypair pending')
        ss = self._brace_kem_local.decapsulate(ct)
        self._brace_kem_local.zeroize()
        self._brace_kem_local = None
        self._rust.rotate_brace_key(ss)
        self._brace_key = kdf_1(KDFUsage.BRACE_KEY_ROTATE, self._brace_key + ss, 32)

    def zeroize(self):
        with self.lock:
            self._rust = None
            self.dh_ratchet_local = None
            self.dh_ratchet_remote = None
            self.dh_ratchet_remote_pub = None
            self.last_remote_pub = None
            if self._brace_kem_local is not None:
                self._brace_kem_local.zeroize()
                self._brace_kem_local = None
            self._brace_kem_ek_out = None
            self._brace_kem_ct_out = None
            for store in (self._rks_send, self._rks_recv, self._rks_root):
                try:
                    store.zeroize()
                except Exception:
                    pass

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass
DoubleRatchet = RustBackedDoubleRatchet

def determine_roles(local_id_pub: bytes, remote_id_pub: bytes) -> bool:
    return local_id_pub < remote_id_pub

def _safe_b64decode(data: str) -> bytes:
    try:
        data = str(data).strip()
        if not data:
            raise ValueError('Empty base64 data')
        data = ''.join(data.split())
        if '[' in data and ']' in data:
            end_bracket = data.rfind(']')
            if end_bracket != -1:
                data = data[end_bracket + 1:].strip()
        try:
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + '=' * padding_needed
            return base64.urlsafe_b64decode(data)
        except Exception:
            data = data.replace('-', '+').replace('_', '/')
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + '=' * padding_needed
            return base64.b64decode(data)
    except Exception as e:
        try:
            import re as _re
            data = _re.sub('[^A-Za-z0-9+/=-]', '', data)
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + '=' * padding_needed
            return base64.b64decode(data)
        except Exception as e2:
            raise ValueError(f'Base64 decode failed: {e}, also: {e2}')

class DAKE1RateLimiter:
    MAX_ATTEMPTS: int = 5
    WINDOW_SECONDS: float = 60.0

    def __init__(self):
        self._lock = threading.Lock()
        self._attempts: Dict[str, deque] = defaultdict(deque)

    def is_allowed(self, peer_key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            dq = self._attempts[peer_key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.MAX_ATTEMPTS:
                return False
            dq.append(now)
            return True

    def reset(self, peer_key: str) -> None:
        with self._lock:
            self._attempts.pop(peer_key, None)
_dake1_rate_limiter = DAKE1RateLimiter()

class RustDAKEAdapter:

    def __init__(self, client_profile: Optional['ClientProfile']=None, explicit_initiator: bool=False, tracer: Optional['OTRTracer']=None, logger: Optional['OTRLogger']=None):
        self._tracer = tracer
        self._logger = logger or NullLogger()
        self._is_initiator = explicit_initiator
        self.client_profile = client_profile or ClientProfile()
        self._rust = None
        if RUST_DAKE_AVAILABLE and _RustDAKE is not None:
            try:
                _profile_bytes = self.client_profile.encode()
                if self.client_profile.identity_pub_bytes is None and self.client_profile.identity_key is not None:
                    self.client_profile.identity_pub_bytes = bytes(self.client_profile.identity_key.public_bytes())
                if self.client_profile.prekey_pub_bytes is None and self.client_profile.prekey is not None:
                    self.client_profile.prekey_pub_bytes = bytes(self.client_profile.prekey.public_bytes())
                _mldsa_priv = None
                _mldsa_pub = None
                _unsigned_body = self.client_profile.encode_unsigned()
                self._rust, _sig_py = _RustDAKE.sign_profile_body_and_construct_with_handles(explicit_initiator, _profile_bytes, _unsigned_body, self.client_profile.identity_key, self.client_profile.prekey, _mldsa_priv, _mldsa_pub)
                _sig = bytes(_sig_py)
                if len(_sig) != OTRConstants.ED448_SIGNATURE_SIZE:
                    raise ValueError(f'sign_profile_body_and_construct_with_handles returned signature of wrong length: {len(_sig)} (expected {OTRConstants.ED448_SIGNATURE_SIZE})')
                if self.client_profile.signature != _sig:
                    raise ValueError('sign_profile_body_and_construct_with_handles produced a different signature than ClientProfile.encode() — Ed448 determinism violated, refusing to construct adapter')
                if logger:
                    logger.debug('RustDAKEAdapter: using Rust DAKE backend (Phase 5.3e: Rust-owned identity key handles, single-call sign+construct, no Python-heap private bytes)')
            except Exception as _rust_err:
                if logger:
                    logger.debug(f'RustDAKEAdapter: Rust init failed ({_rust_err})')
                raise RuntimeError(f'RustDAKEAdapter: Rust DAKE construction failed ({_rust_err}).  v10.6.11+ has no Python fallback — the Rust core must be functional for the protocol to operate.')
        self._state: DAKEState = DAKEState.IDLE
        self._session_created_at: float = 0.0
        self._session_max_age: float = 86400.0
        self.remote_identity_pub_bytes: Optional[bytes] = None
        self.remote_identity_key = None
        self.remote_profile: Optional['ClientProfile'] = None
        self._mldsa_auth: Optional['MLDSA87Auth'] = None
        self._remote_mldsa_pub: Optional[bytes] = None
        if MLDSA87_AVAILABLE:
            try:
                self._mldsa_auth = MLDSA87Auth()
            except Exception:
                self._mldsa_auth = None
        self._raw_dake1_bytes: Optional[bytes] = None
        self._raw_dake2_bytes: Optional[bytes] = None
        if tracer:
            tracer.trace('DAKE', 'INIT', None, 'IDLE', f'DAKE engine initialized, initiator={explicit_initiator}')

    @property
    def state(self) -> DAKEState:
        return self._state

    @property
    def is_initiator(self) -> bool:
        return self._is_initiator

    def is_established(self) -> bool:
        return self._state == DAKEState.ESTABLISHED

    def has_failed(self) -> bool:
        return self._state == DAKEState.FAILED

    def is_session_expired(self) -> bool:
        if self._state != DAKEState.ESTABLISHED:
            return False
        if self._session_created_at == 0.0:
            return False
        return time.time() - self._session_created_at > self._session_max_age

    def is_expired(self) -> bool:
        return False

    def get_state(self) -> DAKEState:
        return self.state

    def _trace(self, *args):
        if self._tracer:
            try:
                self._tracer.trace(*args)
            except Exception:
                pass

    def _log_debug(self, msg: str):
        try:
            self._logger.debug(msg)
        except Exception:
            pass

    def _log_error(self, msg: str):
        try:
            self._logger.error(msg)
        except Exception:
            pass

    def _fail(self, reason: str) -> bool:
        self._state = DAKEState.FAILED
        self._trace('DAKE', 'STATE', self._state.name, 'FAILED', reason)
        self._log_error(reason)
        return False

    def generate_dake1(self) -> str:
        try:
            raw = bytes(self._rust.generate_dake1(mldsa_pub_bytes=self._mldsa_auth.pub_bytes if self._mldsa_auth else None))
            self._raw_dake1_bytes = raw
            self._state = DAKEState.SENT_DAKE1
            self._trace('DAKE', 'STATE', 'IDLE', 'SENT_DAKE1', 'generated DAKE1 (Identity)')
            encoded = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
            return f'?OTRv4 {encoded}'
        except Exception as e:
            self._fail(f'generate_dake1 failed: {e}')
            raise

    def process_dake1(self, dake1_msg: str, peer_key: str='unknown') -> bool:
        if not _dake1_rate_limiter.is_allowed(peer_key):
            self._log_debug(f'DAKE1 rate limit for {peer_key}')
            return False
        try:
            if not dake1_msg.startswith('?OTRv4 '):
                return self._fail('process_dake1: not an OTRv4 message')
            raw = _safe_b64decode(dake1_msg[7:].strip())
            self._raw_dake1_bytes = raw
            result = self._rust.process_dake1(raw)
            if not result.success:
                return self._fail(f'process_dake1: {result.error}')
            self.remote_identity_pub_bytes = bytes(result.remote_identity_pub) if result.remote_identity_pub else None
            self._remote_mldsa_pub = bytes(result.remote_mldsa_pub) if result.remote_mldsa_pub else None
            if self.remote_identity_pub_bytes:
                self.remote_identity_key = self.remote_identity_pub_bytes
            if result.remote_profile_bytes:
                try:
                    self.remote_profile = ClientProfile.decode(bytes(result.remote_profile_bytes))
                except Exception:
                    self.remote_profile = None
            self._state = DAKEState.RECEIVED_DAKE1
            self._trace('DAKE', 'STATE', 'IDLE', 'RECEIVED_DAKE1', 'received DAKE1 (Identity)')
            self._log_debug('DAKE1 (Identity) processed successfully')
            return True
        except Exception as e:
            return self._fail(f'process_dake1 exception: {e}')

    def generate_dake2(self) -> Optional[str]:
        try:
            use_output_api = hasattr(self._rust, 'generate_dake2_output')
            if use_output_api:
                output = self._rust.generate_dake2_output(our_prekey_priv_bytes=None, mldsa_pub_bytes=self._mldsa_auth.pub_bytes if self._mldsa_auth else None)
                raw = bytes(output.dake2_bytes)
                self._raw_dake2_bytes = raw
                self._session_keys = {'_dake_output': output, 'session_id': bytes(output.ssid) + b'\x00' * 24, 'is_initiator': False, 'peer_long_term_pub': self.remote_identity_pub_bytes, 'peer_long_term_key': self.remote_identity_key}
            else:
                result = self._rust.generate_dake2(our_prekey_priv_bytes=None, mldsa_pub_bytes=self._mldsa_auth.pub_bytes if self._mldsa_auth else None)
                if not result.success:
                    return self._fail_str(f'generate_dake2: {result.error}')
                raw = bytes(result.dake2_bytes)
                self._raw_dake2_bytes = raw
                self._session_keys = self._unpack_session_keys(result, is_initiator=False)
            self._state = DAKEState.SENT_DAKE2
            self._trace('DAKE', 'STATE', 'RECEIVED_DAKE1', 'SENT_DAKE2', 'generated DAKE2 (Auth-R)')
            self._log_debug('DAKE2 (Auth-R) generated successfully')
            encoded = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
            return f'?OTRv4 {encoded}'
        except Exception as e:
            return self._fail_str(f'generate_dake2 exception: {e}')

    def _fail_str(self, reason: str) -> None:
        self._fail(reason)
        return None

    def process_dake2(self, dake2_msg: str) -> bool:
        try:
            if not dake2_msg.startswith('?OTRv4 '):
                return self._fail('process_dake2: not an OTRv4 message')
            raw = _safe_b64decode(dake2_msg[7:].strip())
            self._raw_dake2_bytes = raw
            use_output_api = hasattr(self._rust, 'process_dake2_output')
            if use_output_api:
                output = self._rust.process_dake2_output(raw, None)
                self.remote_identity_pub_bytes = bytes(output.remote_identity_pub) if output.remote_identity_pub else None
                self._remote_mldsa_pub = bytes(output.remote_mldsa_pub) if output.remote_mldsa_pub else None
                if self.remote_identity_pub_bytes:
                    self.remote_identity_key = self.remote_identity_pub_bytes
                if output.remote_profile_bytes:
                    try:
                        self.remote_profile = ClientProfile.decode(bytes(output.remote_profile_bytes))
                    except Exception:
                        self.remote_profile = None
                self._session_keys = {'_dake_output': output, 'session_id': bytes(output.ssid) + b'\x00' * 24, 'is_initiator': True, 'peer_long_term_pub': self.remote_identity_pub_bytes, 'peer_long_term_key': self.remote_identity_key}
            else:
                result = self._rust.process_dake2(raw, None)
                if not result.success:
                    return self._fail(f'process_dake2: {result.error}')
                self.remote_identity_pub_bytes = bytes(result.remote_identity_pub) if result.remote_identity_pub else None
                self._remote_mldsa_pub = bytes(result.remote_mldsa_pub) if result.remote_mldsa_pub else None
                if self.remote_identity_pub_bytes:
                    self.remote_identity_key = self.remote_identity_pub_bytes
                if result.remote_profile_bytes:
                    try:
                        self.remote_profile = ClientProfile.decode(bytes(result.remote_profile_bytes))
                    except Exception:
                        self.remote_profile = None
                self._session_keys = self._unpack_session_keys(result, is_initiator=True)
            self._state = DAKEState.ESTABLISHED
            self._session_created_at = time.time()
            self._trace('DAKE', 'STATE', 'SENT_DAKE1', 'ESTABLISHED', 'DAKE2 (Auth-R) processed successfully')
            self._log_debug('DAKE2 (Auth-R) processed successfully')
            return True
        except Exception as e:
            return self._fail(f'process_dake2 exception: {e}')

    def generate_dake3(self) -> Optional[str]:
        try:
            if self._raw_dake1_bytes is None or self._raw_dake2_bytes is None:
                raise ValueError('Transcript bytes missing')
            transcript_msg = kdf_1(KDFUsage.AUTH_I_MSG, self._raw_dake1_bytes + self._raw_dake2_bytes, 64)
            identity_key = self.client_profile.identity_key
            if identity_key is None:
                raise ValueError('Local Ed448 identity key not available')
            A1_bytes = self.client_profile.identity_pub_bytes or bytes(identity_key.public_bytes())
            if self.remote_profile is None:
                raise ValueError('Remote profile not stored')
            A2_bytes = self.remote_profile.identity_pub_bytes
            if A2_bytes is None:
                raise ValueError('Remote identity_pub_bytes not available')
            sigma = RingSignature.sign(identity_key, A1_bytes, A2_bytes, transcript_msg)
            assembled = None
            if hasattr(self._rust, 'assemble_dake3'):
                try:
                    mldsa_sig = None
                    if self._mldsa_auth is not None and self._remote_mldsa_pub is not None:
                        mldsa_sig = self._mldsa_auth.sign(transcript_msg)
                    assembled = bytes(self._rust.assemble_dake3(sigma_bytes=sigma, mldsa_sig_bytes=mldsa_sig))
                except Exception:
                    assembled = None
            if assembled is None:
                msg = bytearray([OTRConstants.MESSAGE_TYPE_DAKE3])
                msg.extend(sigma)
                if self._mldsa_auth is not None and self._remote_mldsa_pub is not None:
                    mldsa_sig = self._mldsa_auth.sign(transcript_msg)
                    msg.append(1)
                    msg.extend(mldsa_sig)
                    self._log_debug(f'DAKE3 hybrid: ring-sig + ML-DSA-87')
                else:
                    msg.append(0)
                    self._log_debug('DAKE3 classical only: ring-sig')
                assembled = bytes(msg)
            encoded = base64.urlsafe_b64encode(assembled).decode('ascii').rstrip('=')
            self._log_debug(f'DAKE3 (Auth-I) generated: {len(assembled)}B total')
            return f'?OTRv4 {encoded}'
        except Exception as e:
            self._log_error(f'DAKE3 (Auth-I) generation failed: {e}')
            return None

    def process_dake3(self, dake3_msg: str) -> bool:
        try:
            if not dake3_msg.startswith('?OTRv4 '):
                return self._fail('process_dake3: not an OTRv4 message')
            decoded = _safe_b64decode(dake3_msg[7:].strip())
            SIG_LEN = RingSignature.TOTAL_BYTES
            if len(decoded) < 1 + SIG_LEN:
                return self._fail(f'DAKE3 too short: {len(decoded)}')
            if decoded[0] != OTRConstants.MESSAGE_TYPE_DAKE3:
                return self._fail(f'Not a DAKE3: 0x{decoded[0]:02x}')
            sigma = decoded[1:1 + SIG_LEN]
            if self._raw_dake1_bytes is None or self._raw_dake2_bytes is None:
                return self._fail('Transcript bytes missing — cannot verify DAKE3')
            transcript_msg = kdf_1(KDFUsage.AUTH_I_MSG, self._raw_dake1_bytes + self._raw_dake2_bytes, 64)
            if self.remote_profile is None:
                return self._fail('Remote profile not stored')
            A1_bytes = self.remote_profile.identity_pub_bytes
            A2_bytes = self.client_profile.identity_pub_bytes or bytes(self.client_profile.identity_key.public_bytes())
            if A1_bytes is None:
                return self._fail('Remote identity_pub_bytes not available')
            if not RingSignature.verify(A1_bytes, A2_bytes, transcript_msg, sigma):
                return self._fail('DAKE3 ring signature verification failed')
            _mldsa_off = 1 + SIG_LEN
            _has_mldsa = _mldsa_off < len(decoded) and decoded[_mldsa_off] == 1
            _pq_auth = 'classical only (ring-sig ✓)'
            if _has_mldsa and self._remote_mldsa_pub is not None and MLDSA87_AVAILABLE:
                _available = len(decoded) - (_mldsa_off + 1)
                if _available < MLDSA87Auth.SIG_BYTES:
                    return self._fail(f'DAKE3 ML-DSA-87 flag 0x01 but only {_available} bytes remain')
                _mldsa_sig = decoded[_mldsa_off + 1:_mldsa_off + 1 + MLDSA87Auth.SIG_BYTES]
                if not MLDSA87Auth.verify(self._remote_mldsa_pub, transcript_msg, _mldsa_sig):
                    return self._fail('DAKE3 ML-DSA-87 signature verification failed')
                _pq_auth = 'hybrid (ring-sig ✓ + ML-DSA-87 ✓)'
            self._state = DAKEState.ESTABLISHED
            self._session_created_at = time.time()
            self._trace('DAKE', 'STATE', 'SENT_DAKE2', 'ESTABLISHED', f'DAKE3 verified — {_pq_auth}')
            self._log_debug(f'DAKE3 (Auth-I) verified — {_pq_auth}')
            return True
        except Exception as e:
            return self._fail(f'process_dake3 exception: {e}')

    def _unpack_session_keys(self, result, is_initiator: bool) -> Dict[str, Any]:
        root_raw = bytes(result.root_key)
        ck_a = bytes(result.chain_key_a)
        ck_b = bytes(result.chain_key_b)
        brace_key = bytes(result.brace_key)
        ssid = bytes(result.ssid)
        mac_key = bytes(result.mac_key)
        root_key_mem = SecureMemory(32)
        root_key_mem.write(root_raw)
        return {'root_key': root_key_mem, 'chain_key_send': ck_a if is_initiator else ck_b, 'chain_key_recv': ck_b if is_initiator else ck_a, 'mac_key': mac_key, 'session_id': ssid + b'\x00' * 24, 'brace_key': brace_key, 'is_initiator': is_initiator, 'peer_long_term_pub': self.remote_identity_pub_bytes, 'peer_long_term_key': self.remote_identity_key}

    def get_session_keys(self) -> Optional[Dict[str, Any]]:
        if self._state != DAKEState.ESTABLISHED:
            return None
        keys = getattr(self, '_session_keys', None)
        if keys is None:
            return None
        return keys.copy()

def _derive_key(password: bytes, salt: bytes, dklen: int=32) -> bytes:
    if ARGON2_AVAILABLE:
        try:
            from argon2.low_level import hash_secret_raw, Type as _ArgonType
            key = hash_secret_raw(secret=password, salt=salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=dklen, type=_ArgonType.ID)
            return key
        except Exception:
            pass
    return hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=dklen)

class SecureKeyStorage:

    def __init__(self, storage_dir: Optional[str]=None):
        self._lock = threading.RLock()
        self.storage_dir = storage_dir or os.path.expanduser('~/.otrv4plus/keys')
        os.makedirs(self.storage_dir, exist_ok=True)
        try:
            os.chmod(self.storage_dir, 448)
        except Exception:
            pass
        self._master_key = None
        self._auto_initialize()
        self._migrate_remove_legacy_private_blobs()

    def _migrate_remove_legacy_private_blobs(self):
        for legacy_name in ('identity.ed448.bin', 'prekey.x448.bin'):
            path = os.path.join(self.storage_dir, legacy_name)
            if not os.path.exists(path):
                continue
            try:
                size = os.path.getsize(path)
                with open(path, 'r+b') as f:
                    f.write(b'\x00' * size)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
                os.unlink(path)
                if DEBUG_MODE:
                    try:
                        _sys.stderr.write(f'[Phase 5.3b migration] removed legacy private-key blob: {legacy_name}\n')
                    except Exception:
                        pass
            except Exception:
                pass

    def _auto_initialize(self):
        seed_path = os.path.join(self.storage_dir, '.device_seed')
        seed = None
        if os.path.exists(seed_path):
            try:
                with open(seed_path, 'rb') as f:
                    seed = f.read(32)
                if len(seed) != 32:
                    seed = None
            except Exception:
                seed = None
        if seed is None:
            seed = secrets.token_bytes(32)
            try:
                with open(seed_path, 'wb') as f:
                    f.write(seed)
                os.chmod(seed_path, 384)
            except Exception:
                pass
        salt = hashlib.sha3_256(b'OTRv4+KeyStorage:v1' + seed).digest()
        try:
            self._master_key = _derive_key(seed, salt, 32)
        except Exception:
            self._master_key = None

    def _encrypt_key(self, key_data: bytes) -> bytes:
        if self._master_key is None:
            raise RuntimeError('Storage not initialized')
        nonce = secrets.token_bytes(12)
        ciphertext = _RustDAKE_module.aes256gcm_encrypt(self._master_key, nonce, key_data, b'otrv4+key')
        return nonce + ciphertext

    def _decrypt_key(self, encrypted_data: bytes) -> bytes:
        if self._master_key is None:
            raise RuntimeError('Storage not initialized')
        if len(encrypted_data) < 12:
            raise ValueError('Invalid encrypted data')
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return _RustDAKE_module.aes256gcm_decrypt(self._master_key, nonce, ciphertext, b'otrv4+key')

    @staticmethod
    def _safe_key_component(s: str, max_len: int=64) -> str:
        import re as _re_kc
        if not s or len(s) > max_len:
            raise ValueError(f'Key component empty or too long: {s!r}')
        if not _re_kc.match('^[A-Za-z0-9_\\-]+$', s):
            raise ValueError(f'Key component contains invalid characters: {s!r}')
        return s

    def store_key(self, key_id: str, key_type: str, key_data: bytes) -> bool:
        with self._lock:
            if self._master_key is None:
                return False
            try:
                key_id = self._safe_key_component(key_id)
                key_type = self._safe_key_component(key_type)
                encrypted = self._encrypt_key(key_data)
                key_file = os.path.join(self.storage_dir, f'{key_id}.{key_type}.bin')
                with open(key_file, 'wb') as f:
                    f.write(encrypted)
                os.chmod(key_file, 384)
                return True
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to store key {key_id}: {e}')
                return False

    def load_key(self, key_id: str, key_type: str) -> Optional[bytes]:
        with self._lock:
            if self._master_key is None:
                return None
            try:
                key_id = self._safe_key_component(key_id)
                key_type = self._safe_key_component(key_type)
            except ValueError:
                return None
            key_file = os.path.join(self.storage_dir, f'{key_id}.{key_type}.bin')
            if not os.path.exists(key_file):
                return None
            try:
                with open(key_file, 'rb') as f:
                    encrypted = f.read()
                return self._decrypt_key(encrypted)
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to load key {key_id}: {e}')
                return None

    def delete_key(self, key_id: str, key_type: str) -> bool:
        with self._lock:
            try:
                key_id = self._safe_key_component(key_id)
                key_type = self._safe_key_component(key_type)
            except ValueError:
                return False
            key_file = os.path.join(self.storage_dir, f'{key_id}.{key_type}.bin')
            if os.path.exists(key_file):
                try:
                    _secure_file_destroy(key_file)
                    return True
                except Exception:
                    return False
            return False

    def clear_all(self):
        with self._lock:
            for filename in os.listdir(self.storage_dir):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    if os.path.isfile(filepath):
                        _secure_file_destroy(filepath)
                except Exception:
                    pass
            if self._master_key:
                master_key_ba = bytearray(self._master_key)
                _secure_wipe(master_key_ba)
                self._master_key = None

class SMPAutoRespondStorage:

    def __init__(self, secrets_path: Optional[str]=None):
        self._secrets: Dict[str, str] = {}
        self._lock = threading.RLock()
        self.secrets_path = secrets_path or os.path.expanduser('~/.otrv4plus/smp_secrets.json')
        try:
            _smp_dir = os.path.dirname(self.secrets_path)
            if _smp_dir:
                os.makedirs(_smp_dir, exist_ok=True)
                os.chmod(_smp_dir, 448)
        except Exception:
            pass
        self._load()

    def _load(self):
        with self._lock:
            if not os.path.exists(self.secrets_path):
                self._secrets = {}
                return
            try:
                with open(self.secrets_path, 'rb') as f:
                    raw = f.read()
                if len(raw) < 44:
                    self._secrets = {}
                    return
                salt = raw[:16]
                nonce = raw[16:28]
                ct_tag = raw[28:]
                key = _derive_key(self._master_passphrase(), salt, 32)
                plaintext = _RustDAKE_module.aes256gcm_decrypt(key, nonce, ct_tag, b'smp_secrets_v1')
                self._secrets = json.loads(plaintext.decode('utf-8'))
            except Exception:
                try:
                    key = hashlib.scrypt(self._master_passphrase(), salt=salt, n=16384, r=8, p=1, dklen=32)
                    plaintext = _RustDAKE_module.aes256gcm_decrypt(key, nonce, ct_tag, b'smp_secrets_v1')
                    self._secrets = json.loads(plaintext.decode('utf-8'))
                except Exception:
                    self._secrets = {}
            finally:
                try:
                    del key
                except Exception:
                    pass

    def _master_passphrase(self) -> bytes:
        seed_path = os.path.join(os.path.dirname(self.secrets_path), '.smp_seed')
        if os.path.exists(seed_path):
            try:
                with open(seed_path, 'rb') as f:
                    return f.read(32)
            except Exception:
                pass
        seed = secrets.token_bytes(32)
        try:
            os.makedirs(os.path.dirname(seed_path) or '.', exist_ok=True)
            with open(seed_path, 'wb') as f:
                f.write(seed)
            os.chmod(seed_path, 384)
        except Exception:
            pass
        return seed

    def _save(self):
        with self._lock:
            try:
                plaintext = json.dumps(self._secrets, separators=(',', ':')).encode('utf-8')
                salt = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                key = _derive_key(self._master_passphrase(), salt, 32)
                ct_tag = _RustDAKE_module.aes256gcm_encrypt(key, nonce, plaintext, b'smp_secrets_v1')
                blob = salt + nonce + ct_tag
                _tmp_path = None
                with tempfile.NamedTemporaryFile(mode='wb', dir=os.path.dirname(self.secrets_path) or '.', delete=False) as f:
                    _tmp_path = f.name
                    f.write(blob)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(_tmp_path, 384)
                os.replace(_tmp_path, self.secrets_path)
            except Exception:
                if _tmp_path:
                    try:
                        os.unlink(_tmp_path)
                    except Exception:
                        pass
            finally:
                try:
                    del key, plaintext, blob
                except Exception:
                    pass

    def set_secret(self, peer: str, secret: str) -> None:
        with self._lock:
            self._secrets[peer] = secret
            self._save()

    def get_secret(self, peer: str) -> str:
        with self._lock:
            return self._secrets.get(peer, '')

    def remove_secret(self, peer: str) -> bool:
        with self._lock:
            if peer in self._secrets:
                del self._secrets[peer]
                self._save()
                return True
            return False

    def clear_all(self) -> None:
        with self._lock:
            self._secrets.clear()
            self._save()

    def list_secrets(self) -> Dict[str, str]:
        with self._lock:
            masked = {}
            for peer, secret in self._secrets.items():
                if len(secret) > 3:
                    masked[peer] = secret[:1] + '*' * (len(secret) - 2) + secret[-1]
                else:
                    masked[peer] = '*' * len(secret)
            return masked

class TrustDatabase:

    class FingerprintMismatchError(ValueError):

        def __init__(self, peer: str, stored: str, received: str):
            self.peer = peer
            self.stored = stored
            self.received = received
            super().__init__(f'FINGERPRINT MISMATCH for {peer}! Stored: {stored[:16]}… Got: {received[:16]}… This may indicate a MITM attack. Session aborted.')

    def __init__(self, db_path: Optional[str]=None):
        self._lock = threading.RLock()
        self.db_path = db_path or os.path.expanduser('~/.otrv4plus/trust.json')
        self._db: Dict[str, dict] = {}
        self._load()

    def _load(self):
        with self._lock:
            if not os.path.exists(self.db_path):
                self._db = {}
                return
            try:
                with open(self.db_path, 'r') as f:
                    raw = json.load(f)
                migrated = {}
                for k, v in raw.items():
                    if isinstance(v, str):
                        migrated[k] = {'fingerprint': v, 'trusted': True}
                    elif isinstance(v, dict):
                        migrated[k] = v
                    else:
                        continue
                self._db = migrated
            except (json.JSONDecodeError, IOError, OSError) as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Error loading: {e}')
                self._db = {}
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Unexpected error loading: {e}')
                self._db = {}

    def _save(self):
        with self._lock:
            try:
                _db_dir = os.path.dirname(self.db_path) or '.'
                os.makedirs(_db_dir, exist_ok=True)
                try:
                    os.chmod(_db_dir, 448)
                except Exception:
                    pass
                _tmp_path2 = None
                with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(self.db_path) or '.', delete=False, encoding='utf-8') as f:
                    _tmp_path2 = f.name
                    json.dump(self._db, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(_tmp_path2, 384)
                os.replace(_tmp_path2, self.db_path)
            except (IOError, OSError, PermissionError) as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Error saving: {e}')
                if _tmp_path2:
                    try:
                        os.unlink(_tmp_path2)
                    except Exception:
                        pass
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Unexpected error saving: {e}')
                try:
                    os.unlink(f.name)
                except Exception:
                    pass

    def check_or_pin(self, peer: str, fingerprint: str) -> bool:
        if not peer or not fingerprint:
            raise ValueError('Peer and fingerprint cannot be empty')
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            raise TypeError('Peer and fingerprint must be strings')
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    self._db[peer] = {'fingerprint': fingerprint, 'trusted': False}
                    self._save()
                    return False
                stored_fp = entry.get('fingerprint', '')
                if not stored_fp:
                    self._db[peer] = {'fingerprint': fingerprint, 'trusted': False}
                    self._save()
                    return False
                if not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8')):
                    raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)
                return entry.get('trusted', False)
            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f'Invalid trust database entry: {e}')
            except Exception as e:
                raise RuntimeError(f'Trust database error: {e}')

    def is_trusted(self, peer: str, fingerprint: str) -> bool:
        if not peer or not fingerprint:
            return False
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            return False
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    return False
                stored_fp = entry.get('fingerprint', '')
                if not stored_fp:
                    return False
                if not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8')):
                    return False
                return entry.get('trusted', False)
            except (KeyError, AttributeError, TypeError):
                return False
            except Exception:
                return False

    def add_trust(self, peer: str, fingerprint: str) -> bool:
        if not peer or not fingerprint:
            raise ValueError('Peer and fingerprint cannot be empty')
        if not isinstance(peer, str) or not isinstance(fingerprint, str):
            raise TypeError('Peer and fingerprint must be strings')
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is not None:
                    stored_fp = entry.get('fingerprint', '')
                    if stored_fp and (not hmac.compare_digest(stored_fp.encode('utf-8'), fingerprint.encode('utf-8'))):
                        raise TrustDatabase.FingerprintMismatchError(peer, stored_fp, fingerprint)
                self._db[peer] = {'fingerprint': fingerprint, 'trusted': True}
                self._save()
                return True
            except TrustDatabase.FingerprintMismatchError:
                raise
            except (KeyError, AttributeError, TypeError) as e:
                raise ValueError(f'Invalid trust database entry: {e}')
            except Exception as e:
                raise RuntimeError(f'Failed to add trust: {e}')

    def remove_trust(self, peer: str) -> bool:
        if not peer:
            return False
        with self._lock:
            try:
                if peer in self._db:
                    del self._db[peer]
                    self._save()
                    return True
                return False
            except (KeyError, AttributeError) as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Error removing trust: {e}')
                return False
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'[TrustDatabase] Unexpected error removing trust: {e}')
                return False

    def get_trusted_fingerprint(self, peer: str) -> str:
        if not peer:
            return ''
        with self._lock:
            try:
                entry = self._db.get(peer)
                if entry is None:
                    return ''
                if not entry.get('trusted', False):
                    return ''
                return entry.get('fingerprint', '')
            except (KeyError, AttributeError):
                return ''
            except Exception:
                return ''

    def list_trusted(self) -> Dict[str, str]:
        with self._lock:
            try:
                return {p: e['fingerprint'] for p, e in self._db.items() if e.get('trusted')}
            except (KeyError, AttributeError, TypeError):
                return {}
            except Exception:
                return {}

class TabBar:

    def __init__(self, terminal_width: int=TERMINAL_WIDTH):
        self.terminal_width = terminal_width
        self.visible_start = 0
        self.tab_data: Dict[str, dict] = {}

    def calculate_tab_width(self, tab_name: str, has_unread: int, is_active: bool) -> int:
        width = len(tab_name) + 2
        if '🔵' in tab_name or '🟢' in tab_name or '🟡' in tab_name or ('🔴' in tab_name):
            width += 2
        if has_unread > 0:
            width += len(f'({has_unread})') + 1
        width += 1
        return width

    def render(self, panels: Dict[str, 'ChatPanel'], active_panel_name: str) -> List[str]:
        if not panels:
            return []
        tabs = []
        total_width = 0
        max_tabs_width = self.terminal_width - 10
        for panel_name, panel in panels.items():
            icon = UIConstants.SECURITY_ICONS.get(panel.security_level, '')
            display_name = panel_name
            if icon:
                display_name = f'{display_name}{icon}'
            is_active = panel_name == active_panel_name
            self.tab_data[panel_name] = {'display_name': display_name, 'icon': icon, 'unread': panel.unread_count, 'active': is_active, 'width': self.calculate_tab_width(display_name, panel.unread_count, is_active)}
            tabs.append(panel_name)
        total_tabs_width = sum((self.tab_data[tab]['width'] for tab in tabs))
        need_scroll = total_tabs_width > max_tabs_width
        if need_scroll:
            try:
                active_index = tabs.index(active_panel_name)
            except ValueError:
                active_index = 0
            if active_index < self.visible_start:
                self.visible_start = active_index
            elif active_index >= self.visible_start + self._max_visible_tabs(tabs, max_tabs_width):
                self.visible_start = active_index - 2
            self.visible_start = max(0, min(self.visible_start, len(tabs) - 1))
            visible_tabs = []
            current_width = 0
            max_visible = self._max_visible_tabs(tabs, max_tabs_width)
            for i in range(self.visible_start, min(len(tabs), self.visible_start + max_visible)):
                tab_name = tabs[i]
                tab_info = self.tab_data[tab_name]
                if current_width + tab_info['width'] > max_tabs_width - 6:
                    break
                visible_tabs.append(tab_name)
                current_width += tab_info['width']
            if self.visible_start > 0:
                visible_tabs.insert(0, '<<')
            if self.visible_start + len(visible_tabs) < len(tabs):
                visible_tabs.append('>>')
        else:
            visible_tabs = tabs
            self.visible_start = 0
        tab_strings = []
        for tab_name in visible_tabs:
            if tab_name == '<<':
                tab_strings.append('◀')
                continue
            elif tab_name == '>>':
                tab_strings.append('▶')
                continue
            tab_info = self.tab_data[tab_name]
            display_name = tab_info['display_name']
            unread = tab_info['unread']
            is_active = tab_info['active']
            if unread > 0:
                tab_display = f'{display_name}({unread})'
            else:
                tab_display = display_name
            if is_active:
                tab_str = f'{colorize('[' + tab_display + ']', 'bg_green')}'
            elif unread > 0:
                _hl = 'magenta' if not tab_name.startswith('#') else 'cyan'
                tab_str = colorize(f'[{tab_display}]', _hl)
            else:
                tab_str = f'[{tab_display}]'
            tab_strings.append(tab_str)
        tab_line = ' | '.join(tab_strings)
        if len(tab_line) > self.terminal_width - 2:
            tab_line = tab_line[:self.terminal_width - 4] + '…'
        return [tab_line]

    def _max_visible_tabs(self, tabs: List[str], max_width: int) -> int:
        avg_width = 12
        return max(1, max_width // avg_width)

class Pager:

    def __init__(self, lines_per_page: int=20):
        self.lines_per_page = lines_per_page if not IS_TERMUX else 15
        self.active = False

    def display(self, lines: List[str], header: str='', footer: str=''):
        if not lines:
            safe_print(colorize('  (empty)', 'dim'))
            return
        self.active = True
        total_pages = (len(lines) + self.lines_per_page - 1) // self.lines_per_page
        page = 0
        try:
            while self.active:
                start = page * self.lines_per_page
                end = min(start + self.lines_per_page, len(lines))
                safe_print(colorize(f'── {header} ', 'cyan') + colorize(f'({page + 1}/{total_pages})' if total_pages > 1 else '', 'dim') + colorize(' ' + '─' * 30, 'cyan'))
                for line in lines[start:end]:
                    if len(line) > TERMINAL_WIDTH:
                        line = line[:TERMINAL_WIDTH - 3] + '...'
                    safe_print(line)
                if footer:
                    safe_print(colorize(footer, 'dim'))
                safe_print(colorize('─' * 42, 'cyan'))
                if total_pages <= 1:
                    self.active = False
                    break
                safe_print(colorize('  [n]ext  [p]rev  [q]uit', 'dim'), end='  ', flush=True)
                try:
                    if _raw_mode_active:
                        b = os.read(_stdin_fd, 1)
                        ch = chr(b[0]).lower() if b else 'q'
                        sys.stdout.write('\n')
                        sys.stdout.flush()
                    else:
                        ch = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ch = 'q'
                if ch in ('n', '\r', '\n', ' '):
                    page = min(page + 1, total_pages - 1)
                    if page >= total_pages - 1 and ch == 'n':
                        self.active = False
                elif ch == 'p':
                    page = max(0, page - 1)
                elif ch in ('q',):
                    self.active = False
        finally:
            # Drain any buffered keystrokes (e.g. the \n after 'q')
            # so they don't leak into the main input loop as chat messages.
            try:
                import select as _sel
                while True:
                    r2, _, _ = _sel.select([_stdin_fd], [], [], 0.05)
                    if not r2:
                        break
                    os.read(_stdin_fd, 64)
            except Exception:
                pass
            _input_buffer.clear()
            _flush_display_queue()
            # Repaint TUI so body isn't corrupted by pager output
            try:
                _c2 = getattr(__import__('builtins'), '_active_client', None)
                if _c2 and getattr(_c2, '_tui_enabled', False) and _c2._screen:
                    _c2._screen.redraw_full()
            except Exception:
                pass

class Screen:

    def __init__(self, client):
        self.client = client
        self.scroll_offset = 0
        self.cols = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
        self.rows = TERMINAL_HEIGHT if TERMINAL_HEIGHT > 0 else 24

    def _measure(self) -> None:
        sz = shutil.get_terminal_size(fallback=(80, 24))
        self.cols = max(20, sz.columns)
        self.rows = max(10, sz.lines)
        if IS_TERMUX and self.cols < 40:
            self.cols = 80

    def _sep(self) -> str:
        return colorize('-' * self.cols, 'dim')

    def _tabbar_lines(self) -> list:
        pm = self.client.panel_manager
        try:
            bar = TabBar(self.cols)
            lines = bar.render(pm.panels, pm.active_panel)
        except Exception as exc:
            lines = [colorize(f'[tabbar: {exc}]', 'red')]
        if isinstance(lines, str):
            lines = [lines]
        return lines or ['']

    def _body_visual_lines(self) -> list:
        pm = self.client.panel_manager
        panel = pm.panels.get(pm.active_panel)
        if panel is None:
            return []
        out = []
        for entry in panel.history:
            ts = colorize(time.strftime('%H:%M:%S', time.localtime(entry.get('timestamp', time.time()))), 'dim')
            line = f'{ts} {entry['message']}'
            wrapped = _word_wrap(line, self.cols)
            out.extend(wrapped.split('\n'))
        return out

    def _input_line(self) -> str:
        buf = ''.join(_input_buffer)
        return (_current_prompt or '') + buf

    def _chrome(self, tabs):
        return 1 + 1 + len(tabs)

    def _row_tab(self, tabs, i):
        return self.rows - len(tabs) + i + 1

    def redraw_full(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [''] * (body_h - len(shown)) + shown
            k = '\x1b[K'
            rows = [ln + k for ln in shown]
            rows.append(self._sep() + k)
            rows.append(self._input_line() + k)
            rows += [t + k for t in tabs]
            sys.stdout.write('\x1b[2J\x1b[H')
            sys.stdout.write('\r\n'.join(rows))
            sys.stdout.write(f'\x1b[{len(tabs)}A\r')
            sys.stdout.flush()

    def redraw_body(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [''] * (body_h - len(shown)) + shown
            out = ['\x1b7']
            for i, ln in enumerate(shown):
                out.append(f'\x1b[{1 + i};1H\x1b[K')
                out.append(ln)
            # Move to input row and redraw the prompt + typed buffer so
            # text the user was typing is never lost when a message arrives.
            _input_r = self.rows - len(tabs)
            _buf = ''.join(_input_buffer)
            out.append(f'\x1b[{_input_r};1H\x1b[2K')
            out.append((_current_prompt or '') + _buf)
            out.append('\x1b8')
            out.append(f'\x1b[{_input_r};1H')
            # Restore cursor to end of typed buffer
            _vis = len(_ANSI_RE.sub('', (_current_prompt or '') + _buf))
            if _vis > 0:
                out.append(f'\x1b[{_vis + 1}G')
            sys.stdout.write(''.join(out))
            sys.stdout.flush()

    def redraw_tabbar(self) -> None:
        with _print_lock:
            self._measure()
            tabs = self._tabbar_lines()
            out = ['\x1b7']
            for i, t in enumerate(tabs):
                out.append(f'\x1b[{self._row_tab(tabs, i)};1H\x1b[K')
                out.append(t)
            out.append('\x1b8')
            sys.stdout.write(''.join(out))
            sys.stdout.flush()

class ChatPanel:

    def __init__(self, name: str, panel_type: str):
        self.name = name
        self.type = panel_type
        self.history: List[Dict[str, Any]] = []
        self.unread_count = 0
        self.active = False
        self.created = time.time()
        self.recent_users: Set[str] = set()
        self.secure_session = False
        self.last_activity = time.time()
        self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        self.smp_progress = (0, 4)

    def add_message(self, message: str, metadata: Optional[dict]=None) -> int:
        msg_id = len(self.history)
        self.history.append({'id': msg_id, 'message': message, 'timestamp': time.time(), 'metadata': metadata or {}})
        self.last_activity = time.time()
        return msg_id

    def get_messages(self, start: int=0, count: Optional[int]=None) -> List[str]:
        if not self.history:
            return []
        messages = [msg['message'] for msg in self.history]
        if count is None:
            return messages[start:]
        else:
            return messages[start:start + count]

    def clear_unread(self):
        self.unread_count = 0
        self.recent_users.clear()

    def mark_secure(self, level: UIConstants.SecurityLevel=UIConstants.SecurityLevel.ENCRYPTED):
        self.secure_session = True
        self.type = 'secure'
        self.security_level = level

    def update_smp_progress(self, step: int, total_steps: int):
        self.smp_progress = (step, total_steps)

    def get_progress_display(self) -> str:
        step, total = self.smp_progress
        if step == 0:
            return ''
        elif step == total:
            return '✅'
        else:
            progress_chars = ['○', '◔', '◑', '◕', '●']
            progress_index = min(int(step / total * len(progress_chars)), len(progress_chars) - 1)
            return f'🔄 {progress_chars[progress_index]} {step}/{total}'

    def clear_history(self):
        self.history.clear()

class PanelManager:

    def __init__(self, client):
        self.client = client
        self.panels: Dict[str, ChatPanel] = {}
        self.active_panel: Optional[str] = None
        self.panel_order: List[str] = []
        self.lock = threading.RLock()
        self.auto_switch_enabled = True
        self.tab_bar = TabBar()
        self.add_panel('system', 'system')

    def add_panel(self, name: str, panel_type: str) -> bool:
        with self.lock:
            if name not in self.panels:
                self.panels[name] = ChatPanel(name, panel_type)
                self.panel_order.append(name)
                if not self.active_panel:
                    self.active_panel = name
                    self.panels[name].active = True
                self._render_ui()
                return True
            return False

    def get_or_create_panel(self, name: str, panel_type: str='private') -> ChatPanel:
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, panel_type)
            return self.panels[name]

    def get_panel(self, name: str) -> Optional[ChatPanel]:
        with self.lock:
            return self.panels.get(name)

    def get_active_panel(self) -> Optional[ChatPanel]:
        with self.lock:
            if self.active_panel in self.panels:
                return self.panels[self.active_panel]
            return None

    def switch_to_panel(self, name: str) -> bool:
        with self.lock:
            if name in self.panels:
                if self.active_panel and self.active_panel in self.panels:
                    self.panels[self.active_panel].active = False
                    self.panels[self.active_panel].clear_unread()
                self.active_panel = name
                self.panels[name].active = True
                self.panels[name].clear_unread()
                self._render_ui()
                return True
            return False

    def list_panels(self) -> List[str]:
        with self.lock:
            return list(self.panel_order)

    def add_message(self, target: str, message: str) -> None:
        with self.lock:
            if target not in self.panels:
                self.add_panel(target, 'private')
            panel = self.panels[target]
            panel.add_message(message)
            if self.active_panel != target:
                panel.unread_count += 1

    def update_panel_security(self, name: str, level: UIConstants.SecurityLevel) -> None:
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, 'private')
            panel = self.panels[name]
            panel.security_level = level
            if level in (UIConstants.SecurityLevel.ENCRYPTED, UIConstants.SecurityLevel.FINGERPRINT, UIConstants.SecurityLevel.SMP_VERIFIED):
                panel.mark_secure(level)
            self._render_ui()

    def update_smp_progress(self, name: str, step: int, total_steps: int) -> None:
        with self.lock:
            if name in self.panels:
                self.panels[name].update_smp_progress(step, total_steps)
                self._render_ui()

    def clear_panel_history(self, panel_name: str) -> None:
        with self.lock:
            if panel_name in self.panels:
                self.panels[panel_name].clear_history()
                self._render_ui()

    def clear_all_histories(self) -> None:
        with self.lock:
            for panel in self.panels.values():
                panel.clear_history()
            self._render_ui()

    def render_panel_header(self, panel: ChatPanel) -> str:
        level = getattr(panel, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)
        icon = UIConstants.SECURITY_ICONS.get(level, '')
        name = colorize(panel.name, 'cyan')
        sec_name = UIConstants.SECURITY_NAMES.get(level, 'PLAINTEXT')
        color_map = {UIConstants.SecurityLevel.PLAINTEXT: 'bold_red', UIConstants.SecurityLevel.ENCRYPTED: 'bold_yellow', UIConstants.SecurityLevel.FINGERPRINT: 'bold_green', UIConstants.SecurityLevel.SMP_VERIFIED: 'blue'}
        sec_color = color_map.get(level, 'white')
        sec_text = colorize(f'[{sec_name}]', sec_color)
        if panel.type in ('private', 'secure'):
            return f'{icon} {name} {sec_text}'
        return name

    def _render_ui(self) -> None:
        now = time.time()
        if now - getattr(self, '_last_render_ts', 0) < 0.25:
            return
        self._last_render_ts = now
        try:
            cb = getattr(self.client, '_prompt_refresh_cb', None)
            if cb is not None:
                cb()
        except Exception:
            pass

class MessageRouter:

    def __init__(self, panel_manager: PanelManager):
        self.panel_manager = panel_manager
        self.routes = {'^\\?OTRv4.*': self._route_otr_message, '^PRIVMSG.*#[^:]+:.*': self._route_to_channel_tab, '^PRIVMSG.*:.*': self._route_to_sender_tab, '^JOIN.*': self._route_join, '^PART.*': self._route_part, '^QUIT.*': self._route_quit, '^NICK.*': self._route_nick}

    def route(self, message: str, prefix: Optional[str]=None, msg_type: Optional[str]=None) -> str:
        sender_nick = prefix.split('!')[0] if prefix and '!' in prefix else prefix or 'server'
        if msg_type == 'OTR_STATUS':
            return sender_nick if sender_nick and sender_nick != 'system' else 'system'
        if msg_type == 'SMP_STATUS':
            return sender_nick if sender_nick and sender_nick != 'system' else 'system'
        for pattern, handler in self.routes.items():
            if re.match(pattern, message):
                result = handler(message, sender_nick)
                if result:
                    return result
        return 'system'

    def _route_otr_message(self, message: str, sender: str) -> Optional[str]:
        if '?OTRv4' in message:
            return sender
        return None

    def _route_to_channel_tab(self, message: str, sender: str) -> Optional[str]:
        match = re.match('PRIVMSG (\\#[^\\s]+) :', message)
        if match:
            channel = match.group(1)
            return channel
        return None

    def _route_to_sender_tab(self, message: str, sender: str) -> Optional[str]:
        match = re.match('PRIVMSG ([^#][^\\s]*) :', message)
        if match:
            target = match.group(1)
            if target == self.panel_manager.client.nick:
                return sender
        return None

    def _route_join(self, message: str, sender: str) -> Optional[str]:
        match = re.match('JOIN :?(#[^\\s]+)', message)
        if match:
            channel = match.group(1)
            return channel
        return None

    def _route_part(self, message: str, sender: str) -> Optional[str]:
        match = re.match('PART :?(#[^\\s]+)', message)
        if match:
            channel = match.group(1)
            return channel
        return None

    def _route_quit(self, message: str, sender: str) -> Optional[str]:
        return 'system'

    def _route_nick(self, message: str, sender: str) -> Optional[str]:
        return 'system'

class EnhancedOTRSession:

    def __init__(self, peer: str, is_initiator: bool, tracer: OTRTracer, logger: Optional[OTRLogger]=None):
        self.peer = peer
        self.is_initiator = is_initiator
        self.tracer = tracer
        self.logger = logger or NullLogger()
        self.lock = threading.RLock()
        self.session_state = SessionState.PLAINTEXT
        self.dake_state = DAKEState.IDLE
        self.smp_state = UIConstants.SMPState.NONE
        self.dake_engine: Optional['RustDAKEAdapter'] = None
        self.ratchet: Optional[RustBackedDoubleRatchet] = None
        self.rust_smp = None
        self.smp_vault = None
        self.session_id: Optional[bytes] = None
        self.root_key: Optional[SecureMemory] = None
        self.remote_long_term_pub: Optional[bytes] = None
        self._remote_long_term_pub_bytes: Optional[bytes] = None
        self._dake_chain_key_send: Optional[bytes] = None
        self._dake_chain_key_recv: Optional[bytes] = None
        self._dake_brace_key: Optional[bytes] = None
        self._dake_output = None
        self.pending_messages: List[str] = []
        self.received_messages: List[bytes] = []
        self.created = time.time()
        self.last_activity = time.time()
        self.dake_start_time: Optional[float] = None
        self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        self._sender_tag: int = _generate_instance_tag()
        self._receiver_tag: int = 0
        self._peer_disconnected: bool = False
        self._last_extra_sym_key: Optional[bytes] = None
        self._extra_sym_key_cb = None
        self._queued_smp_response: Optional[str] = None
        self.auto_smp_secret: bool = False
        self.auto_smp_scheduled: bool = False
        self.auto_smp_started: bool = False
        self.auto_smp_completed: bool = False
        self.smp_step: int = 0
        self.smp_total_steps: int = 4
        self.smp_start_time: float = 0.0
        self._smp_notify_cb = None
        self._ping_refresh_cb = None
        self.tracer.trace(peer, 'SESSION', None, 'PLAINTEXT', 'session created')
        if is_initiator:
            self.tracer.trace(peer, 'ROLE', None, 'INITIATOR')
        else:
            self.tracer.trace(peer, 'ROLE', None, 'RESPONDER')

    def _acquire_lock(self, timeout: float=5.0) -> bool:
        try:
            return self.lock.acquire(timeout=timeout)
        except Exception:
            return False

    def _release_lock(self):
        try:
            self.lock.release()
        except Exception:
            pass

    def transition_session(self, new_state: SessionState, reason: str=''):
        if not self._acquire_lock():
            raise StateMachineError('Failed to acquire lock for state transition')
        try:
            old_state = self.session_state
            valid_transitions = {SessionState.PLAINTEXT: [SessionState.DAKE_IN_PROGRESS, SessionState.FAILED], SessionState.DAKE_IN_PROGRESS: [SessionState.ENCRYPTED, SessionState.FAILED, SessionState.PLAINTEXT], SessionState.ENCRYPTED: [SessionState.FINISHED, SessionState.FAILED], SessionState.FAILED: [SessionState.PLAINTEXT], SessionState.FINISHED: []}
            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(f'REJECTED illegal session transition: {old_state.name} → {new_state.name}. Peer may be attempting a state confusion attack.')
            self.session_state = new_state
            self.tracer.trace(self.peer, 'SESSION', old_state.name, new_state.name, reason)
            if new_state == SessionState.ENCRYPTED:
                self.security_level = UIConstants.SecurityLevel.ENCRYPTED
                self.tracer.trace(self.peer, 'SECURITY', 'PLAINTEXT', 'ENCRYPTED', 'DAKE completed')
                self._process_queued_messages()
            elif new_state == SessionState.FAILED:
                self.tracer.trace(self.peer, 'ERROR', old_state.name, 'FAILED', reason)
                self._cleanup_failed_session()
            elif new_state == SessionState.PLAINTEXT:
                self.dake_state = DAKEState.IDLE
                self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        finally:
            self._release_lock()

    def transition_dake(self, new_state: DAKEState, reason: str=''):
        if not self._acquire_lock():
            raise StateMachineError('Failed to acquire lock for DAKE transition')
        try:
            old_state = self.dake_state
            valid_transitions = {DAKEState.IDLE: [DAKEState.SENT_DAKE1, DAKEState.RECEIVED_DAKE1, DAKEState.FAILED], DAKEState.SENT_DAKE1: [DAKEState.ESTABLISHED, DAKEState.FAILED], DAKEState.RECEIVED_DAKE1: [DAKEState.SENT_DAKE2, DAKEState.FAILED], DAKEState.SENT_DAKE2: [DAKEState.ESTABLISHED, DAKEState.FAILED], DAKEState.ESTABLISHED: [], DAKEState.FAILED: []}
            if new_state not in valid_transitions.get(old_state, []):
                raise StateMachineError(f'Invalid DAKE transition: {old_state.name} → {new_state.name}')
            self.dake_state = new_state
            self.tracer.trace(self.peer, 'DAKE', old_state.name, new_state.name, reason)
            if new_state == DAKEState.ESTABLISHED:
                self.transition_session(SessionState.ENCRYPTED, 'DAKE established')
                self._initialize_ratchet()
        finally:
            self._release_lock()

    def transition_smp(self, new_state: UIConstants.SMPState, reason: str=''):
        if not self._acquire_lock():
            raise StateMachineError('Failed to acquire lock for SMP transition')
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError('SMP requires encrypted session')
            old_state = self.smp_state
            self.smp_state = new_state
            self.tracer.trace(self.peer, 'SMP', old_state.name, new_state.name, reason)
            if new_state == UIConstants.SMPState.SUCCEEDED:
                self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                self.tracer.trace(self.peer, 'SECURITY', 'ENCRYPTED', 'SMP_VERIFIED', 'SMP succeeded')
        finally:
            self._release_lock()

    def initialize_dake(self, client_profile: ClientProfile, explicit_initiator: bool=False) -> 'RustDAKEAdapter':
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for DAKE initialization')
        try:
            if self.dake_engine is not None:
                raise RuntimeError('DAKE engine already initialized')
            self.dake_engine = RustDAKEAdapter(client_profile=client_profile, explicit_initiator=explicit_initiator, tracer=self.tracer, logger=self.logger)
            return self.dake_engine
        finally:
            self._release_lock()

    def _initialize_ratchet(self):
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for ratchet initialization')
        try:
            if self.ratchet is not None:
                raise RuntimeError('Ratchet already initialized')
            if not RUST_RATCHET_AVAILABLE:
                raise RuntimeError('otrv4_core Rust module not installed — cannot create encrypted session. Build with: cd Rust && cargo test --release && maturin build --release && pip install target/wheels/otrv4_core-*.whl')
            dake_output = getattr(self, '_dake_output', None)
            if dake_output is not None and (not getattr(dake_output, 'consumed', True)):
                self.ratchet = RustBackedDoubleRatchet.from_dake_output(dake_output=dake_output, is_initiator=self.is_initiator, ad=b'OTRv4-DATA', logger=self.logger, rekey_interval=OTRConstants.REKEY_INTERVAL, rekey_timeout=OTRConstants.REKEY_TIMEOUT)
                self._ratchet_backend = 'rust'
                self._dake_output = None
                _backend_label = 'Rust (Phase-4 opaque handle; keys never in Python)'
                self.tracer.trace(self.peer, 'RATCHET', None, 'ACTIVE', f'ratchet: {_backend_label}')
                return
            if self.root_key is None:
                raise RuntimeError('Root key not available')
            _ratchet_args = dict(root_key=self.root_key, is_initiator=self.is_initiator, ad=b'OTRv4-DATA', logger=self.logger, chain_key_send=self._dake_chain_key_send, chain_key_recv=self._dake_chain_key_recv, brace_key=self._dake_brace_key, rekey_interval=OTRConstants.REKEY_INTERVAL, rekey_timeout=OTRConstants.REKEY_TIMEOUT)
            self.ratchet = RustBackedDoubleRatchet(**_ratchet_args)
            self._ratchet_backend = 'rust'
            self._dake_chain_key_send = None
            self._dake_chain_key_recv = None
            self._dake_brace_key = None
            _backend_label = 'Rust (zeroize-on-drop; legacy v10.6.2 path)'
            self.tracer.trace(self.peer, 'RATCHET', None, 'ACTIVE', f'ratchet: {_backend_label}')
        finally:
            self._release_lock()

    def initialize_smp(self):
        if self.rust_smp is None:
            try:
                from otrv4_core import RustSMP, RustSMPVault
                self.rust_smp = RustSMP(self.is_initiator)
                self.smp_vault = RustSMPVault()
                self.tracer.trace(self.peer, 'SMP', None, 'READY', 'Rust SMP engine initialized')
            except Exception as e:
                self.logger.debug(f'initialize_smp FAILED: {e}')
                raise RuntimeError(f'Failed to initialize Rust SMP engine: {e}') from e

    def queue_outgoing_message(self, message: str):
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for queueing')
        try:
            if self.session_state == SessionState.ENCRYPTED:
                return self.encrypt_message(message)
            elif self.session_state == SessionState.DAKE_IN_PROGRESS:
                self.pending_messages.append(message)
                self.tracer.trace(self.peer, 'QUEUE', 'OUTGOING', str(len(self.pending_messages)), f'message queued (DAKE in progress)')
                return None
            elif self.session_state == SessionState.PLAINTEXT:
                raise StateMachineError('Cannot send message: OTR not established')
            else:
                raise StateMachineError(f'Cannot send message in state: {self.session_state.name}')
        finally:
            self._release_lock()

    def _process_queued_messages(self):
        if not self._acquire_lock():
            return
        try:
            if not self.pending_messages:
                return
            self.tracer.trace(self.peer, 'QUEUE', 'PROCESSING', str(len(self.pending_messages)), 'processing queued messages')
            for msg in self.pending_messages:
                self.tracer.trace(self.peer, 'QUEUE', 'QUEUED', 'PROCESSED', f'message: {msg[:50]}...')
            self.pending_messages.clear()
        finally:
            self._release_lock()

    def encrypt_message(self, plaintext: str) -> Optional[str]:
        return self.encrypt_with_tlvs(plaintext, [])

    def encrypt_with_tlvs(self, plaintext: str, tlvs: List['OTRv4TLV']) -> Optional[str]:
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for encryption')
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError('Cannot encrypt: session not in ENCRYPTED state')
            if self.ratchet is None:
                raise RuntimeError('Ratchet not initialized — DAKE may not be complete')
            if self.dake_engine is not None and self.dake_engine.is_session_expired():
                raise StateMachineError('OTR session has exceeded its maximum age (24 h). Re-establish DAKE to continue communicating securely.')
            self.last_activity = time.time()
            payload_obj = OTRv4Payload(plaintext or '', tlvs)
            payload = payload_obj.encode(add_padding=True)
            ct, rh_bytes, nonce, tag, ratchet_id, reveal_keys = self.ratchet.encrypt_message(payload)
            ct_with_tag = ct + tag
            rh = RatchetHeader.decode(rh_bytes)
            mac_key = hashlib.sha3_512(self.session_id + ratchet_id.to_bytes(4, 'big') + rh.msg_num.to_bytes(4, 'big') + b'OTRv4-MAC-KEY').digest()[:32]
            dmsg = OTRv4DataMessage()
            dmsg.sender_tag = self._sender_tag
            dmsg.receiver_tag = self._receiver_tag
            dmsg.flags = 0
            dmsg.prev_chain_len = rh.prev_chain_len
            dmsg.ratchet_id = ratchet_id
            dmsg.message_id = rh.msg_num
            dmsg.ecdh_pub = rh.dh_pub
            dmsg.nonce = nonce
            dmsg.ciphertext = ct_with_tag
            _kem_ct = self.ratchet.consume_outgoing_kem_ct()
            _kem_ek = self.ratchet.consume_outgoing_kem_ek() if _kem_ct is None else None
            dmsg.kem_ct = _kem_ct
            dmsg.kem_ek = _kem_ek
            dmsg.mac = dmsg.compute_mac(mac_key)
            dmsg.revealed_mac_keys = [k for k in reveal_keys if len(k) == 32]
            wire = dmsg.encode()
            encoded = base64.urlsafe_b64encode(wire).decode('ascii').rstrip('=')
            result = f'?OTRv4 {encoded}.'
            self.tracer.trace(self.peer, 'ENCRYPT', 'PLAINTEXT', 'ENCRYPTED', f'len={len(plaintext)} tlvs={[t.type for t in tlvs]}')
            return result
        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, 'ERROR', 'ENCRYPT', 'FAILED', str(e))
            raise EncryptionError(f'Encryption failed: {e}', self)
        finally:
            self._release_lock()

    def decrypt_message(self, encrypted_msg: str) -> bytes:
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for decryption')
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise StateMachineError('Cannot decrypt: session not in ENCRYPTED state')
            if self.ratchet is None:
                raise RuntimeError('Ratchet not initialized')
            self.last_activity = time.time()
            if not encrypted_msg.startswith('?OTRv4 '):
                raise ValueError('Not an OTRv4 message')
            raw = encrypted_msg[7:].strip().rstrip('.')
            try:
                decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))
            except Exception:
                decoded = base64.b64decode(raw.replace('-', '+').replace('_', '/') + '=' * (-len(raw) % 4))
            if len(decoded) >= 3 and decoded[0] == 0 and (decoded[1] == 4) and (decoded[2] == OTRv4DataMessage.TYPE):
                text_bytes = self._enh_dec_v6(decoded)
            else:
                text_bytes = self._enh_dec_legacy(decoded)
            self.tracer.trace(self.peer, 'DECRYPT', 'ENCRYPTED', 'PLAINTEXT', f'len={len(text_bytes)}')
            return text_bytes
        except (EncryptionError, StateMachineError):
            raise
        except Exception as e:
            self.tracer.trace(self.peer, 'ERROR', 'DECRYPT', 'FAILED', str(e))
            raise EncryptionError(f'Decryption failed: {e}', self)
        finally:
            self._release_lock()

    def _enh_dec_v6(self, decoded: bytes) -> bytes:
        dmsg = OTRv4DataMessage.decode(decoded)
        if self._receiver_tag == 0 and dmsg.sender_tag >= 256:
            self._receiver_tag = dmsg.sender_tag
        if dmsg.receiver_tag != 0 and dmsg.receiver_tag != self._sender_tag:
            raise ValueError(f'Instance tag mismatch: 0x{self._sender_tag:08x} vs 0x{dmsg.receiver_tag:08x}')
        mac_key = hashlib.sha3_512(self.session_id + dmsg.ratchet_id.to_bytes(4, 'big') + dmsg.message_id.to_bytes(4, 'big') + b'OTRv4-MAC-KEY').digest()[:32]
        if not dmsg.verify_mac(mac_key):
            raise ValueError('MAC verification failed — message may be forged or replayed')
        rh_bytes = RatchetHeader(dmsg.ecdh_pub, dmsg.prev_chain_len, dmsg.message_id).encode()
        if len(dmsg.ciphertext) < 16:
            raise ValueError('Ciphertext too short for GCM tag')
        ct, tag = (dmsg.ciphertext[:-16], dmsg.ciphertext[-16:])
        _rid_before = self.ratchet.ratchet_id
        plaintext = self.ratchet.decrypt_message(rh_bytes, ct, dmsg.nonce, tag)
        _did_dh_ratchet = self.ratchet.ratchet_id != _rid_before
        if dmsg.kem_ct is not None:
            self.ratchet.process_incoming_kem_ct(dmsg.kem_ct)
        if dmsg.kem_ek is not None:
            self.ratchet.process_incoming_kem_ek(dmsg.kem_ek)
        if _did_dh_ratchet:
            self.ratchet.prepare_brace_rotation()
        payload_obj = OTRv4Payload.decode(plaintext)
        self._enh_route_tlvs(payload_obj.tlvs)
        return payload_obj.text.encode('utf-8')

    def _enh_dec_legacy(self, decoded: bytes) -> bytes:
        if not decoded or decoded[0] != OTRConstants.MESSAGE_TYPE_DATA:
            raise ValueError(f'Not a DATA message: 0x{(decoded[0] if decoded else 0):02x}')
        off = 1
        sid = decoded[off:off + OTRConstants.SESSION_ID_BYTES]
        off += OTRConstants.SESSION_ID_BYTES
        if not hmac.compare_digest(sid, self.session_id):
            raise ValueError('Session ID mismatch (legacy)')
        hdr = decoded[off:off + 64]
        off += 64
        non = decoded[off:off + 12]
        off += 12
        tag = decoded[off:off + 16]
        off += 16
        ct = decoded[off:]
        pt = self.ratchet.decrypt_message(hdr, ct, non, tag)
        null_pos = pt.find(b'\x00')
        return pt[:null_pos] if null_pos != -1 else pt

    def _enh_route_tlvs(self, tlvs: List['OTRv4TLV']) -> None:
        for tlv in tlvs:
            try:
                if tlv.type == OTRv4TLV.DISCONNECTED:
                    self._peer_disconnected = True
                    self.tracer.trace(self.peer, 'DISCONNECT', 'TLV', 'RECEIVED', 'peer ended session gracefully')
                    if self.session_state == SessionState.ENCRYPTED:
                        try:
                            self.transition_session(SessionState.FINISHED, 'peer sent DISCONNECTED TLV')
                        except StateMachineError:
                            pass
                elif tlv.type in OTRv4TLV.SMP_TYPES:
                    self._enh_handle_smp_tlv(tlv)
                elif tlv.type == OTRv4TLV.EXTRA_SYMMETRIC_KEY:
                    key = hashlib.sha3_512(self.session_id + b'OTRv4-EXTRA-SYM' + tlv.value).digest()[:32]
                    self._last_extra_sym_key = key
                    if self._extra_sym_key_cb:
                        try:
                            self._extra_sym_key_cb(self.peer, tlv.value, key)
                        except Exception:
                            pass
            except Exception as e:
                self.tracer.trace(self.peer, 'ERROR', 'TLV', f'0x{tlv.type:04x}', str(e)[:80])

    def _enh_handle_smp_tlv(self, tlv: 'OTRv4TLV') -> None:
        self.initialize_smp()
        if self._ping_refresh_cb is not None:
            try:
                self._ping_refresh_cb()
            except Exception:
                pass
        resp_bytes = None
        out_type = None
        try:
            if tlv.type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                phase = self.rust_smp.get_phase()
                if phase != 'IDLE':
                    local_fp = b''
                    try:
                        if self.dake_engine and self.dake_engine.client_profile:
                            cp = self.dake_engine.client_profile
                            if cp.identity_pub_bytes:
                                local_fp = cp.identity_pub_bytes
                            elif cp.identity_key:
                                local_fp = bytes(cp.identity_key.public_bytes())
                    except Exception:
                        pass
                    remote_fp = self._remote_long_term_pub_bytes or b''
                    if not local_fp or not remote_fp:
                        self.tracer.trace(self.peer, 'SMP', 'SMP1_RECEIVED', f'phase={phase}', 'race detected, no fingerprints to tie-break — aborting')
                        try:
                            self.rust_smp.abort()
                        except Exception:
                            pass
                        self._queued_smp_response = self.encrypt_with_tlvs('', [OTRv4TLV(OTRv4TLV.SMP_ABORT, b'')])
                        return
                    if local_fp < remote_fp:
                        self.tracer.trace(self.peer, 'SMP', 'SMP1_RECEIVED', f'phase={phase}', 'race detected, local_fp < remote_fp — keeping our role as initiator')
                        return
                    self.tracer.trace(self.peer, 'SMP', 'SMP1_RECEIVED', f'phase={phase}', 'race detected, local_fp > remote_fp — yielding initiator role')
                    try:
                        self.rust_smp.abort()
                    except Exception:
                        pass
                    self.rust_smp = None
                    self.initialize_smp()
                    if self.rust_smp is None or self.smp_vault is None:
                        raise RuntimeError('SMP race-recovery: re-init failed')
                    sid_recover = self.session_id or b''
                    ok = self.rust_smp.set_secret_from_vault(self.smp_vault, 'smp_secret', sid_recover, local_fp, remote_fp)
                    if not ok:
                        raise RuntimeError('SMP race-recovery: vault rebind failed')
                if not self.rust_smp.check_secret_set():
                    self.tracer.trace(self.peer, 'SMP', 'SMP1_RECEIVED', 'NO_SECRET', 'SMP1 received but no secret set — aborting')
                    self._queued_smp_response = self.encrypt_with_tlvs('', [OTRv4TLV(OTRv4TLV.SMP_ABORT, b'')])
                    return
                self._smp_progress_notify(1, 4, 'Challenge received — computing response (Rust ZKP, may take a moment)…', color='yellow')
                resp_bytes = self.rust_smp.process_smp1_generate_smp2(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_2
                self.smp_step = 2
                self._smp_progress_notify(2, 4, 'Response computed — sending…', role='responder')
            elif tlv.type == OTRv4TLV.SMP_MSG_2:
                self.smp_step = 2
                self._smp_progress_notify(2, 4, 'Response received — verifying ZKP…', role='initiator')
                resp_bytes = self.rust_smp.process_smp2_generate_smp3(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_3
                self.smp_step = 3
                self._smp_progress_notify(3, 4, 'Proof verified — sending confirmation…', role='initiator')
            elif tlv.type == OTRv4TLV.SMP_MSG_3:
                resp_bytes = self.rust_smp.process_smp3_generate_smp4(tlv.value)
                out_type = OTRv4TLV.SMP_MSG_4
                self.smp_step = 4
                self._smp_progress_notify(4, 4, 'Final step — sending verdict…', role='responder')
                if self.rust_smp.is_verified():
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(self.peer, 'SMP', 'VERIFIED', 'STATE_UPDATED', 'role=responder')
                    self._smp_progress_notify(4, 4, '🔵✅ SMP VERIFIED — identity confirmed!', role=None, color='blue', final=True)
                elif self.rust_smp.is_failed():
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(self.peer, 'SMP', 'FAILED', 'STATE_UPDATED', 'secrets did not match (responder)')
                    self._smp_progress_notify(0, 4, '🔴❌ SMP FAILED — secrets did not match', role=None, color='red', final=True)
            elif tlv.type == OTRv4TLV.SMP_MSG_4:
                verified = self.rust_smp.process_smp4(tlv.value)
                self.smp_step = 4
                if verified:
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(self.peer, 'SMP', 'VERIFIED', 'STATE_UPDATED', f'role={('initiator' if self.is_initiator else 'responder')}')
                    self._smp_progress_notify(4, 4, '🔵✅ SMP VERIFIED — identity confirmed!', role=None, color='blue', final=True)
                else:
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(self.peer, 'SMP', 'FAILED', 'STATE_UPDATED', 'secrets did not match')
                    self._smp_progress_notify(0, 4, '🔴❌ SMP FAILED — secrets did not match', role=None, color='red', final=True)
                return
            elif tlv.type == OTRv4TLV.SMP_ABORT:
                self.rust_smp.abort()
                self.auto_smp_started = False
                self.auto_smp_completed = False
                self.smp_step = 0
                self.tracer.trace(self.peer, 'SMP', 'ABORTED', 'PEER_ABORT', 'Remote peer aborted SMP')
                self._smp_progress_notify(0, 4, '⚠ SMP aborted by remote peer', role=None, color='red')
                return
        except Exception as e:
            self.tracer.trace(self.peer, 'ERROR', 'SMP', f'0x{tlv.type:04x}', str(e)[:120])
            if self.rust_smp:
                self.rust_smp.abort()
            self.auto_smp_started = False
            self.auto_smp_completed = False
            self.smp_step = 0
            self._smp_progress_notify(0, 4, f'❌ SMP error: {str(e)[:60]}', role=None, color='red')
            return
        if resp_bytes is not None and out_type is not None:
            try:
                self._queued_smp_response = self.encrypt_with_tlvs('', [OTRv4TLV(out_type, bytes(resp_bytes))])
            except Exception as e:
                self.tracer.trace(self.peer, 'ERROR', 'SMP_RESP', 'ENCRYPT', str(e)[:80])
    _SMP_STEP_LABELS = {1: 'Sending challenge', 2: 'Challenge sent → awaiting response', 3: 'Response received → sending verification', 4: 'Finalising'}

    def _smp_progress_notify(self, step: int, total: int, detail: str, role: Optional[str]=None, color: str='yellow', final: bool=False) -> None:
        now = time.time()
        if not hasattr(self, '_smp_step_times'):
            self._smp_step_times: list = []
        if step > 0 and (not self._smp_step_times or self._smp_step_times[-1][0] != step):
            self._smp_step_times.append((step, now))
        t0 = getattr(self, 'smp_start_time', 0) or now
        elapsed = max(0.0, now - t0)

        def _fmt(s: float) -> str:
            return f'{int(s // 60)}:{int(s % 60):02d}'
        elapsed_str = _fmt(elapsed)
        eta_str = ''
        if step > 0 and elapsed > 0 and (not final):
            avg_per_step = elapsed / step
            remaining = (total - step) * avg_per_step
            if remaining > 0:
                eta_str = f' · ETA ~{_fmt(remaining)}'
        SEGS = total if total > 0 else 4
        if step > 0 and total > 0:
            seg_w = 3
            filled = '█' * seg_w
            empty_s = '░' * seg_w
            partial = '▒' * seg_w
            bar_segs = []
            for i in range(SEGS):
                if i < step - 1:
                    bar_segs.append(filled)
                elif i == step - 1:
                    bar_segs.append(filled)
                else:
                    bar_segs.append(empty_s)
            bar_body = ' '.join(bar_segs)
            pct = int(step / total * 100)
            bar = f'[{bar_body}]'
            step_str = f'step {step}/{total}'
            if final:
                time_str = f' · ✓ {elapsed_str}'
            elif elapsed > 5:
                time_str = f' · {elapsed_str} elapsed{eta_str}'
            else:
                time_str = ''
            label = f'🔐 SMP {bar} {step_str}{time_str} · {detail}'
        else:
            label = f'🔐 SMP · {detail}'
        colored = colorize(label, color)
        if self._smp_notify_cb is not None:
            try:
                self._smp_notify_cb(colored)
            except Exception:
                pass
        elif self.tracer and self.tracer._emit_cb:
            self.tracer._emit_cb(colored)
        if final or step == 0:
            self._smp_step_times = []

    def send_disconnect(self) -> Optional[str]:
        return self.encrypt_with_tlvs('', [OTRv4TLV(OTRv4TLV.DISCONNECTED, b'')])

    def start_dake(self) -> Optional[str]:
        if not self._acquire_lock():
            raise RuntimeError('Failed to acquire lock for DAKE start')
        try:
            if self.session_state != SessionState.PLAINTEXT:
                raise StateMachineError(f'Cannot start DAKE in state: {self.session_state.name}')
            if self.dake_state != DAKEState.IDLE:
                raise StateMachineError(f'Cannot start DAKE: state is {self.dake_state.name}')
            if not self.is_initiator:
                raise StateMachineError('Only initiator can start DAKE')
            if self.dake_engine is None:
                raise RuntimeError('DAKE engine not initialized')
            self.transition_session(SessionState.DAKE_IN_PROGRESS, 'starting DAKE')
            dake1 = self.dake_engine.generate_dake1()
            self.dake_start_time = time.time()
            self.transition_dake(DAKEState.SENT_DAKE1, 'opportunistic start')
            self.tracer.trace(self.peer, 'OPPORTUNISTIC', 'IDLE', 'STARTED', 'first outgoing message')
            return dake1
        except Exception as e:
            self.transition_session(SessionState.FAILED, f'DAKE start failed: {e}')
            return None
        finally:
            self._release_lock()

    def terminate(self, reason: str='explicit termination'):
        if not self._acquire_lock():
            return
        try:
            if self.session_state in [SessionState.FINISHED, SessionState.FAILED]:
                return
            old_state = self.session_state
            self.transition_session(SessionState.FINISHED, reason)
            self._cleanup_resources()
            self.tracer.trace(self.peer, 'TERMINATE', old_state.name, 'FINISHED', reason)
        finally:
            self._release_lock()

    def _cleanup_resources(self):
        try:
            if self.ratchet:
                self.ratchet.zeroize()
                self.ratchet = None
            if self.root_key:
                self.root_key.zeroize()
                self.root_key = None
            if self.rust_smp is not None:
                self.rust_smp.abort()
                self.rust_smp = None
            if self.smp_vault is not None:
                self.smp_vault.clear()
                self.smp_vault = None
            self.auto_smp_secret = False
            self.pending_messages.clear()
            self.received_messages.clear()
        except Exception as e:
            self.tracer.trace(self.peer, 'ERROR', 'CLEANUP', 'FAILED', str(e))

    def _cleanup_failed_session(self):
        self._cleanup_resources()
        self.tracer.reset_peer(self.peer)

    def get_fingerprint(self) -> str:
        try:
            if self.remote_long_term_pub is not None:
                try:
                    pub_bytes = bytes(self.remote_long_term_pub)
                    fp_bytes = hashlib.sha3_512(pub_bytes).digest()
                    return fp_bytes.hex().upper()
                except Exception:
                    pass
            if self._remote_long_term_pub_bytes is not None:
                try:
                    fp_bytes = hashlib.sha3_512(self._remote_long_term_pub_bytes).digest()
                    return fp_bytes.hex().upper()
                except Exception:
                    pass
        except Exception:
            pass
        return ''

    def start_smp(self, secret: str, question: Optional[str]=None) -> Optional[str]:
        if not self._acquire_lock():
            raise RuntimeError('start_smp: could not acquire session lock (timeout)')
        try:
            if self.session_state != SessionState.ENCRYPTED:
                raise RuntimeError(f'start_smp: session not encrypted (state={self.session_state!r})')
            self.initialize_smp()
            if self.rust_smp is None:
                raise RuntimeError('start_smp: RustSMP is None after initialize_smp')
            phase = self.rust_smp.get_phase()
            if phase not in ('IDLE', 'FAILED'):
                raise RuntimeError(f'start_smp: SMP already in progress (phase={phase})')
            if secret:
                self.set_smp_secret(secret)
            if not self.rust_smp.check_secret_set():
                raise RuntimeError('start_smp: secret not set in Rust SMP engine — call set_smp_secret() first or pass secret explicitly')
            smp1_bytes = self.rust_smp.generate_smp1(question)
            self.smp_step = 1
            self._smp_progress_notify(1, 4, 'Challenge sent — awaiting response (Rust ZKP)…', color='yellow')
            return self.encrypt_with_tlvs('', [OTRv4TLV(OTRv4TLV.SMP_MSG_1, bytes(smp1_bytes))])
        except Exception as e:
            import traceback as _tb
            msg = f'start_smp: Error: {e}'
            self.logger.debug(msg + '\n' + _tb.format_exc())
            raise RuntimeError(f'SMP start failed: {e}') from e
        finally:
            self._release_lock()

    def process_smp_message(self, data: bytes) -> Optional[str]:
        if not self._acquire_lock():
            return None
        try:
            if len(data) < 4:
                return None
            self.initialize_smp()
            tlv_type = struct.unpack_from('!H', data, 0)[0]
            tlv_len = struct.unpack_from('!H', data, 2)[0]
            tlv_val = data[4:4 + tlv_len]
            out_type = None
            resp = None
            if tlv_type in (OTRv4TLV.SMP_MSG_1, OTRv4TLV.SMP_MSG_1Q):
                resp = self.rust_smp.process_smp1_generate_smp2(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_2
            elif tlv_type == OTRv4TLV.SMP_MSG_2:
                resp = self.rust_smp.process_smp2_generate_smp3(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_3
            elif tlv_type == OTRv4TLV.SMP_MSG_3:
                resp = self.rust_smp.process_smp3_generate_smp4(tlv_val)
                out_type = OTRv4TLV.SMP_MSG_4
                if self.rust_smp.is_verified():
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                elif self.rust_smp.is_failed():
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
            elif tlv_type == OTRv4TLV.SMP_MSG_4:
                verified = self.rust_smp.process_smp4(tlv_val)
                if verified:
                    self.auto_smp_completed = True
                    self.auto_smp_started = False
                    self.security_level = UIConstants.SecurityLevel.SMP_VERIFIED
                    self.tracer.trace(self.peer, 'SMP', 'VERIFIED', 'STATE_UPDATED', 'role=initiator')
                    self._smp_progress_notify(4, 4, '🔵✅ SMP VERIFIED — identity confirmed!', role=None, color='blue', final=True)
                else:
                    self.auto_smp_started = False
                    self.auto_smp_completed = False
                    self.smp_step = 0
                    self.tracer.trace(self.peer, 'SMP', 'FAILED', 'STATE_UPDATED', 'secrets did not match (initiator)')
                    self._smp_progress_notify(0, 4, '🔴❌ SMP FAILED — secrets did not match', role=None, color='red', final=True)
                return None
            elif tlv_type == OTRv4TLV.SMP_ABORT:
                self.rust_smp.abort()
                return None
            if resp is not None and out_type is not None:
                return self.encrypt_with_tlvs('', [OTRv4TLV(out_type, bytes(resp))])
            return None
        except Exception as e:
            import traceback as _tb
            self.logger.debug(f'process_smp_message: {e}\n{_tb.format_exc()}')
            return None
        finally:
            self._release_lock()

    def get_smp_status(self) -> Dict[str, Any]:
        if not self._acquire_lock():
            return {'state': 'NONE', 'verified': False, 'failed': False, 'progress': '0/4', 'can_start_smp': False, 'secret_set': False}
        try:
            if self.rust_smp is None:
                return {'state': 'NONE', 'verified': False, 'failed': False, 'progress': '0/4', 'has_question': False, 'question': '', 'can_start_smp': self.session_state == SessionState.ENCRYPTED, 'can_retry': False, 'retry_count': 0, 'expired': False, 'secret_set': False}
            phase = self.rust_smp.get_phase()
            verified = self.rust_smp.is_verified()
            failed = phase == 'FAILED'
            step_map = {'IDLE': 0, 'AWAITING_MSG2': 1, 'AWAITING_MSG3': 2, 'AWAITING_MSG4': 3, 'VERIFIED': 4, 'FAILED': 0}
            step = step_map.get(phase, 0)
            return {'state': phase, 'verified': verified or self.auto_smp_completed, 'failed': failed, 'failure_reason': '' if not failed else 'secrets did not match', 'progress': f'{step}/4', 'has_question': False, 'question': '', 'can_start_smp': phase in ('IDLE', 'FAILED') and self.session_state == SessionState.ENCRYPTED, 'can_retry': failed, 'retry_count': 0, 'expired': False, 'secret_set': self.rust_smp.check_secret_set()}
        except Exception as e:
            self.logger.debug(f'get_smp_status: {e}')
            return {'state': 'NONE', 'verified': False, 'failed': False, 'progress': '0/4', 'can_start_smp': self.session_state == SessionState.ENCRYPTED}
        finally:
            self._release_lock()

    def get_smp_progress(self) -> Tuple[int, int]:
        if self.rust_smp is None:
            return (0, 4)
        phase = self.rust_smp.get_phase()
        step_map = {'IDLE': 0, 'AWAITING_MSG2': 1, 'AWAITING_MSG3': 2, 'AWAITING_MSG4': 3, 'VERIFIED': 4, 'FAILED': 0}
        return (step_map.get(phase, 0), 4)

    def set_smp_secret(self, secret: str):
        _MIN_LEN = 8
        if len(secret) < _MIN_LEN:
            raise ValueError(f'SMP secret must be at least {_MIN_LEN} characters.')
        if not self._acquire_lock():
            return
        try:
            if self.rust_smp is not None:
                phase = self.rust_smp.get_phase()
                if phase not in ('IDLE', 'FAILED', 'VERIFIED', 'ABORTED'):
                    raise RuntimeError(f'Cannot rebind SMP secret while SMP is active (current phase: {phase}). Abort the current run first.')
            self.initialize_smp()
            if self.rust_smp is None or self.smp_vault is None:
                raise RuntimeError('Rust SMP engine not initialized')
            sid = self.session_id or b''
            local_fp = b''
            try:
                if self.dake_engine and self.dake_engine.client_profile:
                    cp = self.dake_engine.client_profile
                    if cp.identity_pub_bytes:
                        local_fp = cp.identity_pub_bytes
                    elif cp.identity_key:
                        local_fp = bytes(cp.identity_key.public_bytes())
            except Exception:
                pass
            remote_fp = self._remote_long_term_pub_bytes or b''
            raw = bytearray(secret.encode('utf-8'))
            try:
                self.smp_vault.store('smp_secret', bytes(raw))
                ok = self.rust_smp.set_secret_from_vault(self.smp_vault, 'smp_secret', sid, local_fp, remote_fp)
                if not ok:
                    raise RuntimeError('Vault key not found after store — internal error')
            finally:
                for i in range(len(raw)):
                    raw[i] = 0
                del raw
            if not self.rust_smp.check_secret_set():
                raise RuntimeError('Rust SMP secret not stored after set_secret_from_vault')
            self.auto_smp_secret = True
        finally:
            self._release_lock()

    def can_start_smp(self) -> bool:
        if not self._acquire_lock():
            return False
        try:
            if self.session_state != SessionState.ENCRYPTED:
                return False
            if self.rust_smp is None:
                return True
            phase = self.rust_smp.get_phase()
            return phase in ('IDLE', 'FAILED')
        finally:
            self._release_lock()

    def get_state_summary(self) -> Dict[str, Any]:
        if not self._acquire_lock():
            return {}
        try:
            smp_status = self.get_smp_status() if hasattr(self, 'get_smp_status') else {}
            return {'peer': self.peer, 'session_state': self.session_state.name, 'dake_state': self.dake_state.name, 'smp_state': smp_status.get('state', 'NONE'), 'security_level': self.security_level.name, 'is_initiator': self.is_initiator, 'session_id': self.session_id.hex()[:16] if self.session_id else None, 'created': time.ctime(self.created), 'last_activity': time.ctime(self.last_activity), 'queued_messages': len(self.pending_messages), 'has_ratchet': self.ratchet is not None, 'has_smp': self.rust_smp is not None, 'is_encrypted': self.session_state == SessionState.ENCRYPTED, 'is_active': self.session_state not in [SessionState.FINISHED, SessionState.FAILED], 'fingerprint': self.get_fingerprint(), 'smp_verified': smp_status.get('verified', False)}
        finally:
            self._release_lock()

    def is_encrypted(self) -> bool:
        return self.session_state == SessionState.ENCRYPTED

    def can_send_message(self) -> bool:
        return self.session_state in [SessionState.ENCRYPTED, SessionState.PLAINTEXT]

    def should_start_dake(self) -> bool:
        return self.session_state == SessionState.PLAINTEXT and self.dake_state == DAKEState.IDLE and self.is_initiator

    def __del__(self):
        try:
            if hasattr(self, 'session_state') and self.session_state != SessionState.FINISHED:
                self.terminate('session destroyed')
        except Exception:
            pass

class SessionManager:

    def __init__(self, config: Optional[OTRConfig]=None, logger: Optional[OTRLogger]=None):
        self.config = config or OTRConfig(test_mode=True)
        self.logger = logger or NullLogger()
        self.trust_db = TrustDatabase(self.config.trust_db_path)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        self.key_storage = SecureKeyStorage(self.config.key_storage_path)
        self.client_profile = ClientProfile()
        self.lock = threading.RLock()
        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.pending_dakes: Dict[str, RustDAKEAdapter] = {}
        self._disconnect_callbacks: list = []
        if not self.config.test_mode:
            self._store_identity()

    def _acquire_lock(self, timeout: float=5.0) -> bool:
        try:
            return self.lock.acquire(timeout=timeout)
        except Exception:
            return False

    def _release_lock(self):
        try:
            self.lock.release()
        except Exception:
            pass

    def _store_identity(self):
        try:
            profile_bytes = self.client_profile.encode()
            self.key_storage.store_key('profile', 'client', profile_bytes)
        except Exception as e:
            if DEBUG_MODE:
                safe_print(f'Warning: Could not store profile: {e}')

    def get_fingerprint(self) -> str:
        return self.client_profile.get_fingerprint()

    def start_session(self, peer: str) -> Optional[str]:
        if not self._acquire_lock():
            return None
        try:
            if peer in self.sessions:
                return None
            dake = RustDAKEAdapter(client_profile=self.client_profile, explicit_initiator=True, logger=self.logger)
            try:
                dake1 = dake.generate_dake1()
                self.pending_dakes[peer] = dake
                return dake1
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to start session: {e}')
                return None
        finally:
            self._release_lock()

    def handle_dake1(self, peer: str, dake1_msg: str) -> Optional[str]:
        if not self._acquire_lock():
            return None
        try:
            dake = RustDAKEAdapter(client_profile=self.client_profile, explicit_initiator=False, logger=self.logger)
            try:
                success = dake.process_dake1(dake1_msg)
                if success:
                    dake2 = dake.generate_dake2()
                    self.pending_dakes[peer] = dake
                    return dake2
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to handle DAKE1: {e}')
            return None
        finally:
            self._release_lock()

    def handle_dake2(self, peer: str, dake2_msg: str) -> Optional[str]:
        if not self._acquire_lock():
            return None
        try:
            if peer not in self.pending_dakes:
                return None
            dake = self.pending_dakes[peer]
            try:
                success = dake.process_dake2(dake2_msg)
                if success:
                    dake3 = dake.generate_dake3()
                    session = EnhancedOTRSession(peer=peer, is_initiator=True, tracer=OTRTracer(enabled=DEBUG_MODE), logger=self.logger)
                    if getattr(self, 'smp_notify_factory', None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, 'ping_refresh_cb', None):
                        session._ping_refresh_cb = self.ping_refresh_cb
                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get('session_id')
                        session.root_key = session_keys.get('root_key')
                        session.remote_long_term_pub = session_keys.get('peer_long_term_pub')
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]
                    return dake3
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to handle DAKE2: {e}')
                del self.pending_dakes[peer]
            return None
        finally:
            self._release_lock()

    def handle_dake3(self, peer: str, dake3_msg: str) -> bool:
        if not self._acquire_lock():
            return False
        try:
            if peer not in self.pending_dakes:
                return False
            dake = self.pending_dakes[peer]
            try:
                success = dake.process_dake3(dake3_msg)
                if success:
                    session = EnhancedOTRSession(peer=peer, is_initiator=False, tracer=OTRTracer(enabled=DEBUG_MODE), logger=self.logger)
                    if getattr(self, 'smp_notify_factory', None):
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    if getattr(self, 'ping_refresh_cb', None):
                        session._ping_refresh_cb = self.ping_refresh_cb
                    session_keys = dake.get_session_keys()
                    if session_keys:
                        session.session_id = session_keys.get('session_id')
                        session.root_key = session_keys.get('root_key')
                        session.remote_long_term_pub = session_keys.get('peer_long_term_pub')
                    self.sessions[peer] = session
                    del self.pending_dakes[peer]
                    return True
            except Exception as e:
                if DEBUG_MODE:
                    safe_print(f'Failed to handle DAKE3: {e}')
                del self.pending_dakes[peer]
            return False
        finally:
            self._release_lock()

    def has_session(self, peer: str) -> bool:
        return peer in self.sessions

    def get_session(self, peer: str) -> Optional[EnhancedOTRSession]:
        return self.sessions.get(peer)

    def get_security_level(self, peer: str) -> UIConstants.SecurityLevel:
        if peer not in self.sessions:
            return UIConstants.SecurityLevel.PLAINTEXT
        return self.sessions[peer].security_level

    def encrypt_message(self, peer: str, plaintext: str) -> Optional[str]:
        if peer not in self.sessions:
            return None
        try:
            session = self.sessions[peer]
            return session.encrypt_message(plaintext)
        except Exception as e:
            if DEBUG_MODE:
                safe_print(f'Encryption failed: {e}')
            return None

    def decrypt_message(self, peer: str, encrypted_msg: str) -> bytes:
        if peer not in self.sessions:
            raise ValueError(f'No session with {peer}')
        try:
            session = self.sessions[peer]
            plaintext = session.decrypt_message(encrypted_msg)
            queued = getattr(session, '_queued_smp_response', None)
            if queued:
                session._queued_smp_response = None
                return queued.encode('utf-8') if isinstance(queued, str) else queued
            return plaintext
        except Exception as e:
            raise EncryptionError(f'Decryption failed: {e}', session=self.sessions.get(peer))

    def get_session_info(self, peer: str) -> Dict[str, Any]:
        if peer not in self.sessions:
            return {}
        session = self.sessions[peer]
        return session.get_state_summary() if hasattr(session, 'get_state_summary') else {}

    def display_fingerprints(self, peer: str) -> str:
        if peer not in self.sessions:
            return ''
        session = self.sessions[peer]
        local_fp = self.get_fingerprint()
        remote_fp = session.get_fingerprint() if hasattr(session, 'get_fingerprint') else ''
        return f'Local: {local_fp}\nRemote: {remote_fp}'

    def set_smp_secret(self, peer: str, secret: str) -> bool:
        try:
            self.smp_storage.set_secret(peer, secret)
            self.logger.debug(f'set_smp_secret: Stored in smp_storage for {peer}')
        except Exception as e:
            self.logger.debug(f'set_smp_secret: Error storing in smp_storage: {e}')
        if peer in self.sessions:
            try:
                session = self.sessions[peer]
                if hasattr(session, 'set_smp_secret'):
                    session.set_smp_secret(secret)
                    self.logger.debug(f'set_smp_secret: Set in session for {peer}')
            except Exception as e:
                self.logger.debug(f'set_smp_secret: Error setting in session: {e}')
        return True

    def start_smp(self, peer: str, secret: str, question: Optional[str]=None) -> Optional[str]:
        self.logger.debug(f'start_smp: Called for {peer} with secret length {len(secret)}')
        if peer not in self.sessions:
            self.logger.debug(f'start_smp: No session for {peer}')
            return None
        session = self.sessions[peer]
        if hasattr(session, 'start_smp'):
            self.logger.debug(f'start_smp: Calling session.start_smp for {peer}')
            result = session.start_smp(secret, question)
            self.logger.debug(f'start_smp: session.start_smp returned: {result is not None}')
            return result
        self.logger.debug(f'start_smp: Session has no start_smp method')
        return None

    def process_smp_message(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        if peer not in self.sessions:
            return None
        try:
            session = self.sessions[peer]
            auto_secret = self.smp_storage.get_secret(peer)
            if auto_secret and hasattr(session, 'set_smp_secret'):
                session.set_smp_secret(auto_secret)
            if hasattr(session, 'process_smp_message'):
                return session.process_smp_message(smp_tlv)
        except Exception as e:
            if DEBUG_MODE:
                safe_print(f'SMP message processing failed: {e}')
        return None

    def get_smp_status(self, peer: str) -> Dict[str, Any]:
        if peer not in self.sessions:
            self.logger.debug(f'get_smp_status: No session for {peer}, returning NONE')
            return {'state': 'NONE', 'verified': False, 'failed': False, 'progress': '0/4', 'is_initiator': False, 'can_start_smp': True, 'should_auto_start_smp': False, 'has_question': False, 'question': '', 'auto_smp_secret': bool(self.smp_storage.get_secret(peer)), 'auto_smp_started': False, 'auto_smp_completed': False, 'can_retry': False, 'retry_count': 0, 'expired': False}
        session = self.sessions[peer]
        if hasattr(session, 'get_smp_status'):
            status = session.get_smp_status()
            if 'is_initiator' not in status:
                status['is_initiator'] = getattr(session, 'is_initiator', False)
            status['auto_smp_secret'] = bool(self.smp_storage.get_secret(peer))
            status['auto_smp_started'] = getattr(session, 'auto_smp_started', False)
            status['auto_smp_completed'] = getattr(session, 'auto_smp_completed', False)
            status['should_auto_start_smp'] = False
            status['can_start_smp'] = status.get('can_start_smp', session.can_start_smp() if hasattr(session, 'can_start_smp') else False)
            self.logger.debug(f'get_smp_status: Returning from session: {status}')
            return status
        return {'state': 'NONE', 'verified': False, 'failed': False, 'progress': '0/4', 'is_initiator': getattr(session, 'is_initiator', False), 'can_start_smp': hasattr(session, 'can_start_smp') and session.can_start_smp(), 'should_auto_start_smp': False, 'has_question': False, 'question': '', 'auto_smp_secret': bool(self.smp_storage.get_secret(peer)), 'auto_smp_started': False, 'auto_smp_completed': False, 'can_retry': False, 'retry_count': 0, 'expired': False}

    def get_smp_progress(self, peer: str) -> Tuple[int, int]:
        if peer not in self.sessions:
            return (0, 4)
        session = self.sessions[peer]
        if hasattr(session, 'get_smp_progress'):
            return session.get_smp_progress()
        return (0, 4)

    def get_smp_question(self, peer: str) -> str:
        if peer not in self.sessions:
            return ''
        session = self.sessions[peer]
        if hasattr(session, 'get_smp_question'):
            return session.get_smp_question()
        return ''

    def is_smp_verified(self, peer: str) -> bool:
        if peer not in self.sessions:
            return False
        session = self.sessions[peer]
        if hasattr(session, 'is_smp_verified'):
            return session.is_smp_verified()
        status = self.get_smp_status(peer)
        return status.get('verified', False)

    def abort_smp(self, peer: str) -> bool:
        if peer not in self.sessions:
            return False
        session = self.sessions[peer]
        if hasattr(session, 'abort_smp'):
            return session.abort_smp()
        return False

    def process_auto_smp(self, peer: str, smp_tlv: bytes) -> Optional[str]:
        if peer not in self.sessions:
            return None
        try:
            session = self.sessions[peer]
            if hasattr(session, 'process_auto_smp_response'):
                return session.process_auto_smp_response(smp_tlv)
        except Exception as e:
            if DEBUG_MODE:
                safe_print(f'Auto-SMP processing failed: {e}')
        return None

    def check_and_start_auto_smp(self, peer: str) -> Optional[str]:
        return None

    def end_session(self, peer: str):
        if not self._acquire_lock():
            return
        try:
            if peer in self.sessions:
                session = self.sessions[peer]
                try:
                    if hasattr(session, 'send_disconnect'):
                        encrypted = session.send_disconnect()
                        if encrypted:
                            self._disconnect_callbacks.append((peer, encrypted))
                except Exception:
                    pass
                session.terminate('session ended')
                del self.sessions[peer]
                self.logger.debug(f'end_session: Session ended for {peer}')
        finally:
            self._release_lock()

    def zeroize_all(self):
        if not self._acquire_lock():
            return
        try:
            for peer, session in list(self.sessions.items()):
                try:
                    session.terminate('zeroize all')
                except Exception:
                    pass
            self.sessions.clear()
            self.pending_dakes.clear()
            self.logger.debug('zeroize_all: All sessions zeroized')
        finally:
            self._release_lock()

    def get_peer_fingerprint(self, peer: str) -> Optional[str]:
        if peer not in self.sessions:
            return None
        return self.sessions[peer].get_fingerprint()

    def is_peer_trusted(self, peer: str) -> bool:
        fingerprint = self.get_peer_fingerprint(peer)
        if not fingerprint:
            return False
        return self.trust_db.is_trusted(peer, fingerprint)

    def trust_fingerprint(self, peer: str, fingerprint: str) -> bool:
        return self.trust_db.add_trust(peer, fingerprint)

class EnhancedSessionManager:

    def __init__(self, config: Optional[OTRConfig]=None, tracer: Optional[OTRTracer]=None, logger: Optional[OTRLogger]=None):
        self.config = config or OTRConfig(test_mode=True)
        self.tracer = tracer or OTRTracer(enabled=True)
        self.logger = logger or NullLogger()
        self.trust_db = TrustDatabase(self.config.trust_db_path)
        self.smp_storage = SMPAutoRespondStorage(self.config.smp_secrets_path)
        self.key_storage = SecureKeyStorage(self.config.key_storage_path)
        self.client_profile = ClientProfile()
        self.sessions: Dict[str, EnhancedOTRSession] = {}
        self.dake_engines: Dict[str, RustDAKEAdapter] = {}
        self.lock = threading.RLock()
        self.smp_notify_factory = None
        if not self.config.test_mode:
            self._store_identity()
        self.tracer.trace('SYSTEM', 'MANAGER', None, 'READY', 'session manager initialized')

    def _store_identity(self):
        try:
            self.tracer.trace('SYSTEM', 'STORAGE', None, 'READY', 'identity stored (Phase 5.3b: no private material persisted)')
        except Exception as e:
            self.tracer.trace('SYSTEM', 'ERROR', 'STORAGE', 'FAILED', str(e))

    def get_or_create_session(self, peer: str, is_initiator: bool=False) -> EnhancedOTRSession:
        with self.lock:
            if peer in self.sessions:
                session = self.sessions[peer]
                if session.is_initiator != is_initiator:
                    self.tracer.trace(peer, 'ROLE', 'INITIATOR' if session.is_initiator else 'RESPONDER', 'INITIATOR' if is_initiator else 'RESPONDER', 'role updated')
                    session.is_initiator = is_initiator
                if session._smp_notify_cb is None and self.smp_notify_factory is not None:
                    try:
                        session._smp_notify_cb = self.smp_notify_factory(peer)
                    except Exception:
                        pass
                if session._ping_refresh_cb is None and getattr(self, 'ping_refresh_cb', None):
                    session._ping_refresh_cb = self.ping_refresh_cb
                return session
            session = EnhancedOTRSession(peer=peer, is_initiator=is_initiator, tracer=self.tracer, logger=self.logger)
            if self.smp_notify_factory is not None:
                try:
                    session._smp_notify_cb = self.smp_notify_factory(peer)
                except Exception:
                    pass
            if getattr(self, 'ping_refresh_cb', None):
                session._ping_refresh_cb = self.ping_refresh_cb
            self.sessions[peer] = session
            self.tracer.trace(peer, 'SESSION', None, 'CREATED', f'new session (role: {('initiator' if is_initiator else 'responder')})')
            return session

    def get_session(self, peer: str) -> Optional[EnhancedOTRSession]:
        with self.lock:
            return self.sessions.get(peer)

    def has_session(self, peer: str) -> bool:
        with self.lock:
            return peer in self.sessions

    def has_encrypted_session(self, peer: str) -> bool:
        with self.lock:
            if peer not in self.sessions:
                return False
            session = self.sessions[peer]
            return session.is_encrypted()

    def handle_outgoing_message(self, peer: str, message: str) -> Tuple[Optional[str], bool]:
        with self.lock:
            session = self.get_or_create_session(peer, is_initiator=True)
            if session.is_encrypted():
                try:
                    encrypted = session.encrypt_message(message)
                    self.tracer.trace(peer, 'SEND', 'ENCRYPTED', 'READY', f'message encrypted ({len(message)} chars)')
                    return (encrypted, True)
                except Exception as e:
                    self.tracer.trace(peer, 'ERROR', 'ENCRYPT', 'FAILED', str(e))
                    return (None, False)
            elif session.session_state == SessionState.PLAINTEXT:
                if session.should_start_dake():
                    self.tracer.trace(peer, 'OPPORTUNISTIC', 'IDLE', 'STARTING', f'first message to {peer}')
                    dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=True)
                    self.dake_engines[peer] = dake_engine
                    dake1 = session.start_dake()
                    if dake1:
                        session.queue_outgoing_message(message)
                        self.tracer.trace(peer, 'QUEUE', 'MESSAGE', 'QUEUED', f'message queued for later encryption')
                        return (dake1, True)
                    else:
                        self.tracer.trace(peer, 'ERROR', 'DAKE', 'FAILED', 'could not start DAKE')
                        return (None, False)
                else:
                    self.tracer.trace(peer, 'ERROR', 'SEND', 'BLOCKED', f'plaintext session but DAKE not started')
                    return (None, False)
            elif session.session_state == SessionState.DAKE_IN_PROGRESS:
                session.queue_outgoing_message(message)
                self.tracer.trace(peer, 'QUEUE', 'MESSAGE', 'QUEUED', f'DAKE in progress, message queued')
                return (None, False)
            else:
                self.tracer.trace(peer, 'ERROR', 'SEND', 'BLOCKED', f'session in state: {session.session_state.name}')
                return (None, False)

    def handle_incoming_message(self, peer: str, message: str) -> Optional[bytes]:
        with self.lock:
            if message.startswith('?OTRv4 '):
                return self._handle_otr_message(peer, message)
            session = self.get_session(peer)
            if session and session.is_encrypted():
                self.tracer.trace(peer, 'ERROR', 'RECEIVE', 'PLAINTEXT', f'encrypted session but received plaintext - possible downgrade attack')
                return None
            return message.encode('utf-8') if isinstance(message, str) else message

    def _handle_otr_message(self, peer: str, message: str) -> Optional[bytes]:
        with self.lock:
            try:
                payload = message[7:].strip()
                try:
                    decoded = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
                except Exception:
                    decoded = base64.b64decode(payload + '=' * (-len(payload) % 4))
                if len(decoded) < 1:
                    return None
                if len(decoded) >= 3 and decoded[0] == 0 and (decoded[1] == 4) and (decoded[2] == OTRv4DataMessage.TYPE):
                    return self._handle_data_message(peer, message)
                msg_type = decoded[0]
                if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                    return self._handle_dake1(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                    return self._handle_dake2(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                    return self._handle_dake3(peer, message)
                elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                    return self._handle_data_message(peer, message)
                else:
                    self.tracer.trace(peer, 'ERROR', 'PARSE', 'UNKNOWN', f'unknown message type: {msg_type}')
                    return None
            except Exception as e:
                self.tracer.trace(peer, 'ERROR', 'PARSE', 'FAILED', str(e))
                return None

    def _handle_dake1(self, peer: str, dake1_msg: str) -> Optional[bytes]:
        if len(self.sessions) >= getattr(self, 'MAX_SESSIONS', 50):
            self.debug(f'session limit reached — dropping DAKE1 from {peer}')
            return None
        'Handle incoming DAKE1 message'
        with self.lock:
            session = self.get_or_create_session(peer, is_initiator=False)
            if session.session_state != SessionState.PLAINTEXT:
                self.tracer.trace(peer, 'ERROR', 'DAKE1', 'REJECTED', f'session in state: {session.session_state.name}')
                return None
            dake_engine = session.initialize_dake(self.client_profile, explicit_initiator=False)
            self.dake_engines[peer] = dake_engine
            success = dake_engine.process_dake1(dake1_msg)
            if not success:
                return None
            dake2 = dake_engine.generate_dake2()
            if dake2:
                self.tracer.trace(peer, 'DAKE', 'DAKE1_PROCESSED', 'DAKE2_READY', '')
                return dake2.encode('utf-8')
            return None

    def _handle_dake2(self, peer: str, dake2_msg: str) -> Optional[bytes]:
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, 'ERROR', 'DAKE2', 'NO_SESSION', '')
                return None
            session = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, 'ERROR', 'DAKE2', 'NO_ENGINE', '')
                return None
            try:
                if not dake_engine.process_dake2(dake2_msg):
                    self.tracer.trace(peer, 'ERROR', 'DAKE2', 'PROCESS_FAILED', '')
                    return None
                dake3_msg = dake_engine.generate_dake3()
                if not dake3_msg:
                    self.tracer.trace(peer, 'ERROR', 'DAKE3', 'GEN_FAILED', '')
                    return None
                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, 'ERROR', 'DAKE2', 'NO_KEYS', '')
                    return None
                session.session_id = session_keys.get('session_id') or secrets.token_bytes(32)
                session.root_key = session_keys.get('root_key')
                session._dake_chain_key_send = session_keys.get('chain_key_send')
                session._dake_chain_key_recv = session_keys.get('chain_key_recv')
                session._dake_brace_key = session_keys.get('brace_key')
                session._dake_output = session_keys.get('_dake_output')
                pub_key_data = session_keys.get('peer_long_term_pub')
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data
                    session.remote_long_term_pub = None
                    self.tracer.trace(peer, 'KEY', 'PUBKEY', 'PARSED', 'Successfully parsed remote pubkey (bytes)')
                elif pub_key_data is not None:
                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, 'ERROR', 'PUBKEY', 'BYTES_FAILED', str(e))
                        session._remote_long_term_pub_bytes = None
                self._establish_session(session, peer, 'DAKE2→DAKE3 initiator')
                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, 'DAKE', 'COMPLETE', 'INITIATOR_ENCRYPTED', '')
                return dake3_msg.encode('utf-8')
            except Exception as exc:
                self.tracer.trace(peer, 'ERROR', 'DAKE2', 'EXCEPTION', str(exc))
                pass
                return None

    def _handle_dake3(self, peer: str, dake3_msg: str) -> Optional[bytes]:
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, 'ERROR', 'DAKE3', 'NO_SESSION', '')
                return None
            session = self.sessions[peer]
            dake_engine = self.dake_engines.get(peer)
            if dake_engine is None:
                self.tracer.trace(peer, 'ERROR', 'DAKE3', 'NO_ENGINE', '')
                return None
            try:
                if not dake_engine.process_dake3(dake3_msg):
                    self.tracer.trace(peer, 'ERROR', 'DAKE3', 'PROCESS_FAILED', '')
                    return None
                session_keys = dake_engine.get_session_keys()
                if not session_keys:
                    self.tracer.trace(peer, 'ERROR', 'DAKE3', 'NO_KEYS', '')
                    return None
                session.session_id = session_keys.get('session_id') or secrets.token_bytes(32)
                session.root_key = session_keys.get('root_key')
                session._dake_chain_key_send = session_keys.get('chain_key_send')
                session._dake_chain_key_recv = session_keys.get('chain_key_recv')
                session._dake_brace_key = session_keys.get('brace_key')
                session._dake_output = session_keys.get('_dake_output')
                pub_key_data = session_keys.get('peer_long_term_pub')
                if isinstance(pub_key_data, bytes):
                    session._remote_long_term_pub_bytes = pub_key_data
                    session.remote_long_term_pub = None
                    self.tracer.trace(peer, 'KEY', 'PUBKEY', 'PARSED', 'Successfully parsed remote pubkey (bytes)')
                elif pub_key_data is not None:
                    session.remote_long_term_pub = pub_key_data
                    try:
                        session._remote_long_term_pub_bytes = bytes(pub_key_data)
                    except Exception as e:
                        self.tracer.trace(peer, 'ERROR', 'PUBKEY', 'BYTES_FAILED', str(e))
                        session._remote_long_term_pub_bytes = None
                self._establish_session(session, peer, 'DAKE3 responder')
                self.dake_engines.pop(peer, None)
                self.tracer.trace(peer, 'DAKE', 'COMPLETE', 'RESPONDER_ENCRYPTED', '')
                return None
            except Exception as exc:
                self.tracer.trace(peer, 'ERROR', 'DAKE3', 'EXCEPTION', str(exc))
                pass
                return None

    def _establish_session(self, session: 'EnhancedOTRSession', peer: str, reason: str) -> None:
        if session.session_state == SessionState.PLAINTEXT:
            try:
                session.transition_session(SessionState.DAKE_IN_PROGRESS, f'{reason}: fast-path to DAKE_IN_PROGRESS')
            except StateMachineError:
                pass
        if session.session_state == SessionState.DAKE_IN_PROGRESS:
            try:
                session.transition_session(SessionState.ENCRYPTED, reason)
            except StateMachineError as e:
                self.tracer.trace(peer, 'ERROR', 'ESTABLISH', 'STATE_ERR', str(e))
                session.session_state = SessionState.ENCRYPTED
                session.security_level = UIConstants.SecurityLevel.ENCRYPTED
        elif session.session_state == SessionState.ENCRYPTED:
            pass
        else:
            session.session_state = SessionState.ENCRYPTED
            session.security_level = UIConstants.SecurityLevel.ENCRYPTED
        if session.ratchet is None:
            try:
                session._initialize_ratchet()
            except Exception as e:
                self.tracer.trace(peer, 'ERROR', 'RATCHET', 'INIT_FAILED', str(e))

    def _handle_data_message(self, peer: str, data_msg: str) -> Optional[bytes]:
        with self.lock:
            if peer not in self.sessions:
                self.tracer.trace(peer, 'ERROR', 'DATA', 'NO_SESSION', '')
                return None
            session = self.sessions[peer]
            if not session.is_encrypted():
                self.tracer.trace(peer, 'ERROR', 'DATA', 'NOT_ENCRYPTED', session.session_state.name)
                return None
            try:
                auto_secret = self.smp_storage.get_secret(peer)
                if auto_secret and hasattr(session, 'set_smp_secret'):
                    needs_bind = session.rust_smp is None or not session.rust_smp.check_secret_set()
                    if needs_bind:
                        session.set_smp_secret(auto_secret)
                        auto_secret = None
            except Exception as _se:
                self.logger.debug(f'_handle_data_message: smp_storage pre-load failed for {peer}: {_se}')
            try:
                text_bytes = session.decrypt_message(data_msg)
                self.tracer.trace(peer, 'RECEIVE', 'ENCRYPTED', 'DECRYPTED', f'len={len(text_bytes)}')
                queued = session._queued_smp_response
                session._queued_smp_response = None
                if queued:
                    return queued.encode('utf-8') if isinstance(queued, str) else queued
                return text_bytes
            except Exception as e:
                self.tracer.trace(peer, 'ERROR', 'DECRYPT', 'FAILED', str(e))
                return None

    def _handle_smp_message(self, peer: str, smp_tlv: bytes) -> Optional[bytes]:
        with self.lock:
            if peer not in self.sessions:
                return None
            session = self.sessions[peer]
            if not session.is_encrypted():
                self.tracer.trace(peer, 'ERROR', 'SMP', 'NOT_ENCRYPTED', '')
                return None
            if session.rust_smp is None:
                session.initialize_smp()
            try:
                auto_secret = self.smp_storage.get_secret(peer)
                if auto_secret and hasattr(session, 'set_smp_secret'):
                    if not session.rust_smp.check_secret_set():
                        session.set_smp_secret(auto_secret)
                        auto_secret = None
            except Exception as _se:
                self.logger.debug(f'_handle_smp_message: smp_storage pre-load failed for {peer}: {_se}')
            if len(smp_tlv) < 4:
                return None
            tlv_type = struct.unpack_from('!H', smp_tlv, 0)[0]
            tlv_len = struct.unpack_from('!H', smp_tlv, 2)[0]
            tlv_value = smp_tlv[4:4 + tlv_len]
            tlv_obj = OTRv4TLV(tlv_type, tlv_value)
            session._enh_handle_smp_tlv(tlv_obj)
            self.tracer.trace(peer, 'SMP', 'RECEIVED', 'ROUTED', f'type=0x{tlv_type:04x}')
            resp = session._queued_smp_response
            session._queued_smp_response = None
            return resp

    def get_session_state(self, peer: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if peer not in self.sessions:
                return None
            session = self.sessions[peer]
            return session.get_state_summary()

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self.lock:
            sessions = []
            for peer, session in self.sessions.items():
                if session.session_state not in [SessionState.FINISHED, SessionState.FAILED]:
                    sessions.append(session.get_state_summary())
            return sessions

    def list_encrypted_sessions(self) -> List[Dict[str, Any]]:
        with self.lock:
            sessions = []
            for peer, session in self.sessions.items():
                if session.is_encrypted():
                    sessions.append(session.get_state_summary())
            return sessions

    def terminate_session(self, peer: str, reason: str='user request'):
        with self.lock:
            if peer not in self.sessions:
                return False
            session = self.sessions[peer]
            session.terminate(reason)
            if peer in self.dake_engines:
                del self.dake_engines[peer]
            self.tracer.trace(peer, 'TERMINATE', 'ACTIVE', 'TERMINATED', reason)
            return True

    def clear_all_sessions(self, reason: str='cleanup'):
        with self.lock:
            for peer in list(self.sessions.keys()):
                self.terminate_session(peer, reason)
            self.dake_engines.clear()
            self.tracer.trace('SYSTEM', 'CLEANUP', str(len(self.sessions)), '0', f'all sessions cleared: {reason}')

    def get_fingerprint(self) -> str:
        return self.client_profile.get_fingerprint()

    def get_peer_fingerprint(self, peer: str) -> Optional[str]:
        with self.lock:
            if peer not in self.sessions:
                return None
            session = self.sessions[peer]
            return session.get_fingerprint()

    def trust_fingerprint(self, peer: str, fingerprint: str) -> bool:
        with self.lock:
            actual_fp = self.get_peer_fingerprint(peer)
            if not actual_fp:
                return False
            if not hmac.compare_digest(actual_fp, fingerprint):
                self.tracer.trace(peer, 'TRUST', 'VERIFY', 'FAILED', f'fingerprint mismatch')
                return False
            success = self.trust_db.add_trust(peer, fingerprint)
            if success:
                self.tracer.trace(peer, 'TRUST', 'UNTRUSTED', 'TRUSTED', f'fingerprint: {fingerprint[:16]}...')
            else:
                self.tracer.trace(peer, 'ERROR', 'TRUST', 'FAILED', 'could not add to trust database')
            return success

    def is_peer_trusted(self, peer: str) -> bool:
        with self.lock:
            fingerprint = self.get_peer_fingerprint(peer)
            if not fingerprint:
                return False
            return self.trust_db.is_trusted(peer, fingerprint)

    def get_tracer_state(self, peer: str) -> str:
        return self.tracer.format_state_report(peer)

    def get_all_tracer_states(self) -> Dict[str, Any]:
        with self.lock:
            states = {}
            for peer in self.sessions.keys():
                states[peer] = self.tracer.get_peer_state(peer)
            return states

    def cleanup_expired_sessions(self, timeout: float=3600.0):
        with self.lock:
            now = time.time()
            expired = []
            for peer, session in self.sessions.items():
                if session.session_state in [SessionState.FINISHED, SessionState.FAILED]:
                    expired.append(peer)
                elif now - session.last_activity > timeout:
                    session.terminate('inactivity timeout')
                    expired.append(peer)
            for peer in expired:
                if peer in self.dake_engines:
                    del self.dake_engines[peer]
            if expired:
                self.tracer.trace('SYSTEM', 'CLEANUP', 'ACTIVE', 'EXPIRED', f'cleaned {len(expired)} expired sessions')

    def get_security_level(self, peer: str) -> 'UIConstants.SecurityLevel':
        with self.lock:
            sess = self.sessions.get(peer)
            if sess is None:
                return UIConstants.SecurityLevel.PLAINTEXT
            return getattr(sess, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)

    def get_session_info(self, peer: str) -> dict:
        state = self.get_session_state(peer)
        return state or {'peer': peer, 'state': 'no session'}

    def encrypt_message(self, peer: str, plaintext) -> Optional[str]:
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return None
            try:
                if isinstance(plaintext, (bytes, bytearray)) and len(plaintext) == 0:
                    plaintext = ''
                if isinstance(plaintext, bytes):
                    plaintext = plaintext.decode('utf-8', errors='replace')
                return sess.encrypt_message(plaintext)
            except Exception:
                return None

    def decrypt_message(self, peer: str, encrypted_msg: str) -> bytes:
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                raise EncryptionError(f'No session for {peer}')
            try:
                smp_phase = sess.rust_smp.get_phase() if sess.rust_smp is not None else 'IDLE'
                needs_bind = smp_phase in ('IDLE', 'FAILED') and (sess.rust_smp is None or not sess.rust_smp.check_secret_set())
                if needs_bind:
                    auto_secret = self.smp_storage.get_secret(peer) or ''
                    if auto_secret and hasattr(sess, 'set_smp_secret'):
                        sess.set_smp_secret(auto_secret)
                        auto_secret = None
            except Exception as _pe:
                self.logger.debug(f'decrypt_message: SMP pre-load failed for {peer}: {_pe}')
            plaintext = sess.decrypt_message(encrypted_msg)
            queued = getattr(sess, '_queued_smp_response', None)
            if queued:
                sess._queued_smp_response = None
                return queued.encode('utf-8') if isinstance(queued, str) else queued
            return plaintext

    def get_smp_progress(self, peer: str):
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return (0, 4)
            try:
                return sess.get_smp_progress()
            except Exception:
                return (0, 4)

    def get_smp_status(self, peer: str) -> dict:
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                return {'state': 'no_session', 'verified': False, 'failed': False}
            try:
                return sess.get_smp_status()
            except Exception:
                return {'state': 'unknown', 'verified': False, 'failed': False}

    def start_smp(self, peer: str, secret: str, question: str='') -> Optional[str]:
        with self.lock:
            sess = self.sessions.get(peer)
            if not sess:
                raise RuntimeError(f'start_smp: no session for {peer}')
            return sess.start_smp(secret, question if question else None)

    def process_smp_message(self, peer: str, data: bytes) -> Optional[str]:
        raise RuntimeError('process_smp_message is disabled.  SMP messages are processed automatically inside decrypt_message via _enh_handle_smp_tlv.')

    def set_smp_secret(self, peer: str, secret: str) -> bool:
        try:
            self.smp_storage.set_secret(peer, secret)
        except Exception as _se:
            self.logger.debug(f'set_smp_secret: smp_storage write failed for {peer}: {_se}')
        with self.lock:
            sess = self.sessions.get(peer)
        if sess is not None and hasattr(sess, 'set_smp_secret'):
            try:
                sess.set_smp_secret(secret)
            except Exception as _se:
                self.logger.debug(f'set_smp_secret: session bind failed for {peer}: {_se}')
        return True

    def display_fingerprints(self, peer: str) -> str:
        return self.get_peer_fingerprint(peer) or ''

    def handle_dake1(self, peer: str, payload: str) -> Optional[str]:
        result = self.handle_incoming_message(peer, payload)
        if result and isinstance(result, (bytes, str)):
            r = result if isinstance(result, str) else result.decode('utf-8', errors='replace')
            return r if r.startswith('?OTRv4 ') else None
        return None

    def handle_dake2(self, peer: str, payload: str) -> Optional[str]:
        return self.handle_dake1(peer, payload)

    def handle_dake3(self, peer: str, payload: str) -> bool:
        result = self.handle_incoming_message(peer, payload)
        return self.has_session(peer)

class Event:

    def __init__(self, event_type: str, data: Dict[str, Any]):
        self.event_type = event_type
        self.data = data
        self.timestamp = time.time()

class ErrorEvent(Event):

    def __init__(self, error_type: str, peer: str, error: Exception, context: Dict[str, Any]):
        super().__init__('ERROR', {'error_type': error_type, 'peer': peer, 'error': str(error)[:100], 'context': context})

class SMPEvent(Event):

    def __init__(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__('SMP', {'smp_type': smp_type, 'peer': peer, 'session_id': session_id, 'details': details})

class SecurityEvent(Event):

    def __init__(self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        super().__init__('SECURITY', {'security_type': security_type, 'peer': peer, 'session_id': session_id, 'details': details})

class EventHandler:

    def __init__(self, panel_manager: PanelManager):
        self.panel_manager = panel_manager
        self.events: List[Event] = []
        self.lock = threading.RLock()

    def emit_error(self, error_type: str, peer: str, error: Exception, context: Dict[str, Any]):
        event = ErrorEvent(error_type, peer, error, context)
        with self.lock:
            self.events.append(event)
        panel = self.panel_manager.panels.get(peer, self.panel_manager.panels['system'])
        panel.add_message(f'🔴 {error_type}: {str(error)[:50]}')

    def emit_smp_event(self, smp_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        event = SMPEvent(smp_type, peer, session_id, details)
        with self.lock:
            self.events.append(event)

    def emit_security_event(self, security_type: str, peer: str, session_id: str, details: Dict[str, Any]):
        event = SecurityEvent(security_type, peer, session_id, details)
        with self.lock:
            self.events.append(event)

    def get_events(self, since: Optional[float]=None) -> List[Event]:
        with self.lock:
            if since is None:
                return self.events.copy()
            return [e for e in self.events if e.timestamp > since]

    def clear_events(self):
        with self.lock:
            self.events.clear()

class OTRFragmentBuffer:
    _SPEC_RE = re.compile('^\\?OTRv4\\|([0-9A-Fa-f]{8})\\|([0-9A-Fa-f]{8})\\|(\\d{5})\\|(\\d{5})\\|(.*?)\\.?$', re.DOTALL)
    _LEGACY_RE = re.compile('^\\?OTRv4\\s*(?:\\[(\\d+)/(\\d+)\\])?(.*?)(?:\\.?)$', re.DOTALL)

    def __init__(self, timeout: float=UIConstants.FRAGMENT_TIMEOUT):
        self._buffers: Dict[tuple, Dict] = {}
        self._lock = threading.RLock()
        self.timeout = timeout
        self.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT
        self.max_total_senders = 100
        self.first_fragment_cb = None

    def add_fragment(self, sender: str, raw: str) -> Optional[str]:
        with self._lock:
            now = time.monotonic()
            self._expire(now)
            msg = raw.strip()
            m_spec = self._SPEC_RE.match(msg)
            if m_spec:
                _sender_tag, _recv_tag, k_s, n_s, chunk = m_spec.groups()
                idx = int(k_s)
                total = int(n_s)
                if total < 1 or not 1 <= idx <= total:
                    raise ValueError(f'invalid spec fragment index {idx}/{total}')
                return self._buffer(sender, idx, total, chunk.strip(), now)
            while msg.startswith('?OTRv4 ?OTRv4'):
                msg = '?OTRv4 ' + msg[len('?OTRv4 ?OTRv4 '):]
            if msg.startswith('?OTRv4[') and (not msg.startswith('?OTRv4 [')):
                msg = '?OTRv4 [' + msg[7:]
            if msg.endswith('.'):
                msg = msg[:-1]
            m_leg = self._LEGACY_RE.match(msg)
            if not m_leg:
                return raw
            idx_s, total_s, chunk = m_leg.groups()
            chunk = chunk.strip()
            if idx_s is None:
                return f'?OTRv4 {chunk}'
            idx = int(idx_s)
            total = int(total_s)
            if total < 1 or not 1 <= idx <= total:
                raise ValueError(f'invalid legacy fragment index {idx}/{total}')
            return self._buffer(sender, idx, total, chunk, now)

    def _buffer(self, sender: str, idx: int, total: int, chunk: str, now: float) -> Optional[str]:
        if total > self.max_fragments_per_sender:
            raise ValueError(f'Fragment total {total} from {sender} exceeds max {self.max_fragments_per_sender}. Discarding.')
        _ABSOLUTE_MAX_FRAGMENTS = 1000
        if total > _ABSOLUTE_MAX_FRAGMENTS:
            raise ValueError(f'Fragment total {total} from {sender} exceeds absolute maximum of {_ABSOLUTE_MAX_FRAGMENTS}. Discarding.')
        key = (sender, total)
        if idx == 1 or key not in self._buffers:
            self._buffers[key] = {'total': total, 'parts': {}, 'first_ts': now, 'last_ts': now}
            if total > 1 and idx == 1 and (self.first_fragment_cb is not None):
                try:
                    self.first_fragment_cb(sender, total, chunk)
                except Exception:
                    pass
        state = self._buffers[key]
        if len(state['parts']) >= self.max_fragments_per_sender:
            self._buffers.pop(key, None)
            raise ValueError(f'Fragment flood from {sender} (total={total}): exceeded {self.max_fragments_per_sender} in-flight fragments. Buffer evicted.')
        if idx not in state['parts']:
            _MAX_REASSEMBLED_BYTES = 1048576
            _current_bytes = sum((len(c) for c in state['parts'].values()))
            if _current_bytes + len(chunk) > _MAX_REASSEMBLED_BYTES:
                self._buffers.pop(key, None)
                raise ValueError(f'Fragment payload from {sender} exceeds 1 MiB limit — discarding.')
            state['parts'][idx] = chunk
            state['last_ts'] = now
            if DEBUG_MODE:
                _c = getattr(__import__('builtins'), '_active_client', None)
                if _c:
                    _c._emit('debug', f'[OTRFragment] {idx}/{total} for {sender}')
                else:
                    _emit_line(f'[OTRFragment] {idx}/{total} for {sender}')
        if len(state['parts']) == total:
            payload_parts = []
            for i in range(1, total + 1):
                if i not in state['parts']:
                    self._buffers.pop(key, None)
                    return None
                payload_parts.append(state['parts'][i])
            combined = ''.join(payload_parts)
            self._buffers.pop(key, None)
            if DEBUG_MODE:
                _c = getattr(__import__('builtins'), '_active_client', None)
                if _c:
                    _c._emit('debug', f'[OTRFragment] reassembled {len(combined)} chars from {sender}')
                else:
                    _emit_line(f'[OTRFragment] reassembled {len(combined)} chars from {sender}')
            return f'?OTRv4 {combined}'
        return None

    def clear_sender(self, sender: str) -> None:
        with self._lock:
            keys = [k for k in self._buffers if k[0] == sender]
            for k in keys:
                self._buffers.pop(k, None)

    def clear_all(self) -> None:
        with self._lock:
            self._buffers.clear()

    def get_pending_count(self) -> int:
        with self._lock:
            return len(self._buffers)

    def get_pending_for(self, sender: str) -> int:
        with self._lock:
            return sum((len(state['parts']) for (s, _t), state in self._buffers.items() if s == sender))

    def _expire(self, now: float) -> None:
        if len(self._buffers) > self.max_total_senders:
            oldest = sorted(self._buffers.items(), key=lambda x: x[1].get('first_ts', 0))
            for key, _ in oldest[:len(self._buffers) - self.max_total_senders]:
                if DEBUG_MODE:
                    _emit_line(f'[fragment] buffer evict: too many senders, dropping {key[0]}/{key[1]}')
                del self._buffers[key]
        cutoff = now - self.timeout
        expired = [k for k, st in self._buffers.items() if st.get('last_ts', st.get('first_ts', 0)) < cutoff]
        for k in expired:
            sender_nick, frag_total = k
            state = self._buffers.pop(k, None)
            if state is None:
                continue
            got = len(state.get('parts', {}))
            if DEBUG_MODE:
                _emit_line(f'[fragment] timeout: {sender_nick} {got}/{frag_total} frags — type /otr {sender_nick} to retry')

    def cleanup_expired(self) -> int:
        with self._lock:
            now = time.monotonic()
            before = len(self._buffers)
            self._expire(now)
            return before - len(self._buffers)

class OTRMessageFragmenter:
    _SPEC_OVERHEAD = len('?OTRv4|00000000|00000000|00001|00001|.')
    _LEGACY_PREFIX = '?OTRv4 '

    @classmethod
    def fragment(cls, otr_message: str, max_line: int=UIConstants.OTR_FRAGMENT_SIZE, sender_tag: int=0, receiver_tag: int=0) -> List[str]:
        if not otr_message.startswith(cls._LEGACY_PREFIX):
            return [otr_message]
        payload = otr_message[len(cls._LEGACY_PREFIX):]
        if payload.endswith('.'):
            payload = payload[:-1]
        if not payload:
            return [otr_message]
        if len(otr_message) <= max_line:
            return [otr_message]
        stag_hex = f'{sender_tag:08X}'
        rtag_hex = f'{receiver_tag:08X}'
        overhead = len(f'?OTRv4|{stag_hex}|{rtag_hex}|00001|00001|.')
        chunk_size = max_line - overhead
        if chunk_size < 4:
            chunk_size = 4
        chunk_size = chunk_size // 4 * 4
        if chunk_size < 4:
            chunk_size = 4
        total = math.ceil(len(payload) / chunk_size)
        fragments: List[str] = []
        for i in range(total):
            start = i * chunk_size
            end = min(start + chunk_size, len(payload))
            chunk = payload[start:end]
            k_str = f'{i + 1:05d}'
            n_str = f'{total:05d}'
            frag = f'?OTRv4|{stag_hex}|{rtag_hex}|{k_str}|{n_str}|{chunk}.'
            fragments.append(frag)
        if DEBUG_MODE:
            _cp = getattr(__import__('builtins'), '_active_client', None)
            if _cp: _cp._emit('debug', f'[OTRMessageFragmenter] {len(fragments)} frags from {len(payload)} chars chunk={chunk_size}')
            else: _emit_line(f'[OTRMessageFragmenter] {len(fragments)} fragments from {len(payload)} chars (chunk={chunk_size})')
        return fragments

    @staticmethod
    def fragment_otr_message(otr_message: str, fragment_size: int=UIConstants.OTR_FRAGMENT_SIZE) -> List[str]:
        return OTRMessageFragmenter.fragment(otr_message, fragment_size)

class DebugPanel(ChatPanel):

    def __init__(self, name: str):
        super().__init__(name, 'debug')
        self.debug_level = 'FULL'
        self.categories = {'OTR': True, 'SMP': True, 'DAKE': True, 'RATCHET': True, 'NETWORK': True, 'SECURITY': True, 'TRUST': True, 'FINGERPRINT': True, 'UI': True}
        self.max_debug_lines = 1000

    def log(self, category: str, message: str, data: Optional[dict]=None):
        if not self.categories.get(category, False):
            return
        timestamp = time.strftime('%H:%M:%S.%f')[:-3]
        colored_cat = colorize(category, 'magenta')
        msg = f'[{timestamp}] [{colored_cat}] {message}'
        if data:
            data_str = json.dumps(data, default=str)[:200]
            if len(json.dumps(data, default=str)) > 200:
                data_str += '...'
            msg += f' | {data_str}'
        self.add_message(msg)
        if len(self.history) > self.max_debug_lines:
            self.history = self.history[-self.max_debug_lines:]

    def set_category(self, category: str, enabled: bool):
        self.categories[category] = enabled

    def toggle_category(self, category: str):
        self.categories[category] = not self.categories.get(category, False)
        return self.categories[category]

class DebugLogger:

    def __init__(self, debug_panel: Optional[DebugPanel]=None):
        self.debug_panel = debug_panel
        self.enabled = DEBUG_MODE

    def log(self, component: str, method: str, message: str, data: Optional[dict]=None):
        if not self.enabled:
            return
        full_message = f'{component}.{method}: {message}'
        if self.debug_panel:
            self.debug_panel.log(component, full_message, data)
        else:
            safe_print(f'[DEBUG] [{component}] {full_message}')
            if data:
                safe_print(f'  Data: {data}')

def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 0:
        return '0s'
    parts = []
    if s >= 86400:
        d, s = divmod(s, 86400)
        parts.append(f'{d}d')
    if s >= 3600:
        h, s = divmod(s, 3600)
        parts.append(f'{h}h')
    if s >= 60:
        m, s = divmod(s, 60)
        parts.append(f'{m}m')
    if s > 0 or not parts:
        parts.append(f'{s}s')
    return ' '.join(parts)

class TwentySevenClubNick:
    _LEGACY = [('KurtCobain', 'Kurt Cobain', 'Nirvana'), ('AmyWinehouse', 'Amy Winehouse', 'Solo'), ('JimiHendrix', 'Jimi Hendrix', 'The Jimi Hendrix Experience'), ('JanisJoplin', 'Janis Joplin', 'Big Brother & The Holding Company'), ('JimMorrison', 'Jim Morrison', 'The Doors'), ('BrianJones', 'Brian Jones', 'The Rolling Stones'), ('RobertJohnson', 'Robert Johnson', 'Blues Legend'), ('AlanWilson', 'Alan Wilson', 'Canned Heat'), ('RonMcKernan', 'Ron McKernan', 'Grateful Dead'), ('PeteHam', 'Pete Ham', 'Badfinger'), ('RandyRhoads', 'Randy Rhoads', 'Ozzy Osbourne'), ('HillelSlovak', 'Hillel Slovak', 'Red Hot Chili Peppers'), ('AndrewWood', 'Andrew Wood', 'Mother Love Bone'), ('KristenPfaff', 'Kristen Pfaff', 'Hole'), ('RicheyEdwards', 'Richey Edwards', 'Manic Street Preachers'), ('DaveAlexander', 'Dave Alexander', 'The Stooges'), ('GaryThain', 'Gary Thain', 'Uriah Heep'), ('LesHarvey', 'Les Harvey', 'Stone the Crows'), ('ChrisBell', 'Chris Bell', 'Big Star'), ('JeremyWard', 'Jeremy Ward', 'The Mars Volta')]
    _ADJECTIVES = ['Silent', 'Shadow', 'Phantom', 'Midnight', 'Iron', 'Crimson', 'Golden', 'Silver', 'Dark', 'Bright', 'Swift', 'Fierce', 'Calm', 'Wild', 'Lone', 'Bitter', 'Hollow', 'Frozen', 'Burning', 'Hidden', 'Ancient', 'Broken', 'Fading', 'Rising', 'Fallen', 'Distant', 'Restless', 'Wicked', 'Noble', 'Stray', 'Drifting', 'Echoing', 'Veiled', 'Stark', 'Ashen', 'Copper', 'Jade', 'Cobalt', 'Ember', 'Onyx', 'Rustic', 'Pale', 'Dusky', 'Misty', 'Stormy', 'Feral', 'Glacial', 'Lunar', 'Solar', 'Rogue', 'Scarlet', 'Azure', 'Violet', 'Ivory', 'Obsidian', 'Granite', 'Cedar', 'Birch', 'Rowan', 'Hazel', 'Wraith', 'Spectre', 'Vagrant', 'Nomad', 'Hermit', 'Cipher', 'Zero', 'Null', 'Void', 'Apex', 'Primal', 'Austere', 'Cryptic', 'Arcane', 'Lucid', 'Serene', 'Turbid', 'Waning', 'Waxing', 'Errant', 'Sullen', 'Muted', 'Stark', 'Gaunt', 'Bleak', 'Thorned', 'Barbed', 'Tempered', 'Forged', 'Annealed', 'Quartz', 'Basalt', 'Slate', 'Flint', 'Ochre', 'Boreal', 'Tundra', 'Steppe', 'Taiga', 'Mesa']
    _NOUNS = ['Wolf', 'Hawk', 'Raven', 'Fox', 'Lynx', 'Bear', 'Owl', 'Crane', 'Viper', 'Falcon', 'Heron', 'Sparrow', 'Condor', 'Osprey', 'Kestrel', 'Jackal', 'Panther', 'Cobra', 'Mantis', 'Hornet', 'Badger', 'Otter', 'Marten', 'Wren', 'Finch', 'Forge', 'Anvil', 'Blade', 'Shield', 'Arrow', 'Spire', 'Bastion', 'Citadel', 'Tower', 'Gate', 'Storm', 'Thunder', 'Frost', 'Blaze', 'Ember', 'Tide', 'Current', 'Drift', 'Torrent', 'Gale', 'Root', 'Thorn', 'Branch', 'Stone', 'Ridge', 'Peak', 'Crest', 'Vale', 'Glen', 'Cairn', 'Dusk', 'Dawn', 'Shade', 'Gloom', 'Haze', 'Reef', 'Shoal', 'Fjord', 'Gorge', 'Ravine', 'Cipher', 'Signal', 'Beacon', 'Pulse', 'Vector', 'Prism', 'Shard', 'Relic', 'Glyph', 'Rune', 'Wick', 'Tallow', 'Flint', 'Spark', 'Cinder', 'Quarry', 'Ledge', 'Scree', 'Moraine', 'Talus', 'Styx', 'Lethe', 'Acheron', 'Eris', 'Nyx', 'Odin', 'Loki', 'Fenrir', 'Mimir', 'Tyr', 'Kappa', 'Sigma', 'Delta', 'Theta', 'Omega', 'Vertex', 'Node', 'Orbit', 'Zenith', 'Nadir', 'Mantle', 'Cortex', 'Nexus', 'Vortex', 'Matrix']
    _LOOKUP = {nick: (real, band) for nick, real, band in _LEGACY}

    @classmethod
    def generate(cls) -> str:
        adj = secrets.choice(cls._ADJECTIVES)
        noun = secrets.choice(cls._NOUNS)
        nick = adj + noun
        if len(nick) > 30:
            nick = nick[:30]
        return nick

    @classmethod
    def real_name(cls, nick: str) -> str:
        base = nick.rstrip('_0123456789')
        if base in cls._LOOKUP:
            real, band = cls._LOOKUP[base]
            return f'{real} ({band}) — 27 Club'
        return f'{nick} — {VERSION}'

    @classmethod
    def is_member(cls, nick: str) -> bool:
        base = nick.rstrip('_0123456789')
        return base in cls._LOOKUP

class OTRv4IRCClient:

    def __init__(self, config: Optional[OTRConfig]=None):
        self.config = config or OTRConfig()
        self._prompt_refresh_cb: Optional[Callable[[], None]] = None
        self._tui_enabled: bool = False
        self._screen: Optional['Screen'] = None
        self.logger = OTRLogger(self.config)
        self.session_manager = EnhancedSessionManager(self.config, logger=self.logger)
        self.panel_manager = PanelManager(self)
        self.message_router = MessageRouter(self.panel_manager)
        self.event_handler = EventHandler(self.panel_manager)
        self.server = self.config.server
        if self.config.nickserv_nick:
            self.nick = self.config.nickserv_nick
            self.realname = self.nick
        else:
            self.nick = TwentySevenClubNick.generate()
            self.realname = TwentySevenClubNick.real_name(self.nick)
        self._running_event = threading.Event()
        self._shutdown_event = threading.Event()
        self._connected_event = threading.Event()
        self._reconnecting = False
        self.auto_joined = False
        self.auth_complete = False
        self.nickserv_identified = False
        self.shutting_down = False
        self.sock: Optional[socket.socket] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._recv_buf = ''
        self._sock_lock = threading.Lock()
        self._init_state()

    @property
    def running(self) -> bool:
        return self._running_event.is_set()

    @running.setter
    def running(self, value: bool) -> None:
        self._running_event.set() if value else self._running_event.clear()

    @property
    def connected(self) -> bool:
        return self._connected_event.is_set()

    @connected.setter
    def connected(self, value: bool) -> None:
        self._connected_event.set() if value else self._connected_event.clear()

    @property
    def shutdown_flag(self) -> bool:
        return self._shutdown_event.is_set()

    @shutdown_flag.setter
    def shutdown_flag(self, value: bool) -> None:
        self._shutdown_event.set() if value else self._shutdown_event.clear()

    def _init_state(self) -> None:
        self.last_ping = time.time()
        self.connection_healthy = True
        self.connection_attempts = 0
        self.max_connection_attempts = 999
        self._last_otr_sent: Dict[str, float] = {}
        self.ignored_users: Set[str] = set()
        self.channels: Dict[str, dict] = {}
        self.channel_list: List[dict] = []
        self.whois_data: Dict[str, dict] = {}
        self.names_data: Dict[str, List[str]] = {}
        self._pending_names_pager: Optional[str] = None
        self.auto_reply_config: Dict[str, dict] = {}
        self.otr_fragmenter = OTRMessageFragmenter()
        self.fragment_buffers: Dict[str, OTRFragmentBuffer] = {}
        self.pager = Pager()
        self.smp_schedule_timers: Dict[str, dict] = {}
        self.auto_smp_monitor_running = False
        self._smp_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='smp_worker')
        self.terminal_width = TERMINAL_WIDTH
        self.terminal_height = TERMINAL_HEIGHT
        self.input_history: List[str] = []
        self.history_index = -1
        self.input_enabled = True
        self.headless = False
        self.test_runner = None
        self.debug_panel_name = 'debug' if DEBUG_MODE else None
        if DEBUG_MODE:
            self.panel_manager.add_panel('debug', 'debug')
        self.tracer = OTRTracer(enabled=DEBUG_MODE, logger=self.logger)
        self.tracer.set_emit_callback(lambda msg: self._emit('debug', msg))
        self.session_manager.tracer = self.tracer

        def _make_smp_notify(peer: str):

            def _notify(msg: str) -> None:
                try:
                    sec = self.session_manager.get_security_level(peer)
                    self.add_message(peer, msg, sec)
                    self.panel_manager.update_smp_progress(peer, *self.session_manager.get_smp_progress(peer))
                    self.panel_manager.update_panel_security(peer, sec)
                except Exception:
                    pass
            return _notify
        self.session_manager.smp_notify_factory = _make_smp_notify

        def _ping_refresh() -> None:
            self.last_ping = time.time()
        self.session_manager.ping_refresh_cb = _ping_refresh
        self._emit('debug', colorize(f'[CLIENT] nick={self.nick}', 'magenta'))

    def debug(self, message: str, data: Optional[dict]=None):
        if not DEBUG_MODE:
            return
        msg = message
        if data:
            msg += ' | ' + json.dumps(data, separators=(',', ':'))
        self._emit('debug', colorize(msg, 'magenta'))
        self.logger.debug(message)

    def _emit(self, panel: str, message: str) -> None:
        if panel == 'debug' and (not DEBUG_MODE):
            return
        if panel not in self.panel_manager.panels:
            ptype = 'channel' if panel.startswith('#') else 'debug' if panel == 'debug' else 'system' if panel == 'system' else 'private'
            self.panel_manager.add_panel(panel, ptype)
        self.panel_manager.panels[panel].add_message(message)
        if self.panel_manager.active_panel != panel:
            self.panel_manager.panels[panel].unread_count += 1
        _is_background_tab = bool(self.panel_manager.active_panel and panel != self.panel_manager.active_panel)
        if _is_background_tab:
            self._termux_notify_message(panel, message)
            if getattr(self, '_tui_enabled', False) and self._screen is not None:
                self._screen.redraw_tabbar()
            return
        ts = colorize(time.strftime('%H:%M:%S'), 'dark_yellow')
        if panel == 'system':
            tag = colorize('[sys]  ', 'grey')
        elif panel == 'debug':
            tag = colorize('[debug]', 'dark_magenta')
        elif panel.startswith('#'):
            tag = colorize(f'[{panel}]', 'bold_cyan')
        else:
            _sec = self.session_manager.get_security_level(panel) if hasattr(self, 'session_manager') and self.session_manager.has_session(panel) else None
            _tag_colors = {UIConstants.SecurityLevel.ENCRYPTED: 'bold_yellow', UIConstants.SecurityLevel.FINGERPRINT: 'bold_green', UIConstants.SecurityLevel.SMP_VERIFIED: 'blue'}
            _tc = _tag_colors.get(_sec, 'green') if _sec is not None else 'green'
            tag = colorize(f'[{panel}]', _tc)
        if getattr(self, '_tui_enabled', False) and self._screen is not None:
            self._screen.redraw_body()
        else:
            _emit_line(f'{ts} {tag} {message}')

    def _detect_network(self) -> str:
        return NetworkConstants.detect(self.server)

    def setup_proxy(self, net_type: str=None) -> str:
        if net_type is None:
            net_type = self._detect_network()
        if net_type == NetworkConstants.NET_I2P:
            host, port = self.config.i2p_proxy
            if not _probe_socks5(host, port, timeout=2.0):
                raise ConnectionError(f'I2P SOCKS5 proxy not reachable on {host}:{port}.\n  → Ensure i2pd is running (SOCKS5 port 4447).')
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port, rdns=True)
            socket.socket = socks.socksocket
            self.add_message('system', colorize(f'🧅 I2P SOCKS5 proxy: {_sanitise(str(host), 64)}:{port}', 'dark_cyan'))
            self.debug('proxy set', {'type': 'i2p', 'host': host, 'port': port})
        elif net_type == NetworkConstants.NET_TOR:
            host, _cfg_port = self.config.tor_proxy
            _tor_candidates = [_cfg_port]
            for _alt in (9050, 9150):
                if _alt not in _tor_candidates:
                    _tor_candidates.append(_alt)
            port = None
            for _p in _tor_candidates:
                if _probe_socks5(host, _p, timeout=2.0):
                    port = _p
                    break
            if port is None:
                tried = ', '.join((str(p) for p in _tor_candidates))
                raise ConnectionError(f"Tor SOCKS5 proxy not reachable on {host} (tried ports: {tried}).\n  → Start Orbot and tap 'Start' before connecting.")
            self.config.tor_proxy = (host, port)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port, rdns=True)
            socket.socket = socks.socksocket
            self.add_message('system', colorize(f'🧅 Tor SOCKS5 proxy: {host}:{port}', 'dark_magenta'))
            self.debug('proxy set', {'type': 'tor', 'host': host, 'port': port})
        else:
            socks.setdefaultproxy()
            socket.socket = socks.socksocket
            self.add_message('system', colorize('🌐 Clearnet (no proxy)', 'grey'))
            self.debug('proxy set', {'type': 'clearnet'})
        return net_type

    def connect(self) -> bool:
        try:
            net_type = NetworkConstants.detect(self.server)
            if net_type == NetworkConstants.NET_TOR:
                _onion_host = self.server
                if _onion_host.lower().endswith('.onion'):
                    _onion_label = _onion_host[:-6]
                    if len(_onion_label) == 16:
                        pass
                    elif len(_onion_label) != 56:
                        raise ValueError(f'Invalid .onion address — label is {len(_onion_label)} chars, expected 56 (v3) or 16 (v2).\n  Got:     {_onion_host}\n  Hint: v3 onion addresses look like <56-char-base32>.onion')
            timeout_map = {NetworkConstants.NET_CLEARNET: NetworkConstants.TIMEOUT_CLEARNET, NetworkConstants.NET_TOR: NetworkConstants.TIMEOUT_TOR, NetworkConstants.NET_I2P: NetworkConstants.TIMEOUT_I2P}
            timeout = timeout_map.get(net_type, NetworkConstants.TIMEOUT_I2P)
            use_tls = self.config.use_tls
            port = self.config.port
            if net_type == NetworkConstants.NET_CLEARNET:
                if port == 0:
                    port = IRCConstants.TLS_PORT
                if port == IRCConstants.PORT and (not self.config.use_tls):
                    self.add_message('system', colorize('⚠ Plaintext port 6667 — most networks now require TLS on 6697. Use -p 6697 if reset.', 'yellow'))
                    use_tls = False
                else:
                    port = IRCConstants.TLS_PORT
                    use_tls = True
            else:
                use_tls = False
                if port == 0:
                    port = IRCConstants.PORT
            net_label = {NetworkConstants.NET_I2P: 'I2P', NetworkConstants.NET_TOR: 'Tor', NetworkConstants.NET_CLEARNET: 'clearnet'}.get(net_type, net_type)
            sock = None
            self._sam_connection = None
            if net_type == NetworkConstants.NET_I2P:
                sam_host, sam_port = self.config.i2p_sam
                if I2PSAMConnection.is_available(sam_host, sam_port):
                    try:
                        self.add_message('system', f'Connecting to {colorize(self.server, 'cyan')} via {colorize('SAM bridge', 'green')} (unique destination)…')
                        self.debug('connect', {'server': self.server, 'port': port, 'net': 'i2p-sam', 'tls': False, 'timeout': timeout})
                        sam = I2PSAMConnection(sam_host, sam_port)
                        sock = sam.connect(self.server, port)
                        self._sam_connection = sam
                        self.add_message('system', colorize('🧅 I2P SAM: unique destination per session', 'green'))
                    except Exception as e:
                        self.debug('sam_failed', {'error': str(e)})
                        self.add_message('system', colorize(f'SAM failed ({e}), falling back to SOCKS5…', 'yellow'))
                        sock = None
            if sock is None:
                if net_type == NetworkConstants.NET_TOR:
                    _tor_SOCKS5_ERRORS = {1: 'general SOCKS server failure (Tor may not be bootstrapped)', 2: 'connection not allowed by ruleset', 3: 'network unreachable', 4: 'host unreachable (hidden service may be down)', 5: 'connection refused by destination', 6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported'}
                    proxy_host, _cfg_port = self.config.tor_proxy
                    _candidates = [_cfg_port]
                    for _alt in (9050, 9150):
                        if _alt not in _candidates:
                            _candidates.append(_alt)
                    proxy_port = None
                    for _p in _candidates:
                        if _probe_socks5(proxy_host, _p, timeout=2.0):
                            proxy_port = _p
                            break
                    if proxy_port is None:
                        tried = ', '.join((str(p) for p in _candidates))
                        raise ConnectionError(f'Tor SOCKS5 not reachable on {proxy_host} (tried ports: {tried})\n  → Is tor running?  Check: systemctl status tor')
                    self.config.tor_proxy = (proxy_host, proxy_port)
                    self.add_message('system', f'Connecting to {colorize(self.server, 'cyan')}:{port} via {colorize('Tor SOCKS5', 'dark_magenta')} ({proxy_host}:{proxy_port})…')

                    def _recvexact(s, n):
                        buf = b''
                        while len(buf) < n:
                            chunk = s.recv(n - len(buf))
                            if not chunk:
                                raise ConnectionError(f'SOCKS5: connection closed (got {len(buf)}/{n} bytes)')
                            buf += chunk
                        return buf
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(float(timeout))
                    sock.connect((proxy_host, proxy_port))
                    sock.send(b'\x05\x01\x00')
                    auth_resp = _recvexact(sock, 2)
                    if auth_resp[0] != 5:
                        raise ConnectionError(f'SOCKS5 greeting: unexpected version byte {auth_resp[0]:#04x}')
                    if auth_resp[1] == 255:
                        raise ConnectionError("SOCKS5 greeting: proxy requires authentication (add 'SocksPolicy accept 127.0.0.1' to torrc)")
                    if auth_resp[1] != 0:
                        raise ConnectionError(f'SOCKS5 greeting: unsupported auth method {auth_resp[1]:#04x}')
                    domain = self.server.encode('ascii')
                    req = b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack('!H', port)
                    sock.send(req)
                    hdr = _recvexact(sock, 4)
                    if hdr[0] != 5:
                        raise ConnectionError(f'SOCKS5 response: unexpected version byte {hdr[0]:#04x}')
                    rep = hdr[1]
                    if rep != 0:
                        err_desc = _tor_SOCKS5_ERRORS.get(rep, f'unknown error code {rep:#04x}')
                        raise ConnectionError(f'SOCKS5 CONNECT rejected: {err_desc}')
                    atyp = hdr[3]
                    if atyp == 1:
                        _recvexact(sock, 4)
                    elif atyp == 3:
                        _recvexact(sock, ord(_recvexact(sock, 1)))
                    elif atyp == 4:
                        _recvexact(sock, 16)
                    _recvexact(sock, 2)
                    self.add_message('system', colorize('🧅 Tor circuit established', 'green'))
                else:
                    net_type_actual = self.setup_proxy(net_type)
                    tls_label = ' TLS' if use_tls else ''
                    self.add_message('system', f'Connecting to {colorize(self.server, 'cyan')}:{port} ({colorize(net_label + tls_label, 'bold_cyan')}, up to {timeout}s)…')
                    self.debug('connect', {'server': self.server, 'port': port, 'net': net_type, 'tls': use_tls, 'timeout': timeout})
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(float(timeout))
                    sock.connect((self.server, port))
            if use_tls:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=self.server)
                self.add_message('system', colorize('🔒 TLS handshake complete', 'green'))
            sock.setblocking(True)
            sock.settimeout(1.0)
            self.sock = sock
            self.connected = True
            self.connected_at = time.time()
            self.running = True
            self.last_ping = time.time()
            self.auto_joined = False
            self.auth_complete = False
            self.nickserv_identified = False
            self._cap_negotiating = True
            self._cap_accepted: set = set()
            self._cap_end_sent = False
            self._sasl_in_progress = False
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True, name='irc-recv')
            self._recv_thread.start()
            self.send_raw('CAP LS 302')
            self.send_raw(f'NICK {self.nick}')
            self.send_raw(f'USER {self.nick} 0 * :{self.realname}')
            self.add_message('system', f'✅ Connected — nick: {colorize_username(self.nick)}')
            self.debug('handshake sent', {'nick': self.nick, 'caps': 'LS 302'})
            return True
        except Exception as exc:
            self.add_message('system', f'❌ Connection failed: {exc}')
            self.debug('connect failed', {'error': str(exc)})
            self.connected = False
            return False

    def _recv_loop(self):
        buf = ''
        self.debug('recv loop started')
        while self.running and (not self.shutdown_flag):
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    if self.running:
                        self.add_message('system', colorize('⚠ Server closed the connection. Reconnecting automatically…', 'yellow'))
                        self._try_reconnect()
                        return
                    self.connected = False
                    self.running = False
                    break
                buf += chunk.decode('utf-8', errors='replace')
                if len(buf) > 65536:
                    self.debug('recv buffer overflow — truncating')
                    buf = buf[-32768:]
                while '\r\n' in buf:
                    line, buf = buf.split('\r\n', 1)
                    line = line.strip()
                    if len(line) > 8192:
                        self.debug(f'oversized IRC line dropped ({len(line)} bytes)')
                        continue
                    if line:
                        try:
                            self.handle_message(line)
                        except Exception as exc:
                            self.debug(f'handle_message error: {exc}')
            except socket.timeout:
                now = time.time()
                if now - self.last_ping > 600:
                    self.add_message('system', colorize('⚠ Ping timeout. Reconnecting automatically…', 'yellow'))
                    self._try_reconnect()
                    return
                if hasattr(self, '_msg_rate') and len(self._msg_rate) > 500:
                    self._msg_rate.clear()
                _has_otr = hasattr(self, 'session_manager') and bool(self.session_manager.list_encrypted_sessions())
                _irc_ping_interval = 90 if _has_otr else 150
                if not hasattr(self, '_last_irc_ping'):
                    self._last_irc_ping = now
                if now - self._last_irc_ping >= _irc_ping_interval:
                    try:
                        self.send_raw(f'PING :{self.server}')
                        self._last_irc_ping = now
                    except Exception:
                        pass
                try:
                    hb_interval = getattr(self.config, 'heartbeat_interval', 60)
                    if hasattr(self, 'session_manager') and hasattr(self, '_last_otr_sent'):
                        for peer, sess in list(self.session_manager.sessions.items()):
                            if getattr(sess, 'session_state', None) is not None and sess.session_state.name == 'ENCRYPTED':
                                peer_last = self._last_otr_sent.get(peer, 0)
                                if now - peer_last >= hb_interval:
                                    try:
                                        hb = sess.encrypt_with_tlvs('', [])
                                        if hb:
                                            self.send_otr_message(peer, hb)
                                            self._last_otr_sent[peer] = now
                                    except Exception:
                                        pass
                except Exception:
                    pass
                continue
            except OSError as exc:
                if self.running:
                    _uptime = time.time() - getattr(self, 'connected_at', 0)
                    _is_clearnet_plain = NetworkConstants.detect(self.server) == NetworkConstants.NET_CLEARNET and (not self.config.use_tls) and (self.config.port in (IRCConstants.PORT, 0))
                    if _uptime < 3.0 and _is_clearnet_plain and ('104' in str(exc)):
                        self.add_message('system', colorize('⚠ Server reset plaintext connection — auto-upgrading to TLS on port 6697…', 'yellow'))
                        self.config.use_tls = True
                        self.config.port = IRCConstants.TLS_PORT
                    else:
                        self.add_message('system', colorize(f'⚠ Connection lost ({exc}). Reconnecting automatically…', 'yellow'))
                    self._try_reconnect()
                    return
                self.connected = False
                self.running = False
                break
            except Exception as exc:
                self.debug(f'recv_loop unexpected error: {exc}')
                try:
                    self.add_message('system', colorize(f'⚠ Network error (recovered): {str(exc)[:80]}', 'yellow'))
                except Exception:
                    pass
        self.debug('recv loop ended')

    def _try_reconnect(self):
        self._reconnecting = True
        self._rejoin_channels = list(self.channels.keys()) if self.channels else []
        self.connected = False
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        try:
            if hasattr(self, '_sam_connection') and self._sam_connection:
                self._sam_connection.close()
                self._sam_connection = None
        except Exception:
            pass
        self.auto_joined = False
        self.auth_complete = False
        self.nickserv_identified = False
        try:
            if hasattr(self, 'session_manager'):
                for _sess in list(self.session_manager.sessions.values()):
                    try:
                        if hasattr(_sess, 'ratchet') and _sess.ratchet is not None:
                            if hasattr(_sess.ratchet, 'zeroize'):
                                _sess.ratchet.zeroize()
                        for _attr in ('root_key', 'chain_key_send', 'chain_key_recv', '_chain_key_s', '_chain_key_r', 'brace_key', '_brace_key'):
                            if hasattr(_sess, _attr):
                                _v = getattr(_sess, _attr, None)
                                if isinstance(_v, (bytes, bytearray)):
                                    _ba = bytearray(_v)
                                    _secure_wipe(_ba)
                                setattr(_sess, _attr, None)
                    except Exception:
                        pass
                self.session_manager.sessions.clear()
        except Exception:
            pass
        try:
            if hasattr(self, '_pending_action'):
                self._pending_action = None
        except Exception:
            pass
        try:
            for panel in self.panel_manager.panels.values():
                panel.security_level = UIConstants.SecurityLevel.PLAINTEXT
                panel.secure_session = False
                panel.type = 'channel' if panel.name.startswith('#') else 'system' if panel.name == 'system' else 'private'
        except Exception:
            pass
        self.connection_attempts += 1
        backoff = min(120, 5 * 2 ** min(self.connection_attempts - 1, 4))
        self.add_message('system', f'🔄 Reconnecting in {backoff}s (attempt {self.connection_attempts})…')
        for _ in range(backoff * 10):
            if getattr(self, 'shutdown_flag', False):
                self._rejoin_channels = []
                return
            time.sleep(0.1)
        if self.connection_attempts <= self.max_connection_attempts:
            if self.connect():
                self._reconnecting = False
            else:
                self._reconnecting = False
        else:
            self._reconnecting = False
            self.add_message('system', colorize('❌ Max reconnect attempts reached.', 'red'))

    def send_raw(self, message: str) -> bool:
        message = message.replace('\r', '').replace('\n', '')
        if len(message) > 510:
            self.debug(f'BUG: send_raw truncated {len(message)}→510 bytes. Fragmentation should have prevented this.', {'head': message[:80]})
            message = message[:510]
        try:
            with self._sock_lock:
                if self.sock:
                    self.sock.sendall(f'{message}\r\n'.encode('utf-8'))
                    self.logger.network_message('OUT', 'SERVER', 'RAW', len(message))
                    self.debug('send', {'msg': message[:120]})
                    return True
        except Exception as exc:
            self.debug('send_raw failed', {'error': str(exc)})
            self.running = False
        return False

    def send(self, message: str) -> bool:
        return self.send_raw(message) if self.running else False

    def send_otr_message(self, target: str, otr_message: str) -> bool:
        sender_tag = 0
        receiver_tag = 0
        try:
            sess = self.session_manager.get_session(target)
            if sess is not None:
                sender_tag = getattr(sess, '_sender_tag', 0) or 0
                receiver_tag = getattr(sess, '_receiver_tag', 0) or 0
        except Exception:
            pass
        fragments = self.otr_fragmenter.fragment(otr_message, sender_tag=sender_tag, receiver_tag=receiver_tag)
        _net = NetworkConstants.detect(getattr(self, 'server', ''))
        _is_overlay = _net in (NetworkConstants.NET_I2P, NetworkConstants.NET_TOR)
        _bucket = 4.0
        _prev_ts = time.monotonic()
        ok = True
        for i, frag in enumerate(fragments):
            if len(fragments) > 1 and (not _is_overlay):
                _now = time.monotonic()
                _bucket = min(10.0, _bucket + (_now - _prev_ts) * 1.0)
                if _bucket < 2.0:
                    _wait = 2.0 - _bucket + 0.3
                    time.sleep(_wait)
                    _bucket = min(10.0, _bucket + (2.0 - _bucket) + 0.3)
                _bucket -= 2.0
                _prev_ts = time.monotonic()
            elif len(fragments) > 1 and _is_overlay and (i > 0):
                time.sleep(0.2)
            if not self.send(f'PRIVMSG {target} :{frag}'):
                ok = False
                if len(fragments) > 1:
                    self.add_message(target if target in self.panel_manager.panels else 'system', colorize(f'⚠ Fragment send failed at {i + 1}/{len(fragments)} — /otr {target} to retry', 'yellow'))
                break
        if ok:
            self._last_otr_sent[target] = time.time()
        return ok

    def parse_irc_message(self, line: str):
        prefix = None
        trailing = None
        if line.startswith('@'):
            tags_str, line = line.split(' ', 1)
        if line.startswith(':'):
            parts = line[1:].split(' ', 1)
            prefix = parts[0]
            line = parts[1] if len(parts) > 1 else ''
        if ' :' in line:
            params_str, trailing = line.split(' :', 1)
            params = params_str.strip().split()
        else:
            params = line.split()
        command = params[0] if params else None
        params = params[1:] if params else []
        return (prefix, command, params, trailing)

    def _handle_cap(self, params: List[str], trailing: Optional[str]) -> None:
        if len(params) < 2:
            return
        sub = params[1].upper()
        if sub == 'LS':
            avail = (trailing or '').split()
            wanted = [c for c in IRCConstants.IRCV3_CAPS if c in avail]
            if wanted:
                self.send_raw(f'CAP REQ :{' '.join(wanted)}')
                self.debug('cap_ls', {'available': avail, 'requesting': wanted})
            else:
                self._finish_cap_negotiation()
        elif sub == 'ACK':
            accepted = (trailing or '').split()
            self._cap_accepted.update(accepted)
            self.add_message('system', colorize(f'IRCv3: {', '.join(accepted)}', 'dim'))
            self.debug('cap_ack', {'accepted': accepted})
            if 'sasl' in self._cap_accepted and getattr(self.config, 'sasl_user', None) and getattr(self.config, 'sasl_pass', None):
                self._sasl_in_progress = True
                self.send_raw('AUTHENTICATE PLAIN')
                self.add_message('system', colorize('🔑 SASL PLAIN authentication…', 'cyan'))
            else:
                self._finish_cap_negotiation()
        elif sub == 'NAK':
            self.debug('cap_nak', {'rejected': (trailing or '').split()})
            self._finish_cap_negotiation()

    def _handle_authenticate(self, trailing: Optional[str]) -> None:
        if trailing == '+':
            user = self.config.sasl_user or self.nick
            _pw = self.config.sasl_pass or ''
            import base64 as _b64_sasl
            _plain_ba = bytearray(f'\x00{user}\x00{_pw}'.encode('utf-8'))
            token = _b64_sasl.b64encode(bytes(_plain_ba)).decode('ascii')
            _secure_wipe(_plain_ba)
            del _plain_ba
            self.send_raw(f'AUTHENTICATE {token}')
            self.config.sasl_pass = None
            _pw = None
            del _pw
            self.debug('sasl_auth', {'user': user})

    def _finish_cap_negotiation(self) -> None:
        if getattr(self, '_cap_end_sent', False):
            return
        if getattr(self, '_cap_negotiating', True):
            self._cap_negotiating = False
            self._cap_end_sent = True
            self.send_raw('CAP END')
            self.debug('cap_end', {'accepted': list(getattr(self, '_cap_accepted', set()))})

    def handle_message(self, line: str):
        try:
            prefix, command, params, trailing = self.parse_irc_message(line)
            self.logger.network_message('IN', prefix or 'SERVER', command or '?', len(line))
            self.debug('recv', {'cmd': command, 'params': params[:3], 'trail': (trailing or '')[:120]})
            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return
            if command == 'PING':
                target = trailing or (params[0] if params else 'server')
                self.send(f'PONG :{target}')
                self.last_ping = time.time()
                return
            if command == 'PONG':
                self.last_ping = time.time()
                return
            if command == 'CAP':
                self._handle_cap(params, trailing)
                return
            if command == 'AUTHENTICATE':
                self._handle_authenticate(trailing)
                return
            sender = prefix.split('!')[0] if prefix and '!' in prefix else prefix or 'server'
            if sender in self.ignored_users:
                return
            if command == 'PRIVMSG':
                target = params[0] if params else ''
                message = trailing or ''
                if self.is_ctcp_message(message) and '?OTRv4' not in message:
                    return
                if len(message) > 4096:
                    self.debug(f'oversized PRIVMSG from {sender} dropped ({len(message)} bytes)')
                    return
                self.check_auto_reply(sender, target, message)
                if '?OTRv4' in message:
                    self._dispatch_otr_fragment(sender, message)
                else:
                    _now = time.time()
                    if not hasattr(self, '_msg_rate'):
                        self._msg_rate: dict = {}
                    _bucket = self._msg_rate.get(sender, (0, 0.0))
                    _count, _window_start = _bucket
                    if _now - _window_start > 10.4:
                        _count, _window_start = (0, _now)
                    _count += 1
                    self._msg_rate[sender] = (_count, _window_start)
                    if _count > 50:
                        self.debug(f'plaintext flood from {sender} — dropping ({_count} msgs/10s)')
                    else:
                        self._display_plaintext(sender, target, message)
                return
            if command == 'JOIN':
                channel = trailing or (params[0] if params else '')
                if not channel or len(channel) > 64 or '\r' in channel or ('\n' in channel):
                    return
                if sender == self.nick:
                    if channel not in self.panel_manager.panels:
                        self.panel_manager.add_panel(channel, 'channel')
                    self._switch_panel(channel)
                    self.channels[channel] = {'users': set(), 'topic': ''}
                    self.add_message(channel, colorize(f'✅ Joined {_sanitise(channel, 64)}', 'green'))
                elif channel in self.channels:
                    self.channels[channel]['users'].add(sender)
                return
            if command == 'PART':
                channel = params[0] if params else ''
                reason = trailing or ''
                if sender == self.nick:
                    self.add_message('system', f'Left {_sanitise(channel, 64)}')
                    # Remove channel from internal state
                    self.channels.pop(channel, None)
                    # Remove the panel tab and switch to system if it was active
                    if channel in self.panel_manager.panels:
                        was_active = self.panel_manager.active_panel == channel
                        del self.panel_manager.panels[channel]
                        if channel in self.panel_manager.panel_order:
                            self.panel_manager.panel_order.remove(channel)
                        if was_active:
                            self._switch_panel('system')
                        elif getattr(self, '_tui_enabled', False) and self._screen is not None:
                            self._screen.redraw_full()
                        self.panel_manager._render_ui()
                elif channel in self.channels:
                    self.channels[channel]['users'].discard(sender)
                return
            if command == 'QUIT':
                reason = trailing or ''
                for ch, info in self.channels.items():
                    if sender in info['users']:
                        info['users'].discard(sender)
                if self.session_manager.has_session(sender):
                    self._on_peer_disconnected(sender, reason)
                return
            if command == 'NICK':
                new_nick = trailing or (params[0] if params else '')
                if not new_nick or len(new_nick) > 64 or '\r' in new_nick or ('\n' in new_nick):
                    return
                for ch_info in self.channels.values():
                    if sender in ch_info['users']:
                        ch_info['users'].discard(sender)
                        ch_info['users'].add(new_nick)
                if sender == self.nick:
                    self.nick = new_nick
                    self.add_message('system', f'Nick → {colorize_username(_sanitise(new_nick, 64))}')
                return
            if command == 'KICK':
                channel = params[0] if params else ''
                kicked = params[1] if len(params) > 1 else ''
                reason = trailing or ''
                if kicked == self.nick:
                    self.add_message('system', f'❌ Kicked from {_sanitise(channel, 64)}: {_sanitise(reason, 256)}')
                    self.channels.pop(channel, None)
                    if channel in self.panel_manager.panels:
                        was_active = self.panel_manager.active_panel == channel
                        del self.panel_manager.panels[channel]
                        if channel in self.panel_manager.panel_order:
                            self.panel_manager.panel_order.remove(channel)
                        if was_active:
                            self._switch_panel('system')
                        elif getattr(self, '_tui_enabled', False) and self._screen is not None:
                            self._screen.redraw_full()
                        self.panel_manager._render_ui()
                else:
                    self.add_message(channel, f'⚡ {colorize_username(_sanitise(kicked, 64))} kicked: {_sanitise(reason, 256)}')
                return
            if command == 'MODE':
                ch = params[0] if params else ''
                if ch.startswith('#'):
                    self.add_message(ch, f'Mode: {_sanitise(' '.join(params[1:]), 128)}')
                return
            if command == 'NOTICE':
                target = params[0] if params else ''
                message = trailing or ''
                sender_lower = sender.lower() if sender else ''
                if sender_lower == 'nickserv':
                    self.add_message('system', colorize('NickServ', 'bold_cyan') + colorize(': ', 'dim') + colorize(_sanitise(message, 512), 'white'))
                    msg_lower = message.lower()
                    if 'you are now' in msg_lower and 'identified' in msg_lower or 'password accepted' in msg_lower or 'you are successfully identified' in msg_lower:
                        self.nickserv_identified = True
                        self.add_message('system', colorize('✅ NickServ: identified successfully', 'green'))
                    elif 'registered' in msg_lower and ('successfully' in msg_lower or 'is now' in msg_lower):
                        self.nickserv_identified = True
                        self.add_message('system', colorize('✅ NickServ: nick registered successfully', 'green'))
                    elif 'invalid' in msg_lower or 'denied' in msg_lower or 'incorrect' in msg_lower or ('wrong' in msg_lower):
                        self.add_message('system', colorize('❌ NickServ: authentication failed', 'red'))
                elif sender_lower in ('chanserv', 'memoserv', 'operserv'):
                    self.add_message('system', colorize(_sanitise(sender, 64), 'dim') + colorize(': ', 'dim') + colorize(_sanitise(message, 512), 'dim'))
                elif message and (not message.startswith('***')):
                    self.add_message('system', colorize(f'[notice] {_sanitise(sender, 64)}: {_sanitise(message, 512)}', 'dim'))
                return
            if command == 'TOPIC':
                ch = params[0] if params else ''
                topic = trailing or ''
                if ch in self.channels:
                    self.channels[ch]['topic'] = topic
                self.add_message(ch, f'Topic: {_sanitise(topic, 390)}')
                return
        except Exception as exc:
            self.debug(f'handle_message error: {exc}')

    def _handle_unknown_command(self, command: str, params, trailing) -> None:
        pass

    def handle_numeric_reply(self, code: int, params: List[str], trailing: Optional[str]):
        try:
            if code in (900, 903):
                self.nickserv_identified = True
                self.add_message('system', colorize('✅ SASL authentication successful', 'green'))
                if getattr(self, '_sasl_in_progress', False):
                    self._sasl_in_progress = False
                    self._finish_cap_negotiation()
                return
            if code in (902, 904, 905, 906):
                self.add_message('system', colorize(f'⚠ SASL authentication failed (code {code})', 'yellow'))
                if getattr(self, '_sasl_in_progress', False):
                    self._sasl_in_progress = False
                    self._finish_cap_negotiation()
                return
            if code == 1:
                self.auth_complete = True
                welcome_text = trailing or ''
                words = welcome_text.split()
                clean_words = []
                for w in words:
                    if '!' in w or '@' in w:
                        break
                    clean_words.append(w)
                clean = ' '.join(clean_words) if clean_words else welcome_text
                self.add_message('system', colorize(f'✅ {clean}', 'green'))
                self.debug('RPL_WELCOME')
                if self.config.nickserv_login and self.config.nickserv_pass:
                    self.add_message('system', colorize('🔑 Identifying with NickServ…', 'cyan'))
                    _ns_pass = self.config.nickserv_pass
                    self.send(f'PRIVMSG NickServ :IDENTIFY {_ns_pass}')
                    _ns_pass_ba = bytearray(_ns_pass.encode('utf-8'))
                    _secure_wipe(_ns_pass_ba)
                    del _ns_pass, _ns_pass_ba
                    self.config.nickserv_pass = None
                elif self.config.nickserv_register and self.config.nickserv_pass:
                    self.add_message('system', colorize('📝 Registering nick with NickServ…', 'cyan'))
                    _ns_pass = self.config.nickserv_pass
                    self.send(f'PRIVMSG NickServ :REGISTER {_ns_pass} no-email')
                    _ns_pass_ba = bytearray(_ns_pass.encode('utf-8'))
                    _secure_wipe(_ns_pass_ba)
                    del _ns_pass, _ns_pass_ba
                    self.config.nickserv_pass = None
                delay = 3.0 if self.config.nickserv_login or self.config.nickserv_register else 2.0
                threading.Timer(delay, self.auto_join_channel).start()
                return
            if code in (433, 436):
                new_nick = TwentySevenClubNick.generate()
                if new_nick == self.nick:
                    new_nick = self.nick + str(secrets.randbelow(100))
                self.nick = new_nick
                self.realname = TwentySevenClubNick.real_name(self.nick)
                self.send(f'NICK {self.nick}')
                self.add_message('system', f'Nick collision → {colorize_username(self.nick)}')
                return
            if code == 375:
                self._motd_buf = []
                return
            if code == 372:
                if not hasattr(self, '_motd_buf'):
                    self._motd_buf = []
                if trailing:
                    import re as _re_irc
                    line = trailing.lstrip('- ').strip()
                    line = _re_irc.sub('\\x03(?:\\d{1,2}(?:,\\d{1,2})?)?', '', line)
                    line = _re_irc.sub('[\\x02\\x0f\\x16\\x1d\\x1f]', '', line).strip()
                    if line:
                        self._motd_buf.append(line)
                return
            if code == 376:
                buf = getattr(self, '_motd_buf', [])
                if buf:
                    self.add_message('system', colorize('── MOTD ──────────────────────────────────', 'dim'))
                    import re as _re
                    _SECTION_RE = _re.compile('^(?:\\d+[.)]\\s|/|https?://|\\[|[A-Z]{3,}\\s*:)')
                    paragraphs = []
                    current = []
                    for frag in buf:
                        is_new = not current or _SECTION_RE.match(frag) or (len(frag) > 30 and frag[0].isupper() and (not current[-1].endswith(',')))
                        if is_new and current:
                            paragraphs.append(' '.join(current))
                            current = []
                        current.append(frag)
                    if current:
                        paragraphs.append(' '.join(current))
                    for para in paragraphs:
                        if len(para) > 68:
                            for wline in textwrap.wrap(para, width=68, break_long_words=False, break_on_hyphens=False):
                                self.add_message('system', colorize(wline, 'dim'))
                        else:
                            self.add_message('system', colorize(para, 'dim'))
                    self.add_message('system', colorize('──────────────────────────────────────────', 'dim'))
                self._motd_buf = []
                return
            if code in (2, 4, 5, 251, 252, 253, 254, 255, 265, 266, 396):
                return
            if code == 352:
                _who_nick = params[5] if len(params) > 5 else ''
                _who_user = params[2] if len(params) > 2 else ''
                _who_host = params[3] if len(params) > 3 else ''
                _who_flags = params[6] if len(params) > 6 else ''
                _who_real = trailing or ''
                if _who_real and _who_real.startswith('0 '):
                    _who_real = _who_real[2:]
                if not hasattr(self, '_otrv4_users'):
                    self._otrv4_users: Dict[str, bool] = {}
                if _who_nick:
                    self._otrv4_users[_who_nick] = 'OTRv4+' in _who_real
                # Display if user explicitly ran /who
                if getattr(self, '_who_pending', False):
                    _wp2 = self.panel_manager.active_panel or 'system'
                    _otr_mark = colorize(' 🔒', 'blue') if 'OTRv4+' in _who_real else ''
                    self.add_message(_wp2,
                        f'  {colorize(_who_nick or "?", "cyan"):<20}'
                        f'{_sanitise(_who_user + "@" + _who_host, 60):<40}'
                        f'{_who_flags:<4}'
                        f'{_sanitise(_who_real, 40)}{_otr_mark}')
                return
            if code == 303:
                _online = trailing or ''
                _wp5 = self.panel_manager.active_panel or 'system'
                if _online.strip():
                    self.add_message(_wp5, colorize(f'ISON online: {_sanitise(_online, 256)}', 'green'))
                else:
                    self.add_message(_wp5, colorize('ISON: none of those nicks are online', 'dim'))
                return
            if code == 314:
                _ww_nick = params[1] if len(params) > 1 else '?'
                _ww_user = params[2] if len(params) > 2 else ''
                _ww_host = params[3] if len(params) > 3 else ''
                _ww_real = trailing or ''
                _wp4 = self.panel_manager.active_panel or 'system'
                self.add_message(_wp4, colorize('── WHOWAS ───────────────────────────────────', 'dim'))
                self.add_message(_wp4, f'  Nick: {colorize_username(_ww_nick)}  {_sanitise(_ww_user + "@" + _ww_host, 80)}  {_sanitise(_ww_real, 60)}')
                return
            if code == 315:
                if getattr(self, '_who_pending', False):
                    _wp3 = self.panel_manager.active_panel or 'system'
                    self.add_message(_wp3, colorize('────────────────────────────────────────────────────────', 'dim'))
                    self._who_pending = False
                return
            if code == 332:
                channel = params[1] if len(params) > 1 else ''
                topic = trailing or ''
                if channel in self.channels:
                    self.channels[channel]['topic'] = topic
                self.add_message(channel or 'system', f'Topic: {topic}')
                return
            if code == 353:
                channel = params[2] if len(params) > 2 else ''
                users = trailing.split() if trailing else []
                if channel not in self.names_data:
                    self.names_data[channel] = []
                self.names_data[channel].extend(users)
                if channel in self.channels:
                    for u in users:
                        self.channels[channel]['users'].add(u.lstrip('@+&~'))
                return
            if code == 366:
                channel = params[1] if len(params) > 1 else ''
                if getattr(self, '_pending_names_pager', None) == channel:
                    self._pending_names_pager = None
                    raw_users = self.names_data.get(channel, [])
                    ops = []
                    voiced = []
                    regular = []
                    for u in raw_users:
                        prefix = u[0] if u and u[0] in '@+~&%' else ''
                        nick = u.lstrip('@+~&%')
                        if prefix in ('@', '~', '&'):
                            ops.append((prefix, nick))
                        elif prefix in ('+', '%'):
                            voiced.append((prefix, nick))
                        else:
                            regular.append(('', nick))
                    ops.sort(key=lambda x: x[1].lower())
                    voiced.sort(key=lambda x: x[1].lower())
                    regular.sort(key=lambda x: x[1].lower())
                    total = len(raw_users)
                    _otrv4_map = getattr(self, '_otrv4_users', {})
                    _otr_count = sum(1 for _, n in ops + voiced + regular if _otrv4_map.get(n))
                    _pager_lines = []
                    if _otr_count:
                        _pager_lines.append(colorize(f'  🔒 = OTRv4+ ({_otr_count} user(s)) — /otr <nick> to encrypt', 'blue'))
                    col_width = 20
                    _ncols = max(1, 56 // col_width)
                    def _group_lines(label, users, color):
                        if not users:
                            return
                        _pager_lines.append(colorize(f'  {label} ({len(users)}):', color))
                        row = []
                        for pfx, nk in users:
                            disp = f'{pfx}{nk}'
                            entry = colorize(f'  🔒{disp:<{col_width-1}}', 'blue') if _otrv4_map.get(nk) else colorize(f'  {disp:<{col_width}}', color)
                            row.append(entry)
                            if len(row) >= _ncols:
                                _pager_lines.append(''.join(row))
                                row = []
                        if row:
                            _pager_lines.append(''.join(row))
                    _group_lines('Operators', ops, 'bold_green')
                    _group_lines('Voiced', voiced, 'yellow')
                    _group_lines('Users', regular, 'white')
                    self.names_data[channel] = []
                    self.pager.display(_pager_lines, f'Users in {_sanitise(channel, 64)} ({total})')
                    if hasattr(self, '_prompt_refresh_cb') and self._prompt_refresh_cb:
                        self._prompt_refresh_cb()
                return
            if code == 311:
                target = params[1] if len(params) > 1 else ''
                user = params[2] if len(params) > 2 else ''
                host = params[3] if len(params) > 3 else ''
                real = trailing or ''
                display_real = TwentySevenClubNick.real_name(target)
                if display_real == target:
                    display_real = real
                _wp = self.panel_manager.active_panel or 'system'
                self._whois_panel = _wp
                self.add_message(_wp, colorize('── WHOIS ─────────────────────────────────', 'dim'))
                self.add_message(_wp, f'  Nick     : {colorize_username(target)}')
                self.add_message(_wp, f'  Client   : {colorize(VERSION, "cyan")}')
                self.add_message(_wp, f'  User     : {_sanitise(user, 64)}@{_sanitise(host, 128)}')
                self.add_message(_wp, f'  Name     : {_sanitise(display_real, 128)}')
                return
            if code == 312:
                target = params[1] if len(params) > 1 else ''
                server = params[2] if len(params) > 2 else ''
                info = trailing or ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Server   : {_sanitise(server, 128)}' + (f' ({_sanitise(info, 256)})' if info else ''))
                return
            if code == 313:
                target = params[1] if len(params) > 1 else ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Status   : {colorize('IRC Operator', 'yellow')}')
                return
            if code == 319:
                target = params[1] if len(params) > 1 else ''
                chans = trailing or ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Channels : {_sanitise(chans, 512)}')
                return
            if code == 317:
                target = params[1] if len(params) > 1 else ''
                idle_s = int(params[2]) if len(params) > 2 and params[2].isdigit() else 0
                signon = int(params[3]) if len(params) > 3 and params[3].isdigit() else 0
                idle_str = _fmt_duration(idle_s)
                if signon > 0:
                    import datetime as _dtmod
                    signon_str = _dtmod.datetime.fromtimestamp(signon).strftime('%Y-%m-%d %H:%M:%S')
                    self.add_message(getattr(self,'_whois_panel','system'), f'  Idle     : {idle_str}')
                    self.add_message(getattr(self,'_whois_panel','system'), f'  Signon   : {signon_str}')
                else:
                    self.add_message('system', f'  Idle     : {idle_str}')
                return
            if code == 301:
                target = params[1] if len(params) > 1 else ''
                away = trailing or ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Away     : {colorize(_sanitise(away, 256), 'yellow')}')
                return
            if code == 671:
                target = params[1] if len(params) > 1 else ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Secure   : {colorize('Yes (TLS)', 'green')}')
                return
            if code == 330:
                target = params[1] if len(params) > 1 else ''
                account = params[2] if len(params) > 2 else ''
                self.add_message(getattr(self,'_whois_panel','system'), f'  Account  : {_sanitise(account, 64)}')
                return
            if code == 318:
                self.add_message(getattr(self,'_whois_panel','system'), colorize('──────────────────────────────────────────', 'dim'))
                return
            if code == 321:
                self.channel_list = []
            elif code == 322:
                if len(params) >= 3:
                    self.channel_list.append({'channel': _sanitise(params[1], 64), 'users': int(params[2]) if params[2].isdigit() else 0, 'topic': _sanitise((trailing or '')[:60], 60)})
            elif code == 323:
                lines = [f'{colorize(c['channel'], 'green'):<20} {c['users']:>4} users  {colorize(_sanitise(c['topic'], 256), 'dim')}' for c in sorted(self.channel_list, key=lambda x: x['users'], reverse=True)]
                self.pager.display(lines, 'Channel list', f'{len(lines)} channels')
            elif code == 401:
                target = params[1] if len(params) > 1 else params[0] if params else ''
                if target and self.session_manager.has_session(target):
                    sess = self.session_manager.get_session(target)
                    state = getattr(sess, 'session_state', None) if sess else None
                    if not hasattr(self, '_401_count'):
                        self._401_count = {}
                    if not hasattr(self, '_401_handled'):
                        self._401_handled = set()
                    self._401_count[target] = self._401_count.get(target, 0) + 1
                    state_name = getattr(state, 'name', str(state)) if state is not None else ''
                    is_dake_phase = state_name in ('DAKE_IN_PROGRESS', 'CREATED', 'PLAINTEXT')
                    if is_dake_phase and self._401_count[target] < 5:
                        self.debug('401 during DAKE', {'peer': target, 'state': state_name, 'count': self._401_count[target]})
                    elif target not in self._401_handled:
                        self._401_handled.add(target)
                        self._on_peer_disconnected(target, 'nick no longer on server')
                elif trailing:
                    self.add_message('system', colorize(f'⚠ {_sanitise(trailing, 512)}', 'dim'))
            elif trailing:
                self.add_message('system', colorize(trailing, 'dim'))
        except Exception as exc:
            self.debug(f'numeric reply error code={code}: {exc}')

    def _dispatch_otr_fragment(self, sender: str, fragment: str):
        if sender not in self.fragment_buffers:
            buf = OTRFragmentBuffer(timeout=self.config.fragment_timeout)

            def _on_first_fragment(s: str, n: int, chunk: str='') -> None:
                try:
                    buf.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT
                    msg_type = None
                    try:
                        import base64 as _b64
                        peek = _b64.b64decode(chunk[:20] + '==')
                        if len(peek) >= 3 and peek[0] == 0 and (peek[1] == 4):
                            msg_type = 'data'
                        elif len(peek) >= 1:
                            msg_type = {53: 'dake1', 54: 'dake2', 55: 'dake3'}.get(peek[0])
                    except Exception:
                        pass
                    if s not in self.panel_manager.panels:
                        self.panel_manager.add_panel(s, 'private')
                    if msg_type == 'data' and self.session_manager.has_session(s):
                        buf.max_fragments_per_sender = UIConstants.SMP_FRAGMENT_LIMIT
                    _should_switch = msg_type in ('dake1', 'dake2', 'dake3') or not self.session_manager.has_session(s)
                    if _should_switch:
                        _cur = self.panel_manager.active_panel
                        _cur_panel = self.panel_manager.panels.get(_cur)
                        _in_channel = _cur is None or (_cur_panel is not None and _cur_panel.type in ('channel', 'system')) or _cur == s
                        if _in_channel or _cur == s:
                            self._switch_panel(s)
                    if msg_type == 'dake1' or not self.session_manager.has_session(s):
                        notice = colorize(f'🔑 {colorize_username(s)} is requesting an OTR session…', 'cyan')
                        self.add_message(s, notice)
                        self._termux_fire(['--title', '🔑 OTR request', '--content', f'{s} is requesting an encrypted session', '--priority', 'high', '--id', f'otrv4_{s}_incoming', '--vibrate', '0,150,100,150'])
                except Exception:
                    pass
            buf.first_fragment_cb = _on_first_fragment
            self.fragment_buffers[sender] = buf
        try:
            complete = self.fragment_buffers[sender].add_fragment(sender, fragment)
        except ValueError as exc:
            self.debug(f'fragment error from {sender}: {exc}')
            return
        if complete:
            self.process_otr_payload(sender, complete)

    def process_otr_payload(self, sender: str, payload: str):
        self.debug('otr payload', {'sender': sender, 'len': len(payload)})
        try:
            if not payload.startswith('?OTRv4 '):
                return
            raw = payload[7:].strip()
            if not raw:
                return
            decoded = _safe_b64decode(raw)
            if not decoded:
                return
            if len(decoded) >= 3 and decoded[0] == 0 and (decoded[1] == 4) and (decoded[2] == OTRv4DataMessage.TYPE):
                self._handle_data_message(sender, payload)
                return
            msg_type = decoded[0]
            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, payload)
        except Exception as exc:
            self.debug(f'otr payload error: {exc}')

    def _handle_data_message(self, sender: str, payload: str):
        if not self.session_manager.has_session(sender):
            return
        self.last_ping = time.time()

        def _do_decrypt():
            try:
                self.last_ping = time.time()
                result = self.session_manager.decrypt_message(sender, payload)
                if result is None:
                    return
                text = result if isinstance(result, str) else result.decode('utf-8', errors='replace')
                self.last_ping = time.time()
                if text.startswith('?OTRv4 '):
                    self.send_otr_message(sender, text)
                    self.last_ping = time.time()
                    return
                sec = self.session_manager.get_security_level(sender)
                if text.strip():
                    self.add_message(sender, f'{colorize_username(sender)}: {text}', sec)
                self.panel_manager.update_panel_security(sender, sec)
                self.panel_manager.update_smp_progress(sender, *self.session_manager.get_smp_progress(sender))
            except Exception as exc:
                self.debug(f'data decrypt error from {sender}: {exc}')
        try:
            self._smp_executor.submit(_do_decrypt)
        except RuntimeError:
            _do_decrypt()

    def _display_plaintext(self, sender: str, target: str, message: str):
        _OTR_PROTO_MARKERS = ('?OTRv4', '?OTR', 'otrv4_smp', 'otrv4:')
        if any((message.startswith(m) for m in _OTR_PROTO_MARKERS)):
            self._dispatch_otr_fragment(sender, message)
            return
        # Handle CTCP ACTION (/me)
        if message.startswith('\x01ACTION ') and message.endswith('\x01'):
            _action_text = _sanitise(message[8:-1], 490)
            panel = target if target.startswith('#') else sender
            self.add_message(panel, colorize(f'* {sender} {_action_text}', 'cyan'))
            return
        panel = target if target.startswith('#') else sender
        _safe_msg = _sanitise(message, 512)
        self.add_message(panel, colorize_username(sender) + colorize(':', 'dim') + f' {colorize(_safe_msg, 'white')}')
        if not target.startswith('#'):
            _active = self.panel_manager.active_panel
            if _active and _active != panel and (_active not in ('system', 'debug')):
                _hint = colorize(f'💬 PM from {sender} — /switch {sender} to view', 'yellow')
                self._emit(_active, _hint)

    def process_dake1(self, sender: str, payload: str):
        active = self.panel_manager.active_panel
        alert = colorize(f'🔑 OTR request from {_sanitise(sender, 64)} — switching to their tab…', 'cyan')
        if active:
            self.add_message(active, alert)
        else:
            self.add_message('system', alert)
        self._route_otr_to_session_manager(sender, payload, 'DAKE1', is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        pass

    def process_dake3(self, sender: str, payload: str):
        pass

    def process_smp_message(self, sender: str, data: bytes):
        pass

    def auto_join_channel(self):
        if not self.auto_joined and self.connected:
            rejoin = getattr(self, '_rejoin_channels', [])
            if rejoin:
                channels_to_join = rejoin
                self._rejoin_channels = []
            else:
                channels_to_join = [self.config.channel]
            seen = set()
            ordered = []
            for ch in channels_to_join:
                if ch.lower() not in seen:
                    seen.add(ch.lower())
                    ordered.append(ch)
            if self.config.channel.lower() not in seen:
                ordered.insert(0, self.config.channel)
            for ch in ordered:
                self.send(f'JOIN {ch}')
                self.add_message('system', f'Auto-joining {colorize(ch, 'cyan')}…')
                self.debug('auto_join', {'channel': ch})
            self.auto_joined = True
            self.connection_attempts = 0
            peers = [name for name, p in self.panel_manager.panels.items() if not name.startswith('#') and name not in ('system', 'debug') and p.history]
            if peers:
                self.add_message('system', colorize('⚠ OTR sessions lost on reconnect — ' + ', '.join((f'/otr {p}' for p in peers)), 'yellow'))

    def start_auto_smp_monitor(self):
        if self.auto_smp_monitor_running:
            return
        self.auto_smp_monitor_running = True

        def _monitor():
            while self.running and (not self.shutdown_flag):
                now = time.time()
                due = [peer for peer, info in list(self.smp_schedule_timers.items()) if info.get('scheduled') and now >= info.get('when', 0)]
                for peer in due:
                    del self.smp_schedule_timers[peer]
                    try:
                        self._fire_auto_smp(peer)
                    except Exception as exc:
                        self.debug(f'auto_smp error: {exc}')
                time.sleep(1)
        threading.Thread(target=_monitor, daemon=True, name='smp-monitor').start()

    def _fire_auto_smp(self, peer: str):
        secret = self.session_manager.smp_storage.get_secret(peer) if hasattr(self.session_manager, 'smp_storage') else ''
        if not secret:
            return
        try:
            tlv = self.session_manager.start_smp(peer, secret)
            if tlv:
                enc = self.session_manager.encrypt_message(peer, '')
                if enc:
                    self.send_otr_message(peer, enc)
        finally:
            secret = None

    def schedule_auto_smp(self, peer: str, delay: float=2.0):
        if peer not in self.smp_schedule_timers:
            self.smp_schedule_timers[peer] = {'when': time.time() + delay, 'scheduled': True}

    def clear_pending_smp(self, peer: str):
        self.smp_schedule_timers.pop(peer, None)

    def add_message(self, target: str, message: str, security_level: Optional[UIConstants.SecurityLevel]=None, is_initiator: Optional[bool]=None):
        if target in self.ignored_users:
            return
        if security_level is None:
            if not target.startswith('#'):
                if self.session_manager.has_session(target):
                    security_level = self.session_manager.get_security_level(target)
                elif target in self.panel_manager.panels:
                    security_level = self.panel_manager.panels[target].security_level
        icon = UIConstants.SECURITY_ICONS.get(security_level, '') if security_level else ''
        if icon and (not message.startswith(icon)):
            message = f'{icon}{message}'
        self._emit(target, message)
        if security_level is not None:
            self.panel_manager.update_panel_security(target, security_level)
    # Block incoming CTCP requests that leak info or enable attacks.
    # DCC: IP exposure. VERSION/FINGER/USERINFO: fingerprinting.
    # PING/TIME: timing/timezone attacks. ACTION is exempted — it's display content.
    _CTCP_BLOCKED = frozenset({'VERSION', 'FINGER', 'USERINFO', 'CLIENTINFO', 'DCC', 'PING', 'TIME', 'SOURCE'})

    def is_ctcp_message(self, message: str) -> bool:
        if message.startswith('?OTRv4'):
            return False
        if message.startswith('\x01') and message.endswith('\x01'):
            cmd = message[1:-1].split()[0].upper() if message[1:-1].split() else ''
            # ACTION is display content (/me), not a request — let it through
            if cmd == 'ACTION':
                return False
            return True
        return False

    def check_auto_reply(self, sender: str, target: str, message: str):
        if sender == self.nick or sender not in self.auto_reply_config:
            return
        cfg = self.auto_reply_config[sender]
        if 'channels' in cfg and cfg['channels'] and (target not in cfg['channels']):
            return
        reply = cfg.get('message', '')
        if reply:
            dest = sender if target == self.nick else target

            def _send_reply(d=dest, r=reply):
                self.send(f'PRIVMSG {d} :{r}')
                self.add_message(d, f'{colorize_username(self.nick)}: {r}')
            threading.Timer(0.3, _send_reply).start()

    def _switch_panel(self, name: str) -> bool:
        if name not in self.panel_manager.panels:
            return False
        self.panel_manager.switch_to_panel(name)
        if getattr(self, '_tui_enabled', False) and self._screen is not None:
            self._screen.scroll_offset = 0
            self._screen.redraw_full()
            if self._prompt_refresh_cb is not None:
                self._prompt_refresh_cb()
            return True
        panel = self.panel_manager.panels[name]
        if name == 'system':
            tag = colorize('[sys]  ', 'dim')
        elif name == 'debug':
            tag = colorize('[debug]', 'magenta')
        elif name.startswith('#'):
            tag = colorize(f'[{name}]', 'cyan')
        else:
            tag = colorize(f'[{name}]', 'green')
        icon = UIConstants.SECURITY_ICONS.get(panel.security_level, '')
        width = 46
        hdr_name = f' {icon}{name} '
        dashes = max(0, width - len(hdr_name))
        left = dashes // 2
        right = dashes - left
        # Write the entire history replay atomically under _print_lock so:
        # 1. The recv thread cannot interleave mid-replay
        # 2. The prompt is reprinted exactly once at the end, not after
        #    every line (which caused the prompt to appear mid-screen on
        #    slow terminals and when switching between busy channels)
        lines_out = [colorize('─' * left + hdr_name + '─' * right, 'cyan')]
        history = panel.history
        if not history:
            lines_out.append(colorize('  (no messages yet)', 'dim'))
        else:
            for entry in history:
                ts = colorize(time.strftime('%H:%M:%S', time.localtime(entry['timestamp'])), 'dim')
                lines_out.append(f'{ts} {tag} {entry["message"]}')
        lines_out.append(colorize('─' * left + ' live ' + '─' * max(0, right - 1), 'dim'))
        with _print_lock:
            try:
                buf = ''.join(_input_buffer)
                if _current_prompt or buf:
                    sys.stdout.write('\x1b[1G\x1b[2K')
                for ln in lines_out:
                    wrapped = _word_wrap(ln, shutil.get_terminal_size(fallback=(80,24)).columns)
                    sys.stdout.write(wrapped + '\n')
                if _current_prompt or buf:
                    sys.stdout.write(_current_prompt + buf)
                sys.stdout.flush()
            except (RuntimeError, ValueError, OSError):
                pass
        return True

    def get_timestamp(self) -> str:
        return time.strftime('%H:%M:%S')

    def clear_screen(self):
        if IS_TERMUX:
            safe_print('\n' * 60)
        else:
            self.panel_manager._render_ui()

    def switch_to_next_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else -1
        self._switch_panel(order[(idx + 1) % len(order)])

    def switch_to_previous_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else 0
        self._switch_panel(order[(idx - 1) % len(order)])

    def show_tabs(self):
        self.add_message('system', colorize('─── Tabs ───────────────────────────────────', 'cyan'))
        for i, name in enumerate(self.panel_manager.panel_order):
            p = self.panel_manager.panels[name]
            is_active = name == self.panel_manager.active_panel
            marker = colorize('▶', 'green') if is_active else ' '
            icon = UIConstants.SECURITY_ICONS.get(p.security_level, '')
            badge = colorize(f' [{p.unread_count} new]', 'yellow') if p.unread_count else ''
            name_col = colorize(name, 'green' if is_active else 'white')
            self.add_message('system', f'  {marker} {i + 1:2d}.  {icon}{name_col}{badge}')
        self.add_message('system', colorize('  /switch <name>  /tab-next  /tab-prev', 'dim'))

    def show_status_panel(self):
        self.add_message('system', colorize('── Client Status ─────────────────────────', 'cyan'))
        conn_str = colorize('YES', 'green') if self.connected else colorize('NO', 'red')
        uptime = ''
        if self.connected and hasattr(self, 'connected_at'):
            uptime = f'  ({_fmt_duration(time.time() - self.connected_at)})'
        self.add_message('system', f'  Connected : {conn_str}{uptime}')
        self.add_message('system', f'  Server    : {self.server}')
        self.add_message('system', f'  Nick      : {colorize_username(self.nick)}')
        real = TwentySevenClubNick.real_name(self.nick)
        if real != self.nick:
            self.add_message('system', f'  Identity  : {real}')
        ns_status = ''
        if self.nickserv_identified:
            ns_status = colorize('  (NickServ ✓)', 'green')
        elif self.config.nickserv_login or self.config.nickserv_register:
            ns_status = colorize('  (NickServ pending)', 'yellow')
        self.add_message('system', f'  IRC ready : {(colorize('YES', 'green') if self.auth_complete else colorize('NO', 'yellow'))}{ns_status}')
        self.add_message('system', f'  Channels  : {len(self.channels)}')
        self.add_message('system', f'  OTR sess  : {len(self.session_manager.sessions)}')
        self.add_message('system', colorize('──────────────────────────────────────────', 'cyan'))

    def handle_chat_message(self, msg: str):
        if not self.connected:
            self.add_message('system', colorize('Not connected', 'red'))
            return
        active = self.panel_manager.get_active_panel()
        if not active or active.type in ('system', 'debug'):
            self.add_message('system', colorize('Switch to a chat panel first', 'red'))
            return
        target = active.name
        if self.session_manager.has_session(target):
            enc = self.session_manager.encrypt_message(target, msg)
            if enc and self.send_otr_message(target, enc):
                sec = self.session_manager.get_security_level(target)
                self.add_message(target, colorize_username(self.nick) + colorize(': ', 'dim') + colorize(msg, 'white'), sec)
            else:
                self.add_message('system', colorize('❌ Encryption failed', 'red'))
        elif self.send(f'PRIVMSG {target} :{msg}'):
            self.add_message(target, colorize_username(self.nick) + colorize(': ', 'dim') + colorize(msg, 'white'))

    def handle_command(self, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()
        if cmd == 'help':
            topic = parts[1] if len(parts) > 1 else None
            self.show_help(topic)
        elif cmd == 'tui':
            arg = parts[1].lower() if len(parts) > 1 else 'toggle'
            if arg in ('on', '1', 'yes'):
                want = True
            elif arg in ('off', '0', 'no'):
                want = False
            else:
                want = not self._tui_enabled
            self._tui_enabled = want
            if want:
                if self._screen is None:
                    self._screen = Screen(self)
                self._screen.scroll_offset = 0
                self._screen.redraw_full()
            else:
                with _print_lock:
                    sys.stdout.write('\x1b[2J\x1b[H')
                    sys.stdout.flush()
                self.add_message('system', colorize('TUI off — back to scrollback mode.', 'dim'))
                if self._prompt_refresh_cb is not None:
                    self._prompt_refresh_cb()
        elif cmd == 'join' and len(parts) > 1:
            # Support: /join ch1, ch2, ch3  or  /join ch1 ch2 ch3
            _raw = ' '.join(parts[1:]).replace(',', ' ')
            for _ch in _raw.split():
                _ch = _ch.strip()
                if not _ch:
                    continue
                if not _ch.startswith('#'):
                    _ch = '#' + _ch
                self.send(f'JOIN {_ch}')
        elif cmd == 'part':
            ch = parts[1] if len(parts) > 1 else self.panel_manager.active_panel or ''
            if ch:
                if ch and (not ch.startswith('#')):
                    ch = '#' + ch
                self.send(f'PART {ch}')
        elif cmd == 'nick' and len(parts) > 1:
            _new_nick = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            if _new_nick:
                self.send(f'NICK {_new_nick}')
        elif cmd == 'msg' and len(parts) > 2:
            _msg_target = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            _msg_text = _sanitise(' '.join(parts[2:]), 490)
            if _msg_target:
                self.send(f'PRIVMSG {_msg_target} :{_msg_text}')
                self.add_message(_msg_target, colorize_username(self.nick) + colorize(': ', 'dim') + colorize(_msg_text, 'white'))
        elif cmd == 'list':
            self.send('LIST')
        elif cmd == 'whois' and len(parts) > 1:
            _whois_nick = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            if _whois_nick:
                self.send(f'WHOIS {_whois_nick}')
        elif cmd == 'names':
            ch = parts[1] if len(parts) > 1 else self.panel_manager.active_panel or ''
            if ch and (not ch.startswith('#')):
                ch = '#' + ch
            if ch and ch.startswith('#'):
                self.names_data[ch] = []
                if not hasattr(self, '_otrv4_users'):
                    self._otrv4_users: Dict[str, bool] = {}
                self.send(f'WHO {ch}')
                self.send(f'NAMES {ch}')
                self._pending_names_pager = ch
            else:
                self.add_message('system', colorize('Usage: /names [#channel]', 'dim'))
        elif cmd == 'topic':
            ch = self.panel_manager.active_panel or ''
            if len(parts) > 1 and parts[1].startswith('#'):
                ch = parts[1]
                new_topic = ' '.join(parts[2:]) if len(parts) > 2 else ''
            else:
                new_topic = ' '.join(parts[1:]) if len(parts) > 1 else ''
            if new_topic:
                self.send(f'TOPIC {ch} :{new_topic}')
            else:
                self.send(f'TOPIC {ch}')
        elif cmd == 'notice' and len(parts) > 2:
            target = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            text = _sanitise(' '.join(parts[2:]), 490)
            if target:
                self.send(f'NOTICE {target} :{text}')
        elif cmd == 'invite' and len(parts) > 2:
            _inv_nick = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            _inv_chan = parts[2] if parts[2].startswith('#') else '#' + parts[2]
            _inv_chan = _sanitise(_inv_chan, 64).split()[0] if _sanitise(_inv_chan, 64).split() else ''
            if _inv_nick and _inv_chan:
                self.send(f'INVITE {_inv_nick} {_inv_chan}')
        elif cmd == 'kick' and len(parts) > 1:
            ch = self.panel_manager.active_panel or ''
            target = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ''
            reason = _sanitise(' '.join(parts[2:]), 256) if len(parts) > 2 else ''
            if ch.startswith('#') and target:
                self.send(f'KICK {ch} {target}' + (f' :{reason}' if reason else ''))
            elif not target:
                self.add_message('system', colorize('Usage: /kick <nick> [reason]', 'dim'))
            else:
                self.add_message('system', colorize('Must be in a channel to kick', 'red'))
        elif cmd == 'mode':
            if len(parts) > 1:
                _mode_args = [_sanitise(p, 64).split()[0] for p in parts[1:] if _sanitise(p, 64).split()]
                if _mode_args:
                    self.send(f'MODE {' '.join(_mode_args)}')
            else:
                self.add_message('system', colorize('Usage: /mode <target> <+/-flag>', 'dim'))
                self.add_message('system', '  Type /help mode for all available modes')
        elif cmd == 'away':
            reason = ' '.join(parts[1:]) if len(parts) > 1 else 'Away'
            self.send(f'AWAY :{reason}')
            self.add_message('system', colorize(f'Set away: {reason}', 'dim'))
        elif cmd == 'back':
            self.send('AWAY')
            self.add_message('system', colorize('No longer away', 'green'))
        elif cmd == 'raw' and len(parts) > 1:
            self.send(' '.join(parts[1:]))
        elif cmd == 'who':
            target = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or '')
            if target and not target.startswith('#'):
                target = '#' + target
            if target:
                self.send(f'WHO {target}')
            else:
                self.send('WHO')
            self._who_pending = True
            _who_header = self.panel_manager.active_panel or 'system'
            self.add_message(_who_header, colorize('── WHO ──────────────────────────────────────────────────', 'dim'))
        elif cmd == 'whowas' and len(parts) > 1:
            _ww = _sanitise(parts[1], 64).split()[0]
            if _ww:
                self.send(f'WHOWAS {_ww}')
        elif cmd == 'ison' and len(parts) > 1:
            nicks = ' '.join(_sanitise(p, 64) for p in parts[1:])
            self.send(f'ISON {nicks}')
        elif cmd == 'userhost' and len(parts) > 1:
            nicks = ' '.join(_sanitise(p, 64) for p in parts[1:6])
            self.send(f'USERHOST {nicks}')
        elif cmd == 'motd':
            self.send('MOTD')
        elif cmd == 'time':
            self.send('TIME')
        elif cmd == 'me' and len(parts) > 1:
            _me_text = _sanitise(' '.join(parts[1:]), 490)
            _me_target = self.panel_manager.active_panel or ''
            if _me_target and _me_target not in ('system', 'debug'):
                self.send(f'PRIVMSG {_me_target} :\x01ACTION {_me_text}\x01')
                self.add_message(_me_target, colorize(f'* {self.nick} {_me_text}', 'cyan'))
        elif cmd == 'ctcp' and len(parts) > 2:
            _ctcp_target = _sanitise(parts[1], 64).split()[0]
            _ctcp_cmd = _sanitise(parts[2], 32).upper()
            _ctcp_args = (' ' + _sanitise(' '.join(parts[3:]), 400)) if len(parts) > 3 else ''
            if _ctcp_target:
                self.send(f'PRIVMSG {_ctcp_target} :\x01{_ctcp_cmd}{_ctcp_args}\x01')
        elif cmd == 'cycle':
            _cyc = parts[1] if len(parts) > 1 else self.panel_manager.active_panel or ''
            if _cyc and not _cyc.startswith('#'):
                _cyc = '#' + _cyc
            if _cyc:
                self.send(f'PART {_cyc} :cycling')
                import time as _t; _t.sleep(0.5)
                self.send(f'JOIN {_cyc}')
        elif cmd == 'op' and len(parts) > 1:
            _op_ch = self.panel_manager.active_panel or ''
            _op_nicks = ' '.join(parts[1:])
            if _op_ch.startswith('#'):
                _flags = '+' + 'o' * len(parts[1:])
                self.send(f'MODE {_op_ch} {_flags} {_op_nicks}')
        elif cmd == 'deop' and len(parts) > 1:
            _op_ch = self.panel_manager.active_panel or ''
            _op_nicks = ' '.join(parts[1:])
            if _op_ch.startswith('#'):
                _flags = '-' + 'o' * len(parts[1:])
                self.send(f'MODE {_op_ch} {_flags} {_op_nicks}')
        elif cmd == 'voice' and len(parts) > 1:
            _v_ch = self.panel_manager.active_panel or ''
            _v_nicks = ' '.join(parts[1:])
            if _v_ch.startswith('#'):
                _flags = '+' + 'v' * len(parts[1:])
                self.send(f'MODE {_v_ch} {_flags} {_v_nicks}')
        elif cmd == 'devoice' and len(parts) > 1:
            _v_ch = self.panel_manager.active_panel or ''
            _v_nicks = ' '.join(parts[1:])
            if _v_ch.startswith('#'):
                _flags = '-' + 'v' * len(parts[1:])
                self.send(f'MODE {_v_ch} {_flags} {_v_nicks}')
        elif cmd == 'ban' and len(parts) > 1:
            _ban_ch = self.panel_manager.active_panel or ''
            _ban_mask = _sanitise(parts[1], 128)
            if _ban_ch.startswith('#'):
                self.send(f'MODE {_ban_ch} +b {_ban_mask}')
        elif cmd == 'unban' and len(parts) > 1:
            _ban_ch = self.panel_manager.active_panel or ''
            _ban_mask = _sanitise(parts[1], 128)
            if _ban_ch.startswith('#'):
                self.send(f'MODE {_ban_ch} -b {_ban_mask}')
        elif cmd == 'kickban' and len(parts) > 1:
            _kb_ch = self.panel_manager.active_panel or ''
            _kb_nick = _sanitise(parts[1], 64).split()[0]
            _kb_reason = _sanitise(' '.join(parts[2:]), 200) if len(parts) > 2 else 'banned'
            if _kb_ch.startswith('#') and _kb_nick:
                self.send(f'MODE {_kb_ch} +b {_kb_nick}!*@*')
                self.send(f'KICK {_kb_ch} {_kb_nick} :{_kb_reason}')
        elif cmd == 'accept' and len(parts) > 1:
            # IRCv3 +g caller-ID: /accept nick or /accept -nick to remove
            _acc = _sanitise(parts[1], 64)
            self.send(f'ACCEPT {_acc}')
        elif cmd == 'monitor' and len(parts) > 1:
            # IRCv3 MONITOR: /monitor + nick  /monitor - nick  /monitor l (list)
            _mon_op = parts[1]
            if _mon_op == 'l':
                self.send('MONITOR L')
            elif len(parts) > 2:
                _mon_nicks = ','.join(_sanitise(p, 64) for p in parts[2:])
                self.send(f'MONITOR {_mon_op.upper()} {_mon_nicks}')
        elif cmd == 'setname' and len(parts) > 1:
            # IRCv3 SETNAME — change displayed realname
            _sn = _sanitise(' '.join(parts[1:]), 128)
            self.send(f'SETNAME :{_sn}')
        elif cmd == 'server' and len(parts) > 1:
            _srv = _sanitise(parts[1], 256).split()[0]
            _port_str = parts[2] if len(parts) > 2 else ''
            try:
                _p = int(_port_str) if _port_str else self.config.port
            except ValueError:
                _p = self.config.port
            if _srv:
                self.config.server = _srv
                self.config.port = _p
                self.server = _srv
                self.add_message('system', colorize(f'Switching to {_srv}:{_p}…', 'cyan'))
                self._request_reconnect()
        elif cmd in ('switch', 'tab') and len(parts) > 1:
            _sw_name = parts[1]
            if not self._switch_panel(_sw_name):
                _sw_hashed = '#' + _sw_name if not _sw_name.startswith('#') else _sw_name
                if not self._switch_panel(_sw_hashed):
                    self.add_message('system', colorize(f'❌ No panel: {_sw_name}', 'red'))
        elif cmd == 'tabs':
            self.show_tabs()
        elif cmd == 'tab-next':
            self.switch_to_next_tab()
        elif cmd == 'tab-prev':
            self.switch_to_previous_tab()
        elif cmd == 'tab-close' and len(parts) > 1:
            p = parts[1]
            if p in ('system', 'debug'):
                return
            if p not in self.panel_manager.panels and (not p.startswith('#')):
                p = '#' + p
            if p in self.panel_manager.panels:
                if self.panel_manager.active_panel == p:
                    self._switch_panel('system')
                del self.panel_manager.panels[p]
                if p in self.panel_manager.panel_order:
                    self.panel_manager.panel_order.remove(p)
                self.panel_manager._render_ui()
        elif cmd == 'clear':
            active = self.panel_manager.get_active_panel()
            if active:
                self.panel_manager.clear_panel_history(active.name)
        elif cmd == 'clear-screen':
            self.clear_screen()
        elif cmd == 'otr' and len(parts) > 1:
            self.start_guided_otr_session(parts[1])
        elif cmd == 'fingerprint':
            fp = self.session_manager.client_profile.get_fingerprint() if hasattr(self.session_manager, 'client_profile') else 'N/A'
            self.add_message('system', f'Your fingerprint: {colorize(fp, 'cyan')}')
        elif cmd == 'trust' and len(parts) > 2:
            self.session_manager.trust_db.add_trust(parts[1], parts[2])
            self.add_message('system', f'✅ Trusted {parts[1]}: {parts[2][:16]}…')
        elif cmd == 'smp' and len(parts) > 1:
            active = self.panel_manager.get_active_panel()
            peer = active.name if active and active.type not in ('system', 'debug') else None
            sub = parts[1].lower()
            if not peer:
                self.add_message('system', colorize('⚠ Switch to a peer panel first', 'yellow'))
            elif sub == 'start':
                stored = ''
                if hasattr(self.session_manager, 'smp_storage'):
                    stored = self.session_manager.smp_storage.get_secret(peer) or ''
                if not stored:
                    self.add_message('system', colorize('⚠ No SMP secret stored — use /smp <secret> first', 'yellow'))
                else:
                    self._start_smp(peer, stored)
            elif sub == 'abort':
                self.clear_pending_smp(peer)
                self.add_message('system', f'🛑 SMP aborted for {peer}')
            elif sub == 'status':
                status = self.session_manager.get_smp_status(peer) if hasattr(self.session_manager, 'get_smp_status') else {}
                self.add_message('system', f'SMP {peer}: {status}')
            else:
                secret = ' '.join(parts[1:])
                if len(secret) < 8:
                    self.add_message('system', colorize(f'⚠ SMP secret rejected — only {len(secret)} chars. Minimum 8 required to resist brute-force attacks.', 'red'))
                    return
                self._start_smp(peer, secret)
        elif cmd == 'smp-secret' and len(parts) > 2:
            peer = parts[1]
            secret = ' '.join(parts[2:])
            if len(secret) < 8:
                self.add_message('system', colorize(f'⚠ SMP secret rejected — only {len(secret)} chars. Minimum 8 required to resist brute-force attacks.', 'red'))
                return
            if hasattr(self.session_manager, 'smp_storage'):
                self.session_manager.smp_storage.set_secret(peer, secret)
            self.add_message('system', f'🔑 SMP secret set for {peer}')
        elif cmd == 'smp-auto' and len(parts) > 1:
            self.schedule_auto_smp(parts[1], delay=1.0)
            self.add_message('system', f'🔄 Auto-SMP scheduled for {parts[1]}')
        elif cmd == 'smp-abort' and len(parts) > 1:
            self.clear_pending_smp(parts[1])
            self.add_message('system', f'🛑 SMP aborted for {parts[1]}')
        elif cmd == 'smp-status' and len(parts) > 1:
            status = self.session_manager.get_smp_status(parts[1])
            self.add_message('system', f'SMP {parts[1]}: {status}')
        elif cmd in ('secure', 'sessions'):
            if not self.session_manager.sessions:
                self.add_message('system', 'No OTR sessions active')
            for peer, sess in self.session_manager.sessions.items():
                sec = getattr(sess, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)
                icon = UIConstants.SECURITY_ICONS.get(sec, '')
                self.add_message('system', f'  {icon} {colorize_username(peer)}: {sec.name}')
        elif cmd == 'ignore' and len(parts) > 1:
            self.ignored_users.add(parts[1])
            self.add_message('system', f'🚫 Ignoring {colorize_username(parts[1])}')
        elif cmd == 'unignore' and len(parts) > 1:
            self.ignored_users.discard(parts[1])
            self.add_message('system', f'✅ Unignored {colorize_username(parts[1])}')
        elif cmd == 'ignored':
            if self.ignored_users:
                self.add_message('system', colorize('Ignored users:', 'cyan'))
                for u in sorted(self.ignored_users):
                    self.add_message('system', f'  🚫 {colorize_username(u)}')
            else:
                self.add_message('system', colorize('No users ignored', 'dim'))
        elif cmd == 'status':
            self.show_status_panel()
        elif cmd == 'quit':
            self.shutdown()
        elif cmd == 'reconnect':
            if self.running and self.connected:
                self.add_message('system', colorize('Already connected.', 'yellow'))
            else:
                self.add_message('system', colorize('🔄 Reconnecting…', 'cyan'))
                self._try_reconnect()
        elif cmd == 'debug':
            global DEBUG_MODE
            DEBUG_MODE = not DEBUG_MODE
            if hasattr(self, 'logger') and hasattr(self.logger, 'set_debug'):
                self.logger.set_debug(DEBUG_MODE)
            self.add_message('system', f'Debug: {('ON' if DEBUG_MODE else 'OFF')}')
            if DEBUG_MODE and 'debug' not in self.panel_manager.panels:
                self.panel_manager.add_panel('debug', 'debug')
        elif cmd == 'version':
            self.add_message('system', f'Version: {VERSION}')
            self.add_message('system', 'DAKE   : 🦀 Rust (X448 + ML-KEM-1024 + ML-DSA-87)')
            self.add_message('system', 'Ratchet: 🦀 Rust (zeroize-on-drop)')
            self.add_message('system', 'SMP    : 🦀 Rust (ML-DSA-87 + ML-KEM-1024, ZeroizeOnDrop)')
        elif cmd == 'pause':
            global _scroll_locked
            _scroll_locked = True
            self.add_message('system', colorize('⏸ Scroll paused — /resume to continue', 'yellow'))
        elif cmd == 'resume':
            _scroll_unlock()
            self.add_message('system', colorize('▶ Scroll resumed', 'green'))
        else:
            if cmd == '/server':
                if not parts[1:]:
                    _cur_net = NetworkConstants.detect(self.server)
                    _icons = {'i2p': '🧅 I2P', 'tor': '🧅 Tor', 'clearnet': '🌐 Clearnet'}
                    self.add_message('system', f'Current server: {colorize(self.server, 'cyan')} ({colorize(_icons.get(_cur_net, _cur_net), 'dark_cyan')})')
                    self.add_message('system', colorize('Usage: /server <hostname[:port]>', 'dim'))
                else:
                    new_srv = parts[1]
                    _new_net = NetworkConstants.detect(new_srv)
                    _icons = {'i2p': '🧅 I2P', 'tor': '🧅 Tor', 'clearnet': '🌐 Clearnet'}
                    _cols = {'i2p': 'dark_cyan', 'tor': 'dark_magenta', 'clearnet': 'grey'}
                    self.add_message('system', f'Switching to {colorize(new_srv, 'cyan')} ({colorize(_icons.get(_new_net, _new_net), _cols.get(_new_net, 'white'))})…')
                    if self.connected:
                        self.send_raw('QUIT :switching server')
                        self.connected = False
                        self.running = False
                        try:
                            if self.sock:
                                self.sock.close()
                        except Exception:
                            pass
                    self.server = new_srv
                    self.config.server = new_srv
                    if not self.connect():
                        self.add_message('system', colorize(f'❌ Failed to connect to {new_srv}', 'bold_red'))
                return
            self.add_message('system', colorize(f'❌ Unknown command: {cmd}  (try /help)', 'bold_red'))

    def show_help(self, topic=None):
        if topic:
            topic = topic.lower().strip()
        lines = []
        header = 'Help'
        if topic in ('mode', 'modes'):
            header = 'IRC Modes'
            lines = [
                colorize('  User modes (/mode YourNick +flag):', 'cyan'),
                '    +i  Invisible — hidden from /who and /names',
                '    +g  Caller-ID — /accept nick before they can PM you',
                '    +R  Block PMs from unregistered users',
                '    +w  Receive wallops (server announcements)',
                '    +x  Cloak hostname (hide IP in /whois)',
                '',
                colorize('  Channel modes (/mode #channel +flag):', 'cyan'),
                '    +o nick  Give operator status (@)',
                '    +v nick  Give voice status (+)',
                '    +b mask  Ban (e.g. +b *!*@bad.host)',
                '    +m       Moderated — only ops/voiced speak',
                '    +n       No external messages',
                '    +t       Only ops change topic',
                '    +i       Invite-only',
                '    +k pass  Channel password',
                '    +l N     User limit',
                '    +s       Secret — hidden from /list',
                '',
                colorize('  Recommended for privacy:', 'yellow'),
                '    /mode YourNick +gi',
            ]
        elif topic == 'otr':
            header = 'OTR Commands'
            lines = [
                '  /otr <nick>          Start encrypted session',
                '  /endotr <nick>       End session',
                '  /fingerprint         Show your Ed448 fingerprint',
                '  /trust <nick> <fp>   Trust a fingerprint',
                '  /smp <secret>        Verify identity (shared secret)',
                '  /smp start           Start SMP',
                '  /smp abort           Abort SMP',
                '  /smp status          SMP status',
                '  /secure              Show all session security levels',
                '',
                colorize('  Security icons:', 'yellow'),
                '    🔴 Plaintext  🟡 Encrypted  🟢 Trusted  🔵 SMP verified',
            ]
        elif topic == 'irc':
            header = 'IRC Commands'
            lines = [
                '  /join <#channel>     Join a channel',
                '  /part [#channel]     Leave channel',
                '  /nick <name>         Change nickname',
                '  /msg <nick> <text>   Private message',
                '  /names [#channel]    List users (pager)',
                '  /topic [#ch] [text]  View/set topic',
                '  /list                List channels (pager)',
                '  /whois <nick>        User info',
                '  /invite <n> <#ch>    Invite to channel',
                '  /kick <nick> [why]   Kick from channel',
                '  /mode <t> <+/-flag>  Set mode (/help mode)',
                '  /away [message]      Set away',
                '  /back                Clear away',
                '  /raw <command>       Raw IRC command',
                '  /reconnect           Reconnect',
                '  /quit                Exit',
            ]
        elif topic == 'ui':
            header = 'UI Commands'
            lines = [
                '  /switch <panel>      Switch to tab',
                '  /tabs                List open tabs',
                '  /tab-next            Next tab',
                '  /tab-prev            Previous tab',
                '  /tab-close <panel>   Close tab',
                '  /clear               Clear panel history',
                '  /tui                 Toggle TUI mode (pinned tab bar + input at bottom)',
                '  /tui on|off          Explicitly enable or disable',
                '  /names [#channel]    List channel users — pager, q to quit',
                '  /list                List all channels — pager, q to quit',
                '  /ignore <nick>       Ignore user',
                '  /unignore <nick>     Unignore',
                '  /status              Connection status',
                '  /debug               Toggle debug mode',
                '  /version             Version info',
            ]
        else:
            header = 'OTRv4+ Help'
            lines = [
                colorize('  Quick start:', 'yellow'),
                '    /join #channel       Join a channel',
                '    /otr <nick>          Start encrypted chat',
                '    /smp <secret>        Verify identity',
                '    /names               List users in channel',
                '    /quit                Exit',
                '',
                colorize('  Help topics:', 'yellow'),
                '    /help irc    — IRC commands',
                '    /help otr    — OTR encryption',
                '    /help mode   — IRC modes',
                '    /help ui     — UI/TUI commands',
                '',
                colorize('  TUI mode:', 'cyan'),
                '    Type /tui to toggle pinned header+tab bar.',
                '    /tui on | off | toggle',
                '',
                colorize('  Privacy tip:', 'green'),
                '    /mode YourNick +gi   Invisible + block unsolicited PMs',
            ]
        self.pager.display(lines, header)

    def start_guided_otr_session(self, nick: str):
        if nick not in self.panel_manager.panels:
            self.panel_manager.add_panel(nick, 'private')
        self._switch_panel(nick)
        self.add_message(nick, colorize(f'🔑 Initiating OTR with {colorize_username(nick)}…', 'cyan'))
        dake_msg, should_send = self.session_manager.handle_outgoing_message(nick, '')
        if dake_msg and should_send:
            self.send_otr_message(nick, dake_msg)
            self.add_message(nick, colorize(f'🔑 DAKE1 → sent — waiting for response…', 'bold_cyan'))

    def shutdown(self):
        self.add_message('system', colorize('🛑 Shutting down…', 'yellow'))
        self.running = False
        self.shutdown_flag = True
        try:
            if self.sock:
                self.send_raw('QUIT :OTRv4 client shutting down')
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        try:
            if hasattr(self, '_sam_connection') and self._sam_connection:
                self._sam_connection.close()
                self._sam_connection = None
        except Exception:
            pass
        try:
            self._smp_executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._smp_executor.shutdown(wait=False)
        except Exception:
            pass
        self.add_message('system', colorize('✅ Clean shutdown complete', 'green'))

    def send_privmsg(self, target: str, message: str) -> bool:
        return self.send(f'PRIVMSG {target} :{message}')

class EnhancedOTRv4IRCClient(OTRv4IRCClient):

    def __init__(self, config=None):
        super().__init__(config)
        self._pending_action: Optional[dict] = None
        self._pending_lock = threading.Lock()

    def _set_pending(self, action_type: str, peer: str, **kwargs):
        with self._pending_lock:
            self._pending_action = {'type': action_type, 'peer': peer, **kwargs}

    def _clear_pending(self):
        with self._pending_lock:
            self._pending_action = None

    def _get_pending(self) -> Optional[dict]:
        with self._pending_lock:
            return self._pending_action

    def _dispatch_pending_response(self, text: str) -> bool:
        action = self._get_pending()
        if not action:
            return False
        atype = action['type']
        peer = action['peer']
        self._clear_pending()
        if atype == 'trust':
            self._handle_trust_response(peer, text.strip().lower(), action)
            return True
        elif atype == 'smp_secret':
            self._handle_smp_secret_response(peer, text.strip(), action)
            return True
        return False

    def process_dake1(self, sender: str, payload: str):
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, 'secure')
        if self.panel_manager.active_panel != sender:
            self._switch_panel(sender)
        self._route_otr_to_session_manager(sender, payload, 'DAKE1', is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, 'private')
        self.add_message(sender, colorize(f'🔑 DAKE2 ← received from {colorize_username(sender)}', 'cyan'))
        self._route_otr_to_session_manager(sender, payload, 'DAKE2', is_initiator=True)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            self.add_message(sender, colorize(f'🔑 DAKE3 → sent to {colorize_username(sender)}', 'cyan'))
            self._handle_session_established(sender, is_initiator=True)
        else:
            self.add_message(sender, colorize('⚠ DAKE2 processed but session not yet encrypted', 'yellow'))

    def process_dake3(self, sender: str, payload: str):
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, 'secure')
        self.add_message(sender, colorize(f'🔑 DAKE3 ← received from {colorize_username(sender)}', 'cyan'))
        self._route_otr_to_session_manager(sender, payload, 'DAKE3', is_initiator=False)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            self._handle_session_established(sender, is_initiator=False)
        else:
            self.add_message(sender, colorize('⚠ DAKE3 processed but session not encrypted', 'yellow'))

    def _route_otr_to_session_manager(self, sender: str, payload: str, label: str, is_initiator: bool):
        try:
            result = self.session_manager.handle_incoming_message(sender, payload)
            if result and isinstance(result, (bytes, str)):
                resp = result if isinstance(result, str) else result.decode('utf-8', errors='replace')
                if resp.startswith('?OTRv4 '):
                    self.send_otr_message(sender, resp)
                    if label == 'DAKE1':
                        if sender not in self.panel_manager.panels:
                            self.panel_manager.add_panel(sender, 'secure')
                        self.add_message(sender, colorize(f'🔑 DAKE2 → sent to {colorize_username(sender)}', 'cyan'))
                    return
            self.debug(f'{label} processed', {'sender': sender})
        except Exception as exc:
            self.debug(f'{label} error: {exc}')
            self.add_message('system', f'{colorize(f'❌ {label} error from', 'red')} {sender}: {str(exc)[:60]}')

    def _otr_panel(self, peer: str) -> str:
        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, 'secure')
        return peer

    def _handle_session_established(self, peer: str, is_initiator: bool):
        try:
            channel_panel = None
            for ch, info in self.channels.items():
                if peer in info.get('users', set()):
                    channel_panel = ch
                    break
            if peer not in self.panel_manager.panels:
                self.panel_manager.add_panel(peer, 'secure')
            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.panel_manager.update_panel_security(peer, sec)
            if channel_panel:
                self.panel_manager.update_panel_security(channel_panel, sec)
            role = 'initiator' if is_initiator else 'responder'
            _session = self.session_manager.get_session(peer) if hasattr(self.session_manager, 'get_session') else None
            _backend = getattr(_session, '_ratchet_backend', 'python') if _session else 'python'
            _ratchet_tag = '🦀 Rust' if _backend == 'rust' else '🐍 Python'
            _dake_engine = getattr(_session, 'dake_engine', None)
            _dake_tag = '🦀 Rust'
            _smp_tag = '🦀 Rust' if getattr(_session, 'rust_smp', None) is not None else '🐍 Python'
            if channel_panel:
                self.add_message(channel_panel, f'🔒 OTR session with {colorize_username(peer)} established — Ed448/X448, AES-256-GCM ({role}) [DAKE {_dake_tag} | Ratchet {_ratchet_tag} | SMP {_smp_tag}]', sec)
            local_fp = self._get_local_fp()
            remote_fp = self._get_remote_fp(peer)
            self.add_message(peer, colorize('─' * 50, 'dim'), sec)
            self.add_message(peer, colorize(f'🔑 FINGERPRINTS ({peer})', 'cyan'), sec)
            self.add_message(peer, f'  Yours : {colorize(self._fmt_fp(local_fp), 'green')}', sec)
            self.add_message(peer, f'  Theirs: {colorize(self._fmt_fp(remote_fp), 'yellow')}', sec)
            self.add_message(peer, colorize('─' * 50, 'dim'), sec)
            if self.panel_manager.active_panel != peer:
                self._switch_panel(peer)
            elif self._prompt_refresh_cb is not None:
                self._prompt_refresh_cb()
            already_trusted = False
            if remote_fp:
                try:
                    if hasattr(self.session_manager, 'is_peer_trusted'):
                        already_trusted = self.session_manager.is_peer_trusted(peer)
                    elif hasattr(self.session_manager, 'trust_db'):
                        already_trusted = self.session_manager.trust_db.is_trusted(peer, remote_fp)
                except Exception:
                    already_trusted = False
            if already_trusted:
                self.add_message(peer, colorize('✅ Fingerprint already trusted', 'green'), sec)
                self._finish_trust(peer, trusted=True, remote_fp=remote_fp, is_initiator=is_initiator)
            else:
                self.add_message(peer, colorize('❓ Trust this fingerprint? Type  y  or  n', 'yellow'), sec)
                self._set_pending('trust', peer, remote_fp=remote_fp, is_initiator=is_initiator)
        except Exception as exc:
            self.debug(f'_handle_session_established error: {exc}')
            self.add_message('system', f'{colorize('❌ Session setup error:', 'red')} {str(exc)[:100]}')

    def _handle_trust_response(self, peer: str, response: str, action: dict):
        trusted = response == 'y'
        remote_fp = action.get('remote_fp', '')
        is_initiator = action.get('is_initiator', False)
        if trusted and remote_fp:
            try:
                if hasattr(self.session_manager, 'trust_fingerprint'):
                    self.session_manager.trust_fingerprint(peer, remote_fp)
                else:
                    self.session_manager.trust_db.add_trust(peer, remote_fp)
            except Exception as exc:
                self.debug(f'trust save error: {exc}')
        self._finish_trust(peer, trusted=trusted, remote_fp=remote_fp, is_initiator=is_initiator)

    def _finish_trust(self, peer: str, trusted: bool, remote_fp: str, is_initiator: bool):
        if trusted:
            sec = UIConstants.SecurityLevel.FINGERPRINT
            self.add_message(peer, colorize('🟢 Fingerprint trusted — VERIFIED', 'green'), sec)
        else:
            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.add_message(peer, colorize('🟡 Fingerprint NOT trusted — encrypted only', 'yellow'), sec)
        self.panel_manager.update_panel_security(peer, sec)
        self.add_message(peer, colorize('─' * 50, 'dim'), sec)
        self.add_message(peer, colorize('🔐 SMP VERIFICATION SETUP (🦀 Rust SMP)', 'blue'), sec)
        self.add_message(peer, 'Type your shared secret (both sides must use the same).', sec)
        self.add_message(peer, colorize('After setting secret, type  /smp start  to begin verification.', 'cyan'), sec)
        self.add_message(peer, colorize('Press Enter / type  skip  to skip SMP for now.', 'dim'), sec)
        self._set_pending('smp_secret', peer, security_level=sec, is_initiator=is_initiator)

    def _ensure_rust_smp(self, peer: str) -> None:
        session = self.session_manager.get_session(peer) if hasattr(self.session_manager, 'get_session') else None
        if session is not None and hasattr(session, 'initialize_smp'):
            session.initialize_smp()

    def _handle_smp_secret_response(self, peer: str, secret: str, action: dict):
        sec = action.get('security_level', UIConstants.SecurityLevel.ENCRYPTED)
        is_initiator = action.get('is_initiator', False)
        if secret and secret.lower() != 'skip':
            try:
                self._ensure_rust_smp(peer)
                if hasattr(self.session_manager, 'set_smp_secret'):
                    self.session_manager.set_smp_secret(peer, secret)
                self.add_message(self._otr_panel(peer), colorize('✅ SMP secret stored (🦀 Rust vault)', 'green'), sec)
                if is_initiator:
                    self.add_message(self._otr_panel(peer), colorize('🔐 Type  /smp start  to begin verification.', 'cyan'), sec)
                else:
                    self.add_message(self._otr_panel(peer), colorize('🔐 Type  /smp start  to initiate, or wait for the other side.', 'cyan'), sec)
            except Exception as exc:
                self.debug(f'smp secret store error: {exc}')
                self.add_message(self._otr_panel(peer), colorize('⚠ Could not store SMP secret', 'yellow'), sec)
        else:
            self.add_message(self._otr_panel(peer), colorize('⚠ SMP skipped — use /smp <secret> later', 'dim'), sec)
        self._finish_session_setup(peer, sec)

    def _finish_session_setup(self, peer: str, sec):
        _session = self.session_manager.get_session(peer) if hasattr(self.session_manager, 'get_session') else None
        _backend = getattr(_session, '_ratchet_backend', 'python') if _session else 'python'
        _ratchet_tag = '🦀 Rust' if _backend == 'rust' else '🐍 Python'
        _dake_engine = getattr(_session, 'dake_engine', None)
        _dake_tag = '🦀 Rust'
        _smp_tag = '🦀 Rust' if getattr(_session, 'rust_smp', None) is not None else '🐍 Python'
        self.add_message(peer, colorize('─' * 50, 'dim'), sec)
        self.add_message(peer, colorize(f'✅ Session ready! — DAKE {_dake_tag} | Ratchet {_ratchet_tag} | SMP {_smp_tag}', 'green'), sec)
        self.add_message('system', f'{colorize('Commands:', 'cyan')} /fingerprint  /smp <secret>  /smp start  /trust <nick>  /secure')

    def process_smp_message(self, sender: str, data: bytes):
        self.debug(f'process_smp_message called for {sender} — ignored (use decrypt_message path)')
    _NOTIF_COOLDOWN = 30

    def _termux_fire(self, args: list) -> None:
        try:
            import subprocess as _sp
            _sp.Popen(['termux-notification'] + args, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except Exception:
            pass

    def _termux_remove_notification(self, panel: str) -> None:
        try:
            import subprocess as _sp
            _sp.Popen(['termux-notification-remove', 'otrv4_' + panel.lstrip('#')], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
        except Exception:
            pass

    def _termux_notify_message(self, panel: str, message: str) -> None:
        _now = time.time()
        if not hasattr(self, '_last_notif'):
            self._last_notif = {}
        if _now - self._last_notif.get(panel, 0) < self._NOTIF_COOLDOWN:
            return
        self._last_notif[panel] = _now
        is_channel = panel.startswith('#')
        sec_level = UIConstants.SecurityLevel.PLAINTEXT
        if not is_channel:
            try:
                if hasattr(self, 'session_manager') and self.session_manager.has_session(panel):
                    sec_level = self.session_manager.get_security_level(panel)
                elif panel in self.panel_manager.panels:
                    sec_level = self.panel_manager.panels[panel].security_level
            except Exception:
                pass
        is_encrypted = not is_channel and sec_level != UIConstants.SecurityLevel.PLAINTEXT
        sec_icon = UIConstants.SECURITY_ICONS.get(sec_level, '🔴')
        if is_channel:
            _notif_title = panel
            _notif_body = 'New message in ' + panel
        elif is_encrypted:
            _notif_title = sec_icon + ' ' + panel
            _notif_body = 'New encrypted message from ' + panel
        else:
            _notif_title = '🔴 ' + panel
            _notif_body = 'New plaintext message from ' + panel
        args = ['--title', _notif_title, '--content', _notif_body, '--priority', 'high' if is_encrypted else 'default', '--id', 'otrv4_' + panel.lstrip('#'), '--alert-once']
        if is_encrypted:
            args += ['--vibrate', '0,200,100,200']
        self._termux_fire(args)

    def _termux_notify_otr_event(self, peer: str, started: bool) -> None:
        if started:
            self._termux_fire(['--title', '🔒 OTR session started', '--content', 'Encrypted session with ' + peer + ' established', '--priority', 'high', '--id', 'otrv4_' + peer + '_session', '--vibrate', '0,150,100,150,100,150'])
        else:
            self._termux_fire(['--title', '🔓 OTR session ended', '--content', 'Session with ' + peer + ' closed', '--priority', 'default', '--id', 'otrv4_' + peer + '_session'])

    def _on_peer_disconnected(self, peer: str, reason: str='') -> None:
        if peer not in self.panel_manager.panels:
            return
        if not hasattr(self, '_disconnected_peers'):
            self._disconnected_peers: set = set()
        if peer in self._disconnected_peers:
            return
        self._disconnected_peers.add(peer)
        sec = UIConstants.SecurityLevel.PLAINTEXT
        reason_str = f': {reason}' if reason else ''
        self.add_message(peer, colorize(f'⚠ {peer} disconnected{reason_str} — OTR session ended', 'red'), sec)
        self.panel_manager.update_panel_security(peer, sec)
        self.panel_manager.update_smp_progress(peer, 0, 0)
        try:
            if hasattr(self.session_manager, 'terminate_session'):
                self.session_manager.terminate_session(peer, 'peer disconnected')
            elif hasattr(self.session_manager, 'sessions'):
                self.session_manager.sessions.pop(peer, None)
        except Exception:
            pass
        try:
            action = getattr(self, '_pending_action', None)
            if action and action.get('peer') == peer:
                self._pending_action = None
        except Exception:
            pass

    def _on_smp_verified(self, peer: str):
        if getattr(self, '_smp_verified_notified', {}).get(peer):
            return
        if not hasattr(self, '_smp_verified_notified'):
            self._smp_verified_notified = {}
        self._smp_verified_notified[peer] = True
        sec = UIConstants.SecurityLevel.SMP_VERIFIED
        self.panel_manager.update_panel_security(peer, sec)
        self.panel_manager.update_smp_progress(peer, 0, 0)
        self.add_message(self._otr_panel(peer), colorize('🔵 SMP VERIFIED — identity confirmed by shared secret! (🦀 Rust SMP)', 'blue'), sec)
        self.add_message('system', f'{colorize('🔵 SMP verified with', 'blue')} {colorize_username(peer)}')
        self._termux_fire(['--title', '🔵 OTR identity verified', '--content', peer + ' — SMP shared secret confirmed', '--priority', 'high', '--id', 'otrv4_' + peer + '_session', '--vibrate', '0,100,50,100'])

    def handle_message(self, line: str):
        try:
            prefix, command, params, trailing = self.parse_irc_message(line)
            self.logger.network_message('IN', prefix or 'SERVER', command or '?', len(line))
            self.debug('recv', {'cmd': command, 'params': params[:3], 'trail': (trailing or '')[:120]})
            if command == 'PING':
                self.send(f'PONG :{trailing or (params[0] if params else 'server')}')
                self.last_ping = time.time()
                return
            if command == 'PONG':
                self.last_ping = time.time()
                return
            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return
            sender = prefix.split('!')[0] if prefix and '!' in prefix else prefix or 'server'
            if len(sender) > 50 or '\r' in sender or '\n' in sender:
                return
            if sender in self.ignored_users:
                return
            if command == 'PRIVMSG':
                target = params[0] if params else ''
                message = trailing or ''
                if self.is_ctcp_message(message) and '?OTRv4' not in message:
                    return
                self.check_auto_reply(sender, target, message)
                if '?OTRv4' in message:
                    if hasattr(self, '_401_count'):
                        self._401_count.pop(sender, None)
                    if hasattr(self, '_401_handled'):
                        self._401_handled.discard(sender)
                    if hasattr(self, '_disconnected_peers'):
                        self._disconnected_peers.discard(sender)
                    self._dispatch_otr_fragment(sender, message)
                    return
                panel = target if target.startswith('#') else sender
                self.add_message(panel, f'{colorize_username(sender)}: {message}')
                return
            OTRv4IRCClient.handle_message(self, line)
        except Exception as exc:
            self.debug(f'handle_message error: {exc}', {'line': line[:100]})

    def process_incoming_otr_message(self, sender: str, message: str):
        self.debug('otr msg', {'sender': sender, 'len': len(message)})
        try:
            if not message.startswith('?OTRv4 '):
                return
            raw = message[7:].strip()
            if not raw:
                return
            try:
                decoded = _safe_b64decode(raw)
            except Exception:
                return
            if not decoded:
                return
            if len(decoded) >= 3 and decoded[0] == 0 and (decoded[1] == 4) and (decoded[2] == OTRv4DataMessage.TYPE):
                self.debug('otr type', {'type': 'DATA_V6', 'sender': sender})
                self._handle_data_message(sender, message)
                return
            msg_type = decoded[0]
            self.debug('otr type', {'type': msg_type, 'sender': sender})
            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, message)
        except Exception as exc:
            self.debug(f'process_incoming_otr error: {exc}')

    def handle_chat_message(self, msg: str):
        if self._dispatch_pending_response(msg):
            return
        OTRv4IRCClient.handle_chat_message(self, msg)

    def start_guided_otr_session(self, peer: str):
        if self.session_manager.has_session(peer) and self.session_manager.get_security_level(peer) != UIConstants.SecurityLevel.PLAINTEXT:
            if peer not in self.panel_manager.panels:
                self.panel_manager.add_panel(peer, 'private')
            self._switch_panel(peer)
            self.add_message(peer, colorize(f'✅ Already encrypted with {colorize_username(peer)}', 'green'))
            return
        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, 'private')
        self._switch_panel(peer)
        self.add_message(peer, colorize(f'🔑 Starting OTR session with {colorize_username(peer)}…', 'cyan'))
        try:
            otr_msg, should_send = self.session_manager.handle_outgoing_message(peer, '')
            if otr_msg and should_send:
                self.send_otr_message(peer, otr_msg)
                self.add_message(peer, colorize(f'🔑 DAKE1 → sent — waiting for response…', 'cyan'))
            else:
                self.send(f'PRIVMSG {peer} :?OTRv4 ')
        except Exception as exc:
            self.debug(f'start_guided_otr_session error: {exc}')

    def handle_command(self, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()
        if cmd == 'otr' and len(parts) > 1:
            self.start_guided_otr_session(parts[1])
        elif cmd == 'trust' and len(parts) > 1:
            peer = parts[1]
            sec = self.session_manager.get_security_level(peer) if self.session_manager.has_session(peer) else UIConstants.SecurityLevel.ENCRYPTED
            remote_fp = self._get_remote_fp(peer)
            if remote_fp:
                try:
                    if hasattr(self.session_manager, 'trust_fingerprint'):
                        self.session_manager.trust_fingerprint(peer, remote_fp)
                    else:
                        self.session_manager.trust_db.add_trust(peer, remote_fp)
                    new_sec = UIConstants.SecurityLevel.FINGERPRINT
                    self.panel_manager.update_panel_security(peer, new_sec)
                    self.add_message(peer, colorize('🟢 Fingerprint trusted — VERIFIED', 'green'), new_sec)
                except Exception as exc:
                    self.add_message('system', f'{colorize('❌ Trust failed:', 'red')} {exc}')
            else:
                self.add_message('system', colorize('No active session to trust', 'red'))
        elif cmd in ('smp', 'verify'):
            if len(parts) < 2:
                self.add_message('system', colorize('Usage: /smp <command> [args]', 'red'))
                return
            subcmd = parts[1].lower()
            if subcmd == 'start':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                if not peer:
                    self.add_message('system', colorize('Usage: /smp start [peer]  (or switch to peer panel)', 'red'))
                    return
                if not self.session_manager.has_session(peer):
                    self.add_message('system', f'{colorize('❌ No session with', 'red')} {peer}')
                    return
                if self.session_manager.get_security_level(peer) == UIConstants.SecurityLevel.PLAINTEXT:
                    self.add_message('system', f'{colorize('❌ No encrypted session with', 'red')} {peer}')
                    return
                secret = None
                if hasattr(self.session_manager, 'smp_storage'):
                    secret = self.session_manager.smp_storage.get_secret(peer)
                    self.debug(f'Got secret from smp_storage: {bool(secret)}')
                if not secret:
                    self.add_message('system', colorize(f'No SMP secret stored for {peer} - use /smp <peer> <secret> first', 'yellow'))
                    return
                self.debug(f'Starting SMP with secret length: {len(secret)}')
                self._start_smp(peer, secret)
            elif subcmd == 'abort':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                if not peer:
                    self.add_message('system', colorize('Usage: /smp abort [peer]', 'red'))
                    return
                self.clear_pending_smp(peer)
                if hasattr(self.session_manager, 'abort_smp'):
                    self.session_manager.abort_smp(peer)
                self.add_message('system', f'🛑 SMP aborted for {colorize_username(peer)}')
            elif subcmd == 'status':
                peer = None
                if len(parts) > 2:
                    peer = parts[2]
                else:
                    active = self.panel_manager.get_active_panel()
                    if active and active.type not in ('system', 'debug'):
                        peer = active.name
                if not peer:
                    self.add_message('system', colorize('Usage: /smp status [peer]', 'red'))
                    return
                self._show_smp_status(peer)
            else:
                active = self.panel_manager.get_active_panel()
                peer = active.name if active and active.type not in ('system', 'debug') else None
                if not peer and len(parts) > 2:
                    peer = parts[1]
                    secret = ' '.join(parts[2:])
                elif peer:
                    secret = ' '.join(parts[1:])
                else:
                    self.add_message('system', colorize('Usage: /smp <peer> <secret>  or  /smp <secret> (in peer panel)', 'red'))
                    return
                if secret:
                    if len(secret) < 8:
                        self.add_message('system', colorize(f'⚠ SMP secret rejected — only {len(secret)} chars. Minimum 8 required to resist brute-force attacks.', 'red'))
                        return
                    try:
                        if hasattr(self.session_manager, 'set_smp_secret'):
                            self.session_manager.set_smp_secret(peer, secret)
                        elif hasattr(self.session_manager, 'smp_storage'):
                            self.session_manager.smp_storage.set_secret(peer, secret)
                        sec_level = self.session_manager.get_security_level(peer)
                        self.add_message(self._otr_panel(peer), colorize('✅ SMP secret stored (🦀 Rust vault)', 'green'), sec_level)
                        self.add_message(self._otr_panel(peer), colorize('🔐 Type  /smp start  to begin verification.', 'cyan'), sec_level)
                    except Exception as exc:
                        self.add_message('system', f'{colorize('❌', 'red')} {exc}')
                else:
                    self.add_message('system', colorize('Usage: /smp <secret>  or  /smp start [peer]', 'red'))
        elif cmd == 'smp-secret' and len(parts) > 2:
            peer = parts[1]
            secret = ' '.join(parts[2:])
            if len(secret) < 8:
                self.add_message('system', colorize(f'⚠ SMP secret rejected — only {len(secret)} chars. Minimum 8 required to resist brute-force attacks.', 'red'))
                return
            try:
                if hasattr(self.session_manager, 'set_smp_secret'):
                    self.session_manager.set_smp_secret(peer, secret)
                elif hasattr(self.session_manager, 'smp_storage'):
                    self.session_manager.smp_storage.set_secret(peer, secret)
                self.add_message('system', f'🔑 SMP secret set for {colorize_username(peer)}')
                sec_level = self.session_manager.get_security_level(peer)
                self.add_message(self._otr_panel(peer), colorize('🔐 Type  /smp start  to begin verification.', 'cyan'), sec_level)
            except Exception as exc:
                self.add_message('system', f'{colorize('❌', 'red')} {exc}')
        elif cmd == 'fingerprint':
            self._show_fingerprints()
        elif cmd in ('secure', 'sessions', 'otr-status'):
            self._show_all_sessions()
        elif cmd == 'session-info' and len(parts) > 1:
            self._show_session_info(parts[1])
        elif cmd == 'endotr' and len(parts) > 1:
            peer = parts[1]
            try:
                if hasattr(self.session_manager, 'terminate_session'):
                    self.session_manager.terminate_session(peer, 'user request')
                self.panel_manager.update_panel_security(peer, UIConstants.SecurityLevel.PLAINTEXT)
                self.add_message('system', f'Session ended with {colorize_username(peer)}')
            except Exception:
                pass
        else:
            OTRv4IRCClient.handle_command(self, command)

    def _start_smp(self, peer: str, secret: str, question: str=''):
        if not self.session_manager.has_session(peer):
            self.add_message('system', f'{colorize('❌ No session with', 'red')} {peer}')
            return
        if self.session_manager.get_security_level(peer) == UIConstants.SecurityLevel.PLAINTEXT:
            self.add_message('system', f'{colorize('❌ No encrypted session with', 'red')} {peer}')
            return
        sess = self.session_manager.get_session(peer)
        if sess is not None and getattr(sess, '_smp_notify_cb', None) is None:
            factory = getattr(self.session_manager, 'smp_notify_factory', None)
            if factory is not None:
                try:
                    sess._smp_notify_cb = factory(peer)
                except Exception:
                    pass
        sec = self.session_manager.get_security_level(peer)
        self.add_message(peer, colorize('🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4 (🦀 Rust SMP) · Computing challenge — please wait…', 'yellow'), sec)
        self.panel_manager.update_smp_progress(peer, 1, 4)
        if hasattr(self.session_manager, 'set_smp_secret'):
            self.session_manager.set_smp_secret(peer, secret)
        secret = None

        def _do_smp():
            try:
                if not hasattr(self.session_manager, 'start_smp'):
                    self.add_message('system', colorize('SMP not supported by session manager', 'red'))
                    return
                self.debug(f'SMP background compute starting for {peer}')
                try:
                    encrypted_msg = self.session_manager.start_smp(peer, '', question)
                except Exception as smp_exc:
                    self.debug(f'SMP start exception: {smp_exc}')
                    self.add_message('system', colorize(f'❌ SMP failed: {str(smp_exc)[:200]}', 'red'))
                    self.panel_manager.update_smp_progress(peer, 0, 0)
                    return
                self.debug(f'SMP compute done: msg={('yes' if encrypted_msg else 'no')}')
                if encrypted_msg and isinstance(encrypted_msg, str) and encrypted_msg.startswith('?OTRv4 '):
                    if self.send_otr_message(peer, encrypted_msg):
                        s = self.session_manager.get_security_level(peer)
                        self.add_message(peer, colorize('🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4 (🦀 Rust SMP) · Challenge sent — awaiting response…', 'yellow'), s)
                    else:
                        self.add_message('system', colorize('❌ Failed to send SMP challenge', 'red'))
                        self.panel_manager.update_smp_progress(peer, 0, 0)
                else:
                    self.panel_manager.update_smp_progress(peer, 0, 0)
                    if hasattr(self.session_manager, 'get_smp_status'):
                        status = self.session_manager.get_smp_status(peer)
                        if status.get('verified'):
                            self.add_message(peer, colorize('✅ SMP already verified!', 'green'), self.session_manager.get_security_level(peer))
                        elif status.get('state') not in ('NONE', 'FAILED'):
                            self.add_message(peer, colorize(f'⚠ SMP already in progress (state: {status.get('state')})', 'yellow'), self.session_manager.get_security_level(peer))
                        else:
                            self.add_message('system', colorize('❌ SMP init failed — check session state', 'red'))
            except Exception as exc:
                self.debug(f'_start_smp background error: {exc}')
                self.add_message('system', colorize(f'❌ SMP error: {str(exc)[:80]}', 'red'))
                self.panel_manager.update_smp_progress(peer, 0, 0)
        threading.Thread(target=_do_smp, daemon=True, name=f'smp-{peer}').start()

    def _get_local_fp(self) -> str:
        try:
            if hasattr(self.session_manager, 'get_fingerprint'):
                fp = self.session_manager.get_fingerprint()
                if fp:
                    return fp
            if hasattr(self.session_manager, 'client_profile'):
                return self.session_manager.client_profile.get_fingerprint()
        except Exception:
            pass
        return 'unavailable'

    def _get_remote_fp(self, peer: str) -> str:
        try:
            if hasattr(self.session_manager, 'get_peer_fingerprint'):
                fp = self.session_manager.get_peer_fingerprint(peer)
                if fp:
                    self.debug(f'_get_remote_fp: got from get_peer_fingerprint: {fp[:16]}...')
                    return fp
            sess = self.session_manager.get_session(peer)
            if sess:
                if hasattr(sess, 'get_fingerprint'):
                    fp = sess.get_fingerprint()
                    if fp:
                        self.debug(f'_get_remote_fp: got from session.get_fingerprint: {fp[:16]}...')
                        return fp
                if hasattr(sess, 'remote_long_term_pub') and sess.remote_long_term_pub:
                    try:
                        pub_bytes = bytes(sess.remote_long_term_pub)
                        fp_bytes = hashlib.sha3_512(pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug(f'_get_remote_fp: got from remote_long_term_pub: {fp[:16]}...')
                        return fp
                    except Exception as e:
                        self.debug(f'_get_remote_fp: remote_long_term_pub conversion failed: {e}')
                if hasattr(sess, '_remote_long_term_pub_bytes') and sess._remote_long_term_pub_bytes:
                    try:
                        fp_bytes = hashlib.sha3_512(sess._remote_long_term_pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug(f'_get_remote_fp: got from stored bytes: {fp[:16]}...')
                        return fp
                    except Exception as e:
                        self.debug(f'_get_remote_fp: stored bytes conversion failed: {e}')
        except Exception as e:
            self.debug(f'_get_remote_fp error: {e}')
        self.debug(f'_get_remote_fp: no fingerprint found for {peer}')
        return ''

    @staticmethod
    def _fmt_fp(fp: str) -> str:
        if not fp or fp == 'unavailable':
            return fp
        clean = fp.upper().replace(' ', '')
        if len(clean) < 40:
            clean = clean.ljust(40, '0')
        return ' '.join((clean[i:i + 8] for i in range(0, 40, 8)))

    def _show_fingerprints(self):
        local_fp = self._get_local_fp()
        self.add_message('system', f'Your fingerprint: {colorize(self._fmt_fp(local_fp), 'cyan')}')
        for peer in list(self.session_manager.sessions.keys()):
            fp = self._get_remote_fp(peer)
            sec = self.session_manager.get_security_level(peer)
            icon = UIConstants.SECURITY_ICONS.get(sec, '')
            trusted = ''
            if fp:
                try:
                    is_t = self.session_manager.is_peer_trusted(peer) if hasattr(self.session_manager, 'is_peer_trusted') else self.session_manager.trust_db.is_trusted(peer, fp)
                    trusted = colorize(' ✅ trusted', 'green') if is_t else colorize(' ⚠ untrusted', 'yellow')
                except Exception:
                    trusted = ''
            self.add_message('system', f'  {icon} {colorize_username(peer)}: {colorize(self._fmt_fp(fp), 'green')}{trusted}')

    def _show_all_sessions(self):
        sessions = self.session_manager.sessions
        if not sessions:
            self.add_message('system', 'No OTR sessions active')
            return
        self.add_message('system', colorize('Active OTR sessions:', 'cyan'))
        for peer, sess in sessions.items():
            sec = getattr(sess, 'security_level', UIConstants.SecurityLevel.PLAINTEXT)
            icon = UIConstants.SECURITY_ICONS.get(sec, '')
            name = UIConstants.SECURITY_NAMES.get(sec, sec.name)
            _dake_engine = getattr(sess, 'dake_engine', None)
            _dake_tag = '🦀R'
            _ratchet_backend = getattr(sess, '_ratchet_backend', 'python')
            _ratchet_tag = '🦀R' if _ratchet_backend == 'rust' else '🐍Py'
            _smp_tag = '🦀R' if getattr(sess, 'rust_smp', None) is not None else '🐍Py'
            self.add_message('system', f'  {icon} {colorize_username(peer):<20} {colorize(name, 'yellow')}  [DAKE {_dake_tag} | Ratchet {_ratchet_tag} | SMP {_smp_tag}]')

    def _show_session_info(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message('system', f'{colorize('No session with', 'red')} {peer}')
            return
        info = self.session_manager.get_session_info(peer)
        for k, v in info.items():
            self.add_message('system', f'  {k}: {v}')

    def _show_smp_status(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message('system', f'{colorize('No session with', 'red')} {peer}')
            return
        if hasattr(self.session_manager, 'get_smp_status'):
            status = self.session_manager.get_smp_status(peer)
            _sess = self.session_manager.get_session(peer)
            _smp_tag = '🦀 Rust' if getattr(_sess, 'rust_smp', None) is not None else '🐍 Python'
            self.add_message('system', f'SMP {colorize_username(peer)} [{_smp_tag}]: {status}')

    def shutdown(self):
        self.add_message('system', colorize('🔄 Shutting down OTR sessions…', 'yellow'))
        _session_count = len(self.session_manager.sessions) if hasattr(self.session_manager, 'sessions') else 0
        _rust_count = 0
        try:
            if hasattr(self.session_manager, 'sessions'):
                for peer, sess in self.session_manager.sessions.items():
                    if getattr(sess, '_ratchet_backend', None) == 'rust':
                        _rust_count += 1
        except Exception:
            pass
        try:
            if hasattr(self.session_manager, 'clear_all_sessions'):
                self.session_manager.clear_all_sessions('client shutdown')
        except Exception:
            pass
        if _rust_count > 0:
            self.add_message('system', colorize(f'🦀 {_rust_count} Rust ratchet(s) zeroized (deterministic memory wipe)', 'green'))
        elif _session_count > 0:
            self.add_message('system', colorize(f'🐍 {_session_count} Python ratchet(s) cleaned (GC-dependent)', 'yellow'))
        self._secure_wipe_data()
        try:
            OTRv4IRCClient.shutdown(self)
        except Exception:
            pass
        try:
            sys.stdout.write('\x1b[2J')
            sys.stdout.write('\x1b[H')
            sys.stdout.write('\x1b[3J')
            sys.stdout.flush()
            print('\n' * 100)
            try:
                import subprocess as _subp
                _subp.run(['clear'], check=False)
            except Exception:
                pass
            _wipe_msg = '🦀 Rust memory zeroized' if RUST_RATCHET_AVAILABLE else 'Memory cleared'
            print(colorize(f'\nOTRv4+ terminated — {_wipe_msg} — screen cleared', 'green'))
            print(colorize("Type 'python otrv4+.py --debug' to start again", 'cyan'))
        except Exception as e:
            self.debug(f'Error clearing screen: {e}')

    def _secure_wipe_data(self):
        import glob
        otrv4plus_dir = os.path.expanduser('~/.otrv4plus')
        try:
            os.makedirs(otrv4plus_dir, exist_ok=True)
            os.chmod(otrv4plus_dir, 448)
        except Exception:
            pass
        wiped = 0
        failed = 0
        try:
            if os.path.isdir(otrv4plus_dir):
                for fpath in glob.glob(os.path.join(otrv4plus_dir, '**', '*'), recursive=True):
                    if os.path.isfile(fpath):
                        try:
                            _real = os.path.realpath(fpath)
                            _base = os.path.realpath(otrv4plus_dir)
                            if not _real.startswith(_base + os.sep) and _real != _base:
                                continue
                        except Exception:
                            continue
                        try:
                            _secure_file_destroy(fpath)
                            wiped += 1
                        except Exception:
                            try:
                                os.remove(fpath)
                            except Exception:
                                pass
                            failed += 1
                import shutil
                shutil.rmtree(otrv4plus_dir, ignore_errors=True)
                status = f'🗑  ~/.otrv4plus wiped — {wiped} file(s) cryptographically destroyed'
                if failed:
                    status += f' ({failed} fallback)'
                self.add_message('system', colorize(status, 'green'))
        except Exception as e:
            self.add_message('system', colorize(f'⚠ Wipe incomplete: {e}', 'yellow'))

def parse_args() -> OTRConfig:
    config = OTRConfig()
    if '--help' in sys.argv or '-h' in sys.argv:
        print('\nOTRv4+ — Post-quantum encrypted IRC client\n\nUsage: python otrv4+.py [options]\n\nConnection:\n  -s, --server HOST[:PORT]   Server to connect to (default: irc.postman.i2p)\n  -p, --port PORT            Server port (default: auto — 6697 TLS, 6667 plain)\n  -c, --channel #CHANNEL     Channel to auto-join (default: #otr)\n  -n, --nick NICK            Nickname (default: random from pool)\n      --tls                  Force TLS on\n      --no-tls               Disable TLS (for Tor/I2P only — clearnet auto-uses TLS)\n\nAuthentication:\n      --sasl                 SASL login (prompts for nick + password)\n      --login                NickServ login (prompts for nick + password)\n\nDebug:\n  -d, --debug                Enable debug output\n      --smp-debug            Enable SMP protocol debug output\n\nNetwork auto-detection:\n  *.i2p    → I2P SAM bridge (preferred) or SOCKS5 fallback\n  *.onion  → Tor SOCKS5 on 127.0.0.1:9050\n  other    → Direct connection with TLS\n\nExamples:\n  python otrv4+.py                           # I2P default (irc.postman.i2p)\n  python otrv4+.py -s irc.libera.chat:6697   # Clearnet with TLS\n  python otrv4+.py -s irc.postman.i2p -c #i2p-chat\n  python otrv4+.py --sasl -n YourNick -s irc.libera.chat:6697\n  python otrv4+.py -s somehidden.onion --no-tls\n\nOnce connected, type /help for in-client commands.\nType /help mode for IRC user modes (+g, +i, etc).\n')
        sys.exit(0)
    if '--debug' in sys.argv or '-d' in sys.argv:
        global DEBUG_MODE
        DEBUG_MODE = True
    if '--smp-debug' in sys.argv:
        global SMP_DEBUG
        SMP_DEBUG = True
    for i, arg in enumerate(sys.argv):
        if arg in ('--server', '-s') and i + 1 < len(sys.argv):
            config.server = sys.argv[i + 1]
        elif arg in ('--channel', '-c') and i + 1 < len(sys.argv):
            config.channel = sys.argv[i + 1]
        elif arg in ('--nick', '-n') and i + 1 < len(sys.argv):
            config.nickserv_nick = sys.argv[i + 1]
        elif arg in ('--port', '-p') and i + 1 < len(sys.argv):
            _pval = int(sys.argv[i + 1])
            if not 1 <= _pval <= 65535:
                print(f'Error: --port must be 1-65535 (got {_pval})')
                sys.exit(1)
            config.port = _pval
        elif arg == '--tls':
            config.use_tls = True
        elif arg == '--no-tls':
            config.use_tls = False
            if config.port == 0:
                config.port = IRCConstants.PORT
    if ':' in config.server:
        _parts = config.server.rsplit(':', 1)
        if _parts[1].isdigit():
            config.server = _parts[0]
            if config.port == 0:
                config.port = int(_parts[1])
    if '--sasl' in sys.argv:
        if not config.nickserv_nick:
            config.nickserv_nick = input('Nick: ').strip()
        if not config.nickserv_nick:
            print('Error: nick required for --sasl')
            sys.exit(1)
        config.sasl_user = config.nickserv_nick
        config.sasl_pass = getpass.getpass('SASL password: ')
        if not config.sasl_pass:
            print('Error: password required for --sasl')
            sys.exit(1)
    elif '--login' in sys.argv:
        config.nickserv_login = True
        if not config.nickserv_nick:
            config.nickserv_nick = input('Nick: ').strip()
        if not config.nickserv_nick:
            print('Error: nick required for --login')
            sys.exit(1)
        config.nickserv_pass = getpass.getpass('NickServ password: ')
        if not config.nickserv_pass:
            print('Error: password required for --login')
            sys.exit(1)
    elif '--register' in sys.argv:
        config.nickserv_register = True
        if not config.nickserv_nick:
            config.nickserv_nick = input('Choose nick: ').strip()
        if not config.nickserv_nick:
            print('Error: nick required for --register')
            sys.exit(1)
        config.nickserv_pass = getpass.getpass('Choose password: ')
        if not config.nickserv_pass:
            print('Error: password required for --register')
            sys.exit(1)
        pass2 = getpass.getpass('Confirm password: ')
        if config.nickserv_pass != pass2:
            print('Error: passwords do not match')
            sys.exit(1)
    return config

def main():
    import select as _select
    global _current_prompt
    config = parse_args()
    config.trust_db_path = os.path.expanduser('~/.otrv4plus/trust.json')
    config.smp_secrets_path = os.path.expanduser('~/.otrv4plus/smp_secrets.json')
    config.key_storage_path = os.path.expanduser('~/.otrv4plus/keys')
    config.log_file_path = os.path.expanduser('~/.otrv4plus/logs/otrv4plus.log')
    config.test_mode = TEST_MODE
    config.i2p_proxy = (NetworkConstants.I2P_PROXY_HOST, NetworkConstants.I2P_PROXY_PORT)
    config.tor_proxy = (NetworkConstants.TOR_PROXY_HOST, NetworkConstants.TOR_PROXY_PORT)
    config.log_level = 'DEBUG' if DEBUG_MODE else 'INFO'
    config.dake_timeout = 120.0
    config.fragment_timeout = 120.0
    config.heartbeat_interval = 60
    config.rekey_interval = 100
    _legacy_orphan_paths = [os.path.expanduser('~/.otrv4_vault'), os.path.expanduser('~/.otrv4_smp_secrets.json')]
    for _orphan in _legacy_orphan_paths:
        try:
            if os.path.exists(_orphan):
                _secure_file_destroy(_orphan)
                if DEBUG_MODE:
                    print(f'[startup] securely destroyed legacy file: {_orphan}')
        except Exception as _e:
            if DEBUG_MODE:
                print(f'[startup] could not destroy legacy file {_orphan}: {_e}')
    _legacy_keys_dir = os.path.expanduser('~/.otrv4_keys')
    try:
        if os.path.isdir(_legacy_keys_dir):
            import shutil as _shutil
            for _root, _dirs, _files in os.walk(_legacy_keys_dir):
                for _fn in _files:
                    try:
                        _secure_file_destroy(os.path.join(_root, _fn))
                    except Exception:
                        pass
            try:
                _shutil.rmtree(_legacy_keys_dir, ignore_errors=True)
            except Exception:
                pass
            if DEBUG_MODE:
                print(f'[startup] removed legacy directory: {_legacy_keys_dir}')
    except Exception as _e:
        if DEBUG_MODE:
            print(f'[startup] could not remove legacy keys dir: {_e}')
    _net = NetworkConstants.detect(config.server)
    _net_icon = {'i2p': '🧅 I2P', 'tor': '🧅 Tor', 'clearnet': '🌐 Clearnet'}.get(_net, _net)
    _net_col = {'i2p': 'dark_cyan', 'tor': 'dark_magenta', 'clearnet': 'grey'}.get(_net, 'white')
    _disp_port = config.port if config.port != 0 else IRCConstants.TLS_PORT if _net == 'clearnet' else IRCConstants.PORT
    _tls_disp = '🔒 TLS' if _net == 'clearnet' and _disp_port == IRCConstants.TLS_PORT or config.use_tls else 'plaintext'
    _auth_disp = 'SASL' if config.sasl_user else 'NickServ' if config.nickserv_login else 'anonymous'
    safe_print(f'\n{colorize('OTRv4 IRC Client', 'bold_cyan')}')
    safe_print(colorize('=' * 50, 'dim'))
    safe_print(f'Version : {colorize(VERSION, 'yellow')}')
    safe_print(f'Server  : {colorize(config.server + ':' + str(_disp_port), 'green')}')
    safe_print(f'Network : {colorize(_net_icon, _net_col)} ({_tls_disp})')
    safe_print(f'Auth    : {colorize(_auth_disp, 'cyan')}')
    safe_print(f'Channel : {colorize(config.channel, 'cyan')}')
    safe_print(f'Debug   : {colorize('ON' if DEBUG_MODE else 'OFF', 'green' if DEBUG_MODE else 'dim')}')
    _rt_label = '🦀 Rust (zeroize-on-drop)' if RUST_RATCHET_AVAILABLE else '❌ NOT INSTALLED'
    safe_print(f'Ratchet : {colorize(_rt_label, 'green' if RUST_RATCHET_AVAILABLE else 'red')}')
    _dake_label = '🦀 Rust (DH secrets never Python)' if RUST_DAKE_AVAILABLE else '🐍 Python (C extensions)'
    safe_print(f'DAKE    : {colorize(_dake_label, 'green' if RUST_DAKE_AVAILABLE else 'yellow')}')
    _smp_label = '🦀 Rust (ZeroizeOnDrop, 50k-round Argon2-class KDF)' if RUST_RATCHET_AVAILABLE else '🐍 Python (C extensions)'
    safe_print(f'SMP     : {colorize(_smp_label, 'green' if RUST_RATCHET_AVAILABLE else 'yellow')}')
    if not RUST_RATCHET_AVAILABLE:
        safe_print(colorize('\n❌ FATAL: otrv4_core Rust module not installed.', 'red'))
        safe_print(colorize('   Encrypted sessions require the Rust ratchet core.', 'red'))
        safe_print(colorize('   Build with:', 'yellow'))
        safe_print(colorize('     cd Rust && cargo test --release && maturin build --release', 'cyan'))
        safe_print(colorize('     pip install target/wheels/otrv4_core-*.whl', 'cyan'))
        safe_print('')
        return 1
    _net_detect = NetworkConstants.detect(config.server)
    if _net_detect == NetworkConstants.NET_I2P:
        _sam_host, _sam_port = config.i2p_sam
        _sam_ok = I2PSAMConnection.is_available(_sam_host, _sam_port)
        if _sam_ok:
            safe_print(f'I2P     : {colorize('SAM bridge (unique destination per session)', 'green')}')
        else:
            safe_print(f'I2P     : {colorize('SOCKS5 (shared destination — SAM not available)', 'yellow')}')
    safe_print(colorize('=' * 50, 'dim') + '\n')
    if TEST_MODE:
        safe_print(colorize('Tests are now run via pytest:', 'cyan'))
        safe_print(colorize("  pytest -v -k 'not 300k'", 'green'))
        safe_print(colorize('  (207 tests across 9 test files)', 'dim'))
        return 0
    client = EnhancedOTRv4IRCClient(config)
    if not client.connect():
        _fail_net = NetworkConstants.detect(config.server)
        _fail_hints = {NetworkConstants.NET_TOR: "Failed to connect via Tor.\n  • Desktop: ensure tor is running  (systemctl start tor)\n  • Android: start Orbot and tap 'Start'\n  • Tor Browser: make sure it is open (SOCKS5 on 9150)\n  Probed ports: 9050, 9150.", NetworkConstants.NET_I2P: 'Failed to connect via I2P — is i2pd running?\n  Check: i2pd SOCKS5 port 4447, SAM port 7656.', NetworkConstants.NET_CLEARNET: 'Failed to connect — check server address and network.'}
        safe_print(colorize(_fail_hints.get(_fail_net, 'Failed to connect.'), 'red'))
        return 1
    client.start_auto_smp_monitor()
    import builtins as _b
    _b._active_client = client

    try:
        import signal as _sig

        def _on_winch(_s, _f):
            if client._tui_enabled and client._screen is not None:
                client._screen.redraw_full()
        _sig.signal(_sig.SIGWINCH, _on_winch)
    except Exception:
        pass

    def _print_prompt():
        active = client.panel_manager.get_active_panel()
        if not active:
            _set_prompt(colorize('> ', 'green'))
            return
        sec_lvl = active.security_level
        if active.type in ('private', 'secure'):
            icon = UIConstants.SECURITY_ICONS.get(sec_lvl, '🔴')
        else:
            icon = ''
        if active.type in ('private', 'secure'):
            type_sym = ''
        elif active.type == 'channel':
            type_sym = ''
        elif active.type == 'system':
            type_sym = '⚙'
        elif active.type == 'debug':
            type_sym = '🐛'
        else:
            type_sym = ''
        smp_inset = ''
        step, total = active.smp_progress
        if 0 < step < total:
            bar = '⬤' * step + '◯' * (total - step)
            smp_inset = colorize(f' {bar} ', 'yellow')
        nick = getattr(client, 'nick', '')
        bracket = f'{type_sym}{icon}{active.name}'
        prompt = (colorize(nick, 'cyan')
                  + colorize(' | ', 'dim')
                  + colorize(f'[{bracket}]', 'green')
                  + smp_inset + ' ')
        _set_prompt(prompt)
    client._prompt_refresh_cb = _print_prompt
    try:
        _print_prompt()
        _use_raw = _setup_raw_mode()
        if _use_raw:
            atexit.register(_restore_terminal)
        _fd = _stdin_fd if _use_raw else sys.stdin.fileno()

        def _read_line_raw() -> Optional[str]:
            ch = _read_one_char()
            if ch is None:
                return _EOF_SENTINEL
            return _handle_input_char(ch)

        def _read_line_cooked() -> Optional[str]:
            global _current_prompt
            line = sys.stdin.readline()
            _current_prompt = ''
            _flush_display_queue()
            if not line:
                return _EOF_SENTINEL
            return line.rstrip('\r\n')
        _read_input = _read_line_raw if _use_raw else _read_line_cooked
        while not client.shutdown_flag:
            try:
                r, _, _ = _select.select([_fd], [], [], 0.2)
                if not r:
                    _flush_display_queue()
                    if not client.running and (not client.shutdown_flag) and (not client._reconnecting):
                        safe_print(colorize('\n⚠ Disconnected from server. Type /reconnect to reconnect, or /quit to exit.', 'yellow'))
                        while not client.shutdown_flag and (not client.running) and (not client._reconnecting):
                            try:
                                r2, _, _ = _select.select([_fd], [], [], 0.5)
                                if not r2:
                                    continue
                                result = _read_input()
                                if result is _EOF_SENTINEL:
                                    client.shutdown_flag = True
                                    break
                                if result is None:
                                    continue
                                l2 = result
                                if l2.startswith('/'):
                                    client.handle_command(l2[1:])
                                elif l2:
                                    safe_print(colorize('Not connected — use /reconnect first.', 'yellow'))
                                _print_prompt()
                            except KeyboardInterrupt:
                                safe_print(colorize('\nCtrl-C — type /quit to exit', 'yellow'))
                                _print_prompt()
                            except Exception:
                                pass
                        continue
                    continue
                result = _read_input()
                if result is _EOF_SENTINEL:
                    safe_print(colorize('\nEOF — shutting down', 'yellow'))
                    break
                if result is None:
                    continue
                line = result
                if not line:
                    _print_prompt()
                    continue
                if line.startswith('/'):
                    client.handle_command(line[1:])
                else:
                    client.handle_chat_message(line)
                _print_prompt()
            except KeyboardInterrupt:
                safe_print(colorize('\nCtrl-C — type /quit to exit', 'yellow'))
                _print_prompt()
            except Exception as exc:
                try:
                    client.debug(f'main loop error: {exc}')
                    client.add_message('system', colorize(f'⚠ Internal error (recovered): {str(exc)[:80]}', 'yellow'))
                except Exception:
                    pass
                _print_prompt()
    except Exception as exc:
        try:
            safe_print(colorize(f'⚠ Critical error (attempting recovery): {exc}', 'yellow'))
            while True:
                try:
                    r, _, _ = _select.select([_fd], [], [], 1.0)
                    if r:
                        if _use_raw:
                            ch = _read_one_char()
                            if ch is None:
                                break
                            res = _handle_input_char(ch)
                            if res is _EOF_SENTINEL:
                                break
                            if isinstance(res, str) and res.startswith('/quit'):
                                break
                            if res is None:
                                continue
                        else:
                            l = sys.stdin.readline()
                            if not l:
                                break
                            l = l.rstrip('\r\n')
                            if l.startswith('/quit'):
                                break
                        safe_print(colorize('Emergency mode — type /quit to exit', 'yellow'))
                except Exception:
                    break
        except Exception:
            pass
    _restore_terminal()
    client.shutdown()
    return 0
if __name__ == '__main__':
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        gc.freeze()
    except AttributeError:
        pass
    sys.setswitchinterval(0.05)
    if 'PYTHONMALLOC' not in os.environ:
        print(colorize('[HARDENING] For maximum security launch with:  PYTHONMALLOC=malloc python otrv4+.py', 'yellow'))
    atexit.register(lambda: safe_print(colorize('\nClean shutdown', 'green')))
    main()