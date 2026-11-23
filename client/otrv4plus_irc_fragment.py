# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Splitting OTRv4 messages to fit IRC lines, and putting them back together.

An IRC line is at most 512 bytes; a post-quantum DAKE message is about
12 KB. `OTRMessageFragmenter` splits one into `?OTRv4|sender|receiver|k|n|...`
pieces (and still reads the older `?OTRv4 [k/n]` form), and
`OTRFragmentBuffer` reassembles them per sender, with limits on count,
size and age so a peer cannot make it hold unbounded memory.

This is the IRC client's format. XMPP uses `?OTRv4F|` (otrv4plus_fragment,
shared with the Android app). Moved out of otrv4+.py, which re-exports
both classes.
"""
import math
import re
import threading
import time
from typing import Dict, List, Optional

import otrv4plus_debug as _debug
from otrv4plus_states import UIConstants
from otrv4plus_tty import _emit_line, _set_prompt


class OTRFragmentBuffer:
    """Reassemble fragmented OTRv4 messages.

    Supports both the spec-compliant pipe format (for interoperability) and the
    legacy bracket format (for backward compatibility with older builds):

        Spec:   ?OTRv4|sender_tag|receiver_tag|k|n|data.
        Legacy: ?OTRv4 [k/n]data
    """

    _SPEC_RE = re.compile(
        r"^\?OTRv4"
        r"\|([0-9A-Fa-f]{8})"
        r"\|([0-9A-Fa-f]{8})"
        r"\|(\d{5})"
        r"\|(\d{5})"
        r"\|(.*?)\.?$",
        re.DOTALL,
    )

    _LEGACY_RE = re.compile(r"^\?OTRv4\s*" r"(?:\[(\d+)/(\d+)\])?" r"(.*?)(?:\.?)$", re.DOTALL)

    def __init__(self, timeout: float = UIConstants.FRAGMENT_TIMEOUT):

        self._buffers: Dict[tuple, Dict] = {}
        self._lock = threading.RLock()
        self.timeout = timeout
        self.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT
        self.max_total_senders = 100
        self.first_fragment_cb = None

    def add_fragment(self, sender: str, raw: str) -> Optional[str]:
        """Accept one raw PRIVMSG payload from `sender`.

        Returns str (fully reassembled ``?OTRv4 <payload>``) when complete,
        or None while still waiting for more fragments.
        """
        with self._lock:
            now = time.monotonic()
            self._expire(now)

            msg = raw.strip()

            m_spec = self._SPEC_RE.match(msg)
            if m_spec:
                _sender_tag, _recv_tag, k_s, n_s, chunk = m_spec.groups()
                idx = int(k_s)
                total = int(n_s)
                if total < 1 or not (1 <= idx <= total):
                    raise ValueError(f"invalid spec fragment index {idx }/{total }")
                return self._buffer(sender, idx, total, chunk.strip(), now)

            while msg.startswith("?OTRv4 ?OTRv4"):
                msg = "?OTRv4 " + msg[len("?OTRv4 ?OTRv4 ") :]
            if msg.startswith("?OTRv4[") and not msg.startswith("?OTRv4 ["):
                msg = "?OTRv4 [" + msg[7:]
            if msg.endswith("."):
                msg = msg[:-1]

            m_leg = self._LEGACY_RE.match(msg)
            if not m_leg:
                return raw

            idx_s, total_s, chunk = m_leg.groups()
            chunk = chunk.strip()

            if idx_s is None:
                return f"?OTRv4 {chunk }"

            idx = int(idx_s)
            total = int(total_s)
            if total < 1 or not (1 <= idx <= total):
                raise ValueError(f"invalid legacy fragment index {idx }/{total }")
            return self._buffer(sender, idx, total, chunk, now)

    def _buffer(self, sender: str, idx: int, total: int, chunk: str, now: float) -> Optional[str]:
        """Insert chunk into the reassembly buffer and return full message when done.

        Buffer key is ``(sender_nick, total)`` so concurrent in-flight messages
        with different fragment counts (e.g. a 10-frag SMP1 alongside a 2-frag
        ratchet advance) coexist without corrupting each other.

        When fragment 1 of a new sequence arrives for a ``(sender, total)`` slot
        that already contains a partial assembly, the slot is reset - this safely
        handles the edge case of two sequential messages with the same total count.
        """

        if total > self.max_fragments_per_sender:
            raise ValueError(
                f"Fragment total {total } from {sender } exceeds max "
                f"{self .max_fragments_per_sender }. Discarding."
            )
        _ABSOLUTE_MAX_FRAGMENTS = 1000
        if total > _ABSOLUTE_MAX_FRAGMENTS:
            raise ValueError(
                f"Fragment total {total } from {sender } exceeds absolute "
                f"maximum of {_ABSOLUTE_MAX_FRAGMENTS }. Discarding."
            )

        key = (sender, total)

        if idx == 1 or key not in self._buffers:
            self._buffers[key] = {
                "total": total,
                "parts": {},
                "first_ts": now,
                "last_ts": now,
            }
            if total > 1 and idx == 1 and self.first_fragment_cb is not None:
                try:
                    self.first_fragment_cb(sender, total, chunk)
                except Exception:
                    pass

        state = self._buffers[key]

        if len(state["parts"]) >= self.max_fragments_per_sender:
            self._buffers.pop(key, None)
            raise ValueError(
                f"Fragment flood from {sender } (total={total }): exceeded "
                f"{self .max_fragments_per_sender } in-flight fragments. Buffer evicted."
            )

        if idx not in state["parts"]:

            _MAX_REASSEMBLED_BYTES = 1_048_576
            _current_bytes = sum(len(c) for c in state["parts"].values())
            if _current_bytes + len(chunk) > _MAX_REASSEMBLED_BYTES:
                self._buffers.pop(key, None)
                raise ValueError(
                    f"Fragment payload from {sender } exceeds 1 MiB limit - discarding."
                )
            state["parts"][idx] = chunk
            state["last_ts"] = now

            if _debug.FLAGS.debug:
                _c = getattr(__import__("builtins"), "_active_client", None)
                if _c:
                    _c._emit("debug", "[OTRFragment] fragment received")
                else:
                    _emit_line(f"[OTRFragment] {idx }/{total } for {sender }")

            if total > 1:
                try:
                    got = len(state["parts"])
                    _rb = "█" * got + "░" * (total - got)
                    _set_prompt(f"\x1b[36m⟳ RX {sender } [{got }/{total }] {_rb }\x1b[0m ")
                except Exception:
                    pass

        if len(state["parts"]) == total:
            payload_parts = []
            for i in range(1, total + 1):
                if i not in state["parts"]:
                    self._buffers.pop(key, None)
                    return None
                payload_parts.append(state["parts"][i])

            combined = "".join(payload_parts)
            self._buffers.pop(key, None)

            if _debug.FLAGS.debug:
                _c = getattr(__import__("builtins"), "_active_client", None)
                if _c:
                    _c._emit(
                        "debug", "[OTRFragment] fragment reassembled"
                    )
                else:
                    _emit_line(f"[OTRFragment] reassembled {len (combined )} chars from {sender }")

            try:
                _cr = getattr(__import__("builtins"), "_active_client", None)
                if _cr and _cr._prompt_refresh_cb:
                    _cr._prompt_refresh_cb()
            except Exception:
                pass
            return f"?OTRv4 {combined }"

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
        """Return total fragment count across all in-progress assemblies for sender."""
        with self._lock:
            return sum(
                len(state["parts"]) for (s, _t), state in self._buffers.items() if s == sender
            )

    def _expire(self, now: float) -> None:
        if len(self._buffers) > self.max_total_senders:
            oldest = sorted(self._buffers.items(), key=lambda x: x[1].get("first_ts", 0))
            for key, _ in oldest[: len(self._buffers) - self.max_total_senders]:
                if _debug.FLAGS.debug:
                    _emit_line(
                        f"[fragment] buffer evict: too many senders, dropping {key [0 ]}/{key [1 ]}"
                    )
                del self._buffers[key]
        cutoff = now - self.timeout
        expired = [
            k
            for k, st in self._buffers.items()
            if st.get("last_ts", st.get("first_ts", 0)) < cutoff
        ]
        for k in expired:
            sender_nick, frag_total = k
            state = self._buffers.pop(k, None)
            if state is None:
                continue
            got = len(state.get("parts", {}))
            if _debug.FLAGS.debug:
                _emit_line(
                    f"[fragment] timeout: {sender_nick } {got }/{frag_total } frags - type /otr {sender_nick } to retry"
                )

    def cleanup_expired(self) -> int:
        with self._lock:
            now = time.monotonic()
            before = len(self._buffers)
            self._expire(now)
            return before - len(self._buffers)


class OTRMessageFragmenter:
    """Fragment OTRv4 messages for IRC/I2P transmission.

    Spec §4.7 fragment wire format:
        ?OTRv4|sender_tag|receiver_tag|k|n|data.

    Where:
      sender_tag / receiver_tag  are 8-digit zero-padded hex (32-bit instance tags)
      k                          is the 1-based fragment index, zero-padded to 5 digits
      n                          is the total count, zero-padded to 5 digits
      data                       is the raw base64 chunk (no ?OTRv4 prefix, no trailing dot)
      trailing dot               is appended by this encoder

    The buffer class (OTRFragmentBuffer) accepts both this format and the legacy
    ``?OTRv4 [k/n]data`` format produced by older builds.
    """

    _SPEC_OVERHEAD = len("?OTRv4|00000000|00000000|00001|00001|.")
    _LEGACY_PREFIX = "?OTRv4 "

    @classmethod
    def fragment(
        cls,
        otr_message: str,
        max_line: int = UIConstants.OTR_FRAGMENT_SIZE,
        sender_tag: int = 0,
        receiver_tag: int = 0,
    ) -> List[str]:
        """Fragment an OTRv4 message for IRC/I2P transmission.

        Unfragmented (fits in max_line): returned as-is (``?OTRv4 <base64>``).
        Fragmented: emits spec-compliant ``?OTRv4|stag|rtag|k|n|data.`` lines.

        NOT anti-fingerprinting.  This docstring used to claim that every
        multi-fragment message was padded to a uniform fragment count so an
        observer could not tell DAKE1 from DAKE3 by counting IRC lines.  No
        such padding is implemented here, and no MIN_FRAGMENTS constant
        exists anywhere in the file -- the claim described an intention, and
        a reader checking whether the traffic pattern is protected would have
        found the answer and been wrong.

        The fragment count is therefore a reliable signal of which protocol
        message is in flight, to anyone who can see the lines: the IRC server
        always, and on I2P nobody else.  Fixing it means padding every
        message to the largest (48 fragments for SMP2/SMP3), which would cost
        more time than the whole pacing change in v10.25.0 saves.  Recorded
        as a known limitation rather than silently implied to be solved.
        """
        if not otr_message.startswith(cls._LEGACY_PREFIX):
            return [otr_message]

        payload = otr_message[len(cls._LEGACY_PREFIX) :]
        if payload.endswith("."):
            payload = payload[:-1]

        if not payload:
            return [otr_message]

        if len(otr_message) <= max_line:
            return [otr_message]

        stag_hex = f"{sender_tag :08X}"
        rtag_hex = f"{receiver_tag :08X}"
        overhead = len(f"?OTRv4|{stag_hex }|{rtag_hex }|00001|00001|.")

        chunk_size = max_line - overhead
        if chunk_size < 4:
            chunk_size = 4

        chunk_size = (chunk_size // 4) * 4
        if chunk_size < 4:
            chunk_size = 4

        total = math.ceil(len(payload) / chunk_size)

        fragments: List[str] = []
        for i in range(total):
            start = i * chunk_size
            end = min(start + chunk_size, len(payload))
            chunk = payload[start:end]
            k_str = f"{i +1 :05d}"
            n_str = f"{total :05d}"
            frag = f"?OTRv4|{stag_hex }|{rtag_hex }|{k_str }|{n_str }|{chunk }."
            fragments.append(frag)

        if _debug.FLAGS.debug:
            _c = getattr(__import__("builtins"), "_active_client", None)
            _msg = f"[OTRMessageFragmenter] {len (fragments )} frags from {len (payload )} chars"
            if _c:
                _c._emit("debug", _msg)
            else:
                _emit_line(_msg)

        return fragments

    @staticmethod
    def fragment_otr_message(
        otr_message: str, fragment_size: int = UIConstants.OTR_FRAGMENT_SIZE
    ) -> List[str]:
        return OTRMessageFragmenter.fragment(otr_message, fragment_size)
