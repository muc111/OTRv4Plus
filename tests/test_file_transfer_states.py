#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A transfer says how it ended, in codes, from the protocol -- never a timer.

The Android report: a transfer could sit at "transferring" forever. The
sender's row stayed at 100% because nothing ever told it the receiver had
the file, and every line the engine wrote about an ending went to a `notify`
the Android bridge drops by design. These drive two real managers over real
ratchets from one DAKE and hold:

* success: the receiver reaches RECEIVED only after its integrity checks, and
  the sender goes SENT -> DELIVERED only on the receiver's RECEIVED;
* a peer that never sends RECEIVED (an older build) leaves the sender at SENT,
  which is true, rather than DELIVERED, which would not be;
* decline, cancel, a forged chunk and a hash mismatch each end in their own
  state on BOTH sides -- the sender is told when the receiver throws the file
  away;
* a RECEIVED from the wrong peer, or before the send finished, is ignored;
* the Android bridge turns each change into a `FileTransferChanged` event and
  keeps ended rows visible.
"""

import hashlib
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")
ft = pytest.importorskip("otrv4plus_filetransfer")

S = ft.TransferState
R = ft.TransferReason


def _session_manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


def _relay(current, sender, receiver, sender_id, receiver_id, limit=10):
    for _ in range(limit):
        if not current:
            break
        out = receiver.handle_incoming_message(sender_id, current)
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        if not text or not text.startswith("?OTRv4"):
            break
        current = text
        sender, receiver = receiver, sender
        sender_id, receiver_id = receiver_id, sender_id


@pytest.fixture(scope="module")
def ratchets():
    try:
        otr._dake1_rate_limiter._attempts.clear()
    except Exception:
        pass
    a_mgr, b_mgr = _session_manager(), _session_manager()
    alice, bob = "alice@states.test", "bob@states.test"
    dake1, _ = a_mgr.handle_outgoing_message(bob, "")
    _relay(dake1, a_mgr, b_mgr, alice, bob)
    return (a_mgr.get_session(bob).ratchet._rust,
            b_mgr.get_session(alice).ratchet._rust, a_mgr, b_mgr)


class _Link(ft.ChunkTransport):
    """Delivers straight into the other manager, as `peer`.

    `drop` names verbs to swallow (an older peer that never sends RECEIVED);
    `tamper` corrupts one chunk index on the way.
    """

    def __init__(self, me, drop=(), tamper=None):
        self.me, self.other, self.drop, self.tamper = me, None, set(drop), tamper
        self.sent = []

    def send_control(self, peer, verb, payload):
        self.sent.append(verb)
        if verb in self.drop:
            return True
        self.other.handle_control(self.me, ft.FILE_PREFIX + verb +
                                  ((":" + payload) if payload else ""))
        return True

    def send_chunk(self, peer, transfer_id, index, sealed):
        if self.tamper == index:
            sealed = bytes(sealed[:-1]) + bytes([sealed[-1] ^ 1])
        try:
            self.other.deliver_chunk(self.me, transfer_id, index, sealed)
        except ft.TransferError:
            pass
        return True


def _pair(ratchets, alice_drop=(), bob_drop=(), tamper=None):
    a_ratchet, b_ratchet, _, _ = ratchets
    alice, bob = "alice@states.test", "bob@states.test"
    a_link, b_link = _Link(alice, drop=alice_drop, tamper=tamper), _Link(bob, drop=bob_drop)
    seen = {"a": [], "b": []}
    a = ft.FileTransferManager(a_link, notify=lambda _t: None, verified=lambda _p: True,
                               on_state=lambda t, out: seen["a"].append((out, t.state, t.reason)))
    b = ft.FileTransferManager(b_link, notify=lambda _t: None, verified=lambda _p: True,
                               on_state=lambda t, out: seen["b"].append((out, t.state, t.reason)))
    a_link.other, b_link.other = b, a
    return a, b, a_ratchet, b_ratchet, alice, bob, seen


def _file(size=40_000):
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(os.urandom(size))
    return path


@pytest.fixture(autouse=True)
def _private_dirs(monkeypatch):
    # mkdtemp, not tmp_path: the suite stubs `pwd`, which tmp_path needs.
    monkeypatch.setenv("OTRV4PLUS_FILE_DIR",
                       os.path.join(tempfile.mkdtemp(), "files"))


def _states(seen, side):
    return [s for _out, s, _r in seen[side]]


def test_success_is_received_then_delivered(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    path = _file()
    a.offer_file(bob, path, ar)
    (key,) = list(b.incoming)
    assert _states(seen, "b") == [S.OFFERED]
    b.accept(bytes.fromhex(key), br)
    assert _states(seen, "a") == [S.WAITING, S.ACCEPTED, S.SENT, S.DELIVERED]
    assert _states(seen, "b") == [S.OFFERED, S.ACCEPTED, S.RECEIVED]
    assert a.outgoing == {} and b.incoming == {}
    saved = [f for f in os.listdir(ft.state_dir()) if not f.startswith(".")]
    assert len(saved) == 1
    with open(path, "rb") as fh, open(os.path.join(ft.state_dir(), saved[0]), "rb") as gh:
        assert hashlib.sha256(fh.read()).digest() == hashlib.sha256(gh.read()).digest()


def test_an_older_peer_that_never_confirms_leaves_the_sender_at_sent(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets, bob_drop={"RECEIVED"})
    a.offer_file(bob, _file(), ar)
    (key,) = list(b.incoming)
    b.accept(bytes.fromhex(key), br)
    assert _states(seen, "a")[-1] == S.SENT, "claimed delivery nobody confirmed"
    assert _states(seen, "b")[-1] == S.RECEIVED


def test_decline_ends_both_sides(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    a.offer_file(bob, _file(), ar)
    (key,) = list(b.incoming)
    b.decline(bytes.fromhex(key))
    assert seen["b"][-1] == (False, S.DECLINED, R.BY_US)
    assert seen["a"][-1] == (True, S.DECLINED, R.BY_PEER)
    assert a.outgoing == {} and b.incoming == {}


def test_cancel_by_the_sender_ends_both_sides(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    t = a.offer_file(bob, _file(), ar)
    a.cancel(t.offer.transfer_id)
    assert seen["a"][-1] == (True, S.CANCELLED, R.BY_US)
    assert seen["b"][-1] == (False, S.CANCELLED, R.BY_PEER)
    assert b.incoming == {}


def test_a_forged_chunk_fails_the_receiver_and_tells_the_sender(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets, tamper=1)
    a.offer_file(bob, _file(200_000), ar)
    (key,) = list(b.incoming)
    b.accept(bytes.fromhex(key), br)
    assert (False, S.FAILED, R.AUTH_FAILED) in seen["b"]
    assert S.RECEIVED not in _states(seen, "b")
    assert S.DELIVERED not in _states(seen, "a")
    assert (True, S.CANCELLED, R.BY_PEER) in seen["a"]
    assert os.listdir(ft.incoming_dir()) == [], "a partial file was left behind"


def test_a_hash_mismatch_at_done_fails_and_tells_the_sender(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    t = a.offer_file(bob, _file(), ar)
    (key,) = list(b.incoming)
    # The offer's advertised plaintext hash no longer matches what arrives.
    b.incoming[key].offer.plaintext_sha256 = b"\0" * 32
    b.accept(bytes.fromhex(key), br)
    assert seen["b"][-1] == (False, S.FAILED, R.VERIFY_FAILED)
    assert S.DELIVERED not in _states(seen, "a")
    assert (True, S.CANCELLED, R.BY_PEER) in seen["a"]
    assert [f for f in os.listdir(ft.state_dir()) if not f.startswith(".")] == []
    assert os.listdir(ft.incoming_dir()) == []
    del t


def test_a_received_from_the_wrong_peer_or_too_early_is_ignored(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    t = a.offer_file(bob, _file(), ar)
    key = t.offer.transfer_id.hex()
    a.handle_control("mallory@states.test", ft.FILE_PREFIX + "RECEIVED:" + key)
    a.handle_control(bob, ft.FILE_PREFIX + "RECEIVED:" + key)   # not accepted yet
    assert S.DELIVERED not in _states(seen, "a")
    assert key in a.outgoing


def test_a_cancel_from_the_wrong_peer_is_ignored(ratchets):
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    t = a.offer_file(bob, _file(), ar)
    key = t.offer.transfer_id.hex()
    a.handle_control("mallory@states.test", ft.FILE_PREFIX + "CANCEL:" + key)
    assert key in a.outgoing and S.CANCELLED not in _states(seen, "a")


def test_a_ui_callback_that_raises_does_not_break_the_transfer(ratchets):
    a_ratchet, b_ratchet, _, _ = ratchets
    a, b, ar, br, alice, bob, seen = _pair(ratchets)

    def boom(*_a):
        raise RuntimeError("ui bug")
    a._on_state = boom
    b._on_state = boom
    a.offer_file(bob, _file(), ar)
    (key,) = list(b.incoming)
    b.accept(bytes.fromhex(key), br)
    assert a.outgoing == {} and b.incoming == {}


# -- the Android bridge -------------------------------------------------------

class _Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


def test_the_bridge_emits_structured_events_and_keeps_ended_rows():
    from android_bridge.files import FileBridge
    from android_bridge.events import FileTransferChanged

    class _App:
        def __init__(self):
            self.sink = _Sink()

        def _emit(self, event):
            self.sink.on_event(event)

    app = _App()
    bridge = FileBridge(app)
    bridge._manager = object()        # not None: transfers() reads the dicts

    class _Mgr:
        outgoing, incoming = {}, {}
    bridge._manager = _Mgr()

    offer = ft.Offer(transfer_id=b"\x07" * 16, filename="../../evil‮.txt",
                     plaintext_size=1234, encrypted_size=1300, chunk_count=1,
                     encrypted_sha256=b"\0" * 32, plaintext_sha256=b"\0" * 32,
                     envelope=b"e")
    transfer = ft.IncomingTransfer(peer="bob@states.test", offer=offer)
    transfer.state, transfer.reason = S.RECEIVED, ""
    bridge._on_state(transfer, False)

    (event,) = app.sink.events
    assert isinstance(event, FileTransferChanged)
    assert event.state == S.RECEIVED and event.outgoing is False and event.size == 1234
    assert "/" not in event.filename and "‮" not in event.filename
    rows = bridge.transfers()
    assert [r["state"] for r in rows] == [S.RECEIVED], "an ended row vanished"
    assert "sha" not in " ".join(rows[0].keys())

    bridge.shutdown()
    assert bridge.transfers() == []


def test_the_bridge_can_cancel_its_own_send(ratchets):
    """Cancel on a sending row used to route through `decline`, which only
    knows incoming offers, and did nothing."""
    from android_bridge.files import FileBridge, FileOutcome
    a, b, ar, br, alice, bob, seen = _pair(ratchets)
    t = a.offer_file(bob, _file(), ar)

    class _App:
        def _emit(self, _e):
            pass
    bridge = FileBridge(_App())
    bridge._manager = a
    key = t.offer.transfer_id.hex()
    assert bridge.decline(key) == FileOutcome.NO_TRANSFER     # the old route
    assert bridge.cancel(key) == FileOutcome.STARTED
    assert seen["a"][-1] == (True, S.CANCELLED, R.BY_US)
    assert seen["b"][-1] == (False, S.CANCELLED, R.BY_PEER)
    assert bridge.cancel("00" * 16) == FileOutcome.NO_TRANSFER
