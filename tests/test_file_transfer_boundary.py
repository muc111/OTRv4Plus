#!/usr/bin/env python3
"""INV-21, INV-22 end to end: two real sessions, a real file, on real disk.

The other two modules test the pieces.  This one runs a whole transfer --
offer, accept, chunks, verification, atomic placement -- between two managers
whose ratchets came from an actual DAKE, and then tries to break it.

It also pins the SCOPE rule: /sendfile is XMPP-only.  The IRC client must not
import the transfer module, gain a /sendfile command, or acquire any
file-transfer TLV handling.  TestTheFeatureIsXmppOnly is what fails if that
changes, and it is the reason this file exists rather than the assertions
living in the other two.
"""

import ast
import hashlib
import inspect
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ft = pytest.importorskip("otrv4plus_filetransfer")
core = pytest.importorskip("otrv4_core")
otr = pytest.importorskip("otrv4_")

from test_file_transfer_crypto import (          # noqa: E402
    _clear_dake_rate_limit, _manager, _relay,
)


# --------------------------------------------------------------------------
# a wired-up pair
# --------------------------------------------------------------------------

class Wire:
    """Two managers joined by a list.  Stands in for the OTR channel.

    Deliberately NOT the XMPP client: the engine takes its pump as a
    parameter, and proving that means driving it with something that is not
    XMPP.  If this test ever needs slixmpp, the transport independence the
    module claims has been lost.
    """

    def __init__(self):
        self.alice = None
        self.bob = None
        self.notes = []
        self.drop = set()

    def send_from(self, who):
        def _send(peer, verb, payload):
            if verb in self.drop:
                return True                      # delivered nowhere
            body = ft.FILE_PREFIX + verb + ((":" + payload) if payload else "")
            target = self.bob if who == "alice" else self.alice
            # The label is who SENT it.  Getting this backwards made three
            # tests fail with "data frame from the wrong peer", which is the
            # engine correctly refusing a frame attributed to the wrong side.
            target.handle_control(who, body)
            return True
        return _send

    def note(self, line):
        self.notes.append(line)


@pytest.fixture(scope="module")
def ratchets():
    _clear_dake_rate_limit()
    alice_mgr, bob_mgr = _manager(), _manager()
    a_id, b_id = "a@example.test", "b@example.test"
    dake1, _ = alice_mgr.handle_outgoing_message(b_id, "")
    _relay(dake1, alice_mgr, bob_mgr, a_id, b_id)
    assert alice_mgr.has_encrypted_session(b_id)
    return (alice_mgr.get_session(b_id).ratchet._rust,
            bob_mgr.get_session(a_id).ratchet._rust)


@pytest.fixture
def wired(ratchets, monkeypatch, tmp_path_factory):
    directory = tempfile.mkdtemp()
    monkeypatch.setenv("OTRV4PLUS_FILE_DIR", os.path.join(directory, "files"))
    wire = Wire()
    wire.alice = ft.FileTransferManager(
        transport=ft.OtrChunkTransport(wire.send_from("alice")),
        notify=wire.note, verified=lambda peer: True)
    wire.bob = ft.FileTransferManager(
        transport=ft.OtrChunkTransport(wire.send_from("bob")),
        notify=wire.note, verified=lambda peer: True)
    a_ratchet, b_ratchet = ratchets
    return wire, a_ratchet, b_ratchet


def _source_file(size, name="video.mp4"):
    directory = tempfile.mkdtemp()
    path = os.path.join(directory, name)
    blob = os.urandom(size)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path, blob


def _run(wired, size=5000, name="video.mp4"):
    """Offer, accept, pump, finish.  Returns (final_path, original_bytes)."""
    wire, a_ratchet, b_ratchet = wired
    path, blob = _source_file(size, name)
    transfer = wire.alice.offer_file("bob", path, a_ratchet)
    incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
    wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
    wire.alice._pump(transfer)
    return incoming, blob


# --------------------------------------------------------------------------
# the happy path
# --------------------------------------------------------------------------

class TestAWholeTransfer:

    def test_the_file_arrives_byte_identical(self, wired):
        wire, *_ = wired
        _incoming, blob = _run(wired, 5000)
        landed = os.listdir(ft.state_dir())
        landed = [f for f in landed if not f.startswith(".")]
        assert landed == ["video.mp4"]
        got = open(os.path.join(ft.state_dir(), "video.mp4"), "rb").read()
        assert got == blob
        assert hashlib.sha256(got).digest() == hashlib.sha256(blob).digest()

    @pytest.mark.parametrize("size", [0, 1, 100, 20_000, 200_000])
    def test_sizes_from_empty_to_multi_chunk(self, wired, size):
        _incoming, blob = _run(wired, size)
        got = open(os.path.join(ft.state_dir(), "video.mp4"), "rb").read()
        assert got == blob

    def test_the_offer_reaches_the_peer_before_any_data(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(2000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        assert transfer.offer.transfer_id.hex() in wire.bob.incoming
        assert not wire.bob.incoming[
            transfer.offer.transfer_id.hex()].accepted

    def test_nothing_is_written_before_acceptance(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(2000)
        wire.alice.offer_file("bob", path, a_ratchet)
        visible = [f for f in os.listdir(ft.state_dir())
                   if not f.startswith(".")]
        assert visible == []
        assert os.listdir(ft.incoming_dir()) == []

    def test_the_temporary_file_is_gone_afterwards(self, wired):
        _run(wired, 20_000)
        assert os.listdir(ft.incoming_dir()) == [], (
            "a partial file survived a completed transfer")

    def test_the_transfer_state_is_dropped_on_completion(self, wired):
        wire, *_ = wired
        _run(wired, 3000)
        assert wire.bob.incoming == {}


# --------------------------------------------------------------------------
# declining and cancelling
# --------------------------------------------------------------------------

class TestDeclining:

    def test_declining_writes_nothing(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(3000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        wire.bob.decline(transfer.offer.transfer_id)
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []
        assert os.listdir(ft.incoming_dir()) == []

    def test_declining_clears_both_sides(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(3000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        wire.bob.decline(transfer.offer.transfer_id)
        assert wire.bob.incoming == {}
        assert wire.alice.outgoing == {}, (
            "the sender is still holding a sealed file and its key")


class TestCancelling:

    def test_cancelling_mid_transfer_removes_the_partial_file(self, wired):
        wire, a_ratchet, b_ratchet = wired
        path, _ = _source_file(200_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        wire.drop.add("ACCEPT")          # do not let the sender auto-pump
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        wire.drop.discard("ACCEPT")
        # one chunk in, then stop
        wire.alice.transport.send_chunk(
            "bob", transfer.offer.transfer_id, 0,
            getattr(transfer, "_sealed")[0])
        assert len(os.listdir(ft.incoming_dir())) == 1
        wire.bob.cancel(transfer.offer.transfer_id)
        assert os.listdir(ft.incoming_dir()) == []
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []

    def test_cancelling_zeroizes_the_sender(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(3000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        wire.alice.cancel(transfer.offer.transfer_id)
        assert transfer.sender.zeroized
        assert transfer.cancelled

    def test_a_cancelled_transfer_leaves_no_usable_file(self, wired):
        wire, a_ratchet, b_ratchet = wired
        path, _ = _source_file(150_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        wire.drop.add("ACCEPT")          # do not let the sender auto-pump
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        wire.drop.discard("ACCEPT")
        wire.bob.cancel(transfer.offer.transfer_id)
        everything = os.listdir(ft.state_dir()) + os.listdir(ft.incoming_dir())
        assert [f for f in everything if not f.startswith(".")] == []


# --------------------------------------------------------------------------
# things that must not produce a file
# --------------------------------------------------------------------------

class TestVerificationFailuresLeaveNothing:

    def _accepted(self, wired, size=20_000):
        """Accept without letting ACCEPT reach the sender.

        A delivered ACCEPT makes the sender pump the whole file immediately,
        which is what should happen in normal use -- and would finish the
        transfer before these tests could inject anything into it.  Dropping
        the ACCEPT leaves the receiver armed and the sender idle, so each
        chunk can be delivered deliberately.
        """
        wire, a_ratchet, b_ratchet = wired
        path, blob = _source_file(size)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        wire.drop.add("ACCEPT")
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        wire.drop.discard("ACCEPT")
        return wire, transfer, incoming, blob

    def test_a_truncated_transfer_is_refused(self, wired):
        """Every chunk but the last, then DONE."""
        wire, transfer, incoming, _ = self._accepted(wired)
        sealed = getattr(transfer, "_sealed")
        for i, chunk in enumerate(sealed[:-1]):
            wire.alice.transport.send_chunk(
                "bob", transfer.offer.transfer_id, i, chunk)
        with pytest.raises(ft.TransferError):
            wire.bob.on_done("alice", transfer.offer.transfer_id.hex())
        assert os.listdir(ft.incoming_dir()) == []
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []

    def test_a_tampered_chunk_is_refused_and_writes_nothing(self, wired):
        wire, transfer, incoming, _ = self._accepted(wired)
        bad = bytearray(getattr(transfer, "_sealed")[0])
        bad[5] ^= 0xFF
        tmp = incoming.tmp_path
        with pytest.raises(ft.TransferError, match="authentication"):
            wire.bob.on_data("alice", "%s|0|%s" % (
                transfer.offer.transfer_id.hex(), ft._b64(bytes(bad))))
        assert incoming.chunks_received == 0
        # The partial file is removed, not left waiting for chunks that can
        # never verify.
        assert not os.path.exists(tmp)
        assert os.listdir(ft.incoming_dir()) == []
        assert wire.bob.incoming == {}

    def test_an_out_of_order_chunk_is_refused(self, wired):
        wire, transfer, _incoming, _ = self._accepted(wired)
        sealed = getattr(transfer, "_sealed")
        assert len(sealed) > 1
        with pytest.raises(ft.TransferError, match="was expected"):
            wire.bob.on_data("alice", "%s|1|%s" % (
                transfer.offer.transfer_id.hex(), ft._b64(sealed[1])))

    def test_a_gap_abandons_the_transfer_instead_of_reporting_every_chunk(
            self, wired):
        """The chunk AEAD is a sequence: a gap can never be filled in, so the
        transfer is already dead.  Reporting it once per remaining chunk
        buried the cause under twenty identical lines on a real device."""
        wire, transfer, _incoming, _ = self._accepted(wired)
        sealed = getattr(transfer, "_sealed")
        assert len(sealed) > 1
        tid = transfer.offer.transfer_id.hex()
        with pytest.raises(ft.TransferError, match="was expected"):
            wire.bob.on_data("alice", "%s|1|%s" % (tid, ft._b64(sealed[1])))
        assert wire.bob.incoming == {}, (
            "the transfer survived the gap, so every later chunk reports too")
        # And nothing partial is left behind.
        assert os.listdir(ft.incoming_dir()) == []

    def test_the_message_says_what_to_do_about_it(self, wired):
        """There is no retransmit.  A message that only names the fault
        leaves the user waiting for a transfer that cannot finish."""
        wire, transfer, _incoming, _ = self._accepted(wired)
        sealed = getattr(transfer, "_sealed")
        try:
            wire.bob.on_data("alice", "%s|1|%s" % (
                transfer.offer.transfer_id.hex(), ft._b64(sealed[1])))
        except ft.TransferError as exc:
            assert "send it again" in str(exc)
        else:
            raise AssertionError("the gap was accepted")

    def test_data_for_an_unaccepted_transfer_is_refused(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(3000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        with pytest.raises(ft.TransferError, match="not accepted"):
            wire.bob.on_data("alice", "%s|0|%s" % (
                transfer.offer.transfer_id.hex(),
                ft._b64(getattr(transfer, "_sealed")[0])))

    def test_data_for_an_unknown_transfer_is_refused(self, wired):
        wire, *_ = wired
        with pytest.raises(ft.TransferError, match="no such transfer"):
            wire.bob.on_data("alice", "%s|0|%s" % ("aa" * 16, ft._b64(b"x")))

    def _offer_with(self, wired, override):
        """Alice seals honestly, then lies in the offer.

        The offer's hashes and counts are NOT covered by the key envelope --
        the envelope binds the transfer id only -- so a malicious sender can
        state whatever it likes.  These are the checks that catch that.
        """
        wire, a_ratchet, b_ratchet = wired
        path, blob = _source_file(20_000)
        wire.drop.add("OFFER")
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        wire.drop.discard("OFFER")
        fields = transfer.offer.encode().split("|")
        for index, value in override.items():
            fields[index] = value
        wire.bob.on_offer("alice", "|".join(fields))
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        wire.drop.add("ACCEPT")
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        wire.drop.discard("ACCEPT")
        return wire, transfer, incoming

    def test_a_lying_plaintext_hash_is_caught(self, wired):
        """A sender that encrypts one file and claims the hash of another."""
        wire, transfer, _incoming = self._offer_with(wired, {8: "ab" * 32})
        sealed = getattr(transfer, "_sealed")
        for i, chunk in enumerate(sealed):
            wire.alice.transport.send_chunk(
                "bob", transfer.offer.transfer_id, i, chunk)
        with pytest.raises(ft.TransferError, match="hash mismatch"):
            wire.bob.on_done("alice", transfer.offer.transfer_id.hex())
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []
        assert os.listdir(ft.incoming_dir()) == []

    def test_a_lying_ciphertext_hash_is_caught(self, wired):
        wire, transfer, _incoming = self._offer_with(wired, {7: "cd" * 32})
        for i, chunk in enumerate(getattr(transfer, "_sealed")):
            wire.alice.transport.send_chunk(
                "bob", transfer.offer.transfer_id, i, chunk)
        with pytest.raises(ft.TransferError, match="hash mismatch"):
            wire.bob.on_done("alice", transfer.offer.transfer_id.hex())
        assert os.listdir(ft.incoming_dir()) == []

    def test_a_lying_chunk_count_is_caught(self, wired):
        """An offer claiming more chunks than the sender will deliver.

        The receiver must not accept a file it was told is incomplete, even
        if every chunk it did receive authenticated.
        """
        wire, transfer, _incoming = self._offer_with(wired, {6: "99"})
        for i, chunk in enumerate(getattr(transfer, "_sealed")):
            try:
                wire.alice.transport.send_chunk(
                    "bob", transfer.offer.transfer_id, i, chunk)
            except Exception:
                pass
        with pytest.raises(ft.TransferError):
            wire.bob.on_done("alice", transfer.offer.transfer_id.hex())
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []

    def test_a_size_larger_than_the_ciphertext_is_refused_at_parse(self, wired):
        """Ciphertext is always larger than plaintext, so this one never even
        reaches the transfer machinery."""
        wire, a_ratchet, _b = wired
        path, _ = _source_file(20_000)
        wire.drop.add("OFFER")
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        wire.drop.discard("OFFER")
        fields = transfer.offer.encode().split("|")
        fields[4] = "999999"
        with pytest.raises(ft.TransferError):
            ft.Offer.decode("|".join(fields))

    def test_a_size_smaller_than_reality_is_caught_at_the_end(self, wired):
        """Understating the size passes parsing -- it is consistent -- and is
        caught when what actually landed is measured."""
        wire, transfer, _incoming = self._offer_with(wired, {4: "100"})
        for i, chunk in enumerate(getattr(transfer, "_sealed")):
            wire.alice.transport.send_chunk(
                "bob", transfer.offer.transfer_id, i, chunk)
        with pytest.raises(ft.TransferError, match="size mismatch"):
            wire.bob.on_done("alice", transfer.offer.transfer_id.hex())
        assert [f for f in os.listdir(ft.state_dir())
                if not f.startswith(".")] == []

    def test_a_duplicate_offer_is_refused(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(1000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        with pytest.raises(ft.TransferError, match="duplicate"):
            wire.bob.on_offer("alice", transfer.offer.encode())

    def test_an_offer_from_an_unverified_peer_is_ignored(self, wired):
        wire, a_ratchet, _b = wired
        strict = ft.FileTransferManager(
            transport=ft.OtrChunkTransport(lambda *a: True),
            notify=wire.note, verified=lambda peer: False)
        path, _ = _source_file(1000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        assert strict.on_offer("alice", transfer.offer.encode()) is None
        assert strict.incoming == {}

    def test_sending_to_an_unverified_peer_is_refused(self, wired):
        wire, a_ratchet, _b = wired
        strict = ft.FileTransferManager(
            transport=ft.OtrChunkTransport(lambda *a: True),
            notify=wire.note, verified=lambda peer: False)
        path, _ = _source_file(1000)
        with pytest.raises(ft.TransferError, match="SMP verification"):
            strict.offer_file("bob", path, a_ratchet)


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------

class TestTheFeatureIsXmppOnly:
    """The scope rule, enforced rather than documented.

    /sendfile is for the XMPP client.  The IRC client must not import the
    module, gain the command, or acquire file-transfer message handling.
    """

    def _engine_source(self):
        return open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()

    def test_the_irc_engine_does_not_import_the_module(self):
        tree = ast.parse(self._engine_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "filetransfer" not in node.module, (
                    "the shared engine imports the file-transfer module at "
                    "line %d" % node.lineno)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert "filetransfer" not in alias.name, node.lineno

    def test_the_irc_engine_has_no_sendfile_command(self):
        src = self._engine_source()
        for banned in ("/sendfile", "sendfile", "FILE_PREFIX",
                       "?OTRv4-FILE"):
            assert banned not in src, (
                "the IRC client gained %r; file transfer is XMPP-only"
                % banned)

    def test_the_irc_engine_gained_no_file_transfer_tlv(self):
        """The feature rides a prefixed OTR body, exactly as voice does, so
        the shared TLV code needs no new type.  A FILE TLV appearing here
        would mean IRC's OTR behaviour had changed for an XMPP feature."""
        src = self._engine_source()
        for banned in ("TLV_TYPE_FILE", "FILE_TRANSFER =", "FILE_OFFER"):
            assert banned not in src

    def test_the_xmpp_client_is_the_only_importer(self):
        importers = []
        for name in sorted(os.listdir(ROOT)):
            if not name.endswith(".py") or name == "otrv4plus_filetransfer.py":
                continue
            path = os.path.join(ROOT, name)
            if os.path.islink(path):
                continue
            if "otrv4plus_filetransfer" in open(path, encoding="utf-8").read():
                importers.append(name)
        assert importers == ["otrv4plus_xmpp.py"], (
            "file transfer is referenced by %s; it is XMPP-only" % importers)

    def test_the_module_says_so(self):
        head = inspect.getdoc(ft) or ""
        assert "XMPP only" in head
        assert "IRC" in head


# --------------------------------------------------------------------------
# the transport seam
# --------------------------------------------------------------------------

class BulkTransport(ft.ChunkTransport):
    """A second transport, standing in for the future torrent/SAM one.

    Control still goes over the OTR-shaped channel.  Chunks bypass it
    entirely: raw sealed bytes are handed straight to the peer's
    `deliver_chunk`, with no base64, no control framing and no size limit
    inherited from a stanza.  That is exactly the shape a bulk transport
    takes, and the point of these tests is that the engine above it does not
    change at all.
    """

    chunk_bytes = 64 * 1024          # the format maximum, not a stanza limit

    def __init__(self, wire, who):
        self.wire = wire
        self.who = who
        self.control_frames = 0
        self.bulk_chunks = 0

    def _peer(self):
        return self.wire.bob if self.who == "alice" else self.wire.alice

    def send_control(self, peer, verb, payload):
        self.control_frames += 1
        body = ft.FILE_PREFIX + verb + ((":" + payload) if payload else "")
        self._peer().handle_control(self.who, body)
        return True

    def send_chunk(self, peer, transfer_id, index, sealed):
        self.bulk_chunks += 1
        assert isinstance(sealed, (bytes, bytearray)), (
            "a transport received something other than raw sealed bytes")
        self._peer().deliver_chunk(self.who, transfer_id, index, bytes(sealed))
        return True


class TestTheEngineIsTransportIndependent:
    """The seam the torrent phase depends on.

    If these pass, swapping the transport is a transport change and nothing
    else -- the FileKey, the format, the hashes, the filename handling, the
    temporary-file lifecycle and the atomic commit are all above the line.
    """

    @pytest.fixture
    def bulk(self, ratchets, monkeypatch):
        directory = tempfile.mkdtemp()
        monkeypatch.setenv("OTRV4PLUS_FILE_DIR",
                           os.path.join(directory, "files"))
        wire = Wire()
        wire.alice = ft.FileTransferManager(
            transport=BulkTransport(wire, "alice"), notify=wire.note,
            verified=lambda peer: True)
        wire.bob = ft.FileTransferManager(
            transport=BulkTransport(wire, "bob"), notify=wire.note,
            verified=lambda peer: True)
        a_ratchet, b_ratchet = ratchets
        return wire, a_ratchet, b_ratchet

    def test_a_bulk_transport_delivers_the_same_file(self, bulk):
        """The whole lifecycle over a transport that shares no framing with
        the OTR one."""
        wire, a_ratchet, b_ratchet = bulk
        path, blob = _source_file(200_000, "clip.bin")
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        # accept() sends ACCEPT, which the sender answers by pumping.  No
        # manual pump: this is the real sequence.
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        got = open(os.path.join(ft.state_dir(), "clip.bin"), "rb").read()
        assert got == blob
        assert hashlib.sha256(got).digest() == hashlib.sha256(blob).digest()

    def test_bulk_chunks_never_touch_the_control_path(self, bulk):
        wire, a_ratchet, b_ratchet = bulk
        path, _ = _source_file(200_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        incoming = wire.bob.incoming[transfer.offer.transfer_id.hex()]
        wire.bob.accept(incoming.offer.transfer_id, b_ratchet)
        sender = wire.alice.transport
        assert sender.bulk_chunks > 1, "the file was not chunked"
        # OFFER and DONE only.  ACCEPT and the rest come from the other side.
        assert sender.control_frames == 2, (
            "control frames: %d -- a chunk went over the signalling path"
            % sender.control_frames)

    def test_the_transport_chooses_the_chunk_size(self, bulk):
        """A bulk transport can use the full format chunk; the OTR one
        cannot.  The size is a transport parameter, never a cryptographic
        one, so the same file produces different chunk counts and identical
        bytes."""
        wire, a_ratchet, _b = bulk
        path, _ = _source_file(200_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        assert transfer.offer.chunk_count == 4, "64 KiB chunks over ~195 KiB"

    def test_the_otr_transport_uses_a_smaller_chunk(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(200_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        assert transfer.offer.chunk_count == 13, "16 KiB chunks over ~195 KiB"

    def test_both_transports_produce_the_same_plaintext_hash(self, wired,
                                                             ratchets):
        """Chunk size changes the ciphertext framing and nothing about the
        file.  If this ever diverges, the format has become
        transport-dependent."""
        wire, a_ratchet, b_ratchet = wired
        path, blob = _source_file(200_000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        assert transfer.offer.plaintext_sha256 == hashlib.sha256(blob).digest()

    def test_the_engine_knows_nothing_about_xmpp(self):
        """Checked on CODE, not on prose.

        The module's comments discuss stanzas and SAM streams because that is
        what a reader needs to understand the seam.  What matters is that no
        executable line reaches for any of it.
        """
        tree = ast.parse(inspect.getsource(ft))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                node.value.value = ""
        code = ast.unparse(tree)
        for banned in ("slixmpp", "stanza", "send_message", "boundjid",
                       "presence", "Iq", "Message("):
            assert banned not in code, (
                "the transfer engine references %r in executable code; it "
                "must not know what carries its bytes" % banned)

    def test_only_the_otr_transport_knows_the_control_framing(self):
        """base64 and the pipe-joined DATA frame are properties of
        OtrChunkTransport, not of the format.  The engine keeps exactly one
        method that understands them -- on_data -- and it delegates."""
        engine = inspect.getsource(ft.FileTransferManager)
        assert engine.count("_b64(") == 0, (
            "the manager base64s a chunk; that belongs to the transport")
        assert engine.count("_unb64(") == 1, (
            "only on_data may decode a control-framed chunk")

    def test_every_transport_funnels_through_one_inbound_seam(self):
        engine = inspect.getsource(ft.FileTransferManager)
        assert "def deliver_chunk" in engine
        assert engine.count("open_chunk(") == 1, (
            "a second path calls open_chunk, so the ordering rule and the "
            "authentication can diverge between transports")

    def test_the_base_transport_refuses_rather_than_no_ops(self):
        """An incomplete transport must fail loudly, not silently drop."""
        base = ft.ChunkTransport()
        with pytest.raises(NotImplementedError):
            base.send_control("peer", "OFFER", "x")
        with pytest.raises(NotImplementedError):
            base.send_chunk("peer", b"\x00" * 16, 0, b"x")


# --------------------------------------------------------------------------
# the boundary
# --------------------------------------------------------------------------

class TestPythonHoldsNoKey:

    def test_the_engine_never_names_a_key(self):
        """The module is orchestration.  A variable holding key material
        would be the first sign that changed."""
        src = inspect.getsource(ft)
        for banned in ("file_key", "filekey", "wrap_key", "derive_key",
                       "AESGCM", "aes256gcm_encrypt", "aes256gcm_decrypt"):
            assert banned not in src, (
                "the Python engine references %r; all key handling belongs "
                "in Rust" % banned)

    def test_it_does_no_cryptography_of_its_own(self):
        src = inspect.getsource(ft)
        assert "import cryptography" not in src
        assert "from cryptography" not in src
        # hashlib is allowed for ONE thing: the independent read-back of the
        # finished plaintext, which is a verification, not a key operation.
        assert src.count("hashlib.") == 1

    def test_the_transfer_key_comes_only_from_the_ratchet(self):
        src = inspect.getsource(ft)
        assert "ratchet.file_sender" in src
        assert "ratchet.file_receiver" in src

    def test_a_transfer_object_exposes_no_secret(self, wired):
        wire, a_ratchet, _b = wired
        path, _ = _source_file(1000)
        transfer = wire.alice.offer_file("bob", path, a_ratchet)
        for banned in ("file_key", "key", "secret", "envelope_key"):
            assert not hasattr(transfer, banned)
        # the envelope is on the offer, and it is wrapped material
        assert len(transfer.offer.envelope) == 60

    def test_no_notification_carries_key_material(self, wired):
        wire, *_ = wired
        _run(wired, 20_000)
        joined = "\n".join(wire.notes)
        assert "envelope" not in joined.lower()
        for note in wire.notes:
            assert len(note) < 400, (
                "a notification is long enough to be carrying a payload")
