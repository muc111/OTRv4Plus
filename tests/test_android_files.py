#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Android could not send a file, and displayed the peer's file signalling.

WHAT EXISTED AND WHAT DID NOT
=============================
All of `otrv4plus_filetransfer`: the FileKey, the AEAD, the chunk format,
the hashes, the offer/accept semantics, filename sanitising, the
temporary-file lifecycle, the atomic commit -- and the SMP gate on BOTH
sides. It is packaged into the APK. Nothing on Android could reach it.

AND THE INBOUND HALF WAS A DEFECT. Measured through two real bridges with a
live OTR session, the peer sending one control message:

    file signalling returned as a displayable body: True
      returned: '?OTRv4-FILE:OFFER:deadbeef|secret.pdf|1024'

That went to the UI as a chat message. A DATA chunk is base64 of a sealed
chunk, so an actual transfer would have rendered as hundreds of walls of
base64 from the user's contact.

WHAT IS REAL HERE
=================
Everything. The `FileTransferManager` is the shipped one, the OTR sessions
are real, the chunks are really sealed by the Rust core and really
delivered, and a file really arrives -- these tests move bytes from one
bridge to another and read the result off disk.

Enforces INV-12's sibling rule for transfers: one gate, one definition of
verified. `otrv4plus_xmpp._file_peer_verified` reads the VOICE manager's
`_smp_verified` -- "not display state, not a trust pin, not the blue OTRv4+
marker" -- and the Android bridge reads the same one.
"""

import os
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")
ft = pytest.importorskip("otrv4plus_filetransfer")
voice = pytest.importorskip("otrv4plus_voice")

from android_bridge.app import OtrApp, Transport                  # noqa: E402
from android_bridge.events import SecurityState, SmpState         # noqa: E402
from android_bridge.files import FileOutcome, is_file_signal      # noqa: E402

SECRET = "a shared secret we both know"


class Wire(Transport):
    """Delivers whatever one bridge sends straight into the other."""

    def __init__(self):
        self.sent = []
        self.peer_app = None
        self.peer_id = None

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        self.sent.append((peer, text))
        if self.peer_app is not None:
            self.peer_app.receive_message(self.peer_id, text)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


class Pair:
    def __init__(self, alice, bob, alice_jid, bob_jid):
        self.alice, self.bob = alice, bob
        self.alice_jid, self.bob_jid = alice_jid, bob_jid


class Landing:
    """A directory this test owns, with the two reads these tests need.

    `tempfile.mkdtemp` rather than pytest's `tmp_path`: this suite's
    `conftest.py` stubs `pwd`, and `tmp_path` reaches `getpass.getuser()`,
    which needs it. Every other test file here uses `mkdtemp` for the same
    reason.
    """

    def __init__(self, path):
        self.path = path

    def files(self):
        """Finished files only. `.incoming` is the engine's partial-work
        directory and lives inside this one; counting it would be counting
        exactly the files that are not the user's yet."""
        return [os.path.join(self.path, name)
                for name in sorted(os.listdir(self.path))
                if not name.startswith(".")]

    def is_empty(self):
        return not self.files()


@pytest.fixture
def landing(monkeypatch):
    """Where a FINISHED file goes, pointed somewhere this test owns.

    `OTRV4PLUS_FILE_DIR` is the engine's own knob, read by `state_dir`, and
    `state_dir` is what the atomic commit renames into. An earlier version of
    this fixture patched `incoming_dir` instead and the test failed with "the
    accepted file never landed" -- correctly: `incoming_dir` is "where
    partial work lives ... separate from the finished directory so a partial
    file can never be mistaken for a complete one", and the file had landed
    perfectly well in the real one.
    """
    target = tempfile.mkdtemp()
    monkeypatch.setenv("OTRV4PLUS_FILE_DIR", target)
    return Landing(target)


@pytest.fixture
def pair(landing):
    """Two Android bridges with a real encrypted session between them."""
    import uuid
    alice_jid = "alice-%s@example.test" % uuid.uuid4().hex[:8]
    bob_jid = "bob-%s@example.test" % uuid.uuid4().hex[:8]
    otr._dake1_rate_limiter._attempts.clear()

    alice_wire, bob_wire = Wire(), Wire()
    alice = OtrApp(_manager(), alice_wire)
    bob = OtrApp(_manager(), bob_wire)
    alice_wire.peer_app, alice_wire.peer_id = bob, alice_jid
    bob_wire.peer_app, bob_wire.peer_id = alice, bob_jid

    alice.start_session(bob_jid)
    assert alice.security_state(bob_jid) is not SecurityState.PLAINTEXT, \
        "the fixture never reached an encrypted session"

    made = Pair(alice, bob, alice_jid, bob_jid)
    try:
        yield made
    finally:
        for app in (alice, bob):
            try:
                app.shutdown()
            except Exception:
                pass


@pytest.fixture
def verified(pair):
    """The same two, having actually completed SMP through the Rust core."""
    pair.alice.smp_start(pair.bob_jid, SECRET)
    pair.bob.smp_respond(pair.alice_jid, SECRET)
    assert pair.alice.smp_state(pair.bob_jid) is SmpState.VERIFIED
    assert pair.bob.smp_state(pair.alice_jid) is SmpState.VERIFIED
    return pair


@pytest.fixture
def a_file():
    path = os.path.join(tempfile.mkdtemp(), "notes.txt")
    with open(path, "wb") as handle:
        handle.write(b"the quick brown fox " * 200)
    return path


# -- the inbound defect ------------------------------------------------------


class TestFileSignallingIsNotAMessage:

    @staticmethod
    def _signal(sender, to, body):
        frame, _ = sender._engine.handle_outgoing_message(to, body)
        return (frame.decode("utf-8", errors="replace")
                if isinstance(frame, (bytes, bytearray)) else str(frame))

    def test_an_offer_is_not_returned_as_a_body(self, pair):
        text = self._signal(pair.bob, pair.alice_jid,
                            ft.FILE_PREFIX + "OFFER:deadbeef|x.pdf|10")
        assert pair.alice.receive_message(pair.bob_jid, text) is None, (
            "file signalling was handed to the UI as a chat message")

    def test_a_data_chunk_is_not_returned_as_a_body(self, pair):
        """The loud one: each chunk is base64 of a sealed chunk, so a
        transfer would have been hundreds of walls of base64."""
        text = self._signal(pair.bob, pair.alice_jid,
                            ft.FILE_PREFIX + "DATA:dead|0|QUJDRA==")
        assert pair.alice.receive_message(pair.bob_jid, text) is None

    def test_an_ordinary_message_still_arrives(self, pair):
        text = self._signal(pair.bob, pair.alice_jid, "hello there")
        assert pair.alice.receive_message(pair.bob_jid, text) == "hello there"

    def test_a_body_merely_mentioning_the_prefix_is_a_message(self, pair):
        said = "the prefix is " + ft.FILE_PREFIX + " apparently"
        text = self._signal(pair.bob, pair.alice_jid, said)
        assert pair.alice.receive_message(pair.bob_jid, text) == said

    def test_the_prefix_is_not_a_second_definition(self):
        from android_bridge import files as bridge_files
        assert bridge_files.FILE_PREFIX_FALLBACK == ft.FILE_PREFIX

    def test_signalling_is_recognised_before_the_module_loads(self):
        assert is_file_signal(ft.FILE_PREFIX + "OFFER:x")
        assert not is_file_signal("hello")
        assert not is_file_signal(None)
        assert not is_file_signal(b"?OTRv4-FILE:OFFER")

    def test_call_and_file_signalling_do_not_collide(self):
        """Two prefixes, two routes. If one matched the other's traffic the
        wrong engine would be handed it."""
        from android_bridge.voice import is_call_signal
        assert not is_call_signal(ft.FILE_PREFIX + "OFFER:x")
        assert not is_file_signal(voice.CALL_PREFIX + "INVITE:x")


# -- the gate ----------------------------------------------------------------


class TestTheSmpGate:
    """One gate, one definition of verified -- the voice manager's, which
    reads only the engine's published predicates."""

    def test_an_unverified_peer_cannot_be_sent_a_file(self, pair, a_file):
        assert pair.alice.send_file(pair.bob_jid, a_file) == \
            FileOutcome.UNVERIFIED, (
            "a file was offered to a peer whose identity is not verified")

    def test_nothing_reaches_the_wire_for_an_unverified_peer(self, pair,
                                                             a_file):
        """Stronger than the code: no offer, no chunk, nothing."""
        before = len(pair.alice._transport.sent)
        pair.alice.send_file(pair.bob_jid, a_file)
        assert len(pair.alice._transport.sent) == before, (
            "an offer went out to an unverified peer")

    def test_an_unverified_peer_cannot_offer_us_a_file(self, verified,
                                                       a_file):
        """The inbound half, driven with a REAL offer.

        An earlier version of this test fed a made-up payload
        (`OFFER:deadbeef|x.pdf|10`) and passed with the gate deleted --
        because `Offer.decode` rejected it as malformed long before anything
        asked whether the peer was verified. It proved the parser worked and
        nothing about the gate.

        So the offer here is one the engine really produced, captured on its
        way out, and then delivered to a bridge that has NOT verified the
        sender.
        """
        captured = []
        bridge = verified.alice.files
        manager = bridge._ensure_manager()
        # Patched on the TRANSPORT, not the bridge: `OtrChunkTransport` binds
        # `_send_signal` when the manager is constructed, so replacing the
        # bridge attribute afterwards captures nothing.
        real_send = manager.transport._send
        manager.transport._send = lambda peer, verb, payload: (
            captured.append((verb, payload)) or real_send(peer, verb, payload))
        assert verified.alice.send_file(verified.bob_jid, a_file) == \
            FileOutcome.STARTED
        offers = [payload for verb, payload in captured if verb == "OFFER"]
        assert offers, "the engine produced no OFFER to test with"

        # A third bridge, which has verified nobody.
        stranger = OtrApp(_manager())
        stranger.files._ensure_manager()
        stranger.files.handle_signal(
            verified.alice_jid, ft.FILE_PREFIX + "OFFER:" + offers[0])
        try:
            assert stranger.transfers() == [], (
                "an unverified peer created a transfer on this device")
        finally:
            stranger.shutdown()

    def test_a_verified_peer_is_not_refused_by_the_gate(self, verified,
                                                        a_file):
        """The other direction, without which the assertions above would
        pass with the gate wired permanently shut."""
        assert verified.alice.send_file(verified.bob_jid, a_file) == \
            FileOutcome.STARTED

    def test_the_gate_is_the_same_one_voice_uses(self, verified):
        """`otrv4plus_xmpp._file_peer_verified` reads the voice manager's
        predicate and says why: one gate, one definition of verified. A
        second predicate here could drift, and then a peer could be callable
        but not sendable."""
        bridge = verified.alice.files
        manager = verified.alice.calls._ensure_manager()
        assert manager is not None
        assert bridge._verified(verified.bob_jid) is \
            manager._smp_verified(verified.bob_jid) is True
        assert bridge._verified("stranger@example.test") is False


# -- a file actually moving --------------------------------------------------


class TestAFileReallyArrives:
    """Bytes, from one bridge to the other, read off disk at the end."""

    @staticmethod
    def _settle(tries=200):
        """The send runs on its own thread, as the engine requires."""
        for _ in range(tries):
            time.sleep(0.02)

    def test_the_offer_reaches_the_peer(self, verified, a_file):
        assert verified.alice.send_file(verified.bob_jid, a_file) == \
            FileOutcome.STARTED
        rows = verified.bob.transfers()
        assert len(rows) == 1, "the offer did not reach the peer"
        assert rows[0]["filename"] == "notes.txt"
        assert rows[0]["outgoing"] is False
        assert rows[0]["size"] == os.path.getsize(a_file)

    def test_accepting_delivers_the_file(self, verified, a_file, landing):
        verified.alice.send_file(verified.bob_jid, a_file)
        offered = verified.bob.transfers()[0]
        assert verified.bob.accept_file(offered["id"]) == FileOutcome.STARTED
        self._settle()

        arrived = landing.files()
        assert arrived, "the accepted file never landed"
        assert open(arrived[0], "rb").read() == open(a_file, "rb").read(), (
            "the delivered bytes are not the bytes that were sent")

    def test_declining_delivers_nothing(self, verified, a_file, landing):
        verified.alice.send_file(verified.bob_jid, a_file)
        offered = verified.bob.transfers()[0]
        assert verified.bob.decline_file(offered["id"]) == FileOutcome.STARTED
        self._settle(tries=40)
        assert landing.is_empty(), (
            "a declined transfer still wrote a file")

    def test_the_conversation_shows_no_protocol_text(self, verified, a_file):
        """The whole transfer, and not one chunk rendered as a message."""
        seen = []
        verified.bob._sink = type("S", (), {
            "on_event": lambda _s, e: seen.append(e)})()
        verified.alice.send_file(verified.bob_jid, a_file)
        offered = verified.bob.transfers()[0]
        verified.bob.accept_file(offered["id"])
        self._settle()

        from android_bridge.events import MessageReceived
        bodies = [e.body for e in seen if isinstance(e, MessageReceived)]
        assert bodies == [], (
            "a transfer put %d protocol frames in the conversation" %
            len(bodies))


# -- refusals ----------------------------------------------------------------


class TestRefusalsAreHonest:

    def test_a_missing_file_says_so(self, verified):
        missing = os.path.join(tempfile.mkdtemp(), "nope.txt")
        assert verified.alice.send_file(verified.bob_jid, missing) == \
            FileOutcome.BAD_FILE

    def test_a_peer_with_no_session_says_so(self, verified, a_file):
        assert verified.alice.send_file("stranger@example.test", a_file) == \
            FileOutcome.NO_SESSION

    def test_a_transfer_that_does_not_exist_says_so(self, verified):
        assert verified.alice.accept_file("nosuchid") == \
            FileOutcome.NO_TRANSFER
        assert verified.alice.decline_file("nosuchid") == \
            FileOutcome.NO_TRANSFER

    def test_sending_without_a_transport_says_so(self, verified, a_file):
        verified.alice._transport = None
        assert verified.alice.send_file(verified.bob_jid, a_file) == \
            FileOutcome.NOT_CONNECTED

    def test_no_refusal_carries_engine_text(self, verified):
        """`TransferError` messages name the file and are written for a
        terminal. What crosses to Kotlin is a code from a fixed set."""
        secret_name = "my-private-document-name.txt"
        outcome = verified.alice.send_file(
            verified.bob_jid, os.path.join(tempfile.mkdtemp(), secret_name))
        assert outcome == FileOutcome.BAD_FILE
        assert secret_name not in outcome


# -- teardown ----------------------------------------------------------------


class TestTeardown:

    def test_shutdown_forgets_every_transfer(self, verified, a_file):
        verified.alice.send_file(verified.bob_jid, a_file)
        assert verified.alice.transfers() != []
        verified.alice.shutdown()
        assert verified.alice.transfers() == []

    def test_shutdown_is_safe_to_call_twice(self, verified):
        verified.alice.shutdown()
        verified.alice.shutdown()

    def test_the_received_directory_is_the_finished_one(self, verified,
                                                        landing):
        """NOT the partial-work directory. Pointing the user at `.incoming`
        would be pointing them at the files that are not theirs yet -- the
        engine keeps the two apart precisely so a partial file cannot be
        mistaken for a complete one."""
        where = verified.alice.received_file_dir()
        assert where == landing.path
        assert not where.endswith(".incoming")

    def test_asking_for_transfers_does_not_build_a_manager(self, pair):
        """The conversation screen reads this. A device that has never sent
        a file must not load the transfer engine to be told there are none."""
        assert pair.alice._files_bridge is None
        assert pair.alice.files.transfers() == []
        assert pair.alice.files._manager is None, (
            "reading the transfer list built a transfer manager")


# -- the module boundary -----------------------------------------------------


class TestTheTransferStackIsNotLoadedAtImport:

    def test_it_does_not_import_the_engine_at_module_scope(self):
        import ast
        import inspect
        import android_bridge.files as mod
        tree = ast.parse(inspect.getsource(mod))
        names = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        for banned in ("otrv4plus_filetransfer", "otrv4plus_xmpp", "otrv4_"):
            assert not any(n.startswith(banned) for n in names), (
                "%r is imported at module scope: %r" % (banned, names))

    def test_the_termux_picker_is_never_reached(self):
        """`pick_file` shells out to a Termux picker. Android picks through
        the Storage Access Framework, in Kotlin, and hands down a resolved
        path -- the engine takes a path and does not care who chose it."""
        import inspect
        import android_bridge.files as mod
        source = inspect.getsource(mod)
        assert "pick_file" not in source.replace("pick_file` shells", ""), (
            "the Android bridge reaches for the Termux file picker")


# -- the Kotlin side ---------------------------------------------------------


ANDROID = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
ANDROID_TESTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "android", "app", "src", "test", "java", "org", "otrv4plus", "android")
MANIFEST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "android", "app", "src", "main", "AndroidManifest.xml")


def _kt(*parts):
    import io
    with io.open(os.path.join(ANDROID, *parts), encoding="utf-8") as handle:
        return handle.read()


class TestTheTwoSidesAgreeOnTheCodes:

    @staticmethod
    def _python_codes():
        from android_bridge.files import FileOutcome as F
        return {F.STARTED, F.UNVERIFIED, F.NO_SESSION, F.BAD_FILE,
                F.NO_TRANSFER, F.UNAVAILABLE, F.NOT_CONNECTED,
                F.CANNOT_SCRUB}

    @staticmethod
    def _kotlin_codes():
        import re
        source = _kt("bridge", "OtrCore.kt")
        block = source[source.index("object FileOutcome {"):]
        block = block[:block.index("\n}")]
        return set(re.findall(r'=\s*"([a-z_]+)"', block))

    def test_every_python_code_exists_in_kotlin(self):
        assert self._python_codes() <= self._kotlin_codes(), (
            "Python can answer with a code Kotlin does not know: %r"
            % (self._python_codes() - self._kotlin_codes()))

    def test_kotlin_invents_no_code_of_its_own(self):
        assert self._kotlin_codes() <= self._python_codes(), (
            "Kotlin branches on a code Python never sends: %r"
            % (self._kotlin_codes() - self._python_codes()))

    @pytest.mark.parametrize("field", [
        "id", "peer", "filename", "size", "outgoing", "accepted",
        "cancelled", "progress"])
    def test_every_row_field_is_read_by_kotlin(self, field):
        """`transfers()` returns dicts. A key Kotlin does not read is a field
        that silently never reaches the screen."""
        source = _kt("bridge", "ChaquopyOtrCore.kt")
        body = source[source.index("fun transfers(): List<FileTransferView>"):]
        body = body[:body.index("\n    /**")]
        assert '"%s"' % field in body, (
            "FileTransferView drops the %r the bridge sends" % field)


class TestTheCoreExposesTheTransfers:

    @staticmethod
    @pytest.fixture(scope="class")
    def core():
        return _kt("bridge", "ChaquopyOtrCore.kt")

    @pytest.mark.parametrize("method,attr", [
        ("fun sendFile(", "send_file"),
        ("fun acceptFile(", "accept_file"),
        ("fun declineFile(", "decline_file"),
        ("fun transfers(", "transfers"),
        ("fun receivedFileDir(", "received_file_dir"),
    ])
    def test_each_method_exists_and_reaches_python(self, core, method, attr):
        assert method in core, "%s is missing" % method
        body = core[core.index(method):]
        body = body[:body.index("\n\n")]
        assert '"%s"' % attr in body, "%s does not call %r" % (method, attr)

    @pytest.mark.parametrize("attr", [
        "send_file", "accept_file", "decline_file", "transfers",
        "received_file_dir"])
    def test_python_actually_has_that_method(self, attr):
        assert callable(getattr(OtrApp, attr, None)), (
            "ChaquopyOtrCore calls OtrApp.%s, which does not exist" % attr)

    def test_the_core_decides_nothing_about_verification(self, core):
        body = core[core.index("fun sendFile("):]
        body = body[:body.index("fun acceptFile(")]
        for decided in ("SMP_VERIFIED", "smpState", "securityState"):
            assert decided not in body, (
                "sendFile decides on %s itself instead of letting the "
                "transfer engine refuse" % decided)


class TestTheAndroidSideUsesSaf:
    """`otrv4plus_filetransfer.pick_file` shells out to a Termux picker, and
    an APK has no business doing that. Android picks through the Storage
    Access Framework and hands down a resolved path."""

    @staticmethod
    @pytest.fixture(scope="class")
    def screen():
        return _kt("ui", "ConversationScreen.kt")

    def test_the_picker_is_the_system_document_picker(self, screen):
        assert "ActivityResultContracts.OpenDocument()" in screen, (
            "the file picker is not the system's")

    def test_no_storage_permission_is_requested(self):
        """SAF means the user picks, and only what they picked is readable.
        A broad storage permission would make the picker decorative."""
        import io
        manifest = io.open(MANIFEST, encoding="utf-8").read()
        for broad in ("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                      "MANAGE_EXTERNAL_STORAGE"):
            assert broad not in manifest, (
                "the app asks for %s; SAF means the user picks and only what "
                "they picked is readable" % broad)

    def test_the_staged_copy_stays_in_the_apps_own_cache(self, screen):
        """What is copied is about to be encrypted and sent. A readable
        duplicate in a shared directory would undo the point."""
        body = screen[screen.index("private fun stageForSending("):]
        body = body[:body.index("\n}")]
        assert "context.cacheDir" in body
        for shared in ("getExternalStorage", "Environment.DIRECTORY",
                       "Downloads"):
            assert shared not in body, (
                "the staged copy is written to shared storage")

    def test_a_provider_supplied_name_cannot_carry_a_path(self, screen):
        """The display name comes from somebody else's content provider and
        is about to become a File()."""
        body = screen[screen.index("private fun displayName("):]
        body = body[:body.index("\n}")]
        assert "substringAfterLast('/')" in body, (
            "a provider-supplied name reaches File() with its separators")


class TestTheTransferUiRulesAreExecutable:

    def test_the_rules_touch_neither_compose_nor_android(self):
        source = _kt("crypto", "TransferUi.kt")
        for line in source.splitlines():
            if line.startswith("import "):
                assert line.startswith("import org.otrv4plus."), (
                    "TransferUi imports a platform type (%s)" % line.strip())
        assert "@Composable" not in source

    def test_a_kotlin_test_drives_them(self):
        assert os.path.exists(
            os.path.join(ANDROID_TESTS, "crypto", "TransferUiTest.kt"))

    def test_only_a_verified_conversation_is_offered_a_transfer(self):
        source = _kt("crypto", "TransferUi.kt")
        block = source[source.index("fun offer("):]
        block = block[:block.index("/** What a transfer row shows")]
        assert block.count("Offer.Available") == 1, (
            "more than one security state may send a file")
        available = block[:block.index("Offer.Available") + 20]
        assert "SecurityState.SMP_VERIFIED" in available


class TestTheThirdControlPrefix:
    """`otrv4plus_trade` carries `?OTRv4-TRADE:` in a body exactly as voice
    and file transfer do, and Android has no trade support at all -- so
    without a branch for it a peer's trade signalling reaches the screen as
    a message from their contact.

    SUPPRESSED, NOT HANDLED. This does not make trading work on Android; it
    stops protocol text being rendered as something a person said.
    """

    @staticmethod
    def _signal(sender, to, body):
        frame, _ = sender._engine.handle_outgoing_message(to, body)
        return (frame.decode("utf-8", errors="replace")
                if isinstance(frame, (bytes, bytearray)) else str(frame))

    def test_trade_signalling_is_not_returned_as_a_body(self, pair):
        trade = pytest.importorskip("otrv4plus_trade")
        text = self._signal(pair.bob, pair.alice_jid,
                            trade.TRADE_PREFIX + "OPEN:1|2|3")
        assert pair.alice.receive_message(pair.bob_jid, text) is None, (
            "trade signalling was handed to the UI as a chat message")

    def test_the_prefix_is_not_a_second_definition(self):
        trade = pytest.importorskip("otrv4plus_trade")
        from android_bridge import app as bridge_app
        assert bridge_app.TRADE_PREFIX_FALLBACK == trade.TRADE_PREFIX

    def test_recognising_it_does_not_load_the_trade_module(self):
        """A twelve-character prefix must not cost a twelve-thousand-line
        import for a feature this build does not have."""
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = ("import sys; sys.path.insert(0, %r)\n"
                "from android_bridge.app import _is_trade_signal\n"
                "assert _is_trade_signal('?OTRv4-TRADE:OPEN:1')\n"
                "assert not _is_trade_signal('hello')\n"
                "print('trade' if 'otrv4plus_trade' in sys.modules "
                "else 'clean')" % root)
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, timeout=120)
        assert out.stdout.strip() == "clean", (out.stdout + out.stderr)[:300]

    def test_every_control_prefix_the_project_defines_is_routed(self):
        """The list, so a FOURTH one cannot be added and quietly rendered.

        Found by reading the project's own sources rather than remembering:
        a prefix added tomorrow shows up here on the next run.
        """
        import io as _io
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        found = set()
        for name in sorted(os.listdir(root)):
            if not name.startswith("otrv4plus_") or not name.endswith(".py"):
                continue
            text = _io.open(os.path.join(root, name), encoding="utf-8").read()
            found |= set(re.findall(r'^[A-Z_]*PREFIX\s*=\s*"(\?OTRv4-[^"]+)"',
                                    text, re.M))
        assert found, "no control prefixes were found at all"

        handled = _io.open(os.path.join(root, "android_bridge", "app.py"),
                           encoding="utf-8").read()
        for prefix in sorted(found):
            assert prefix in handled or any(
                prefix in _io.open(os.path.join(root, "android_bridge", mod),
                                   encoding="utf-8").read()
                for mod in ("voice.py", "files.py")), (
                "%s is carried in a message body and nothing on the Android "
                "inbound path recognises it, so it renders as chat text"
                % prefix)


# -- metadata: the user's choice, carried through ----------------------------


def _fixture_photo():
    """A copy of the real GPS-tagged JPEG, somewhere this test owns."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "data", "photo_with_gps.jpg"), "rb") as src:
        data = src.read()
    path = os.path.join(tempfile.mkdtemp(), "holiday.jpg")
    with open(path, "wb") as dst:
        dst.write(data)
    return path


class TestTheMetadataChoiceReachesThePeer:
    """End to end: a photo chosen to be stripped arrives stripped, one chosen
    to be kept arrives as it was, and nothing is decided for the user."""

    @staticmethod
    def _deliver(verified, landing, photo, strip):
        assert verified.alice.send_file(verified.bob_jid, photo, strip) == \
            FileOutcome.STARTED
        offered = verified.bob.transfers()[0]
        verified.bob.accept_file(offered["id"])
        for _ in range(200):
            if landing.files():
                break
            time.sleep(0.02)
        arrived = landing.files()
        assert arrived, "nothing landed"
        return open(arrived[0], "rb").read()

    def test_inspect_reports_the_metadata_before_sending(self, verified):
        found = verified.alice.inspect_file(_fixture_photo())
        assert found["kind"] == "jpeg"
        assert found["can_scrub"] is True
        assert found["carries_metadata"] is True
        assert found["metadata_bytes"] > 0

    def test_stripped_means_the_peer_never_sees_it(self, verified, landing):
        received = self._deliver(verified, landing, _fixture_photo(), True)
        for leaked in (b"PhoneMaker", b"Model X9", b"2026:09:23"):
            assert leaked not in received, (
                "%r reached the peer although the user chose to strip it"
                % leaked)
        assert received[:2] == b"\xff\xd8", "what arrived is not a JPEG"

    def test_kept_means_it_arrives_exactly_as_it_was(self, verified, landing):
        """The user's other choice, honoured just as literally."""
        photo = _fixture_photo()
        original = open(photo, "rb").read()
        assert self._deliver(verified, landing, photo, False) == original

    def test_the_default_changes_nothing(self, verified, landing):
        """No silent scrubbing behind the user's back either: a caller that
        does not ask gets the file as it is."""
        photo = _fixture_photo()
        original = open(photo, "rb").read()
        assert verified.alice.send_file(verified.bob_jid, photo) == \
            FileOutcome.STARTED
        offered = verified.bob.transfers()[0]
        verified.bob.accept_file(offered["id"])
        for _ in range(200):
            if landing.files():
                break
            time.sleep(0.02)
        assert open(landing.files()[0], "rb").read() == original

    def test_the_users_own_file_is_never_modified(self, verified):
        photo = _fixture_photo()
        original = open(photo, "rb").read()
        verified.alice.send_file(verified.bob_jid, photo, True)
        assert open(photo, "rb").read() == original

    def test_no_scrubbed_copy_is_left_behind(self, verified):
        """The engine seals the file into memory in `offer_file` and never
        reads the path again, so a leftover copy would only be a second
        plaintext of the photo on disk."""
        photo = _fixture_photo()
        directory = os.path.dirname(photo)
        verified.alice.send_file(verified.bob_jid, photo, True)
        assert sorted(os.listdir(directory)) == ["holiday.jpg"], (
            "a scrubbed copy was left on disk: %r" % os.listdir(directory))

    def test_asking_to_strip_an_uncheckable_file_is_refused(self, verified):
        """Not sent as-is. Sending it anyway would quietly overrule the
        choice the user just made."""
        path = os.path.join(tempfile.mkdtemp(), "notes.pdf")
        with open(path, "wb") as handle:
            handle.write(b"%PDF-1.7 with an author field inside")
        before = len(verified.alice._transport.sent)
        assert verified.alice.send_file(verified.bob_jid, path, True) == \
            FileOutcome.CANNOT_SCRUB
        assert len(verified.alice._transport.sent) == before, (
            "the file went out although it could not be scrubbed")


class TestTheMetadataChoiceOnAndroid:
    """The Kotlin half of the choice. Compose cannot run here; the rules are
    driven in `MetadataChoiceTest`, and the scrub itself in
    `tests/test_metadata_scrub.py` against real photographs."""

    @staticmethod
    @pytest.fixture(scope="class")
    def model():
        return _kt("chat", "ChatViewModel.kt")

    def test_a_picked_file_is_examined_before_it_is_sent(self):
        screen = _kt("ui", "ConversationScreen.kt")
        picker = screen[screen.index("ActivityResultContracts.OpenDocument()"):]
        picker = picker[:picker.index("model.pendingMetadata")]
        assert "model.prepareFile(" in picker, (
            "a picked file is sent without being examined")
        assert "model.sendFile(" not in picker

    def test_dismissing_the_question_sends_nothing(self, model):
        body = model[model.index("fun cancelMetadata()"):]
        body = body[:body.index("\n    }")]
        assert "sendFile(" not in body, (
            "dismissing the metadata question sends the file anyway")
        assert "discardStaged(" in body, (
            "a dismissed file's staged copy is left in the cache")

    def test_the_staged_copy_is_deleted_after_sending(self, model):
        body = model[model.index("private fun sendFile("):]
        body = body[:body.index("private fun discardStaged(")]
        assert "discardStaged(path)" in body

    def test_the_core_passes_the_choice_through(self):
        core = _kt("bridge", "ChaquopyOtrCore.kt")
        body = core[core.index("fun sendFile("):]
        body = body[:body.index("\n\n")]
        assert "stripMetadata" in body and '"send_file"' in body

    def test_inspect_reaches_python(self):
        core = _kt("bridge", "ChaquopyOtrCore.kt")
        assert '"inspect_file"' in core
        assert callable(getattr(OtrApp, "inspect_file", None))

    def test_the_choice_leaf_is_dependency_free(self):
        source = _kt("crypto", "MetadataChoice.kt")
        for line in source.splitlines():
            if line.startswith("import "):
                assert line.startswith("import org.otrv4plus."), line
        assert os.path.exists(os.path.join(ANDROID_TESTS, "crypto",
                                           "MetadataChoiceTest.kt"))


# ── opening a received file: only a verified one has a path ─────────────────

class TestOnlyAVerifiedFileCanBeOpened:
    """The row carries `path` for a file this device RECEIVED after every
    hash check and the atomic commit -- and for nothing else. The in-app
    viewer opens only that path."""

    def _wait(self, predicate):
        for _ in range(300):
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def test_the_received_row_names_the_verified_file(self, verified, landing,
                                                       a_file):
        assert verified.alice.send_file(verified.bob_jid, a_file) == \
            FileOutcome.STARTED
        offered = verified.bob.transfers()[0]
        assert offered["path"] == "", "an unanswered offer had a path"
        verified.bob.accept_file(offered["id"])
        assert self._wait(lambda: any(
            r["state"] == "received" for r in verified.bob.transfers()))
        row = [r for r in verified.bob.transfers() if r["state"] == "received"][0]
        assert row["path"], "a verified file had no path to open"
        assert os.path.realpath(os.path.dirname(row["path"])) == \
            os.path.realpath(landing.path)
        assert open(row["path"], "rb").read() == open(a_file, "rb").read()
        assert os.stat(row["path"]).st_mode & 0o077 == 0, \
            "the received file is readable by others"

    def test_the_sender_never_gets_a_path(self, verified, landing, a_file):
        verified.alice.send_file(verified.bob_jid, a_file)
        verified.bob.accept_file(verified.bob.transfers()[0]["id"])
        self._wait(lambda: any(r["state"] == "received"
                               for r in verified.bob.transfers()))
        assert all(r["path"] == "" for r in verified.alice.transfers())


class TestTheMetadataDialogOffersThreeChoices:
    """Strip (primary, the default), Keep, Cancel -- and dismissing sends
    nothing. Read from the Compose source, which only CI can compile."""

    def test_the_dialog(self):
        screen = open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "android/app/src/main/java/org/otrv4plus/android/ui/ConversationScreen.kt"),
            encoding="utf-8").read()
        dialog = screen[screen.index("model.pendingMetadata"):]
        dialog = dialog[:dialog.index("for (transfer in transfers)")]
        confirm = dialog[dialog.index("confirmButton"):dialog.index("dismissButton")]
        assert "answerMetadata(strip = true)" in confirm
        assert "MetadataChoice.STRIP" in confirm
        assert "MetadataChoice.KEEP" in dialog and "MetadataChoice.CANCEL" in dialog
        assert "onDismissRequest = { model.cancelMetadata() }" in dialog
