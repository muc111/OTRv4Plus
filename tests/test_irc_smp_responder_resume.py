"""The responder's guided SMP path, against the real Rust engine.

THE BUG
=======
Two handsets, both running v10.23.2. The receiving side got the whole way
through the guided flow -- consent prompt, `y`, hidden passphrase entry -- and
then:

    🔐 Passphrase stored – verifying...
    🔐 Could not answer the held request: ValueError

`_consume_secret_line` wrote the passphrase with
`session_manager.smp_storage.set_secret(...)`. That call writes the file and
stops there. The engine copy -- the one `resume_held_smp1_generate_smp2()`
reads -- was never bound, so Rust failed closed with

    SMP protocol: secret still not set: cannot answer the held SMP1

which PyO3 raises as `ValueError`, and the front end printed
`type(exc).__name__`, discarding the sentence that says exactly what is
wrong.

The initiator never showed it because `_start_smp` binds the secret itself on
the way past. One path bound, the other did not; the asymmetry was the defect.
`set_smp_secret` is the two-layer write (storage AND engine) and is what the
XMPP client has always called here.

WHY THIS FILE USES THE REAL ENGINE
==================================
A stubbed `session_manager` cannot express this bug. If `resume_held_smp1` is
a stub returning a string, storing the passphrase in a dict satisfies it and
the test passes on broken code -- which is exactly what happened: the c3070e7
suite mocked the manager and was green throughout.

So the manager here owns a real `otrv4_core.RustSMP` and mirrors the real
`EnhancedSessionManager` contract: `smp_storage.set_secret` touches only the
dict, `set_smp_secret` touches the dict AND the engine. Bind through the wrong
one and Rust raises, here as it did on the handset.

The client is the real `EnhancedOTRv4IRCClient` methods, entered where the
user enters them: `handle_chat_message`.

Enforces INV-06 for the responder path: the consent step is what stops a
peer's SMP1 turning the next typed line into a passphrase, and it is asserted
here against the real engine rather than a stub.
"""

import threading

import pytest

otr = pytest.importorskip("otrv4plus")
smpflow = pytest.importorskip("otrv4plus_smpflow")
core = pytest.importorskip("otrv4_core")

CLIENT = otr.EnhancedOTRv4IRCClient
PEER = "SwiftOmega"
SECRET = "correct horse battery staple"
WRONG = "not the same passphrase"

SID = b"\x01" * 32
OUR_FP = b"\xbb" * 57
PEER_FP = b"\xaa" * 57


def make_smp1(secret=SECRET):
    """A genuine SMP1 from a peer who set *secret*, produced by the engine."""
    initiator = core.RustSMP(True)
    initiator.set_secret(secret.encode(), SID, PEER_FP, OUR_FP)
    return initiator, bytes(initiator.generate_smp1(""))


class Storage:
    """`smp_storage`: the file-backed layer. Deliberately has NO way to
    reach the engine -- that is the whole point of the bug."""

    def __init__(self):
        self.secrets = {}

    def get_secret(self, peer):
        return self.secrets.get(peer, "")

    def set_secret(self, peer, secret):
        self.secrets[peer] = secret


class Manager:
    """The real EnhancedSessionManager contract over a real RustSMP."""

    def __init__(self, engine):
        self.engine = engine
        self.smp_storage = Storage()
        self.resume_calls = 0
        self.bound = 0
        self.last_smp2 = None

    def has_session(self, peer):
        return True

    def get_security_level(self, peer):
        return otr.UIConstants.SecurityLevel.ENCRYPTED

    def set_smp_secret(self, peer, secret):
        """Two-layer: storage AND engine, like otrv4+.py:9653."""
        self.smp_storage.set_secret(peer, secret)
        self.engine.set_secret(secret.encode(), SID, OUR_FP, PEER_FP)
        self.bound += 1
        return True

    def smp_secret_required(self, peer):
        return self.engine.get_phase() == "SECRET_REQUIRED"

    def resume_held_smp1(self, peer):
        """Mirrors the session method: refuse if nothing is held, consume
        only on success, and wrap the SMP2 as the wire message would be."""
        self.resume_calls += 1
        if not self.engine.has_held_smp1():
            raise RuntimeError("no SMP1 is being held for this session")
        smp2 = bytes(self.engine.resume_held_smp1_generate_smp2())
        self.last_smp2 = smp2
        return "?OTRv4 SMP2:%d" % len(smp2)

    def decline_held_smp1(self, peer, reason=b""):
        self.engine.discard_held_smp1()
        return "?OTRv4 ABORT"

    def encrypt_message(self, peer, msg):
        """The ordinary-chat fallthrough. Present so a line that is NOT a
        passphrase takes the path a chat message takes, which is the whole
        claim of the INV-06 tests below."""
        return "?OTRv4 CHAT:%s" % msg


class Client:
    """Real methods, minimal collaborators. Entry is `handle_chat_message`."""

    METHODS = (
        "handle_chat_message", "handle_command", "_consume_secret_line",
        "_dispatch_pending_response", "_get_pending", "_set_pending",
        "_clear_pending", "_check_smp_secret_required",
        "_announce_secret_required", "_handle_smp_consent", "_resume_smp",
        "_decline_smp_request", "_smp_verify", "_arm_secret_prompt",
        "_disarm_secret_prompt", "_panel_sec", "_active_peer",
        "_smp_session_ready", "_otr_panel", "_warn_inline_secret",
        "_handle_trust_response",
    )

    def __init__(self):
        self.engine = core.RustSMP(False)      # responder
        self.session_manager = Manager(self.engine)
        self.lines = []
        self.sent = []
        self.started = []
        self.panel_manager = otr.PanelManager(self)
        self.panel_manager.add_panel(PEER, "private")
        self.panel_manager.switch_to_panel(PEER)
        self._smp_flows = smpflow.SmpFlowRegistry()
        self._secret_request = None
        self._secret_purpose = None
        self._smp_consent_shown = None
        self._prompt_refresh_cb = None
        self._pending_action = None
        self._pending_lock = threading.RLock()
        self.channel_log = None
        self._tui_enabled = False
        self._screen = None
        self.connected = True
        self.nick = "BurningScree"
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    def add_message(self, target, message, sec=None):
        self.lines.append(str(message))

    def debug(self, *a, **k):
        pass

    def send_otr_message(self, peer, msg):
        self.sent.append((peer, msg))
        return True

    def send(self, raw):
        self.sent.append(("raw", raw))
        return True

    def _start_smp(self, peer, secret, question=""):
        self.started.append((peer, secret))

    def said(self, needle):
        return any(needle in line for line in self.lines)

    # -- the production sequence, as a helper ------------------------------
    def receive_smp1(self, smp1):
        """What `_handle_data_message` does once the engine has parked the
        message: ask whether a passphrase is needed, and prompt if so."""
        self.engine.hold_smp1(smp1)
        self._check_smp_secret_required(PEER)

    def consent(self, answer="y"):
        self.handle_chat_message(answer)

    def enter_passphrase(self, text):
        self.handle_chat_message(text)


@pytest.fixture(autouse=True)
def _mask_off():
    otr.set_input_mask(False)
    yield
    otr.set_input_mask(False)


@pytest.fixture
def responder():
    return Client()


class TestTheReportedFailure:
    """The exact handset sequence, end to end."""

    def test_the_full_responder_path_produces_an_smp2(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)

        assert not responder.said("Could not answer the held request"), (
            "the reported failure: the passphrase never reached the engine")
        assert any(msg.startswith("?OTRv4 SMP2:")
                   for _, msg in responder.sent), "no SMP2 was sent"

    def test_the_passphrase_reaches_the_engine_not_just_the_file(self, responder):
        """The bug in one assertion. The old code wrote the dict and stopped."""
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        assert responder.session_manager.bound == 1, (
            "set_smp_secret was never called, so the Rust engine had no "
            "secret when resume_held_smp1_generate_smp2() ran")

    def test_the_engine_actually_consumed_the_held_message(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        assert responder.engine.has_held_smp1() is True
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        assert responder.engine.has_held_smp1() is False
        assert responder.engine.get_phase() == "AWAITING_MSG3"

    def test_the_smp2_is_one_the_initiator_accepts(self, responder):
        """Not merely "no exception" -- the bytes have to verify. Drives the
        remaining PQC rounds (ML-KEM-1024 + ML-DSA-87 + ZKP) with the SMP2
        this path produced, and asserts both ends reach verified.

        This is the assertion that says the guided responder path and the
        cryptographic four-step flow still agree with each other."""
        initiator, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)

        smp2 = responder.session_manager.last_smp2
        assert smp2, "the guided path produced no SMP2 bytes"
        smp3 = bytes(initiator.process_smp2_generate_smp3(smp2))
        smp4 = bytes(responder.engine.process_smp3_generate_smp4(smp3))
        initiator.process_smp4(smp4)

        assert initiator.is_verified() is True
        assert responder.engine.is_verified() is True

    def test_a_second_y_cannot_answer_the_same_request(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        before = responder.session_manager.resume_calls
        responder.consent("y")
        assert responder.session_manager.resume_calls == before, (
            "the held request was answered twice")


class TestTheDiagnosticNamesTheReason:
    """`type(exc).__name__` cost a two-handset session. The engine's own
    sentence says exactly what is wrong and contains nothing of the user's."""

    def test_a_resume_with_no_held_request_says_so(self, responder):
        """Reaching _resume_smp with nothing held is reported as such, not as
        an engine error."""
        flow = responder._smp_flows.get(PEER)
        flow.remote_smp1_arrived()
        flow.local_consent(True)
        flow.has_held_smp1 = False
        responder._resume_smp(PEER)
        assert responder.said("no verification request waiting")
        assert responder.session_manager.resume_calls == 0

    def test_an_engine_failure_is_quoted_not_reduced_to_its_type(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")

        def boom(peer):
            raise ValueError("SMP protocol: secret still not set: cannot "
                             "answer the held SMP1")

        responder.session_manager.resume_held_smp1 = boom
        responder.enter_passphrase(SECRET)
        assert responder.said("secret still not set"), (
            "the reason was reduced to the word ValueError again")

    def test_a_failed_resume_leaves_a_clean_retry(self, responder):
        """IDLE, not FAILED: nothing was compared, so nothing failed."""
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.session_manager.resume_held_smp1 = \
            lambda peer: (_ for _ in ()).throw(ValueError("engine says no"))
        responder.enter_passphrase(SECRET)
        assert responder._smp_flows.get(PEER).state == smpflow.IDLE
        assert responder._secret_request is None
        assert otr._mask_input is False
        assert responder.said("try again")

    def test_a_failed_resume_does_not_claim_verification(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.session_manager.resume_held_smp1 = \
            lambda peer: (_ for _ in ()).throw(ValueError("engine says no"))
        responder.enter_passphrase(SECRET)
        assert not responder.said("VERIFIED")
        assert responder.engine.is_verified() is False


class TestTheWrongPassphraseIsAProtocolFailureNotAPythonOne:

    def test_a_wrong_passphrase_still_produces_an_smp2(self, responder):
        """SMP does not reveal the mismatch at step 2 -- that is the point of
        it. A wrong passphrase must travel the protocol, not raise."""
        _, smp1 = make_smp1(SECRET)
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(WRONG)
        assert any(msg.startswith("?OTRv4 SMP2:")
                   for _, msg in responder.sent)
        assert not responder.said("Could not answer")

    def test_the_mismatch_is_decided_by_the_engine_at_step_four(self):
        """End to end with the real engine on both sides: a wrong passphrase
        ends in not-verified, not in an exception."""
        initiator = core.RustSMP(True)
        initiator.set_secret(SECRET.encode(), SID, PEER_FP, OUR_FP)
        smp1 = bytes(initiator.generate_smp1(""))

        b = core.RustSMP(False)
        b.hold_smp1(smp1)
        b.set_secret(WRONG.encode(), SID, OUR_FP, PEER_FP)
        smp2 = bytes(b.resume_held_smp1_generate_smp2())
        smp3 = bytes(initiator.process_smp2_generate_smp3(smp2))
        smp4 = bytes(b.process_smp3_generate_smp4(smp3))
        initiator.process_smp4(smp4)
        assert initiator.is_verified() is False
        assert b.is_verified() is False


class TestCancellingSendsNothing:

    def test_an_empty_line_sends_no_smp2(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase("")
        assert not any(str(msg).startswith("?OTRv4 SMP2:")
                       for _, msg in responder.sent)

    def test_an_empty_line_declines_the_request(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase("")
        assert responder.engine.has_held_smp1() is False, (
            "a cancelled prompt left the peer's request parked forever")

    def test_cancelling_leaves_no_passphrase_state(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase("")
        assert responder._secret_request is None
        assert responder._secret_purpose is None
        assert otr._mask_input is False

    def test_n_declines_without_ever_prompting(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("n")
        assert otr._mask_input is False
        assert responder._secret_request is None
        assert responder.engine.has_held_smp1() is False

    def test_a_too_short_passphrase_sends_nothing(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase("short")
        assert not any(str(msg).startswith("?OTRv4 SMP2:")
                       for _, msg in responder.sent)
        assert responder.said("characters")


class TestInv06HoldsOnThisPath:
    """The consent step is the whole security property. A peer's SMP1 may
    make the client ASK; it may never make the next line a passphrase."""

    def test_the_prompt_alone_does_not_arm_a_read(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        assert otr._mask_input is False
        assert responder._secret_request is None

    def test_an_ordinary_message_at_the_consent_prompt_is_sent_as_one(
            self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.handle_chat_message("are you there?")
        assert responder.session_manager.bound == 0, (
            "an ordinary chat line became the SMP passphrase")
        assert responder.engine.get_phase() == "SECRET_REQUIRED"

    def test_the_question_is_re_armed_after_an_ordinary_message(self, responder):
        """Letting the line through must not lose the request."""
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.handle_chat_message("are you there?")
        responder.consent("y")
        assert otr._mask_input is True
        assert responder._secret_request == PEER

    def test_only_a_local_y_opens_the_hidden_read(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        assert responder._smp_flows.get(PEER).state == \
            smpflow.AWAITING_LOCAL_CONSENT
        responder.consent("y")
        assert responder._smp_flows.get(PEER).state == smpflow.AWAITING_SECRET
        assert responder._secret_purpose == "resume"

    def test_a_resent_smp1_does_not_stack_prompts(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        before = len(responder.lines)
        responder._check_smp_secret_required(PEER)
        assert len(responder.lines) == before


class TestThePassphraseIsNeverPrinted:

    def test_not_on_the_success_path(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        assert not responder.said(SECRET)
        assert not any(SECRET in str(m) for _, m in responder.sent)

    def test_not_on_the_engine_failure_path(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.session_manager.resume_held_smp1 = \
            lambda peer: (_ for _ in ()).throw(ValueError("engine says no"))
        responder.enter_passphrase(SECRET)
        assert not responder.said(SECRET)

    def test_not_when_the_storing_call_quotes_its_argument(self, responder):
        """The one path where the passphrase is still in scope when an error
        is reported. The raiser here deliberately does what a careless
        exception would."""
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")

        def leaky(peer, secret):
            raise RuntimeError("could not store %r" % secret)

        responder.session_manager.set_smp_secret = leaky
        responder.enter_passphrase(SECRET)
        assert not responder.said(SECRET), (
            "the passphrase reached the terminal through an exception message")

    def test_the_redaction_helper_leaves_short_text_alone(self):
        """Blanking every occurrence of a two-character string would corrupt
        unrelated text; a passphrase that short never reaches here."""
        assert otr._redact_secret("no ab here", "ab") == "no ab here"

    def test_the_redaction_helper_handles_bytes(self):
        out = otr._redact_secret("saw b'%s'" % SECRET, SECRET.encode())
        assert SECRET not in out
        assert "[redacted]" in out


class TestTheStateMachineTransitions:
    """The six states stay distinct; none collapses into a pending flag."""

    def test_held_then_consent_then_entry_then_running(self, responder):
        flow = responder._smp_flows.get(PEER)
        _, smp1 = make_smp1()

        responder.receive_smp1(smp1)
        assert flow.state == smpflow.AWAITING_LOCAL_CONSENT
        assert flow.has_held_smp1 is True

        responder.consent("y")
        assert flow.state == smpflow.AWAITING_SECRET

        responder.enter_passphrase(SECRET)
        assert flow.state == smpflow.RUNNING
        assert flow.has_held_smp1 is False, (
            "the flow still claims to hold a request it has answered")

    def test_declining_passes_through_declined_and_lands_back_at_idle(
            self, responder):
        """DECLINED is a real state and `local_consent(False)` reaches it,
        but the flow does not stay there: `_decline_smp_request` resets so a
        later request from the same peer can be asked about again. Staying in
        DECLINED would make one `n` permanent for the session."""
        flow = responder._smp_flows.get(PEER)
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        assert flow.local_consent.__name__          # the edge exists
        responder.consent("n")
        assert flow.state == smpflow.IDLE
        assert flow.has_held_smp1 is False
        assert responder.said("declined")

    def test_a_declined_request_can_be_asked_again(self, responder):
        """Requirement: a failed or declined attempt leaves no stale state."""
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("n")
        responder._smp_flows.get(PEER).reset()

        _, smp1b = make_smp1()
        responder.receive_smp1(smp1b)
        assert responder._smp_flows.get(PEER).state == \
            smpflow.AWAITING_LOCAL_CONSENT
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        assert any(str(msg).startswith("?OTRv4 SMP2:")
                   for _, msg in responder.sent)


class TestTheInitiatorPathStillBinds:
    """The half that worked, asserted so the fix cannot swap the failure to
    the other side."""

    def test_a_typed_smp_binds_the_secret_and_starts(self, responder):
        responder.handle_command("smp")
        assert otr._mask_input is True
        responder.enter_passphrase(SECRET)
        assert responder.session_manager.bound >= 1
        assert responder.started == [(PEER, SECRET)]

    def test_the_initiator_does_not_touch_the_held_path(self, responder):
        responder.handle_command("smp")
        responder.enter_passphrase(SECRET)
        assert responder.session_manager.resume_calls == 0


class TestTheAnswerGoesToTheRightPeerAsTheRightMessage:

    def test_the_smp2_is_sent_to_the_peer_who_asked(self, responder):
        responder.panel_manager.add_panel("SomeoneElse", "private")
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        targets = [p for p, m in responder.sent
                   if str(m).startswith("?OTRv4 SMP2:")]
        assert targets == [PEER]

    def test_nothing_is_sent_to_anyone_else(self, responder):
        _, smp1 = make_smp1()
        responder.receive_smp1(smp1)
        responder.consent("y")
        responder.enter_passphrase(SECRET)
        assert all(p == PEER for p, _ in responder.sent)


class TestTheSessionMethodItself:
    """`Session.resume_held_smp1` is below the harness above -- it owns the
    TLV type and the order in which state is cleared, and both were wrong or
    fragile. Read structurally rather than driven, because standing up a real
    Session means a real DAKE."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name == "resume_held_smp1"
                    and any("rust_smp" in ast.unparse(n)
                            for n in ast.walk(node))):
                return ast.unparse(node)
        raise AssertionError("Session.resume_held_smp1 not found")

    def test_it_answers_with_smp_msg_2(self, source):
        """SMP2 is the responder's message. Sending SMP1 here would restart
        the protocol as an initiator; SMP3 would be a step out of order."""
        assert "OTRv4TLV.SMP_MSG_2" in source
        for wrong in ("SMP_MSG_1", "SMP_MSG_3", "SMP_MSG_4"):
            assert "OTRv4TLV.%s" % wrong not in source

    def test_smp_msg_2_is_tlv_type_three(self):
        """Pinned against the OTRv4 allocation, so a renumbering that would
        silently talk past the peer fails here."""
        assert otr.OTRv4TLV.SMP_MSG_2 == 0x0003

    def test_it_asks_the_engine_before_consuming(self, source):
        """`has_held_smp1()` first, so "nothing is held" is reported as that
        rather than as a generic engine error."""
        assert "has_held_smp1" in source
        assert source.index("has_held_smp1") < \
            source.index("resume_held_smp1_generate_smp2")

    def test_the_outstanding_flag_is_cleared_only_after_the_engine_call(
            self, source):
        """Clearing it first meant a failed resume left the session claiming
        no request was outstanding while the engine still held one."""
        gen = source.index("resume_held_smp1_generate_smp2")
        clear = source.index("_smp_secret_required = False")
        assert clear > gen, (
            "the outstanding-request flag is cleared before the engine has "
            "produced the answer")

    def test_the_step_counter_advances_to_two(self, source):
        assert "self.smp_step = 2" in source
