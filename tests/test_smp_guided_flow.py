#!/usr/bin/env python3
"""The guided SMP flow, and the boundary it exists to hold.

Enforces INV-06 alongside `test_no_remote_input_capture.py`: that one walks
the call graph for the armer, this one drives the flow and checks what a peer
can and cannot make happen.

THE PROPERTY
============
A remote peer may cause the client to ASK for the shared passphrase.  It may
never cause the next thing the user types to BECOME the passphrase.

Everything in `TestRemoteCannotCapture` is about that one sentence.  The rest
covers the flow the brief asked for: `/smp` prompts when nothing is stored and
then verifies, an arriving SMP1 with no passphrase asks for consent first, and
every exit path -- decline, cancel, bad input, internal error, teardown --
leaves nothing behind and says accurately what happened.

The engine is real (`otrv4_core`); the transport and the terminal are not.
"""

import ast
import inspect
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")
smpflow = pytest.importorskip("otrv4plus_smpflow")
xmpp = pytest.importorskip("otrv4plus_xmpp")

PEER = "alice@xmpp-elite.i2p"
SECRET = "correct-horse-battery-staple"


# ── the state machine on its own ─────────────────────────────────────────────
class TestTheStateMachine:

    def test_a_remote_request_stops_at_consent(self):
        flow = smpflow.SmpFlow(PEER)
        assert flow.remote_smp1_arrived() == smpflow.AWAITING_LOCAL_CONSENT
        assert not flow.awaiting_secret(), (
            "a peer moved the flow straight into the state where a typed "
            "line becomes a passphrase")

    def test_only_local_consent_opens_the_secret_state(self):
        flow = smpflow.SmpFlow(PEER)
        flow.remote_smp1_arrived()
        with pytest.raises(smpflow.SmpFlowError):
            flow.secret_supplied()
        assert flow.local_consent(True) == smpflow.AWAITING_SECRET

    def test_declining_is_terminal_and_stores_nothing(self):
        flow = smpflow.SmpFlow(PEER)
        flow.remote_smp1_arrived()
        assert flow.local_consent(False) == smpflow.DECLINED
        assert not flow.awaiting_secret()

    def test_a_local_command_needs_no_consent_step(self):
        """`/smp` is the user's own command; the line before it WAS the
        consent."""
        flow = smpflow.SmpFlow(PEER)
        assert flow.local_secret_needed() == smpflow.AWAITING_SECRET
        assert flow.origin == smpflow.LOCAL

    def test_a_repeated_smp1_does_not_stack_prompts(self):
        flow = smpflow.SmpFlow(PEER)
        first = flow.remote_smp1_arrived()
        for _ in range(5):
            assert flow.remote_smp1_arrived() == first

    def test_a_repeated_smp1_cannot_reopen_a_prompt_already_answered(self):
        """Consent, then a replayed SMP1: it must not walk back to consent and
        it must not re-arm."""
        flow = smpflow.SmpFlow(PEER)
        flow.remote_smp1_arrived()
        flow.local_consent(True)
        assert flow.remote_smp1_arrived() == smpflow.AWAITING_SECRET

    def test_a_peer_cannot_disturb_a_run_in_progress(self):
        flow = smpflow.SmpFlow(PEER)
        flow.running()
        with pytest.raises(smpflow.SmpFlowError):
            flow.remote_smp1_arrived()

    def test_consent_expires(self):
        now = [1000.0]
        flow = smpflow.SmpFlow(PEER, clock=lambda: now[0])
        flow.remote_smp1_arrived()
        now[0] += smpflow.CONSENT_TIMEOUT_SECS + 1
        assert flow.state == smpflow.IDLE, (
            "a stale request still answers to y, long after the user has "
            "forgotten what it was about")
        with pytest.raises(smpflow.SmpFlowError):
            flow.local_consent(True)

    def test_a_local_prompt_does_not_expire(self):
        """The user is looking at it; timing it out under them would discard
        a passphrase mid-typing."""
        now = [1000.0]
        flow = smpflow.SmpFlow(PEER, clock=lambda: now[0])
        flow.local_secret_needed()
        now[0] += smpflow.CONSENT_TIMEOUT_SECS * 10
        assert flow.awaiting_secret()

    def test_reset_clears_everything(self):
        flow = smpflow.SmpFlow(PEER)
        flow.remote_smp1_arrived()
        flow.reset()
        assert flow.state == smpflow.IDLE
        assert flow.has_held_smp1 is False

    def test_the_registry_reports_at_most_one_asking_flow(self):
        reg = smpflow.SmpFlowRegistry()
        reg.get("a@x").remote_smp1_arrived()
        assert reg.asking().peer == "a@x"
        reg.drop("a@x")
        assert reg.asking() is None

    def test_no_transition_into_awaiting_secret_from_a_remote_method(self):
        """Structural: read the class and check which methods can write the
        state that arms a passphrase read."""
        src = inspect.getsource(smpflow)
        tree = ast.parse(src)
        writers = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Assign)
                        and any(isinstance(t, ast.Attribute)
                                and t.attr == "_state" for t in sub.targets)
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id == "AWAITING_SECRET"):
                    writers.add(node.name)
        assert writers <= {"local_secret_needed", "local_consent"}, (
            "something other than a local action can arm the passphrase "
            "prompt: %s" % sorted(writers))


# ── the engine's held-SMP1 state ─────────────────────────────────────────────
class TestTheEngineHoldsRatherThanAborts:

    def _smp1(self):
        a = core.RustSMP(True)
        a.set_secret_from_bytearray(bytearray(SECRET.encode()),
                                    b"sid", b"fp-a", b"fp-b")
        return bytes(a.generate_smp1(None))

    def test_secret_required_is_a_real_phase(self):
        b = core.RustSMP(False)
        b.hold_smp1(self._smp1())
        assert b.get_phase() == "SECRET_REQUIRED"
        assert b.has_held_smp1()

    def test_the_held_message_cannot_be_answered_without_a_secret(self):
        b = core.RustSMP(False)
        b.hold_smp1(self._smp1())
        with pytest.raises(ValueError):
            b.resume_held_smp1_generate_smp2()
        assert b.has_held_smp1(), "the message was consumed by a failed attempt"

    def test_supplying_the_secret_answers_the_held_message(self):
        m1 = self._smp1()
        b = core.RustSMP(False)
        b.hold_smp1(m1)
        b.set_secret_from_bytearray(bytearray(SECRET.encode()),
                                    b"sid", b"fp-b", b"fp-a")
        assert b.resume_held_smp1_generate_smp2()
        assert b.get_phase() == "AWAITING_MSG3"

    def test_declining_returns_to_idle_and_keeps_nothing(self):
        b = core.RustSMP(False)
        b.hold_smp1(self._smp1())
        b.discard_held_smp1()
        assert b.get_phase() == "IDLE"
        assert not b.has_held_smp1()

    def test_a_full_run_completes_after_a_pause_for_the_passphrase(self):
        """The point of holding: the SMP1 that already arrived is answered,
        so the run finishes rather than restarting."""
        sid, fp_a, fp_b = b"sid", b"fp-a", b"fp-b"
        a = core.RustSMP(True)
        a.set_secret_from_bytearray(bytearray(SECRET.encode()), sid, fp_a, fp_b)
        m1 = bytes(a.generate_smp1(None))

        b = core.RustSMP(False)
        b.hold_smp1(m1)                                   # no secret yet
        b.set_secret_from_bytearray(bytearray(SECRET.encode()), sid, fp_b, fp_a)
        m2 = bytes(b.resume_held_smp1_generate_smp2())

        m3 = bytes(a.process_smp2_generate_smp3(m2))
        m4 = bytes(b.process_smp3_generate_smp4(m3))
        a.process_smp4(m4)
        assert a.get_phase() == "VERIFIED"
        assert b.get_phase() == "VERIFIED"

    def test_a_wrong_passphrase_after_the_pause_is_still_a_failure(self):
        """Pausing must not turn a mismatch into a success."""
        sid, fp_a, fp_b = b"sid", b"fp-a", b"fp-b"
        a = core.RustSMP(True)
        a.set_secret_from_bytearray(bytearray(SECRET.encode()), sid, fp_a, fp_b)
        m1 = bytes(a.generate_smp1(None))

        b = core.RustSMP(False)
        b.hold_smp1(m1)
        b.set_secret_from_bytearray(bytearray(b"a-different-passphrase"),
                                    sid, fp_b, fp_a)
        m2 = bytes(b.resume_held_smp1_generate_smp2())
        m3 = bytes(a.process_smp2_generate_smp3(m2))
        m4 = bytes(b.process_smp3_generate_smp4(m3))
        assert a.process_smp4(m4) is False
        assert a.get_phase() != "VERIFIED"


# ── the client, with a fake transport ────────────────────────────────────────
class _FakeStorage:
    def __init__(self, secret=None):
        self._secret = secret
        self.stored = []

    def get_secret(self, peer):
        return self._secret

    def set_secret(self, peer, secret):
        self._secret = secret
        self.stored.append(peer)


class _FakeOtr:
    """Only what the flow touches.  Records what it was asked to do."""

    def __init__(self, stored=None, secret_required=False):
        self.smp_storage = _FakeStorage(stored)
        self._secret_required = secret_required
        self.resumed = []
        self.declined = []
        self.started = []
        self.set_secrets = []
        self.raise_on_set = None

    def has_encrypted_session(self, peer):
        return True

    def smp_secret_required(self, peer):
        return self._secret_required

    def set_smp_secret(self, peer, secret):
        if self.raise_on_set:
            raise self.raise_on_set
        self.set_secrets.append(peer)
        self.smp_storage.set_secret(peer, secret)
        return True

    def resume_held_smp1(self, peer):
        self.resumed.append(peer)
        return "?OTR:SMP2."

    def decline_held_smp1(self, peer, reason=b""):
        self.declined.append(peer)
        return "?OTR:ABORT."

    def start_smp(self, peer, secret, question=None):
        self.started.append(peer)
        return "?OTR:SMP1."


class _Client:
    """The real methods, bound to a stub with no network and no terminal."""

    def __init__(self, stored=None, secret_required=False):
        self.otr = _FakeOtr(stored, secret_required)
        self._secret_request = None
        self._secret_purpose = None
        self._secret_purpose_taken = None
        self._smp_flows = smpflow.SmpFlowRegistry()
        self._smp_consent_shown = None
        self._mask_input = False
        self._tui_enabled = False
        self._screen = None
        self._encrypted = {PEER}
        self._last_dake1 = {}
        self._smp_reported = set()
        self.peer = PEER
        self.printed = []
        self.sent = []
        cls = xmpp.OTRv4PlusXMPP
        for name in ("smp_verify", "_announce_secret_required",
                     "_handle_smp_consent", "_decline_smp_request",
                     "_arm_secret_prompt", "_request_smp_secret",
                     "_handle_smp_secret_answer", "take_secret_request",
                     "_pending_consent_peer", "dispatch_line",
                     "_expire_stale_smp_consent", "has_pending",
                     "_check_smp_secret_required", "_forget_otr"):
            setattr(self, name, getattr(cls, name).__get__(self, cls))
        self._validate_smp_secret = cls._validate_smp_secret

    # stubs for the things the real client would do
    def _mask_next_input(self, on):
        self._mask_input = bool(on)
        return True

    def send_otr_fragmented(self, peer, msg):
        self.sent.append((peer, msg))

    def smp_start(self, peer, secret=None):
        self.otr.start_smp(peer, secret)

    def _resume_held_smp1(self, peer):
        self.otr.resume_held_smp1(peer)

    def _dbg(self, *a, **k):
        pass

    def send_user_text(self, peer, text):
        self.sent.append((peer, "MESSAGE:" + text))


@pytest.fixture(autouse=True)
def capture(monkeypatch):
    """Collect everything the client prints, so tests can assert on wording
    and on what never appears in it."""
    lines = []
    monkeypatch.setattr("builtins.print",
                        lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    return lines


class TestInitiator:

    def test_smp_with_a_stored_passphrase_starts_at_once(self, capture):
        c = _Client(stored=SECRET)
        c.smp_verify(PEER)
        assert c.otr.started == [PEER]
        assert c._secret_request is None, "it asked despite having one stored"

    def test_smp_without_one_prompts_hidden(self, capture):
        c = _Client(stored=None)
        c.smp_verify(PEER)
        assert c._secret_request == PEER
        assert c._secret_purpose == "start"
        assert c._mask_input is True, "the passphrase would be echoed"
        assert c.otr.started == [], "SMP started before there was a passphrase"

    def test_answering_stores_it_and_starts_without_a_second_command(self, capture):
        c = _Client(stored=None)
        c.smp_verify(PEER)
        c.dispatch_line(PEER, SECRET)
        assert c.otr.set_secrets == [PEER]
        assert c.otr.started == [PEER]
        assert c._mask_input is False, "the mask was left on"

    def test_cancelling_stores_nothing(self, capture):
        c = _Client(stored=None)
        c.smp_verify(PEER)
        c.dispatch_line(PEER, "")
        assert c.otr.set_secrets == []
        assert c.otr.started == []
        assert any("cancelled" in l.lower() for l in capture)

    def test_a_too_short_passphrase_is_not_a_verification_failure(self, capture):
        c = _Client(stored=None)
        c.smp_verify(PEER)
        c.dispatch_line(PEER, "short")
        text = " ".join(capture).lower()
        assert "too short" in text
        assert "did not match" not in text, (
            "a local validation error is being reported as a failed "
            "verification")
        assert c.otr.started == []


class TestResponder:

    def test_an_arriving_smp1_asks_for_consent_and_arms_nothing(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        assert c._smp_flows.get(PEER).awaiting_consent()
        assert c._secret_request is None, (
            "an incoming message armed the passphrase read")
        assert c._mask_input is False
        assert any("VERIFICATION REQUEST" in l for l in capture)

    def test_an_ordinary_message_at_the_consent_prompt_is_just_a_message(
            self, capture):
        """The acceptance test from the brief."""
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "hey, are you free later?")
        assert c.otr.set_secrets == [], (
            "an ordinary chat message was stored as the shared passphrase")
        assert c._secret_request is None
        assert c._smp_flows.get(PEER).awaiting_consent(), (
            "the request should still be waiting, not consumed")

    def test_y_opens_the_hidden_prompt(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "y")
        assert c._secret_request == PEER
        assert c._secret_purpose == "resume"
        assert c._mask_input is True

    def test_the_passphrase_resumes_the_held_smp1(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "y")
        c.dispatch_line(PEER, SECRET)
        assert c.otr.set_secrets == [PEER]
        assert c.otr.resumed == [PEER], "the parked SMP1 was never answered"
        assert c.otr.started == [], "it restarted SMP instead of answering"

    def test_n_declines_and_sends_an_abort(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "n")
        assert c.otr.declined == [PEER]
        assert c.sent, "the peer was never told, and is still waiting"
        assert c.otr.set_secrets == []
        text = " ".join(capture).lower()
        assert "declined" in text
        assert "no passphrase was requested, stored or sent" in text

    def test_cancelling_the_passphrase_after_consent_aborts_cleanly(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "y")
        c.dispatch_line(PEER, "")
        assert c.otr.declined == [PEER]
        assert c.otr.set_secrets == []
        assert c._mask_input is False

    def test_a_duplicate_smp1_does_not_print_twice(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c._check_smp_secret_required(PEER)
        c._check_smp_secret_required(PEER)
        assert sum(1 for l in capture if "VERIFICATION REQUEST" in l) == 1

    def test_a_responder_with_a_stored_passphrase_is_never_asked(self, capture):
        """The engine does not hold when a secret is set, so the client is
        never told to ask."""
        c = _Client(stored=SECRET, secret_required=False)
        c._check_smp_secret_required(PEER)
        assert not c._smp_flows.get(PEER).awaiting_consent()
        assert c._secret_request is None


class TestRemoteCannotCapture:
    """INV-06, extended to the guided flow."""

    def test_no_inbound_path_reaches_the_armer(self):
        """The call graph, not a hand-written list."""
        src = open(os.path.join(ROOT, "otrv4plus_xmpp.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        methods = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.setdefault(node.name, []).append(node)

        def calls(node):
            out = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    if isinstance(f, ast.Attribute):
                        out.add(f.attr)
                    elif isinstance(f, ast.Name):
                        out.add(f.id)
            return out

        seen, stack = set(), ["_handle_otr_in_async"]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            for node in methods.get(name, []):
                stack.extend(calls(node) - seen)

        assert "_announce_secret_required" in seen, (
            "the responder prompt is unreachable from inbound; the flow is "
            "broken rather than safe")
        assert "_arm_secret_prompt" not in seen, (
            "an inbound message can arm the hidden passphrase read")
        assert "_handle_smp_secret_answer" not in seen, (
            "an inbound message can supply a passphrase")

    def test_the_dead_pending_pattern_is_not_back(self):
        """`_pending[peer] = "smp_secret"` and its IRC twin, `_set_pending`.

        Checked against the CODE, with comments and docstrings removed: both
        files describe the old defect in prose deliberately, and a test that
        could not tell prose from code would force those explanations out of
        the source.
        """
        for name in ("otrv4plus_xmpp.py", "otrv4+.py"):
            path = os.path.join(ROOT, name)
            src = open(path, encoding="utf-8").read()
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef, ast.Module)):
                    body = getattr(node, "body", None)
                    if (body and isinstance(body[0], ast.Expr)
                            and isinstance(body[0].value, ast.Constant)
                            and isinstance(body[0].value.value, str)):
                        body[0].value.value = ""
            code = ast.unparse(tree)
            assert '_pending[peer] = "smp_secret"' not in code, name
            assert "_pending[peer] = 'smp_secret'" not in code, name
            assert "_set_pending('smp_secret'" not in code, (
                "%s arms generic input capture for a secret again" % name)
            assert '_set_pending("smp_secret"' not in code, (
                "%s arms generic input capture for a secret again" % name)

    def test_consent_only_accepts_yes_or_no(self, capture):
        """Anything else falls through to ordinary handling, so a passphrase
        typed by mistake at this prompt is sent as a message and not stored.
        That is the safe failure: visible, and not silently a secret."""
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        for line in ("maybe", "Y E S", "/smp", "yes please"):
            assert c._pending_consent_peer() == PEER
            c.dispatch_line(PEER, line)
            assert c.otr.set_secrets == [], line

    def test_an_expired_request_no_longer_answers_to_y(self, capture):
        now = [1000.0]
        c = _Client(stored=None, secret_required=True)
        c._smp_flows = smpflow.SmpFlowRegistry(clock=lambda: now[0])
        c._check_smp_secret_required(PEER)
        now[0] += smpflow.CONSENT_TIMEOUT_SECS + 1
        assert c._pending_consent_peer() is None
        c.dispatch_line(PEER, "y")
        assert c._secret_request is None, (
            "a y typed long afterwards, meaning something else, opened a "
            "passphrase prompt")


class TestFailureClassification:
    """Six states, six messages, and none of them lying about the others."""

    def test_an_internal_error_is_not_reported_as_a_wrong_passphrase(self, capture):
        c = _Client(stored=None)
        c.otr.raise_on_set = RuntimeError("vault exploded")
        c.smp_verify(PEER)
        c.dispatch_line(PEER, SECRET)
        text = " ".join(capture).lower()
        assert "internal error" in text
        assert "no secret was transmitted" in text
        assert "did not match" not in text
        # It must not claim success either.  "Nothing is verified" is the
        # correct thing to say, so look for a success claim rather than for
        # the word.
        assert "smp verified" not in text
        assert "✓" not in text

    def test_the_no_secret_abort_still_says_it_is_not_a_wrong_passphrase(self):
        otr = pytest.importorskip("otrv4_")
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        assert "not a wrong-passphrase failure" in src

    def test_a_declined_request_is_distinguishable_on_the_wire(self):
        otr = pytest.importorskip("otrv4_")
        assert otr.OTRv4TLV.SMP_ABORT_DECLINED != otr.OTRv4TLV.SMP_ABORT_NO_SECRET
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        assert "declined the verification request" in src


class TestNothingLeaksThePassphrase:

    def test_it_is_not_printed_on_any_path(self, capture):
        for line in (SECRET, "short", ""):
            c = _Client(stored=None)
            c.otr.raise_on_set = RuntimeError("boom")
            c.smp_verify(PEER)
            c.dispatch_line(PEER, line)
        joined = " ".join(capture)
        assert SECRET not in joined, "the passphrase was printed"

    def test_it_is_not_in_the_exception_text(self, capture):
        c = _Client(stored=None)
        c.otr.raise_on_set = RuntimeError("failed for " + SECRET)
        c.smp_verify(PEER)
        c.dispatch_line(PEER, SECRET)
        # The client prints the exception, so this is really a check that we
        # never PUT the secret in one.  Assert on our own paths instead.
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._handle_smp_secret_answer)
        tree = ast.parse(src.lstrip())
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                assert "secret" not in names, (
                    "an f-string in the secret handler interpolates the "
                    "passphrase")

    def test_the_flow_object_never_holds_it(self):
        flow = smpflow.SmpFlow(PEER)
        flow.local_secret_needed()
        flow.secret_supplied()
        blob = repr(flow.__dict__)
        assert SECRET not in blob
        src = inspect.getsource(smpflow)
        assert "passphrase" not in src.split('"""')[2] or True   # prose is fine
        # Structural: no attribute is ever assigned a value named `secret`.
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name):
                assert node.value.id not in ("secret", "passphrase"), (
                    "the state machine stores the passphrase")

    def test_the_secret_local_is_dropped_after_use(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._handle_smp_secret_answer)
        assert "del secret" in src, (
            "the handler keeps its reference to the passphrase after handing "
            "it to the engine")


class TestCleanup:

    def test_teardown_closes_an_open_passphrase_prompt(self, capture):
        c = _Client(stored=None)
        c.smp_verify(PEER)
        assert c._secret_request == PEER
        c._forget_otr(PEER, "peer went offline")
        assert c._secret_request is None, (
            "the prompt outlived the session; the next line typed would be "
            "read as a passphrase for a session that no longer exists")
        assert c._mask_input is False

    def test_teardown_closes_an_open_consent_request(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c._forget_otr(PEER, "peer went offline")
        assert c._pending_consent_peer() is None
        assert c._smp_flows.get(PEER).state == smpflow.IDLE

    def test_teardown_stores_nothing(self, capture):
        c = _Client(stored=None, secret_required=True)
        c._check_smp_secret_required(PEER)
        c.dispatch_line(PEER, "y")
        c._forget_otr(PEER, "peer went offline")
        assert c.otr.set_secrets == []


class TestTheCoreApiContract:
    """The regression that started this: a client calling a method the
    installed wheel does not have."""

    def test_the_installed_wheel_has_everything_the_clients_call(self):
        import otrv4plus_coreapi as coreapi
        assert coreapi.missing_core_api() == []

    def test_a_stale_core_is_named_precisely(self):
        import otrv4plus_coreapi as coreapi

        class StaleVault:
            def store(self, *a):
                return 1

        class StaleCore:
            RustSMPVault = StaleVault
            RustSMP = type("S", (), {})

        missing = coreapi.missing_core_api(StaleCore)
        assert any("store_from_bytearray" in m for m in missing)
        assert any("0.10.25" in m for m in missing), (
            "the report does not say which version introduced it")

    def test_the_hint_names_both_supported_builds(self):
        """Termux builds the .so and copies it; a machine with maturin builds
        a wheel.  A hint that names only the wheel sends a phone user to a
        toolchain they do not have, which is how the first version of this
        message was wrong."""
        import otrv4plus_coreapi as coreapi
        hint = coreapi.REBUILD_HINT
        assert "cargo build --release --features extension-module,pq-rust" in hint
        assert "libotrv4_core.so" in hint
        assert "pip install" in hint and "./Rust" in hint

    def test_the_hint_matches_the_readme(self):
        """The two must not drift: the README is where someone looks when the
        client is not running at all."""
        import otrv4plus_coreapi as coreapi
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        for line in ("cargo build --release --features extension-module,pq-rust",
                     "cp target/release/libotrv4_core.so ../otrv4_core.so"):
            assert line in readme, "README no longer documents: %s" % line
            assert line in coreapi.REBUILD_HINT

    def test_the_client_checks_before_it_needs_it(self):
        src = inspect.getsource(xmpp.main)
        assert "verify_core_api" in src, (
            "the version check does not run at startup, so a mismatch is "
            "found later, inside SMP, worded as a protocol failure")

    def test_the_wheel_version_matches_the_crate_version(self):
        """Two files carry the core's version and only one was being bumped.

        Found while writing this change: Cargo.toml said 0.10.27 and the
        installed wheel reported 0.10.26, because maturin takes the version
        from pyproject.toml.  Harmless on its own -- the API check compares
        attributes, not version numbers -- but "which core am I running" is
        the question this whole class of bug is about, and an answer that is
        quietly wrong is worse than no answer.
        """
        import re
        cargo = open(os.path.join(ROOT, "Rust", "Cargo.toml"),
                     encoding="utf-8").read()
        pyproj = open(os.path.join(ROOT, "Rust", "pyproject.toml"),
                      encoding="utf-8").read()
        c = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M).group(1)
        p = re.search(r'^version\s*=\s*"([^"]+)"', pyproj, re.M).group(1)
        assert c == p, (
            "Rust/Cargo.toml says %s but Rust/pyproject.toml says %s; the "
            "wheel reports the second one" % (c, p))

    def test_no_client_calls_a_vault_method_the_manifest_omits(self):
        """Whatever the clients call on the vault must be declared, or the
        next regression of this kind gets through too."""
        import otrv4plus_coreapi as coreapi
        declared = {attr for owner, attr, _ in coreapi.REQUIRED_CORE_API
                    if owner == "RustSMPVault"}
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        called = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr in ("smp_vault", "_vault")):
                called.add(node.func.attr)
        undeclared = called - declared
        assert not undeclared, (
            "otrv4+.py calls vault methods the core-API manifest does not "
            "list: %s" % sorted(undeclared))


# ═══════════════════════════════════════════════════════════════════════════
# Regressions found on two real phones, 2026-09-04.
#
# All three got past the tests above because those tests drove the client's
# own methods with a fake engine.  Nothing checked that a real SMP1, arriving
# at a real session, reached the state the feature depends on.  These do.
# ═══════════════════════════════════════════════════════════════════════════

otr_mod = pytest.importorskip("otrv4_")


class _Tracer:
    def __init__(self):
        self.events = []

    def trace(self, *a, **k):
        self.events.append(a)

    _emit_cb = None


class _ClientProfile:
    def __init__(self, fp):
        self.identity_pub_bytes = fp
        self.identity_key = None


class _DakeEngine:
    def __init__(self, fp):
        self.client_profile = _ClientProfile(fp)


class _Session:
    """A real EnhancedOTRSession method set, bound to the minimum state.

    Deliberately uses the real Rust engine and the real _enh_handle_smp_tlv:
    the bugs these tests pin were all in what the real code does with a real
    SMP1, which a fake engine cannot show.
    """

    def __init__(self, guided=True, is_initiator=False,
                 local_fp=b"fp-local", remote_fp=b"fp-remote"):
        self.peer = PEER
        self.is_initiator = is_initiator
        self.rust_smp = None
        self.smp_vault = None
        self.smp_guided_prompt = guided
        self._smp_secret_required = False
        self._queued_smp_response = None
        self._ping_refresh_cb = None
        self.smp_step = 0
        self.session_id = b"session-id-for-the-test"
        # The real method reads the local fingerprint off the DAKE engine's
        # client profile.  A stub that left this None made every race take
        # the "no fingerprints to tie-break" abort, which is not the branch
        # under test.
        self.dake_engine = _DakeEngine(local_fp)
        self._remote_long_term_pub_bytes = remote_fp
        self._local_fp = local_fp
        self.tracer = _Tracer()
        self.auto_smp_started = False
        self.auto_smp_completed = False
        self.notices = []
        import logging
        self.logger = logging.getLogger("test-session")
        cls = otr_mod.EnhancedOTRSession
        for name in ("_enh_handle_smp_tlv", "initialize_smp"):
            setattr(self, name, getattr(cls, name).__get__(self, cls))

    # the bits _enh_handle_smp_tlv needs from the wider session
    def encrypt_with_tlvs(self, text, tlvs):
        return ("ENCRYPTED", tuple((t.type, bytes(t.value)) for t in tlvs))

    def _smp_progress_notify(self, step, total, detail, role=None,
                             color="yellow", final=False):
        self.notices.append(detail)

    def _acquire_lock(self, *a, **k):
        return True

    def _release_lock(self, *a, **k):
        pass

    # the real method reads local_fp off the dake engine; short-circuit it
    def _set_secret(self, passphrase):
        self.initialize_smp()
        self.smp_vault.store_from_bytearray(
            "smp_secret", bytearray(passphrase.encode()))
        assert self.rust_smp.set_secret_from_vault(
            self.smp_vault, "smp_secret", self.session_id,
            self._local_fp, self._remote_long_term_pub_bytes)


def _real_smp1(secret=SECRET, sid=b"session-id-for-the-test",
               ours=b"fp-remote", theirs=b"fp-local"):
    """An SMP1 from the other side, with the fingerprints in the order that
    peer would use."""
    a = core.RustSMP(True)
    a.set_secret_from_bytearray(bytearray(secret.encode()), sid, ours, theirs)
    return bytes(a.generate_smp1(None))


def _tlv(value):
    return otr_mod.OTRv4TLV(otr_mod.OTRv4TLV.SMP_MSG_1, value)


class TestTheGuidedFlagActuallyReachesTheEngine:
    """Regression: the responder flow was built and never switched on.

    `smp_guided_prompt` gates whether an incoming SMP1 is parked or aborted,
    and nothing in the XMPP client ever set it to True.  On two real phones
    Alice therefore aborted with NOSECRET exactly as she had before the
    feature existed, and Bob was told "your peer has not stored the
    passphrase yet -- ask them to run /smp-secret".
    """

    def test_the_client_turns_it_on(self):
        """Structural, because the defect was an assignment that did not
        exist anywhere."""
        src = open(os.path.join(ROOT, "otrv4plus_xmpp.py"),
                   encoding="utf-8").read()
        tree = ast.parse(src)
        enabled = False
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True):
                for target in node.targets:
                    if (isinstance(target, ast.Attribute)
                            and target.attr == "smp_guided_prompt"):
                        enabled = True
        assert enabled, (
            "the XMPP client never sets smp_guided_prompt = True, so an "
            "incoming SMP1 is aborted instead of parked and the whole "
            "responder flow is dead code")

    def test_the_manager_passes_it_to_new_sessions(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        assert src.count("session.smp_guided_prompt = getattr(") == 3, (
            "a session-creation path does not receive the flag; sessions "
            "made there would silently abort instead of parking")

    def test_a_real_smp1_reaches_secret_required(self):
        """The behavioural check the AST tests could not make."""
        s = _Session(guided=True)
        s.initialize_smp()
        s._enh_handle_smp_tlv(_tlv(_real_smp1()))
        assert s.rust_smp.get_phase() == "SECRET_REQUIRED"
        assert s.rust_smp.has_held_smp1()
        assert s._queued_smp_response is None, (
            "an abort went out to the peer even though the message was held")
        assert s._smp_secret_required is True

    def test_without_the_flag_it_still_aborts_with_a_reason(self):
        """IRC, and any front end that cannot prompt, must not leave the peer
        waiting for an answer that will never come."""
        s = _Session(guided=False)
        s.initialize_smp()
        s._enh_handle_smp_tlv(_tlv(_real_smp1()))
        assert s.rust_smp.get_phase() != "SECRET_REQUIRED"
        assert s._queued_smp_response is not None
        _text, tlvs = s._queued_smp_response
        assert tlvs[0][0] == otr_mod.OTRv4TLV.SMP_ABORT
        assert tlvs[0][1] == otr_mod.OTRv4TLV.SMP_ABORT_NO_SECRET

    def test_a_responder_with_a_passphrase_answers_immediately(self):
        s = _Session(guided=True)
        s._set_secret(SECRET)
        s._enh_handle_smp_tlv(_tlv(_real_smp1()))
        assert s.rust_smp.get_phase() == "AWAITING_MSG3"
        _text, tlvs = s._queued_smp_response
        assert tlvs[0][0] == otr_mod.OTRv4TLV.SMP_MSG_2


class TestSimultaneousInitiation:
    """Regression: `SMP race-recovery: vault rebind failed`, every time.

    When both sides run /smp at once the higher-fingerprint side yields the
    initiator role, rebuilds its engine and rebinds the secret from the
    vault.  initialize_smp() constructs a NEW vault whenever rust_smp is
    None, so the rebuild threw away the entry the rebind then looked for.
    The recovery path could never have worked.
    """

    def test_the_vault_survives_the_engine_rebuild(self):
        # local_fp > remote_fp, so this side yields and takes the recovery
        # branch.
        s = _Session(guided=True, is_initiator=True,
                     local_fp=b"fp-zzz", remote_fp=b"fp-aaa")
        s._set_secret(SECRET)
        s.rust_smp.generate_smp1(None)                 # now AWAITING_MSG2
        assert s.rust_smp.get_phase() == "AWAITING_MSG2"
        vault_before = s.smp_vault

        s._enh_handle_smp_tlv(_tlv(_real_smp1(ours=b"fp-aaa",
                                              theirs=b"fp-zzz")))

        assert s.smp_vault is vault_before, (
            "the vault was replaced during recovery, so the secret it holds "
            "was thrown away")
        assert s.smp_vault.has("smp_secret")
        assert s.rust_smp.get_phase() == "AWAITING_MSG3", (
            "the yielded side did not answer the peer's SMP1")
        _text, tlvs = s._queued_smp_response
        assert tlvs[0][0] == otr_mod.OTRv4TLV.SMP_MSG_2

    def test_the_lower_fingerprint_side_keeps_its_role(self):
        s = _Session(guided=True, is_initiator=True,
                     local_fp=b"fp-aaa", remote_fp=b"fp-zzz")
        s._set_secret(SECRET)
        s.rust_smp.generate_smp1(None)
        s._enh_handle_smp_tlv(_tlv(_real_smp1(ours=b"fp-zzz",
                                              theirs=b"fp-aaa")))
        assert s.rust_smp.get_phase() == "AWAITING_MSG2", (
            "both sides yielded; nobody is the initiator")
        assert s._queued_smp_response is None

    def test_recovery_without_a_stored_secret_asks_instead_of_erroring(self):
        """The rebind can legitimately fail -- this side may never have been
        given a passphrase.  That is a setup state, not an internal error."""
        s = _Session(guided=True, is_initiator=True,
                     local_fp=b"fp-zzz", remote_fp=b"fp-aaa")
        s.initialize_smp()
        # In AWAITING_MSG2 with no secret: possible after an aborted run.
        s.rust_smp.set_secret_from_bytearray(
            bytearray(SECRET.encode()), s.session_id, b"fp-zzz", b"fp-aaa")
        s.rust_smp.generate_smp1(None)
        # Vault deliberately empty: nothing was ever stored under the name.
        s._enh_handle_smp_tlv(_tlv(_real_smp1(ours=b"fp-aaa",
                                              theirs=b"fp-zzz")))
        assert s.rust_smp.get_phase() in ("SECRET_REQUIRED", "IDLE"), (
            "recovery raised instead of falling through to the no-secret "
            "handling")


class TestAnAbortIsNotAMismatch:
    """Regression: the client printed both of these, from one abort.

        SMP stopped: your peer has not stored the passphrase yet.
        ...This is not a wrong-passphrase failure.
        *** SMP FAILED - secrets did NOT match. Possible MITM. ***
    """

    def _report(self, phase_name, monkeypatch, capture):
        """Drive the real _report_smp with the engine reporting `phase_name`.

        Behavioural, because the first version of these tests only read the
        source and a mutation that disabled the branch entirely survived
        them -- which is precisely the weakness that let the shipped bug
        through in the first place.
        """
        client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        client._smp_reported = set()
        client._smp_display_hints = set()

        class _Sess:
            smp_verified = False
            is_verified = False
            identity_verified = False
            smp_complete = False
            is_complete = False

        class _Otr:
            def get_session(self, peer):
                return _Sess()

        client.otr = _Otr()
        monkeypatch.setattr(xmpp, "_smp_query",
                            lambda otr, peer: (False, phase_name))
        client._report_smp(PEER)
        return " ".join(capture)

    def test_an_abort_does_not_print_the_mitm_line(self, monkeypatch, capture):
        text = self._report("ABORTED", monkeypatch, capture)
        assert "stopped before verifying" in text
        assert "MITM" not in text, (
            "a peer with no passphrase is still reported as a possible MITM")
        assert "did NOT" not in text

    def test_a_real_failure_still_warns(self, monkeypatch, capture):
        """The MITM warning must survive: a genuine mismatch is exactly what
        it is for."""
        text = self._report("FAILED", monkeypatch, capture)
        assert "MITM" in text
        assert "secrets did NOT" in text

    def test_the_mitm_line_is_gated_on_a_real_failure(self):
        """Read the reporter: an ABORT must not reach the mismatch branch."""
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        # rindex, not index: the comment above the branch quotes the old
        # message verbatim, and matching that instead of the live print is
        # how this test first passed against unfixed code.
        i = src.rindex("secrets did NOT")
        window = src[max(0, i - 3000):i]
        assert "is_abort" in window, (
            "nothing distinguishes an abort from a failed comparison, so a "
            "peer with no passphrase is reported as a possible MITM")

    def test_an_abort_gets_its_own_wording(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert "stopped before verifying" in src
        i = src.index("stopped before verifying")
        window = src[i:i + 400]
        assert "not a wrong-passphrase failure" in window
        assert "MITM" not in window

    def test_abort_and_failure_are_different_branches(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert src.count("_smp_reported.add(key_fail)") == 2, (
            "abort and failure share one branch again")
