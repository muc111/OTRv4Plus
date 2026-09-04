#!/usr/bin/env python3
"""INV-06: no remote protocol message may arm local secret-input capture.

The defect this pins
--------------------
`_apply_tofu` used to end by setting `_pending[peer] = "smp_secret"`, and
`dispatch_line` consumed that pending state before any command parsing.
`_apply_tofu` is reached from `_handle_otr_in_async` -- the inbound message
handler -- so a peer who completed a DAKE could make the user's next typed
line, whatever it was, be swallowed and stored as a shared secret.  Only
`/quit` escaped.

The line was masked and never transmitted, so this was not exfiltration.
It was a remote peer deciding what the local user's keystrokes mean, which
is the property being defended here.

These tests read the source rather than driving a live client, because the
property is structural: it is about which functions can reach which, not
about what one particular sequence of calls happens to do.
"""

import ast
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

XMPP = os.path.join(ROOT, "otrv4plus_xmpp.py")


def _src():
    return open(XMPP, encoding="utf-8").read()


def _tree():
    return ast.parse(_src())


def _methods(tree):
    """Every method body in the file, keyed by name."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, []).append(node)
    return out


def _calls_in(node):
    """Names of everything called anywhere inside `node`."""
    names = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute):
                names.add(f.attr)
            elif isinstance(f, ast.Name):
                names.add(f.id)
    return names


def _reachable_from(entry, methods, limit=40):
    """Transitive closure of method names reachable from `entry`."""
    seen, frontier = set(), [entry]
    while frontier and len(seen) < 5000:
        name = frontier.pop()
        if name in seen:
            continue
        seen.add(name)
        for defn in methods.get(name, ()):
            for called in _calls_in(defn):
                if called not in seen and called in methods:
                    frontier.append(called)
    return seen


# --------------------------------------------------------------------------
# The mechanism is gone
# --------------------------------------------------------------------------

class TestThePendingMechanismIsGone:

    def test_no_peer_keyed_pending_secret_state(self):
        """Checked against the AST, not the text.

        The docstring of `_announce_smp_needed` quotes the old assignment on
        purpose, so a substring search over the source would match the
        explanation of the fix and fail forever.
        """
        tree = _tree()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Subscript):
                    continue
                val = target.value
                name = val.attr if isinstance(val, ast.Attribute) else None
                assert name != "_pending", (
                    "a peer-keyed _pending map is back at line %d"
                    % node.lineno)

    def test_feed_pending_is_gone(self):
        assert "def feed_pending" not in _src(), (
            "feed_pending consumed an arbitrary line into a pending state; "
            "it has no safe use")

    def test_subscription_pending_is_a_different_thing_and_survives(self):
        """_pending_subscriptions is XMPP presence approval, not input capture.

        Named similarly enough that a careless sweep would delete it, which
        would silently auto-accept subscription requests.
        """
        src = _src()
        assert "_pending_subscriptions" in src
        assert "def accept_subscription" in src or "/accept" in src


# --------------------------------------------------------------------------
# Arming requires local intent
# --------------------------------------------------------------------------

class TestOnlyLocalCommandsCanArm:

    def test_exactly_one_method_arms_the_request(self):
        src = _src()
        armers = re.findall(r"^\s*self\._secret_request = (?!None)", src,
                            re.MULTILINE)
        assert len(armers) == 1, (
            "expected exactly one assignment that arms the secret prompt, "
            "found %d" % len(armers))

    def test_the_armer_is_arm_secret_prompt(self):
        """One function arms the hidden read, and it is the only one.

        `_request_smp_secret` (the /smp-secret command), `smp_verify` (the
        /smp command) and `_handle_smp_consent` (after a y) all go through it,
        so the reachability tests below have a single target to check.
        """
        methods = _methods(_tree())
        assert "_arm_secret_prompt" in methods
        body = ast.get_source_segment(_src(), methods["_arm_secret_prompt"][0])
        assert "self._secret_request = peer" in body
        src = _src()
        assignments = [l for l in src.splitlines()
                       if "self._secret_request = peer" in l]
        assert len(assignments) == 1, (
            "the hidden read is armed in %d places; it must be one: %r"
            % (len(assignments), assignments))

    def test_inbound_handler_cannot_reach_the_armer(self):
        """The whole point.  Walks the real call graph, not a hand-list."""
        methods = _methods(_tree())
        assert "_handle_otr_in_async" in methods, "inbound handler renamed"
        reachable = _reachable_from("_handle_otr_in_async", methods)
        assert "_arm_secret_prompt" not in reachable, (
            "a remote message can reach the secret-prompt armer again; "
            "reachable set included it")

    def test_tofu_cannot_reach_the_armer(self):
        methods = _methods(_tree())
        reachable = _reachable_from("_apply_tofu", methods)
        assert "_arm_secret_prompt" not in reachable

    def test_dake_completion_cannot_reach_the_armer(self):
        methods = _methods(_tree())
        reachable = _reachable_from("_check_dake_complete", methods)
        assert "_arm_secret_prompt" not in reachable

    def test_signal_handlers_cannot_reach_the_armer(self):
        """Voice control messages are remote input too."""
        methods = _methods(_tree())
        for handler in ("_on_rekey", "_on_rekey_ack", "_on_rekey_commit"):
            if handler in methods:
                assert "_request_smp_secret" not in _reachable_from(
                    handler, methods), handler

    def test_the_announcement_path_arms_nothing(self):
        methods = _methods(_tree())
        assert "_announce_smp_needed" in methods
        body = ast.get_source_segment(_src(), methods["_announce_smp_needed"][0])
        assert "_secret_request" not in body
        assert "_mask_next_input" not in body, (
            "the announcement must not even change echo state; that is a "
            "remote peer touching the terminal")


# --------------------------------------------------------------------------
# The request is single-use
# --------------------------------------------------------------------------

class TestTheRequestIsSingleUse:

    def test_dispatch_takes_it_unconditionally(self):
        methods = _methods(_tree())
        body = ast.get_source_segment(_src(), methods["dispatch_line"][0])
        assert "take_secret_request()" in body
        # Taken before any command matching: a passphrase may start with "/".
        assert body.index("take_secret_request()") < body.index("lstrip =")

    def test_take_always_clears(self):
        methods = _methods(_tree())
        body = ast.get_source_segment(_src(), methods["take_secret_request"][0])
        assert "self._secret_request" in body and "None" in body, body
        # and prove it behaviourally rather than by shape
        assert "return peer" in body

    def test_quit_no_longer_needs_a_special_case(self):
        """The old code had to exempt /quit because the capture was sticky.

        A single-use request consumed on the very next line does not trap the
        user, so the exemption is gone -- and its absence is the evidence that
        the stickiness is gone with it.
        """
        methods = _methods(_tree())
        body = ast.get_source_segment(_src(), methods["dispatch_line"][0])
        head = body[:body.index("lstrip =")]
        assert "/quit" not in head

    def test_ending_a_session_drops_a_request_for_that_peer(self):
        src = _src()
        assert src.count("if self._secret_request == peer:") >= 1, (
            "a secret prompt must not outlive the session it belongs to")


# --------------------------------------------------------------------------
# Behavioural: a client double, driven end to end
# --------------------------------------------------------------------------

class _FakeOtr:
    def __init__(self):
        self.stored = []
        self.encrypted = {"alice@example.i2p"}

    def has_encrypted_session(self, peer):
        return peer in self.encrypted

    def set_smp_secret(self, peer, secret):
        self.stored.append((peer, secret))
        return True


class _Client:
    """Only the pieces dispatch_line touches, bound to the real methods."""

    def __init__(self, cls):
        import otrv4plus_smpflow as smpflow
        self.otr = _FakeOtr()
        self._secret_request = None
        self._secret_purpose = None
        self._secret_purpose_taken = None
        # The guided flow.  Real object, not a stub: the property these tests
        # are about is which transitions exist, so faking it would test
        # nothing.
        self._smp_flows = smpflow.SmpFlowRegistry()
        self._smp_consent_shown = None
        self._mask_input = False
        self._tui_enabled = False
        self._screen = None
        self.sent = []
        self.peer = "alice@example.i2p"
        for name in ("take_secret_request", "has_pending",
                     "_request_smp_secret", "_announce_smp_needed",
                     "_handle_smp_secret_answer", "_arm_secret_prompt",
                     "_pending_consent_peer", "_announce_secret_required",
                     "_handle_smp_consent", "_decline_smp_request",
                     "smp_verify"):
            setattr(self, name, getattr(cls, name).__get__(self, cls))
        # A staticmethod must NOT be rebound, or it swallows `self` as the
        # secret and every validation call raises TypeError.
        self._validate_smp_secret = cls._validate_smp_secret

    def _mask_next_input(self, on):
        self._mask_input = bool(on)
        return True


@pytest.fixture
def cls():
    otr = pytest.importorskip("otrv4plus_xmpp")
    return otr.OTRv4PlusXMPP


class TestBehaviour:

    def test_announcement_leaves_ordinary_text_ordinary(self, cls, capsys):
        c = _Client(cls)
        c._announce_smp_needed("alice@example.i2p")
        capsys.readouterr()
        assert c.take_secret_request() is None, (
            "an announcement armed a capture")

    def test_request_then_line_stores_the_secret(self, cls, capsys):
        c = _Client(cls)
        c._request_smp_secret("alice@example.i2p")
        capsys.readouterr()
        target = c.take_secret_request()
        assert target == "alice@example.i2p"
        c._handle_smp_secret_answer(target, "correct horse battery staple")
        assert c.otr.stored == [("alice@example.i2p",
                                 "correct horse battery staple")]

    def test_a_request_survives_exactly_one_line(self, cls, capsys):
        c = _Client(cls)
        c._request_smp_secret("alice@example.i2p")
        capsys.readouterr()
        assert c.take_secret_request() == "alice@example.i2p"
        assert c.take_secret_request() is None
        assert c.take_secret_request() is None

    def test_request_refused_without_an_encrypted_session(self, cls, capsys):
        c = _Client(cls)
        c._request_smp_secret("stranger@example.i2p")
        out = capsys.readouterr().out
        assert "no encrypted session" in out
        assert c.take_secret_request() is None

    def test_masking_is_lifted_after_the_answer(self, cls, capsys):
        c = _Client(cls)
        c._request_smp_secret("alice@example.i2p")
        assert c._mask_input is True
        c._handle_smp_secret_answer(c.take_secret_request(), "a passphrase")
        capsys.readouterr()
        assert c._mask_input is False, "echo left disabled after the prompt"

    def test_cancelling_stores_nothing(self, cls, capsys):
        c = _Client(cls)
        c._request_smp_secret("alice@example.i2p")
        c._handle_smp_secret_answer(c.take_secret_request(), "")
        capsys.readouterr()
        assert c.otr.stored == []
        assert c._mask_input is False

    def test_the_answer_is_never_printed(self, cls, capsys):
        c = _Client(cls)
        secret = "zebra-vault-9911-passphrase"
        c._request_smp_secret("alice@example.i2p")
        c._handle_smp_secret_answer(c.take_secret_request(), secret)
        out = capsys.readouterr()
        assert secret not in out.out
        assert secret not in out.err

    def test_a_rejected_secret_is_not_echoed_in_the_error(self, cls, capsys):
        c = _Client(cls)
        secret = "shrt"          # below SMP_MIN_LEN
        c._request_smp_secret("alice@example.i2p")
        c._handle_smp_secret_answer(c.take_secret_request(), secret)
        out = capsys.readouterr()
        assert secret not in out.out, "validation error quoted the secret"
        assert c.otr.stored == []
