#!/usr/bin/env python3
"""SMP when the responder has no secret, and the input-capture boundary.

Two separate problems, fixed together because they meet at the same prompt.

1. A responder with no stored passphrase used to queue SMP_ABORT and return in
   silence. The responder was told nothing at all, and the initiator saw a
   generic "aborted" that reads identically to a wrong passphrase -- so the one
   failure a user can actually fix looked like the one they cannot.

2. The obvious fix is to prompt the responder for the secret. That would be a
   remote-triggered input capture: `_pending[peer] = "smp_secret"` makes
   `dispatch_line` swallow the NEXT line typed, ahead of every command except
   /quit. A peer could then decide that the user's next sentence -- possibly
   meant for a different conversation -- becomes a stored secret. So the secret
   is supplied by an explicit local command, and these tests hold that line.
"""

import ast
import inspect
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")


def _fn(obj):
    return ast.parse(textwrap.dedent(inspect.getsource(obj))).body[0]


def _calls_named(node, name):
    """Every Call in `node` whose target ends in `name`."""
    out = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        if isinstance(f, ast.Attribute) and f.attr == name:
            out.append(sub)
        elif isinstance(f, ast.Name) and f.id == name:
            out.append(sub)
    return out


class TestTheAbortSaysWhy:

    def test_the_reason_code_exists_and_is_bytes(self):
        assert isinstance(otr.OTRv4TLV.SMP_ABORT_NO_SECRET, bytes)
        assert otr.OTRv4TLV.SMP_ABORT_NO_SECRET

    def test_the_no_secret_path_sends_the_reason(self):
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        tree = ast.parse(textwrap.dedent(src))
        # Find the branch guarded by `not ...check_secret_set()`.
        branch = None
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _calls_named(node.test, "check_secret_set"):
                branch = node
                break
        assert branch is not None, "the no-secret branch is gone"
        names = {n.attr for n in ast.walk(branch) if isinstance(n, ast.Attribute)}
        assert "SMP_ABORT_NO_SECRET" in names, (
            "the no-secret abort no longer names its reason, so the initiator "
            "cannot tell it apart from a wrong passphrase")

    def test_the_no_secret_path_still_aborts(self):
        # Explaining the failure must not replace failing.
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        tree = ast.parse(textwrap.dedent(src))
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _calls_named(node.test, "check_secret_set"):
                names = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
                assert "SMP_ABORT" in names
                return
        pytest.fail("the no-secret branch is gone")

    def test_the_responder_is_told_what_command_to_run(self):
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        tree = ast.parse(textwrap.dedent(src))
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and _calls_named(node.test, "check_secret_set"):
                assert _calls_named(node, "_smp_progress_notify"), (
                    "the responder is not told anything")
                text = " ".join(
                    n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))
                assert "/smp-secret" in text, (
                    "the message does not name the command that fixes it")
                return
        pytest.fail("the no-secret branch is gone")

    def test_the_initiator_distinguishes_no_secret_from_a_generic_abort(self):
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        tree = ast.parse(textwrap.dedent(src))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert "SMP_ABORT_NO_SECRET" in names
        assert "PEER_NO_SECRET" in {
            n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}, (
            "the initiator no longer traces the no-secret case separately")

    def test_the_reason_is_read_from_the_tlv_value_field(self):
        # OTRv4TLV.__slots__ is ("type", "value"). Reading `.data` would make
        # the comparison silently always-false and the feature a no-op.
        assert otr.OTRv4TLV.__slots__ == ("type", "value")
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        assert 'getattr(tlv, "value"' in src, (
            "the abort reason is read from a field the TLV does not have")

    def test_the_reason_is_not_a_security_predicate(self):
        """It may choose wording. It must not choose an outcome.

        The payload is written by the peer. If verification, trust or session
        state ever branched on it, a peer could talk its way past SMP by
        claiming a reason.
        """
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        tree = ast.parse(textwrap.dedent(src))
        target = None
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "no_secret"):
                target = node
        assert target is not None, "the reason is no longer decoded"
        # Every use of `no_secret` must be inside an If that only picks a
        # notification, never an assignment to verification state.
        for node in ast.walk(tree):
            if not (isinstance(node, ast.If)
                    and any(isinstance(n, ast.Name) and n.id == "no_secret"
                            for n in ast.walk(node.test))):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        attr = getattr(t, "attr", "")
                        assert "verif" not in attr and "trust" not in attr, (
                            "the peer-supplied abort reason drives %s" % attr)


class TestRemoteInputCannotBecomeASecret:

    def test_the_no_secret_branch_never_arms_the_pending_prompt(self):
        src = inspect.getsource(otr.EnhancedOTRSession._enh_handle_smp_tlv)
        assert "_pending" not in src, (
            "an inbound SMP message reaches the pending-input state; a peer "
            "could make the user's next typed line a secret")
        assert "_prompt_smp_secret" not in src

    def test_nothing_in_the_engine_arms_it(self):
        """The engine handles remote input. The prompt belongs to the UI."""
        import otrv4_
        src = inspect.getsource(otrv4_)
        assert "_prompt_smp_secret" not in src, (
            "the protocol engine can arm the secret prompt")

    def test_only_local_flows_arm_it_in_the_client(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        callers = []
        tree = ast.parse(inspect.getsource(xmpp))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if _calls_named(node, "_prompt_smp_secret"):
                callers.append(node.name)
        assert callers, "nothing prompts for the secret any more"
        # Every caller must be reached from local input or local session state,
        # never from a decoded peer message.
        allowed = {"_check_dake_complete", "_handle_trust_answer",
                   "_apply_tofu", "store_smp_secret"}
        assert set(callers) <= allowed, (
            "the secret prompt is armed from %s, which is not a local flow"
            % (set(callers) - allowed))

    def test_pending_input_still_takes_precedence_once_locally_armed(self):
        # The precedence itself is fine and wanted -- it is only dangerous if a
        # remote peer can arm it. Pin the precedence so the fix is understood
        # as "control who arms it", not "make the prompt weaker".
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        assert "has_pending" in src.split("lstrip = line.strip()")[0]

    def test_the_explicit_command_still_exists(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        assert "/smp-secret " in src
        assert hasattr(xmpp.OTRv4PlusXMPP, "store_smp_secret")

    def test_the_explicit_command_consumes_its_own_argument(self):
        """`/smp-secret <secret>` must take the secret from the command line,
        not by arming a prompt that eats the following line."""
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        fn = _fn(xmpp.OTRv4PlusXMPP.store_smp_secret)
        assert "_pending" not in inspect.getsource(xmpp.OTRv4PlusXMPP.store_smp_secret)
        args = [a.arg for a in fn.args.args]
        assert "secret" in args, "the command does not take a secret argument"
