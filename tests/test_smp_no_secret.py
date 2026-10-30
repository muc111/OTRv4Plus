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

from source_of import irc_and_engine_source, open_irc_and_engine  # noqa: E402,F401
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

    # Phase 5 (2026-10-30): these ran an SMP between two real sessions in
    # place of reading `_enh_handle_smp_tlv`'s source for the branch.

    @pytest.fixture
    def no_secret_run(self, monkeypatch):
        """Alice starts SMP with a secret; Bob has none. Returns what each
        side was told and traced, and both SMP states."""
        import test_smp_end_to_end as E
        # A fresh DAKE1 limiter: the module-wide one is shared with every
        # earlier test in the run, which can leave it refusing this DAKE.
        monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())
        alice_mgr, bob_mgr = E._manager(), E._manager()
        alice, bob = "alice@example.test", "bob@example.test"
        dake1, _send = alice_mgr.handle_outgoing_message(bob, "")
        E._relay(dake1, alice_mgr, bob_mgr, alice, bob)
        seen = {"alice": [], "bob": [], "alice_trace": [], "bob_trace": []}
        for mgr, peer, who in ((alice_mgr, bob, "alice"), (bob_mgr, alice, "bob")):
            session = mgr.get_session(peer)
            notify = session._smp_progress_notify
            session._smp_progress_notify = (
                lambda *a, _n=notify, _w=who, **k: (seen[_w].append(a[2]), _n(*a, **k)))
            trace = session.tracer.trace
            session.tracer.trace = (
                lambda *a, _t=trace, _w=who, **k: (seen[_w + "_trace"].append(a), _t(*a, **k)))
        alice_mgr.set_smp_secret(bob, E.SECRET)
        delivered = E._relay(alice_mgr.start_smp(bob, E.SECRET), alice_mgr, bob_mgr, alice, bob)
        seen["delivered"] = delivered
        seen["alice_state"] = alice_mgr.get_smp_status(bob)
        seen["bob_state"] = bob_mgr.get_smp_status(alice)
        return seen

    def test_the_responder_aborts_and_nothing_is_verified(self, no_secret_run):
        # Explaining the failure must not replace failing.
        r = no_secret_run
        assert r["delivered"] == 2, "SMP1 out, the abort back, nothing more"
        assert r["alice_state"]["state"] == "ABORTED"
        assert not r["alice_state"]["verified"] and not r["bob_state"]["verified"]

    def test_the_responder_is_told_what_command_to_run(self, no_secret_run):
        # `/smp` asks for the passphrase and then verifies, so the user needs
        # one verb; `/smp-secret` remains the explicit store-only form.
        told = " ".join(no_secret_run["bob"])
        assert told, "the responder is not told anything"
        assert "/smp" in told, "the message does not name the command that fixes it"

    def test_the_initiator_distinguishes_no_secret_from_a_generic_abort(self, no_secret_run):
        traced = [t for t in no_secret_run["alice_trace"] if t[1:3] == ("SMP", "ABORTED")]
        assert traced and traced[-1][3] == "PEER_NO_SECRET", (
            "the initiator no longer traces the no-secret case separately: %r" % traced)
        told = " ".join(no_secret_run["alice"])
        assert "has not stored the passphrase" in told
        assert "not a wrong-passphrase failure" in told

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
        assert "_request_smp_secret" not in src

    def test_nothing_in_the_engine_arms_it(self):
        """The engine handles remote input. The prompt belongs to the UI."""
        import otrv4_
        src = irc_and_engine_source()
        assert "_request_smp_secret" not in src, (
            "the protocol engine can arm the secret prompt")

    def test_only_the_explicit_command_arms_the_prompt(self):
        """Superseded and tightened at v10.13.1.

        The previous version of this test allowed `_apply_tofu` and
        `_check_dake_complete` in the set of "local flows" that may arm the
        prompt.  That was wrong: both are reached from
        `_handle_otr_in_async`, so a remote peer decided when they ran.  The
        test passed while the property it was named for was false.

        The rule now is the narrow one -- only a command the user typed may
        arm it -- and the call-graph proof lives in
        `test_no_remote_input_capture.py`, which walks the inbound handlers
        transitively rather than checking a hand-maintained allow-list.
        """
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        callers = []
        tree = ast.parse(inspect.getsource(xmpp))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if _calls_named(node, "_request_smp_secret"):
                callers.append(node.name)
        assert callers, "nothing prompts for the secret any more"
        assert set(callers) == {"_dispatch_smp"}, (
            "the secret prompt is armed from %s; only the user's own typed "
            "command may arm it" % sorted(callers))

    def test_the_prompt_is_single_use_rather_than_a_pending_state(self):
        """The old mechanism was sticky: once armed it consumed every line
        until answered, and only `/quit` escaped.  The replacement is taken
        unconditionally on the next dispatched line, so a prompt cannot
        outlive the line it was armed for."""
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        head = src.split("lstrip = line.strip()")[0]
        pending = inspect.getsource(xmpp.OTRv4PlusXMPP._dispatch_pending)
        assert "_dispatch_pending(line)" in head and "take_secret_request()" in pending, (
            "the secret request must be taken before command parsing, "
            "because a passphrase may legitimately begin with '/'")
        assert "/quit" not in head + pending, (
            "a /quit escape hatch means the prompt is sticky again")

    def test_the_explicit_command_still_exists(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._dispatch_smp)
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
