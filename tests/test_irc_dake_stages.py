"""The handshake should say which stage it is on, and OK only when it is.

The old output was a running commentary interleaved with fragment progress
bars -- "DAKE1 -> sent - waiting for response...", "DAKE2 <- received from X",
"DAKE3 -> sent to X", "sent DAKE1 (18 fragments)" -- and on a handset it was
hard to tell which step you were on or whether it had worked.

Now each stage is one call, made after the operation returned:

    🔐 DAKE 1
    🟢 OK

The header and the verdict come from the same call on purpose rather than for
tidiness. There is no code path that prints the header alone, so there is no
path that can print `OK` for a stage whose operation has not returned -- the
structural version of "do not print a misleading OK".

Fragment counts are not deleted, they are moved: `detail` goes to
`self.debug`, which reaches the debug panel only under DEBUG_MODE. Same split
the XMPP client makes with `_dbg`.
"""

import re

import pytest

otr = pytest.importorskip("otrv4plus")

CLIENT = otr.EnhancedOTRv4IRCClient
PEER = "IronFenrir"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(text):
    return _ANSI.sub("", str(text))


class Manager:
    def __init__(self, level=None):
        self.level = level or otr.UIConstants.SecurityLevel.ENCRYPTED

    def get_security_level(self, peer):
        return self.level


class Client:
    METHODS = ("_dake_stage", "_dake_ready")

    def __init__(self):
        self.lines = []
        self.debugged = []
        self.session_manager = Manager()
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    def add_message(self, target, message, sec=None):
        self.lines.append(plain(message))

    def debug(self, message, data=None):
        self.debugged.append((message, data))

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture
def client():
    return Client()


class TestTheStagesAreSeparateAndUnambiguous:

    @pytest.mark.parametrize("stage", [1, 2, 3])
    def test_a_stage_names_its_own_number(self, client, stage):
        client._dake_stage(PEER, stage, "ok")
        assert "DAKE %d" % stage in client.text

    def test_ok_is_its_own_line(self, client):
        client._dake_stage(PEER, 1, "ok")
        assert client.lines[0].strip() == "🔐 DAKE 1"
        assert client.lines[1].strip() == "🟢 OK"

    def test_the_three_stages_read_in_order(self, client):
        for stage in (1, 2, 3):
            client._dake_stage(PEER, stage, "ok")
        assert [ln.strip() for ln in client.lines] == [
            "🔐 DAKE 1", "🟢 OK",
            "🔐 DAKE 2", "🟢 OK",
            "🔐 DAKE 3", "🟢 OK",
        ]

    def test_the_ready_line_comes_after(self, client):
        client._dake_stage(PEER, 3, "ok")
        client._dake_ready(PEER)
        assert client.lines[-1].strip() == "🟢 OTR SESSION READY"


class TestOkIsNeverPrintedForAFailure:

    def test_a_failure_is_reported_against_its_own_stage(self, client):
        client._dake_stage(PEER, 2, "ring signature did not verify")
        assert "DAKE 2" in client.text
        assert "FAILED" in client.text
        assert "OK" not in client.text

    def test_the_failure_carries_the_reason(self, client):
        client._dake_stage(PEER, 2, "ring signature did not verify")
        assert "ring signature did not verify" in client.text

    @pytest.mark.parametrize("outcome", ["ok", "OK", "Ok"])
    def test_only_the_exact_ok_token_means_success(self, client, outcome):
        """A near-miss must fail loudly rather than read as success."""
        client._dake_stage(PEER, 1, outcome)
        if outcome == "ok":
            assert "🟢 OK" in client.text
        else:
            assert "FAILED" in client.text

    def test_a_failure_reason_is_sanitised(self, client):
        """Reasons can quote peer-influenced text; a terminal escape in one
        would rewrite the screen around the verdict."""
        client._dake_stage(PEER, 1, "bad \x1b[2Jthing")
        assert "\x1b[2J" not in "".join(client.lines)

    def test_a_long_reason_is_capped(self, client):
        client._dake_stage(PEER, 1, "x" * 500)
        assert len(client.lines[-1]) < 200


class TestFragmentCountsMoveToDebug:

    def test_the_count_is_not_in_the_normal_output(self, client):
        client._dake_stage(PEER, 1, "ok", detail="sent — 18 fragments")
        assert "18 fragments" not in client.text

    def test_the_count_is_still_available_to_debug(self, client):
        client._dake_stage(PEER, 1, "ok", detail="sent — 18 fragments")
        assert client.debugged, "the diagnostic was deleted rather than moved"
        assert any("18 fragments" in str(data)
                   for _msg, data in client.debugged)

    def test_no_debug_line_when_there_is_nothing_to_say(self, client):
        client._dake_stage(PEER, 1, "ok")
        assert client.debugged == []

    def test_the_send_path_records_a_count_for_it(self):
        """`send_otr_message` sets `_last_fragment_count`; without it the
        debug line would always say zero."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        assert "_last_fragment_count = len(fragments)" in ast.unparse(fn)


class TestTheNoteIsForWaiting:

    def test_a_note_is_shown_under_ok(self, client):
        client._dake_stage(PEER, 1, "ok", note="waiting for their answer…")
        assert "waiting for their answer" in client.text

    def test_a_note_is_not_shown_on_failure(self, client):
        client._dake_stage(PEER, 1, "no route", note="waiting…")
        assert "waiting" not in client.text


class TestNoSecretsInTheHandshakeOutput:
    """These lines are printed at the exact moment key material exists."""

    def test_the_stage_line_carries_only_a_number_and_a_verdict(self, client):
        client._dake_stage(PEER, 2, "ok",
                           detail="sent — 18 fragments")
        for line in client.lines:
            assert not re.search(r"[0-9a-f]{32,}", line), (
                "something key-shaped reached the handshake output")

    def test_a_broken_security_lookup_does_not_stop_the_report(self, client):
        """The verdict matters more than the badge colour."""
        class Boom:
            def get_security_level(self, peer):
                raise RuntimeError("no session yet")

        client.session_manager = Boom()
        client._dake_stage(PEER, 1, "ok")
        assert "🟢 OK" in client.text


class TestTheHandlersUseIt:
    """Having the helper is not the change; the DAKE handlers calling it is."""

    @staticmethod
    @pytest.fixture(scope="class")
    def sources():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        out = {}
        cls = next(n for n in tree.body
                   if isinstance(n, ast.ClassDef)
                   and n.name == "EnhancedOTRv4IRCClient")
        for node in cls.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            # Docstrings out: `"""DAKE2 received -> send DAKE3"""` is prose
            # about the protocol, not a line printed to the user, and a
            # substring assertion that cannot tell them apart tests the
            # comments rather than the code.
            body = list(node.body)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            out[node.name] = "\n".join(ast.unparse(n) for n in body)
        return out

    @pytest.mark.parametrize("fn", ["process_dake1", "process_dake2",
                                    "process_dake3",
                                    "start_guided_otr_session"])
    def test_each_handler_reports_a_stage(self, sources, fn):
        assert "_dake_stage" in sources[fn]

    @pytest.mark.parametrize("fn", ["process_dake2", "process_dake3",
                                    "start_guided_otr_session"])
    def test_the_old_arrow_commentary_is_gone(self, sources, fn):
        for old in ("DAKE1 →", "DAKE2 ←", "DAKE3 →", "DAKE3 ←", "DAKE2 →"):
            assert old not in sources[fn], (
                "%s still prints the old running commentary" % fn)

    def test_the_initiator_reports_ok_from_the_send_result(self, sources):
        """Not from having attempted the send: a DAKE1 that never left the
        socket is not a completed stage."""
        src = sources["start_guided_otr_session"]
        assert "sent = self.send_otr_message" in src
        assert "'ok' if sent else" in src

    def test_the_responder_reports_stage_two_from_its_send(self, sources):
        src = sources["_route_otr_to_session_manager"]
        assert "sent = self.send_otr_message" in src
        assert "_dake_stage" in src

    def test_the_ready_line_replaces_session_ready(self, sources):
        src = sources["_finish_session_setup"]
        assert "_dake_ready" in src
        assert "Session ready! - DAKE" not in src

    def test_the_engine_tags_are_kept(self, sources):
        """Which engine did the work is a security-relevant reassurance and
        stays on screen -- dim, not deleted."""
        src = sources["_finish_session_setup"]
        assert "_ratchet_tag" in src and "_smp_tag" in src

    def test_the_tofu_wording_is_untouched(self, sources):
        """Pinned is not verified, and the two must keep saying so. This is
        the state the user has to be able to tell apart, and a handshake
        tidy-up is exactly the change that would blur it."""
        src = sources["_handle_session_established"]
        assert "Pinning is not verification" in src
        assert "First contact" in src
