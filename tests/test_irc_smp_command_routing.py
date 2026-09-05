"""`/smp` has to reach the guided flow through the dispatcher that runs.

v10.23.0 shipped the guided SMP flow for the IRC client -- masked prompt, no
passphrase in the scrollback, verification starting the moment the passphrase
is entered -- and on a handset it did nothing at all:

    2026-09-05 14:56:49 [sys]   Usage: /smp <command> [args]
    2026-09-05 14:57:07 [IronFenrir] ✅ SMP secret stored (🦀 Rust vault)
    2026-09-05 14:57:07 [IronFenrir] 🔐 Type  /smp start  to begin verification.

The flow was correct and unreachable. There were two `/smp` dispatchers in
`otrv4+.py` -- one in `OTRv4IRCClient.handle_command`, one in the
`EnhancedOTRv4IRCClient` override -- and the new branch went into the base
class, which the subclass shadows for this command. The only class the
program instantiates is the subclass.

WHY THE TESTS DID NOT CATCH IT
==============================
`test_irc_guided_smp.py` binds the flow methods onto a stub and calls
`_smp_verify` directly. Every assertion in it was true. Not one of them went
through `handle_command`, so the question "can a user get here by typing
/smp" was never asked. That is the gap this file closes: everything here
enters through `handle_command`, the real method, on the real class.

A unit test that constructs the collaborator it is testing against will
happily pass on code nobody can run. When the reported symptom is "I typed
the command and got the old behaviour", the test has to start at the typing.

Enforces INV-06 and INV-11 for the IRC client's command surface.
"""

import threading

import pytest

otr = pytest.importorskip("otrv4plus")
smpflow = pytest.importorskip("otrv4plus_smpflow")

CLIENT = otr.EnhancedOTRv4IRCClient
PEER = "IronFenrir"


class Storage:
    def __init__(self, owner):
        self._o = owner

    def get_secret(self, peer):
        return self._o.stored.get(peer, "")

    def set_secret(self, peer, secret):
        self._o.stored[peer] = secret


class Manager:
    """A session manager that says yes, so the command path is what is
    under test rather than the guards in front of it."""

    def __init__(self, owner, encrypted=True, session=True):
        self._o = owner
        self._encrypted = encrypted
        self._session = session
        self.smp_storage = Storage(owner)

    def has_session(self, peer):
        return self._session

    def get_security_level(self, peer):
        return (otr.UIConstants.SecurityLevel.ENCRYPTED if self._encrypted
                else otr.UIConstants.SecurityLevel.PLAINTEXT)

    def set_smp_secret(self, peer, secret):
        self._o.stored[peer] = secret

    def smp_secret_required(self, peer):
        return False


class Client:
    """The real `handle_command` and the real flow methods, bound onto the
    smallest object that can carry them.

    Deliberately NOT a stub of `handle_command` itself -- that is the method
    the bug was in.
    """

    #: Everything reached from the /smp command path.
    METHODS = (
        "handle_command", "_smp_verify", "_active_peer", "_smp_session_ready",
        "_warn_inline_secret", "_arm_secret_prompt", "_disarm_secret_prompt",
        "_consume_secret_line", "_panel_sec", "_otr_panel", "_set_pending",
        "_get_pending", "_clear_pending", "_handle_smp_consent",
        "_announce_secret_required", "_decline_smp_request", "_resume_smp",
    )

    def __init__(self, stored=None, encrypted=True, session=True, active=PEER):
        self.lines = []
        self.stored = dict(stored or {})
        self.started = []
        self.panel_manager = otr.PanelManager(self)
        self.panel_manager.add_panel(PEER, "private")
        if active is not None:
            self.panel_manager.switch_to_panel(active)
        self.session_manager = Manager(self, encrypted, session)
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
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    # -- collaborators the command path calls ------------------------
    def add_message(self, target, message, sec=None):
        self.lines.append(str(message))

    def debug(self, *a, **k):
        pass

    def _start_smp(self, peer, secret, question=""):
        self.started.append((peer, secret))

    def send_otr_message(self, peer, msg):
        pass

    def said(self, needle):
        return any(needle in line for line in self.lines)


@pytest.fixture(autouse=True)
def _mask_off():
    """The mask is a module global; a test that arms and then fails would
    otherwise hide the next test's input."""
    otr.set_input_mask(False)
    yield
    otr.set_input_mask(False)


@pytest.fixture
def client():
    return Client()


class TestBareSmpReachesTheGuidedFlow:
    """The reported bug. Every one of these fails on v10.23.1."""

    @pytest.mark.parametrize("typed", ["smp", "SMP", "verify", " smp "])
    def test_it_arms_the_masked_prompt(self, typed):
        c = Client()
        c.handle_command(typed)
        assert otr._mask_input is True, "the passphrase would be echoed"
        assert c._secret_request == PEER
        assert c._secret_purpose == "start"

    def test_it_does_not_print_the_usage_line(self, client):
        client.handle_command("smp")
        assert not client.said("Usage: /smp <command>"), (
            "bare /smp fell through to the argument-parsing error, which is "
            "exactly what the handset showed"
        )

    def test_the_next_line_becomes_the_passphrase_and_verifies(self, client):
        client.handle_command("smp")
        assert client._consume_secret_line("correct horse battery") is True
        assert client.stored[PEER] == "correct horse battery"
        assert client.started == [(PEER, "correct horse battery")]

    def test_no_second_command_is_demanded(self, client):
        """The handset was told to type /smp start after storing. One
        command, or the flow is not simpler than what it replaced."""
        client.handle_command("smp")
        client._consume_secret_line("correct horse battery")
        assert not client.said("/smp start")

    def test_the_passphrase_is_never_printed(self, client):
        client.handle_command("smp")
        client._consume_secret_line("correct horse battery")
        assert not client.said("correct horse battery")

    def test_a_stored_passphrase_verifies_without_asking(self):
        c = Client(stored={PEER: "already agreed"})
        c.handle_command("smp")
        assert otr._mask_input is False
        assert c._secret_request is None
        assert c.started == [(PEER, "already agreed")]


class TestSmpStartIsTheSameThing:
    """`/smp start` used to dead-end on "use /smp <peer> <secret> first" --
    pointing the user at the one spelling that echoes the passphrase."""

    def test_it_asks_when_nothing_is_stored(self, client):
        client.handle_command("smp start")
        assert otr._mask_input is True
        assert client._secret_request == PEER

    def test_it_no_longer_sends_the_user_to_the_echoed_form(self, client):
        client.handle_command("smp start")
        assert not client.said("/smp <peer> <secret>")
        assert not client.said("No SMP secret stored")

    def test_it_starts_when_something_is_stored(self):
        c = Client(stored={PEER: "already agreed"})
        c.handle_command("smp start")
        assert c.started == [(PEER, "already agreed")]

    def test_an_explicit_peer_still_works(self):
        c = Client(stored={PEER: "already agreed"}, active="system")
        c.handle_command("smp start %s" % PEER)
        assert c.started == [(PEER, "already agreed")]


class TestTheInlineFormStillWorksAndSaysWhatItCost:
    """`/smp <secret>` is not removed -- it is scriptable and some people
    want it -- but it echoes, and it should not need a second command."""

    def test_it_stores_and_starts_in_one_step(self, client):
        client.handle_command("smp correct horse battery")
        assert client.stored[PEER] == "correct horse battery"
        assert client.started == [(PEER, "correct horse battery")]

    def test_it_no_longer_demands_smp_start(self, client):
        client.handle_command("smp correct horse battery")
        assert not client.said("Type  /smp start")

    def test_it_warns_that_the_passphrase_was_echoed(self, client):
        client.handle_command("smp correct horse battery")
        assert client.said("typed in the clear"), (
            "the input line is cleared on Enter, but a session capture "
            "recorded the keystrokes; saying nothing implies it was hidden"
        )

    def test_the_warning_points_at_the_hidden_form(self, client):
        client.handle_command("smp correct horse battery")
        assert client.said("/smp  asks for it hidden")

    def test_a_short_passphrase_is_refused_and_nothing_starts(self, client):
        client.handle_command("smp short")
        assert client.started == []
        assert client.stored == {}

    def test_the_refusal_does_not_name_the_passphrase(self, client):
        client.handle_command("smp shortpw")
        assert not client.said("shortpw")


class TestItRefusesToAskWhenThereIsNothingToVerify:
    """A passphrase prompt for a session that does not exist is a passphrase
    typed for nothing -- and the user cannot tell the difference."""

    def test_no_session_means_no_prompt(self):
        c = Client(session=False)
        c.handle_command("smp")
        assert otr._mask_input is False
        assert c._secret_request is None
        assert c.said("No session with")

    def test_a_plaintext_session_means_no_prompt(self):
        c = Client(encrypted=False)
        c.handle_command("smp")
        assert otr._mask_input is False
        assert c._secret_request is None
        assert c.said("No encrypted session with")

    def test_a_raising_session_manager_means_no_prompt(self):
        """Fail-closed, like INV-12: a predicate that raises counts as not
        ready rather than as ready."""
        c = Client()

        def boom(peer):
            raise RuntimeError("gone")

        c.session_manager.has_session = boom
        c.handle_command("smp")
        assert otr._mask_input is False
        assert c._secret_request is None

    def test_the_system_tab_is_not_a_peer(self):
        c = Client(active="system")
        c.handle_command("smp")
        assert otr._mask_input is False
        assert c._secret_request is None
        assert c.said("Switch to a peer panel first")


class TestOnlyOneDispatcherOwnsTheCommand:
    """The shape of the bug, asserted directly: two handlers for one command
    in one file, and the fix landing in the shadowed one."""

    def test_the_base_class_does_not_claim_smp(self):
        """If it does, the next person to fix /smp has a 50% chance of
        editing the copy that never runs."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        base = next(n for n in tree.body
                    if isinstance(n, ast.ClassDef) and n.name == "OTRv4IRCClient")
        fn = next(n for n in base.body
                  if isinstance(n, ast.FunctionDef) and n.name == "handle_command")
        src = ast.unparse(fn)
        for claim in ("cmd == 'smp'", "cmd in ('smp'", "'smp', 'verify'"):
            assert claim not in src, (
                "OTRv4IRCClient.handle_command claims /smp again; "
                "EnhancedOTRv4IRCClient shadows it and the branch is dead"
            )

    def test_the_subclass_does(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        sub = next(n for n in tree.body
                   if isinstance(n, ast.ClassDef)
                   and n.name == "EnhancedOTRv4IRCClient")
        fn = next(n for n in sub.body
                  if isinstance(n, ast.FunctionDef) and n.name == "handle_command")
        assert "_smp_verify" in ast.unparse(fn)


class TestTheInlineFormCannotTalkOverAHeldRequest:
    """`/smp <secret>` used to go straight to `_start_smp`. If the engine is
    holding a peer's SMP1 at that moment, starting a fresh run leaves the
    held one parked and the peer waiting on a message that never comes."""

    def test_it_reports_the_pending_prompt_instead_of_starting(self, client):
        client._smp_flows.get(PEER).remote_smp1_arrived()
        client.handle_command("smp correct horse battery")
        assert client.started == [], (
            "a second SMP run was started while one was already pending")
        assert client.said("Already asking you")

    def test_the_passphrase_is_still_stored_for_the_answer(self, client):
        """Refusing to start is not refusing to keep what they typed --
        they will be asked for it again when they answer `y`."""
        client._smp_flows.get(PEER).remote_smp1_arrived()
        client.handle_command("smp correct horse battery")
        assert client.stored[PEER] == "correct horse battery"
