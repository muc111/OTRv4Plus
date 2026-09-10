"""A transport interruption is not a security boundary.

Reported from a handset: the I2P SAM tunnel dropped, the IRC connection died
with it, and the OTR session became unusable. The only way back was `/quit`
and a full restart of the client -- losing the DAKE, the pinned fingerprint
for the session, and any SMP verification already done.

`_try_reconnect` was doing it on purpose. It called `ratchet.zeroize()` on
every session, wiped the root and chain keys by hand, and then
`session_manager.sessions.clear()`. A tunnel blip destroyed every encrypted
conversation on the client.

The XMPP client has never done this, and it is the reference: its
`_on_disconnected` drops trades and presence, rebuilds the SAM tunnel,
reconnects the stream, and leaves `self.otr.sessions` untouched. The double
ratchet is a property of the two peers and their keys, not of the socket that
carried the bytes.

WHAT MUST NOT BE PRESERVED, AND WHY EACH ONE HAS ITS OWN TEST
=============================================================
Preserving state is only safe if the things that are genuinely per-connection
go. Three of them, and each would be a real defect if kept:

  * A half-reassembled inbound message. Its remaining fragments were on the
    socket that died; keeping the prefix means the next connection's
    fragments get appended to it.
  * An armed passphrase prompt. Keeping it means the user's next line becomes
    a passphrase for a session whose transport just vanished -- and the input
    mask stays on over their ordinary chat. INV-06 governs who may arm that
    prompt; this is the other half of it.
  * A pending y/n consent question, for the same reason.

And nothing is replayed. Not a data message, not a fragment, not an SMP
message. OTRv4 replay protection is not something to work around.

Enforces INV-06 (the half about an armed prompt not outliving its transport)
and INV-24 (the conversation still must not cross the connection boundary on
screen, even though the keys now do).
"""

import threading

import pytest

otr = pytest.importorskip("otrv4plus")
smpflow = pytest.importorskip("otrv4plus_smpflow")

CLIENT = otr.EnhancedOTRv4IRCClient
PEER = "IronFenrir"
OTHER = "GlacialWolf"


class Ratchet:
    def __init__(self):
        self.zeroized = False

    def zeroize(self):
        self.zeroized = True


class Session:
    def __init__(self, phase="IDLE"):
        self.ratchet = Ratchet()
        self.root_key = b"\x11" * 64
        self.chain_key_send = b"\x22" * 64
        self.chain_key_recv = b"\x33" * 64
        self.rust_smp = Engine(phase)


class Engine:
    def __init__(self, phase):
        self._phase = phase

    def get_phase(self):
        return self._phase


class Manager:
    def __init__(self):
        self.sessions = {}

    def has_session(self, peer):
        return peer in self.sessions

    def get_security_level(self, peer):
        return (otr.UIConstants.SecurityLevel.ENCRYPTED if peer in self.sessions
                else otr.UIConstants.SecurityLevel.PLAINTEXT)


class Client:
    METHODS = ("_preserve_otr_across_reconnect", "_report_preserved_sessions",
               "_arm_secret_prompt", "_disarm_secret_prompt", "_panel_sec",
               "_set_pending", "_get_pending", "_clear_pending")

    def __init__(self, peers=(PEER,), phase="IDLE"):
        self.lines = []
        self.session_manager = Manager()
        for p in peers:
            self.session_manager.sessions[p] = Session(phase)
        self.panel_manager = otr.PanelManager(self)
        for p in peers:
            self.panel_manager.add_panel(p, "private")
            self.panel_manager.panels[p].security_level = \
                otr.UIConstants.SecurityLevel.SMP_VERIFIED
        self.fragment_buffers = {}
        self._smp_flows = smpflow.SmpFlowRegistry()
        self._secret_request = None
        self._secret_purpose = None
        self._smp_consent_shown = None
        self._prompt_refresh_cb = None
        self._pending_action = None
        self._pending_lock = threading.RLock()
        self._preserved = None
        self.channel_log = None
        self._tui_enabled = False
        self._screen = None
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    def add_message(self, target, message, sec=None):
        self.lines.append(str(message))

    def debug(self, *a, **k):
        pass

    def said(self, needle):
        return any(needle in line for line in self.lines)


@pytest.fixture(autouse=True)
def _mask_off():
    otr.set_input_mask(False)
    yield
    otr.set_input_mask(False)


@pytest.fixture
def client():
    return Client()


class TestTheSessionSurvives:
    """The reported bug, and the reason `/quit` was the only way back."""

    def test_the_session_is_still_there(self, client):
        client._preserve_otr_across_reconnect()
        assert PEER in client.session_manager.sessions

    def test_the_ratchet_is_not_zeroized(self, client):
        sess = client.session_manager.sessions[PEER]
        client._preserve_otr_across_reconnect()
        assert sess.ratchet.zeroized is False, (
            "a tunnel blip destroyed the double ratchet")

    def test_the_keys_are_not_wiped(self, client):
        sess = client.session_manager.sessions[PEER]
        client._preserve_otr_across_reconnect()
        assert sess.root_key == b"\x11" * 64
        assert sess.chain_key_send == b"\x22" * 64
        assert sess.chain_key_recv == b"\x33" * 64

    def test_several_sessions_all_survive(self):
        c = Client(peers=(PEER, OTHER))
        c._preserve_otr_across_reconnect()
        assert set(c.session_manager.sessions) == {PEER, OTHER}

    def test_the_panel_keeps_its_badge(self, client):
        """The padlock is not stale -- the session behind it is still live,
        so downgrading the panel would be the lie."""
        client._preserve_otr_across_reconnect()
        assert client.panel_manager.panels[PEER].security_level == \
            otr.UIConstants.SecurityLevel.SMP_VERIFIED

    def test_a_panel_with_no_session_goes_back_to_plaintext(self, client):
        client.panel_manager.add_panel("Stranger", "private")
        client.panel_manager.panels["Stranger"].security_level = \
            otr.UIConstants.SecurityLevel.ENCRYPTED
        client._preserve_otr_across_reconnect()
        assert client.panel_manager.panels["Stranger"].security_level == \
            otr.UIConstants.SecurityLevel.PLAINTEXT


class TestWhatMustNotSurvive:

    def test_partial_reassembly_is_dropped(self, client):
        """Its remaining fragments died with the socket. Keeping the prefix
        means the next connection's fragments are appended to it."""
        client.fragment_buffers[PEER] = object()
        client._preserve_otr_across_reconnect()
        assert client.fragment_buffers == {}

    def test_an_armed_passphrase_prompt_is_cancelled(self, client):
        client._arm_secret_prompt(PEER, "start")
        assert otr._mask_input is True
        client._preserve_otr_across_reconnect()
        assert client._secret_request is None
        assert client._secret_purpose is None

    def test_the_input_mask_is_lifted(self, client):
        """Left on, it hides the user's ordinary chat after the reconnect."""
        client._arm_secret_prompt(PEER, "start")
        client._preserve_otr_across_reconnect()
        assert otr._mask_input is False

    def test_a_pending_consent_question_is_dropped(self, client):
        client._set_pending("smp_consent", PEER)
        client._preserve_otr_across_reconnect()
        assert client._get_pending() is None

    def test_the_consent_shown_marker_is_cleared(self, client):
        """Otherwise a re-sent request after the reconnect prints nothing,
        and the user is never asked."""
        client._smp_consent_shown = PEER
        client._preserve_otr_across_reconnect()
        assert client._smp_consent_shown is None


class TestNothingIsReplayed:
    """The tempting bug: re-send what was in flight. OTRv4 replay protection
    exists, and a message the peer already processed must not arrive twice."""

    def test_the_preserve_step_sends_nothing(self, client):
        sent = []
        client.send_otr_message = lambda peer, msg: sent.append((peer, msg))
        client.send = lambda raw: sent.append(("raw", raw))
        client._preserve_otr_across_reconnect()
        assert sent == []

    def test_the_report_step_sends_nothing(self, client):
        sent = []
        client.send_otr_message = lambda peer, msg: sent.append((peer, msg))
        client.send = lambda raw: sent.append(("raw", raw))
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        assert sent == []

    def test_the_user_is_told_that_nothing_is_re_sent(self, client):
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        assert client.said("is not re-sent")


class TestTheUserIsToldWhatSurvived:
    """A padlock that came through a transport drop with no explanation is a
    claim the user has no way to check."""

    def test_it_reports_the_surviving_sessions(self, client):
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        assert client.said("kept through the reconnect")

    def test_it_says_the_fingerprint_did_not_change(self, client):
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        assert client.said("fingerprints unchanged")

    def test_it_reports_only_once(self, client):
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        before = len(client.lines)
        client._report_preserved_sessions()
        assert len(client.lines) == before

    def test_it_says_nothing_when_no_session_survived(self):
        c = Client(peers=())
        c._preserved = c._preserve_otr_across_reconnect()
        c._report_preserved_sessions()
        assert not c.said("kept through the reconnect")

    def test_a_cancelled_prompt_is_reported(self, client):
        client._arm_secret_prompt(PEER, "start")
        client._preserved = client._preserve_otr_across_reconnect()
        client._report_preserved_sessions()
        assert client.said("passphrase prompt was cancelled")
        assert client.said("Nothing was stored or sent")


class TestSmpInFlightIsNamed:
    """An SMP run whose next message was on the dead socket may be stranded.
    Saying so beats leaving the user waiting on a step that cannot arrive."""

    @pytest.mark.parametrize("phase", ["AWAITING_MSG2", "AWAITING_MSG3",
                                       "AWAITING_MSG4", "SECRET_REQUIRED"])
    def test_a_run_in_progress_is_flagged(self, phase):
        c = Client(phase=phase)
        c._preserved = c._preserve_otr_across_reconnect()
        assert c._preserved["smp_in_flight"] == [PEER]
        c._report_preserved_sessions()
        assert c.said("part-way through")

    @pytest.mark.parametrize("phase", ["IDLE", "VERIFIED", "FAILED"])
    def test_a_settled_run_is_not_flagged(self, phase):
        c = Client(phase=phase)
        c._preserved = c._preserve_otr_across_reconnect()
        assert c._preserved["smp_in_flight"] == []

    def test_a_verified_session_is_not_told_to_start_again(self):
        c = Client(phase="VERIFIED")
        c._preserved = c._preserve_otr_across_reconnect()
        c._report_preserved_sessions()
        assert not c.said("part-way through")

    def test_the_smp_state_itself_is_not_touched(self):
        c = Client(phase="AWAITING_MSG3")
        c._preserve_otr_across_reconnect()
        assert c.session_manager.sessions[PEER].rust_smp.get_phase() == \
            "AWAITING_MSG3"


class TestItSurvivesABrokenSessionManager:
    """Fail-safe, not fail-secure, and the distinction is deliberate: the
    worst case here is a missing report, not a leak. Raising out of
    `_try_reconnect` would leave the client with no reconnect at all."""

    def test_an_unreadable_session_list_does_not_raise(self, client):
        class Broken:
            @property
            def sessions(self):
                raise RuntimeError("gone")

        client.session_manager = Broken()
        assert client._preserve_otr_across_reconnect()["sessions"] == []

    def test_a_session_with_no_smp_engine_is_fine(self, client):
        client.session_manager.sessions[PEER].rust_smp = None
        assert client._preserve_otr_across_reconnect()["smp_in_flight"] == []

    def test_an_engine_that_raises_is_not_flagged(self, client):
        class Boom:
            def get_phase(self):
                raise RuntimeError("no")

        client.session_manager.sessions[PEER].rust_smp = Boom()
        assert client._preserve_otr_across_reconnect()["smp_in_flight"] == []


class TestTheReconnectPathUsesIt:
    """Having the method is not the fix; `_try_reconnect` calling it is --
    and the destructive block it replaced must not come back."""

    @staticmethod
    @pytest.fixture(scope="class")
    def reconnect_src():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_try_reconnect")
        return ast.unparse(fn)

    def test_it_calls_the_preserve_step(self, reconnect_src):
        assert "_preserve_otr_across_reconnect" in reconnect_src

    def test_it_no_longer_clears_the_sessions(self, reconnect_src):
        assert "sessions.clear()" not in reconnect_src, (
            "the reconnect path is dropping every OTR session again")

    def test_it_no_longer_zeroizes_the_ratchet(self, reconnect_src):
        assert "zeroize" not in reconnect_src, (
            "a transport interruption is destroying the double ratchet again")

    def test_it_still_purges_the_scrollback(self, reconnect_src):
        """INV-24 is untouched by this change: the conversation must still
        not cross the connection boundary on screen, even though the keys
        now do."""
        assert "_purge_scrollback" in reconnect_src

    def test_shutdown_still_clears_everything(self):
        """`/quit` IS a boundary. Preserving across a blip must not turn
        into preserving across a deliberate exit."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        found = [ast.unparse(n) for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef) and n.name == "shutdown"]
        assert any("clear_all_sessions" in src for src in found), (
            "shutdown no longer tears the sessions down")
