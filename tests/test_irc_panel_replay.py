"""A tab switch that isn't a switch must not reprint the tab.

Reported from a handset, mid-handshake:

    2026-09-05 14:52:59 [IronFenrir] 🔑 Starting OTR session with IronFenrir…
    2026-09-05 14:53:50 [IronFenrir] 🔑 DAKE1 → sent - waiting for response…
    ──────────────── 🔴IronFenrir ─────────────────
    2026-09-05 14:52:59 [IronFenrir] 🔑 Starting OTR session with IronFenrir…
    2026-09-05 14:53:50 [IronFenrir] 🔑 DAKE1 → sent - waiting for response…
    ──────────────── live ────────────────

    "strange to be sending DAKE 1 twice"

Nothing was sent twice. `_switch_panel` replays the tab's whole buffer with
each message's *stored* timestamp, and it had no guard against being asked to
switch to the tab already focused -- so the inbound DAKE2's first fragment,
arriving while the initiator was sitting on the peer's tab, reprinted the two
lines the initiator had just watched appear.

The identical timestamps are the proof and the test: a genuine second send
carries a new one. That is asserted below, because it is the property that
tells a reader of a future log which of the two bugs they are looking at.

Why this is worth a test and not just a fix: the display is the only account
the user has of what the protocol did. A client that shows a handshake step
happening twice, when it happened once, is lying about the protocol in the
direction that makes a real duplicate -- a replay, a glare, a second
initiator -- invisible, because the user has learnt to discount it.

The guard is in `_switch_panel` rather than at the call site on purpose:
fifteen call sites, and before this only three checked.
"""

import ast
import os
import time

import pytest

otr = pytest.importorskip("otrv4plus")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "otrv4+.py")

PEER = "IronFenrir"
STARTING = "🔑 Starting OTR session with IronFenrir…"
DAKE1 = "🔑 DAKE1 → sent - waiting for response…"


class Client:
    """Enough of the IRC client for `_switch_panel` and nothing more.

    A stub rather than a live client so that anything the method reaches for
    which is not here is a dependency nobody intended it to have.
    """

    def __init__(self):
        self._tui_enabled = False
        self._screen = None
        self._prompt_refresh_cb = None
        self.channel_log = None
        self.panel_manager = otr.PanelManager(self)
        self._switch_panel = otr.OTRv4IRCClient._switch_panel.__get__(self)


@pytest.fixture
def client():
    c = Client()
    c.panel_manager.add_panel(PEER, "private")
    c.panel_manager.switch_to_panel(PEER)
    c.panel_manager.panels[PEER].add_message(STARTING)
    c.panel_manager.panels[PEER].add_message(DAKE1)
    return c


def printed(capsys):
    return capsys.readouterr().out


class TestTheReportedBug:

    def test_the_handshake_lines_are_not_reprinted(self, client, capsys):
        """The whole bug in one assertion. The peer tab is focused; a
        fragment callback asks to switch to it again."""
        capsys.readouterr()
        client._switch_panel(PEER)
        out = printed(capsys)
        assert DAKE1 not in out
        assert STARTING not in out

    def test_nothing_at_all_is_printed(self, client, capsys):
        """Not the header, not the separator, not the tab bar. A no-op
        switch that still drew a header would look like a second event
        even with the message lines gone."""
        capsys.readouterr()
        client._switch_panel(PEER)
        assert printed(capsys) == ""

    def test_it_still_reports_success(self, client):
        """`/switch` distinguishes 'no such panel' from 'switched' by the
        return value and falls back to a '#'-prefixed name on False. A guard
        that returned False would send it looking for '#IronFenrir'."""
        assert client._switch_panel(PEER) is True

    def test_a_missing_panel_is_still_a_failure(self, client):
        assert client._switch_panel("NoSuchNick") is False

    def test_the_panel_stays_active(self, client):
        client._switch_panel(PEER)
        assert client.panel_manager.active_panel == PEER


class TestRealSwitchesStillWork:
    """The guard must not cost the feature it is guarding."""

    def test_switching_away_and_back_replays(self, client, capsys):
        client._switch_panel("system")
        capsys.readouterr()
        client._switch_panel(PEER)
        out = printed(capsys)
        assert STARTING in out
        assert DAKE1 in out

    def test_the_first_switch_to_a_tab_replays(self, capsys):
        c = Client()
        c.panel_manager.add_panel(PEER, "private")
        c.panel_manager.panels[PEER].add_message(DAKE1)
        capsys.readouterr()
        assert c._switch_panel(PEER) is True
        assert DAKE1 in printed(capsys)

    def test_force_replays_the_tab_you_are_on(self, client, capsys):
        """`/switch <this tab>` typed by a user who has scrolled away is a
        request to redraw, and stays one."""
        capsys.readouterr()
        client._switch_panel(PEER, force=True)
        assert DAKE1 in printed(capsys)

    def test_force_defaults_to_off(self):
        import inspect
        sig = inspect.signature(otr.OTRv4IRCClient._switch_panel)
        assert sig.parameters["force"].default is False, (
            "a default of True restores the bug for every unguarded caller"
        )


class TestTheTimestampsAreTheTell:
    """What separates this bug from a real duplicate send, in a log."""

    def test_a_replay_carries_the_original_timestamp(self, client, capsys):
        """Reproduces the reporter's screen: switch away, wait, switch back,
        and the reprinted line still says when it first happened."""
        old = time.time() - 3600
        for entry in client.panel_manager.panels[PEER].history:
            entry["timestamp"] = old
        client._switch_panel("system")
        capsys.readouterr()
        client._switch_panel(PEER)
        out = printed(capsys)
        assert time.strftime(otr.TIMESTAMP_FORMAT, time.localtime(old)) in out
        assert time.strftime(otr.TIMESTAMP_FORMAT) not in out, (
            "a replayed line printed with the current time would be "
            "indistinguishable from a genuine second send"
        )

    def test_the_timestamp_is_a_full_date(self):
        """Two copies an hour apart are obvious; two copies a day apart are
        not, without the date. v10.19.0 added it -- this pins it, because
        this bug is diagnosed from the timestamp."""
        assert "%Y" in otr.TIMESTAMP_FORMAT and "%d" in otr.TIMESTAMP_FORMAT


class TestTheFragmentCallbackNoLongerAsksForIt:
    """The guard in `_switch_panel` fixes this call site and every other one,
    but the call site said `if _in_channel or _cur == s` -- it asked, in as
    many words, to switch to the tab it was already on. Left in place it is a
    trap for whoever removes the guard's `force` parameter later.

    Parsed rather than grepped: `tests/test_no_remote_input_capture.py`
    documents why a substring assertion over this file matches the comment
    that explains the removal.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def switch_call_guards():
        with open(ENGINE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_on_first_fragment")
        guards = []
        for node in ast.walk(fn):
            if not isinstance(node, ast.If):
                continue
            calls = [c for c in ast.walk(node)
                     if isinstance(c, ast.Call)
                     and isinstance(c.func, ast.Attribute)
                     and c.func.attr == "_switch_panel"]
            if calls:
                guards.append(ast.unparse(node.test))
        return guards

    def test_the_callback_still_switches_tabs(self, switch_call_guards):
        assert switch_call_guards, (
            "no guarded _switch_panel call left in _on_first_fragment -- an "
            "incoming DAKE1 while the user is in a channel must still open "
            "the peer's tab"
        )

    def test_no_guard_asks_for_the_active_tab(self, switch_call_guards):
        for guard in switch_call_guards:
            assert "_cur == s" not in guard, (
                "this guard asks to switch to the tab already focused: %s"
                % guard
            )

    def test_the_active_tab_is_excluded(self, switch_call_guards):
        assert any("_cur != s" in g for g in switch_call_guards), (
            "the callback should decline the no-op switch itself rather "
            "than lean on the guard inside _switch_panel"
        )


class TestTheUserCommandAsksForTheRedraw:
    """`/switch` is the one caller that should be able to replay the current
    tab, so it is the one caller allowed to pass force."""

    @staticmethod
    @pytest.fixture(scope="class")
    def forced_calls():
        with open(ENGINE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        return [c for c in ast.walk(tree)
                if isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute)
                and c.func.attr == "_switch_panel"
                and any(k.arg == "force" for k in c.keywords)]

    def test_the_switch_command_forces(self, forced_calls):
        assert len(forced_calls) == 2, (
            "expected exactly the two probes in the /switch handler; "
            "found %d forcing call sites" % len(forced_calls)
        )

    def test_no_other_caller_forces(self):
        """Counted from the other direction: every remaining call site must
        take the guard. A new one passing force=True is a new way to get the
        duplicate back on screen."""
        with open(ENGINE, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        calls = [c for c in ast.walk(tree)
                 if isinstance(c, ast.Call)
                 and isinstance(c.func, ast.Attribute)
                 and c.func.attr == "_switch_panel"]
        forced = [c for c in calls if any(k.arg == "force" for k in c.keywords)]
        assert len(calls) - len(forced) >= 12, (
            "call sites stopped taking the guard"
        )
