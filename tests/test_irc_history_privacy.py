"""An IRC conversation must not outlive the connection it happened on.

Reported from a real session. The client dropped, reconnected in five
seconds, found its own previous session still holding the nick, renamed
itself, and replayed the entire previous conversation into the new one --
three times over, with the unread badge climbing system(53) -> system(105)
-> system(158) as each reconnect appended another copy of the connection
chatter under another name:

    AngryMouse -> BrokenNexus -> HollowNexus

Three things were wrong and each needed its own fix:

  * The panel history was unbounded and nothing ever cleared it, so a tab
    switch replayed everything back to the start of the process.
  * The reconnect backoff started at 5s, shorter than any server's ping
    timeout, so the reconnect raced the server's reaping of the old session
    and lost.
  * A 433 collision was answered by taking a new random nick permanently,
    so one dropped connection cost the user their identity for good.

The privacy half is the reason this is a security test and not a UI one.
This client runs over I2P, where the point of a new session is that it is
not linkable to the previous one. Carrying the previous session's messages
across the boundary links them on the screen regardless of what the
transport did.

What is NOT claimed anywhere here: that a Python `str` can be scrubbed from
process memory. It cannot -- strings are immutable and may be interned. The
guarantee is that the client drops its last reference, so nothing it does
later can put the conversation back on screen. Material that must genuinely
be destroyed lives in Rust behind `zeroize()`, never in a chat panel.

Enforces INV-24.
"""

import time

import pytest

otr = pytest.importorskip("otrv4plus")


@pytest.fixture
def panel():
    return otr.ChatPanel("#i2p-chat", "channel")


class TestTheHistoryHasACeiling:

    def test_it_stops_growing_at_the_cap(self, panel):
        for i in range(otr.ChatPanel.MAX_HISTORY * 2):
            panel.add_message("message %d" % i)
        assert len(panel.history) == otr.ChatPanel.MAX_HISTORY

    def test_the_oldest_are_the_ones_dropped(self, panel):
        for i in range(otr.ChatPanel.MAX_HISTORY + 10):
            panel.add_message("message %d" % i)
        kept = [e["message"] for e in panel.history]
        assert kept[-1] == "message %d" % (otr.ChatPanel.MAX_HISTORY + 9)
        assert "message 0" not in kept
        assert "message 9" not in kept

    def test_message_ids_stay_unique_across_pruning(self, panel):
        """The id was `len(self.history)`, which starts repeating itself the
        moment the first entry is pruned. Two live messages sharing an id
        means anything holding one addresses the other."""
        ids = [panel.add_message("m%d" % i)
               for i in range(otr.ChatPanel.MAX_HISTORY + 50)]
        assert len(set(ids)) == len(ids)
        live = [e["id"] for e in panel.history]
        assert len(set(live)) == len(live)

    def test_a_cap_of_one_still_keeps_the_newest(self, panel):
        """Boundary: off-by-one in the prune would either keep nothing or
        keep two."""
        panel.MAX_HISTORY = 1
        panel.add_message("old")
        panel.add_message("new")
        assert [e["message"] for e in panel.history] == ["new"]


class TestClearingReallyClears:

    def test_it_empties_the_history_and_reports_the_count(self, panel):
        for i in range(25):
            panel.add_message("m%d" % i)
        assert panel.clear_history() == 25
        assert panel.history == []

    def test_it_resets_the_unread_badge(self, panel):
        """The accumulating system(53) -> system(105) -> system(158) counter
        was this: the badge was never reset when the history behind it went
        away."""
        panel.add_message("m")
        panel.unread_count = 158
        panel.clear_history()
        assert panel.unread_count == 0

    def test_it_forgets_who_was_talking(self, panel):
        """`recent_users` is a set of nicks from the old connection. Left
        behind, it is a list of who was in the previous session -- exactly
        the linkage the purge exists to break."""
        panel.recent_users.add("someone")
        panel.clear_history()
        assert panel.recent_users == set()

    def test_the_retained_text_is_overwritten_not_just_unlinked(self, panel):
        """Best effort, and worth pinning as such: the dict entry no longer
        holds the text even if something else is still holding the dict."""
        entries = []
        for i in range(5):
            panel.add_message("secret %d" % i)
        entries = list(panel.history)
        panel.clear_history()
        assert all(e["message"] == "" for e in entries)

    def test_clearing_an_empty_panel_is_harmless(self, panel):
        assert panel.clear_history() == 0
        assert panel.clear_history() == 0


class TestTheReconnectBackoffOutlivesTheGhost:
    """A reconnect that beats the server's ping timeout is what caused the
    collision in the first place."""

    backoff = staticmethod(otr.OTRv4IRCClient._reconnect_backoff)

    def test_the_first_attempt_already_waits_long_enough(self):
        assert self.backoff(1) >= 30, (
            "the first retry is the one that raced the server's reaping of "
            "the old session; 5s was the reported bug"
        )

    def test_it_climbs(self):
        assert self.backoff(1) < self.backoff(2) < self.backoff(3)

    def test_it_is_capped(self):
        for attempt in (4, 10, 100, 10_000):
            assert self.backoff(attempt) <= 120

    def test_the_documented_schedule_is_what_it_does(self):
        assert [self.backoff(n) for n in range(1, 6)] == [30, 60, 90, 120, 120]

    def test_a_zero_or_negative_attempt_still_waits(self):
        """Nothing should be able to talk the client into a busy-reconnect
        loop by arriving at this with a bad counter."""
        for attempt in (0, -1, -1000):
            assert self.backoff(attempt) >= 30


class TestNickCollisionRecovery:
    """433 must not cost the user their identity permanently."""

    def test_the_original_nick_is_remembered_at_startup(self):
        assert "_original_nick" in otr.OTRv4IRCClient.__init__.__code__.co_names, (
            "nothing records the nick we want, so there is nothing to reclaim"
        )

    def test_a_collision_does_not_rename_an_already_registered_session(self):
        """After registration a 433 is a *failed reclaim*, not a failed
        login. Renaming again there is how one drop became three names."""
        client = _StubClient()
        client.auth_complete = True
        client.nick = "HollowNexus"
        client._original_nick = "AngryMouse"
        otr.OTRv4IRCClient._on_nick_collision(client)
        assert client.nick == "HollowNexus"
        assert client.sent == [], "it tried to rename an established session"
        assert client.scheduled, "it gave up on the original nick"

    def test_a_collision_during_registration_takes_a_temporary_nick(self):
        """You cannot finish registration without a free nick, so here the
        rename is correct -- but it must be recorded as temporary."""
        client = _StubClient()
        client.auth_complete = False
        client.nick = "AngryMouse"
        otr.OTRv4IRCClient._on_nick_collision(client)
        assert client.nick != "AngryMouse"
        assert client._original_nick == "AngryMouse"
        assert any(m.startswith("NICK ") for m in client.sent)
        assert client.scheduled, "no reclaim was scheduled"

    def test_the_reclaim_stops_after_a_bounded_number_of_tries(self, timers):
        """If someone else genuinely holds the nick, this must go quiet
        rather than send NICK forever."""
        client = _StubClient()
        client.nick = "Temporary"
        client._original_nick = "AngryMouse"
        client._nick_reclaim_tries = otr.OTRv4IRCClient.NICK_RECLAIM_ATTEMPTS
        otr.OTRv4IRCClient._schedule_nick_reclaim(client)
        assert timers == [], "it is still asking for a nick someone else holds"

    def test_it_does_keep_trying_below_the_limit(self, timers):
        """The other half of the bound: a limit that stopped at the first
        attempt would pass the test above and never reclaim anything."""
        client = _StubClient()
        client.nick = "Temporary"
        client._original_nick = "AngryMouse"
        client._nick_reclaim_tries = 0
        otr.OTRv4IRCClient._schedule_nick_reclaim(client)
        assert len(timers) == 1
        assert timers[0].delay >= 30

    def test_the_scheduled_reclaim_asks_for_the_original_nick(self, timers):
        client = _StubClient()
        client.nick = "Temporary"
        client._original_nick = "AngryMouse"
        otr.OTRv4IRCClient._schedule_nick_reclaim(client)
        timers[0].fn()
        assert client.sent == ["NICK AngryMouse"]

    def test_a_reclaim_that_fires_after_shutdown_sends_nothing(self, timers):
        client = _StubClient()
        client.nick = "Temporary"
        client._original_nick = "AngryMouse"
        otr.OTRv4IRCClient._schedule_nick_reclaim(client)
        client.shutdown_flag = True
        timers[0].fn()
        assert client.sent == [], "a timer outlived the session and still sent"

    def test_no_reclaim_is_scheduled_once_we_have_the_nick(self, timers):
        client = _StubClient()
        client.nick = "AngryMouse"
        client._original_nick = "AngryMouse"
        otr.OTRv4IRCClient._schedule_nick_reclaim(client)
        assert timers == []
        assert client._nick_reclaim_tries == 0

    def test_the_reclaim_delay_is_long_enough_to_outlive_a_ghost(self):
        assert otr.OTRv4IRCClient.NICK_RECLAIM_DELAY >= 30


class TestThePurgeReachesEveryPanel:
    """`_purge_scrollback` is the single place the boundary is enforced, so
    it is the one that has to be right."""

    def test_it_empties_every_panel_not_just_the_active_one(self):
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system", "#i2p-chat", "alice"])
        for panel in client.panel_manager.panels.values():
            for i in range(10):
                panel.add_message("m%d" % i)
            panel.unread_count = 10

        purged = otr.OTRv4IRCClient._purge_scrollback(client, "test", announce=False)

        assert purged == 30
        for name, panel in client.panel_manager.panels.items():
            assert panel.history == [], "%s kept its history" % name
            assert panel.unread_count == 0, "%s kept its badge" % name

    def test_one_broken_panel_does_not_stop_the_others(self):
        """A purge that aborts halfway leaves the rest of the conversation on
        screen, which is the failure this whole change is about."""
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system", "#i2p-chat"])

        class _Exploding:
            unread_count = 0

            def clear_history(self):
                raise RuntimeError("boom")

        client.panel_manager.panels["broken"] = _Exploding()
        for name in ("system", "#i2p-chat"):
            client.panel_manager.panels[name].add_message("secret")

        otr.OTRv4IRCClient._purge_scrollback(client, "test", announce=False)

        for name in ("system", "#i2p-chat"):
            assert client.panel_manager.panels[name].history == []

    def test_purging_nothing_is_not_an_error(self):
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system"])
        assert otr.OTRv4IRCClient._purge_scrollback(client, "test", announce=False) == 0

    def test_the_terminal_is_wiped_when_the_user_is_leaving_or_asked(self, capsys):
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system"])
        client.panel_manager.panels["system"].add_message("m")
        otr.OTRv4IRCClient._purge_scrollback(
            client, "/clear", announce=False, wipe_terminal=True)
        # Only when stdout is a tty, which it is not under pytest -- so what
        # is asserted here is that the call is reachable and does not raise.
        # The tty branch itself is one `sys.stdout.write`.
        assert client.panel_manager.panels["system"].history == []

    def test_an_automatic_reconnect_does_not_blank_the_terminal(self, capsys):
        """The buffers are purged so nothing replays; the lines already
        printed stay, because they are the error messages the user is
        reading to find out why the connection dropped."""
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system"])
        client.panel_manager.panels["system"].add_message("m")
        otr.OTRv4IRCClient._purge_scrollback(
            client, "connection lost", announce=False, wipe_terminal=False)
        assert "\033[3J" not in capsys.readouterr().out
        assert client.panel_manager.panels["system"].history == []

    def test_it_announces_only_when_asked(self):
        client = _StubClient()
        client.panel_manager = _StubPanelManager(["system"])
        client.panel_manager.panels["system"].add_message("m")
        otr.OTRv4IRCClient._purge_scrollback(client, "/clear", announce=True)
        assert client.messages, "a user-typed /clear should say what it did"

        client.messages.clear()
        client.panel_manager.panels["system"].add_message("m")
        otr.OTRv4IRCClient._purge_scrollback(client, "shutdown", announce=False)
        assert client.messages == [], (
            "the shutdown path wrote into a panel it had just emptied"
        )


class TestThePurgeIsWiredIntoTheLifecycle:
    """Having the method is not the fix; calling it at each boundary is.

    Source-level, deliberately. Driving a real reconnect needs a socket, a
    server and thirty seconds of backoff; what has to be asserted is simply
    that neither path can be edited into forgetting the purge.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), "r", encoding="utf-8") as fh:
            return fh.read()

    def _body(self, source, marker):
        start = source.index(marker)
        rest = source[start:]
        # Up to the next method definition at the same indentation.
        end = rest.index("\n    def ", len(marker))
        return rest[:end]

    def test_the_reconnect_path_purges(self, source):
        body = self._body(source, "    def _try_reconnect(self")
        assert "_purge_scrollback" in body, (
            "a reconnect no longer clears the previous session's messages"
        )
        assert "wipe_terminal=False" in body, (
            "a routine reconnect now blanks the terminal, destroying the "
            "error messages the user is reading at exactly that moment"
        )

    def test_the_shutdown_path_purges(self, source):
        body = self._body(source, "    def shutdown(self):")
        assert "_purge_scrollback" in body, (
            "/quit no longer clears the conversation before exiting"
        )

    def test_process_exit_purges(self, source):
        assert "atexit.register(_purge_on_exit)" in source, (
            "SIGINT and unhandled exceptions leave the conversation rendered"
        )


class TestTimestampsCarryTheDate:

    def test_the_format_includes_a_four_digit_year(self):
        rendered = time.strftime(otr.TIMESTAMP_FORMAT, time.localtime(0))
        assert rendered.startswith(("1969-", "1970-")), rendered

    def test_it_is_the_documented_shape(self):
        assert otr.TIMESTAMP_FORMAT == "%Y-%m-%d %H:%M:%S"

    def test_nothing_still_renders_a_bare_clock_time(self):
        """Four call sites used to carry their own `"%H:%M:%S"` literal.
        One left behind would put an undated line next to dated ones, which
        is worse than either alone."""
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), "r", encoding="utf-8") as fh:
            source = fh.read()
        assert 'time.strftime("%H:%M:%S' not in source, (
            "a hard-coded clock-only timestamp is back; use TIMESTAMP_FORMAT"
        )


class _StubClient:
    """The bits of the client the nick logic touches, and nothing else.

    Driving the real client would need a socket, a panel manager and a
    session manager; the collision logic depends on none of them, and a stub
    makes it obvious which four attributes it actually reads.
    """

    NICK_RECLAIM_DELAY = otr.OTRv4IRCClient.NICK_RECLAIM_DELAY
    NICK_RECLAIM_ATTEMPTS = otr.OTRv4IRCClient.NICK_RECLAIM_ATTEMPTS

    def __init__(self):
        self.nick = "nobody"
        self.auth_complete = False
        self.connected = True
        self.shutdown_flag = False
        self._nick_reclaim_tries = 0
        self.sent = []
        self.messages = []
        self.scheduled = False

    def send(self, line):
        self.sent.append(line)
        return True

    def add_message(self, panel, message):
        self.messages.append((panel, message))

    def _schedule_nick_reclaim(self):
        self.scheduled = True
        otr.OTRv4IRCClient._schedule_nick_reclaim(self)


class _FakeTimer:
    """Records the scheduled callback instead of sleeping for 30 seconds.

    The tests need to see *that* a reclaim was scheduled, with what delay,
    and what it does when it fires -- none of which is worth half a minute
    of wall clock, and a real `threading.Timer` would leave daemon threads
    behind after the suite finished.
    """

    def __init__(self, delay, fn):
        self.delay = delay
        self.fn = fn
        self.daemon = False
        self.started = False

    def start(self):
        self.started = True


class _StubPanelManager:
    def __init__(self, names):
        self.panels = {n: otr.ChatPanel(n, "channel") for n in names}
        self.panel_order = list(names)
        self.active_panel = names[0] if names else None


@pytest.fixture(autouse=True)
def timers(monkeypatch):
    """Every timer `_schedule_nick_reclaim` starts during one test.

    `otr.threading` is the real threading module, so this patch is global
    for the duration -- monkeypatch puts it back at teardown, and nothing
    else in this file starts a timer.
    """
    started = []

    def _timer(delay, fn, *args, **kwargs):
        t = _FakeTimer(delay, fn)
        started.append(t)
        return t

    monkeypatch.setattr(otr.threading, "Timer", _timer)
    return started
